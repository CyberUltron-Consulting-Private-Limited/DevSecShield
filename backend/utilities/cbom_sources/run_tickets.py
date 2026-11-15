"""Jira tickets for the findings of a CBOM Sources run, and the remediation metrics of a run (CB-38 PR-4).

* Credentials: the team's Jira connection (``team.integration_settings["jira"]``, the code lane's, read through
  ``jira_ticketing._jira_creds``); the project and issue type for CBOM Sources are team settings
  (``cbomcollectionsettings.jira_project_key`` / ``jira_issue_type``) that only a team admin changes.
* One ticket per asset across runs: the issue key is stored on the asset's ``CbomRemediationAssignment``, which is keyed
  by the asset's STABLE identity (``identity.stable_key``), so ticketing the same asset from a later run reports the
  existing issue instead of opening another one. Every issue carries the label ``zs-asset-<stable key>``.
* No database transaction, lock or connection is held while Jira is called. Per asset: (a) a short committed
  transaction makes sure the assignment row exists (``INSERT … ON CONFLICT DO NOTHING``) and claims it
  (``ticket_state='claimed'`` + a claim id, compare-and-set); (b) Jira is called with no session open; (c) a short
  transaction stores the key only while the claim is still ours. A live claim of another request makes this request
  report the asset as ``deferred``. A claim older than ``CLAIM_TTL`` is taken over, and the new holder first searches
  Jira by the asset's label: a call that timed out (or a process that stopped) may have created the issue already.
  A timeout, or a Jira 5xx, keeps the claim for that reason; a refusal (4xx, unreachable) releases it.
* Time budget: no new Jira call starts after ``TIME_BUDGET_S``; the remaining assets are reported as ``deferred``.
* Buckets: ``created``, ``existing``, ``failed`` (Jira's own error text, or a fixed message), ``skipped`` (clean
  inventory and coverage notes: not findings), ``deferred`` (another request holds the asset, or the time budget ran
  out: retry).
* Logged: ids, counts and error kinds only; never credentials, Jira response bodies or asset text.
"""
from __future__ import annotations

import datetime as _dt
import re
import time
import uuid
from typing import Any, Iterable, Literal

from fastapi import HTTPException
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import update
from sqlalchemy.dialects import postgresql as pg_dialect
from sqlalchemy.dialects import sqlite as sqlite_dialect
from sqlalchemy.exc import IntegrityError
from sqlmodel import Session, select

from backend.new_models import (
    CbomCollectedAsset,
    CbomCollectionJob,
    CbomCollectionRun,
    CbomCollectionSettings,
    CbomCollectionSource,
    CbomRemediationAssignment,
    CbomScanNode,
    Team,
)
from backend.utilities.cbom_sources import waves as WAVES
from backend.utilities.cbom_sources.common import iso_z, log
from backend.utilities.integrations import jira as JIRA
from backend.utilities.integrations.jira_ticketing import _jira_creds

MAX_ASSETS = 50  # per request, as the code lane's MAX_AUTO_TICKETS (one Jira call per asset)
DEFAULT_ISSUE_TYPE = "Task"
SUMMARY_MAX = 255
DESCRIPTION_MAX = 8_000
ERROR_MAX = 300
TIME_BUDGET_S = 120.0  # no Jira call starts after this; one call is bounded by jira.REQUEST_TIMEOUT (5 s + 30 s)
CLAIM_TTL = _dt.timedelta(minutes=2)  # longer than one Jira call; an older claim is taken over
LABEL_PREFIX = "zs-asset-"
GENERIC_ERROR = "Could not create the ticket; please try again."
NOT_A_FINDING = "Not a finding: clean inventory and coverage notes are not ticketed"
IN_PROGRESS = "Another request is creating this ticket; try again in a few minutes."
OUT_OF_TIME = "Not attempted (time limit); try again."
_PROJECT = re.compile(r"^(?:[A-Z][A-Z0-9_]{1,31}|[1-9][0-9]{0,17})$")
NOT_CONNECTED = "Jira is not connected for this team. A team admin connects it in Team settings → Integrations."
NO_PROJECT = "No Jira project is set for CBOM Sources. A team admin sets it in the Ticketing tab."


def _utcnow() -> _dt.datetime:
    return _dt.datetime.now(_dt.timezone.utc).replace(tzinfo=None)  # naive UTC, as every stored time


# ----------------------------------------------------------------------------- request bodies
class TicketBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    asset_ids: list[int] = Field(min_length=1, max_length=1_000)
    ticket_type: Literal["jira"] = "jira"

    @field_validator("asset_ids")
    @classmethod
    def _ids(cls, v: list[int]) -> list[int]:
        if any(i < 1 or i > 2_147_483_647 for i in v):
            raise ValueError("not an asset id")
        ids = list(dict.fromkeys(v))  # duplicates first, then the cap
        if len(ids) > MAX_ASSETS:
            raise ValueError(f"at most {MAX_ASSETS} different assets per request")
        return ids


class JiraSettingsBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    jira_project_key: str | None = Field(default=None, max_length=32)
    jira_issue_type: str | None = Field(default=None, max_length=64)
    expected_version: int | None = Field(default=None, ge=1)

    @field_validator("jira_project_key")
    @classmethod
    def _project(cls, v: str | None) -> str | None:
        text = (v or "").strip()
        if not text:
            return None
        text = text.upper()
        if not _PROJECT.match(text):
            raise ValueError("use the project key (such as SEC) or the numeric project id")
        return text

    @field_validator("jira_issue_type")
    @classmethod
    def _issue_type(cls, v: str | None) -> str | None:
        text = "".join(ch for ch in (v or "") if ch >= " " and ch != "\x7f").strip()
        return text or None


# ----------------------------------------------------------------------------- settings
def project_ref(value: str) -> dict[str, str]:
    """Arguments for ``create_issue_in_project``: a numeric value is a project id, anything else a project key."""
    return {"project_id": value} if value.isdigit() else {"project_id": "", "project_key": value}


def public_jira_settings(settings: CbomCollectionSettings, team: Team | None, *, is_admin: bool) -> dict[str, Any]:
    """What the Ticketing tab needs; never a credential (``connected`` only says the team has one)."""
    return {
        "connected": team is not None and _jira_creds(team) is not None,
        "jira_project_key": settings.jira_project_key,
        "jira_issue_type": settings.jira_issue_type or DEFAULT_ISSUE_TYPE,
        "issue_type_default": DEFAULT_ISSUE_TYPE,
        "is_admin": is_admin,
        "row_version": settings.row_version,
    }


# ----------------------------------------------------------------------------- ticket text
def _clip(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[: limit - 1] + "…"


def is_ticketable(item: dict[str, Any]) -> bool:
    """A finding (an impact, or something to remediate in a wave); clean inventory is listed, never ticketed."""
    return bool(item.get("impact")) or item.get("suggested_wave") is not None


def ticket_text(run_id: int, item: dict[str, Any], detail: dict[str, Any]) -> tuple[str, str]:
    """(summary, description) of one asset's issue, from the knowledge base's finding text for its codes."""
    details = detail.get("details") or []
    title = (details[0].get("title") if details else None) or detail.get("finding") or "Cryptographic finding"
    impact = detail.get("impact") or ("Quantum-vulnerable" if detail.get("quantum_vulnerable") else "Informational")
    summary = _clip(f"[CBOM] {impact}: {title} · {item.get('label') or detail.get('location') or ''}".strip(),
                    SUMMARY_MAX)
    lines = [
        f"DevSecShield CBOM Sources finding (run #{run_id}).",
        f"Impact: {impact}",
        f"Asset: {detail.get('type')} · {item.get('label') or ''}",
        f"Location: {detail.get('location') or '—'}",
    ]
    if detail.get("target"):
        lines.append(f"Target: {detail['target']}")
    lines.append(f"Source: {item.get('source_name') or detail.get('source_name') or '—'}")
    if detail.get("finding"):
        lines.append(f"Finding: {detail['finding']}")
    codes = detail.get("finding_codes") or []
    if codes:
        lines.append(f"Codes: {', '.join(codes)}")
    lines.append(f"Quantum vulnerable: {'yes' if detail.get('quantum_vulnerable') else 'no'}")
    if detail.get("exposure"):
        lines.append(f"Exposure: {detail['exposure']}")
    for d in details:
        lines.append("")
        lines.append(f"{d.get('code')}: {d.get('title')}")
        if d.get("observed") or d.get("description"):
            lines.append(str(d.get("observed") or d.get("description")))
        fix = d.get("remediation") or {}
        if fix.get("summary"):
            lines.append(f"Fix: {fix['summary']}")
        for step in fix.get("steps") or []:
            lines.append(f"  - {step}")
        for v in d.get("verify") or []:
            lines.append(f"Verify ({v.get('label')}): {v.get('command')}")
    lines.append("")
    lines.append(f"Asset key: {item.get('asset_key')}")
    return summary, _clip("\n".join(lines), DESCRIPTION_MAX)


def _detail(session: Session, team_id: int, row: CbomCollectedAsset) -> dict[str, Any]:
    from backend.utilities.cbom_sources import posture as POSTURE

    source = session.get(CbomCollectionSource, row.source_id) if row.source_id else None
    source = source if source is not None and source.team_id == team_id else None
    job = session.get(CbomCollectionJob, row.job_id) if row.job_id else None
    job = job if job is not None and job.team_id == team_id else None
    node = session.get(CbomScanNode, source.node_id) if source is not None and source.node_id else None
    node = node if node is not None and node.team_id == team_id else None
    return POSTURE.asset_detail(row, source, job=job, node=node)


def label_for(asset_key: str) -> str:
    return f"{LABEL_PREFIX}{asset_key}"


def _error_text(exc: BaseException) -> str:
    """Only the Jira client's own messages reach the user; anything else (database, address check) is generic."""
    if isinstance(exc, JIRA.JiraError):
        return _clip(" ".join(str(exc).split()) or GENERIC_ERROR, ERROR_MAX)
    return GENERIC_ERROR


def _error_kind(exc: BaseException) -> str:
    return getattr(exc, "kind", None) or type(exc).__name__


# ----------------------------------------------------------------------------- create
_M = CbomRemediationAssignment


def _ensure_row(session: Session, team_id: int, item: dict[str, Any], user_id: int, now: _dt.datetime) -> None:
    """The asset's assignment row exists (committed by the caller); a concurrent insert by ``waves.upsert`` or another
    ticket request is fine (``ON CONFLICT DO NOTHING``)."""
    values = {"team_id": team_id, "asset_key": item["asset_key"], "scope": "node",
              "source_ref": str(item["source_ref"])[:255], "label": str(item.get("label") or "")[:255] or None,
              "status": "open", "row_version": 1, "updated_by_user_id": user_id, "created_at": now,
              "last_updated": now}
    dialect = session.get_bind().dialect.name
    if dialect in ("postgresql", "sqlite"):
        mod = pg_dialect if dialect == "postgresql" else sqlite_dialect
        session.exec(mod.insert(_M).values(**values)  # type: ignore[call-overload]
                     .on_conflict_do_nothing(index_elements=["team_id", "asset_key"]))
        return
    try:  # other dialects: the unique key decides
        with session.begin_nested():
            session.exec(_M.__table__.insert().values(**values))  # type: ignore[attr-defined,call-overload]
    except IntegrityError:
        pass


def _claim(engine, team_id: int, item: dict[str, Any], user_id: int, now: _dt.datetime
           ) -> tuple[str, str | None, bool, CbomRemediationAssignment | None]:
    """Short committed transaction. Returns (outcome, claim id, search_first, row): outcome ``existing`` (a ticket is
    stored), ``busy`` (another request holds a live claim) or ``claimed`` (ours; ``search_first`` when we took over a
    stale claim, whose Jira call may have created the issue)."""
    with Session(engine) as session:
        _ensure_row(session, team_id, item, user_id, now)
        session.commit()
        for _attempt in range(3):
            row = session.exec(select(_M).where(_M.team_id == team_id, _M.asset_key == item["asset_key"])).one()
            if row.ticket_key:
                return "existing", None, False, row
            stale = row.ticket_claimed_at is None or row.ticket_claimed_at < now - CLAIM_TTL
            if row.ticket_state == "claimed" and not stale:
                return "busy", None, False, row
            claim = uuid.uuid4().hex
            previous, was_claimed = row.ticket_claim, row.ticket_state == "claimed"  # read before the commit expires row
            won = session.exec(update(_M).where(  # type: ignore[call-overload]
                _M.id == row.id, _M.ticket_key.is_(None),  # type: ignore[union-attr]
                _M.ticket_claim.is_(None) if previous is None else _M.ticket_claim == previous)  # type: ignore
                .values(ticket_state="claimed", ticket_claim=claim, ticket_claimed_at=now,
                        row_version=_M.row_version + 1)
                .execution_options(synchronize_session=False)).rowcount
            session.commit()
            if won == 1:
                return "claimed", claim, was_claimed, None
            session.expire_all()  # someone changed the row between the read and the claim: read again
        return "busy", None, False, None


def _finish(engine, team_id: int, asset_key: str, claim: str, user_id: int, *, key: str | None = None,
            url: str | None = None, release: bool = False) -> CbomRemediationAssignment | None:
    """Short transaction: store the key (or release the claim) only while the claim is still ours. Returns the row
    as stored when the claim was no longer ours."""
    now = _utcnow()
    values: dict[str, Any] = {"row_version": _M.row_version + 1, "last_updated": now, "updated_by_user_id": user_id}
    if key is not None:
        values.update(ticket_key=key[:64], ticket_url=(url or "")[:512] or None, ticket_state="created",
                      ticket_claim=None, ticket_claimed_at=None)
    elif release:
        values.update(ticket_state=None, ticket_claim=None, ticket_claimed_at=None)
    with Session(engine) as session:
        won = session.exec(update(_M).where(  # type: ignore[call-overload]
            _M.team_id == team_id, _M.asset_key == asset_key, _M.ticket_claim == claim)
            .values(**values).execution_options(synchronize_session=False)).rowcount
        session.commit()
        if won == 1:
            return None
        return session.exec(select(_M).where(_M.team_id == team_id, _M.asset_key == asset_key)).first()


def _jira_issue(url: str, token: str, email: str, project: str, issue_type: str, item: dict[str, Any],
                detail: dict[str, Any], run_id: int, search_first: bool) -> tuple[str, bool]:
    """(issue key, found by search). No database session is open here."""
    label = label_for(item["asset_key"])
    if search_first:
        found = JIRA.find_issue_by_label(url, token, label, jira_email=email)
        if found:
            return found, True
    summary, description = ticket_text(run_id, item, detail)
    answer = JIRA.create_issue_in_project(jira_url=url, jira_token=token, summary=summary, description=description,
                                          jira_email=email, issue_type=issue_type, labels=[label],
                                          **project_ref(project))
    key = str((answer or {}).get("key") or "").strip()
    if not key:
        raise JIRA.JiraError("http_5xx", "Jira did not return an issue key")
    return key, False


def create_tickets(engine, team_id: int, user_id: int, run_id: int, body: TicketBody, *,
                   budget_s: float | None = None) -> dict[str, Any]:
    started = time.monotonic()
    budget = TIME_BUDGET_S if budget_s is None else budget_s
    with Session(engine) as session:
        run = session.get(CbomCollectionRun, run_id)
        if run is None or run.team_id != team_id:
            raise HTTPException(status_code=404, detail="Run not found")
        team = session.get(Team, team_id)
        creds = _jira_creds(team) if team is not None else None
        if creds is None:
            raise HTTPException(status_code=400, detail=NOT_CONNECTED)
        settings = session.exec(select(CbomCollectionSettings).where(CbomCollectionSettings.team_id == team_id)).first()
        project = settings.jira_project_key if settings is not None else None
        if not project:
            raise HTTPException(status_code=400, detail=NO_PROJECT)
        issue_type = (settings.jira_issue_type if settings is not None else None) or DEFAULT_ISSUE_TYPE
        rows = {r.id: r for r in session.exec(select(CbomCollectedAsset).where(
            CbomCollectedAsset.team_id == team_id, CbomCollectedAsset.run_id == run.id,
            CbomCollectedAsset.id.in_(body.asset_ids))).all()}  # type: ignore[union-attr]
        unknown = [i for i in body.asset_ids if i not in rows]
        if unknown:
            raise HTTPException(status_code=400, detail=f"asset_ids: {len(unknown)} asset(s) are not in this run")
        items = {i["asset_id"]: i for i in WAVES.node_items(session, team_id, run, asset_ids=body.asset_ids)}
        work: list[tuple[int, dict[str, Any] | None, dict[str, Any] | None]] = []
        for asset_id in body.asset_ids:
            item = items.get(asset_id)  # coverage ("not collected") rows have no item
            work.append((asset_id, item, _detail(session, team_id, rows[asset_id])
                         if item is not None and is_ticketable(item) else None))
    # the read session is closed: nothing below holds a connection while Jira answers

    email, token, url = creds
    out: dict[str, list[dict[str, Any]]] = {"created": [], "existing": [], "failed": [], "skipped": [], "deferred": []}

    def ref(asset_id: int, item: dict[str, Any], key: str | None, link: str | None) -> dict[str, Any]:
        return {"asset_id": asset_id, "asset_key": item["asset_key"], "ticket_key": key, "ticket_url": link}

    for asset_id, item, detail in work:
        if item is None or detail is None:
            out["skipped"].append({"asset_id": asset_id, "asset_key": item["asset_key"] if item else None,
                                   "reason": NOT_A_FINDING})
            continue
        if time.monotonic() - started > budget:  # no new Jira call after the budget: the user retries the rest
            out["deferred"].append({"asset_id": asset_id, "asset_key": item["asset_key"], "reason": OUT_OF_TIME})
            continue
        try:
            outcome, claim, search_first, row = _claim(engine, team_id, item, user_id, _utcnow())
        except Exception as exc:  # noqa: BLE001 - one asset's failure never loses the others
            log("run ticket FAILED", team=team_id, run=run_id, asset=asset_id, step="claim", error=_error_kind(exc))
            out["failed"].append({"asset_id": asset_id, "asset_key": item["asset_key"], "error": GENERIC_ERROR})
            continue
        if outcome == "existing" and row is not None:
            out["existing"].append(ref(asset_id, item, row.ticket_key, row.ticket_url))
            continue
        if outcome == "busy" or claim is None:
            out["deferred"].append({"asset_id": asset_id, "asset_key": item["asset_key"], "reason": IN_PROGRESS})
            continue
        try:
            key, found = _jira_issue(url, token, email, project, issue_type, item, detail, run_id, search_first)
        except Exception as exc:  # noqa: BLE001
            uncertain = getattr(exc, "kind", None) in ("timeout", "http_5xx")
            if not uncertain:  # nothing was created: let the next request try at once
                try:
                    _finish(engine, team_id, item["asset_key"], claim, user_id, release=True)
                except Exception as release_exc:  # noqa: BLE001
                    log("run ticket release FAILED", team=team_id, asset=asset_id, error=_error_kind(release_exc))
            log("run ticket FAILED", team=team_id, run=run_id, asset=asset_id, step="jira", error=_error_kind(exc),
                kept_claim=uncertain)
            out["failed"].append({"asset_id": asset_id, "asset_key": item["asset_key"], "error": _error_text(exc)})
            continue
        link = f"{url.rstrip('/')}/browse/{key}"
        try:
            other = _finish(engine, team_id, item["asset_key"], claim, user_id, key=key, url=link)
        except Exception as exc:  # noqa: BLE001 - the issue exists: a retry finds it by its label
            log("run ticket FAILED", team=team_id, run=run_id, asset=asset_id, step="store", error=_error_kind(exc))
            out["failed"].append({"asset_id": asset_id, "asset_key": item["asset_key"], "error": GENERIC_ERROR})
            continue
        if other is None:
            out["existing" if found else "created"].append(ref(asset_id, item, key[:64], link[:512]))
        elif other.ticket_key:  # our claim expired and another request stored its key first
            log("run ticket claim lost", team=team_id, run=run_id, asset=asset_id)
            out["existing"].append(ref(asset_id, item, other.ticket_key, other.ticket_url))
        else:  # the request holding the claim now searches by label and finds this issue
            out["deferred"].append({"asset_id": asset_id, "asset_key": item["asset_key"], "reason": IN_PROGRESS})
    if out["created"]:
        from backend.utilities.cbom_sources.common import audit

        with Session(engine) as session:
            audit(session, team_id=team_id, actor_type="user", actor_id=user_id, action="remediation.ticket",
                  object_type="run", object_id=run_id, changed_fields=["ticket_key", "ticket_url"])
            session.commit()
    log("run tickets", team=team_id, run=run_id, by=user_id, **{k: len(v) for k, v in out.items()})
    return out


# ----------------------------------------------------------------------------- list fields
def add_ticket_fields(session: Session, team_id: int, run: CbomCollectionRun, items: list[dict[str, Any]]) -> None:
    """``ticket_key`` / ``ticket_url`` on each run asset list item (None when the asset has no ticket). Reads the
    assignment the enriched list already carries (``item["wave"]["assignment"]``); items without one are looked up by
    their ``asset_key``, and items without a key (an older list) by the stable key of the page's assets."""
    by_id: dict[int, str] = {}
    for item in items:
        assignment = (item.get("wave") or {}).get("assignment") if isinstance(item.get("wave"), dict) else None
        if isinstance(assignment, dict) and "ticket_key" in assignment:
            item["ticket_key"], item["ticket_url"] = assignment.get("ticket_key"), assignment.get("ticket_url")
        elif item.get("asset_key"):
            by_id[item["id"]] = item["asset_key"]
    missing = [i["id"] for i in items if "ticket_key" not in i and not i.get("asset_key") and i.get("type") != "coverage"]
    if missing:
        by_id.update({i["asset_id"]: i["asset_key"] for i in WAVES.node_items(session, team_id, run, asset_ids=missing)})
    found = WAVES._assignments(session, team_id, set(by_id.values())) if by_id else {}
    for item in items:
        if "ticket_key" in item:
            continue
        a = found.get(by_id.get(item["id"]) or "")
        item["ticket_key"] = a.ticket_key if a is not None else None
        item["ticket_url"] = a.ticket_url if a is not None else None


# ----------------------------------------------------------------------------- remediation metrics
def remediation_metrics(items: Iterable[dict[str, Any]], assignments: dict[str, CbomRemediationAssignment],
                        now: _dt.datetime | None = None) -> dict[str, Any]:
    """The code lane's ``get_remediation_metrics`` shape for run assets (``node_items`` items) and their assignments:
    mean time to remediate ([days, hours, minutes] from when the asset was first planned to ``done_at``), Critical
    assets done, assets done in the past 7 days, and the Critical / High backlog (not done, not accepted).
    ``metrics_available`` is False while no assignment of these assets has a ``done_at``."""
    now = now or _utcnow()
    week_ago = now - _dt.timedelta(days=7)
    deltas: list[_dt.timedelta] = []
    critical_fixed = velocity = backlog = 0
    any_done = False
    seen: set[str] = set()
    for item in items:
        key = item.get("asset_key")
        if not key or key in seen:
            continue
        seen.add(key)
        a = assignments.get(key)
        status = a.status if a is not None else "open"
        impact = str(item.get("impact") or "")
        if impact in ("Critical", "High") and status not in ("done", "accepted_risk"):
            backlog += 1
        if a is None or status != "done" or a.done_at is None:
            continue
        any_done = True
        if impact == "Critical":
            critical_fixed += 1
        if a.done_at >= week_ago:
            velocity += 1
        if a.created_at is not None and a.done_at >= a.created_at:
            deltas.append(a.done_at - a.created_at)
    mean = [0, 0, 0]
    if deltas:
        avg = sum(deltas, _dt.timedelta()) / len(deltas)
        mean = [avg.days, avg.seconds // 3600, avg.seconds % 3600 // 60]
    return {"mean_time_to_remediate": mean, "critical_issues_fixed": critical_fixed,
            "remediation_velocity": velocity, "high_priority_backlog": backlog,
            "metrics_available": any_done, "mttr_basis": "assignment_created",
            "computed_at": iso_z(now)}


def run_remediation_metrics(session: Session, team_id: int, run: CbomCollectionRun) -> dict[str, Any]:
    items = WAVES.node_items(session, team_id, run)
    return remediation_metrics(items, WAVES._assignments(session, team_id, (i["asset_key"] for i in items)))


__all__ = ["JiraSettingsBody", "TicketBody", "add_ticket_fields", "create_tickets", "is_ticketable", "project_ref",
           "public_jira_settings", "remediation_metrics", "run_remediation_metrics", "ticket_text"]
