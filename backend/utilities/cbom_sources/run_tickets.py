"""Jira tickets for the findings of a CBOM Sources run, and the remediation metrics of a run (CB-38 PR-4).

* Credentials: the team's Jira connection (``team.integration_settings["jira"]``, the code lane's, read through
  ``jira_ticketing._jira_creds``); the project and issue type for CBOM Sources are team settings
  (``cbomcollectionsettings.jira_project_key`` / ``jira_issue_type``) that only a team admin changes.
* One ticket per asset across runs: the issue key is stored on the asset's ``CbomRemediationAssignment``, which is keyed
  by the asset's STABLE identity (``identity.stable_key``), so ticketing the same asset from a later run reports the
  existing issue instead of opening another one. On PostgreSQL the assignment row is locked (``FOR UPDATE``) while its
  issue is created, so two concurrent requests for one asset open one issue.
* Partial failure: each asset gets its own Jira call and its own transaction; one refused issue is reported in
  ``failed`` and never loses the others.
* Never logged: credentials, Jira responses, asset text. Logs carry ids and counts only.
"""
from __future__ import annotations

import datetime as _dt
import re
from typing import Any, Iterable, Literal

from fastapi import HTTPException
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import update
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
_PROJECT = re.compile(r"^(?:[A-Z][A-Z0-9_]{1,31}|[1-9][0-9]{0,17})$")
NOT_CONNECTED = "Jira is not connected for this team. A team admin connects it in Team settings → Integrations."
NO_PROJECT = "No Jira project is set for CBOM Sources. A team admin sets it in the Ticketing tab."


# ----------------------------------------------------------------------------- request bodies
class TicketBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    asset_ids: list[int] = Field(min_length=1, max_length=MAX_ASSETS)
    ticket_type: Literal["jira"] = "jira"

    @field_validator("asset_ids")
    @classmethod
    def _ids(cls, v: list[int]) -> list[int]:
        if any(i < 1 or i > 2_147_483_647 for i in v):
            raise ValueError("asset_ids: not an asset id")
        return list(dict.fromkeys(v))


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
            raise ValueError("jira_project_key: use the project key (such as SEC) or the numeric project id")
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


def _error_text(exc: BaseException) -> str:
    text = " ".join(str(exc).split()) or type(exc).__name__
    return _clip(text, ERROR_MAX)


# ----------------------------------------------------------------------------- create
def _locked_assignment(session: Session, team_id: int, item: dict[str, Any], user_id: int,
                       now: _dt.datetime) -> CbomRemediationAssignment:
    """The asset's assignment, write-locked for this transaction until its commit or rollback; created when the asset
    has none yet. An existing row without a ticket is claimed with ``UPDATE … WHERE ticket_key IS NULL`` (a row lock on
    PostgreSQL, the database write lock on SQLite): a concurrent request for the same asset waits for this one, then
    finds the key it stored. A new row is held by its insert (the unique key makes the other insert wait)."""
    model = CbomRemediationAssignment
    query = select(model).where(model.team_id == team_id, model.asset_key == item["asset_key"])
    row = session.exec(query).first()
    if row is None:
        row = model(team_id=team_id, asset_key=item["asset_key"], scope="node",
                    source_ref=str(item["source_ref"])[:255], label=str(item.get("label") or "")[:255] or None,
                    updated_by_user_id=user_id, created_at=now, last_updated=now)
        session.add(row)
        try:
            session.flush()
            return row
        except IntegrityError:  # another request created it first (and has committed): read what it stored
            session.rollback()
            row = session.exec(query).one()
    if row.ticket_key:
        return row
    claimed = session.exec(update(model).where(model.id == row.id, model.ticket_key.is_(None))  # type: ignore
                           .values(last_updated=now).execution_options(synchronize_session=False)).rowcount
    if claimed != 1:  # another request stored a ticket while this one waited
        session.rollback()
        row = session.exec(query).one()
    return row


def create_tickets(engine, team_id: int, user_id: int, run_id: int, body: TicketBody) -> dict[str, Any]:
    now = _dt.datetime.utcnow()
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

    email, token, url = creds
    created: list[dict[str, Any]] = []
    existing: list[dict[str, Any]] = []
    failed: list[dict[str, Any]] = []
    for asset_id, item, detail in work:
        if item is None or detail is None:
            failed.append({"asset_id": asset_id, "asset_key": item["asset_key"] if item else None,
                           "error": "Not a finding: clean inventory and coverage notes are not ticketed"})
            continue
        with Session(engine) as session:
            try:
                row = _locked_assignment(session, team_id, item, user_id, now)
                if row.ticket_key:
                    existing.append({"asset_id": asset_id, "asset_key": item["asset_key"],
                                     "ticket_key": row.ticket_key, "ticket_url": row.ticket_url})
                    session.rollback()
                    continue
                summary, description = ticket_text(run_id, item, detail)
                answer = JIRA.create_issue_in_project(jira_url=url, jira_token=token, summary=summary,
                                                      description=description, jira_email=email,
                                                      issue_type=issue_type, **project_ref(project))
                key = str((answer or {}).get("key") or "").strip()
                if not key:
                    raise ValueError("Jira did not return an issue key")
                row.ticket_key, row.ticket_url = key[:64], f"{url.rstrip('/')}/browse/{key}"[:512]
                row.updated_by_user_id, row.last_updated = user_id, now
                if row.id is not None:
                    row.row_version = (row.row_version or 0) + 1
                session.add(row)
                session.commit()
                created.append({"asset_id": asset_id, "asset_key": item["asset_key"],
                                "ticket_key": row.ticket_key, "ticket_url": row.ticket_url})
            except Exception as exc:  # noqa: BLE001 - one asset's failure never loses the others
                session.rollback()
                log("run ticket FAILED", team=team_id, run=run_id, asset=asset_id, error=type(exc).__name__)
                failed.append({"asset_id": asset_id, "asset_key": item["asset_key"], "error": _error_text(exc)})
    if created:
        from backend.utilities.cbom_sources.common import audit

        with Session(engine) as session:
            audit(session, team_id=team_id, actor_type="user", actor_id=user_id, action="remediation.ticket",
                  object_type="run", object_id=run_id, changed_fields=["ticket_key", "ticket_url"])
            session.commit()
    log("run tickets", team=team_id, run=run_id, created=len(created), existing=len(existing), failed=len(failed),
        by=user_id)
    return {"created": created, "existing": existing, "failed": failed}


# ----------------------------------------------------------------------------- list fields
def add_ticket_fields(session: Session, team_id: int, run: CbomCollectionRun, items: list[dict[str, Any]]) -> None:
    """``ticket_key`` / ``ticket_url`` on each run asset list item (None when the asset has no ticket). Uses the item's
    ``asset_key`` when the list already carries it, else the stable key of the page's assets."""
    missing = [i["id"] for i in items if not i.get("asset_key") and i.get("type") != "coverage"]
    keys = {i["asset_id"]: i["asset_key"] for i in WAVES.node_items(session, team_id, run, asset_ids=missing)} \
        if missing else {}
    for item in items:
        if item.get("asset_key"):
            keys[item["id"]] = item["asset_key"]
    found = WAVES._assignments(session, team_id, set(keys.values()))
    for item in items:
        a = found.get(keys.get(item["id"]) or "")
        item["ticket_key"] = a.ticket_key if a is not None else None
        item["ticket_url"] = a.ticket_url if a is not None else None


# ----------------------------------------------------------------------------- remediation metrics
def remediation_metrics(items: Iterable[dict[str, Any]], assignments: dict[str, CbomRemediationAssignment],
                        now: _dt.datetime | None = None) -> dict[str, Any]:
    """The code lane's ``get_remediation_metrics`` shape for run assets (``node_items`` items) and their assignments:
    mean time to remediate ([days, hours, minutes] from when the asset was first planned to ``done_at``), Critical
    assets done, assets done in the past 7 days, and the Critical / High backlog (not done, not accepted).
    ``metrics_available`` is False while no assignment of these assets has a ``done_at``."""
    now = now or _dt.datetime.utcnow()
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
            "metrics_available": any_done,
            "computed_at": iso_z(now)}


def run_remediation_metrics(session: Session, team_id: int, run: CbomCollectionRun) -> dict[str, Any]:
    items = WAVES.node_items(session, team_id, run)
    return remediation_metrics(items, WAVES._assignments(session, team_id, (i["asset_key"] for i in items)))


__all__ = ["JiraSettingsBody", "TicketBody", "add_ticket_fields", "create_tickets", "is_ticketable", "project_ref",
           "public_jira_settings", "remediation_metrics", "run_remediation_metrics", "ticket_text"]
