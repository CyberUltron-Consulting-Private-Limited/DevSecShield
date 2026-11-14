"""The Q0 gap lifecycle of the team's quantum risk register (CB-23 PR-A; CB-19 PLAN §2.5, §2.6, §2.10).

One ``CbomQ0Gap`` row per *opening* of a Q0 item: open while ``closed_at`` is NULL (at most one open row per team,
kind and key: a partial unique index), closed with a cause and the grade it closed to; a later reopening is a new row
with a new ``opened_at``.

Items and where they come from
* ``evidence``: every E0 evidence area or vendor (``qgrade.evidence_snapshot``, the same function the run snapshot
  and the Evidence tab read; the vendor-area roll-up is not an item). Key ``evidence:area:<key>`` /
  ``evidence:vendor:<id>``; reason ``evidence_e0`` with ``detail.sub_reason``. Synced in the same transaction as every
  evidence write (PATCH area, vendor create / edit / link / answer / delete), by the daily tick (an E2/E3 area turns
  E0 on day 366 with no write, cx3 ST-G) and before the register is read.
* ``scope`` / ``asset`` / ``inputs``: the Q0 items of each source's latest run, graded with the team's inputs now (a
  team view shows the current grade, PLAN §2.3), recorded with the run's drift (``drift.record_run_drift``, inside its
  ``drift_at`` compare-and-set). CB-20's estate store (PR #167) is not on dev yet: when it lands, ``sync_run`` is the
  function to register with ``estate.register_hook(fn, atomic=True)``; until then it reads the run's own rows.

Closing causes: ``evidence`` (an evidence write raised the item above E0), ``removed`` (the vendor or the source was
deleted), ``observation`` (a later comparable collection of the source no longer has it), ``inputs`` (Mosca set),
``model_change`` (the grade model or classifier that recorded it changed and the current one grades it: recorded,
never forwarded). Every other closure stores one ``q0_closed`` drift event (dedupe = register | team | key |
opened_at: one closure per opening), forwarded by the integrations dispatcher like every drift event.
"""
from __future__ import annotations

import base64
import datetime as _dt
import hashlib
import threading
import time
from collections import Counter
from typing import Any, Iterable

from sqlalchemy import text, update
from sqlmodel import Session, select

from backend.new_models import (
    CbomCollectedAsset,
    CbomCollectionJob,
    CbomCollectionRun,
    CbomCollectionSettings,
    CbomCollectionSource,
    CbomEvidenceArea,
    CbomEvidenceVendor,
    CbomQ0Gap,
)
from backend.utilities.cbom_sources.common import iso_z, log

KINDS = ("evidence", "scope", "asset", "inputs")
CAUSES = ("evidence", "removed", "observation", "inputs", "model_change")
NOT_FORWARDED = ("model_change",)
KEY_MAX = 128
EVENT_KEY_MAX = 64  # CbomDriftEvent.asset_key
DETAIL_ADDRESSES = 20
EVERY_S = 3600.0  # the tick re-judges evidence at most hourly per process (day 366 lands within the hour)
_last = 0.0
_lock = threading.Lock()


def _fit(key: str, limit: int) -> str:
    """A key that fits a column: kept when short enough, else a readable prefix and a hash of the whole key."""
    if len(key) <= limit:
        return key
    return key[: limit - 17] + "~" + hashlib.sha256(key.encode("utf-8", "replace")).hexdigest()[:16]


def _date(now: _dt.datetime) -> str:
    return now.date().isoformat()


# ----------------------------------------------------------------------------- open / keep / close
def _open_rows(session: Session, team_id: int, kinds: Iterable[str]) -> dict[tuple[str, str], CbomQ0Gap]:
    rows = session.exec(select(CbomQ0Gap).where(CbomQ0Gap.team_id == team_id,
                                                CbomQ0Gap.item_kind.in_(tuple(kinds)),  # type: ignore[attr-defined]
                                                CbomQ0Gap.closed_at.is_(None))).all()  # type: ignore[union-attr]
    return {(r.item_kind, r.item_key): r for r in rows}


def _insert_open(session: Session, values: dict[str, Any]) -> bool:
    """INSERT ... ON CONFLICT (team, kind, key) WHERE closed_at IS NULL DO NOTHING: two syncs opening the same item
    keep one open row."""
    if session.get_bind().dialect.name == "postgresql":
        from sqlalchemy.dialects.postgresql import insert as dialect_insert
    else:
        from sqlalchemy.dialects.sqlite import insert as dialect_insert
    stmt = dialect_insert(CbomQ0Gap.__table__).values(**values).on_conflict_do_nothing(
        index_elements=["team_id", "item_kind", "item_key"], index_where=text("closed_at IS NULL"))
    return bool(session.exec(stmt).rowcount)  # type: ignore[call-overload]


def _apply(session: Session, team_id: int, now: _dt.datetime, current: dict[tuple[str, str], dict[str, Any]],
           existing: dict[tuple[str, str], CbomQ0Gap], *, closable: set[tuple[str, str]],
           cause_of, run_id: int | None = None) -> dict[str, int]:
    """Open what is new, refresh what is still open, close ``closable`` rows that are no longer current."""
    out = {"opened": 0, "closed": 0, "events": 0}
    for ident, item in current.items():
        row = existing.get(ident)
        if row is None:
            out["opened"] += _insert_open(session, {
                "team_id": team_id, "item_kind": ident[0], "item_key": ident[1], "reason": item["reason"],
                "detail": item["detail"], "opened_at": now, "as_of": _date(now), "last_seen_at": now,
                "run_id": run_id})
            continue
        row.reason, row.detail, row.as_of, row.last_seen_at = item["reason"], item["detail"], _date(now), now
        if run_id is not None:
            row.run_id = run_id
        session.add(row)
    events: list[dict[str, Any]] = []
    for ident, row in existing.items():
        if ident in current or ident not in closable:
            continue
        cause, grade = cause_of(row)
        grade = grade if grade in ("Q1", "Q2", "Q3", "Q4") else None  # still Q0 under another item (inputs:mosca)
        won = session.exec(update(CbomQ0Gap).where(CbomQ0Gap.id == row.id, CbomQ0Gap.closed_at.is_(None))  # type: ignore[union-attr]
                           .values(closed_at=now, close_cause=cause, closed_grade=grade)).rowcount == 1
        if not won:  # another sync closed it first: its closer records the event
            continue
        out["closed"] += 1
        if cause not in NOT_FORWARDED:
            events.append(_closed_event(row, now, cause, grade, run_id))
    if events:
        from backend.utilities.cbom_sources.drift import insert_events

        out["events"] = insert_events(session, events)
    return out


def _closed_event(row: CbomQ0Gap, now: _dt.datetime, cause: str, grade: str | None,
                  run_id: int | None) -> dict[str, Any]:
    from backend.utilities.cbom_sources.drift import dedupe

    detail = row.detail if isinstance(row.detail, dict) else {}
    opened = iso_z(row.opened_at)
    return {"team_id": row.team_id, "at": now, "scope": "register", "kind": "q0_closed",
            # the run is in detail.run_id: a run's own events stay its estate drift (drift tests, run Changes)
            "run_id": None, "baseline_run_id": None, "scan_id": None,
            "baseline_scan_id": None, "source_ref": str(detail.get("source_ref") or "")[:255],
            "source_name": (str(detail["source_name"])[:255] if detail.get("source_name") else None),
            "asset_key": _fit(row.item_key, EVENT_KEY_MAX),
            "asset_label": str(detail.get("title") or detail.get("location") or row.item_key)[:255],
            "code": row.reason[:48], "severity": "Info",
            "detail": {"item_kind": row.item_kind, "item_key": row.item_key, "reason": row.reason,
                       "sub_reason": detail.get("sub_reason"), "cause": cause, "new_grade": grade,
                       "opened_at": opened, "run_id": run_id if run_id is not None else row.run_id},
            "dedupe_key": dedupe("register", row.team_id, row.item_key, opened), "forwarded_at": None}


# ----------------------------------------------------------------------------- evidence items
def evidence_items(session: Session, team_id: int, now: _dt.datetime) -> dict[tuple[str, str], dict[str, Any]]:
    from backend.utilities.cbom_sources.qgrade import evidence_snapshot

    out: dict[tuple[str, str], dict[str, Any]] = {}
    for item in evidence_snapshot(session, team_id, now)["items"]:
        if item["level"] != "E0" or not item.get("reason"):
            continue
        key = _fit(f"evidence:{item['kind']}:{item['key']}", KEY_MAX)
        out[("evidence", key)] = {"reason": "evidence_e0", "detail": {
            "kind": item["kind"], "key": item["key"], "title": item["title"], "sub_reason": item["reason"],
            "detail": item.get("detail"), "level": item["level"], "status": item.get("status"),
            "evidence_date": item.get("evidence_date")}}
    return out


def sync_evidence(session: Session, team_id: int, now: _dt.datetime) -> dict[str, int]:
    """Bring the team's evidence gaps in line with its evidence now. The caller commits (same transaction as the
    evidence write that triggered it)."""
    current = evidence_items(session, team_id, now)
    existing = _open_rows(session, team_id, ("evidence",))
    vendor_ids = {str(v) for v in session.exec(select(CbomEvidenceVendor.id).where(
        CbomEvidenceVendor.team_id == team_id)).all()}

    def cause_of(row: CbomQ0Gap) -> tuple[str, str | None]:
        detail = row.detail if isinstance(row.detail, dict) else {}
        if detail.get("kind") == "vendor" and str(detail.get("key")) not in vendor_ids:
            return "removed", None
        return "evidence", None  # E1..E3: attested without a class is "no grade" (qg-1 rule 3)

    return _apply(session, team_id, now, current, existing, closable=set(existing), cause_of=cause_of)


def sync_evidence_safely(session: Session, team_id: int, now: _dt.datetime) -> None:
    """``sync_evidence`` inside a savepoint: a register failure is logged and never undoes the evidence write (the
    daily tick and the next read bring the register back in line)."""
    try:
        with session.begin_nested():
            out = sync_evidence(session, team_id, now)
        if out["opened"] or out["closed"]:
            log("q0 register evidence synced", team=team_id, **out)
    except Exception as exc:
        log("q0 register evidence sync FAILED", team=team_id, error=type(exc).__name__)


# ----------------------------------------------------------------------------- run items (scope / asset / inputs)
def _run_items(session: Session, run: CbomCollectionRun, risk_model: dict[str, Any]
               ) -> tuple[list[dict[str, Any]], Any, dict[str, str | None]]:
    """Every Q0 item of the run graded with the team's inputs now (the posture loop, without the cap)."""
    from backend.utilities.cbom_sources import identity as ID
    from backend.utilities.cbom_sources import posture as P
    from backend.utilities.cbom_sources import qgrade as QG
    from backend.utilities.cbom_sources.classify import shown

    grades = QG.RunGrades(session, team_id=run.team_id, run_id=run.id, risk_model=risk_model)  # type: ignore[arg-type]
    grades.ctx = grades.ctx.with_inputs(risk_model)  # a team view: the current grade, not the run's record
    grades.now = None
    rows = list(session.exec(select(CbomCollectedAsset).where(CbomCollectedAsset.team_id == run.team_id,
                                                              CbomCollectedAsset.run_id == run.id)).all())
    elsewhere = P.JudgedElsewhere(rows)
    when = _dt.datetime.utcnow()
    graded: dict[str, str | None] = {}
    for row in rows:
        codes = [c for c in shown(row, when)["finding_codes"] if not c.startswith("COVERAGE_")]
        if row.asset_type == "coverage":
            grades.add(row, codes)
            continue
        out = grades.add(row, codes, cls=P.classify_pqc(row, codes, elsewhere=elsewhere)[0])
        uid = grades.ctx._job(row.job_id).source_uid
        graded[_fit("asset:" + ID.stable_key("node", uid, ID.node_identity(row)), KEY_MAX)] = out.q_grade
    scope, _not_items = QG.scope_items(grades.ctx, grades.coverage)
    items = scope + list(grades.assets.by_key.values()) + ([grades._mosca] if grades._mosca else [])
    return items, grades.ctx, graded


def _owned_sources(session: Session, run: CbomCollectionRun) -> tuple[set[int], set[int]]:
    """(sources whose latest synced run is this one, those of them whose collection here is comparable)."""
    from backend.utilities.cbom_sources.drift import job_comparable

    jobs = list(session.exec(select(CbomCollectionJob).where(CbomCollectionJob.run_id == run.id,
                                                             CbomCollectionJob.kind == "collect")).all())
    mine = {j.source_id for j in jobs if j.source_id is not None}
    breakdown = run.breakdown if isinstance(run.breakdown, dict) else {}
    mine |= {e["source_id"] for e in breakdown.get("skipped") or []
             if isinstance(e, dict) and isinstance(e.get("source_id"), int)}
    if mine:  # a newer run already synced owns the source
        newer = session.exec(select(CbomCollectionJob.source_id).join(
            CbomCollectionRun, CbomCollectionRun.id == CbomCollectionJob.run_id).where(  # type: ignore[arg-type]
            CbomCollectionJob.team_id == run.team_id, CbomCollectionJob.kind == "collect",
            CbomCollectionJob.source_id.in_(sorted(mine)),  # type: ignore[union-attr]
            CbomCollectionJob.run_id > run.id, CbomCollectionRun.drift_at.is_not(None))).all()  # type: ignore[union-attr,operator]
        mine -= set(newer)
    comparable = {j.source_id for j in jobs if j.source_id in mine and job_comparable(j)[0]}
    return mine, comparable  # type: ignore[return-value]


def _detail(item: dict[str, Any], ctx: Any, run: CbomCollectionRun) -> dict[str, Any]:
    from backend.utilities.cbom_sources import qgrade as QG

    detail = {k: item.get(k) for k in ("source_id", "source_name", "target", "check", "status", "detail", "count",
                                       "asset_id", "type", "location", "missing") if item.get(k) is not None}
    if isinstance(item.get("addresses"), list):
        detail["addresses"] = item["addresses"][:DETAIL_ADDRESSES]
    job = next((j for j in ctx.jobs.values() if j.source_id is not None and j.source_id == item.get("source_id")), None)
    if job is not None:
        detail["source_ref"] = job.source_uid
    detail["model_version"] = QG.GRADE_MODEL_VERSION
    detail["classifier_version"] = run.classifier_version
    return detail


def sync_run(session: Session, run: CbomCollectionRun, now: _dt.datetime) -> dict[str, int]:
    """Record the scope / asset / inputs Q0 items of a finished run for every source whose latest run it is, and
    close what a comparable collection of those sources no longer has. The caller commits."""
    from backend.utilities.cbom_sources import qgrade as QG

    settings = session.exec(select(CbomCollectionSettings).where(
        CbomCollectionSettings.team_id == run.team_id)).first()
    risk_model = (settings.risk_model if settings is not None else None) or {}
    mine, comparable = _owned_sources(session, run)
    items, ctx, graded = _run_items(session, run, risk_model)
    current: dict[tuple[str, str], dict[str, Any]] = {}
    for item in items:
        kind = item["kind"] if item["kind"] in KINDS else "scope"
        if kind != "inputs" and item.get("source_id") not in mine:
            continue  # another run is that source's latest (or the source was deleted)
        current[(kind, _fit(item["key"], KEY_MAX))] = {"reason": item["reason"], "detail": _detail(item, ctx, run)}
    existing = _open_rows(session, run.team_id, ("scope", "asset", "inputs"))
    sources = {s for s in session.exec(select(CbomCollectionSource.id).where(
        CbomCollectionSource.team_id == run.team_id)).all()}
    mosca_set = all(v is not None for v in QG.mosca_of(risk_model).values())
    closable: set[tuple[str, str]] = set()
    for ident, row in existing.items():
        sid = (row.detail or {}).get("source_id") if isinstance(row.detail, dict) else None
        if ident[0] == "inputs":
            if mosca_set:
                closable.add(ident)
        elif sid not in sources or sid in comparable:
            closable.add(ident)
    def cause_of(row: CbomQ0Gap) -> tuple[str, str | None]:
        detail = row.detail if isinstance(row.detail, dict) else {}
        if row.item_kind == "inputs":
            return "inputs", None
        if detail.get("source_id") not in sources:
            return "removed", None
        if row.item_kind == "asset":
            grade = graded.get(row.item_key)
            if detail.get("model_version") not in (None, QG.GRADE_MODEL_VERSION) or (
                    detail.get("classifier_version") and detail.get("classifier_version") != run.classifier_version):
                return "model_change", grade
            return "observation", grade
        return "observation", None

    out = _apply(session, run.team_id, now, current, existing, closable=closable, cause_of=cause_of, run_id=run.id)
    if out["opened"] or out["closed"]:
        log("q0 register run synced", team=run.team_id, run=run.id, **out)
    return out


def sync_run_safely(session: Session, run: CbomCollectionRun, now: _dt.datetime) -> None:
    try:
        with session.begin_nested():
            sync_run(session, run, now)
    except Exception as exc:
        log("q0 register run sync FAILED", team=run.team_id, run=run.id, error=type(exc).__name__)


def close_removed_sources(session: Session, team_id: int, now: _dt.datetime) -> dict[str, int]:
    """Scope and asset items of a deleted source close as ``removed`` (the tick, and after a source is deleted)."""
    existing = _open_rows(session, team_id, ("scope", "asset"))
    sources = set(session.exec(select(CbomCollectionSource.id).where(CbomCollectionSource.team_id == team_id)).all())
    closable = {i for i, r in existing.items()
                if isinstance(r.detail, dict) and r.detail.get("source_id") is not None
                and r.detail.get("source_id") not in sources}
    return _apply(session, team_id, now, {}, existing, closable=closable, cause_of=lambda _r: ("removed", None))


def close_removed_sources_safely(session: Session, team_id: int, now: _dt.datetime) -> None:
    try:
        with session.begin_nested():
            close_removed_sources(session, team_id, now)
    except Exception as exc:
        log("q0 register removed-source sync FAILED", team=team_id, error=type(exc).__name__)


def close_mosca(session: Session, team_id: int, risk_model: dict[str, Any] | None, now: _dt.datetime) -> None:
    """Settings saved with X, Y and Z all set: the open ``inputs:mosca`` item closes (cause ``inputs``)."""
    from backend.utilities.cbom_sources.qgrade import mosca_of

    if not all(v is not None for v in mosca_of(risk_model).values()):
        return
    try:
        with session.begin_nested():
            existing = _open_rows(session, team_id, ("inputs",))
            _apply(session, team_id, now, {}, existing, closable=set(existing), cause_of=lambda _r: ("inputs", None))
    except Exception as exc:
        log("q0 register inputs sync FAILED", team=team_id, error=type(exc).__name__)


# ----------------------------------------------------------------------------- the daily tick
def _teams(session: Session) -> list[int]:
    ids: set[int] = set()
    for model in (CbomCollectionSettings, CbomEvidenceArea, CbomEvidenceVendor, CbomQ0Gap):
        ids |= set(session.exec(select(model.team_id).distinct()).all())  # type: ignore[attr-defined]
    return sorted(ids)


def tick(engine, now: _dt.datetime) -> dict[str, int]:
    """Re-judge every team's evidence (day 366: an E2/E3 area becomes E0 with no write) and close the items of
    deleted sources; each team in its own transaction (pattern of ``drift.record_pending_drift``)."""
    with Session(engine) as session:
        teams = _teams(session)
    total: Counter[str] = Counter()
    for team_id in teams:
        with Session(engine) as session:
            try:
                total.update(sync_evidence(session, team_id, now))
                total.update(close_removed_sources(session, team_id, now))
                session.commit()
            except Exception as exc:
                session.rollback()
                log("q0 register tick FAILED", team=team_id, error=type(exc).__name__)
    out = {"teams": len(teams), "opened": total["opened"], "closed": total["closed"], "events": total["events"]}
    if out["opened"] or out["closed"]:
        log("q0 register tick", **out)
    return out


def tick_due(engine, now: _dt.datetime) -> dict[str, int] | None:
    """``tick`` at most once per ``EVERY_S`` per process (the scheduler ticks every 30 s)."""
    global _last
    with _lock:
        if time.monotonic() - _last < EVERY_S and _last:
            return None
        _last = time.monotonic()
    return tick(engine, now)


# ----------------------------------------------------------------------------- the register API
STATUSES = ("open", "closed")
LIMIT_MAX = 500


def encode_after(row: CbomQ0Gap) -> str:
    return base64.urlsafe_b64encode(f"{iso_z(row.opened_at)}|{row.id}".encode()).decode().rstrip("=")


def decode_after(value: str) -> tuple[_dt.datetime, int]:
    raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4)).decode()
    when, _sep, ident = raw.partition("|")
    moment = _dt.datetime.fromisoformat(when.replace("Z", "+00:00")).replace(tzinfo=None)
    return moment, int(ident)


def public_gap(row: CbomQ0Gap, now: _dt.datetime) -> dict[str, Any]:
    from backend.utilities.cbom_sources.qgrade import REASONS

    detail = row.detail if isinstance(row.detail, dict) else {}
    end = row.closed_at or now
    return {"id": row.id, "item_kind": row.item_kind, "item_key": row.item_key, "reason": row.reason,
            "reason_text": (REASONS.get(row.reason) or {}).get("text"), "sub_reason": detail.get("sub_reason"),
            "title": detail.get("title") or detail.get("location") or detail.get("target") or row.item_key,
            "source_id": detail.get("source_id"), "source_name": detail.get("source_name"),
            "detail": detail, "status": "open" if row.closed_at is None else "closed",
            "opened_at": iso_z(row.opened_at), "as_of": row.as_of, "last_seen_at": iso_z(row.last_seen_at),
            "closed_at": iso_z(row.closed_at), "close_cause": row.close_cause, "closed_grade": row.closed_grade,
            "forwarded": None if row.closed_at is None else row.close_cause not in NOT_FORWARDED,
            "age_days": max(0, (end - row.opened_at).days), "run_id": row.run_id}


def list_gaps(session: Session, team_id: int, now: _dt.datetime, *, status: str, kind: str | None,
              reason: str | None, after: tuple[_dt.datetime, int] | None, limit: int) -> dict[str, Any]:
    from sqlalchemy import and_, func, or_

    base = [CbomQ0Gap.team_id == team_id,
            CbomQ0Gap.closed_at.is_(None) if status == "open" else CbomQ0Gap.closed_at.is_not(None)]  # type: ignore[union-attr]
    if kind:
        base.append(CbomQ0Gap.item_kind == kind)
    if reason:
        base.append(CbomQ0Gap.reason == reason)
    query = select(CbomQ0Gap).where(*base)
    if after is not None:
        query = query.where(or_(CbomQ0Gap.opened_at < after[0],  # type: ignore[arg-type,operator]
                                and_(CbomQ0Gap.opened_at == after[0], CbomQ0Gap.id < after[1])))  # type: ignore[arg-type,operator]
    rows = list(session.exec(query.order_by(CbomQ0Gap.opened_at.desc(), CbomQ0Gap.id.desc())  # type: ignore[union-attr,attr-defined]
                             .limit(limit + 1)).all())
    more = len(rows) > limit
    rows = rows[:limit]
    by_reason = dict(session.exec(select(CbomQ0Gap.reason, func.count()).where(*base)  # type: ignore[call-overload]
                                  .group_by(CbomQ0Gap.reason)).all())
    counts = {s: session.exec(select(func.count()).select_from(CbomQ0Gap).where(  # type: ignore[call-overload]
        CbomQ0Gap.team_id == team_id,
        CbomQ0Gap.closed_at.is_(None) if s == "open" else CbomQ0Gap.closed_at.is_not(None))).one()  # type: ignore[union-attr]
        for s in STATUSES}
    return {"status": status, "items": [public_gap(r, now) for r in rows],
            "next_after": encode_after(rows[-1]) if more and rows else None,
            "by_reason": dict(sorted(by_reason.items())), "counts": counts, "server_time": iso_z(now),
            "source": "latest_runs"}  # CB-20's estate store is not on dev yet: run items come from each latest run


__all__ = ["sync_evidence", "sync_evidence_safely", "sync_run", "sync_run_safely", "close_removed_sources",
           "close_removed_sources_safely", "close_mosca", "tick", "tick_due", "list_gaps", "public_gap", "encode_after", "decode_after",
           "KINDS", "CAUSES", "STATUSES", "LIMIT_MAX"]
