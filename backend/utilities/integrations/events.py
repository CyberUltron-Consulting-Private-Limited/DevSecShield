"""Integration events: one JSON shape for every destination, and the queue they are fanned out into.

Where events come from
* the drift events of WP10 (``CbomDriftEvent``: finding opened / resolved, asset new / removed, certificate renewed /
  expiring, schedule skipped). The dispatcher picks up rows whose ``forwarded_at`` is empty, queues them for every
  enabled integration that subscribes to their kind, and stamps ``forwarded_at`` (``enqueue_drift``);
* "scan finished": a collection run whose drift was recorded (``drift.record_run_drift``) and a CBOM code scan whose
  results were ingested (``drift.on_code_scan_success``) call ``scan_finished`` once.

At least once: every event has an id (``uid``, a UUID v5 of the team and the event's own dedupe key) that is the same
on every retry and for every destination. Receivers drop duplicates by it.
"""
from __future__ import annotations

import datetime as _dt
import uuid
from typing import Any, Iterable

from sqlalchemy import update
from sqlmodel import Session, select

from backend.new_models import CbomDriftEvent, IntegrationDelivery, TeamIntegration
from backend.utilities.cbom_sources.common import iso_z, log

SCHEMA = "zeroshield.cbom.event/1"
_NS = uuid.uuid5(uuid.NAMESPACE_URL, "https://zeroshield.ai/ns/integrations/events")
TYPES: dict[str, str] = {
    "opened": "finding.opened",
    "resolved": "finding.resolved",
    "new_asset": "asset.new",
    "removed_asset": "asset.removed",
    "cert_renewed": "certificate.renewed",
    "cert_expiring": "certificate.expiring",
    "schedule_skipped": "schedule.skipped",
    "scan_finished": "scan.finished",
}
EVENT_KINDS = tuple(TYPES)
SEVERITIES = ("Critical", "High", "Medium", "Low", "Info")
ENQUEUE_BATCH = 1000
_DETAIL_KEYS = ("finding_codes", "type", "location", "target", "changes", "asset_removed", "new_asset", "not_after",
                "bom_ref", "rule_change", "reason", "cause")


def event_uid(*parts: Any) -> str:
    return str(uuid.uuid5(_NS, "|".join(str(p) for p in parts)))


def severity(kind: str, impact: str | None) -> str:
    """Opened findings and expiring certificates carry the finding's impact; everything else is informational."""
    if kind in ("opened", "cert_expiring"):
        return impact if impact in SEVERITIES else ("Medium" if kind == "cert_expiring" else "Low")
    return "Info"


def _kb_title(scope: str, code: str | None) -> str | None:
    if not code:
        return None
    try:
        from backend.utilities.cbom_sources.crypto_kb import entry

        e = entry("node" if scope == "node" else "code", code)
        return str(e["title"]) if e else None
    except Exception:  # an unreadable KB never blocks forwarding
        return None


def drift_payload(e: CbomDriftEvent) -> dict[str, Any]:
    detail = {k: v for k, v in (e.detail or {}).items() if k in _DETAIL_KEYS}
    asset = None
    if e.asset_key:
        asset = {"key": e.asset_key, "label": e.asset_label, "type": detail.get("type"),
                 "target": detail.get("target"), "location": detail.get("location")}
    finding = None
    if e.code:
        finding = {"code": e.code, "title": _kb_title(e.scope, e.code), "impact": e.severity}
    return {
        "schema": SCHEMA, "id": event_uid("drift", e.team_id, e.dedupe_key), "type": TYPES.get(e.kind, e.kind),
        "kind": e.kind, "time": iso_z(e.at), "team_id": e.team_id, "severity": severity(e.kind, e.severity),
        "scope": e.scope, "run_id": e.run_id, "baseline_run_id": e.baseline_run_id, "scan_id": e.scan_id,
        "baseline_scan_id": e.baseline_scan_id,
        "source": {"ref": e.source_ref, "name": e.source_name},
        "asset": asset, "finding": finding, "detail": detail,
    }


def scan_finished_payload(team_id: int, *, scope: str, at: _dt.datetime | None, run_id: int | None = None,
                          scan_id: int | None = None, summary: dict[str, Any] | None = None,
                          source_name: str | None = None) -> dict[str, Any]:
    anchor = f"run:{run_id}" if run_id is not None else f"scan:{scan_id}"
    return {
        "schema": SCHEMA, "id": event_uid("scan_finished", team_id, anchor), "type": TYPES["scan_finished"],
        "kind": "scan_finished", "time": iso_z(at), "team_id": team_id, "severity": "Info", "scope": scope,
        "run_id": run_id, "baseline_run_id": None, "scan_id": scan_id, "baseline_scan_id": None,
        "source": {"ref": anchor, "name": source_name}, "asset": None, "finding": None, "detail": {},
        "summary": summary or {},
    }


def _enabled(session: Session, team_ids: Iterable[int]) -> dict[int, list[TeamIntegration]]:
    ids = sorted(set(team_ids))
    out: dict[int, list[TeamIntegration]] = {t: [] for t in ids}
    if not ids:
        return out
    for row in session.exec(select(TeamIntegration).where(TeamIntegration.team_id.in_(ids),  # type: ignore[attr-defined]
                                                          TeamIntegration.enabled == True)).all():  # noqa: E712
        out.setdefault(row.team_id, []).append(row)
    return out


def subscribed(integration: TeamIntegration, kind: str) -> bool:
    from backend.utilities.integrations.registry import subscribed_kinds

    return kind in subscribed_kinds(integration)


def _insert(session: Session, rows: list[dict[str, Any]]) -> int:
    """INSERT ... ON CONFLICT (integration_id, event_uid) DO NOTHING: queueing an event twice keeps one copy."""
    if not rows:
        return 0
    if session.get_bind().dialect.name == "postgresql":
        from sqlalchemy.dialects.postgresql import insert as dialect_insert
    else:
        from sqlalchemy.dialects.sqlite import insert as dialect_insert
    total = 0
    for start in range(0, len(rows), 500):
        stmt = dialect_insert(IntegrationDelivery.__table__).values(rows[start:start + 500]).on_conflict_do_nothing(
            index_elements=["integration_id", "event_uid"])
        total += int(session.exec(stmt).rowcount or 0)  # type: ignore[call-overload]
    return total


def _rows(integrations: list[TeamIntegration], payloads: list[dict[str, Any]], now: _dt.datetime) -> list[dict]:
    rows = []
    for payload in payloads:
        for integration in integrations:
            if not subscribed(integration, payload["kind"]):
                continue
            rows.append({"team_id": integration.team_id, "integration_id": integration.id, "kind": integration.kind,
                         "event_uid": payload["id"], "event_type": payload["type"], "payload": payload,
                         "status": "pending", "attempts": 0, "created_at": now})
    return rows


def emit(session: Session, team_id: int, payloads: list[dict[str, Any]], now: _dt.datetime) -> int:
    """Queue events for the team's enabled, subscribed integrations (in the caller's transaction). Returns rows queued."""
    integrations = _enabled(session, [team_id]).get(team_id) or []
    return _insert(session, _rows(integrations, payloads, now)) if integrations else 0


def emit_safely(session: Session, team_id: int, payloads: list[dict[str, Any]], now: _dt.datetime) -> int:
    """``emit`` inside a savepoint: a queueing failure is logged and never undoes the caller's own work."""
    try:
        with session.begin_nested():
            return emit(session, team_id, payloads, now)
    except Exception as exc:
        log("integration emit FAILED", team=team_id, error=type(exc).__name__)
        return 0


def enqueue_drift(engine, now: _dt.datetime, *, limit: int = ENQUEUE_BATCH) -> int:
    """Queue drift events not forwarded yet, then stamp ``forwarded_at``. Idempotent under concurrent dispatchers:
    the unique (integration, event) key drops a second copy and the stamp is a compare-and-set."""
    with Session(engine) as session:
        events = list(session.exec(select(CbomDriftEvent).where(CbomDriftEvent.forwarded_at.is_(None))  # type: ignore[union-attr]
                                   .order_by(CbomDriftEvent.id).limit(limit)).all())
        if not events:
            return 0
        by_team = _enabled(session, [e.team_id for e in events])
        rows: list[dict[str, Any]] = []
        for e in events:
            integrations = by_team.get(e.team_id) or []
            if integrations:
                rows += _rows(integrations, [drift_payload(e)], now)
        queued = _insert(session, rows)
        session.exec(update(CbomDriftEvent).where(CbomDriftEvent.id.in_([e.id for e in events]),  # type: ignore[union-attr]
                                                  CbomDriftEvent.forwarded_at.is_(None)).values(forwarded_at=now))  # type: ignore[union-attr]
        session.commit()
    if queued:
        log("integration events queued", events=len(events), deliveries=queued)
    return queued
