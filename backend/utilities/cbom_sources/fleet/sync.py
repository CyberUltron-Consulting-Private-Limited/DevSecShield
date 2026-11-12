"""Inventory source sync: queue (from the API), claim (one process wins, with a lease), discover without holding a
database session, then upsert in one transaction.  The thread in ``backend/workers/cbom_inventory_sync.py`` runs it.

Only AWS sources sync; CSV, JSON and API sources are written when their data is imported or PUT.
"""
from __future__ import annotations

import datetime as _dt
import time
from typing import Any, Callable

from sqlalchemy import or_, update
from sqlmodel import Session, select

from backend.new_models import CbomCollectionSource
from backend.utilities.cbom_sources.common import iso_z, log, new_ref, utcnow
from backend.utilities.cbom_sources.fleet import evaluate as EVAL
from backend.utilities.cbom_sources.fleet import store
from backend.utilities.cbom_sources.fleet.aws_inventory import AwsInventoryConfig, AwsInventorySource, Discovery
from backend.utilities.cbom_sources.fleet.inventory_sources import InventoryError
from backend.utilities.cbom_sources.fleet.models import CbomInventorySource
from backend.utilities.cbom_sources.settings import get_or_create_settings

LEASE = _dt.timedelta(minutes=30)
# Listing stops (what is left becomes "cancelled") this long after the claim, so the sync saves and releases the
# source before its lease runs out and another worker could claim it.  A call already started can still take its
# retries (about a minute at worst), hence the margin.
SYNC_BUDGET = LEASE - _dt.timedelta(minutes=5)
MIN_EVERY_MIN = 15
_monotonic = time.monotonic


def request_sync(session: Session, source: CbomInventorySource, now: _dt.datetime) -> str:
    sync_id = new_ref()
    source.last_sync_status = "queued"
    source.last_sync_summary = {**(source.last_sync_summary or {}), "sync_id": sync_id, "requested_at": iso_z(now)}
    source.last_updated = now
    session.add(source)
    return sync_id


def due_ids(session: Session, now: _dt.datetime, limit: int = 20) -> list[int]:
    """Sources to sync now, fairest first: one a person queued ("Sync now"), then never synced, then the one that
    waited longest.  Callers take one at a time and ask again, so a long run of syncs never works through a stale
    list and no source starves behind lower ids."""
    s = CbomInventorySource
    rows = session.exec(select(s.id, s.last_sync_status, s.last_sync_at, s.sync_every_min).where(
        s.kind == "aws", s.enabled == True, s.deleted_at.is_(None),  # type: ignore[union-attr]  # noqa: E712
        or_(s.lease_until.is_(None), s.lease_until < now))).all()  # type: ignore[union-attr]
    due = []
    for sid, status, last, every_min in rows:
        every = _dt.timedelta(minutes=max(MIN_EVERY_MIN, int(every_min or 60)))
        if status == "queued" or last is None or last + every <= now:
            due.append((status != "queued", last is not None, last or _dt.datetime.min, sid))
    return [sid for *_rank, sid in sorted(due)[:limit]]


def claim(session: Session, source_id: int, now: _dt.datetime) -> bool:
    s = CbomInventorySource
    won = session.exec(update(s).where(s.id == source_id, s.deleted_at.is_(None),  # type: ignore[call-overload, union-attr]
                                       or_(s.lease_until.is_(None), s.lease_until < now))  # type: ignore[union-attr]
                       .values(lease_until=now + LEASE, last_sync_status="running", last_updated=now)).rowcount
    session.commit()
    return won == 1


def _in_scope(coverage: dict[str, dict[str, str]]) -> Callable[[Any], bool]:
    def check(row: Any) -> bool:  # row = (id, external_id, region, attributes)
        service = (row[3] or {}).get("service") if isinstance(row[3], dict) else None
        return bool(service) and (coverage.get(row[2] or "") or {}).get(service) == "ok"

    return check


def _region_order(regions: list[str], coverage: dict[str, Any]) -> list[str]:
    """Regions the last sync could not finish (cut by its time budget) go first, so the same tail regions are not cut
    on every sync of a large account."""
    cut = [r for r in regions if any(v == "cancelled" for v in (coverage.get(r) or {}).values())]
    return cut + [r for r in regions if r not in cut]


def run_sync(engine, source_id: int, *, now_fn: Callable[[], _dt.datetime] = utcnow,
             discover: Callable[[AwsInventorySource], Discovery] | None = None) -> dict[str, Any]:
    """Claim and sync one AWS inventory source.  Returns the summary (also stored on the source)."""
    now = now_fn()
    with Session(engine) as session:
        if not claim(session, source_id, now):
            return {"status": "busy"}
        src = session.get(CbomInventorySource, source_id)
        team_id = src.team_id
        sync_id = (src.last_sync_summary or {}).get("sync_id") or new_ref()
        try:
            cfg = AwsInventoryConfig.model_validate(src.config or {})
            account = session.get(CbomCollectionSource, cfg.aws_account_source_id)
            if account is None or account.team_id != team_id or account.kind != "aws_account":
                raise InventoryError("no_account", "The AWS account source was not found in this team")
            if account.last_test_status != "passed":
                raise InventoryError("not_validated", "Validate the AWS account first; only a role that passed "
                                                      "validation is read")
            role_arn = str((account.config or {}).get("role_arn") or "")
            external_id = get_or_create_settings(session, team_id).aws_external_id
            previous = dict(src.coverage or {})
            session.commit()
        except (InventoryError, ValueError) as exc:
            return _finish(engine, source_id, now_fn(), "failed", {"sync_id": sync_id, "error": str(exc)[:300]}, {})
    deadline = _monotonic() + SYNC_BUDGET.total_seconds()
    lister = AwsInventorySource(team_id, role_arn, external_id, _region_order(cfg.regions, previous), cfg.services,
                                should_stop=lambda: "out of time" if _monotonic() > deadline else None)
    try:
        if discover is not None:
            result = discover(lister)
        else:
            lister.discover()
            result = lister.result  # type: ignore[assignment]
    except InventoryError as exc:
        return _finish(engine, source_id, now_fn(), "failed", {"sync_id": sync_id, "error": str(exc)[:300]}, {})
    except Exception as exc:
        ref = new_ref()
        log("inventory sync FAILED", ref=ref, team=team_id, source=source_id, error=type(exc).__name__)
        return _finish(engine, source_id, now_fn(), "failed",
                       {"sync_id": sync_id, "error": f"Something went wrong while listing the account (ref {ref})"}, {})
    return save_discovery(engine, source_id, result, now_fn(), sync_id=sync_id)


def save_discovery(engine, source_id: int, result: Discovery, now: _dt.datetime, *, sync_id: str) -> dict[str, Any]:
    """Upsert what a discovery found (snapshot: what disappeared from a completely read scope is marked missing)."""
    with Session(engine) as session:
        src = session.get(CbomInventorySource, source_id)
        team_id = src.team_id
        engine_ = EVAL.inputs(session, team_id, now).engine
        known = store.existing(session, team_id, [t.external_id for t in result.targets])
        room = store.MAX_TARGETS_PER_TEAM - EVAL.target_count(session, team_id)  # the team cap binds a sync too
        counts = store.upsert(session, team_id, src, result.targets, now, engine=engine_, snapshot=True,
                              in_scope=_in_scope(result.coverage), known=known, room=room)
        # the decisions of what changed are stored; the team's counts and managed sources follow on the fleet worker
        EVAL.request(session, team_id, now, evaluation=True, reconcile=True)
        session.commit()
    status = "ok" if result.complete and not result.errors and not counts.errors and not counts.capped else "partial"
    summary = {"sync_id": sync_id, **counts.public(), "errors": (result.errors + counts.errors)[:100],
               "targets": len(result.targets), "account_id": result.account_id}
    if counts.capped:
        summary["capped_reason"] = (f"the team has the most inventory targets it may hold "
                                    f"({store.MAX_TARGETS_PER_TEAM:,}); {counts.capped:,} new ones were not added")
    return _finish(engine, source_id, now, status, summary, result.coverage)


def _finish(engine, source_id: int, now: _dt.datetime, status: str, summary: dict[str, Any],
            coverage: dict[str, Any]) -> dict[str, Any]:
    with Session(engine) as session:
        src = session.get(CbomInventorySource, source_id)
        src.last_sync_status, src.last_sync_at, src.lease_until = status, now, None
        src.last_sync_summary = {**summary, "finished_at": iso_z(now)}
        src.coverage = coverage
        src.last_updated = now
        session.add(src)
        session.commit()
        log("inventory synced", team=src.team_id, source=source_id, status=status,
            created=summary.get("created"), updated=summary.get("updated"), missing=summary.get("missing"))
    return {"status": status, **summary}
