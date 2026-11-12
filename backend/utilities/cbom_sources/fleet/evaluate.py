"""Team evaluation: keep every target's stored decision and the per-policy counts current, off the request path for
large teams.

A decision depends on the target and on the team's **inputs**: its policies, credentials, scan nodes, the transports
and SSH CAs its policies use, the never-scan list, and the day (the 7-day rule for targets a sync missed).
``inputs`` hashes them into a digest; the team state row (``CbomFleetTeamState``) keeps the digest of the last
evaluation.  Stored decisions are **stale** when the digests differ or an evaluation was requested (an import, a
delete).

``after_change`` is what every write calls: a team with at most ``CBOM_FLEET_INLINE_EVAL_MAX`` targets (default 2,000;
tens of milliseconds) is re-evaluated in the request, so it sees the new decisions at once; a larger team gets
``eval_requested_at`` and the fleet worker (``run_requested``, on the inventory thread) evaluates it within seconds,
while reads serve the stored decisions marked ``stale``.  With ``CBOM_FLEET_MATERIALIZE`` on, a write also asks for a
reconcile, which the worker runs; a reconcile that had to defer a change to a busy source asks again, so deferred
edits are retried until they are applied.  The worker also re-evaluates (and, with managed sources on, reconciles)
every team it last evaluated a day ago or more, so a target a sync stopped listing leaves collection after its 7 days
without anyone touching the team.
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import json
import os
from dataclasses import dataclass
from typing import Any

from sqlalchemy import func, or_, update
from sqlmodel import Session, select

from backend.utilities.cbom_sources.common import log, new_ref
from backend.utilities.cbom_sources.fleet import flags as FLAGS
from backend.utilities.cbom_sources.fleet import store
from backend.utilities.cbom_sources.fleet.models import CbomFleetPolicy, CbomFleetTeamState, CbomInventoryTarget
from backend.utilities.cbom_sources.fleet.policy import PolicyEngine
from backend.utilities.cbom_sources.fleet.refs import build_refs
from backend.utilities.cbom_sources.settings import get_or_create_settings

LEASE = _dt.timedelta(minutes=10)
RETRY_DEFERRED = _dt.timedelta(seconds=60)
DAILY = _dt.timedelta(days=1)  # the 7-day rule for targets a sync missed moves with time, not with a write


def inline_max() -> int:
    try:
        return max(0, int(os.environ.get("CBOM_FLEET_INLINE_EVAL_MAX", "2000")))
    except ValueError:
        return 2000


@dataclass
class Inputs:
    engine: PolicyEngine
    digest: str
    policies: list[Any]


def inputs(session: Session, team_id: int, now: _dt.datetime) -> Inputs:
    """The team's policy engine and the digest of everything it decides with besides the targets."""
    policies = list(session.exec(select(CbomFleetPolicy).where(CbomFleetPolicy.team_id == team_id)).all())
    settings = get_or_create_settings(session, team_id)
    refs = build_refs(session, team_id, policies)
    engine = PolicyEngine(policies, settings, refs=refs, now=now)
    blob = {
        "policies": sorted([p.id, p.name, bool(p.enabled), p.deleted_at is not None, p.priority, p.selector, p.action]
                           for p in policies),
        "refs": [sorted(refs.credentials.items()), sorted(refs.credential_types.items()),
                 sorted(refs.credential_cas.items(), key=lambda kv: kv[0]), sorted(refs.transports.items()),
                 sorted(refs.cas.items()), sorted(refs.nodes.items())],
        "never_scan": settings.network_exclusions or [],
        "day": now.date().isoformat(),  # the 7-day rule moves with the date
    }
    digest = hashlib.sha256(json.dumps(blob, sort_keys=True, default=str).encode()).hexdigest()
    return Inputs(engine, digest, policies)


def state(session: Session, team_id: int, now: _dt.datetime) -> CbomFleetTeamState:
    row = session.exec(select(CbomFleetTeamState).where(CbomFleetTeamState.team_id == team_id)).first()
    if row is None:
        row = CbomFleetTeamState(team_id=team_id, counts={}, last_reconcile={}, created_at=now, last_updated=now)
        session.add(row)
        session.flush()
    return row


def target_count(session: Session, team_id: int) -> int:
    return int(session.exec(select(func.count()).select_from(CbomInventoryTarget)
                            .where(CbomInventoryTarget.team_id == team_id)).one())


def stale(session: Session, team_id: int, now: _dt.datetime, current: Inputs | None = None) -> bool:
    row = state(session, team_id, now)
    current = current or inputs(session, team_id, now)
    return row.eval_requested_at is not None or row.inputs_digest != current.digest or row.evaluated_at is None


def current_for(session: Session, team_id: int, current: Inputs) -> bool:
    """Whether the stored decisions were made with ``current`` inputs and no evaluation is pending (an import, a
    sync or a delete asks for one), without creating the state row."""
    row = session.exec(select(CbomFleetTeamState).where(CbomFleetTeamState.team_id == team_id)).first()
    return (row is not None and row.evaluated_at is not None and row.eval_requested_at is None
            and row.inputs_digest == current.digest)


def evaluate_team(session: Session, team_id: int, now: _dt.datetime, *, keep_collect: bool = False,
                  current: Inputs | None = None) -> store.Refreshed:
    """Re-evaluate every target and store the decisions, the counts and the digest (not committed).  An evaluation
    requested after ``now`` stays requested."""
    current = current or inputs(session, team_id, now)
    out = store.refresh_decisions(session, team_id, current.engine, keep_collect=keep_collect)
    row = state(session, team_id, now)
    row.inputs_digest, row.evaluated_at, row.counts, row.last_updated = current.digest, now, out.counts, now
    if row.eval_requested_at is not None and row.eval_requested_at <= now:
        row.eval_requested_at = None
    session.add(row)
    return out


def request(session: Session, team_id: int, now: _dt.datetime, *, evaluation: bool = True,
            reconcile: bool = False) -> None:
    row = state(session, team_id, now)
    if evaluation:
        row.eval_requested_at = now
    if reconcile and FLAGS.materialize_enabled():
        row.reconcile_requested_at = row.reconcile_requested_at or now
    row.last_updated = now
    session.add(row)


def after_change(session: Session, team_id: int, now: _dt.datetime, *, reconcile: bool = True) -> dict[str, Any]:
    """What a write calls (not committed): evaluate now if the team is small, else ask the worker; ask for a reconcile
    when managed sources are on.  Returns ``{"evaluation": "done"|"queued", "decisions_changed": n|None}``."""
    request(session, team_id, now, evaluation=False, reconcile=reconcile)
    if target_count(session, team_id) <= inline_max():
        out = evaluate_team(session, team_id, now)
        return {"evaluation": "done", "decisions_changed": out.changed}
    request(session, team_id, now)
    return {"evaluation": "queued", "decisions_changed": None}


def ensure_fresh(session: Session, team_id: int, now: _dt.datetime) -> bool:
    """For reads: evaluate a small stale team in place; ask the worker for a large one.  True if stale after this."""
    current = inputs(session, team_id, now)
    if not stale(session, team_id, now, current):
        return False
    if target_count(session, team_id) <= inline_max():
        evaluate_team(session, team_id, now, current=current)
        return False
    row = state(session, team_id, now)
    if row.eval_requested_at is None:
        request(session, team_id, now)
    return True


def status(row: CbomFleetTeamState, is_stale: bool) -> dict[str, Any]:
    from backend.utilities.cbom_sources.common import iso_z

    return {"evaluated_at": iso_z(row.evaluated_at), "stale": is_stale,
            "evaluation_requested": row.eval_requested_at is not None,
            "reconcile_requested": row.reconcile_requested_at is not None,
            "last_reconcile": dict(row.last_reconcile or {})}


# ----------------------------------------------------------------------------- the worker
def due_teams(session: Session, now: _dt.datetime, limit: int = 20) -> list[int]:
    s = CbomFleetTeamState
    rows = session.exec(select(s.team_id).where(
        or_(s.eval_requested_at.is_not(None), s.reconcile_requested_at <= now,  # type: ignore[union-attr, operator]
            s.evaluated_at.is_(None), s.evaluated_at <= now - DAILY),  # type: ignore[union-attr, operator]
        or_(s.lease_until.is_(None), s.lease_until < now))  # type: ignore[union-attr]
        .order_by(func.coalesce(s.eval_requested_at, s.reconcile_requested_at, s.evaluated_at)).limit(limit)).all()
    return [int(r) for r in rows]


def _claim(session: Session, team_id: int, now: _dt.datetime) -> bool:
    s = CbomFleetTeamState
    won = session.exec(update(s).where(s.team_id == team_id, or_(s.lease_until.is_(None), s.lease_until < now))  # type: ignore[call-overload, union-attr]
                       .values(lease_until=now + LEASE)).rowcount
    session.commit()
    return won == 1


def run_team(engine, team_id: int, now: _dt.datetime) -> dict[str, Any]:
    """Run what the team's state asks for: a reconcile (it re-evaluates too) when managed sources are on and one was
    asked for or the daily pass is due, else an evaluation."""
    with Session(engine) as session:
        if not _claim(session, team_id, now):
            return {"team_id": team_id, "status": "busy"}
    try:
        with Session(engine) as session:
            row = state(session, team_id, now)
            asked = row.reconcile_requested_at
            daily = row.evaluated_at is None or row.evaluated_at <= now - DAILY
            if ((asked is not None and asked <= now) or daily) and FLAGS.materialize_enabled() \
                    and FLAGS.policies_enabled():
                from backend.utilities.cbom_sources.fleet.materialize import reconcile

                result = reconcile(session, team_id, now, actor_id=None)
                row = state(session, team_id, now)
                row.last_reconcile = {**result.public(), "at": now.isoformat(timespec="seconds") + "Z"}
                if result.deferred:  # a busy source: try again once its job may have ended
                    row.reconcile_requested_at = now + RETRY_DEFERRED
                elif row.reconcile_requested_at == asked:
                    row.reconcile_requested_at = None
                out: dict[str, Any] = {"team_id": team_id, "status": "reconciled", **result.public()}
            else:
                if asked is not None and not FLAGS.materialize_enabled():
                    row.reconcile_requested_at = None
                refreshed = evaluate_team(session, team_id, now)
                out = {"team_id": team_id, "status": "evaluated", "decisions_changed": refreshed.changed}
            row.lease_until = None
            session.add(row)
            session.commit()
            return out
    except Exception as exc:
        ref = new_ref()
        log("fleet evaluation FAILED", ref=ref, team=team_id, error=type(exc).__name__)
        with Session(engine) as session:
            session.exec(update(CbomFleetTeamState).where(CbomFleetTeamState.team_id == team_id)  # type: ignore[call-overload]
                         .values(lease_until=None))
            session.commit()
        return {"team_id": team_id, "status": "failed", "ref": ref}


def run_requested(engine, now: _dt.datetime, limit: int = 20) -> list[dict[str, Any]]:
    with Session(engine) as session:
        teams = due_teams(session, now, limit)
    return [run_team(engine, team_id, now) for team_id in teams]
