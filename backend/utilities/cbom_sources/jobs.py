"""Job queue for scan nodes: create, claim, finish, cancel, expire, and run roll-up.

Every state change is a guarded ``UPDATE ... WHERE status = <expected>`` so two requests can never
move the same job twice (two nodes claiming, a cancel racing a claim, a late result after a lease
expired).  Credits are charged and refunded inside the same transaction as the job change.

Scale (F1.1): nothing on the claim, heartbeat or finish path reads every job of a run or a node.  Claims page the
node's pending jobs with ``FOR UPDATE SKIP LOCKED`` (PostgreSQL), a run's status is decided from indexed EXISTS
checks (``recompute_run``), and the reaper fetches only the jobs that need action.
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import json
import os
import secrets
import time
from typing import Any

from fastapi import HTTPException
from sqlalchemy import Boolean, Integer, and_, bindparam, case, delete, func, or_, text, update
from sqlalchemy.orm import aliased
from sqlalchemy.orm.attributes import set_committed_value
from sqlmodel import Session, select

from backend.new_models import (
    CbomCollectedAsset,
    CbomCollectionJob,
    CbomCollectionRun,
    CbomCollectionSettings,
    CbomCollectionSource,
    CbomScanNode,
    Team,
)
from backend.utilities.cbom_sources import capabilities as CAPS
from backend.utilities.cbom_sources import limits as L
from backend.utilities.cbom_sources import secret_refs as SR
from backend.utilities.cbom_sources import billing as BILLING  # CB-14 credit ledger
from backend.utilities.cbom_sources import host_key_resets as HKR  # #150
from backend.utilities.cbom_sources import targets as T
from backend.utilities.cbom_sources.classify import ASSET_TYPES, CDX_TYPE, classify
from backend.utilities.cbom_sources.node_facts import normalise_tls
from backend.utilities.cbom_sources.common import audit, clean_text, log
from backend.utilities.cbom_sources.crypto import scrub
from backend.utilities.cbom_sources.kinds import KINDS, METADATA_FIELDS
from backend.utilities.cbom_sources import ops_metrics as OPS
from backend.utilities.cbom_sources import policy_scope as PS
from backend.utilities.cbom_sources.planning import credits, node_status, team_range_cidrs
from backend.utilities.cbom_sources.settings import get_or_create_settings, team_exclusions, window_allows, window_end

LEASE = _dt.timedelta(minutes=15)  # the default; CBOM_JOB_LEASE_S sets it (``lease()``)


def lease() -> _dt.timedelta:
    """How long a claimed job stays leased without a heartbeat: after that the reaper re-queues it (attempts left)
    and any node that may run it claims it."""
    return _dt.timedelta(seconds=L.lease_seconds())


MAX_ATTEMPTS = 3
TEST_JOB_TTL = _dt.timedelta(hours=24)
COLLECT_JOB_TTL = _dt.timedelta(days=7)
TERMINAL = ("success", "failure", "cancelled", "expired")
OPEN = ("pending", "claimed")
# A job may run at most this long after it was claimed, whatever its lease says.
MAX_RUNTIME = {"test_connection": _dt.timedelta(minutes=20), "collect": _dt.timedelta(hours=8),
               "discovery": _dt.timedelta(hours=8)}
# A claimed job its node no longer reports as running is released after this grace period.
ORPHAN_GRACE = _dt.timedelta(seconds=120)
# A node that does not confirm a requested cancel within this time has the job cancelled for it.
CANCEL_GRACE = _dt.timedelta(minutes=10)
MAX_ASSETS_PER_ATTEMPT = 50_000
TARGET_STATUSES = frozenset({
    "ok", "unreachable", "refused", "timeout", "no_route", "auth_failed", "mfa_required", "host_key_changed",
    "host_key_mismatch", "identity_unverified", "kex_unsupported",
    "sudoers_missing", "sudo_denied", "rbac_denied", "winrm_denied", "tls_unavailable", "not_supported", "error",
    "skipped_never_scan",
    "skipped_window", "skipped_stop", "skipped_deadline", "skipped_cancelled", "skipped_cap",
    "skipped_credential_refused",  # CB-10: the node stopped using a credential after K refused logins in a row
})


def _run_of(session: Session, job: CbomCollectionJob) -> CbomCollectionRun | None:
    return session.get(CbomCollectionRun, job.run_id) if job.run_id else None


# ----------------------------------------------------------------------------- credits
# The team balance is a float column shared with other features (a chat message costs 0.006), so it is not a whole
# number of centi-credits and sums of them carry binary error: 1.0 - 0.01 - 0.06 is 0.92999...  A charge of exactly the
# balance the team sees must still pass; this slack is far below a centi-credit and far above the float error.
_BALANCE_SLACK = 1e-6


def charge_team(session: Session, team_id: int, centi: int) -> bool:
    """Atomic conditional deduction in the caller's transaction."""
    if centi <= 0:
        return True
    amount = centi / 100
    left = Team.credit_balance - amount
    result = session.exec(
        update(Team).where(Team.id == team_id, Team.credit_balance >= amount - _BALANCE_SLACK)
        .values(credit_balance=case((left < 0, 0.0), else_=left))  # never a -0.0000001 balance
    )
    return result.rowcount == 1


def refund_job(session: Session, job: CbomCollectionJob, run: CbomCollectionRun | None = None, *,
               amount: int | None = None, reason: str | None = None) -> int:
    """Owe back a job's credits once: all of its weight, or ``amount`` of it (the runtime-skip share, CB-14).  Returns
    the centi-credits now owed (0 when nothing is owed, or another transaction already owed or refunded them).

    The ledger row (``billing.refund_key``, CB-14) is inserted first and is the exactly-once guard: a retried result,
    a cancel racing the node's result, or the reaper racing a cancel can each try, but only the transaction whose row
    went in marks the job.  No money moves here (F1.1, DA C2): a job end used to UPDATE the run row and then the team
    row inside its own transaction, so every failed job of a large run queued on those two rows.  The job row records
    the amount (``refunded_c``) and ``refund_due``; ``run_closers`` moves the money right after this transaction
    commits (``settle_after_commit``), under the run row it takes without waiting, and the reaper settles whatever
    is left within one pass.  ``refunded`` is set exactly once, by settlement."""
    if job.refunded or job.weight_c <= 0 or job.refund_due:
        return 0
    amount = job.weight_c if amount is None else max(0, min(int(amount), job.weight_c))
    if amount <= 0:
        return 0
    why = reason or {"cancelled": "cancelled", "failure": "failed", "expired": "expired"}.get(job.status, "refund")
    if not BILLING.record(session, team_id=job.team_id, run_id=job.run_id, job_id=job.id, kind="refund", reason=why,
                          amount_c=amount, idem_key=BILLING.refund_key(job.id)):  # type: ignore[arg-type]
        session.expire(job, ["refunded", "refunded_c", "refund_due"])
        log("refund SKIPPED: this job was refunded already", team=job.team_id, run=job.run_id, job=job.id)
        return 0
    changed = session.exec(
        update(CbomCollectionJob)
        .where(CbomCollectionJob.id == job.id, CbomCollectionJob.refunded == False,  # noqa: E712
               CbomCollectionJob.refund_due == False, CbomCollectionJob.weight_c > 0)  # noqa: E712
        .values(refund_due=True, refunded_c=amount).execution_options(synchronize_session=False)
    ).rowcount
    if not changed:
        return 0
    set_committed_value(job, "refund_due", True)
    set_committed_value(job, "refunded_c", amount)
    settle_after_commit(session, job.run_id if job.run_id is not None else None, team_id=job.team_id)
    return amount


def _settle_one(session: Session, run_id: int | None, team_id: int | None) -> tuple[int, int, int | None]:
    """Settle the refund-due jobs of one run (or, ``run_id`` None, a team's jobs that belong to no run).  Returns
    (centi-credits, jobs, team to credit or None when nothing is to be credited)."""
    J_, R_ = CbomCollectionJob.__table__, CbomCollectionRun.__table__
    cond = [J_.c.refund_due == True, J_.c.refunded == False]  # noqa: E712
    cond += [J_.c.run_id == run_id] if run_id is not None else [J_.c.run_id.is_(None), J_.c.team_id == team_id]
    rows = [(int(i), int(c or 0)) for i, c in session.exec(  # type: ignore[call-overload]
        update(J_).where(*cond).values(refunded=True).returning(J_.c.id, J_.c.refunded_c)).all()]
    amount, jobs, team = sum(c for _i, c in rows), len(rows), None
    if amount > 0 and run_id is not None:
        # never refund more than the run was charged (a run is charged exactly the sum of its jobs' weights, so the
        # guard never stops a refund that is due)
        team = session.exec(  # type: ignore[call-overload]
            update(R_).where(R_.c.id == run_id, R_.c.credits_charged_c - R_.c.credits_refunded_c >= amount)
            .values(credits_refunded_c=R_.c.credits_refunded_c + amount).returning(R_.c.team_id)).first()
        team = team[0] if team else None
    elif amount > 0:
        team = team_id
    if jobs and amount > 0 and team is None:
        log("refund SKIPPED: the run has no credits left to refund", run=run_id, amount_c=amount, jobs=jobs)
        ids = [i for i, _c in rows]
        # the ledger and the jobs say what moved: nothing (CB-14)
        session.exec(update(J_).where(J_.c.id.in_(ids)).values(refunded_c=0))  # type: ignore[call-overload]
        session.exec(update(BILLING.CbomCreditEntry).where(  # type: ignore[call-overload]
            BILLING.CbomCreditEntry.idem_key.in_([BILLING.refund_key(i) for i in ids])).values(amount_c=0))  # type: ignore[attr-defined]
        amount = 0
    return amount, jobs, team


def settle_refunds(session: Session, run_ids: Any = None, *, team_ids: Any = None) -> dict[str, int]:
    """Move the money for every refund-due job: per run, one UPDATE flags its jobs refunded exactly once and one raises
    the run's ``credits_refunded_c`` by their owed sum (``refunded_c``) under the charged guard; then one UPDATE per
    team.  Lock order: jobs, runs by id, then teams by id.  ``run_ids`` None = every run with a refund due (the partial
    index), plus jobs that belong to no run; otherwise those runs plus the run-less jobs of ``team_ids``.  The caller
    commits.  Returns {"runs", "jobs", "centi"}."""
    J_ = CbomCollectionJob.__table__
    due = (J_.c.refund_due == True) & (J_.c.refunded == False)  # noqa: E712
    if run_ids is None:
        runs = sorted(int(r) for r in session.exec(  # type: ignore[call-overload]
            select(J_.c.run_id).where(due, J_.c.run_id.is_not(None)).distinct()).all())
        loose_teams = sorted(int(t) for t in session.exec(  # type: ignore[call-overload]
            select(J_.c.team_id).where(due, J_.c.run_id.is_(None)).distinct()).all())
    else:
        runs = sorted({int(r) for r in run_ids if r is not None})
        loose_teams = sorted({int(t) for t in (team_ids or ()) if t is not None})
    credit: dict[int, int] = {}
    total_jobs = total = 0
    for run_id in runs:
        amount, jobs, team = _settle_one(session, run_id, None)
        total_jobs += jobs
        if team is not None and amount > 0:
            credit[team] = credit.get(team, 0) + amount
            total += amount
    for team_id in loose_teams:
        amount, jobs, team = _settle_one(session, None, team_id)
        total_jobs += jobs
        if team is not None and amount > 0:
            credit[team] = credit.get(team, 0) + amount
            total += amount
    for team_id in sorted(credit):
        session.exec(update(Team).where(Team.id == team_id)  # type: ignore[call-overload]
                     .values(credit_balance=Team.credit_balance + credit[team_id] / 100)
                     .execution_options(synchronize_session=False))
    if total_jobs:
        log("refunds settled", runs=len(runs), jobs=total_jobs, refunded_c=total)
    return {"runs": len(runs), "jobs": total_jobs, "centi": total}


def refund_backlog(session: Session) -> int:
    """Refund-due jobs not yet settled (the partial index): the reaper's summary line."""
    J_ = CbomCollectionJob.__table__
    return int(session.exec(select(func.count()).select_from(J_).where(  # type: ignore[call-overload]
        J_.c.refund_due == True, J_.c.refunded == False)).one())  # noqa: E712


def policy_refund_units(job: CbomCollectionJob, result: dict[str, Any]) -> int:
    """CB-11: per-target units charged for targets the never-scan list left out, which the estimate could not
    subtract.  The planner subtracts every listed address and every listed name that is a target itself; a listed
    host NAME that the node resolves to a charged address (R2: ``canary.lab`` -> 10.20.0.8) is known only to the
    node.  Charged units minus the targets the node counted as in scope (counted - excluded) is that number.  Only
    sources charged per target (``unit`` "targets": servers, appliances): a network range is charged per /24 block,
    which one blocked address does not change."""
    params = job.params or {}
    units = params.get("units")
    counts = result.get("counts") if isinstance(result.get("counts"), dict) else {}
    total = counts.get("total")
    if params.get("unit") != "targets" or not isinstance(units, int) or units <= 0 or not isinstance(total, int):
        return 0
    excluded = int(result.get("excluded_by_policy") or 0)
    return max(0, min(units, units - (total - excluded)))


def refund_policy_excluded(session: Session, job: CbomCollectionJob, run: CbomCollectionRun | None,
                           result: dict[str, Any]) -> int:
    """The refund of a collection that ended ``success`` but did not read all it was charged for, in one ledger row
    (``refund_job``): the per-target charge of the never-scan targets ``policy_refund_units`` counts (CB-11; recorded
    in the result as ``policy_refund_c``), plus the runtime-skip share of the rest (CB-14, ``billing.runtime_refund_c``).
    Returns centi-credits refunded."""
    if job.refunded or job.weight_c <= 0:
        return 0
    units = policy_refund_units(job, result)
    policy_c = 0
    if units > 0:
        policy_c = min(job.weight_c, job.weight_c * units // max(int((job.params or {}).get("units") or 1), 1))
    share = BILLING.runtime_refund_c(job.weight_c - policy_c, result)
    amount = min(job.weight_c, policy_c + share)
    if amount <= 0:
        return 0
    if policy_c:
        job.result = {**(job.result or {}), "policy_refund_c": policy_c, "policy_refund_units": units}
        session.add(job)
    refunded = refund_job(session, job, run, amount=amount, reason="runtime_skips" if share else "never_scan")
    if refunded and policy_c:
        log("never-scan targets refunded", team=job.team_id, run=job.run_id, job=job.id, units=units, amount_c=policy_c)
    return refunded


# ----------------------------------------------------------------------------- run status
# A job end does not lock or write the run row (DA C1, Nov 12).  It records the run id on its session
# (``touch_run``); after that transaction commits, ``run_closers`` (called by the node routes in the same session, or
# the session's after_commit hook in a new one) asks one indexed EXISTS question per run and closes a run with no open
# job in a separate short transaction with a guarded UPDATE.  The transaction that commits the run's last open job
# runs its check after every other job end committed, so it sees no open job and closes the run; two checkers that
# both see none race only on the guarded UPDATE, and both would write the same status.  A process that dies between
# the commit and the check leaves the run to ``reconcile_runs`` (the reaper, every 30 s).
_RUNS = "zs_runs_touched"
_SETTLE = "zs_runs_settle"
_SETTLE_TEAMS = "zs_teams_settle"
_AFTER = "zs_log_after_commit"
_DEFER = "zs_closer_in_session"


def touch_run(session: Session, run_id: int | None) -> None:
    if run_id is not None:
        session.info.setdefault(_RUNS, set()).add(int(run_id))


def settle_after_commit(session: Session, run_id: int | None, *, team_id: int | None = None) -> None:
    """Settle this run's refunds right after the commit, not at the next reaper pass (a refund the user sees at once,
    CB-14).  ``run_id`` None with ``team_id``: that team's refund-due jobs that belong to no run."""
    if run_id is not None:
        session.info.setdefault(_SETTLE, set()).add(int(run_id))
    elif team_id is not None:
        session.info.setdefault(_SETTLE_TEAMS, set()).add(int(team_id))


def log_after_commit(session: Session, message: str, **fields: Any) -> None:
    """A log line about a state change, written only once that change is committed (DA §4 item 6)."""
    session.info.setdefault(_AFTER, []).append((message, fields))


def _run_has(session: Session, run_id: int, status: str) -> bool:
    """One indexed probe of (run_id, status): never reads the run's other jobs."""
    return session.exec(select(CbomCollectionJob.id).where(
        CbomCollectionJob.run_id == run_id, CbomCollectionJob.status == status).limit(1)).first() is not None


def _run_open(session: Session, run_id: int) -> bool:
    return session.exec(select(CbomCollectionJob.id).where(
        CbomCollectionJob.run_id == run_id,
        CbomCollectionJob.status.in_(OPEN)).limit(1)).first() is not None  # type: ignore[attr-defined]


def _final_status(session: Session, run_id: int) -> str:
    """The status of a run none of whose jobs is open: one aggregate over its jobs (once per run, at its end)."""
    rows = session.exec(
        select(CbomCollectionJob.status, func.count(),
               func.sum(case((CbomCollectionJob.outcome.in_(("partial", "failed")), 1), else_=0)))  # type: ignore[union-attr]
        .where(CbomCollectionJob.run_id == run_id).group_by(CbomCollectionJob.status)).all()
    counts = {status: int(n) for status, n, _bad in rows}
    bad = sum(int(b or 0) for status, _n, b in rows if status == "success")
    statuses = set(counts)
    if not statuses:
        return "done"
    if statuses == {"success"}:
        return "partial" if bad else "done"
    if statuses == {"cancelled"}:
        return "cancelled"
    if statuses <= {"failure", "expired"}:
        return "failed"
    return "partial"


def close_run(session: Session, run_id: int | None, now: _dt.datetime, *, locked: bool = False) -> str | None:
    """Close the run when none of its jobs is open: one indexed EXISTS probe, then (only then) the run row taken with
    SKIP LOCKED, the final status and a guarded ``UPDATE ... WHERE status IN ('queued','running')``.  Returns the
    status written, or None (still open, closed or being closed by another closer, or gone).  The caller commits."""
    if run_id is None or _run_open(session, run_id):
        return None
    # Several job ends can commit the last open jobs at once and all see none open: the first to take the run row
    # closes it, the others leave it (SKIP LOCKED), so no closer ever waits on another.  A run row held by anything
    # else at that instant (a refund settlement) is closed by the reaper's reconcile_runs within one pass.
    if not locked and session.get_bind().dialect.name == "postgresql":
        free = session.exec(select(CbomCollectionRun.id).where(
            CbomCollectionRun.id == run_id, CbomCollectionRun.status.in_(("queued", "running")))  # type: ignore[attr-defined]
            .with_for_update(skip_locked=True)).first()
        if free is None:
            return None
    final = _final_status(session, run_id)
    changed = session.exec(
        update(CbomCollectionRun)
        .where(CbomCollectionRun.id == run_id, CbomCollectionRun.status.in_(("queued", "running")))  # type: ignore[attr-defined]
        .values(status=final, finished_at=now, last_updated=now)
        .execution_options(synchronize_session=False)).rowcount
    return final if changed == 1 else None


def recompute_run(session: Session, run_id: int | None, now: _dt.datetime) -> CbomCollectionRun | None:
    """Kept for callers outside the job paths: closes the run when nothing is open (``close_run``) and returns it."""
    if run_id is None:
        return None
    close_run(session, run_id, now)
    return session.exec(select(CbomCollectionRun).where(CbomCollectionRun.id == run_id)
                        .execution_options(populate_existing=True)).first()


def _emit(lines: list[tuple[str, dict[str, Any]]]) -> None:
    for message, fields in lines:
        log(message, **fields)


RUN_ROW_TRIES = 4  # SKIP LOCKED attempts on a run row another closer or settler holds, 20-60 ms apart


def _take_run_row(session: Session, run_id: int) -> bool:
    """Lock the run row for this transaction without ever waiting on a lock: ``FOR UPDATE SKIP LOCKED``, retried a
    few times a few tens of ms apart while another closer or settler holds it (their transactions are two short
    UPDATEs).  False: still held, or the run is gone; the reaper's pass then closes and settles it."""
    if session.get_bind().dialect.name != "postgresql":
        return True
    for attempt in range(RUN_ROW_TRIES):
        if session.exec(select(CbomCollectionRun.id).where(CbomCollectionRun.id == run_id)
                        .with_for_update(skip_locked=True)).first() is not None:
            return True
        if attempt + 1 < RUN_ROW_TRIES:
            time.sleep(0.02 * (attempt + 1))
    return False


def run_closers(session: Session, now: _dt.datetime | None = None) -> list[tuple[int, str]]:
    """After a commit: for each run this session's job ends touched, or a refund, user cancel or node deletion asked
    to settle, take the run row (``_take_run_row``: never a lock wait), close the run when none of its jobs is open,
    settle its refund-due jobs, and commit, one run at a time.  Closing and settling in the same step under the same
    row lock means a closer that finds the row held never leaves the run open: the holder settles and closes it, or
    the closer gets the row a moment later.  Then the run-less refunds of ``settle_teams``, and the deferred log
    lines.  Returns [(run id, status)] for the runs closed."""
    session.info.pop(_DEFER, None)
    runs = session.info.pop(_RUNS, None) or set()
    settle = set(session.info.pop(_SETTLE, None) or set())
    settle_teams = set(session.info.pop(_SETTLE_TEAMS, None) or set())
    lines = session.info.pop(_AFTER, None) or []
    _emit(lines)
    if not runs and not settle and not settle_teams:
        return []
    now = now or _dt.datetime.utcnow()
    closed: list[tuple[int, str]] = []
    for run_id in sorted(set(runs) | settle):
        if run_id not in settle and _run_open(session, run_id):
            continue  # nothing to close yet and no money to move: the run row is not even read (DA C1)
        if not _take_run_row(session, run_id):
            log("run closer skipped: the run row stays held (the reaper closes and settles it)", run=run_id)
            continue
        status = close_run(session, run_id, now, locked=True)
        if status is not None:
            closed.append((run_id, status))
        settle_refunds(session, [run_id])  # the row is ours: no other settler moves this run's money now
        session.commit()
    if settle_teams:
        settle_refunds(session, [], team_ids=settle_teams)
    session.info.pop(_AFTER, None)
    session.commit()
    _emit(session.info.pop(_AFTER, None) or [])
    for run_id, status in closed:
        team = session.exec(select(CbomCollectionRun.team_id).where(CbomCollectionRun.id == run_id)).first()
        log("run status", team=team, run=run_id, status=status)
    return closed


def defer_closers(session: Session) -> None:
    """The caller runs ``run_closers`` itself in this session right after its commit (one connection per request)."""
    session.info[_DEFER] = True


def _after_commit(session) -> None:
    if session.info.get(_DEFER):
        return
    if not (session.info.get(_RUNS) or session.info.get(_SETTLE) or session.info.get(_SETTLE_TEAMS)
            or session.info.get(_AFTER)):
        return
    carry = {k: session.info.pop(k) for k in (_RUNS, _SETTLE, _SETTLE_TEAMS, _AFTER) if k in session.info}
    bind = session.get_bind()
    engine = getattr(bind, "engine", bind)
    try:
        with Session(engine) as fresh:
            fresh.info.update(carry)
            run_closers(fresh)
    except Exception as exc:  # the reaper's reconcile_runs and settle pass are the safety net
        log("run closer FAILED", error=type(exc).__name__, runs=sorted(carry.get(_RUNS) or []))


def _after_rollback(session) -> None:
    for key in (_RUNS, _SETTLE, _SETTLE_TEAMS, _AFTER, _DEFER):
        session.info.pop(key, None)


from sqlalchemy import event as _sa_event  # noqa: E402
from sqlalchemy.orm import Session as _SaSession  # noqa: E402

if not _sa_event.contains(_SaSession, "after_commit", _after_commit):
    _sa_event.listen(_SaSession, "after_commit", _after_commit)
    _sa_event.listen(_SaSession, "after_soft_rollback", lambda session, _previous: _after_rollback(session))


def reconcile_runs(session: Session, now: _dt.datetime, team_id: int | None = None, limit: int = 50) -> int:
    """Close runs still marked queued/running that have no open job left (a closer that never ran: the process died
    between a job end's commit and its check).  Returns how many changed; the run ids go to the session's closer
    lines, so their status is logged after the caller commits."""
    open_job = (select(CbomCollectionJob.id).where(CbomCollectionJob.run_id == CbomCollectionRun.id,
                                                   CbomCollectionJob.status.in_(OPEN))  # type: ignore[attr-defined]
                .exists())
    query = select(CbomCollectionRun.id, CbomCollectionRun.team_id).where(
        CbomCollectionRun.status.in_(("queued", "running")), ~open_job)  # type: ignore[attr-defined]
    if team_id is not None:
        query = query.where(CbomCollectionRun.team_id == team_id)
    changed = 0
    for run_id, run_team in session.exec(query.order_by(CbomCollectionRun.id).limit(limit)).all():
        status = close_run(session, run_id, now)
        if status is not None:
            changed += 1
            settle_after_commit(session, run_id)
            log_after_commit(session, "run reconciled", team=run_team, run=run_id, status=status)
    return changed


def mark_run_running(session: Session, run_id: int | None, now: _dt.datetime) -> None:
    """A job of the run was claimed: the run is running (one guarded UPDATE, only the first claim writes, and on
    PostgreSQL no claim waits for another's lock on the run row)."""
    if run_id is None:
        return
    current = session.exec(select(CbomCollectionRun.status).where(CbomCollectionRun.id == run_id)).first()
    if current is None or current == "running":
        return
    target = CbomCollectionRun.id == run_id
    if session.get_bind().dialect.name == "postgresql":
        # EC2 E2a round 7: the first claims of a run all reach this UPDATE together; each waited on the row lock of
        # the first claim's open transaction.  A row someone else is locking is being marked by them: skip it (if
        # that claim rolls back, the next claim marks the run).
        target = CbomCollectionRun.id == select(CbomCollectionRun.id).where(
            CbomCollectionRun.id == run_id).with_for_update(skip_locked=True).scalar_subquery()
    if session.exec(update(CbomCollectionRun)
                    .where(target, CbomCollectionRun.status.in_(("queued",)))  # type: ignore[attr-defined]
                    .values(status="running", last_updated=now, finished_at=None)
                    .execution_options(synchronize_session=False)).rowcount:
        team = session.exec(select(CbomCollectionRun.team_id).where(CbomCollectionRun.id == run_id)).first()
        log_after_commit(session, "run status", team=team, run=run_id, status="running")


# ----------------------------------------------------------------------------- reaper
REAP_BATCH = 500


def _reap_candidates(session: Session, now: _dt.datetime, team_id: int | None, node_id: int | None,
                     limit: int) -> list[CbomCollectionJob]:
    """Only the open jobs a rule may apply to, each set read through its own index: claimed with an expired lease,
    claimed longer than the shortest maximum runtime or with an unconfirmed cancel, a fanned-out AWS parent (its
    slices decide), pending longer than the shortest TTL.  ``_reap_one`` then decides each exactly as before.  (This
    used to load every open job: with an AWS organisation fanned out into thousands of pending slices, loading every
    open job each pass in every replica is the cost.)"""
    from backend.utilities.cbom_sources import slices as S

    claimed = CbomCollectionJob.status == "claimed"

    def scoped(query):
        if team_id is not None:
            query = query.where(CbomCollectionJob.team_id == team_id)
        if node_id is not None:
            query = query.where(CbomCollectionJob.node_id == node_id)
        return query.order_by(CbomCollectionJob.id).limit(limit)

    shortest_runtime = min(MAX_RUNTIME.values())
    queries = [
        select(CbomCollectionJob).where(claimed, CbomCollectionJob.lease_expires_at < now),
        select(CbomCollectionJob).where(claimed, CbomCollectionJob.claimed_at < now - shortest_runtime),
        select(CbomCollectionJob).where(claimed, CbomCollectionJob.cancel_requested_at < now - CANCEL_GRACE),
        select(CbomCollectionJob).where(claimed, CbomCollectionJob.lease_id.like(S.FANOUT_PREFIX + "%")),  # type: ignore[union-attr]
        select(CbomCollectionJob).where(CbomCollectionJob.status == "pending",
                                        CbomCollectionJob.created_at < now - min(TEST_JOB_TTL, COLLECT_JOB_TTL)),
    ]
    seen: dict[int, CbomCollectionJob] = {}
    for query in queries:
        for job in session.exec(scoped(query)).all():
            seen.setdefault(job.id, job)  # type: ignore[arg-type]
    return [seen[k] for k in sorted(seen)]


REAP_COMMIT_EVERY = 50


def reap(session: Session, now: _dt.datetime, *, team_id: int | None = None, node_id: int | None = None,
         limit: int = REAP_BATCH, commit_every: int | None = None, stats: dict[str, int] | None = None) -> int:
    """Apply lease and age rules to the candidates, in id order.  The caller commits; with ``commit_every`` (the
    reaper) the work is also committed every that many moved jobs, so no transaction holds hundreds of job rows.
    Job ends here never touch the run or team rows (refunds are only marked due).  Returns the number of jobs moved;
    ``stats`` (optional) is filled with per-rule counts for the reaper's summary line."""
    from backend.utilities.cbom_sources import slices as S

    moved = 0
    parents: set[int] = set()
    for job in _reap_candidates(session, now, team_id, node_id, limit):
        if job.status == "claimed" and S.is_parent(job):  # a fanned-out AWS collection: its slices decide
            moved += S.reap_parent(session, job, now)
            continue
        if job.parent_job_id is not None:
            parents.add(job.parent_job_id)
        rule = _reap_one(session, job, now)
        if rule:
            moved += 1
            touch_run(session, job.run_id)
            if stats is not None:
                stats[rule] = stats.get(rule, 0) + 1
            if commit_every and moved % commit_every == 0:
                session.commit()
    for parent_id in sorted(parents):  # a slice the reaper ended may have been its parent's last open one
        S.maybe_finalize(session, parent_id, now)
    moved += reconcile_runs(session, now, team_id=team_id)
    return moved


def reap_claimed(session: Session, now: _dt.datetime, jobs: list[CbomCollectionJob]) -> int:
    """The same rules for jobs already loaded (a heartbeat's claimed jobs): no extra query."""
    moved = 0
    for job in sorted(jobs, key=lambda j: j.id or 0):
        if job.status != "claimed":
            continue
        if _reap_one(session, job, now):
            moved += 1
            touch_run(session, job.run_id)
    return moved


def _requeue_node():
    """A job going back to pending: a segment job loses its claimer (any node of the segment may take it), a pinned
    job keeps its node."""
    return case((CbomCollectionJob.node_segment.is_not(None), None), else_=CbomCollectionJob.node_id)  # type: ignore[union-attr]


def _reap_one(session: Session, job: CbomCollectionJob, now: _dt.datetime) -> str | None:
    """Apply the lease and age rules to one job (the caller touches its run).  The rule that moved it, or None."""
    started = job.claimed_at
    too_long = job.status == "claimed" and started is not None and started < now - MAX_RUNTIME.get(job.kind, MAX_RUNTIME["collect"])
    stale_cancel = job.status == "claimed" and job.cancel_requested_at is not None and job.cancel_requested_at < now - CANCEL_GRACE
    if too_long or stale_cancel:
        status = "cancelled" if stale_cancel and not too_long else "failure"
        error = (job.cancel_reason or "Cancelled") if status == "cancelled" else "Stopped: ran longer than the maximum time for this job"
        changed = session.exec(
            update(CbomCollectionJob)
            .where(CbomCollectionJob.id == job.id, CbomCollectionJob.status == "claimed",
                   CbomCollectionJob.lease_id == job.lease_id)
            .values(status=status, finished_at=now, error=error[:1024], lease_id=None, lease_expires_at=None,
                    outcome="failed")
        ).rowcount
        if not changed:
            return None
        session.refresh(job)
        refunded = refund_job(session, job) if job.kind == "collect" else 0
        _test_result_from_job(session, job, now)
        audit(session, team_id=job.team_id, actor_type="system", actor_id=None, action=f"job.{status}",
              object_type="job", object_id=job.id, changed_fields=["max_runtime" if too_long else "cancel"])
        log_after_commit(session, "job stopped", team=job.team_id, job=job.id, node=job.node_id, status=status,
                         reason="max_runtime" if too_long else "cancel_unconfirmed", refund_due_c=refunded)
        return "max_runtime" if too_long else "cancel_unconfirmed"
    if job.status == "claimed" and job.lease_expires_at is not None and job.lease_expires_at < now:
        if job.attempts < MAX_ATTEMPTS:
            target, values = "pending", {"lease_id": None, "lease_expires_at": None, "node_id": _requeue_node()}
        else:
            target, values = "failure", {"finished_at": now, "error": "Scan node stopped responding",
                                         "lease_id": None, "lease_expires_at": None}
        changed = session.exec(
            update(CbomCollectionJob)
            .where(CbomCollectionJob.id == job.id, CbomCollectionJob.status == "claimed",
                   CbomCollectionJob.lease_id == job.lease_id)
            .values(status=target, **values)
        ).rowcount
        if not changed:
            return None
        held_by, claimed_at = job.node_id, job.claimed_at
        session.refresh(job)
        refunded = 0
        if target == "failure" and job.kind == "collect":
            refunded = refund_job(session, job)
        _test_result_from_job(session, job, now)
        audit(session, team_id=job.team_id, actor_type="system", actor_id=None, action=f"job.lease_expired.{target}",
              object_type="job", object_id=job.id)
        OPS.bump(session, OPS.LEASE_EXPIRED[target], now=now)  # cbom_job_lease_expiries_total (CB-31)
        age = int((now - claimed_at).total_seconds()) if claimed_at else None
        if target == "pending":
            log_after_commit(session, "job released", team=job.team_id, job=job.id, node=held_by,
                             reason="lease_expired", claimed_age_s=age, attempt=job.attempts, retry=True)
        else:
            log_after_commit(session, "job lease expired", team=job.team_id, job=job.id, node=held_by,
                             status=target, claimed_age_s=age, attempt=job.attempts, refund_due_c=refunded)
        return "lease_expired"
    if job.status == "pending":
        ttl = COLLECT_JOB_TTL if job.kind in CLOUD_KINDS else TEST_JOB_TTL
        if job.created_at is not None and job.created_at < now - ttl:
            return "expired" if _expire_pending(session, job, now) else None
    return None


def _expire_pending(session: Session, job: CbomCollectionJob, now: _dt.datetime) -> bool:
    """A pending job no node picked up within its TTL: expired, refunded (collect)."""
    changed = session.exec(
        update(CbomCollectionJob)
        .where(CbomCollectionJob.id == job.id, CbomCollectionJob.status == "pending")
        .values(status="expired", finished_at=now, error="No scan node picked this job up in time")
    ).rowcount
    if not changed:
        return False
    session.refresh(job)
    refunded = 0
    if job.kind == "collect":
        refunded = refund_job(session, job)
    _test_result_from_job(session, job, now)
    touch_run(session, job.run_id)
    audit(session, team_id=job.team_id, actor_type="system", actor_id=None, action="job.expired",
          object_type="job", object_id=job.id)
    log_after_commit(session, "job expired", team=job.team_id, job=job.id, node=job.node_id, refund_due_c=refunded)
    return True


def safe_reap(session: Session, now: _dt.datetime, **kwargs: Any) -> None:
    """Reaping on a read path must never fail the read."""
    try:
        reap(session, now, **kwargs)
        # always: a fanned-out parent's lease and "N of M slices" are written without moving any job (#140 review)
        session.commit()
    except Exception as exc:  # pragma: no cover - defensive
        session.rollback()
        log("reap FAILED", error=type(exc).__name__, **{k: v for k, v in kwargs.items() if v is not None})


# ----------------------------------------------------------------------------- versions
def _validated_config(source: CbomCollectionSource) -> Any:
    """The source's config read by its kind's model, or None (unknown kind, or a stored config that no longer
    validates)."""
    spec = KINDS.get(source.kind)
    if spec is None:
        return None
    try:
        return spec.model.model_validate(source.config or {})
    except Exception:
        return None


_UNSET: Any = object()


def connection_version(source: CbomCollectionSource, validated: Any = _UNSET) -> str:
    """What a job depends on, as a hash: where the source points and how it connects (every config field except the
    metadata ones: targets, ports, where-fields, credential type, vault reference, tier, window, exclusions ...), the
    scan node, and the stored credential (a digest of its ciphertext, never the secret).

    ``row_version`` is the EDIT version (a stale form gets a 409, any change bumps it); jobs check this instead, so a
    rename or a metadata edit (business criticality, exposure, owner ...) never cancels a queued or running job.

    The config is hashed as the kind's model reads it (defaults filled in, values normalised), not as stored: a source
    saved before a field existed (AWS decrypt_lambda_cmk / read_glue, Azure credential_type, the AD CS host and port)
    and the same source saved again with that field at its default connect the same way, so they hash the same.  A
    stored config that no longer validates is hashed as stored (such a source's jobs are refused anyway).
    ``validated``: the caller's ``_validated_config(source)``, so a claim reads each config once."""
    model = _validated_config(source) if validated is _UNSET else validated
    raw = model.model_dump(mode="json") if model is not None else (source.config or {})
    config = {k: v for k, v in sorted(raw.items()) if k not in METADATA_FIELDS}
    secret = hashlib.sha256((source.secret_encrypted or "").encode("utf-8")).hexdigest()
    parts: dict[str, Any] = {"kind": source.kind, "node_id": source.node_id, "config": config, "secret": secret}
    # added only when set, so a source without them keeps the version it had (its open jobs stay valid)
    if getattr(source, "node_segment", None):
        parts["node_segment"] = source.node_segment
    extra = SR.version_input(source)
    if extra is not None:
        parts["plugins"] = extra
    blob = json.dumps(parts, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:32]


def metadata_snapshot(source: CbomCollectionSource, node: CbomScanNode | None) -> dict[str, Any]:
    """The source's metadata (and its node's segment) when a run is created; posture scores the run with these."""
    cfg = source.config or {}
    return {**{k: cfg.get(k) for k in METADATA_FIELDS}, "node_segment": node.segment if node else None}


# ----------------------------------------------------------------------------- create
def _snapshot_exclusions(settings: CbomCollectionSettings) -> list[str]:
    return [str(item.get("cidr")) for item in (settings.network_exclusions or []) if isinstance(item, dict)]


def create_test_job(
    session: Session, source: CbomCollectionSource, settings: CbomCollectionSettings, user_id: int, now: _dt.datetime
) -> CbomCollectionJob:
    """Queue a connection test for the source's node and mark the source ``pending``.  Caller commits."""
    cancel_open_jobs(session, source, now, reason="Replaced by a newer connection test", kinds=("test_connection",))
    params: dict[str, Any] = {"exclusions": _snapshot_exclusions(settings), "conn_v": connection_version(source)}
    spec = KINDS[source.kind]
    if spec.group == "servers" or source.kind == "appliance":
        parsed = T.parse_targets((source.config or {}).get("targets") or [], allow_empty=True)
        excl = T.parse_exclusions(((source.config or {}).get("exclusions") or []) + params["exclusions"])
        params["samples"] = T.sample_targets(parsed, excl, 5)
        if not params["samples"]:
            # every target is on a never-scan list (N10): the node still gets a few of them, refuses each one
            # itself (never-scan wins there) and reports why, so the test reads "skipped", never "passed: 0 of 0"
            params["samples"] = parsed.normalized[:5]
    job = CbomCollectionJob(
        team_id=source.team_id, source_id=source.id, node_id=source.node_id, kind="test_connection",
        node_segment=None if source.node_id else source.node_segment,
        params=params, source_version=source.row_version, created_by_user_id=user_id, created_at=now,
    )
    session.add(job)
    session.flush()
    source.last_test_status = "pending"
    source.last_test_job_id = job.id
    source.last_test_summary = "Waiting for the scan node to run the test"
    source.last_test_result = {"samples": [{"target": t, "status": "pending"} for t in params.get("samples", [])]}
    session.add(source)
    return job


def cancel_open_jobs(
    session: Session, source: CbomCollectionSource, now: _dt.datetime, *, reason: str,
    kinds: tuple[str, ...] = ("test_connection", "collect"),
) -> int:
    """Cancel the source's pending jobs (refunding collect jobs) and ask the node to stop claimed ones.

    A claimed job gets ``cancel_requested_at``: the node sees it in its next heartbeat, and its next
    asset batch or result is refused, so nothing collected under the old settings is stored."""
    session.exec(
        update(CbomCollectionJob)
        .where(CbomCollectionJob.source_id == source.id, CbomCollectionJob.status == "claimed",
               CbomCollectionJob.kind.in_(kinds),  # type: ignore[attr-defined]
               CbomCollectionJob.cancel_requested_at.is_(None))  # type: ignore[union-attr]
        .values(cancel_requested_at=now, cancel_reason=reason[:255])
    )
    rows = session.exec(
        select(CbomCollectionJob).where(
            CbomCollectionJob.source_id == source.id, CbomCollectionJob.status == "pending",
            CbomCollectionJob.kind.in_(kinds),  # type: ignore[attr-defined]
        )
    ).all()
    count = 0
    for job in rows:
        changed = session.exec(
            update(CbomCollectionJob).where(CbomCollectionJob.id == job.id, CbomCollectionJob.status == "pending")
            .values(status="cancelled", finished_at=now, error=reason[:1024])
        ).rowcount
        if changed:
            session.refresh(job)
            if job.kind == "collect":
                refund_job(session, job)
            count += 1
            touch_run(session, job.run_id)
            settle_after_commit(session, job.run_id)  # a user action: the refund shows at once
    return count


def stop_discoveries_using(session: Session, source: CbomCollectionSource, now: _dt.datetime, reason: str) -> int:
    """A range was edited, disabled or deleted: ask running discovery sweeps that include it to stop.  Pending
    sweeps are re-checked at claim (``_live_discovery_ranges``), so they only ever sweep ranges that still apply."""
    if source.kind != "network_range":
        return 0
    rows = session.exec(select(CbomCollectionJob).where(
        CbomCollectionJob.team_id == source.team_id, CbomCollectionJob.kind == "discovery",
        CbomCollectionJob.status == "claimed", CbomCollectionJob.cancel_requested_at.is_(None))).all()  # type: ignore[union-attr]
    count = 0
    for job in rows:
        if any(isinstance(r, dict) and r.get("source_id") == source.id for r in (job.params or {}).get("ranges") or []):
            job.cancel_requested_at, job.cancel_reason = now, reason[:255]
            session.add(job)
            count += 1
    return count


def _live_discovery_ranges(session: Session, job: CbomCollectionJob) -> list[dict[str, Any]]:
    """The discovery job's ranges that still exist, are enabled, sit on the job's node and keep the CIDR the SOC
    agreed to when the sweep was queued (mode follows the range's current setting)."""
    live = []
    for r in (job.params or {}).get("ranges") or []:
        if not isinstance(r, dict):
            continue
        src = session.get(CbomCollectionSource, r.get("source_id")) if isinstance(r.get("source_id"), int) else None
        if (src is None or src.team_id != job.team_id or src.kind != "network_range" or not src.enabled
                or src.node_id != job.node_id or (src.config or {}).get("cidr") != r.get("cidr")):
            continue
        live.append({"source_id": src.id, "cidr": r.get("cidr"), "mode": (src.config or {}).get("mode", "full")})
    return live


def create_discovery_jobs(
    session: Session, team_id: int, settings: CbomCollectionSettings, user_id: int, now: _dt.datetime
) -> list[CbomCollectionJob]:
    ranges = session.exec(
        select(CbomCollectionSource).where(
            CbomCollectionSource.team_id == team_id, CbomCollectionSource.kind == "network_range",
            CbomCollectionSource.enabled == True,  # noqa: E712
        )
    ).all()
    by_node: dict[int, list[CbomCollectionSource]] = {}
    for source in ranges:
        if source.node_id:
            by_node.setdefault(source.node_id, []).append(source)
    jobs = []
    for node_id, items in sorted(by_node.items()):
        job = CbomCollectionJob(
            team_id=team_id, node_id=node_id, kind="discovery", created_by_user_id=user_id, created_at=now,
            params={"ranges": [{"source_id": s.id, "cidr": (s.config or {}).get("cidr"),
                                "mode": (s.config or {}).get("mode", "full")} for s in items],
                    "exclusions": _snapshot_exclusions(settings)},
        )
        session.add(job)
        jobs.append(job)
    return jobs


# ----------------------------------------------------------------------------- claim
def _scope_for(job: CbomCollectionJob, source: CbomCollectionSource | None, settings: CbomCollectionSettings,
               now: _dt.datetime | None = None, live_ranges: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    """What the node may touch.  Exclusions are the union of those at job creation and now."""
    exclusions = sorted(set((job.params or {}).get("exclusions") or []) | set(_snapshot_exclusions(settings)))
    scope: dict[str, Any] = {"never_scan": exclusions}
    now = now or _dt.datetime.utcnow()
    scope["max_runtime_s"] = int(MAX_RUNTIME.get(job.kind, MAX_RUNTIME["collect"]).total_seconds())
    ends = None if job.kind == "test_connection" else window_end(_job_window(source, settings), settings.window_timezone, now)
    scope["window_ends_at"] = ends.strftime("%Y-%m-%dT%H:%M:%SZ") if ends else None
    cfg = (source.config or {}) if source else {}
    if source is not None and (KINDS[source.kind].group == "servers" or source.kind == "appliance"):
        scope["targets"] = cfg.get("targets") or []
        scope["never_scan"] = sorted(set(exclusions) | set(cfg.get("exclusions") or []))
        if job.kind == "test_connection":
            scope["targets"] = (job.params or {}).get("samples") or []
    elif source is not None and source.kind == "network_range":
        scope["ranges"] = [{"cidr": cfg.get("cidr"), "mode": cfg.get("mode", "full")}]
    elif job.kind == "discovery":
        scope["ranges"] = live_ranges if live_ranges is not None else (job.params or {}).get("ranges") or []
    if job.kind == "discovery" or (source is not None and source.kind == "network_range"):
        scope["ports"] = settings.ports or []
        scope["sni_hostnames"] = settings.sni_hostnames or []
        scope["rate_limits"] = {
            "connections_per_second": settings.rate_conn_per_s,
            "parallel_per_server": settings.rate_parallel_per_server,
            "handshakes_per_endpoint": settings.rate_handshakes_per_endpoint,
        }
        # settings.zeek_span is not sent: no scan node reads a SPAN port (CB-08; the UI no longer offers it)
    return scope


def _job_window(source: CbomCollectionSource | None, settings: CbomCollectionSettings) -> list[list[bool]] | None:
    if source is not None and KINDS.get(source.kind) and KINDS[source.kind].group == "servers":
        cfg = source.config or {}
        if cfg.get("window") == "any":
            return None
        if cfg.get("window") == "custom":
            return cfg.get("custom_window")
    return settings.scan_window


def _invalid_reason(job: CbomCollectionJob, source: CbomCollectionSource | None, node: CbomScanNode | None) -> str | None:
    """Why a job must not run (or must stop), or None.  ``node`` is None for jobs the cloud worker runs."""
    if job.cancel_requested_at is not None:
        return job.cancel_reason or "Cancelled"
    if node is not None and (node.mode or "agentless") == "agent" and (source is None or source.kind != "host_agent"):
        # an agent-mode node collects only its own host, without credentials (WP8b)
        return "Agent-mode scan nodes collect only their own host"
    if node is not None and (node.mode or "agentless") != "agent" and source is not None and source.kind == "host_agent":
        return "Host agent sources need a scan node in agent mode"
    if job.source_id is None:
        return None if job.kind == "discovery" else "Source no longer exists"
    if source is None or source.team_id != job.team_id:
        return "Source no longer exists"
    if job.node_segment:
        # a segment job: the source must still use that segment, and a node that runs it must be in it
        if source.node_id is not None or source.node_segment != job.node_segment:
            return "Source moved to another scan node"
        if node is not None and (node.segment or "") != job.node_segment:
            return "Source moved to another scan node"
    elif node is not None and source.node_id != node.id:
        return "Source moved to another scan node"
    if node is None and job.node_segment:
        return "This source needs a scan node"
    if node is None and source.node_id is not None and job.node_id is not None:
        return "Source moved to another scan node"
    cfg = _validated_config(source)
    conn_v = (job.params or {}).get("conn_v")
    if conn_v is not None:
        if connection_version(source, cfg) != conn_v:
            return "Source changed after this job was created"
    elif job.source_version is not None and source.row_version != job.source_version:
        return "Source changed after this job was created"  # a job queued before connection versions existed
    if job.kind == "collect" and not source.enabled:
        return "Source was disabled"
    spec = KINDS.get(source.kind)
    if spec is not None:
        if cfg is None:
            return "Source configuration is no longer valid"
        if not spec.collectable(cfg):
            return "Collection for this source is not available"
    return None


CLAIM_PAGE = 50
# The first page of a claim is one row: the oldest runnable candidate usually runs, and every row a page reads stays
# locked (FOR UPDATE) until the claim commits, so 10,000 nodes claiming segment jobs at once each lock one row.
CLAIM_FIRST_PAGE = 1
# The runnable predicate (``_runnable``) already leaves out jobs outside their window, network jobs while network
# scanning is stopped and jobs needing a capability this node lacks, so this bound only covers what SQL cannot see
# (stale sources cancelled on the way, config-dependent capability residue).
CLAIM_SCAN_MAX = 200
PENDING_HINT_CAP = 100
MAX_JOBS_CAP = 8  # a node's ``max_jobs`` (capabilities) is clamped to 1..8 by the server


def _is_agentless(node: CbomScanNode) -> bool:
    return (node.mode or "agentless") != "agent"


def node_max_jobs(node: CbomScanNode) -> int:
    return max_jobs_of(node.capabilities)


def max_jobs_of(capabilities: Any) -> int:
    """The job slots a node says it has (``capabilities.max_jobs``), clamped to 1..8: a forged value buys nothing."""
    caps = capabilities if isinstance(capabilities, dict) else {}
    try:
        value = int(caps.get("max_jobs") or 2)
    except (TypeError, ValueError):
        value = 2
    return max(1, min(value, MAX_JOBS_CAP))


def _pending_query(node: CbomScanNode, segment: bool):
    query = select(CbomCollectionJob).where(CbomCollectionJob.team_id == node.team_id,
                                            CbomCollectionJob.status == "pending")
    if segment:
        return query.where(CbomCollectionJob.node_id.is_(None),  # type: ignore[union-attr]
                           CbomCollectionJob.node_segment == node.segment)
    return query.where(CbomCollectionJob.node_id == node.id)


def takes_segment_jobs(node: CbomScanNode) -> bool:
    """Segment jobs carry decrypted credentials to whichever node of the segment claims them, so only a SIGNED
    agentless node with a segment takes them (security review S3): a token-only node never does."""
    return _is_agentless(node) and bool(node.segment) and bool(node.signing_public_key)


def _segments_of(node: CbomScanNode) -> list[bool]:
    """Which pending sets a node reads: its pinned jobs, then (signed agentless nodes with a segment) its segment's."""
    return [False] + ([True] if takes_segment_jobs(node) else [])


_SERVER_KINDS = tuple(sorted(k for k, spec in KINDS.items() if spec.group == "servers"))


def _local_slot(settings: CbomCollectionSettings, now: _dt.datetime) -> tuple[int, int]:
    import zoneinfo

    try:
        zone = zoneinfo.ZoneInfo(settings.window_timezone or "UTC")
    except Exception:
        zone = zoneinfo.ZoneInfo("UTC")
    local = now.replace(tzinfo=_dt.timezone.utc).astimezone(zone)
    return local.weekday(), local.hour


def _runnable_where(query, *, weekday: int, hour: int, team_open: Any, stop_network: bool, kinds: Any,
                    credentials: Any):
    """The runnable predicate's SQL (``_runnable``) for one team grid slot and one node capability set.
    ``team_open``: the team grid's answer for this slot, a Python bool or a bound parameter."""
    S = CbomCollectionSource
    query = query.outerjoin(S, S.id == CbomCollectionJob.source_id)
    server = S.kind.in_(_SERVER_KINDS)  # type: ignore[attr-defined]
    win = S.config["window"].as_string()  # type: ignore[index]
    cell = S.config[("custom_window", weekday, hour)].as_boolean()  # type: ignore[index]
    window_ok = case(
        (CbomCollectionJob.kind == "test_connection", True),
        (and_(server, win == "any"), True),
        (and_(server, win == "custom"), func.coalesce(cell, True)),
        else_=team_open)
    conds = [window_ok == True]  # noqa: E712
    if stop_network:
        conds += [CbomCollectionJob.kind != "discovery", func.coalesce(S.kind, "") != "network_range"]
    if kinds:
        conds.append(func.coalesce(S.kind, "").not_in(list(kinds)))
    if credentials:
        conds.append(func.coalesce(S.config["credential_type"].as_string(), "").not_in(list(credentials)))  # type: ignore[index]
    return query.where(*conds)


def _runnable(query, node: CbomScanNode, settings: CbomCollectionSettings, now: _dt.datetime):
    """The one runnable predicate the claim page query and the heartbeat hint share (DA D1): the job's scan window is
    open now (a connection test ignores it; a server source may say ``any`` or carry its own grid; everything else
    follows the team grid, evaluated once here for the team's weekday and hour), network jobs only while network
    scanning runs, and only kinds whose required capability this node has.  Rows this rules out are never read
    FOR UPDATE.  ``jobs.window_allows`` / ``_job_window`` are the Python twins (a parity test holds them together)."""
    weekday, hour = _local_slot(settings, now)
    kinds, credentials = CAPS.excluded_for(node)
    return _runnable_where(query, weekday=weekday, hour=hour,
                           team_open=window_allows(settings.scan_window, settings.window_timezone, now),
                           stop_network=bool(settings.stop_all_network), kinds=kinds, credentials=credentials)


_COUNT_STMTS: dict[tuple, Any] = {}
_COUNT_STMTS_MAX = 2048  # (segment, stop, kinds, credentials, weekday, hour): a few hundred in practice


def _count_statement(segment: bool, stop_network: bool, kinds: tuple, credentials: tuple, weekday: int, hour: int):
    """``claimable_count``'s bounded count for one shape, built ONCE and reused with bound values (``zs_team``,
    ``zs_node`` / ``zs_segment``, ``zs_open``, ``zs_cap``): building the runnable predicate and its cache key on every
    heartbeat was over half of an idle heartbeat's CPU (B1 bench profile)."""
    shape = (segment, stop_network, kinds, credentials, weekday, hour)
    stmt = _COUNT_STMTS.get(shape)
    if stmt is not None:
        return stmt
    J_ = CbomCollectionJob
    inner = select(J_.id).where(J_.team_id == bindparam("zs_team"), J_.status == "pending")
    if segment:
        inner = inner.where(J_.node_id.is_(None), J_.node_segment == bindparam("zs_segment"))  # type: ignore[union-attr]
    else:
        inner = inner.where(J_.node_id == bindparam("zs_node"))
    inner = _runnable_where(inner, weekday=weekday, hour=hour, team_open=bindparam("zs_open", type_=Boolean),
                            stop_network=stop_network, kinds=kinds, credentials=credentials)
    stmt = select(func.count()).select_from(inner.limit(bindparam("zs_cap", type_=Integer)).subquery())
    if len(_COUNT_STMTS) >= _COUNT_STMTS_MAX:
        _COUNT_STMTS.clear()
    return _COUNT_STMTS.setdefault(shape, stmt)


def _pending_for_node(session: Session, node: CbomScanNode, settings: CbomCollectionSettings, now: _dt.datetime):
    """The node's runnable pending jobs, oldest first, a page at a time (rows another claim holds are skipped on
    PostgreSQL; only the job rows are locked): first the jobs pinned to it, then its segment's jobs."""
    postgres = session.get_bind().dialect.name == "postgresql"
    seen = 0
    for segment in _segments_of(node):
        last_id, size = 0, CLAIM_FIRST_PAGE
        while seen < CLAIM_SCAN_MAX:
            query = _runnable(_pending_query(node, segment).where(CbomCollectionJob.id > last_id), node, settings, now)
            query = query.order_by(CbomCollectionJob.id).limit(size)
            if postgres:
                query = query.with_for_update(skip_locked=True, of=CbomCollectionJob)
            page = session.exec(query).all()
            if not page:
                break
            for job in page:
                last_id, seen = job.id, seen + 1
                yield job
            size = CLAIM_PAGE


def claimable_count(session: Session, node: CbomScanNode, settings: CbomCollectionSettings | None = None,
                    now: _dt.datetime | None = None, cap: int = PENDING_HINT_CAP) -> int:
    """How many pending jobs this node could run now (pinned, then its segment's), counted up to ``cap`` with the same
    runnable predicate as the claim: the heartbeat's ``pending_jobs`` and the base of its ``claim`` grant.  Bounded
    index reads; jobs outside their window, stopped network jobs and jobs this node lacks a capability for count 0."""
    if settings is None:
        settings = get_or_create_settings(session, node.team_id, commit=False)
    now = now or _dt.datetime.utcnow()
    weekday, hour = _local_slot(settings, now)
    kinds, credentials = CAPS.excluded_for(node)
    params = {"zs_team": node.team_id, "zs_node": node.id, "zs_segment": node.segment,
              "zs_open": bool(window_allows(settings.scan_window, settings.window_timezone, now))}
    total = 0
    for segment in _segments_of(node):
        if total >= cap:
            break
        stmt = _count_statement(segment, bool(settings.stop_all_network), tuple(kinds), tuple(credentials),
                                weekday, hour)
        total += int(session.exec(stmt, params={**params, "zs_cap": cap - total}).one())  # type: ignore[call-overload]
    return min(total, cap)


def claimed_jobs(session: Session, node: CbomScanNode) -> list[CbomCollectionJob]:
    """The jobs this node holds now (one read of the claimed-jobs index), in id order (rows are locked in that order)."""
    return list(session.exec(select(CbomCollectionJob).where(
        CbomCollectionJob.node_id == node.id, CbomCollectionJob.status == "claimed")
        .order_by(CbomCollectionJob.id)).all())


def is_network_job(session: Session, job: CbomCollectionJob) -> bool:
    if job.kind == "discovery":
        return True
    source = session.get(CbomCollectionSource, job.source_id) if job.source_id else None
    return source is not None and source.kind == "network_range"


def node_max_concurrency() -> int:
    """Most collections and discoveries one scan node may hold claimed at once (CBOM_NODE_MAX_CONCURRENCY, default 8:
    the node agent's own ZS_MAX_JOBS ceiling).  Connection tests are not counted: they are short and a customer is
    waiting on them."""
    try:
        value = int(os.environ.get("CBOM_NODE_MAX_CONCURRENCY", "") or 8)
    except ValueError:
        value = 8
    return max(1, min(value, 64))


_CAPPED_KINDS = ("collect", "discovery")
_NODE_CLAIM_LOCK_NS = 0x5A4E  # pg_advisory_xact_lock(namespace, node_id): one claim at a time per node (CB-14 cap)


def _node_busy(node_id: int):
    """Claimed collections and discoveries of a node (a scalar subquery, re-read inside the claiming UPDATE)."""
    return (select(func.count()).select_from(CbomCollectionJob)
            .where(CbomCollectionJob.node_id == node_id, CbomCollectionJob.status == "claimed",
                   CbomCollectionJob.kind.in_(_CAPPED_KINDS))  # type: ignore[attr-defined]
            .scalar_subquery())


def claim_next(session: Session, node: CbomScanNode, settings: CbomCollectionSettings, now: _dt.datetime) -> dict | None:
    """Claim the oldest runnable job for this node and return its payload (with decrypted secrets).

    Jobs that cannot run now (outside their scan window, network scanning stopped, a capability this node lacks) are
    left out by the runnable predicate in SQL, so they are never locked and never hide a newer job that can run (a
    connection test ignores the window).  A segment job is taken with a guarded UPDATE that also sets ``node_id`` to
    this node, so two nodes of the segment can never both claim it.  A node holding ``node_max_concurrency()``
    collections and discoveries gets only connection tests until one ends (CB-14); two claim requests of one node at
    once are serialised by an advisory lock on its id (PostgreSQL; one per node, so 10,000 nodes never share a lock, and
    never the node row a heartbeat writes) and the cap is re-checked inside the claiming UPDATE (exact on SQLite).  Lease expiry of dead nodes' jobs is the
    reaper's; a pending job past its TTL is expired here instead of run.  ``last_claim_at`` is stamped by the caller as
    the claim's last statement (C4)."""
    cap = node_max_concurrency()
    if session.get_bind().dialect.name == "postgresql":
        # two claims of one node are serialised by a transaction-scoped advisory lock on the node id, not by the node
        # row: a heartbeat of the same node updates that row (replay window, last seen) and must never wait while a
        # claim plugin mints a certificate (S-10)
        session.exec(text("SELECT pg_advisory_xact_lock(:ns, :node)").bindparams(  # type: ignore[call-overload]
            ns=_NODE_CLAIM_LOCK_NS, node=int(node.id or 0)))
    full = session.exec(select(_node_busy(node.id))).one() >= cap
    for job in _pending_for_node(session, node, settings, now):
        ttl = COLLECT_JOB_TTL if job.kind in CLOUD_KINDS else TEST_JOB_TTL
        if job.created_at is not None and job.created_at < now - ttl:
            _expire_pending(session, job, now)
            continue
        if full and job.kind in _CAPPED_KINDS:
            continue
        source = session.get(CbomCollectionSource, job.source_id) if job.source_id else None
        reason = _invalid_reason(job, source, node)
        live_ranges = _live_discovery_ranges(session, job) if job.kind == "discovery" else None
        if not reason and live_ranges is not None and not live_ranges:
            reason = "Every range in this discovery was removed, disabled or changed"
        if reason:
            changed = session.exec(
                update(CbomCollectionJob).where(CbomCollectionJob.id == job.id, CbomCollectionJob.status == "pending")
                .values(status="cancelled", finished_at=now, error=reason)
            ).rowcount
            if changed:
                session.refresh(job)
                if job.kind == "collect":
                    refund_job(session, job)
                _test_result_from_job(session, job, now)
                touch_run(session, job.run_id)
                audit(session, team_id=job.team_id, actor_type="system", actor_id=None, action="job.cancelled",
                      object_type="job", object_id=job.id, changed_fields=["stale_source"])
                log_after_commit(session, "job cancelled", team=job.team_id, job=job.id, reason="stale_source")
            continue
        if source is not None and not CAPS.can_run(node, source.kind, source.config):
            continue  # left pending for a node that has the capability (config-dependent residue)
        is_network = job.kind == "discovery" or (source is not None and source.kind == "network_range")
        if is_network and settings.stop_all_network:
            continue
        if job.kind != "test_connection" and not window_allows(_job_window(source, settings), settings.window_timezone, now):
            continue
        lease_id = secrets.token_hex(12)
        held = lease()
        guard = [CbomCollectionJob.id == job.id, CbomCollectionJob.status == "pending"]
        if job.kind in _CAPPED_KINDS:
            guard.append(_node_busy(node.id) < cap)
        values: dict[str, Any] = {"status": "claimed", "lease_id": lease_id, "lease_expires_at": now + held,
                                  "claimed_at": now, "attempts": CbomCollectionJob.attempts + 1, "asset_count": 0,
                                  "outcome": None}
        if job.node_id is None:  # a segment job: this node takes it
            guard.append(CbomCollectionJob.node_id.is_(None))  # type: ignore[union-attr]
            values["node_id"] = node.id
        changed = session.exec(update(CbomCollectionJob).where(*guard).values(**values)).rowcount
        if not changed:
            # lost: another claim took this job (SQLite has no SKIP LOCKED), or one of this node filled its slots
            # meanwhile; only the second ends the search for collections
            if job.kind in _CAPPED_KINDS and session.exec(select(_node_busy(node.id))).one() >= cap:
                full = True
            continue
        session.refresh(job)
        _start_attempt(session, job, now)
        mark_run_running(session, job.run_id, now)
        audit(session, team_id=node.team_id, actor_type="node", actor_id=node.id, action="job.claim",
              object_type="job", object_id=job.id)
        payload: dict[str, Any] = {
            "job": {"id": job.id, "kind": job.kind, "lease_id": lease_id, "lease_seconds": int(held.total_seconds()),
                    "attempt": job.attempts, "run_id": job.run_id},
            "scope": _scope_for(job, source, settings, now, live_ranges),
        }
        if payload["scope"].get("ranges"):
            # N3: each range says which of its addresses are the network/broadcast edges of the networks the team's
            # ranges form together; the node skips exactly those (a node older than this ignores the key and applies
            # its own prefix rule: up to two addresses per range then differ from the counts until it is updated)
            skips = T.SkipMap(team_range_cidrs(session, node.team_id))  # once per claim, whatever the number of ranges
            payload["scope"]["ranges"] = [  # copies: the job's stored params are never changed
                {**item, "skip_addresses": T.range_skip_addresses(str(item["cidr"]), skips=skips)}
                if isinstance(item, dict) and item.get("cidr") else item for item in payload["scope"]["ranges"]]
        if source is not None:
            if _is_agentless(node):
                config, secret_values = SR.source_secrets(session, source, node, now)
            else:  # an agent-mode node is never given a credential, whatever a source holds (WP8b)
                config, secret_values = source.config or {}, {}
            resets = HKR.for_claim(session, source, node.id)  # #150: admins' host key decisions for this node
            if resets:
                config = {**config, "host_key_resets": resets}  # a copy: the stored config is never changed
            payload["source"] = {"id": source.id, "kind": source.kind, "name": source.name, "config": config,
                                 "secrets": secret_values}
        # written only once the claim commits (a claim whose commit fails was never claimed)
        log_after_commit(session, "job claimed", team=job.team_id, run=job.run_id, job=job.id, node=node.id,
                         kind=job.kind, attempt=job.attempts, segment=job.node_segment)
        return payload
    return None


def release_undelivered(session: Session, node_id: int, job_id: int, lease_id: str, now: _dt.datetime) -> bool:
    """A claim whose answer never reached the node (it disconnected before the response was written): hand the job
    straight back, without counting the attempt (DA D3).  The node cannot hold the payload, so this is safe.  The
    caller commits."""
    job = session.get(CbomCollectionJob, job_id)
    if job is None or job.node_id != node_id or job.status != "claimed" or job.lease_id != lease_id:
        return False
    changed = session.exec(
        update(CbomCollectionJob)
        .where(CbomCollectionJob.id == job_id, CbomCollectionJob.status == "claimed",
               CbomCollectionJob.lease_id == lease_id, CbomCollectionJob.node_id == node_id)
        .values(status="pending", lease_id=None, lease_expires_at=None, node_id=_requeue_node(),
                attempts=case((CbomCollectionJob.attempts > 0, CbomCollectionJob.attempts - 1), else_=0))
    ).rowcount
    if changed:
        age = (now - job.claimed_at).total_seconds() if job.claimed_at else None
        log_after_commit(session, "job released", team=job.team_id, job=job_id, node=node_id, reason="undelivered",
                         claimed_age_s=round(age, 3) if age is not None else None,
                         attempt=max(0, (job.attempts or 1) - 1), retry=True)
    return bool(changed)


def requeue_unsigned_segment_jobs(session: Session, node: CbomScanNode, claimed: list[CbomCollectionJob],
                                  now: _dt.datetime) -> list[int]:
    """Segment jobs an unsigned (token-only) node still holds from before segment jobs required signed nodes (S3):
    handed back to the segment (pending, no node, the attempt not counted), never cancelled.  Returns their ids (the
    heartbeat tells the node to stop them)."""
    if takes_segment_jobs(node) or not _is_agentless(node):
        return []
    out: list[int] = []
    for job in claimed:
        if job.status != "claimed" or not job.node_segment:
            continue
        changed = session.exec(
            update(CbomCollectionJob)
            .where(CbomCollectionJob.id == job.id, CbomCollectionJob.status == "claimed",
                   CbomCollectionJob.lease_id == job.lease_id)
            .values(status="pending", lease_id=None, lease_expires_at=None, node_id=None,
                    attempts=case((CbomCollectionJob.attempts > 0, CbomCollectionJob.attempts - 1), else_=0))
        ).rowcount
        if changed:
            set_committed_value(job, "status", "pending")
            out.append(job.id)  # type: ignore[arg-type]
            log_after_commit(session, "job released", team=job.team_id, job=job.id, node=node.id,
                             reason="unsigned_segment", attempt=job.attempts, retry=True)
    return out


def _start_attempt(session: Session, job: CbomCollectionJob, now: _dt.datetime) -> None:
    """A (re)claimed job starts clean: assets from earlier attempts are dropped."""
    if job.first_claimed_at is None:
        job.first_claimed_at = now
        session.add(job)
    if job.attempts > 1:
        session.exec(delete(CbomCollectedAsset).where(CbomCollectedAsset.job_id == job.id,
                                                      CbomCollectedAsset.attempt < job.attempts))


def renew_leases(session: Session, node: CbomScanNode, now: _dt.datetime,
                 running: list[tuple[int, str]] | None = None,
                 claimed: list[CbomCollectionJob] | None = None) -> list[int]:
    """Extend the leases of the jobs the node says it is running.

    ``running`` None (an older node that does not report) renews every claimed job of the node.
    Otherwise only the reported (job, lease) pairs are renewed, and a claimed job the node has stopped
    reporting is released once it is older than the grace period.  Returns the released job ids.
    A lease is only written once less than half of it is left (not on every heartbeat).  ``claimed``: the node's
    claimed jobs when the caller already read them."""
    held = lease()
    if running is None:
        if claimed is not None and not claimed:
            return []  # nothing to renew (the caller read the node's claimed jobs already)
        session.exec(
            update(CbomCollectionJob)
            .where(CbomCollectionJob.node_id == node.id, CbomCollectionJob.status == "claimed")
            .values(lease_expires_at=now + held)
        )
        return []
    reported = {(int(job_id), str(lease_id)) for job_id, lease_id in running}
    released: list[int] = []
    for job in (claimed if claimed is not None else claimed_jobs(session, node)):
        if job.status != "claimed":
            continue
        if (job.id, job.lease_id) in reported:
            if job.lease_expires_at is None or job.lease_expires_at - now < held / 2:
                session.exec(update(CbomCollectionJob)
                             .where(CbomCollectionJob.id == job.id, CbomCollectionJob.lease_id == job.lease_id,
                                    CbomCollectionJob.status == "claimed")
                             .values(lease_expires_at=now + held))
                set_committed_value(job, "lease_expires_at", now + held)  # the caller's later checks see it
            continue
        if job.claimed_at is not None and job.claimed_at > now - ORPHAN_GRACE:
            continue  # claimed moments ago; the node may not have reported it yet
        retry = job.attempts < MAX_ATTEMPTS
        values: dict[str, Any] = {"lease_id": None, "lease_expires_at": None}
        if retry:
            values["node_id"] = _requeue_node()
        else:
            values.update(finished_at=now, error="The scan node stopped running this job", outcome="failed")
        changed = session.exec(
            update(CbomCollectionJob)
            .where(CbomCollectionJob.id == job.id, CbomCollectionJob.status == "claimed",
                   CbomCollectionJob.lease_id == job.lease_id)
            .values(status="pending" if retry else "failure", **values)
        ).rowcount
        if changed:
            claimed_at = job.claimed_at
            session.refresh(job)
            refunded = 0
            if not retry and job.kind == "collect":
                refunded = refund_job(session, job)
            _test_result_from_job(session, job, now)
            audit(session, team_id=job.team_id, actor_type="system", actor_id=None,
                  action="job.released" if retry else "job.failure", object_type="job", object_id=job.id,
                  changed_fields=["not_reported_by_node"])
            log_after_commit(session, "job released", team=job.team_id, job=job.id, node=node.id,
                             reason="not_reported", attempt=job.attempts, retry=retry, refund_due_c=refunded,
                             claimed_age_s=int((now - claimed_at).total_seconds()) if claimed_at else None)
            released.append(job.id)
            touch_run(session, job.run_id)
    return released


def cancel_ids_for_node(session: Session, node: CbomScanNode, settings: CbomCollectionSettings,
                        claimed: list[CbomCollectionJob] | None = None) -> list[int]:
    """Claimed jobs this node should stop: cancel requested, source changed, or network scanning stopped."""
    out: list[int] = []
    for job in (claimed if claimed is not None else claimed_jobs(session, node)):
        if job.status != "claimed":
            continue
        source = session.get(CbomCollectionSource, job.source_id) if job.source_id else None
        is_network = job.kind == "discovery" or (source is not None and source.kind == "network_range")
        if _invalid_reason(job, source, node) or (is_network and settings.stop_all_network):
            out.append(job.id)
    return out


def leased_job(session: Session, node: CbomScanNode | None, job_id: int, lease_id: str,
               team_id: int | None = None) -> CbomCollectionJob:
    """The job ``node`` holds under ``lease_id`` (``node`` None: the cloud worker): 404 when it is not this node's
    job, 409 when the lease is no longer this one (expired, re-queued, finished, cancelled)."""
    job = _owned_job(session, node, job_id, team_id if node is None else node.team_id)
    if job.status != "claimed" or job.lease_id != lease_id:
        raise HTTPException(status_code=409, detail="This job is no longer leased to this node")
    return job
def window_ends_for_node(session: Session, node: CbomScanNode, settings: CbomCollectionSettings,
                         now: _dt.datetime, claimed: list[CbomCollectionJob] | None = None) -> dict[str, str]:
    """For each job the node runs that has a scan window: when that window ends, as ``now`` when it is closed now (N4,
    14 Nov 2026: the customer closed the window while a sweep ran, and the job kept scanning for 156 s).  The node
    moves the job's deadline to it (never later), so the job stops at its next connection with ``skipped_window``
    outcomes for the rest; what it read is kept and refunded by the usual rules.  Connection tests have no window."""
    out: dict[str, str] = {}
    jobs = claimed if claimed is not None else claimed_jobs(session, node)  # the heartbeat's one read (F1.1)
    for job in jobs:
        if job.status != "claimed" or job.kind == "test_connection":
            continue
        source = session.get(CbomCollectionSource, job.source_id) if job.source_id else None
        grid = _job_window(source, settings)
        if not window_allows(grid, settings.window_timezone, now):
            ends: _dt.datetime | None = now
        else:
            ends = window_end(grid, settings.window_timezone, now)
        if ends is not None:
            out[str(job.id)] = ends.strftime("%Y-%m-%dT%H:%M:%SZ")
    return out


# ----------------------------------------------------------------------------- finish
def _test_result_from_job(session: Session, job: CbomCollectionJob, now: _dt.datetime) -> None:
    """Copy a test job's outcome onto its source, but only if it is still the newest test."""
    if job.kind != "test_connection" or job.source_id is None or job.status not in TERMINAL:
        return
    source = session.get(CbomCollectionSource, job.source_id)
    if source is None or source.last_test_job_id != job.id:
        return
    result = job.result or {}
    samples = result.get("samples") if isinstance(result.get("samples"), list) else None
    never = [s for s in samples or [] if isinstance(s, dict) and s.get("status") == "skipped_never_scan"]
    if job.status == "success" and samples and len(never) == len(samples):
        # N10: every target is on the never-scan list: nothing was tested, and nothing failed either
        why = str(never[0].get("note") or never[0].get("error") or "").strip()
        status, summary = "skipped", (f"Skipped: on the never-scan list ({why})" if why else
                                      "Skipped: on the never-scan list")[:512]
    elif job.status == "success" and samples:
        ok = sum(1 for s in samples if isinstance(s, dict) and s.get("status") in ("ready", "ok", "passed"))
        status = "passed" if ok == len(samples) else ("failed" if ok == 0 else "partial")
        summary = f"{ok} of {len(samples)} samples ready"
        silent = all(isinstance(s, dict) and s.get("status") == "unreachable" for s in samples)
        if ok == 0 and silent and source.kind == "network_range":
            # Silence on a few sampled addresses proves nothing about a range: ranges are sparse, and clouds reserve
            # the first addresses of every subnet (AWS .1-.3), which never answer.  Finding the live hosts is the
            # sweep's job, so this must not block collection the way a refused login does.
            status = "partial"
            summary = (f"0 of {len(samples)} sampled addresses answered; the node is running and the range "
                       "will be swept (sparse ranges are normal)")
        notes = [str(s.get("note") or s.get("error") or s.get("status")) for s in samples
                 if isinstance(s, dict) and s.get("status") not in ("ready", "ok", "passed")]
        if notes and not (ok == 0 and silent and source.kind == "network_range"):
            # the first reason, so lists that show only the summary still say why
            summary = f"{summary}: {notes[0]}"[:512]
        warnings = [str(s["warning"]) for s in samples if isinstance(s, dict) and s.get("warning")
                    and s.get("status") in ("ready", "ok", "passed")]
        if warnings and status == "passed":
            # ready, but with something the customer must know (a KMIP server not verified without its CA, #212):
            # partial, never a plain pass; it does not block collection the way a failed test does
            status, summary = "partial", f"{summary}, with a warning: {warnings[0]}"[:512]
    elif job.status == "success" and isinstance(result.get("samples"), list) and job.source_id is not None and (
            source.kind == "network_range" or KINDS[source.kind].group == "servers" or source.kind == "appliance"):
        # a sampled test that sampled nothing proved nothing: never "passed: 0 of 0 samples ready" (N10)
        status, summary = "error", "No target was tested: the scan node had no sample to try"
    elif job.status == "success":
        status, summary = "passed", str(result.get("summary") or "Connection test passed")[:512]
    elif job.status == "cancelled":
        status, summary = "never", (job.error or "Test cancelled")[:512]
    elif job.status == "expired":
        status, summary = "error", "No scan node ran the test within 24 hours"
    else:
        status, summary = "failed", (job.error or str(result.get("summary") or "Connection test failed"))[:512]
    # Compare-and-set on the test the source still points at: an edit that changed the connection at the same time
    # cleared last_test_job_id (and reset the test), and this older result must not be written over that reset.
    session.exec(
        update(CbomCollectionSource)
        .where(CbomCollectionSource.id == source.id, CbomCollectionSource.last_test_job_id == job.id)
        .values(last_test_status=status, last_test_summary=summary, last_test_at=now,
                last_test_result={"samples": samples} if samples else {"summary": summary})
        .execution_options(synchronize_session="fetch")
    )


def _refused_counts(value: Any) -> dict[str, int] | None:
    """The node's ``credential_refused`` report (CB-10), as small whole numbers, or None."""
    if not isinstance(value, dict):
        return None
    out = {}
    for key in ("failures", "skipped", "limit"):
        number = value.get(key)
        out[key] = min(int(number), 1_000_000) if isinstance(number, int) and not isinstance(number, bool) and number >= 0 else 0
    return out if out["failures"] > 0 else None


def credential_refused_summary(refused: dict[str, Any]) -> str:
    """What the source card says (and why its runs are skipped) after the node stopped using the credential."""
    failures, skipped = int(refused.get("failures") or 0), int(refused.get("skipped") or 0)
    head = (f"{failures} logins in a row were refused" if failures > 1 else "the login was refused")
    tail = f"; {skipped} target{'s' if skipped != 1 else ''} not tried" if skipped else ""
    return (f"Credential refused: {head} in job #{refused.get('job_id')}{tail}. Runs and schedules skip this source "
            "until its credential is edited or a connection test passes, so the account is not locked out")


def _credential_refused_from_job(session: Session, job: CbomCollectionJob, status: str, result: Any,
                                 now: _dt.datetime) -> None:
    """CB-10: a collect job whose node stopped using the credential (its breaker tripped, or every login was refused)
    marks the source "credential refused": its connection test becomes failed with the reason, so plan_run skips it
    for manual runs and schedules.  Editing the credential changes the connection version, which resets the test;
    a passing connection test overwrites it.  A job finished under settings that no longer apply ends cancelled
    (finish_job), so a result for an old credential never pauses an edited source."""
    if job.kind != "collect" or status != "success" or job.source_id is None or not isinstance(result, dict):
        return
    refused = _refused_counts(result.get("credential_refused"))
    if refused is None:
        return
    refused["job_id"] = job.id
    summary = credential_refused_summary(refused)[:512]
    session.exec(
        update(CbomCollectionSource).where(CbomCollectionSource.id == job.source_id)
        .values(last_test_status="failed", last_test_summary=summary, last_test_at=now, last_test_job_id=job.id,
                last_test_result={"credential_refused": refused, "summary": summary})
        .execution_options(synchronize_session="fetch")
    )
    audit(session, team_id=job.team_id, actor_type="system", actor_id=None, action="source.credential_refused",
          object_type="source", object_id=job.source_id, changed_fields=[f"job:{job.id}"])
    log("source credential refused", team=job.team_id, source=job.source_id, job=job.id,
        failures=refused["failures"], skipped=refused["skipped"])


def _stop_reason(session: Session, job: CbomCollectionJob, source: CbomCollectionSource | None,
                 node: CbomScanNode | None) -> str | None:
    """_invalid_reason plus the team's network stop, for writes coming back from a running job."""
    reason = _invalid_reason(job, source, node)
    if reason:
        return reason
    is_network = job.kind == "discovery" or (source is not None and source.kind == "network_range")
    if is_network and get_or_create_settings(session, job.team_id, commit=False).stop_all_network:
        return "Network scanning was stopped"
    return None


def _owned_job(session: Session, node: CbomScanNode | None, job_id: int, team_id: int | None) -> CbomCollectionJob:
    job = session.get(CbomCollectionJob, job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Job not found")
    if node is not None and (job.node_id != node.id or job.team_id != node.team_id):
        raise HTTPException(status_code=404, detail="Job not found")
    if node is None and (job.node_id is not None or (team_id is not None and job.team_id != team_id)):
        raise HTTPException(status_code=404, detail="Job not found")
    return job


def _count_field(result: dict[str, Any], name: str) -> int | None:
    """A non-negative integer the node reported, else None (absent, a bool, a string: not trusted as a count)."""
    value = result.get(name)
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else None


def _outcome(job: CbomCollectionJob, status: str, result: dict[str, Any], stored: int,
             read: int | None = None) -> tuple[str, dict[str, Any]]:
    """ok / partial / failed from the node's own target counts and what the server actually stored.  A ``partial``
    target (cloud collectors: read, with coverage gaps) makes the job partial, never ok.  ``read``: the stored rows
    that are assets, not coverage gaps.  When no target counts as read but assets were stored (an Azure subscription
    whose vault listing worked while two vaults refused their keys), something WAS read: partial, never "Nothing
    read"."""
    if status != "success":
        return "failed", {}
    counts = result.get("counts") if isinstance(result.get("counts"), dict) else {}

    def count(name: str) -> int:
        return int(counts.get(name) or 0) if str(counts.get(name, "")).isdigit() else 0

    ok, partial, failed, skipped = count("ok"), count("partial"), count("failed"), count("skipped")
    extra: dict[str, Any] = {}
    # CB-11: a target on the never-scan list is excluded by policy, the customer's choice: it never makes the job
    # partial (nor comparable-or-not, drift.job_comparable).  Only the node's other skips (window, stop, deadline)
    # count as skipped.
    excluded = min(PS.excluded_count(result), skipped)
    if excluded:
        extra["excluded_by_policy"] = excluded
        skipped -= excluded
    reported = result.get("asset_count")
    sent = _count_field(result, "sent")
    if job.kind == "collect" and sent is not None:
        # CB-31 (R4 OBS-5): a node that reports what it sent.  Every asset it sent is stored, a duplicate of one
        # already stored (a retried batch), or lost on the way (``assets_lost``, also the Truncated badge); anything
        # else, assets the server refused among them, is a mismatch the badge must show.
        duplicate = _count_field(result, "duplicate") or 0
        lost = _count_field(result, "assets_lost") or 0
        expected = sent - duplicate - lost
        if expected != stored:
            extra["asset_mismatch"] = {"reported": expected, "stored": stored, "sent": sent, "duplicate": duplicate,
                                       "rejected": _count_field(result, "rejected") or 0, "lost": lost}
    elif job.kind == "collect" and isinstance(reported, int) and reported != stored:  # an older node
        extra["asset_mismatch"] = {"reported": reported, "stored": stored}
    if not counts:
        return ("partial" if extra or result.get("truncated") else "ok"), extra
    if ok == 0 and partial == 0 and (failed or skipped or excluded):
        return ("partial" if read else "failed"), extra
    if partial or failed or skipped or extra.keys() - {"excluded_by_policy"} or result.get("truncated"):
        return "partial", extra
    return "ok", extra


def finish_job(
    session: Session, node: CbomScanNode | None, job_id: int, lease_id: str, status: str,
    result: dict[str, Any] | None, error: str | None, now: _dt.datetime, *, team_id: int | None = None,
    known_secrets: list[str] | None = None,
) -> CbomCollectionJob:
    """Record a job's end.  ``node`` None is the cloud worker.  Failed or cancelled collect jobs are refunded."""
    job = _owned_job(session, node, job_id, team_id)
    if job.kind == "slice":  # F1 cloud pool: the slice ends; its parent ends with the last one (cbom_sources.slices)
        from backend.utilities.cbom_sources import slices as S

        return S.finish_slice(session, job, lease_id, status, result, error, now, known_secrets=known_secrets)
    source = session.get(CbomCollectionSource, job.source_id) if job.source_id else None
    known = SR.known_secrets(session, source)
    known += [s for s in (known_secrets or []) if isinstance(s, str)]
    clean_result = scrub(result or {}, known, exact_keys=True)
    clean_error = scrub(error, known) if error else None
    invalid = _stop_reason(session, job, source, node) if job.status == "claimed" and job.lease_id == lease_id else None
    if invalid and status == "success":
        status, clean_error = "cancelled", invalid  # collected under settings that no longer apply
    stored = session.exec(select(func.count()).select_from(CbomCollectedAsset).where(
        CbomCollectedAsset.job_id == job.id, CbomCollectedAsset.attempt == job.attempts)).one()
    # coverage rows say what was NOT read: they never make a job "read something" (outcome, refund)
    read = session.exec(select(func.count()).select_from(CbomCollectedAsset).where(
        CbomCollectedAsset.job_id == job.id, CbomCollectedAsset.attempt == job.attempts,
        CbomCollectedAsset.asset_type != "coverage")).one()
    outcome, extra = _outcome(job, status, clean_result if isinstance(clean_result, dict) else {}, int(stored), int(read))
    if extra and isinstance(clean_result, dict):
        clean_result = {**clean_result, **extra}
    if isinstance(clean_result, dict):
        clean_result["stored_asset_count"] = int(stored)
    changed = session.exec(
        update(CbomCollectionJob)
        .where(CbomCollectionJob.id == job_id,
               (CbomCollectionJob.node_id == node.id) if node is not None else CbomCollectionJob.node_id.is_(None),  # type: ignore[union-attr]
               CbomCollectionJob.status == "claimed", CbomCollectionJob.lease_id == lease_id)
        .values(status=status, finished_at=now, result=clean_result, outcome=outcome, asset_count=int(stored),
                error=(str(clean_error)[:1024] if clean_error else None), lease_id=None, lease_expires_at=None)
    ).rowcount
    if not changed:
        raise HTTPException(status_code=409, detail="This job is no longer leased to this node")
    session.refresh(job)
    refunded = 0
    # "failed" outcome on a success status with nothing read = every target was skipped (never-scan, window, stop,
    # deadline) or refused: nothing was collected, so it is refunded like a failure.  Coverage rows (what was not
    # read, and why) are not a collection: a job that stored only those is refunded too.  Refunds are marked due on
    # the job row and settled right after the commit (F1.1 DA C2), so a job end never locks the run or team row.
    if job.kind == "collect" and (status in ("failure", "cancelled") or (outcome == "failed" and int(read) == 0)):
        refunded = refund_job(session, job, reason="nothing_read" if status == "success" else None)
    elif job.kind == "collect" and status == "success" and isinstance(clean_result, dict):
        # partly read: never-scan targets the estimate could not subtract (CB-11), and the targets skipped at runtime
        # or whose credential was refused (CB-14, OA-10b), are not charged
        refunded = refund_policy_excluded(session, job, None, clean_result)
    _test_result_from_job(session, job, now)
    _credential_refused_from_job(session, job, status, clean_result, now)
    if node is not None:  # #150: the host key decisions the node applied in this job
        HKR.applied(session, job, node.id, clean_result if isinstance(clean_result, dict) else None, now)
    touch_run(session, job.run_id)
    audit(session, team_id=job.team_id, actor_type="node" if node else "system", actor_id=node.id if node else None,
          action=f"job.{status}", object_type="job", object_id=job.id)
    counts = clean_result.get("counts") if isinstance(clean_result, dict) and isinstance(clean_result.get("counts"), dict) else {}
    duration = int((now - job.claimed_at).total_seconds()) if job.claimed_at else None
    log("job finished", team=job.team_id, run=job.run_id, job=job.id, node=node.id if node else "cloud", kind=job.kind,
        attempt=job.attempts, status=status, outcome=outcome, ok=counts.get("ok"), failed=counts.get("failed"),
        skipped=counts.get("skipped"), assets=int(stored), duration_s=duration, refund_due_c=refunded)
    return job


# ----------------------------------------------------------------------------- assets
def _san_name(asset_type: str, facts: dict[str, Any]) -> str | None:
    """CB-17: a certificate with an empty subject (SAN-only, as CA/B Forum allows) is named by its first SAN."""
    if CDX_TYPE.get(asset_type) != "certificate":
        return None
    san = facts.get("san")
    first = san[0] if isinstance(san, list) and san else None
    return clean_text(first, 255) if isinstance(first, str) and first.strip() else None


def _asset_key(asset_type: str, target: str | None, location: str, facts: dict[str, Any], name: str | None) -> str:
    """Dedup key within one job attempt.  The target is part of it: host collectors report host-relative locations
    ("sshd -T", "package:openssl", a file path), so two hosts in one source must never collapse into one row."""
    identity = facts.get("fingerprint_sha256") or facts.get("identity") or name or ""
    return hashlib.sha256(f"{asset_type}|{target or ''}|{location}|{identity}".encode("utf-8", "replace")).hexdigest()


def _insert_ignore(session: Session, rows: list[dict[str, Any]]) -> int:
    """INSERT ... ON CONFLICT DO NOTHING on Postgres and SQLite.  Returns rows inserted."""
    if not rows:
        return 0
    dialect = session.get_bind().dialect.name
    if dialect == "postgresql":
        from sqlalchemy.dialects.postgresql import insert as dialect_insert
    else:
        from sqlalchemy.dialects.sqlite import insert as dialect_insert
    stmt = dialect_insert(CbomCollectedAsset.__table__).values(rows).on_conflict_do_nothing(
        index_elements=["job_id", "attempt", "asset_key"])
    return int(session.exec(stmt).rowcount or 0)  # type: ignore[call-overload]


def _record_progress(session: Session, job: CbomCollectionJob, lease_id: str, progress: dict[str, Any],
                     now: _dt.datetime) -> None:
    """Keep a running network range's "addresses done / total" on the job (``result.progress``, for this attempt;
    the job's result replaces it when the job ends).  Lease-checked, like the asset counter."""
    total = max(0, int(progress.get("total") or 0))
    done = min(max(0, int(progress.get("done") or 0)), total)
    result = {**(job.result or {}), "progress": {"done": done, "total": total, "attempt": job.attempts,
                                                  "at": now.replace(microsecond=0).isoformat() + "Z"}}
    session.exec(update(CbomCollectionJob)
                 .where(CbomCollectionJob.id == job.id, CbomCollectionJob.status == "claimed",
                        CbomCollectionJob.lease_id == lease_id)
                 .values(result=result))


def add_assets(
    session: Session, node: CbomScanNode | None, job_id: int, lease_id: str, assets: list[dict[str, Any]],
    now: _dt.datetime, *, team_id: int | None = None, known_secrets: list[str] | None = None,
    progress: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Store one batch of a running job's assets (and a network range's progress, when the node sends it).  Team,
    run and source always come from the job row."""
    job = _owned_job(session, node, job_id, team_id)
    if job.kind == "slice":  # F1 cloud pool: stored under the parent collect job (cbom_sources.slices)
        from backend.utilities.cbom_sources import slices as S

        return S.add_assets(session, job, lease_id, assets, now, known_secrets=known_secrets)
    if job.status != "claimed" or job.lease_id != lease_id:
        raise HTTPException(status_code=409, detail="This job is no longer leased to this node")
    source = session.get(CbomCollectionSource, job.source_id) if job.source_id else None
    reason = _stop_reason(session, job, source, node)
    if reason:
        changed = session.exec(
            update(CbomCollectionJob)
            .where(CbomCollectionJob.id == job.id, CbomCollectionJob.status == "claimed", CbomCollectionJob.lease_id == lease_id)
            .values(status="cancelled", finished_at=now, error=reason[:1024], lease_id=None, lease_expires_at=None,
                    outcome="failed")
        ).rowcount
        if changed:
            session.refresh(job)
            if job.kind == "collect":
                refund_job(session, job)
            _test_result_from_job(session, job, now)
            touch_run(session, job.run_id)
            audit(session, team_id=job.team_id, actor_type="system", actor_id=None, action="job.cancelled",
                  object_type="job", object_id=job.id, changed_fields=["stale_source"])
            log_after_commit(session, "job cancelled", team=job.team_id, job=job.id, reason="stale_source_on_assets")
        session.commit()
        raise HTTPException(status_code=409, detail=f"Stop this job: {reason}")
    if job.kind == "test_connection":  # a connection test proves access; it does not build inventory
        return {"accepted": 0, "duplicate": 0, "rejected": 0, "dropped": len(assets), "total_for_attempt": 0,
                "cap_reached": False, "ignored": "connection tests do not store assets"}
    known = SR.known_secrets(session, source)
    known += [s for s in (known_secrets or []) if isinstance(s, str)]
    rows, rejected, in_batch_dups = asset_rows(job, assets, known, now)
    inserted, existing, dropped, cap_reached = store_rows(session, job, job, lease_id, rows)
    OPS.bump(session, OPS.INGEST_REJECTED, rejected, now)  # cbom_ingest_rejected_assets_total (CB-31)
    total = int(session.exec(select(func.count()).select_from(CbomCollectedAsset).where(
        CbomCollectedAsset.job_id == job.id, CbomCollectedAsset.attempt == job.attempts)).one())
    duplicate = in_batch_dups + existing
    log("assets stored", team=job.team_id, run=job.run_id, job=job.id, attempt=job.attempts, accepted=inserted,
        duplicate=duplicate, rejected=rejected, dropped=dropped, total=total, cap_reached=cap_reached)
    if cap_reached and isinstance(job.result, dict):
        job.result = {**job.result, "truncated": True}
        session.add(job)
    if progress is not None:
        _record_progress(session, job, lease_id, progress, now)
    return {"accepted": inserted, "duplicate": duplicate, "rejected": rejected, "dropped": dropped,
            "total_for_attempt": total, "cap_reached": cap_reached}


def asset_rows(owner: CbomCollectionJob, assets: list[dict[str, Any]], known: list[str],
               now: _dt.datetime) -> tuple[list[dict[str, Any]], int, int]:
    """Validate, scrub and classify a batch into rows of ``owner``'s current attempt.  Returns (rows, rejected,
    duplicates inside the batch)."""
    rows: list[dict[str, Any]] = []
    rejected = 0
    in_batch_dups = 0
    keys: set[str] = set()
    for raw in assets:
        asset_type = raw.get("type")
        location = clean_text(scrub(raw.get("location"), known), 512) if raw.get("location") else None
        if asset_type not in ASSET_TYPES or not location:
            rejected += 1
            continue
        facts = scrub(raw.get("facts") if isinstance(raw.get("facts"), dict) else {}, known, exact_keys=True) or {}
        name = clean_text(scrub(raw.get("name"), known), 255) if raw.get("name") else None
        algorithm = clean_text(raw.get("algorithm"), 64) if raw.get("algorithm") else None
        key_size = raw.get("key_size") if isinstance(raw.get("key_size"), int) and 0 < raw.get("key_size") < 1_000_000 else None
        protocol = clean_text(raw.get("protocol"), 32) if raw.get("protocol") else None
        target = clean_text(scrub(raw.get("target"), known), 255) if raw.get("target") else None
        facts, algorithm = normalise_tls(asset_type, facts, algorithm)  # no sentinels; one name per suite (CB-12)
        key = _asset_key(asset_type, target, location, facts, name)
        if key in keys:
            in_batch_dups += 1
            continue
        keys.add(key)
        name = name or _san_name(asset_type, facts)  # after the key: a fallback name never moves an asset's key
        try:
            verdict = classify(asset_type, algorithm, key_size, protocol, facts, now)
        except Exception as exc:  # one malformed asset must not cost the rest of the batch
            # `log` here is the module's greppable-line function (common.log), not a logging.Logger
            log("classify FAILED; asset stored without a verdict", asset_type=asset_type, job=owner.id,
                error=type(exc).__name__)
            verdict = {"cdx_type": "other", "quantum_vulnerable": None, "impact": None, "finding_codes": [],
                       "finding": "Not judged: the collected facts could not be read"}
        rows.append({
            "team_id": owner.team_id, "run_id": owner.run_id, "job_id": owner.id, "source_id": owner.source_id,
            "attempt": owner.attempts, "asset_key": key, "asset_type": asset_type, "cdx_type": verdict["cdx_type"],
            "target": target,
            "location": location, "name": name, "algorithm": algorithm, "key_size": key_size, "protocol": protocol,
            "quantum_vulnerable": verdict["quantum_vulnerable"], "impact": verdict["impact"],
            "finding_codes": verdict["finding_codes"], "finding": verdict["finding"], "facts": facts, "created_at": now,
        })
    return rows, rejected, in_batch_dups


def store_rows(session: Session, owner: CbomCollectionJob, counter: CbomCollectionJob, lease_id: str,
               rows: list[dict[str, Any]], *, owner_cap: int | None = None) -> tuple[int, int, int, bool]:
    """Insert rows into ``owner``'s attempt; ``counter`` (the job itself, or a slice of it) carries the lease and the
    per-attempt asset cap.  Rows already stored are skipped, so a batch sent twice (or by a re-run slice) stores
    nothing new.  ``owner_cap`` (a slice writing into its parent): the parent's ``asset_count`` is kept too, with a
    guarded cap summed over every slice, so the source as a whole stays as bounded as a single job was.  Returns
    (inserted, already stored, dropped at the cap, cap reached)."""
    existing = set()
    if rows:
        existing = set(session.exec(select(CbomCollectedAsset.asset_key).where(
            CbomCollectedAsset.job_id == owner.id, CbomCollectedAsset.attempt == owner.attempts,
            CbomCollectedAsset.asset_key.in_([r["asset_key"] for r in rows]))).all())  # type: ignore[attr-defined]
    fresh = [r for r in rows if r["asset_key"] not in existing]
    room = max(MAX_ASSETS_PER_ATTEMPT - (counter.asset_count or 0), 0)
    shared = counter.id != owner.id and owner_cap is not None
    want = min(len(fresh), room)
    if want:
        # the counter (lease-checked) first, then the parent: every writer locks the two rows in the same order, and
        # a batch racing the reaper or the result is refused before it takes any of the parent's room
        changed = session.exec(
            update(CbomCollectionJob)
            .where(CbomCollectionJob.id == counter.id, CbomCollectionJob.status == "claimed",
                   CbomCollectionJob.lease_id == lease_id,
                   CbomCollectionJob.asset_count + want <= MAX_ASSETS_PER_ATTEMPT)
            .values(asset_count=CbomCollectionJob.asset_count + want)
        ).rowcount
        if not changed:
            raise HTTPException(status_code=409, detail="This job is no longer leased to this node")
    take = want
    if shared and want:
        take = 0
        for _try in range(5):  # the parent's counter is shared by every slice: take room with a guarded UPDATE
            # (it fails only when another slice took the last room meanwhile: read the count again)
            have = int(session.exec(select(CbomCollectionJob.asset_count).where(CbomCollectionJob.id == owner.id)).one())
            grant = min(want, max(owner_cap - have, 0))  # type: ignore[operator]
            if grant == 0:
                break
            if session.exec(
                    update(CbomCollectionJob)
                    .where(CbomCollectionJob.id == owner.id, CbomCollectionJob.status == "claimed",
                           CbomCollectionJob.asset_count + grant <= owner_cap)
                    .values(asset_count=CbomCollectionJob.asset_count + grant)).rowcount:
                take = grant
                break
        if take < want:  # give the slice back what the parent's cap did not grant
            session.exec(update(CbomCollectionJob).where(CbomCollectionJob.id == counter.id)
                         .values(asset_count=CbomCollectionJob.asset_count - (want - take)))
    cap_reached = len(fresh) > take
    dropped = max(len(fresh) - take, 0)
    fresh = fresh[:take]
    from backend.utilities.cbom_sources import qgrade_store as QSTORE  # CB-19 PR-3: the record grade, at insert

    QSTORE.ingest_grades(session, owner, fresh)
    inserted = _insert_ignore(session, fresh)
    if inserted < len(fresh):  # another request stored some of these keys first
        for job_id in ((counter.id, owner.id) if shared else (counter.id,)):
            session.exec(update(CbomCollectionJob).where(CbomCollectionJob.id == job_id)
                         .values(asset_count=CbomCollectionJob.asset_count - (len(fresh) - inserted)))
    return inserted, len(existing) + (len(fresh) - inserted), dropped, cap_reached


# ----------------------------------------------------------------------------- cloud worker
CLOUD_KINDS = ("collect", "slice")  # what the cloud worker runs: node-less collect jobs and their F1 slices
_CLAIM_LOCK_NS = 0x5A53  # pg_advisory_xact_lock(namespace, team_id): one claim at a time per team (the cap check)


def cloud_lease() -> _dt.timedelta:
    """Cloud-worker lease (CBOM_CLOUD_LEASE_S, default 900 s = LEASE).  The worker renews it every third of it."""
    try:
        seconds = int(os.environ.get("CBOM_CLOUD_LEASE_S", "") or LEASE.total_seconds())
    except ValueError:
        seconds = int(LEASE.total_seconds())
    return _dt.timedelta(seconds=max(5, min(seconds, 6 * 3600)))


def team_max_concurrency() -> int:
    """Most cloud jobs (collections and slices) one team may have running at once, across every worker replica and
    thread (CBOM_CLOUD_TEAM_MAX_CONCURRENCY, default 8).  One 1,000-account tenant then never holds the whole pool."""
    try:
        value = int(os.environ.get("CBOM_CLOUD_TEAM_MAX_CONCURRENCY", "") or 8)
    except ValueError:
        value = 8
    return max(1, min(value, 10_000))


def _cloud_queue():
    return (CbomCollectionJob.node_id.is_(None),  # type: ignore[union-attr]
            CbomCollectionJob.node_segment.is_(None),  # type: ignore[union-attr]  (segment jobs are for scan nodes, F1.1)
            CbomCollectionJob.kind.in_(CLOUD_KINDS))  # type: ignore[attr-defined]


def _running_cond():
    """Claimed cloud jobs that occupy a worker: a fanned-out parent (``fo…`` lease) is held by its slices, not by a
    worker, so it is not counted."""
    from backend.utilities.cbom_sources.slices import FANOUT_PREFIX

    return (*_cloud_queue(), CbomCollectionJob.status == "claimed",
            or_(CbomCollectionJob.lease_id.is_(None),  # type: ignore[union-attr]
                ~CbomCollectionJob.lease_id.like(FANOUT_PREFIX + "%")))  # type: ignore[union-attr]


def _cloud_running(session: Session, team_id: int | None = None) -> dict[int, int]:
    query = (select(CbomCollectionJob.team_id, func.count())
             .where(*_running_cond()).group_by(CbomCollectionJob.team_id))
    if team_id is not None:
        query = query.where(CbomCollectionJob.team_id == team_id)
    return {int(t): int(n) for t, n in session.exec(query).all()}


def claim_cloud_job(session: Session, now: _dt.datetime, worker: str, *, team_cap: int | None = None) -> dict | None:
    """Claim the next node-less job (a cloud collection, or one F1 slice of an AWS collection) for a cloud worker.

    Fair share, work-conserving: teams with pending work are tried in order of how few jobs they have running (then
    whose oldest pending job is oldest).  While more than one team has pending work, a team already running
    ``team_cap`` jobs is passed over, so a team with one job is served by the next free worker however many slices
    another team has queued; a team that is alone in the queue may use the whole pool.  On PostgreSQL the team's rows
    are taken ``FOR UPDATE SKIP LOCKED`` under a per-team transaction advisory lock taken with
    ``pg_try_advisory_xact_lock`` (a team another claimer is busy with is skipped, never waited for: no lock cycle
    between claimers).

    Whether the cap applies is decided again inside the claiming UPDATE, never only from the queue read above: the
    guarded ``status = 'pending'`` UPDATE claims only while the team is under the cap OR no other team has pending
    work at that moment.  The queue read is an unlocked snapshot: another team's work can appear between it and the
    UPDATE (its collection fanned out into slices just then), and a claim decided "alone" from that snapshot took the
    team past its cap while the other team waited (the flaky test_the_team_cap_holds_while_another_team_is_waiting).
    On SQLite the UPDATE holds the write lock, so the guard is exact; on PostgreSQL the advisory lock serialises the
    team's claims and the guard reads the queue at the UPDATE's own snapshot.  The caller commits."""
    pg = session.get_bind().dialect.name == "postgresql"
    running = _cloud_running(session)
    waiting = session.exec(
        select(CbomCollectionJob.team_id, func.min(CbomCollectionJob.id))
        .where(*_cloud_queue(), CbomCollectionJob.status == "pending").group_by(CbomCollectionJob.team_id)).all()
    cap = team_cap or team_max_concurrency()
    contended = len(waiting) > 1
    for team_id, _oldest in sorted(waiting, key=lambda row: (running.get(int(row[0]), 0), row[1])):
        if contended and running.get(int(team_id), 0) >= cap:
            continue  # the snapshot already says no; the UPDATE's guard decides every other case
        if pg and not session.exec(select(func.pg_try_advisory_xact_lock(_CLAIM_LOCK_NS, int(team_id)))).one():
            continue  # another claimer is taking this team's place now
        payload = _claim_for_team(session, now, worker, int(team_id), pg, cap)
        if payload is not None:
            return payload
    return None


def _claim_for_team(session: Session, now: _dt.datetime, worker: str, team_id: int, pg: bool,
                    cap: int) -> dict | None:
    query = (
        select(CbomCollectionJob)
        .where(*_cloud_queue(), CbomCollectionJob.team_id == team_id, CbomCollectionJob.status == "pending")
        .order_by(CbomCollectionJob.id)
        .limit(25)
    )
    if pg:
        query = query.with_for_update(skip_locked=True)
    for job in session.exec(query).all():
        source = session.get(CbomCollectionSource, job.source_id) if job.source_id else None
        spec = KINDS.get(source.kind) if source is not None else None
        if job.kind == "slice":
            from backend.utilities.cbom_sources import slices as S

            reason = S.slice_invalid_reason(session, job, source) or S.cap_reason(session, job)
        else:
            reason = _invalid_reason(job, source, None)
        if reason is None and (spec is None or not spec.node_less):
            reason = "This source needs a scan node"
        if reason:
            changed = session.exec(
                update(CbomCollectionJob).where(CbomCollectionJob.id == job.id, CbomCollectionJob.status == "pending")
                .values(status="cancelled", finished_at=now, error=reason[:1024], outcome="failed")
            ).rowcount
            if changed:
                session.refresh(job)
                if job.kind == "slice":
                    from backend.utilities.cbom_sources import slices as S

                    S.maybe_finalize(session, job.parent_job_id, now)
                else:
                    refund_job(session, job)
                    touch_run(session, job.run_id)
                    audit(session, team_id=job.team_id, actor_type="system", actor_id=None, action="job.cancelled",
                          object_type="job", object_id=job.id, changed_fields=["stale_source"])
            continue
        lease_id = secrets.token_hex(12)
        # the team's cap, decided inside the claiming UPDATE: under the cap, or no other team waiting right now (on
        # SQLite the UPDATE holds the write lock, so this is exact; on PostgreSQL the advisory lock above serialises
        # the team's claims). Never from the queue snapshot alone (see claim_cloud_job).
        other = aliased(CbomCollectionJob)
        others_waiting = (select(other.id).where(other.node_id.is_(None), other.kind.in_(CLOUD_KINDS),  # type: ignore[union-attr,attr-defined]
                                                  other.status == "pending", other.team_id != team_id).exists())
        under_cap = select(func.count()).select_from(CbomCollectionJob).where(
            CbomCollectionJob.team_id == team_id, *_running_cond()).scalar_subquery() < cap
        guard = [CbomCollectionJob.id == job.id, CbomCollectionJob.status == "pending", or_(under_cap, ~others_waiting)]
        changed = session.exec(
            update(CbomCollectionJob)
            .where(*guard)
            .values(status="claimed", lease_id=lease_id, lease_expires_at=now + cloud_lease(), claimed_at=now,
                    attempts=CbomCollectionJob.attempts + 1, asset_count=0, outcome=None)
        ).rowcount
        if not changed:
            session.refresh(job)
            if job.status == "pending":
                break  # the team reached its cap meanwhile: try the next team
            continue  # another worker took this one
        session.refresh(job)
        params = job.params or {}
        if job.kind == "slice":  # slices are many and short: a log line each, no audit row (the parent has those)
            if job.first_claimed_at is None:
                job.first_claimed_at = now
                session.add(job)
        else:
            _start_attempt(session, job, now)
            mark_run_running(session, job.run_id, now)
            audit(session, team_id=job.team_id, actor_type="system", actor_id=None, action="job.claim",
                  object_type="job", object_id=job.id, changed_fields=["cloud_worker"])
        log("cloud claim", team=job.team_id, run=job.run_id, job=job.id, parent=job.parent_job_id, worker=worker,
            kind=source.kind, job_kind=job.kind, account=params.get("account_id"), region=params.get("region"),
            attempt=job.attempts, wait_ms=int((now - job.created_at).total_seconds() * 1000) if job.created_at else None)
        # the stored config and secrets, then every claim plugin's (F1.1 secret_refs: fleet credentials, transports)
        config, secret_values = SR.source_secrets(session, source, None, now)
        return {
            "job": {"id": job.id, "team_id": job.team_id, "run_id": job.run_id, "lease_id": lease_id,
                    "attempt": job.attempts, "max_runtime_s": int(MAX_RUNTIME["collect"].total_seconds()),
                    "kind": job.kind, "parent_job_id": job.parent_job_id,
                    "slice": ({k: params.get(k) for k in ("account_id", "role_arn", "region")}
                              if job.kind == "slice" else None)},
            "source": {"id": source.id, "kind": source.kind, "name": source.name, "config": config,
                       "last_test_status": source.last_test_status, "secrets": secret_values},
        }
    return None


def renew_cloud_lease(session: Session, job_id: int, lease_id: str, now: _dt.datetime) -> str | None:
    """Extend a cloud job's lease (the worker's heartbeat).  Returns why it must stop, or None to carry on."""
    job = session.get(CbomCollectionJob, job_id)
    if job is None or job.node_id is not None or job.status != "claimed" or job.lease_id != lease_id:
        return "This job is no longer leased to the cloud worker"
    source = session.get(CbomCollectionSource, job.source_id) if job.source_id else None
    if job.kind == "slice":
        from backend.utilities.cbom_sources import slices as S

        reason = S.slice_invalid_reason(session, job, source)
    else:
        reason = _invalid_reason(job, source, None)
    if reason:
        return reason
    session.exec(update(CbomCollectionJob)
                 .where(CbomCollectionJob.id == job_id, CbomCollectionJob.lease_id == lease_id,
                        CbomCollectionJob.status == "claimed")
                 .values(lease_expires_at=now + cloud_lease()))
    return None


def release_cloud_job(session: Session, job_id: int, lease_id: str, now: _dt.datetime, reason: str) -> bool:
    """Give a claimed cloud job back to the queue now (a worker shutting down), instead of letting its lease run out.
    The attempt it used stays counted; its next claim starts a new attempt.  Returns whether it was released."""
    changed = session.exec(
        update(CbomCollectionJob)
        .where(CbomCollectionJob.id == job_id, CbomCollectionJob.node_id.is_(None),  # type: ignore[union-attr]
               CbomCollectionJob.status == "claimed", CbomCollectionJob.lease_id == lease_id)
        .values(status="pending", lease_id=None, lease_expires_at=None)
    ).rowcount
    if changed:
        job = session.get(CbomCollectionJob, job_id)
        if job is not None:
            session.refresh(job)
            touch_run(session, job.run_id)
            log("cloud job released", team=job.team_id, job=job.id, parent=job.parent_job_id, reason=reason[:80])
    return bool(changed)


def cloud_queue_stats(session: Session, now: _dt.datetime) -> dict[str, Any]:
    """Queue depth and age of the cloud worker's queue: pending / running jobs, the oldest pending job's age, and
    the teams with the most pending (for the periodic queue log line)."""
    pending = session.exec(
        select(CbomCollectionJob.team_id, func.count(), func.min(CbomCollectionJob.created_at))
        .where(*_cloud_queue(), CbomCollectionJob.status == "pending").group_by(CbomCollectionJob.team_id)).all()
    running = _cloud_running(session)
    oldest = min((row[2] for row in pending if row[2] is not None), default=None)
    top = sorted(((int(t), int(n)) for t, n, _o in pending), key=lambda tn: -tn[1])[:5]
    return {"pending": sum(int(n) for _t, n, _o in pending), "running": sum(running.values()),
            "teams_waiting": len(pending), "teams_running": len(running),
            "oldest_pending_s": int((now - oldest).total_seconds()) if oldest is not None else 0,
            "top": ",".join(f"{t}:{n}" for t, n in top) or None}


# ----------------------------------------------------------------------------- runs
def cancel_run(session: Session, run: CbomCollectionRun, user_id: int, now: _dt.datetime) -> int:
    """Cancel the run's pending jobs and refund exactly those; ask the node to stop the claimed ones
    (they are refunded when the node confirms, or after the cancel grace period).  Returns centi-credits refunded."""
    asked = session.exec(
        update(CbomCollectionJob)
        .where(CbomCollectionJob.run_id == run.id, CbomCollectionJob.status == "claimed",
               CbomCollectionJob.cancel_requested_at.is_(None))  # type: ignore[union-attr]
        .values(cancel_requested_at=now, cancel_reason="Cancelled by a user")
    ).rowcount
    refunded = 0
    jobs = session.exec(
        select(CbomCollectionJob).where(CbomCollectionJob.run_id == run.id, CbomCollectionJob.status == "pending")
    ).all()
    for job in jobs:
        changed = session.exec(
            update(CbomCollectionJob).where(CbomCollectionJob.id == job.id, CbomCollectionJob.status == "pending")
            .values(status="cancelled", finished_at=now, error="Cancelled by a user")
        ).rowcount
        if changed:
            session.refresh(job)
            refunded += refund_job(session, job)
    if run.cancelled_at is None and (jobs or asked):
        run.cancelled_by = user_id
        run.cancelled_at = now
        session.add(run)
    touch_run(session, run.id)
    settle_after_commit(session, run.id)  # the user sees the refund as soon as the cancel commits
    return refunded


def job_waiting_reason(
    job: CbomCollectionJob, node: CbomScanNode | None, settings: CbomCollectionSettings, now: _dt.datetime,
    source: CbomCollectionSource | None = None,
) -> str | None:
    if job.status == "claimed":
        if job.cancel_requested_at is not None:
            return "Stop requested; waiting for the scan node to confirm"
        return "Running on the scan node" if job.node_id else "Running in ZeroShield cloud"
    if job.status != "pending":
        return None
    if job.node_id is None and job.node_segment:
        is_network = job.kind == "discovery" or (source is not None and source.kind == "network_range")
        if is_network and settings.stop_all_network:
            return "Network scanning is stopped"
        if job.kind != "test_connection" and not window_allows(_job_window(source, settings), settings.window_timezone, now):
            return "Outside the scan window"
        return f"Waiting for a signed scan node of segment {job.node_segment} to pick it up"
    if job.node_id is None and job.kind in CLOUD_KINDS:
        return "Queued for the ZeroShield cloud worker"
    status = node_status(node, now)
    if status == "missing":
        return "No scan node is assigned"
    if status in ("pending_registration", "registration_expired"):
        return f"Scan node {node.name} has not registered yet"
    if status == "offline":
        return f"Scan node {node.name} is offline"
    is_network = job.kind == "discovery" or (source is not None and source.kind == "network_range")
    if is_network and settings.stop_all_network:
        return "Network scanning is stopped"
    if job.kind != "test_connection" and not window_allows(_job_window(source, settings), settings.window_timezone, now):
        return "Outside the scan window"
    return "Waiting for the scan node to pick it up"


def run_credit_summary(run: CbomCollectionRun) -> dict[str, float]:
    return {"charged": credits(run.credits_charged_c), "refunded": credits(run.credits_refunded_c),
            "net": credits(run.credits_charged_c - run.credits_refunded_c)}
