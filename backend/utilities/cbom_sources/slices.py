"""F1 cloud pool: an AWS collection split into one ``slice`` job per account x region.

Why slices, and why this shape (the least invasive one):

* A run still has ONE ``collect`` job per source (the *parent*).  It is created and charged by ``runs.queue_run``
  exactly as before, it is what runs, drift, posture, provenance, exports and the run list read, and it is refunded
  by the same rules.  Nothing downstream learns about slices.
* The cloud worker that claims an AWS parent runs the safety checks and the organisation walk
  (``aws_org.plan_slices``), then ``fan_out`` queues one slice per account x region (``kind='slice'``,
  ``parent_job_id`` set, ``run_id`` NULL, no credits) and hands the parent over to the slices: its lease becomes a
  ``fo…`` lease that only the slices and the reaper use.
* Every worker replica / thread claims slices like any cloud job (fair share, SKIP LOCKED, leases, heartbeat).  A
  slice's assets are stored under the PARENT's (job, attempt), with the same asset keys the serial walk produced:
  ``ON CONFLICT DO NOTHING`` makes a re-sent batch, or a slice re-run after its worker died, store nothing twice.
* The worker that ends the last open slice (or the reaper, when slices ended by lease expiry or the worker died
  between the two) finalises the parent with ``jobs.finish_job``: target rows and counts of all slices, outcome,
  refund and run status by the unchanged rules.  The parent's guarded UPDATE makes that happen once.
* Cancel (user, source change, deletion) is asked on the parent as before; pending slices are cancelled with it and
  running ones stop at their next heartbeat or asset batch (``slice_invalid_reason``).

``CBOM_AWS_SLICES=0`` turns fan-out off (the serial ``aws_collect.collect_aws`` walk in one job, as before).
"""
from __future__ import annotations

import datetime as _dt
import os
import secrets
from typing import Any

from fastapi import HTTPException
from sqlalchemy import func, insert, update
from sqlmodel import Session, select

from backend.new_models import CbomCollectionJob, CbomCollectionSource
from backend.utilities.cbom_sources import jobs as J
from backend.utilities.cbom_sources.common import log
from backend.utilities.cbom_sources.crypto import decrypt_secrets, scrub

SLICE = "slice"
FANOUT_PREFIX = "fo"
# A fanned-out collection may run this long (its slices queue behind other teams' work under the fair-share cap);
# then it ends as a failure and is refunded, like a single job past MAX_RUNTIME.
FANOUT_MAX_RUNTIME = _dt.timedelta(hours=int(os.environ.get("CBOM_CLOUD_FANOUT_MAX_HOURS", "") or 24))
TARGETS_KEPT = 1000  # target rows kept on the parent's result (failures first); counts always cover every slice
INSERT_CHUNK = 1000


def enabled() -> bool:
    return os.environ.get("CBOM_AWS_SLICES", "1").strip() != "0"


def is_parent(job: CbomCollectionJob) -> bool:
    return (job.kind == "collect" and (job.lease_id or "").startswith(FANOUT_PREFIX)
            and isinstance(job.result, dict) and isinstance(job.result.get("fanout"), dict))


def _iso(moment: _dt.datetime) -> str:
    return moment.replace(microsecond=0).isoformat() + "Z"


# ----------------------------------------------------------------------------- fan out
def fan_out(session: Session, parent_id: int, lease_id: str, plan: dict[str, Any], now: _dt.datetime) -> int:
    """Queue the plan's slices and hand the parent over to them.  Raises 409 when the worker no longer holds the
    parent (lease lost, or a cancel was asked meanwhile: the worker then ends the parent itself).  Caller commits."""
    parent = session.get(CbomCollectionJob, parent_id)
    if parent is None:
        raise HTTPException(status_code=404, detail="Job not found")
    slices = plan["slices"]
    fo_lease = FANOUT_PREFIX + secrets.token_hex(11)
    fanout = {"slices": len(slices), "accounts": plan.get("accounts"), "at": _iso(now)}
    if plan.get("org"):
        fanout["org"] = plan["org"]
    result = {"fanout": fanout, "targets": list(plan.get("targets") or []),
              "slices": {"done": 0, "total": len(slices)}}
    changed = session.exec(
        update(CbomCollectionJob)
        .where(CbomCollectionJob.id == parent_id, CbomCollectionJob.status == "claimed",
               CbomCollectionJob.lease_id == lease_id,
               CbomCollectionJob.cancel_requested_at.is_(None))  # type: ignore[union-attr]
        .values(lease_id=fo_lease, lease_expires_at=now + J.cloud_lease(), result=result)
    ).rowcount
    if not changed:
        raise HTTPException(status_code=409, detail="This job is no longer leased to the cloud worker")
    params = parent.params or {}
    base = {"conn_v": params.get("conn_v"), "source_uid": params.get("source_uid"),
            "source_name": params.get("source_name"), "parent_lease": fo_lease, "parent_job_id": parent_id}
    rows = [{
        "team_id": parent.team_id, "run_id": None, "source_id": parent.source_id, "node_id": None, "kind": SLICE,
        "status": "pending", "params": {**base, "account_id": s["account_id"], "role_arn": s["role_arn"],
                                        "region": s["region"]},
        "source_version": parent.source_version, "weight_c": 0, "refunded": False, "attempts": 0,
        "created_by_user_id": parent.created_by_user_id, "created_at": now, "result": {}, "asset_count": 0,
        "parent_job_id": parent_id,
    } for s in slices]
    for start in range(0, len(rows), INSERT_CHUNK):
        session.exec(insert(CbomCollectionJob.__table__).values(rows[start:start + INSERT_CHUNK]))  # type: ignore[call-overload]
    log("cloud fan-out", team=parent.team_id, run=parent.run_id, job=parent_id, slices=len(slices),
        accounts=plan.get("accounts"), org_ms=(plan.get("org") or {}).get("ms"))
    return len(slices)


# ----------------------------------------------------------------------------- slice checks
def slice_invalid_reason(session: Session, job: CbomCollectionJob, source: CbomCollectionSource | None) -> str | None:
    """Why a slice must not run (or must stop): its parent ended or was asked to stop, or the source changed."""
    parent = session.get(CbomCollectionJob, job.parent_job_id) if job.parent_job_id else None
    if parent is None or parent.status != "claimed" or parent.lease_id != (job.params or {}).get("parent_lease"):
        return "The collection this slice belongs to has ended"
    if parent.cancel_requested_at is not None:
        return parent.cancel_reason or "Cancelled"
    reason = J._invalid_reason(job, source, None)
    if reason:
        return reason
    if source is not None and not source.enabled:
        return "Source was disabled"
    return None


def _cancel_slice(session: Session, job: CbomCollectionJob, lease_id: str | None, reason: str,
                  now: _dt.datetime) -> bool:
    cond = [CbomCollectionJob.id == job.id, CbomCollectionJob.status.in_(J.OPEN)]  # type: ignore[attr-defined]
    if lease_id is not None:
        cond.append(CbomCollectionJob.lease_id == lease_id)
    changed = session.exec(update(CbomCollectionJob).where(*cond).values(
        status="cancelled", finished_at=now, error=reason[:1024], lease_id=None, lease_expires_at=None,
        outcome="failed")).rowcount
    return bool(changed)


# ----------------------------------------------------------------------------- assets and results
def add_assets(session: Session, job: CbomCollectionJob, lease_id: str, assets: list[dict[str, Any]],
               now: _dt.datetime, *, known_secrets: list[str] | None = None) -> dict[str, Any]:
    """Store a slice's batch under its parent's current attempt (the lease and the asset cap are the slice's)."""
    if job.status != "claimed" or job.lease_id != lease_id:
        raise HTTPException(status_code=409, detail="This job is no longer leased to this node")
    source = session.get(CbomCollectionSource, job.source_id) if job.source_id else None
    reason = slice_invalid_reason(session, job, source)
    if reason:
        if _cancel_slice(session, job, lease_id, reason, now):
            maybe_finalize(session, job.parent_job_id, now)
            log("job cancelled", team=job.team_id, job=job.id, parent=job.parent_job_id, reason="stale_on_assets")
        session.commit()
        raise HTTPException(status_code=409, detail=f"Stop this job: {reason}")
    parent = session.get(CbomCollectionJob, job.parent_job_id)
    known = list(decrypt_secrets(source.secret_encrypted).values()) if source is not None else []
    known += [s for s in (known_secrets or []) if isinstance(s, str)]
    rows, rejected, in_batch_dups = J.asset_rows(parent, assets, known, now)
    inserted, existing, dropped, cap_reached = J.store_rows(session, parent, job, lease_id, rows)
    if cap_reached:
        session.refresh(job)
        job.result = {**(job.result or {}), "truncated": True}
        session.add(job)
    return {"accepted": inserted, "duplicate": in_batch_dups + existing, "rejected": rejected, "dropped": dropped,
            "total_for_attempt": int((job.asset_count or 0) + inserted), "cap_reached": cap_reached}


def finish_slice(session: Session, job: CbomCollectionJob, lease_id: str, status: str, result: dict[str, Any] | None,
                 error: str | None, now: _dt.datetime, *, known_secrets: list[str] | None = None) -> CbomCollectionJob:
    """End a slice (guarded on its lease: a second result for the same attempt is refused with 409), then finalise
    the parent when this was its last open slice."""
    source = session.get(CbomCollectionSource, job.source_id) if job.source_id else None
    known = list(decrypt_secrets(source.secret_encrypted).values()) if source is not None else []
    known += [s for s in (known_secrets or []) if isinstance(s, str)]
    clean = scrub(result or {}, known, exact_keys=True)
    clean = clean if isinstance(clean, dict) else {}
    if job.status == "claimed" and job.lease_id == lease_id and status == "success":
        invalid = slice_invalid_reason(session, job, source)
        if invalid:
            status, error = "cancelled", invalid
    if isinstance(job.result, dict) and job.result.get("truncated"):
        clean["truncated"] = True
    outcome, _extra = J._outcome(job, status, clean, 0)
    clean_error = scrub(error, known) if error else None
    changed = session.exec(
        update(CbomCollectionJob)
        .where(CbomCollectionJob.id == job.id, CbomCollectionJob.node_id.is_(None),  # type: ignore[union-attr]
               CbomCollectionJob.status == "claimed", CbomCollectionJob.lease_id == lease_id)
        .values(status=status, finished_at=now, result=clean, outcome=outcome,
                error=(str(clean_error)[:1024] if clean_error else None), lease_id=None, lease_expires_at=None)
    ).rowcount
    if not changed:
        raise HTTPException(status_code=409, detail="This job is no longer leased to this node")
    session.refresh(job)
    return job


# ----------------------------------------------------------------------------- the parent's end
def _open_slices(session: Session, parent_id: int) -> dict[str, int]:
    rows = session.exec(select(CbomCollectionJob.status, func.count())
                        .where(CbomCollectionJob.parent_job_id == parent_id,
                               CbomCollectionJob.status.in_(J.OPEN))  # type: ignore[attr-defined]
                        .group_by(CbomCollectionJob.status)).all()
    return {str(s): int(n) for s, n in rows}


def _slice_row(job: CbomCollectionJob) -> dict[str, Any]:
    """The slice's target row: what its collector reported, or one row saying why it never reported."""
    targets = (job.result or {}).get("targets") if isinstance(job.result, dict) else None
    if isinstance(targets, list) and targets and isinstance(targets[0], dict):
        return targets[0]
    params = job.params or {}
    where = f"aws:{params.get('account_id')}/{params.get('region')}"
    status = "skipped_cancelled" if job.status == "cancelled" else "error"
    return {"target": where, "status": status, "assets": 0,
            "error": (job.error or f"slice {job.status}")[:256]}


def finalize(session: Session, parent: CbomCollectionJob, now: _dt.datetime, *, status: str | None = None,
             error: str | None = None) -> CbomCollectionJob | None:
    """End the parent from its slices with ``jobs.finish_job`` (refund, outcome, run status, audit, log).  Returns
    None when another worker or the reaper ended it first."""
    slices = session.exec(select(CbomCollectionJob).where(CbomCollectionJob.parent_job_id == parent.id)
                          .order_by(CbomCollectionJob.id)).all()
    rows = [_slice_row(j) for j in slices]
    pre = list((parent.result or {}).get("targets") or [])
    targets = pre + rows
    ok = sum(1 for t in targets if t.get("status") == "ok")
    part = sum(1 for t in targets if t.get("status") == "partial")
    skipped = sum(1 for t in targets if str(t.get("status", "")).startswith("skipped"))
    counts = {"total": len(targets), "ok": ok, "partial": part, "failed": len(targets) - ok - part - skipped,
              "skipped": skipped}
    by_status: dict[str, int] = {}
    for j in slices:
        by_status[j.status] = by_status.get(j.status, 0) + 1
    # failures first, so the rows a customer needs survive the cap; the counts above cover all of them
    kept = sorted(targets, key=lambda t: (t.get("status") in ("ok", "partial"), str(t.get("target"))))[:TARGETS_KEPT]
    fanout = dict((parent.result or {}).get("fanout") or {})
    durations = [int((j.finished_at - j.claimed_at).total_seconds() * 1000) for j in slices
                 if j.finished_at is not None and j.claimed_at is not None]
    result = {
        "targets": kept, "targets_total": len(targets), "counts": counts, "accounts": fanout.get("accounts"),
        "fanout": {**fanout, "by_status": by_status,
                   "slice_ms_max": max(durations) if durations else None,
                   "slice_ms_sum": sum(durations) if durations else None},
        "slices": {"done": len(slices), "total": len(slices)},
        "truncated": any(isinstance(j.result, dict) and j.result.get("truncated") for j in slices) or None,
        "asset_count": None, "node_version": "cloud-worker-1.0",
        "summary": f"{ok + part} of {len(targets)} account-regions read ({len(slices)} slices)",
    }
    result = {k: v for k, v in result.items() if v is not None or k == "asset_count"}
    if status is None:
        status = "cancelled" if parent.cancel_requested_at is not None else "success"
        error = (parent.cancel_reason or "Cancelled") if status == "cancelled" else None
    try:  # finish_job writes nothing before its guarded UPDATE, so a refusal leaves the transaction clean
        job = J.finish_job(session, None, parent.id, parent.lease_id or "", status, result, error, now,
                           team_id=parent.team_id)
    except HTTPException:
        return None  # ended by someone else first: their result stands
    return job


def maybe_finalize(session: Session, parent_id: int | None, now: _dt.datetime) -> CbomCollectionJob | None:
    """Finalise the parent if it is fanned out and has no open slice left.  The caller commits."""
    if parent_id is None:
        return None
    parent = session.get(CbomCollectionJob, parent_id)
    if parent is None or parent.status != "claimed" or not is_parent(parent):
        return None
    session.refresh(parent)
    if _open_slices(session, parent_id):
        return None
    return finalize(session, parent, now)


def reap_parent(session: Session, parent: CbomCollectionJob, now: _dt.datetime) -> int:
    """The reaper's rules for a fanned-out parent (instead of the single-job lease / runtime / cancel rules).
    Returns 1 when the parent ended."""
    open_ = _open_slices(session, parent.id)
    total = int((parent.result or {}).get("fanout", {}).get("slices") or 0)
    pending_q = (CbomCollectionJob.parent_job_id == parent.id, CbomCollectionJob.status == "pending")
    ended = None
    if parent.cancel_requested_at is not None:
        # pending slices end now; running ones stop at their next heartbeat, or are ended after the cancel grace
        session.exec(update(CbomCollectionJob).where(*pending_q).values(
            status="cancelled", finished_at=now, error=(parent.cancel_reason or "Cancelled")[:1024], outcome="failed"))
        if open_.get("claimed") and parent.cancel_requested_at >= now - J.CANCEL_GRACE:
            return 0
        _end_open(session, parent.id, "cancelled", parent.cancel_reason or "Cancelled", now)
        ended = finalize(session, parent, now)
    elif parent.claimed_at is not None and parent.claimed_at < now - FANOUT_MAX_RUNTIME:
        _end_open(session, parent.id, "cancelled", "Stopped: the collection ran longer than its maximum time", now)
        ended = finalize(session, parent, now, status="failure",
                         error="Stopped: ran longer than the maximum time for this job")
    elif not open_:
        ended = finalize(session, parent, now)
    else:
        # still working: keep the parent's lease ahead of the reaper and show "N of M slices done"
        done = max(total - sum(open_.values()), 0)
        session.exec(update(CbomCollectionJob)
                     .where(CbomCollectionJob.id == parent.id, CbomCollectionJob.status == "claimed",
                            CbomCollectionJob.lease_id == parent.lease_id)
                     .values(lease_expires_at=now + J.cloud_lease(),
                             result={**(parent.result or {}), "slices": {"done": done, "total": total}}))
        return 0
    return 1 if ended is not None else 0


def _end_open(session: Session, parent_id: int, status: str, reason: str, now: _dt.datetime) -> None:
    session.exec(update(CbomCollectionJob)
                 .where(CbomCollectionJob.parent_job_id == parent_id,
                        CbomCollectionJob.status.in_(J.OPEN))  # type: ignore[attr-defined]
                 .values(status=status, finished_at=now, error=reason[:1024], lease_id=None, lease_expires_at=None,
                         outcome="failed"))


__all__ = ["enabled", "fan_out", "finish_slice", "finalize", "maybe_finalize", "reap_parent",
           "slice_invalid_reason", "is_parent", "SLICE", "FANOUT_PREFIX"]
