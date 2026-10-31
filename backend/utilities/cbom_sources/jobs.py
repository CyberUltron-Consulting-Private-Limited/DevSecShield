"""Job queue for scan nodes: create, claim, finish, cancel, expire, and run roll-up.

Every state change is a guarded ``UPDATE ... WHERE status = <expected>`` so two requests can never
move the same job twice (two nodes claiming, a cancel racing a claim, a late result after a lease
expired).  Credits are charged and refunded inside the same transaction as the job change.
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import secrets
from typing import Any

from fastapi import HTTPException
from sqlalchemy import delete, func, update
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
from backend.utilities.cbom_sources import targets as T
from backend.utilities.cbom_sources.classify import ASSET_TYPES, classify
from backend.utilities.cbom_sources.common import audit, clean_text, log
from backend.utilities.cbom_sources.crypto import decrypt_secrets, scrub
from backend.utilities.cbom_sources.kinds import KINDS
from backend.utilities.cbom_sources.planning import credits, node_status
from backend.utilities.cbom_sources.settings import get_or_create_settings, team_exclusions, window_allows, window_end

LEASE = _dt.timedelta(minutes=15)
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
    "sudoers_missing", "sudo_denied", "rbac_denied", "tls_unavailable", "not_supported", "error", "skipped_never_scan",
    "skipped_window", "skipped_stop", "skipped_deadline", "skipped_cancelled",
})


def _run_of(session: Session, job: CbomCollectionJob) -> CbomCollectionRun | None:
    return session.get(CbomCollectionRun, job.run_id) if job.run_id else None


# ----------------------------------------------------------------------------- credits
def charge_team(session: Session, team_id: int, centi: int) -> bool:
    """Atomic conditional deduction in the caller's transaction."""
    if centi <= 0:
        return True
    amount = centi / 100
    result = session.exec(
        update(Team).where(Team.id == team_id, Team.credit_balance >= amount)
        .values(credit_balance=Team.credit_balance - amount)
    )
    return result.rowcount == 1


def refund_job(session: Session, job: CbomCollectionJob, run: CbomCollectionRun | None) -> int:
    """Give back a job's credits once.  Returns centi-credits refunded."""
    if job.refunded or job.weight_c <= 0:
        return 0
    amount = job.weight_c
    if run is not None:
        amount = min(amount, max(run.credits_charged_c - run.credits_refunded_c, 0))
        run.credits_refunded_c += amount
        session.add(run)
    job.refunded = True
    session.add(job)
    if amount > 0:
        session.exec(update(Team).where(Team.id == job.team_id).values(credit_balance=Team.credit_balance + amount / 100))
    return amount


# ----------------------------------------------------------------------------- run status
def recompute_run(session: Session, run_id: int | None, now: _dt.datetime) -> CbomCollectionRun | None:
    if run_id is None:
        return None
    run = session.get(CbomCollectionRun, run_id)
    if run is None:
        return None
    jobs = session.exec(select(CbomCollectionJob).where(CbomCollectionJob.run_id == run_id)).all()
    statuses = [j.status for j in jobs]
    ever_claimed = any(j.claimed_at is not None for j in jobs)
    if not statuses:
        new = "done"
    elif "claimed" in statuses or ("pending" in statuses and ever_claimed):
        new = "running"
    elif "pending" in statuses:
        new = "queued"
    elif all(s == "success" for s in statuses):
        new = "partial" if any(j.outcome in ("partial", "failed") for j in jobs) else "done"
    elif all(s == "cancelled" for s in statuses):
        new = "cancelled"
    elif all(s in ("failure", "expired") for s in statuses):
        new = "failed"
    else:
        new = "partial"
    if new != run.status:
        run.status = new
        run.last_updated = now
        if new in ("done", "partial", "failed", "cancelled"):
            run.finished_at = now
        elif run.finished_at is not None:
            run.finished_at = None  # a job went back to pending (lease expired); the run is open again
        session.add(run)
        log("run status", team=run.team_id, run=run.id, status=new)
    return run


# ----------------------------------------------------------------------------- reaper
def reap(session: Session, now: _dt.datetime, *, team_id: int | None = None, node_id: int | None = None) -> int:
    """Apply lease and age rules.  The caller commits.  Returns the number of jobs moved."""
    query = select(CbomCollectionJob).where(CbomCollectionJob.status.in_(OPEN))  # type: ignore[attr-defined]
    if team_id is not None:
        query = query.where(CbomCollectionJob.team_id == team_id)
    if node_id is not None:
        query = query.where(CbomCollectionJob.node_id == node_id)
    moved = 0
    runs: set[int] = set()
    for job in session.exec(query).all():
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
            if changed:
                session.refresh(job)
                refunded = refund_job(session, job, _run_of(session, job)) if job.kind == "collect" else 0
                _test_result_from_job(session, job, now)
                audit(session, team_id=job.team_id, actor_type="system", actor_id=None, action=f"job.{status}",
                      object_type="job", object_id=job.id, changed_fields=["max_runtime" if too_long else "cancel"])
                log("job stopped", team=job.team_id, job=job.id, node=job.node_id, status=status,
                    reason="max_runtime" if too_long else "cancel_unconfirmed", refunded_c=refunded)
                moved += 1
                if job.run_id:
                    runs.add(job.run_id)
            continue
        if job.status == "claimed" and job.lease_expires_at is not None and job.lease_expires_at < now:
            if job.attempts < MAX_ATTEMPTS:
                target, values = "pending", {"lease_id": None, "lease_expires_at": None}
            else:
                target, values = "failure", {"finished_at": now, "error": "Scan node stopped responding",
                                             "lease_id": None, "lease_expires_at": None}
            changed = session.exec(
                update(CbomCollectionJob)
                .where(CbomCollectionJob.id == job.id, CbomCollectionJob.status == "claimed",
                       CbomCollectionJob.lease_id == job.lease_id)
                .values(status=target, **values)
            ).rowcount
            if changed:
                session.refresh(job)
                refunded = 0
                if target == "failure" and job.kind == "collect":
                    refunded = refund_job(session, job, _run_of(session, job))
                _test_result_from_job(session, job, now)
                audit(session, team_id=job.team_id, actor_type="system", actor_id=None, action=f"job.lease_expired.{target}",
                      object_type="job", object_id=job.id)
                log("job lease expired", team=job.team_id, job=job.id, node=job.node_id, status=target,
                    attempt=job.attempts, refunded_c=refunded)
                moved += 1
                if job.run_id:
                    runs.add(job.run_id)
        elif job.status == "pending":
            ttl = COLLECT_JOB_TTL if job.kind == "collect" else TEST_JOB_TTL
            if job.created_at is not None and job.created_at < now - ttl:
                changed = session.exec(
                    update(CbomCollectionJob)
                    .where(CbomCollectionJob.id == job.id, CbomCollectionJob.status == "pending")
                    .values(status="expired", finished_at=now, error="No scan node picked this job up in time")
                ).rowcount
                if changed:
                    session.refresh(job)
                    refunded = 0
                    if job.kind == "collect":
                        refunded = refund_job(session, job, _run_of(session, job))
                    _test_result_from_job(session, job, now)
                    audit(session, team_id=job.team_id, actor_type="system", actor_id=None, action="job.expired",
                          object_type="job", object_id=job.id)
                    log("job expired", team=job.team_id, job=job.id, node=job.node_id, refunded_c=refunded)
                    moved += 1
                    if job.run_id:
                        runs.add(job.run_id)
    for run_id in runs:
        recompute_run(session, run_id, now)
    return moved


def safe_reap(session: Session, now: _dt.datetime, **kwargs: Any) -> None:
    """Reaping on a read path must never fail the read."""
    try:
        if reap(session, now, **kwargs):
            session.commit()
    except Exception as exc:  # pragma: no cover - defensive
        session.rollback()
        log("reap FAILED", error=type(exc).__name__, **{k: v for k, v in kwargs.items() if v is not None})


# ----------------------------------------------------------------------------- create
def _snapshot_exclusions(settings: CbomCollectionSettings) -> list[str]:
    return [str(item.get("cidr")) for item in (settings.network_exclusions or []) if isinstance(item, dict)]


def create_test_job(
    session: Session, source: CbomCollectionSource, settings: CbomCollectionSettings, user_id: int, now: _dt.datetime
) -> CbomCollectionJob:
    """Queue a connection test for the source's node and mark the source ``pending``.  Caller commits."""
    cancel_open_jobs(session, source, now, reason="Replaced by a newer connection test", kinds=("test_connection",))
    params: dict[str, Any] = {"exclusions": _snapshot_exclusions(settings)}
    spec = KINDS[source.kind]
    if spec.group == "servers":
        parsed = T.parse_targets((source.config or {}).get("targets") or [], allow_empty=True)
        excl = T.parse_exclusions(((source.config or {}).get("exclusions") or []) + params["exclusions"])
        params["samples"] = T.sample_targets(parsed, excl, 5)
    job = CbomCollectionJob(
        team_id=source.team_id, source_id=source.id, node_id=source.node_id, kind="test_connection",
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
    runs: set[int] = set()
    for job in rows:
        changed = session.exec(
            update(CbomCollectionJob).where(CbomCollectionJob.id == job.id, CbomCollectionJob.status == "pending")
            .values(status="cancelled", finished_at=now, error=reason[:1024])
        ).rowcount
        if changed:
            session.refresh(job)
            if job.kind == "collect":
                refund_job(session, job, session.get(CbomCollectionRun, job.run_id) if job.run_id else None)
            count += 1
            if job.run_id:
                runs.add(job.run_id)
    for run_id in runs:
        recompute_run(session, run_id, now)
    return count


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
               now: _dt.datetime | None = None) -> dict[str, Any]:
    """What the node may touch.  Exclusions are the union of those at job creation and now."""
    exclusions = sorted(set((job.params or {}).get("exclusions") or []) | set(_snapshot_exclusions(settings)))
    scope: dict[str, Any] = {"never_scan": exclusions}
    now = now or _dt.datetime.utcnow()
    scope["max_runtime_s"] = int(MAX_RUNTIME.get(job.kind, MAX_RUNTIME["collect"]).total_seconds())
    ends = None if job.kind == "test_connection" else window_end(_job_window(source, settings), settings.window_timezone, now)
    scope["window_ends_at"] = ends.strftime("%Y-%m-%dT%H:%M:%SZ") if ends else None
    cfg = (source.config or {}) if source else {}
    if source is not None and KINDS[source.kind].group == "servers":
        scope["targets"] = cfg.get("targets") or []
        scope["never_scan"] = sorted(set(exclusions) | set(cfg.get("exclusions") or []))
        if job.kind == "test_connection":
            scope["targets"] = (job.params or {}).get("samples") or []
    elif source is not None and source.kind == "network_range":
        scope["ranges"] = [{"cidr": cfg.get("cidr"), "mode": cfg.get("mode", "full")}]
    elif job.kind == "discovery":
        scope["ranges"] = (job.params or {}).get("ranges") or []
    if job.kind == "discovery" or (source is not None and source.kind == "network_range"):
        scope["ports"] = settings.ports or []
        scope["sni_hostnames"] = settings.sni_hostnames or []
        scope["rate_limits"] = {
            "connections_per_second": settings.rate_conn_per_s,
            "parallel_per_server": settings.rate_parallel_per_server,
            "handshakes_per_endpoint": settings.rate_handshakes_per_endpoint,
        }
        scope["read_zeek_span"] = bool(settings.zeek_span)
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
    if job.source_id is None:
        return None if job.kind == "discovery" else "Source no longer exists"
    if source is None or source.team_id != job.team_id:
        return "Source no longer exists"
    if node is not None and source.node_id != node.id:
        return "Source moved to another scan node"
    if node is None and source.node_id is not None and job.node_id is not None:
        return "Source moved to another scan node"
    if job.source_version is not None and source.row_version != job.source_version:
        return "Source changed after this job was created"
    if job.kind == "collect" and not source.enabled:
        return "Source was disabled"
    spec = KINDS.get(source.kind)
    if spec is not None:
        try:
            cfg = spec.model.model_validate(source.config or {})
        except Exception:
            return "Source configuration is no longer valid"
        if not spec.collectable(cfg):
            return "Collection for this source is not available"
    return None


def claim_next(session: Session, node: CbomScanNode, settings: CbomCollectionSettings, now: _dt.datetime) -> dict | None:
    """Claim the oldest runnable job for this node and return its payload (with decrypted secrets)."""
    reap(session, now, node_id=node.id)
    query = (
        select(CbomCollectionJob)
        .where(CbomCollectionJob.node_id == node.id, CbomCollectionJob.team_id == node.team_id,
               CbomCollectionJob.status == "pending")
        .order_by(CbomCollectionJob.id)
        .limit(25)
    )
    if session.get_bind().dialect.name == "postgresql":
        query = query.with_for_update(skip_locked=True)
    for job in session.exec(query).all():
        source = session.get(CbomCollectionSource, job.source_id) if job.source_id else None
        reason = _invalid_reason(job, source, node)
        if reason:
            changed = session.exec(
                update(CbomCollectionJob).where(CbomCollectionJob.id == job.id, CbomCollectionJob.status == "pending")
                .values(status="cancelled", finished_at=now, error=reason)
            ).rowcount
            if changed:
                session.refresh(job)
                if job.kind == "collect":
                    refund_job(session, job, _run_of(session, job))
                _test_result_from_job(session, job, now)
                recompute_run(session, job.run_id, now)
                audit(session, team_id=job.team_id, actor_type="system", actor_id=None, action="job.cancelled",
                      object_type="job", object_id=job.id, changed_fields=["stale_source"])
                log("job cancelled", team=job.team_id, job=job.id, reason="stale_source")
            continue
        is_network = job.kind == "discovery" or (source is not None and source.kind == "network_range")
        if is_network and settings.stop_all_network:
            continue
        if job.kind != "test_connection" and not window_allows(_job_window(source, settings), settings.window_timezone, now):
            continue
        lease_id = secrets.token_hex(12)
        changed = session.exec(
            update(CbomCollectionJob)
            .where(CbomCollectionJob.id == job.id, CbomCollectionJob.status == "pending")
            .values(status="claimed", lease_id=lease_id, lease_expires_at=now + LEASE, claimed_at=now,
                    attempts=CbomCollectionJob.attempts + 1, asset_count=0, outcome=None)
        ).rowcount
        if not changed:
            continue
        session.refresh(job)
        _start_attempt(session, job, now)
        recompute_run(session, job.run_id, now)
        node.last_claim_at = now
        session.add(node)
        audit(session, team_id=node.team_id, actor_type="node", actor_id=node.id, action="job.claim",
              object_type="job", object_id=job.id)
        payload: dict[str, Any] = {
            "job": {"id": job.id, "kind": job.kind, "lease_id": lease_id, "lease_seconds": int(LEASE.total_seconds()),
                    "attempt": job.attempts, "run_id": job.run_id},
            "scope": _scope_for(job, source, settings, now),
        }
        if source is not None:
            payload["source"] = {
                "id": source.id, "kind": source.kind, "name": source.name, "config": source.config or {},
                "secrets": decrypt_secrets(source.secret_encrypted),
            }
        log("job claimed", team=job.team_id, job=job.id, node=node.id, kind=job.kind, attempt=job.attempts)
        return payload
    return None


def _start_attempt(session: Session, job: CbomCollectionJob, now: _dt.datetime) -> None:
    """A (re)claimed job starts clean: assets from earlier attempts are dropped."""
    if job.first_claimed_at is None:
        job.first_claimed_at = now
        session.add(job)
    if job.attempts > 1:
        session.exec(delete(CbomCollectedAsset).where(CbomCollectedAsset.job_id == job.id,
                                                      CbomCollectedAsset.attempt < job.attempts))


def renew_leases(session: Session, node: CbomScanNode, now: _dt.datetime,
                 running: list[tuple[int, str]] | None = None) -> list[int]:
    """Extend the leases of the jobs the node says it is running.

    ``running`` None (an older node that does not report) renews every claimed job of the node.
    Otherwise only the reported (job, lease) pairs are renewed, and a claimed job the node has stopped
    reporting is released once it is older than the grace period.  Returns the released job ids."""
    if running is None:
        session.exec(
            update(CbomCollectionJob)
            .where(CbomCollectionJob.node_id == node.id, CbomCollectionJob.status == "claimed")
            .values(lease_expires_at=now + LEASE)
        )
        return []
    reported = {(int(job_id), str(lease)) for job_id, lease in running}
    released: list[int] = []
    runs: set[int] = set()
    for job in session.exec(select(CbomCollectionJob).where(
            CbomCollectionJob.node_id == node.id, CbomCollectionJob.status == "claimed")).all():
        if (job.id, job.lease_id) in reported:
            session.exec(update(CbomCollectionJob)
                         .where(CbomCollectionJob.id == job.id, CbomCollectionJob.lease_id == job.lease_id,
                                CbomCollectionJob.status == "claimed")
                         .values(lease_expires_at=now + LEASE))
            continue
        if job.claimed_at is not None and job.claimed_at > now - ORPHAN_GRACE:
            continue  # claimed moments ago; the node may not have reported it yet
        retry = job.attempts < MAX_ATTEMPTS
        values: dict[str, Any] = {"lease_id": None, "lease_expires_at": None}
        if not retry:
            values.update(finished_at=now, error="The scan node stopped running this job", outcome="failed")
        changed = session.exec(
            update(CbomCollectionJob)
            .where(CbomCollectionJob.id == job.id, CbomCollectionJob.status == "claimed",
                   CbomCollectionJob.lease_id == job.lease_id)
            .values(status="pending" if retry else "failure", **values)
        ).rowcount
        if changed:
            session.refresh(job)
            refunded = 0
            if not retry and job.kind == "collect":
                refunded = refund_job(session, job, _run_of(session, job))
            _test_result_from_job(session, job, now)
            audit(session, team_id=job.team_id, actor_type="system", actor_id=None,
                  action="job.released" if retry else "job.failure", object_type="job", object_id=job.id,
                  changed_fields=["not_reported_by_node"])
            log("job released", team=job.team_id, job=job.id, node=node.id, retry=retry, refunded_c=refunded)
            released.append(job.id)
            if job.run_id:
                runs.add(job.run_id)
    for run_id in runs:
        recompute_run(session, run_id, now)
    return released


def cancel_ids_for_node(session: Session, node: CbomScanNode, settings: CbomCollectionSettings) -> list[int]:
    """Claimed jobs this node should stop: cancel requested, source changed, or network scanning stopped."""
    out: list[int] = []
    for job in session.exec(select(CbomCollectionJob).where(
            CbomCollectionJob.node_id == node.id, CbomCollectionJob.status == "claimed")).all():
        source = session.get(CbomCollectionSource, job.source_id) if job.source_id else None
        is_network = job.kind == "discovery" or (source is not None and source.kind == "network_range")
        if _invalid_reason(job, source, node) or (is_network and settings.stop_all_network):
            out.append(job.id)
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
    if job.status == "success" and samples:
        ok = sum(1 for s in samples if isinstance(s, dict) and s.get("status") in ("ready", "ok", "passed"))
        status = "passed" if ok == len(samples) else ("failed" if ok == 0 else "partial")
        summary = f"{ok} of {len(samples)} samples ready"
        notes = [str(s.get("note") or s.get("error") or s.get("status")) for s in samples
                 if isinstance(s, dict) and s.get("status") not in ("ready", "ok", "passed")]
        if notes:  # the first reason, so lists that show only the summary still say why
            summary = f"{summary}: {notes[0]}"[:512]
    elif job.status == "success":
        status, summary = "passed", str(result.get("summary") or "Connection test passed")[:512]
    elif job.status == "cancelled":
        status, summary = "never", (job.error or "Test cancelled")[:512]
    elif job.status == "expired":
        status, summary = "error", "No scan node ran the test within 24 hours"
    else:
        status, summary = "failed", (job.error or str(result.get("summary") or "Connection test failed"))[:512]
    source.last_test_status = status
    source.last_test_summary = summary
    source.last_test_at = now
    source.last_test_result = {"samples": samples} if samples else ({"summary": summary})
    session.add(source)


def _stop_reason(session: Session, job: CbomCollectionJob, source: CbomCollectionSource | None,
                 node: CbomScanNode | None) -> str | None:
    """_invalid_reason plus the team's network stop, for writes coming back from a running job."""
    reason = _invalid_reason(job, source, node)
    if reason:
        return reason
    is_network = job.kind == "discovery" or (source is not None and source.kind == "network_range")
    if is_network and get_or_create_settings(session, job.team_id).stop_all_network:
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


def _outcome(job: CbomCollectionJob, status: str, result: dict[str, Any], stored: int) -> tuple[str, dict[str, Any]]:
    """ok / partial / failed from the node's own target counts and what the server actually stored."""
    if status != "success":
        return "failed", {}
    counts = result.get("counts") if isinstance(result.get("counts"), dict) else {}
    ok = int(counts.get("ok") or 0) if str(counts.get("ok", "")).isdigit() else 0
    failed = int(counts.get("failed") or 0) if str(counts.get("failed", "")).isdigit() else 0
    skipped = int(counts.get("skipped") or 0) if str(counts.get("skipped", "")).isdigit() else 0
    extra: dict[str, Any] = {}
    reported = result.get("asset_count")
    if job.kind == "collect" and isinstance(reported, int) and reported != stored:
        extra["asset_mismatch"] = {"reported": reported, "stored": stored}
    if not counts:
        return ("partial" if extra or result.get("truncated") else "ok"), extra
    if ok == 0 and (failed or skipped):
        return "failed", extra
    if failed or skipped or extra or result.get("truncated"):
        return "partial", extra
    return "ok", extra


def finish_job(
    session: Session, node: CbomScanNode | None, job_id: int, lease_id: str, status: str,
    result: dict[str, Any] | None, error: str | None, now: _dt.datetime, *, team_id: int | None = None,
    known_secrets: list[str] | None = None,
) -> CbomCollectionJob:
    """Record a job's end.  ``node`` None is the cloud worker.  Failed or cancelled collect jobs are refunded."""
    job = _owned_job(session, node, job_id, team_id)
    source = session.get(CbomCollectionSource, job.source_id) if job.source_id else None
    known = list(decrypt_secrets(source.secret_encrypted).values()) if source is not None else []
    known += [s for s in (known_secrets or []) if isinstance(s, str)]
    clean_result = scrub(result or {}, known, exact_keys=True)
    clean_error = scrub(error, known) if error else None
    invalid = _stop_reason(session, job, source, node) if job.status == "claimed" and job.lease_id == lease_id else None
    if invalid and status == "success":
        status, clean_error = "cancelled", invalid  # collected under settings that no longer apply
    stored = session.exec(select(func.count()).select_from(CbomCollectedAsset).where(
        CbomCollectedAsset.job_id == job.id, CbomCollectedAsset.attempt == job.attempts)).one()
    outcome, extra = _outcome(job, status, clean_result if isinstance(clean_result, dict) else {}, int(stored))
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
    if job.kind == "collect" and status in ("failure", "cancelled"):
        refunded = refund_job(session, job, _run_of(session, job))
    _test_result_from_job(session, job, now)
    recompute_run(session, job.run_id, now)
    audit(session, team_id=job.team_id, actor_type="node" if node else "system", actor_id=node.id if node else None,
          action=f"job.{status}", object_type="job", object_id=job.id)
    counts = clean_result.get("counts") if isinstance(clean_result, dict) and isinstance(clean_result.get("counts"), dict) else {}
    duration = int((now - job.claimed_at).total_seconds()) if job.claimed_at else None
    log("job finished", team=job.team_id, run=job.run_id, job=job.id, node=node.id if node else "cloud", kind=job.kind,
        attempt=job.attempts, status=status, outcome=outcome, ok=counts.get("ok"), failed=counts.get("failed"),
        skipped=counts.get("skipped"), assets=int(stored), duration_s=duration, refunded_c=refunded)
    return job


# ----------------------------------------------------------------------------- assets
def _asset_key(asset_type: str, location: str, facts: dict[str, Any], name: str | None) -> str:
    identity = facts.get("fingerprint_sha256") or facts.get("identity") or name or ""
    return hashlib.sha256(f"{asset_type}|{location}|{identity}".encode("utf-8", "replace")).hexdigest()


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


def add_assets(
    session: Session, node: CbomScanNode | None, job_id: int, lease_id: str, assets: list[dict[str, Any]],
    now: _dt.datetime, *, team_id: int | None = None, known_secrets: list[str] | None = None,
) -> dict[str, Any]:
    """Store one batch of a running job's assets.  Team, run and source always come from the job row."""
    job = _owned_job(session, node, job_id, team_id)
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
                refund_job(session, job, _run_of(session, job))
            _test_result_from_job(session, job, now)
            recompute_run(session, job.run_id, now)
            audit(session, team_id=job.team_id, actor_type="system", actor_id=None, action="job.cancelled",
                  object_type="job", object_id=job.id, changed_fields=["stale_source"])
            log("job cancelled", team=job.team_id, job=job.id, reason="stale_source_on_assets")
        session.commit()
        raise HTTPException(status_code=409, detail=f"Stop this job: {reason}")
    if job.kind == "test_connection":  # a connection test proves access; it does not build inventory
        return {"accepted": 0, "duplicate": 0, "rejected": 0, "dropped": len(assets), "total_for_attempt": 0,
                "cap_reached": False, "ignored": "connection tests do not store assets"}
    known = list(decrypt_secrets(source.secret_encrypted).values()) if source is not None else []
    known += [s for s in (known_secrets or []) if isinstance(s, str)]
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
        key = _asset_key(asset_type, location, facts, name)
        if key in keys:
            in_batch_dups += 1
            continue
        keys.add(key)
        verdict = classify(asset_type, algorithm, key_size, protocol, facts, now)
        rows.append({
            "team_id": job.team_id, "run_id": job.run_id, "job_id": job.id, "source_id": job.source_id,
            "attempt": job.attempts, "asset_key": key, "asset_type": asset_type, "cdx_type": verdict["cdx_type"],
            "target": clean_text(scrub(raw.get("target"), known), 255) if raw.get("target") else None,
            "location": location, "name": name, "algorithm": algorithm, "key_size": key_size, "protocol": protocol,
            "quantum_vulnerable": verdict["quantum_vulnerable"], "impact": verdict["impact"],
            "finding_codes": verdict["finding_codes"], "finding": verdict["finding"], "facts": facts, "created_at": now,
        })
    existing = set()
    if rows:
        existing = set(session.exec(select(CbomCollectedAsset.asset_key).where(
            CbomCollectedAsset.job_id == job.id, CbomCollectedAsset.attempt == job.attempts,
            CbomCollectedAsset.asset_key.in_([r["asset_key"] for r in rows]))).all())  # type: ignore[attr-defined]
    fresh = [r for r in rows if r["asset_key"] not in existing]
    room = max(MAX_ASSETS_PER_ATTEMPT - (job.asset_count or 0), 0)
    cap_reached = len(fresh) > room
    dropped = max(len(fresh) - room, 0)
    fresh = fresh[:room]
    if fresh:
        # the counter update re-checks the lease, so a batch racing the reaper or the result is refused
        changed = session.exec(
            update(CbomCollectionJob)
            .where(CbomCollectionJob.id == job.id, CbomCollectionJob.status == "claimed",
                   CbomCollectionJob.lease_id == lease_id,
                   CbomCollectionJob.asset_count + len(fresh) <= MAX_ASSETS_PER_ATTEMPT)
            .values(asset_count=CbomCollectionJob.asset_count + len(fresh))
        ).rowcount
        if not changed:
            raise HTTPException(status_code=409, detail="This job is no longer leased to this node")
    inserted = _insert_ignore(session, fresh)
    if inserted < len(fresh):  # another request stored some of these keys first
        session.exec(update(CbomCollectionJob).where(CbomCollectionJob.id == job.id)
                     .values(asset_count=CbomCollectionJob.asset_count - (len(fresh) - inserted)))
    total = int(session.exec(select(func.count()).select_from(CbomCollectedAsset).where(
        CbomCollectedAsset.job_id == job.id, CbomCollectedAsset.attempt == job.attempts)).one())
    duplicate = in_batch_dups + len(existing) + (len(fresh) - inserted)
    log("assets stored", team=job.team_id, run=job.run_id, job=job.id, attempt=job.attempts, accepted=inserted,
        duplicate=duplicate, rejected=rejected, dropped=dropped, total=total, cap_reached=cap_reached)
    if cap_reached and isinstance(job.result, dict):
        job.result = {**job.result, "truncated": True}
        session.add(job)
    return {"accepted": inserted, "duplicate": duplicate, "rejected": rejected, "dropped": dropped,
            "total_for_attempt": total, "cap_reached": cap_reached}


# ----------------------------------------------------------------------------- cloud worker
def claim_cloud_job(session: Session, now: _dt.datetime, worker: str) -> dict | None:
    """Claim the oldest node-less collect job (AWS accounts, identity providers) for the cloud worker."""
    query = (
        select(CbomCollectionJob)
        .where(CbomCollectionJob.node_id.is_(None), CbomCollectionJob.kind == "collect",  # type: ignore[union-attr]
               CbomCollectionJob.status == "pending")
        .order_by(CbomCollectionJob.id)
        .limit(25)
    )
    if session.get_bind().dialect.name == "postgresql":
        query = query.with_for_update(skip_locked=True)
    for job in session.exec(query).all():
        source = session.get(CbomCollectionSource, job.source_id) if job.source_id else None
        spec = KINDS.get(source.kind) if source is not None else None
        reason = _invalid_reason(job, source, None)
        if reason is None and (spec is None or not spec.node_less):
            reason = "This source needs a scan node"
        if reason:
            changed = session.exec(
                update(CbomCollectionJob).where(CbomCollectionJob.id == job.id, CbomCollectionJob.status == "pending")
                .values(status="cancelled", finished_at=now, error=reason, outcome="failed")
            ).rowcount
            if changed:
                session.refresh(job)
                refund_job(session, job, _run_of(session, job))
                recompute_run(session, job.run_id, now)
                audit(session, team_id=job.team_id, actor_type="system", actor_id=None, action="job.cancelled",
                      object_type="job", object_id=job.id, changed_fields=["stale_source"])
            continue
        lease_id = secrets.token_hex(12)
        changed = session.exec(
            update(CbomCollectionJob)
            .where(CbomCollectionJob.id == job.id, CbomCollectionJob.status == "pending")
            .values(status="claimed", lease_id=lease_id, lease_expires_at=now + LEASE, claimed_at=now,
                    attempts=CbomCollectionJob.attempts + 1, asset_count=0, outcome=None)
        ).rowcount
        if not changed:
            continue
        session.refresh(job)
        _start_attempt(session, job, now)
        recompute_run(session, job.run_id, now)
        audit(session, team_id=job.team_id, actor_type="system", actor_id=None, action="job.claim",
              object_type="job", object_id=job.id, changed_fields=["cloud_worker"])
        log("job claimed", team=job.team_id, run=job.run_id, job=job.id, node="cloud", worker=worker,
            kind=source.kind, attempt=job.attempts)
        return {
            "job": {"id": job.id, "team_id": job.team_id, "run_id": job.run_id, "lease_id": lease_id,
                    "attempt": job.attempts, "max_runtime_s": int(MAX_RUNTIME["collect"].total_seconds())},
            "source": {"id": source.id, "kind": source.kind, "name": source.name, "config": source.config or {},
                       "last_test_status": source.last_test_status,
                       "secrets": decrypt_secrets(source.secret_encrypted)},
        }
    return None


def renew_cloud_lease(session: Session, job_id: int, lease_id: str, now: _dt.datetime) -> str | None:
    """Extend a cloud job's lease.  Returns why it must stop, or None to carry on."""
    job = session.get(CbomCollectionJob, job_id)
    if job is None or job.node_id is not None or job.status != "claimed" or job.lease_id != lease_id:
        return "This job is no longer leased to the cloud worker"
    source = session.get(CbomCollectionSource, job.source_id) if job.source_id else None
    reason = _invalid_reason(job, source, None)
    if reason:
        return reason
    session.exec(update(CbomCollectionJob)
                 .where(CbomCollectionJob.id == job_id, CbomCollectionJob.lease_id == lease_id,
                        CbomCollectionJob.status == "claimed")
                 .values(lease_expires_at=now + LEASE))
    return None


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
            refunded += refund_job(session, job, run)
    if run.cancelled_at is None and (jobs or asked):
        run.cancelled_by = user_id
        run.cancelled_at = now
        session.add(run)
    recompute_run(session, run.id, now)
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
    if job.node_id is None and job.kind == "collect":
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
