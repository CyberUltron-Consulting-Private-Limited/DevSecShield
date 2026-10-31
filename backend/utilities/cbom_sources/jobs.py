"""Job queue for scan nodes: create, claim, finish, cancel, expire, and run roll-up.

Every state change is a guarded ``UPDATE ... WHERE status = <expected>`` so two requests can never
move the same job twice (two nodes claiming, a cancel racing a claim, a late result after a lease
expired).  Credits are charged and refunded inside the same transaction as the job change.
"""
from __future__ import annotations

import datetime as _dt
import secrets
from typing import Any

from fastapi import HTTPException
from sqlalchemy import update
from sqlmodel import Session, select

from backend.new_models import (
    CbomCollectionJob,
    CbomCollectionRun,
    CbomCollectionSettings,
    CbomCollectionSource,
    CbomScanNode,
    Team,
)
from backend.utilities.cbom_sources import targets as T
from backend.utilities.cbom_sources.common import audit, log
from backend.utilities.cbom_sources.crypto import decrypt_secrets, scrub
from backend.utilities.cbom_sources.kinds import KINDS
from backend.utilities.cbom_sources.planning import credits, node_status
from backend.utilities.cbom_sources.settings import team_exclusions, window_allows

LEASE = _dt.timedelta(minutes=15)
MAX_ATTEMPTS = 3
TEST_JOB_TTL = _dt.timedelta(hours=24)
COLLECT_JOB_TTL = _dt.timedelta(days=7)
TERMINAL = ("success", "failure", "cancelled", "expired")
OPEN = ("pending", "claimed")


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
        new = "done"
    elif all(s == "cancelled" for s in statuses):
        new = "cancelled"
    elif all(s in ("failure", "expired") for s in statuses):
        new = "failed"
    else:
        new = "partial"
    if new != run.status:
        run.status = new
        run.last_updated = now
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
                if target == "failure" and job.kind == "collect":
                    refund_job(session, job, session.get(CbomCollectionRun, job.run_id) if job.run_id else None)
                _test_result_from_job(session, job, now)
                log("job lease expired", team=job.team_id, job=job.id, node=job.node_id, status=target)
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
                    if job.kind == "collect":
                        refund_job(session, job, session.get(CbomCollectionRun, job.run_id) if job.run_id else None)
                    _test_result_from_job(session, job, now)
                    log("job expired", team=job.team_id, job=job.id, node=job.node_id)
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
    """Cancel the source's pending jobs (refunding collect jobs).  Claimed jobs fail on their next call."""
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
def _scope_for(job: CbomCollectionJob, source: CbomCollectionSource | None, settings: CbomCollectionSettings) -> dict[str, Any]:
    """What the node may touch.  Exclusions are the union of those at job creation and now."""
    exclusions = sorted(set((job.params or {}).get("exclusions") or []) | set(_snapshot_exclusions(settings)))
    scope: dict[str, Any] = {"never_scan": exclusions}
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


def _invalid_reason(job: CbomCollectionJob, source: CbomCollectionSource | None, node: CbomScanNode) -> str | None:
    if job.source_id is None:
        return None if job.kind == "discovery" else "Source no longer exists"
    if source is None or source.team_id != node.team_id:
        return "Source no longer exists"
    if source.node_id != node.id:
        return "Source moved to another scan node"
    if job.source_version is not None and source.row_version != job.source_version:
        return "Source changed after this job was created"
    if job.kind == "collect" and not source.enabled:
        return "Source was disabled"
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
                    refund_job(session, job, session.get(CbomCollectionRun, job.run_id) if job.run_id else None)
                recompute_run(session, job.run_id, now)
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
                    attempts=CbomCollectionJob.attempts + 1)
        ).rowcount
        if not changed:
            continue
        session.refresh(job)
        recompute_run(session, job.run_id, now)
        node.last_claim_at = now
        session.add(node)
        audit(session, team_id=node.team_id, actor_type="node", actor_id=node.id, action="job.claim",
              object_type="job", object_id=job.id)
        payload: dict[str, Any] = {
            "job": {"id": job.id, "kind": job.kind, "lease_id": lease_id, "lease_seconds": int(LEASE.total_seconds()),
                    "attempt": job.attempts, "run_id": job.run_id},
            "scope": _scope_for(job, source, settings),
        }
        if source is not None:
            payload["source"] = {
                "id": source.id, "kind": source.kind, "name": source.name, "config": source.config or {},
                "secrets": decrypt_secrets(source.secret_encrypted),
            }
        log("job claimed", team=job.team_id, job=job.id, node=node.id, kind=job.kind, attempt=job.attempts)
        return payload
    return None


def renew_leases(session: Session, node: CbomScanNode, now: _dt.datetime) -> None:
    session.exec(
        update(CbomCollectionJob)
        .where(CbomCollectionJob.node_id == node.id, CbomCollectionJob.status == "claimed")
        .values(lease_expires_at=now + LEASE)
    )


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


def finish_job(
    session: Session, node: CbomScanNode, job_id: int, lease_id: str, status: str,
    result: dict[str, Any] | None, error: str | None, now: _dt.datetime,
) -> CbomCollectionJob:
    job = session.get(CbomCollectionJob, job_id)
    if job is None or job.node_id != node.id or job.team_id != node.team_id:
        raise HTTPException(status_code=404, detail="Job not found")
    source = session.get(CbomCollectionSource, job.source_id) if job.source_id else None
    known = list(decrypt_secrets(source.secret_encrypted).values()) if source is not None else []
    clean_result = scrub(result or {}, known)
    clean_error = scrub(error, known) if error else None
    changed = session.exec(
        update(CbomCollectionJob)
        .where(CbomCollectionJob.id == job_id, CbomCollectionJob.node_id == node.id,
               CbomCollectionJob.status == "claimed", CbomCollectionJob.lease_id == lease_id)
        .values(status=status, finished_at=now, result=clean_result,
                error=(str(clean_error)[:1024] if clean_error else None), lease_id=None, lease_expires_at=None)
    ).rowcount
    if not changed:
        raise HTTPException(status_code=409, detail="This job is no longer leased to this node")
    session.refresh(job)
    _test_result_from_job(session, job, now)
    recompute_run(session, job.run_id, now)
    audit(session, team_id=node.team_id, actor_type="node", actor_id=node.id, action=f"job.{status}",
          object_type="job", object_id=job.id)
    log("job finished", team=job.team_id, job=job.id, node=node.id, kind=job.kind, status=status)
    return job


# ----------------------------------------------------------------------------- runs
def cancel_run(session: Session, run: CbomCollectionRun, user_id: int, now: _dt.datetime) -> int:
    """Cancel the run's pending jobs and refund exactly those.  Returns centi-credits refunded."""
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
    if run.cancelled_at is None and jobs:
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
        return "Running on the scan node"
    if job.status != "pending":
        return None
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
