"""ZeroShield cloud worker for CBOM Sources: collects node-less sources (AWS accounts, Azure Key Vault, Google Cloud
KMS / CA Service / Secret Manager, identity providers).

    python -m backend.workers.cbom_cloud_worker            # loop
    python -m backend.workers.cbom_cloud_worker --once     # one job (tests)

It uses the same job table, guarded claims and leases as scan nodes: several workers can run side by
side, a crashed worker's job is re-queued when its lease expires, and every asset batch re-checks the
lease so a stale worker can never write into a job another worker re-claimed.  It also runs the job
reaper for every team every 30 s on its own thread (a long collection never delays it), so a dead scan node's job
goes back to the queue when its lease expires and jobs no node or worker will finish are refunded on time.
"""
from __future__ import annotations

import argparse
import os
import signal
import socket
import threading
import time
from typing import Any

from fastapi import HTTPException
from sqlmodel import Session

from backend.get_db import get_db
from backend.utilities.cbom_sources import jobs as J
from backend.utilities.cbom_sources import node_auth as NA
from backend.utilities.cbom_sources.common import log, new_ref, utcnow
from backend.utilities.cbom_sources.settings import get_or_create_settings

BATCH = 500
RENEW_EVERY_S = 60
REAP_EVERY_S = 30  # lease expiry, max runtime, unconfirmed cancels and pending TTLs for every team (F1.1)
REAP_PASSES = 20  # a pass handles up to jobs.REAP_BATCH jobs per rule; a backlog is drained in up to this many passes
IDLE_SLEEP_S = 5
_stopping = False


def _on_term(_signum, _frame) -> None:
    global _stopping
    _stopping = True
    log("cloud worker stopping after the current job")


class _Job:
    def __init__(self, engine, payload: dict[str, Any]):
        self.engine = engine
        self.job = payload["job"]
        self.source = payload["source"]
        self.secrets = list((self.source.get("secrets") or {}).values())
        self.buffer: list[dict[str, Any]] = []
        self.stop_reason: str | None = None
        self.last_renew = time.monotonic()
        self.deadline = time.monotonic() + int(self.job.get("max_runtime_s") or 8 * 3600) - 120
        self.emitted = 0

    # -- leases and batches
    def should_stop(self) -> str | None:
        if self.stop_reason:
            return self.stop_reason
        if time.monotonic() > self.deadline:
            self.stop_reason = "Stopped at the maximum run time"
            return self.stop_reason
        if time.monotonic() - self.last_renew >= RENEW_EVERY_S:
            self.flush()
            with Session(self.engine) as session:
                self.stop_reason = J.renew_cloud_lease(session, self.job["id"], self.job["lease_id"], utcnow())
                session.commit()
            self.last_renew = time.monotonic()
        return self.stop_reason

    def emit(self, asset: dict[str, Any]) -> None:
        if self.stop_reason:
            return
        self.buffer.append(asset)
        self.emitted += 1
        if len(self.buffer) >= BATCH:
            self.flush()

    def flush(self) -> None:
        if not self.buffer or self.stop_reason:
            self.buffer = []
            return
        batch, self.buffer = self.buffer, []
        with Session(self.engine) as session:
            try:
                J.add_assets(session, None, self.job["id"], self.job["lease_id"], batch, utcnow(),
                             team_id=self.job["team_id"], known_secrets=self.secrets)
                session.commit()
            except HTTPException as exc:
                session.rollback()
                self.stop_reason = str(exc.detail)
                log("cloud job stopped", team=self.job["team_id"], job=self.job["id"], reason=self.stop_reason[:120])

    # -- run
    def run(self) -> None:
        kind = self.source["kind"]
        team_id = self.job["team_id"]
        status, error, result = "success", None, {}
        log("cloud job start", team=team_id, run=self.job.get("run_id"), job=self.job["id"], kind=kind,
            attempt=self.job["attempt"], source=self.source["id"])
        try:
            if kind == "aws_account":
                result = self._aws()
            elif kind == "azure_subscription":
                from backend.utilities.cbom_sources.azure_collect import AzureCollectError, collect_azure

                try:
                    result = collect_azure(team_id, self.source["config"], self.source.get("secrets") or {}, self.emit,
                                           self.should_stop)
                except AzureCollectError as exc:
                    raise _Refused(str(exc)) from exc
            elif kind == "gcp_project":
                from backend.utilities.cbom_sources.gcp_collect import GcpCollectError, collect_gcp

                try:
                    result = collect_gcp(team_id, self.source["config"], self.source.get("secrets") or {}, self.emit,
                                         self.should_stop)
                except GcpCollectError as exc:
                    raise _Refused(str(exc)) from exc
            elif kind == "idp":
                from backend.utilities.cbom_sources.idp_collect import collect_idp

                out = collect_idp(self.source["config"], self.source["name"])
                for asset in out.pop("assets"):
                    self.emit(asset)
                result = out
            else:
                status, error = "failure", f"The cloud worker cannot collect {kind}"
        except _Refused as exc:
            status, error = "failure", str(exc)
        except Exception as exc:
            ref = new_ref()
            log("cloud job FAILED", ref=ref, team=team_id, job=self.job["id"], error=type(exc).__name__)
            status, error = "failure", f"Collection failed (ref {ref})"
        self.flush()
        if self.stop_reason and status == "success":
            status, error = "cancelled", self.stop_reason
        targets = result.get("targets") or []
        result = {**result, "targets": targets[:1000], "asset_count": None, "node_version": "cloud-worker-1.0",
                  "summary": result.get("summary") or f"{sum(1 for t in targets if t.get('status') == 'ok')} of {len(targets)} targets read"}
        with Session(self.engine) as session:
            stored = None
            try:
                job = J.finish_job(session, None, self.job["id"], self.job["lease_id"], status, result, error, utcnow(),
                                   team_id=team_id, known_secrets=self.secrets)
                stored = job.asset_count
                session.commit()
            except HTTPException as exc:
                session.rollback()
                log("cloud job result refused", team=team_id, job=self.job["id"], reason=str(exc.detail)[:120])
        log("cloud job done", team=team_id, job=self.job["id"], status=status, emitted=self.emitted, stored=stored)

    def _aws(self) -> dict[str, Any]:
        from backend.utilities.cbom_sources.aws_collect import AwsCollectError, collect_aws

        if self.source.get("last_test_status") != "passed":
            raise _Refused("Validate the AWS role first; only a role that passed validation is scanned")
        with Session(self.engine) as session:
            external_id = get_or_create_settings(session, self.job["team_id"]).aws_external_id
        try:
            return collect_aws(self.job["team_id"], self.source["config"], external_id, self.emit, self.should_stop)
        except AwsCollectError as exc:
            raise _Refused(str(exc)) from exc


class _Refused(Exception):
    """A reason that is safe to show the customer."""


def run_once(engine, worker: str) -> bool:
    now = utcnow()
    with Session(engine) as session:
        payload = J.claim_cloud_job(session, now, worker)
        session.commit()
    if payload is None:
        return False
    _Job(engine, payload).run()
    return True


_PASSES = [0]
SUMMARY_EVERY = 10  # a reaper summary line at least every this many passes (and whenever anything changed)


def _queue_facts(session, now) -> dict:
    """Queue depth for the summary line, read through the partial indexes (pending, claimed, refund-due)."""
    from sqlalchemy import func
    from sqlmodel import select

    from backend.new_models import CbomCollectionJob as Job

    pending = session.exec(select(func.count()).select_from(Job).where(Job.status == "pending")).one()
    claimed = session.exec(select(func.count()).select_from(Job).where(Job.status == "claimed")).one()
    oldest = session.exec(select(func.min(Job.created_at)).where(Job.status == "pending")).one()
    return {"pending": int(pending), "claimed": int(claimed),
            "oldest_pending_s": int((now - oldest).total_seconds()) if oldest else None,
            "refund_backlog": J.refund_backlog(session)}


def reap_all(engine) -> int:
    """One reaper pass over every team: lease and age rules (each rule reads only its jobs, through partial indexes,
    committed every ``REAP_COMMIT_EVERY`` jobs), the run reconcile, refund settlement (one statement per run with a
    refund due, so credits come back within one pass, about 30 s), and the protocol-1 nonce sweep (moved here from
    the heartbeat, DA E4).  Logs ``reap pass ...`` when anything changed, and every ``SUMMARY_EVERY`` passes."""
    moved = 0
    stats: dict[str, int] = {}
    settled = {"jobs": 0, "centi": 0}
    swept = 0
    for _ in range(REAP_PASSES):
        with Session(engine) as session:
            now = utcnow()
            try:
                n = J.reap(session, now, commit_every=J.REAP_COMMIT_EVERY, stats=stats)
                session.commit()
            except Exception as exc:  # a database hiccup: the next tick tries again
                session.rollback()
                log("reap FAILED", ref=new_ref(), error=type(exc).__name__)
                return moved
        moved += n
        if n < J.REAP_BATCH:
            break
    with Session(engine) as session:
        now = utcnow()
        try:
            out = J.settle_refunds(session)
            session.commit()
            settled = {"jobs": out["jobs"], "centi": out["centi"]}
            swept = NA.sweep_nonces(session, now, every_s=0)
            session.commit()
            _PASSES[0] += 1
            if moved or settled["jobs"] or _PASSES[0] % SUMMARY_EVERY == 0:
                log("reap pass", at=int(time.time()), moved=moved, lease_expired=stats.get("lease_expired", 0),
                    expired=stats.get("expired", 0), max_runtime=stats.get("max_runtime", 0),
                    cancel_unconfirmed=stats.get("cancel_unconfirmed", 0), refunds_settled=settled["jobs"],
                    refunded_c=settled["centi"], nonces_swept=swept, **_queue_facts(session, now))
        except Exception as exc:
            session.rollback()
            log("reap settle FAILED", ref=new_ref(), error=type(exc).__name__)
    return moved


def start_reaper(engine) -> threading.Event:
    """Reap on its own thread: the job loop can be busy with one AWS collection for hours, and a dead scan node's job
    must still go back to the queue when its lease expires."""
    stop = threading.Event()

    def loop() -> None:
        while not stop.is_set():
            reap_all(engine)
            stop.wait(REAP_EVERY_S)

    threading.Thread(target=loop, name="cbom-reaper", daemon=True).start()
    return stop


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--once", action="store_true", help="run at most one job and exit")
    args = parser.parse_args()
    signal.signal(signal.SIGTERM, _on_term)
    signal.signal(signal.SIGINT, _on_term)
    engine = get_db()
    worker = f"{socket.gethostname()}:{os.getpid()}"
    log("cloud worker started", worker=worker)
    if args.once:
        reap_all(engine)
        run_once(engine, worker)
        return
    # schedules and drift run on their own thread: this loop can be busy with one AWS collection for hours
    from backend.workers.cbom_scheduler import start_thread

    scheduler_stop = start_thread(engine)
    # integrations forward events on their own thread too: a slow destination must not delay a schedule
    from backend.workers.integration_dispatcher import start_thread as start_dispatcher

    dispatcher_stop = start_dispatcher(engine)
    reaper_stop = start_reaper(engine)
    while not _stopping:
        try:
            busy = run_once(engine, worker)
        except Exception as exc:  # database hiccup: wait and carry on
            log("cloud worker loop FAILED", ref=new_ref(), error=type(exc).__name__)
            busy = False
        if not busy:
            time.sleep(IDLE_SLEEP_S)
    reaper_stop.set()
    if scheduler_stop is not None:
        scheduler_stop.set()
    if dispatcher_stop is not None:
        dispatcher_stop.set()
    log("cloud worker stopped", worker=worker)


if __name__ == "__main__":
    main()
