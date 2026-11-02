"""ZeroShield cloud worker for CBOM Sources: collects node-less sources (AWS accounts, Azure Key Vault, Google Cloud
KMS / CA Service / Secret Manager, identity providers).

    python -m backend.workers.cbom_cloud_worker            # loop
    python -m backend.workers.cbom_cloud_worker --once     # one job (tests)

It uses the same job table, guarded claims and leases as scan nodes: several workers can run side by
side, a crashed worker's job is re-queued when its lease expires, and every asset batch re-checks the
lease so a stale worker can never write into a job another worker re-claimed.  It also runs the job
reaper for every team once a minute, so jobs no node or worker will finish are refunded on time.
"""
from __future__ import annotations

import argparse
import os
import signal
import socket
import time
from typing import Any

from fastapi import HTTPException
from sqlmodel import Session

from backend.get_db import get_db
from backend.utilities.cbom_sources import jobs as J
from backend.utilities.cbom_sources.common import log, new_ref, utcnow
from backend.utilities.cbom_sources.settings import get_or_create_settings

BATCH = 500
RENEW_EVERY_S = 60
REAP_EVERY_S = 60
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


def reap_all(engine) -> None:
    with Session(engine) as session:
        J.safe_reap(session, utcnow())


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
    last_reap = 0.0
    while not _stopping:
        if time.monotonic() - last_reap >= REAP_EVERY_S:
            reap_all(engine)
            last_reap = time.monotonic()
        try:
            busy = run_once(engine, worker)
        except Exception as exc:  # database hiccup: wait and carry on
            log("cloud worker loop FAILED", ref=new_ref(), error=type(exc).__name__)
            busy = False
        if not busy:
            time.sleep(IDLE_SLEEP_S)
    if scheduler_stop is not None:
        scheduler_stop.set()
    log("cloud worker stopped", worker=worker)


if __name__ == "__main__":
    main()
