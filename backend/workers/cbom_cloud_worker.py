"""ZeroShield cloud worker for CBOM Sources: collects node-less sources (AWS accounts, Azure Key Vault, Google Cloud
KMS / CA Service / Secret Manager, identity providers, Certificate Transparency logs).

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


def _aws_lab_mode(config: dict[str, Any]) -> str | None:
    """"same_account" when this AWS source's role is in the deployment's own account and lab mode allows it (the
    collector decides again and logs the use; this only labels the run, failed runs included)."""
    from backend.utilities.cbom_sources.kinds import aws_account_id
    from backend.utilities.cbom_sources.lab_mode import LAB_MODE, lab_same_account
    from backend.utilities.cbom_sources.templates import zeroshield_account_id

    own = zeroshield_account_id()
    same = bool(own) and aws_account_id(str(config.get("role_arn") or "")) == own
    return LAB_MODE if same and (config.get("scope") or "account") == "account" and lab_same_account() else None


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
        self.read = 0  # emitted rows that are assets, not coverage gaps
        self.store_failed: str | None = None  # an asset batch was lost to an error that is not the API's refusal
        self.lab_mode: str | None = None  # "same_account": an AWS source collected in lab mode (lab_mode.py)

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
        if asset.get("type") != "coverage":
            self.read += 1
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
            except Exception as exc:
                # Anything else (the database connection lost, a failover): this batch is gone.  The job fails even
                # when the collector that called emit() or should_stop() swallows the exception, and it stops (no
                # more reads of the customer's cloud, no next SSM command) since nothing more would be kept.
                self.store_failed = type(exc).__name__
                self.stop_reason = self.stop_reason or "Collection stopped: assets could not be stored"
                log("cloud job asset batch NOT stored", team=self.job["team_id"], job=self.job["id"], assets=len(batch),
                    error=self.store_failed)
                raise

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
            elif kind in ("azure_subscription", "gcp_project") and self.source.get("last_test_status") != "passed":
                from backend.utilities.cbom_sources.planning import CLOUD_NOT_CONNECTED

                raise _Refused(CLOUD_NOT_CONNECTED[kind])
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
            elif kind == "ct_logs":
                from backend.utilities.cbom_sources.ct_collect import collect_ct

                result = collect_ct(self.source["config"], self.source["name"], self.emit, self.should_stop,
                                    deadline=self.deadline, first=self._ct_left_over())
                counts = result.get("counts") or {}
                if counts.get("total") and not (counts.get("ok") or counts.get("partial")):
                    # nothing was read: fail (and refund) so the last good collection stays the current one
                    first = next((t.get("error") for t in result.get("targets") or [] if t.get("error")), None)
                    raise _Refused(f"No domain could be searched: {first or 'every search failed'}"[:500])
            elif kind == "idp":
                from backend.utilities.cbom_sources.idp_collect import collect_idp

                out = collect_idp(self.source["config"], self.source["name"])
                for asset in out.pop("assets"):
                    self.emit(asset)
                result = out
            elif kind == "ssm_hosts":  # F1.3: zs-collect through the customer's AWS Systems Manager
                result = self._ssm()
            else:
                status, error = "failure", f"The cloud worker cannot collect {kind}"
            unread = _nothing_read(result, self.read)
            if unread:  # a job that read 0 of N targets is a failure (refunded), never "success" (C2)
                raise _Refused(unread)
        except _Refused as exc:
            status, error = "failure", str(exc)
        except Exception as exc:
            ref = new_ref()
            log("cloud job FAILED", ref=ref, team=team_id, job=self.job["id"], error=type(exc).__name__)
            status, error = "failure", f"Collection failed (ref {ref})"
        self.flush()
        if self.store_failed and status != "failure":  # a collector swallowed the failed store: the job still fails
            ref = new_ref()
            log("cloud job FAILED", ref=ref, team=team_id, job=self.job["id"], error=self.store_failed)
            status, error = "failure", f"Collection failed (ref {ref})"
        if self.stop_reason and status == "success":
            status, error = "cancelled", self.stop_reason
        targets = result.get("targets") or []
        if self.lab_mode:  # every run of a lab-mode source says so, failed runs included
            result = {**result, "lab_mode": self.lab_mode}
        result = {**result, "targets": targets[:1000], "asset_count": None, "node_version": "cloud-worker-1.0",
                  "summary": result.get("summary") or f"{sum(1 for t in targets if t.get('status') == 'ok')} of {len(targets)} targets read"}
        with Session(self.engine) as session:
            stored = None
            try:
                job = J.finish_job(session, None, self.job["id"], self.job["lease_id"], status, result, error, utcnow(),
                                   team_id=team_id, known_secrets=self.secrets)
                stored = job.asset_count
                if self.lab_mode:
                    from backend.utilities.cbom_sources.common import audit

                    audit(session, team_id=team_id, actor_type="system", actor_id=None, action="job.lab_same_account",
                          object_type="job", object_id=self.job["id"])
                session.commit()
            except HTTPException as exc:
                session.rollback()
                log("cloud job result refused", team=team_id, job=self.job["id"], reason=str(exc.detail)[:120])
        log("cloud job done", team=team_id, job=self.job["id"], status=status, emitted=self.emitted, stored=stored)

    def _ct_left_over(self) -> list[str]:
        """Names the source's previous CT job could not search (quota, time, errors): this job searches them first."""
        from sqlmodel import select

        from backend.new_models import CbomCollectionJob

        with Session(self.engine) as session:
            previous = session.exec(
                select(CbomCollectionJob).where(CbomCollectionJob.source_id == self.source["id"],
                                                CbomCollectionJob.kind == "collect",
                                                CbomCollectionJob.id != self.job["id"],
                                                CbomCollectionJob.finished_at.is_not(None))  # type: ignore[union-attr]
                .order_by(CbomCollectionJob.id.desc()).limit(1)).first()  # type: ignore[union-attr]
        targets = ((previous.result or {}).get("targets") if previous is not None else None) or []
        return [str(t.get("target")) for t in targets if isinstance(t, dict) and t.get("status") in ("skipped", "error")]

    def _aws(self) -> dict[str, Any]:
        from backend.utilities.cbom_sources.aws_collect import AwsCollectError, collect_aws

        if self.source.get("last_test_status") != "passed":
            raise _Refused("Validate the AWS role first; only a role that passed validation is scanned")
        with Session(self.engine) as session:
            external_id = get_or_create_settings(session, self.job["team_id"]).aws_external_id
        self.lab_mode = _aws_lab_mode(self.source.get("config") or {})
        try:
            return collect_aws(self.job["team_id"], self.source["config"], external_id, self.emit, self.should_stop)
        except AwsCollectError as exc:
            raise _Refused(str(exc)) from exc


    def _ssm(self) -> dict[str, Any]:
        from backend.new_models import CbomCollectionSource
        from backend.utilities.cbom_sources.transports.claim import payload_for_cloud
        from backend.utilities.cbom_sources.transports.cloud import SsmRefused, collect_ssm
        from backend.utilities.cbom_sources.transports.ssm import SsmTransport, role_client_factory

        team_id = self.job["team_id"]
        with Session(self.engine) as session:
            settings = get_or_create_settings(session, team_id)
            external_id = settings.aws_external_id
            exclusions = [str(i.get("cidr")) for i in (settings.network_exclusions or []) if isinstance(i, dict)]
            row = session.get(CbomCollectionSource, self.source["id"])
            if row is None or row.team_id != team_id:
                raise _Refused("The source was deleted")
            config = dict(self.source.get("config") or {})
            if "transport" not in config:  # the claim did not apply the F1.3 plugin (secret_refs not present)
                config, _secrets = payload_for_cloud(session, row)
        exclusions += list(config.get("exclusions") or []) + list((self.job.get("params") or {}).get("exclusions") or [])
        transport_cfg = config.get("transport") or {}
        try:
            factory = role_client_factory(team_id, str(transport_cfg.get("role_arn") or ""), external_id)
            return collect_ssm(self.job, config, exclusions, SsmTransport(factory, log=lambda *a, **k: None), self.emit,
                               self.should_stop, self.deadline)
        except SsmRefused as exc:
            raise _Refused(str(exc)) from exc
        except Exception as exc:
            if exc.__class__.__name__ == "NoZeroShieldCredentials":
                raise _Refused("ZeroShield's AWS principal is not configured in this deployment") from exc
            raise


class _Refused(Exception):
    """A reason that is safe to show the customer."""


def _nothing_read(result: dict[str, Any], read: int) -> str | None:
    """The failure reason when a collector read none of its targets and stored no asset (only coverage rows: denied,
    API not enabled, unreachable), else None.  Such a job fails, so it is refunded like any failed job and the source's
    last good collection stays the current one; its coverage rows stay on the run and say what was refused.  Targets
    that were all skipped (a stop, the deadline) are not "unread": the job ends cancelled instead."""
    counts = result.get("counts") if isinstance(result.get("counts"), dict) else {}
    total = counts.get("total")
    if read or not isinstance(total, int) or total <= 0 or counts.get("ok") or counts.get("partial"):
        return None
    targets = [t for t in result.get("targets") or [] if isinstance(t, dict)]
    if targets and all(str(t.get("status") or "").startswith("skipped") for t in targets):
        return None
    first = next((t for t in targets if t.get("error") and not str(t.get("status") or "").startswith("skipped")), None)
    reason = f"{first.get('target')}: {first.get('error')}" if first else "every target failed"
    return f"No target could be read (0 of {total}): {reason}"[:500]


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
    # integrations forward events on their own thread too: a slow destination must not delay a schedule
    from backend.workers.integration_dispatcher import start_thread as start_dispatcher

    dispatcher_stop = start_dispatcher(engine)
    # F1.2 fleet inventory: AWS inventory sources sync on their own thread (only while CBOM_FLEET_INVENTORY is on)
    from backend.workers.cbom_inventory_sync import start_thread as start_inventory_sync

    inventory_stop = start_inventory_sync(engine)
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
    if dispatcher_stop is not None:
        dispatcher_stop.set()
    if inventory_stop is not None:
        inventory_stop.set()
    log("cloud worker stopped", worker=worker)


if __name__ == "__main__":
    main()
