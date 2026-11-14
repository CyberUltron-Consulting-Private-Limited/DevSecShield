"""ZeroShield cloud worker for CBOM Sources: collects node-less sources (AWS accounts, Azure Key Vault, Google Cloud
KMS / CA Service / Secret Manager, identity providers, Certificate Transparency logs).

    python -m backend.workers.cbom_cloud_worker                # loop (CBOM_CLOUD_WORKERS threads)
    python -m backend.workers.cbom_cloud_worker --workers 4    # four claim loops in this process
    python -m backend.workers.cbom_cloud_worker --once         # one job (tests)

It uses the same job table, guarded claims and leases as scan nodes, so it runs as a pool: N replicas
(``docker compose --scale`` / ``CBOM_CLOUD_REPLICAS``) times ``CBOM_CLOUD_WORKERS`` threads each.  Claims
are fair across teams and capped per team (``jobs.claim_cloud_job``, ``CBOM_CLOUD_TEAM_MAX_CONCURRENCY``); a
heartbeat thread renews each job's lease every third of ``CBOM_CLOUD_LEASE_S``; a crashed worker's job is
re-queued when its lease expires; every asset batch re-checks the lease so a stale worker can never write into
a job another worker re-claimed.  An AWS collection is split into one slice per account x region
(``cbom_sources.slices``; ``CBOM_AWS_SLICES=0`` keeps the serial walk).  SIGTERM: stop claiming, let running jobs
finish for ``CBOM_CLOUD_SHUTDOWN_GRACE_S`` (default 20 s), then give their leases back so another replica takes
them at once (a second signal releases at once).  Logs: ``cloud claim`` / ``cloud finish`` per job (team, job,
account, region, ms, outcome) and ``cloud queue`` (depth and age) every ``CBOM_CLOUD_QUEUE_LOG_S`` (default 60 s).
It also runs the job reaper for every team once a minute, so jobs no node or worker will finish are refunded on
time.
"""
from __future__ import annotations

import argparse
import os
import random
import signal
import socket
import threading
import time
from typing import Any

from fastapi import HTTPException
from sqlmodel import Session

from backend.get_db import get_db
from backend.utilities.cbom_sources import jobs as J
from backend.utilities.cbom_sources.common import log, new_ref, utcnow
from backend.utilities.cbom_sources.settings import get_or_create_settings

BATCH = 500
REAP_EVERY_S = 60
IDLE_SLEEP_S = 5
RELEASED = "Released: the cloud worker is shutting down"
_stop = threading.Event()  # SIGTERM: claim nothing more
_release = threading.Event()  # grace period over: running jobs give their lease back


def _env_int(name: str, default: int, lo: int, hi: int) -> int:
    try:
        value = int(os.environ.get(name, "") or default)
    except ValueError:
        value = default
    return max(lo, min(hi, value))


def renew_every_s() -> float:
    """Heartbeat period: a third of the lease (at most a minute), so two missed beats still leave the lease alive."""
    return max(1.0, min(60.0, J.cloud_lease().total_seconds() / 3))


def _on_term(_signum, _frame) -> None:
    if _stop.is_set():  # second signal: do not wait for the grace period
        _release.set()
        log("cloud worker releasing running jobs now")
        return
    _stop.set()
    from backend.utilities.cbom_sources import aws_org

    aws_org.STOP.set()  # AWS backoff sleeps end now
    grace = _env_int("CBOM_CLOUD_SHUTDOWN_GRACE_S", 20, 0, 3600)
    log("cloud worker stopping: no new claims; running jobs finish or are released", grace_s=grace)
    timer = threading.Timer(grace, _release.set)
    timer.daemon = True
    timer.start()


def _aws_lab_mode(config: dict[str, Any]) -> str | None:
    """"same_account" when this AWS source's role is in the deployment's own account and lab mode allows it (the
    collector decides again and logs the use; this only labels the run, failed runs included)."""
    from backend.utilities.cbom_sources.kinds import aws_account_id
    from backend.utilities.cbom_sources.lab_mode import LAB_MODE, lab_same_account
    from backend.utilities.cbom_sources.templates import zeroshield_account_id

    own = zeroshield_account_id()
    same = bool(own) and aws_account_id(str(config.get("role_arn") or "")) == own
    return LAB_MODE if same and (config.get("scope") or "account") == "account" and lab_same_account() else None


class _Heartbeat(threading.Thread):
    """Renews the job's lease while the collector works, whether or not the collector calls should_stop (a single
    slow AWS call, a long CT search).  A refused renewal (lease lost, cancel, source changed) becomes the job's stop
    reason, which the collector sees at its next should_stop / emit."""

    def __init__(self, job: "_Job"):
        super().__init__(name=f"cloud-hb-{job.job['id']}", daemon=True)
        self.owner, self.done = job, threading.Event()

    def run(self) -> None:
        while not self.done.wait(renew_every_s()):
            owner = self.owner
            try:
                with Session(owner.engine) as session:
                    reason = J.renew_cloud_lease(session, owner.job["id"], owner.job["lease_id"], utcnow())
                    session.commit()
            except Exception as exc:  # a database hiccup: the next beat tries again, the lease has slack for it
                log("cloud heartbeat FAILED", job=owner.job["id"], error=type(exc).__name__)
                continue
            if reason and not owner.stop_reason:
                owner.stop_reason = reason
                log("cloud job stopped", team=owner.job["team_id"], job=owner.job["id"], reason=reason[:120])


class _Job:
    def __init__(self, engine, payload: dict[str, Any]):
        self.engine = engine
        self.job = payload["job"]
        self.source = payload["source"]
        self.secrets = list((self.source.get("secrets") or {}).values())
        self.buffer: list[dict[str, Any]] = []
        self.stop_reason: str | None = None
        self.last_flush = time.monotonic()
        self.deadline = time.monotonic() + int(self.job.get("max_runtime_s") or 8 * 3600) - 120
        self.emitted = 0
        self.kind = self.job.get("kind") or "collect"
        self.slice = self.job.get("slice") or {}
        self.released = False  # gave the lease back (shutdown) instead of finishing
        self.fanned_out = 0  # slices queued (an AWS parent): the slices finish it
        self.requeue: str | None = None  # a slice AWS kept throttling: back to the queue after a backoff
        self.store_failed: str | None = None  # an asset batch was lost to an error that is not the API's refusal
        self.lab_mode: str | None = None  # "same_account": an AWS source collected in lab mode (lab_mode.py)

    # -- leases and batches
    def should_stop(self) -> str | None:
        if self.stop_reason:
            return self.stop_reason
        if _release.is_set():
            self.stop_reason, self.released = RELEASED, True
            return self.stop_reason
        if time.monotonic() > self.deadline:
            self.stop_reason = "Stopped at the maximum run time"
            return self.stop_reason
        if time.monotonic() - self.last_flush >= renew_every_s():  # the heartbeat renews; this keeps batches moving
            self.flush()
            self.last_flush = time.monotonic()
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
        started = time.monotonic()
        status, error, result = "success", None, {}
        log("cloud job start", team=team_id, run=self.job.get("run_id"), job=self.job["id"], kind=kind,
            attempt=self.job["attempt"], source=self.source["id"], job_kind=self.kind)
        heartbeat = _Heartbeat(self)
        heartbeat.start()
        try:
            status, error, result = self._collect(kind, team_id)
        finally:
            heartbeat.done.set()
        if self.fanned_out:
            self._log_finish(started, "fanned_out", status, slices=self.fanned_out)
            return
        try:
            self.flush()
        except Exception:  # recorded in store_failed: the job fails below
            pass
        if self.store_failed and status != "failure":  # a collector swallowed the failed store: the job still fails
            ref = new_ref()
            log("cloud job FAILED", ref=ref, team=team_id, job=self.job["id"], error=self.store_failed)
            status, error = "failure", f"Collection failed (ref {ref})"
        if self.requeue and status != "failure" and not self.released:
            self._backoff_and_release(started)
            return
        if self.released:
            with Session(self.engine) as session:
                J.release_cloud_job(session, self.job["id"], self.job["lease_id"], utcnow(), RELEASED)
                session.commit()
            self._log_finish(started, "released", "pending")
            return
        if self.stop_reason and status == "success":
            status, error = "cancelled", self.stop_reason
        targets = result.get("targets") or []
        if self.lab_mode:  # every run of a lab-mode source says so, failed runs included
            result = {**result, "lab_mode": self.lab_mode}
        result = {**result, "targets": targets[:1000], "asset_count": None, "node_version": "cloud-worker-1.0",
                  "summary": result.get("summary") or f"{sum(1 for t in targets if t.get('status') == 'ok')} of {len(targets)} targets read"}
        stored, outcome = None, None
        with Session(self.engine) as session:
            try:
                job = J.finish_job(session, None, self.job["id"], self.job["lease_id"], status, result, error, utcnow(),
                                   team_id=team_id, known_secrets=self.secrets)
                stored, outcome = job.asset_count, getattr(job, "outcome", None)
                if self.lab_mode:
                    from backend.utilities.cbom_sources.common import audit

                    audit(session, team_id=team_id, actor_type="system", actor_id=None, action="job.lab_same_account",
                          object_type="job", object_id=self.job["id"])
                session.commit()
            except HTTPException as exc:
                session.rollback()
                outcome = "refused"
                log("cloud job result refused", team=team_id, job=self.job["id"], reason=str(exc.detail)[:120])
        if self.kind == "slice" and outcome != "refused":
            self._finalize_parent()
        log("cloud job done", team=team_id, job=self.job["id"], status=status, emitted=self.emitted, stored=stored)
        self._log_finish(started, outcome or "failed", status, emitted=self.emitted, targets=len(targets))

    def _collect(self, kind: str, team_id: int) -> tuple[str, str | None, dict[str, Any]]:
        status, error, result = "success", None, {}
        try:
            if self.kind == "slice":
                result = self._aws_slice()
            elif kind == "aws_account":
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
        except _Refused as exc:
            status, error = "failure", str(exc)
        except Exception as exc:
            ref = new_ref()
            log("cloud job FAILED", ref=ref, team=team_id, job=self.job["id"], error=type(exc).__name__)
            status, error = "failure", f"Collection failed (ref {ref})"
        return status, error, result

    def _backoff_and_release(self, started: float) -> None:
        """A slice AWS throttled past every retry: wait (exponential in its attempt, jitter, cut short by SIGTERM),
        then give it back to the queue; the next claim is a new attempt, so MAX_ATTEMPTS bounds the tries."""
        delay = min(60.0, 5.0 * (2 ** (int(self.job["attempt"]) - 1))) * (0.5 + random.random() / 2)
        _stop.wait(delay)
        with Session(self.engine) as session:
            J.release_cloud_job(session, self.job["id"], self.job["lease_id"], utcnow(), f"throttled: {self.requeue}")
            session.commit()
        self._log_finish(started, "throttled_requeued", "pending", backoff_ms=int(delay * 1000))

    def _finalize_parent(self) -> None:
        """After this slice's result is committed: end the parent if no slice of it is open any more (the last
        committer always sees every other slice ended; the parent's guarded UPDATE makes a tie harmless)."""
        from backend.utilities.cbom_sources import slices as S

        try:
            with Session(self.engine) as session:
                parent = S.maybe_finalize(session, self.job.get("parent_job_id"), utcnow())
                ended = (parent.id, parent.run_id, parent.status, parent.outcome, parent.asset_count) if parent else None
                session.commit()
            if ended is not None:
                log("cloud parent finished", team=self.job["team_id"], job=ended[0], run=ended[1], status=ended[2],
                    outcome=ended[3], assets=ended[4])
        except Exception as exc:  # the reaper finalises it on its next pass
            log("cloud parent finish FAILED", job=self.job.get("parent_job_id"), error=type(exc).__name__)

    def _log_finish(self, started: float, outcome: str, status: str, **extra: Any) -> None:
        log("cloud finish", team=self.job["team_id"], run=self.job.get("run_id"), job=self.job["id"],
            parent=self.job.get("parent_job_id"), kind=self.source["kind"], job_kind=self.kind,
            account=self.slice.get("account_id"), region=self.slice.get("region"), attempt=self.job["attempt"],
            ms=int((time.monotonic() - started) * 1000), status=status, outcome=outcome, **extra)

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

    def _external_id(self) -> str:
        with Session(self.engine) as session:
            return get_or_create_settings(session, self.job["team_id"]).aws_external_id

    def _aws(self) -> dict[str, Any]:
        from backend.utilities.cbom_sources.aws_collect import AwsCollectError, collect_aws

        if self.source.get("last_test_status") != "passed":
            raise _Refused("Validate the AWS role first; only a role that passed validation is scanned")
        external_id = self._external_id()
        self.lab_mode = _aws_lab_mode(self.source.get("config") or {})
        from backend.utilities.cbom_sources import slices as S

        if not S.enabled():
            try:
                return collect_aws(self.job["team_id"], self.source["config"], external_id, self.emit, self.should_stop)
            except AwsCollectError as exc:
                raise _Refused(str(exc)) from exc
        from backend.utilities.cbom_sources.aws_org import plan_slices

        try:
            plan = plan_slices(self.job["team_id"], self.source["config"], external_id, self.emit, self.should_stop)
        except AwsCollectError as exc:
            raise _Refused(str(exc)) from exc
        self.flush()  # the organisation's coverage rows belong to this attempt, before the slices take over
        if self.stop_reason:
            return {"targets": plan.get("targets") or []}
        with Session(self.engine) as session:
            try:
                self.fanned_out = S.fan_out(session, self.job["id"], self.job["lease_id"], plan, utcnow())
                session.commit()
            except HTTPException as exc:
                session.rollback()
                self.stop_reason = str(exc.detail)
                return {"targets": plan.get("targets") or []}
        return {}

    def _aws_slice(self) -> dict[str, Any]:
        """One account x region of an AWS source the parent job planned."""
        from backend.utilities.cbom_sources.aws_collect import AwsCollectError
        from backend.utilities.cbom_sources.aws_org import collect_slice

        if self.source.get("last_test_status") != "passed":
            raise _Refused("Validate the AWS role first; only a role that passed validation is scanned")
        role_arn = str(self.slice.get("role_arn") or "")
        source_role = str((self.source.get("config") or {}).get("role_arn") or "")
        # only the source's own role, or a member account's role of the same name in the same partition
        if not role_arn or role_arn.split(":role/")[-1] != source_role.split(":role/")[-1] \
                or role_arn.split(":")[1:2] != source_role.split(":")[1:2]:
            raise _Refused("This slice names a role the source does not use")
        from backend.utilities.cbom_sources.aws_collect import AwsThrottled

        last = int(self.job["attempt"]) >= J.MAX_ATTEMPTS  # the last try reports the throttle as an error row
        try:
            return collect_slice(self.job["team_id"], self.source["config"], self._external_id(), role_arn,
                                 str(self.slice.get("region")), self.emit, self.should_stop, raise_throttled=not last)
        except AwsThrottled as exc:
            self.requeue = str(exc)
            return {}
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


def log_queue(engine, worker: str) -> None:
    with Session(engine) as session:
        stats = J.cloud_queue_stats(session, utcnow())
    log("cloud queue", worker=worker, **stats)


def worker_loop(engine, worker: str) -> None:
    """One claim loop (a thread of the pool).  Stops claiming at SIGTERM; the job in hand finishes or is released."""
    while not _stop.is_set():
        try:
            busy = run_once(engine, worker)
        except Exception as exc:  # database hiccup: wait and carry on
            log("cloud worker loop FAILED", ref=new_ref(), worker=worker, error=type(exc).__name__)
            busy = False
        if not busy:
            _stop.wait(IDLE_SLEEP_S * (0.5 + random.random()))  # jitter: N idle replicas do not poll in step


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--once", action="store_true", help="run at most one job and exit")
    parser.add_argument("--workers", type=int, default=None,
                        help="claim loops in this process (default CBOM_CLOUD_WORKERS, 1)")
    args = parser.parse_args()
    signal.signal(signal.SIGTERM, _on_term)
    signal.signal(signal.SIGINT, _on_term)
    engine = get_db()
    host = f"{socket.gethostname()}:{os.getpid()}"
    if args.once:
        log("cloud worker started", worker=host, workers=1)
        reap_all(engine)
        run_once(engine, host)
        return
    workers = max(1, min(args.workers or _env_int("CBOM_CLOUD_WORKERS", 1, 1, 64), 64))
    log("cloud worker started", worker=host, workers=workers, lease_s=int(J.cloud_lease().total_seconds()),
        team_cap=J.team_max_concurrency())
    # schedules and drift run on their own thread: a claim loop can be busy with one collection for hours
    from backend.workers.cbom_scheduler import start_thread

    scheduler_stop = start_thread(engine)
    # integrations forward events on their own thread too: a slow destination must not delay a schedule
    from backend.workers.integration_dispatcher import start_thread as start_dispatcher

    dispatcher_stop = start_dispatcher(engine)
    # F1.2 fleet inventory: AWS inventory sources sync on their own thread (only while CBOM_FLEET_INVENTORY is on)
    from backend.workers.cbom_inventory_sync import start_thread as start_inventory_sync

    inventory_stop = start_inventory_sync(engine)
    threads = [threading.Thread(target=worker_loop, args=(engine, f"{host}:{i}"), name=f"cloud-worker-{i}", daemon=True)
               for i in range(workers)]
    for thread in threads:
        thread.start()
    queue_every = _env_int("CBOM_CLOUD_QUEUE_LOG_S", 60, 0, 86_400)
    last_reap = last_queue = 0.0
    while not _stop.is_set():
        if time.monotonic() - last_reap >= REAP_EVERY_S:
            reap_all(engine)
            last_reap = time.monotonic()
        if queue_every and time.monotonic() - last_queue >= queue_every:
            try:
                log_queue(engine, host)
            except Exception as exc:
                log("cloud queue log FAILED", error=type(exc).__name__)
            last_queue = time.monotonic()
        _stop.wait(1.0)
    for thread in threads:
        thread.join()
    if scheduler_stop is not None:
        scheduler_stop.set()
    if dispatcher_stop is not None:
        dispatcher_stop.set()
    if inventory_stop is not None:
        inventory_stop.set()
    log("cloud worker stopped", worker=host)


if __name__ == "__main__":
    main()
