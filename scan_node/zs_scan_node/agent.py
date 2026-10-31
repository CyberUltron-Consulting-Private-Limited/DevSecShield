"""The scan node process: enroll once, heartbeat, claim jobs, run them, post assets and results.

Environment:
  ZS_API_URL              ZeroShield API base URL (required)
  ZS_REGISTRATION_TOKEN   single-use token from "Add scan node" (needed only until the node has enrolled)
  ZS_STATE_DIR            persistent state (default /var/lib/zs-node; mount a volume here)
  ZS_MAX_JOBS             jobs run in parallel (default 2)
  ZS_VAULT_PATH_PREFIX    allow vault credentials under this path prefix only (vault use is off without it)
  VAULT_ADDR / VAULT_TOKEN  HashiCorp Vault for vault credentials; AWS Secrets Manager uses the node's IAM role
  HTTPS_PROXY / NO_PROXY  outbound proxy to ZeroShield (customer targets are always reached directly)
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import os
import signal
import socket
import threading
import time
import traceback

from zs_scan_node import VERSION
from zs_scan_node.api import Api, ApiError, Unauthorized
from zs_scan_node.collectors import CAPABILITIES, run_job
from zs_scan_node.jobctx import JobContext, LeaseLost
from zs_scan_node.log import global_scrubber, log
from zs_scan_node.netutil import NeverScan, has_ipv6, local_ips
from zs_scan_node.scrub import Scrubber
from zs_scan_node.state import NodeState
from zs_scan_node.tlsprobe import have_openssl

POLL_SECONDS = 5
CLAIM_GRACE = 0  # the heartbeat reports running jobs immediately after claim


class Running:
    def __init__(self, job_id: int, lease_id: str, ctx: JobContext, network: bool, scope_never: list[str]) -> None:
        self.job_id, self.lease_id, self.ctx, self.network = job_id, lease_id, ctx, network
        self.scope_never = scope_never
        self.applied_team: list[str] | None = None


class Agent:
    def __init__(self) -> None:
        self.api_url = os.environ.get("ZS_API_URL", "").strip()
        if not self.api_url.startswith(("https://", "http://")):
            raise SystemExit("ZS_API_URL must be set to the ZeroShield API URL (https://...)")
        self.state = NodeState.load(os.environ.get("ZS_STATE_DIR", "/var/lib/zs-node"))
        self.max_jobs = max(1, min(int(os.environ.get("ZS_MAX_JOBS", "2") or 2), 8))
        self.vault_prefix = os.environ.get("ZS_VAULT_PATH_PREFIX") or None
        self.api = Api(self.api_url, self.state.node_token)
        self.running: dict[int, Running] = {}
        self.lock = threading.Lock()
        self.team_never: list[str] | None = None  # latest team never-scan list from the heartbeat
        self.stop_network = threading.Event()
        self.shutdown = threading.Event()
        self.heartbeat_interval = 30
        self.last_error: str | None = None
        self.server_skew_s = 0.0
        reg = os.environ.get("ZS_REGISTRATION_TOKEN", "")
        g = global_scrubber()
        for secret in (reg, self.state.node_token, os.environ.get("VAULT_TOKEN")):
            g.add(secret)

    # ------------------------------------------------------------------ enrollment
    def ensure_enrolled(self) -> None:
        while not self.state.node_token and not self.shutdown.is_set():
            reg = os.environ.get("ZS_REGISTRATION_TOKEN", "").strip()
            if not reg:
                log("not enrolled and ZS_REGISTRATION_TOKEN is not set; waiting", level="error")
                self.shutdown.wait(60)
                continue
            digest = hashlib.sha256(reg.encode()).hexdigest()
            if self.state.enrolled_with == digest:
                log("the registration token in ZS_REGISTRATION_TOKEN was already used; create a new one in "
                    "ZeroShield (Scan nodes > Reset) and restart with it", level="error")
                self.shutdown.wait(300)
                continue
            body = {"registration_token": reg, "hostname": socket.gethostname()[:255], "version": VERSION,
                    "source_ips": local_ips(), "ssh_public_key": self.state.ssh_public_key(),
                    "capabilities": self.capabilities(), "clock": _now_iso()}
            try:
                data = self.api.enroll(body)
            except Unauthorized:
                log("registration token is invalid or expired; create a new one in ZeroShield", level="error")
                self.state.enrolled_with = digest
                self.state.save()
                self.shutdown.wait(300)
                continue
            except ApiError as exc:
                log("enrollment failed, retrying", error=str(exc), level="error")
                self.shutdown.wait(30)
                continue
            self.state.node_token = data["node_token"]
            self.state.node_id = data.get("node_id")
            self.state.team_id = data.get("team_id")
            self.state.enrolled_with = digest
            self.state.save()
            global_scrubber().add(self.state.node_token)
            self.api.token = self.state.node_token
            self.heartbeat_interval = int(data.get("heartbeat_interval_s") or 30)
            log("enrolled", node=self.state.node_id, team=self.state.team_id)

    def capabilities(self) -> dict:
        return {"collectors": CAPABILITIES, "openssl": have_openssl(), "ipv6": has_ipv6(), "max_jobs": self.max_jobs,
                "vault": bool(self.vault_prefix)}

    # ------------------------------------------------------------------ heartbeat
    def heartbeat_once(self) -> None:
        with self.lock:
            running = [{"job_id": r.job_id, "lease_id": r.lease_id} for r in self.running.values()]
        body = {"hostname": socket.gethostname()[:255], "version": VERSION, "source_ips": local_ips(),
                "capabilities": self.capabilities(), "clock": _now_iso(), "running": running}
        if self.last_error:
            body["last_error"] = global_scrubber().text(self.last_error)[:1900]
        data = self.api.heartbeat(body)
        self.last_error = None
        self.heartbeat_interval = int(data.get("heartbeat_interval_s") or self.heartbeat_interval)
        if isinstance(data.get("never_scan"), list):
            self.team_never = [str(x) for x in data["never_scan"]][:10000]
        if data.get("stop_all_network"):
            self.stop_network.set()
        else:
            self.stop_network.clear()
        cancel = set(int(i) for i in data.get("cancel_job_ids") or [] if str(i).isdigit())
        with self.lock:
            for job_id in cancel:
                r = self.running.get(job_id)
                if r and not r.ctx.cancel.is_set():
                    r.ctx.cancel_reason = "Stopped by ZeroShield (job cancelled, source changed or network stop)"
                    r.ctx.cancel.set()
                    log("cancel requested", job=job_id)

    def heartbeat_loop(self) -> None:
        while not self.shutdown.is_set():
            try:
                self.heartbeat_once()
            except Unauthorized:
                self.on_unauthorized()
            except ApiError as exc:
                log("heartbeat failed", error=str(exc), level="warn")
            except Exception as exc:  # keep the heartbeat alive whatever happens
                log("heartbeat error", error=exc.__class__.__name__, level="error")
            self.shutdown.wait(max(5, min(self.heartbeat_interval, 60)))

    def on_unauthorized(self) -> None:
        log("ZeroShield no longer accepts this node's token (node reset or deleted); stopping jobs and waiting for "
            "a new ZS_REGISTRATION_TOKEN", level="error")
        with self.lock:
            for r in self.running.values():
                r.ctx.cancel_reason = "node token revoked"
                r.ctx.cancel.set()
        self.state.clear_token()
        self.api.token = None

    # ------------------------------------------------------------------ jobs
    def claim_loop(self) -> None:
        while not self.shutdown.is_set():
            if not self.state.node_token:
                self.ensure_enrolled()
                continue
            with self.lock:
                busy = len(self.running) >= self.max_jobs
            if busy:
                self.shutdown.wait(2)
                continue
            try:
                payload = self.api.claim()
            except Unauthorized:
                self.on_unauthorized()
                continue
            except ApiError as exc:
                log("claim failed", error=str(exc), level="warn")
                self.shutdown.wait(POLL_SECONDS * 3)
                continue
            if not payload:
                self.shutdown.wait(POLL_SECONDS)
                continue
            job = payload.get("job") or {}
            job_id = int(job.get("id") or 0)
            with self.lock:
                if job_id in self.running:
                    log("server offered a job that is already running here; ignoring", job=job_id, level="warn")
                    continue
            self.start_job(payload)

    def start_job(self, payload: dict) -> None:
        job, scope, source = payload.get("job") or {}, payload.get("scope") or {}, payload.get("source")
        job_id, attempt = int(job["id"]), int(job.get("attempt") or 1)
        secrets = [v for v in ((source or {}).get("secrets") or {}).values() if isinstance(v, str)]
        scrubber = Scrubber(secrets)
        for s in (self.state.node_token, os.environ.get("VAULT_TOKEN")):
            scrubber.add(s)
        scope_never = [str(x) for x in scope.get("never_scan") or []]
        never = NeverScan(scope_never + (self.team_never or []))
        deadline, reason = _deadline(scope, int(job.get("lease_seconds") or 900))
        lease_id = str(job.get("lease_id") or "")
        is_network = job.get("kind") == "discovery" or (source or {}).get("kind") == "network_range"

        def poster(assets: list[dict], batch_id: str) -> dict:
            return self.api.assets(job_id, attempt, lease_id, batch_id, assets)

        ctx = JobContext(job_id=job_id, attempt=attempt, run_id=job.get("run_id"), kind=str(job.get("kind")),
                         source_kind=(source or {}).get("kind"), scrubber=scrubber, never_scan=never,
                         deadline=deadline, deadline_reason=reason, poster=poster, state_dir=self.state.directory,
                         node_private_key_path=self.state.key_path, vault_prefix=self.vault_prefix)
        if self.stop_network.is_set() and is_network:
            ctx.stop_network.set()
        running = Running(job_id, lease_id, ctx, is_network, scope_never)
        with self.lock:
            self.running[job_id] = running
        threading.Thread(target=self.run_job, args=(running, job, scope, source), name=f"job-{job_id}",
                         daemon=True).start()

    def run_job(self, running: Running, job: dict, scope: dict, source: dict | None) -> None:
        ctx = running.ctx
        ctx.log("job started", kind=job.get("kind"), source_kind=ctx.source_kind)
        watcher = threading.Thread(target=self._watch, args=(running,), daemon=True)
        watcher.start()
        status, error, summary = "failure", None, None
        try:
            status, error, summary = run_job(ctx, job, scope, source)
            ctx.flush()
        except LeaseLost as exc:
            ctx.log("lease lost; stopping without a result", detail=str(exc), level="warn")
            self._done(running)
            return
        except Exception as exc:
            status, error = "failure", f"scan node error: {exc.__class__.__name__}"
            ctx.log("job crashed", error=exc.__class__.__name__, trace=traceback.format_exc(limit=3).replace("\n", " | "),
                    level="error")
            try:
                ctx.flush()
            except LeaseLost:
                self._done(running)
                return
            except Exception:
                pass
        if self.shutdown.is_set() and ctx.cancel_reason == SHUTDOWN_REASON:
            # A restart or upgrade is not the customer's cancel: post nothing, so ZeroShield releases the job
            # (it is no longer in this node's heartbeat) and the next attempt runs it from the start.
            ctx.log("node shutting down; leaving the job for ZeroShield to retry", level="warn")
            self._done(running)
            return
        result = ctx.result(summary)
        result["node_version"] = VERSION
        body = {"lease_id": running.lease_id, "status": status, "result": result,
                "error": ctx.scrubber.text(error)[:3900] if error else None}
        try:
            self.api.result(running.job_id, ctx.attempt, ctx.scrubber.obj(body))
            ctx.log("job finished", status=status, assets=ctx.accepted, ok=result["counts"]["ok"],
                    failed=result["counts"]["failed"], skipped=result["counts"]["skipped"],
                    duration_s=result["duration_s"])
        except LeaseLost:
            ctx.log("lease lost before the result was accepted", level="warn")
        except (ApiError, Unauthorized) as exc:
            self.last_error = f"job {running.job_id}: result not delivered ({exc})"
            ctx.log("result not delivered", error=str(exc), level="error")
        finally:
            self._done(running)

    def _watch(self, running: Running) -> None:
        """Propagate the node-wide never-scan list and stop-all flag into a running job."""
        while running.job_id in self.running and not self.shutdown.is_set():
            if running.network and self.stop_network.is_set():
                running.ctx.stop_network.set()
            team = self.team_never
            if team is not None and team != running.applied_team:
                running.ctx.never_scan.update(running.scope_never + team)  # union: never narrower than at claim
                running.applied_team = team
            self.shutdown.wait(2)

    def _done(self, running: Running) -> None:
        with self.lock:
            self.running.pop(running.job_id, None)

    # ------------------------------------------------------------------ main
    def run(self) -> None:
        def stop(_sig, _frm):
            log("shutting down")
            self.shutdown.set()
            with self.lock:
                for r in self.running.values():
                    r.ctx.cancel_reason = SHUTDOWN_REASON
                    r.ctx.cancel.set()

        signal.signal(signal.SIGTERM, stop)
        signal.signal(signal.SIGINT, stop)
        log("scan node starting", version=VERSION, api=self.api_url, state=self.state.directory,
            openssl=have_openssl())
        self.ensure_enrolled()
        threading.Thread(target=self.heartbeat_loop, name="heartbeat", daemon=True).start()
        self.claim_loop()
        # give running jobs a moment to stop (they post nothing; ZeroShield retries them)
        end = time.monotonic() + 20
        while self.running and time.monotonic() < end:
            time.sleep(0.5)


SHUTDOWN_REASON = "scan node shutting down"


def _now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _deadline(scope: dict, lease_seconds: int) -> tuple[float, str]:
    """monotonic deadline = min(max_runtime_s, window_ends_at); the reason names which one applies."""
    now_wall = time.time()
    now_mono = time.monotonic()
    max_runtime = int(scope.get("max_runtime_s") or 6 * 3600)
    deadline = now_mono + max_runtime
    reason = "skipped_deadline"
    end = scope.get("window_ends_at")
    if end:
        try:
            moment = _dt.datetime.fromisoformat(str(end).replace("Z", "+00:00"))
            if moment.tzinfo is None:
                moment = moment.replace(tzinfo=_dt.timezone.utc)
            win = now_mono + (moment.timestamp() - now_wall)
            if win < deadline:
                deadline, reason = win, "skipped_window"
        except ValueError:
            pass
    return deadline, reason


def main() -> None:
    Agent().run()
