"""The scan node process: enroll once, heartbeat, claim jobs, run them, post assets and results.

Environment:
  ZS_API_URL              ZeroShield API base URL (required)
  ZS_REGISTRATION_TOKEN   single-use token from "Add scan node" (needed only until the node has enrolled), or an
                          agent pool token (zsp_, agent mode): the pod enrolls again with it after a reset or delete
  ZS_STATE_DIR            persistent state (default /var/lib/zs-node; mount a volume here)
  ZS_MAX_JOBS             jobs run in parallel (default 2)
  ZS_VAULT_PATH_PREFIX    allow vault credentials under this path prefix only (vault use is off without it)
  VAULT_ADDR / VAULT_TOKEN  HashiCorp Vault for vault credentials; AWS Secrets Manager uses the node's IAM role
  HTTPS_PROXY / NO_PROXY  outbound proxy to ZeroShield (customer targets are always reached directly)
  ZS_CLIENT_CERT / ZS_CLIENT_KEY  PEM client certificate and key for mTLS to the ZeroShield proxy (optional)
  ZS_CA_FILE              CA bundle that replaces the default trust for the ZeroShield API (optional)
  ZS_MODE                 ``agentless`` (default: reaches other systems with stored credentials) or ``agent``: collect
                          only this node's own host from read-only mounts; never runs another job, never takes a
                          credential, vault use is off.  ZS_REGISTRATION_TOKEN may then be an agent pool token (zsp_).
  ZS_NODE_NAME            agent mode: the name to enroll under (the Helm DaemonSet passes the Kubernetes node name)
  ZS_HOST_ROOT / ZS_HOST_PROC  agent mode: where the host's / is mounted read-only (default /host), and its /proc

Every request is signed with a per-enrollment Ed25519 key (api.py).  The node clears its token only when the
ZeroShield deployment it enrolled with (X-ZS-Deployment) says explicitly that the token is revoked (401 with
X-ZS-Refused: node_token_revoked); any other 401, or a 403 from another server, is a wrong server or proxy: the token
is kept, the node backs off, logs "server at <ZS_API_URL> did not accept this node ...; not the ZeroShield this node
enrolled with?" and reports it in its next successful heartbeat (the node's last error in ZeroShield).
"""
from __future__ import annotations

import base64
import datetime as _dt
import hashlib
import os
import signal
import socket
import threading
import time
import traceback

from zs_scan_node import VERSION
from zs_scan_node.api import Api, ApiError, Unauthorized, WrongServer
from zs_scan_node.collectors import AGENT_CAPABILITIES, CAPABILITIES, run_job
from zs_scan_node.jobctx import JobContext, LeaseLost
from zs_scan_node.log import global_scrubber, log
from zs_scan_node.netutil import NeverScan, has_ipv6, local_ips
from zs_scan_node.scrub import Scrubber
from zs_scan_node.state import NodeState
from zs_scan_node.tlsprobe import have_openssl

POLL_SECONDS = 5
CLAIM_GRACE = 0  # the heartbeat reports running jobs immediately after claim
POOL_PREFIX = "zsp_"  # agent pool tokens: one token for every pod of a DaemonSet, usable again after a reset
ALIVE_FILE = "alive"  # touched by every heartbeat-loop pass; the Docker HEALTHCHECK checks its age
# A job whose collector has not returned this long after its deadline (a target that stopped answering) is ended
# so it cannot hold a job slot forever.  Generous: a target started just before the deadline may run its full
# command list (each command has its own timeout).  After a cancel the job only has to stop, so less is allowed.
STUCK_GRACE_S = 900
STUCK_CANCEL_GRACE_S = 120


class Running:
    def __init__(self, job_id: int, lease_id: str, ctx: JobContext, network: bool, scope_never: list[str]) -> None:
        self.job_id, self.lease_id, self.ctx, self.network = job_id, lease_id, ctx, network
        self.scope_never = scope_never
        self.applied_team: list[str] | None = None
        self.cancel_seen: float | None = None
        self._finish_lock = threading.Lock()
        self._finished = False

    def take_finish(self) -> bool:
        """True exactly once: whoever ends the job (its own thread or the stuck-job watchdog) posts the result."""
        with self._finish_lock:
            if self._finished:
                return False
            self._finished = True
            return True


class Agent:
    def __init__(self) -> None:
        self.api_url = os.environ.get("ZS_API_URL", "").strip()
        insecure_ok = os.environ.get("ZS_ALLOW_INSECURE_HTTP") == "1"  # local test labs only
        if not (self.api_url.startswith("https://") or (insecure_ok and self.api_url.startswith("http://"))):
            # claim answers carry decrypted credentials: never over plain HTTP in a real deployment
            raise SystemExit("ZS_API_URL must be the ZeroShield API URL over https://")
        if self.api_url.startswith("http://"):
            log("WARNING ZS_ALLOW_INSECURE_HTTP=1: credentials travel unencrypted; use only in a local test lab",
                level="warn")
        self.state = NodeState.load(os.environ.get("ZS_STATE_DIR", "/var/lib/zs-node"))
        self.max_jobs = max(1, min(int(os.environ.get("ZS_MAX_JOBS", "2") or 2), 8))
        mode = (os.environ.get("ZS_MODE") or "agentless").strip().lower()
        if mode not in ("agent", "agentless"):
            raise SystemExit("ZS_MODE must be 'agent' (collect only this host) or 'agentless' (the default)")
        self.agent_mode = mode == "agent"
        self.vault_prefix = os.environ.get("ZS_VAULT_PATH_PREFIX") or None
        if self.agent_mode and self.vault_prefix:
            log("agent mode never uses credentials: ZS_VAULT_PATH_PREFIX is ignored", level="warn")
            self.vault_prefix = None
        self.running: dict[int, Running] = {}
        self.lock = threading.Lock()
        self.shutdown = threading.Event()
        self.api = Api(self.api_url, self.state.node_token, signing_key=self.state.signing_key(),
                       deployment_id=self.state.deployment_id, on_deployment=self._adopt_deployment,
                       stop=self.shutdown)
        self.team_never: list[str] | None = None  # latest team never-scan list from the heartbeat
        self.stop_network = threading.Event()
        # When the requests behind the cached stop flag and never-scan list were sent (monotonic).  A claim is
        # answered from the server's current settings, so heartbeat answers to requests sent before it are older.
        # Kept apart: only a network claim says anything about the stop flag.
        self.stop_sent = 0.0
        self.never_sent = 0.0
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
            pool = reg.startswith(POOL_PREFIX)
            # A single-use token is spent once this node enrolled with it.  An agent pool token (zsp_) enrolls every
            # pod and enrolls it again after its node was reset or deleted (a 401 cleared the node token), until
            # ZeroShield refuses it (revoked, expired, or every enrollment used).
            if self.state.refused_with == digest or (not pool and self.state.enrolled_with == digest):
                if pool:
                    log("ZeroShield refused the agent pool token in ZS_REGISTRATION_TOKEN (revoked, expired or every "
                        "enrollment used); create a new agent pool token (CBOM Sources > Scan nodes > Host agents on "
                        "Kubernetes) and upgrade the Helm release with it (--set agent.poolToken=...)", level="error")
                else:
                    log("the registration token in ZS_REGISTRATION_TOKEN was already used; create a new one in "
                        "ZeroShield (Scan nodes > Reset) and restart with it", level="error")
                self.shutdown.wait(300)
                continue
            # A new signing key for this enrollment, on disk before its public half is sent: if the answer is lost,
            # the key ZeroShield stored is still the one this node signs with.
            key = self.state.new_signing_key()
            self.api.signing_key = key
            body = {"registration_token": reg, "hostname": socket.gethostname()[:255], "version": VERSION,
                    "source_ips": local_ips(), "ssh_public_key": self.state.ssh_public_key(),
                    "capabilities": self.capabilities(), "clock": _now_iso(),
                    "signing_public_key": base64.b64encode(key.public_key().public_bytes_raw()).decode()}
            if self.agent_mode:
                body["mode"] = "agent"
                body["node_name"] = (os.environ.get("ZS_NODE_NAME") or socket.gethostname())[:253]
                if pool and self.state.node_id:  # enrolling again: ZeroShield gives this pod its reset node back
                    body["node_id"] = self.state.node_id
            try:
                data = self.api.enroll(body)
            except Unauthorized as exc:
                if self.state.deployment_id and exc.deployment == self.state.deployment_id:
                    # our own ZeroShield refused it: the token is spent, expired or revoked, do not try it again
                    log("registration token is invalid or expired; create a new one in ZeroShield", level="error")
                    self.state.refused_with = digest
                    self.state.save()
                else:
                    # a fresh node cannot tell which ZeroShield answered: keep the token usable and retry slowly
                    log("registration token refused; check that ZS_API_URL is your ZeroShield and the token is "
                        "current (retrying in 5 minutes)", deployment=exc.deployment, level="error")
                self.shutdown.wait(300)
                continue
            except WrongServer as exc:
                log("enrollment refused by a wrong server or proxy; the registration token was kept", error=str(exc),
                    level="error")
                self.shutdown.wait(60)
                continue
            except ApiError as exc:
                log("enrollment failed, retrying", error=str(exc), level="error")
                self.shutdown.wait(30)
                continue
            self.state.node_token = data["node_token"]
            self.state.node_id = data.get("node_id")
            self.state.team_id = data.get("team_id")
            self.state.enrolled_with = digest
            if data.get("deployment_id"):
                self.state.deployment_id = str(data["deployment_id"])
                self.api.deployment_id = self.state.deployment_id
            self.state.save()
            global_scrubber().add(self.state.node_token)
            self.api.token = self.state.node_token
            self.heartbeat_interval = int(data.get("heartbeat_interval_s") or 30)
            log("enrolled", node=self.state.node_id, team=self.state.team_id, deployment=self.state.deployment_id,
                signing=data.get("signing") or "legacy")

    def _adopt_deployment(self, deployment: str) -> None:
        """Remember the deployment id a successful answer carried (nodes enrolled before deployment ids adopt it
        from their first successful request)."""
        with self.lock:
            if self.state.deployment_id != deployment:
                self.state.deployment_id = deployment
                self.state.save()

    def capabilities(self) -> dict:
        return {"collectors": AGENT_CAPABILITIES if self.agent_mode else CAPABILITIES, "openssl": have_openssl(),
                "ipv6": has_ipv6(), "max_jobs": self.max_jobs, "vault": bool(self.vault_prefix),
                "mode": "agent" if self.agent_mode else "agentless"}

    # ------------------------------------------------------------------ heartbeat
    def heartbeat_once(self) -> None:
        with self.lock:
            running = [{"job_id": r.job_id, "lease_id": r.lease_id} for r in self.running.values()]
        body = {"hostname": socket.gethostname()[:255], "version": VERSION, "source_ips": local_ips(),
                "capabilities": self.capabilities(), "clock": _now_iso(), "running": running}
        if self.last_error:
            body["last_error"] = global_scrubber().text(self.last_error)[:1900]
        sent = time.monotonic()
        data = self.api.heartbeat(body)
        self.last_error = None
        self.heartbeat_interval = int(data.get("heartbeat_interval_s") or self.heartbeat_interval)
        self.apply_control(data, sent)
        cancel = set(int(i) for i in data.get("cancel_job_ids") or [] if str(i).isdigit())
        with self.lock:
            for job_id in cancel:
                r = self.running.get(job_id)
                if r and not r.ctx.cancel.is_set():
                    r.ctx.cancel_reason = "Stopped by ZeroShield (job cancelled, source changed or network stop)"
                    r.ctx.cancel.set()
                    log("cancel requested", job=job_id)

    def apply_control(self, data: dict, sent: float) -> None:
        """Cache the team's stop-all flag and never-scan list from a heartbeat answer, unless a claim sent after
        that heartbeat already gave us newer facts (an answer that arrives late must not undo a resume)."""
        with self.lock:
            if sent >= self.never_sent and isinstance(data.get("never_scan"), list):
                self.never_sent = sent
                self.team_never = [str(x) for x in data["never_scan"]][:10000]
            if sent >= self.stop_sent:
                self.stop_sent = sent
                if data.get("stop_all_network"):
                    self.stop_network.set()
                else:
                    self.stop_network.clear()

    def claimed(self, sent: float, is_network: bool) -> None:
        """A claim is answered from the server's current settings: its scope carries the current never-scan list,
        and the server only hands out network work while network scanning is allowed.  So any cached state from
        a heartbeat sent before this claim is stale; drop it until the next heartbeat."""
        with self.lock:
            if sent >= self.never_sent:
                self.never_sent = sent
                self.team_never = None
            if is_network and sent >= self.stop_sent:
                self.stop_sent = sent
                self.stop_network.clear()

    def heartbeat_loop(self) -> None:
        while not self.shutdown.is_set():
            try:
                self.heartbeat_once()
            except Unauthorized:
                self.on_unauthorized()
            except WrongServer as exc:
                self.last_error = str(exc)  # reported in the next successful heartbeat
                log("heartbeat refused by a wrong server or proxy; token kept", error=str(exc), level="error")
            except ApiError as exc:
                log("heartbeat failed", error=str(exc), level="warn")
            except Exception as exc:  # keep the heartbeat alive whatever happens
                log("heartbeat error", error=exc.__class__.__name__, level="error")
            self.mark_alive()
            self.shutdown.wait(max(5, min(self.heartbeat_interval, 60)))

    def mark_alive(self) -> None:
        """Touch <state dir>/alive once per heartbeat-loop pass (at most every 60 s). The image HEALTHCHECK reads its
        age: a node whose loop has stopped turning goes unhealthy even though its process still exists."""
        path = os.path.join(self.state.directory, ALIVE_FILE)
        try:
            with open(path, "a", encoding="utf-8"):
                pass
            os.utime(path, None)
        except OSError as exc:
            log("cannot mark the node alive", error=exc.__class__.__name__, level="warn")

    def on_unauthorized(self) -> None:
        if os.environ.get("ZS_REGISTRATION_TOKEN", "").strip().startswith(POOL_PREFIX):
            log("ZeroShield no longer accepts this node's token (node reset or deleted); stopping jobs and enrolling "
                "again with the agent pool token", level="error")
        else:
            log("ZeroShield no longer accepts this node's token (node reset or deleted); stopping jobs and waiting "
                "for a new ZS_REGISTRATION_TOKEN", level="error")
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
            sent = time.monotonic()
            try:
                # the mode goes with every claim: a node restarted in agent mode is never handed a secret, even
                # before its first heartbeat reaches ZeroShield
                payload = self.api.claim({"mode": "agent" if self.agent_mode else "agentless"})
            except Unauthorized:
                self.on_unauthorized()
                continue
            except WrongServer as exc:
                self.last_error = str(exc)
                log("claim refused by a wrong server or proxy; token kept", error=str(exc), level="error")
                self.shutdown.wait(60)
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
            self.start_job(payload, sent)

    def start_job(self, payload: dict, claim_sent: float | None = None) -> None:
        job, scope, source = payload.get("job") or {}, payload.get("scope") or {}, payload.get("source")
        job_id, attempt = int(job["id"]), int(job.get("attempt") or 1)
        is_network = job.get("kind") == "discovery" or (source or {}).get("kind") == "network_range"
        if claim_sent is not None:
            self.claimed(claim_sent, is_network)
        secrets = [v for v in ((source or {}).get("secrets") or {}).values() if isinstance(v, str)]
        scrubber = Scrubber(secrets)
        for s in (self.state.node_token, os.environ.get("VAULT_TOKEN")):
            scrubber.add(s)
        scope_never = [str(x) for x in scope.get("never_scan") or []]
        never = NeverScan(scope_never + (self.team_never or []))
        deadline, reason = _deadline(scope, int(job.get("lease_seconds") or 900))
        lease_id = str(job.get("lease_id") or "")

        def poster(assets: list[dict], batch_id: str, progress: dict | None = None) -> dict:
            try:
                return self.api.assets(job_id, attempt, lease_id, batch_id, assets, progress)
            except Unauthorized:  # our ZeroShield revoked the token: stop every job, post nothing more
                self.on_unauthorized()
                raise LeaseLost("ZeroShield no longer accepts this node's token") from None

        ctx = JobContext(job_id=job_id, attempt=attempt, run_id=job.get("run_id"), kind=str(job.get("kind")),
                         source_kind=(source or {}).get("kind"), scrubber=scrubber, never_scan=never,
                         deadline=deadline, deadline_reason=reason, poster=poster, state_dir=self.state.directory,
                         node_private_key_path=self.state.key_path, vault_prefix=self.vault_prefix,
                         agent_mode=self.agent_mode)
        ctx.cert_refresher = lambda: self.api.ssh_cert(job_id, attempt, lease_id)  # F1.4: SSH CA certificates
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
            if running.take_finish():
                self._done(running)
            return
        except Exception as exc:
            status, error = "failure", f"scan node error: {exc.__class__.__name__}"
            ctx.log("job crashed", error=exc.__class__.__name__, trace=traceback.format_exc(limit=3).replace("\n", " | "),
                    level="error")
            try:
                ctx.flush()
            except LeaseLost:
                if running.take_finish():
                    self._done(running)
                return
            except Exception:
                pass
        if not running.take_finish():  # the watchdog already ended this job and freed its slot
            ctx.log("collector returned after the job was ended as stuck; result discarded", level="warn")
            return
        if self.shutdown.is_set() and ctx.cancel_reason == SHUTDOWN_REASON:
            # A restart or upgrade is not the customer's cancel: post nothing, so ZeroShield releases the job
            # (it is no longer in this node's heartbeat) and the next attempt runs it from the start.
            ctx.log("node shutting down; leaving the job for ZeroShield to retry", level="warn")
            self._done(running)
            return
        self._post_result(running, status, error, summary)

    def _post_result(self, running: Running, status: str, error: str | None, summary: str | None) -> None:
        ctx = running.ctx
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
        except Unauthorized:
            ctx.log("ZeroShield no longer accepts this node's token; result not delivered", level="error")
            self.on_unauthorized()
        except ApiError as exc:
            self.last_error = f"job {running.job_id}: result not delivered ({exc})"
            ctx.log("result not delivered", error=str(exc), level="error")
        finally:
            self._done(running)

    def _watch(self, running: Running) -> None:
        """Propagate the node-wide never-scan list and stop-all flag into a running job, and end a job whose
        collector is stuck on a target that stopped answering, so it cannot hold a job slot forever."""
        ctx = running.ctx
        while running.job_id in self.running and not self.shutdown.is_set():
            if running.network and self.stop_network.is_set():
                ctx.stop_network.set()
            team = self.team_never
            if team is not None and team != running.applied_team:
                ctx.never_scan.update(running.scope_never + team)  # union: never narrower than at claim
                running.applied_team = team
            now = time.monotonic()
            if ctx.cancel.is_set() and running.cancel_seen is None:
                running.cancel_seen = now
            overdue = now > ctx.deadline + STUCK_GRACE_S
            stuck_cancel = running.cancel_seen is not None and now > running.cancel_seen + STUCK_CANCEL_GRACE_S
            if (overdue or stuck_cancel) and running.take_finish():
                ctx.log("collector did not stop in time; ending the job", level="error")
                try:
                    ctx.flush()
                except Exception:
                    pass
                if stuck_cancel:
                    self._post_result(running, "cancelled", ctx.cancel_reason or "Stopped by ZeroShield", None)
                else:
                    self._post_result(running, "failure", f"A target stopped answering: the collector had not returned "
                                      f"{STUCK_GRACE_S // 60} minutes after the job's time limit, so the job was "
                                      "ended to free the node for new work", None)
                return
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
