"""Per-job context: secrets scrubber, cancel/stop/deadline, live never-scan, asset sink and target outcomes."""
from __future__ import annotations

import datetime as _dt
import json
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable

from zs_scan_node.log import log
from zs_scan_node.netutil import NeverScan
from zs_scan_node.scrub import Scrubber, printable

# A set so collector modules can add the asset types they own with register_asset_types() at import.
ASSET_TYPES: set[str] = {
    "certificate", "private_key", "public_key", "keystore", "ssh_host_key", "ssh_server_config", "ssh_endpoint",
    "tls_endpoint", "crypto_library", "process_library", "disk_encryption", "os_crypto_policy", "database_tls",
    "database_config", "database_user_auth", "k8s_cluster", "k8s_tls_secret", "k8s_certificate", "k8s_ingress_tls",
    "k8s_mesh_policy", "kms_key", "cloud_secret", "storage_encryption", "load_balancer_tls", "cdn_tls", "api_tls",
    "cloud_ca", "iam_certificate", "identity_provider", "signing_key", "open_port", "coverage",
    "host_secret", "crypto_config",
}


def register_asset_types(*names: str) -> None:
    ASSET_TYPES.update(names)


TARGET_STATUSES = frozenset({
    "ok", "unreachable", "refused", "timeout", "no_route", "auth_failed", "mfa_required", "host_key_changed",
    "host_key_mismatch", "identity_unverified", "kex_unsupported",
    "sudoers_missing", "sudo_denied", "rbac_denied", "winrm_denied", "tls_unavailable", "not_supported", "error",
    "skipped_never_scan", "skipped_window", "skipped_stop", "skipped_deadline", "skipped_cancelled",
    "skipped_credential_refused",
})
FAILED = frozenset({"unreachable", "refused", "timeout", "no_route", "auth_failed", "mfa_required", "host_key_changed",
                    "host_key_mismatch", "identity_unverified", "kex_unsupported",
                    "sudoers_missing", "sudo_denied", "rbac_denied", "winrm_denied", "tls_unavailable", "not_supported",
                    "error"})
MAX_FACTS_BYTES = 16 * 1024
MAX_TARGET_ROWS = 1000
BATCH = 500
MAX_BATCH_BYTES = 768 * 1024  # the server refuses asset bodies over 1 MB
# A long job (a network range) posts what it has at least this often, so the job's asset count in ZeroShield grows
# while it runs (the customer's progress) instead of staying at 0 until the end.
FLUSH_INTERVAL_S = 15.0


# CB-10 lockout guard: after this many refused logins in a row with one credential, the job stops using it.
AUTH_FAILURE_LIMIT = 3
CREDENTIAL_REFUSED = "skipped_credential_refused"
# The credential was accepted (what failed came after the login): the account is not being locked.
LOGIN_ACCEPTED = frozenset({"ok", "sudoers_missing", "sudo_denied", "winrm_denied", "rbac_denied"})


class CredentialBreaker:
    """Keeps one job's credential from locking out the customer's account (CB-10).

    Directory accounts (AD, LDAP, a database's own users) count failed logins across every host that checks them, so
    a wrong password tried on 500 hosts locks the account long before the job ends.  Every login with the job's
    credential goes through ``acquire`` / ``release``:

    * After ``limit`` refused logins (``auth_failed``) in a row the breaker trips: every later ``acquire`` answers
      ``skipped_credential_refused`` and nothing else is tried.
    * Until the credential has been accepted once, at most ``limit`` minus the refusals so far are in flight, so
      parallel threads cannot fire more than ``limit`` attempts before the first answers come back.  Once it has
      been accepted, logins run at the job's full parallelism.
    * Other failures (unreachable, timeout, an error after connecting) neither count nor reset the streak.
    """

    def __init__(self, limit: int = AUTH_FAILURE_LIMIT) -> None:
        self.limit = max(1, int(limit))
        self._cond = threading.Condition()
        self.streak = 0  # refused logins in a row
        self.failures = 0  # refused logins in this job
        self.accepted = False  # the credential worked at least once in this job
        self.tripped = False
        self.skipped = 0
        self._in_flight = 0

    def acquire(self, should_stop: Callable[[], str | None]) -> str | None:
        """Before a login: None to go ahead (then ``release`` with the target's status), else the status to record
        for the target (``skipped_credential_refused``, or the job's stop status while waiting)."""
        with self._cond:
            while True:
                if self.tripped:
                    self.skipped += 1
                    return CREDENTIAL_REFUSED
                if self.accepted or self.streak + self._in_flight < self.limit:
                    self._in_flight += 1
                    return None
                stop = should_stop()
                if stop:
                    return stop
                self._cond.wait(0.1)

    def release(self, status: str) -> None:
        with self._cond:
            self._in_flight = max(0, self._in_flight - 1)
            if status == "auth_failed":
                self.streak += 1
                self.failures += 1
                if self.streak >= self.limit:
                    self.tripped = True
            elif status in LOGIN_ACCEPTED:
                self.streak = 0
                self.accepted = True
            self._cond.notify_all()

    def reason(self) -> str:
        return (f"not tried: {self.limit} logins in a row were refused with this credential, so the scan node stopped "
                "using it to avoid locking the account; check the credential and edit the source")

    def refused(self) -> dict | None:
        """For the job result: the breaker tripped, or every login tried was refused (a one-target source: one
        refusal).  The server pauses the source's runs and schedules until its credential is edited."""
        if self.tripped or (self.failures and not self.accepted and self.streak == self.failures):
            return {"failures": self.failures, "skipped": self.skipped, "limit": self.limit}
        return None


class LeaseLost(Exception):
    """The server no longer leases this job to us (409/404): stop at once, post nothing more."""


def utc_iso(ts: float | None = None) -> str:
    moment = _dt.datetime.fromtimestamp(ts if ts is not None else time.time(), _dt.timezone.utc)
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def _clean(value: Any, depth: int = 0) -> Any:
    """Strip control characters from every string a remote system gave us (ANSI escapes, NUL)."""
    if depth > 12:
        return None
    if isinstance(value, str):
        return printable(value, 4096)
    if isinstance(value, dict):
        return {printable(str(k), 128): _clean(v, depth + 1) for k, v in list(value.items())[:500]}
    if isinstance(value, (list, tuple, set)):
        return [_clean(v, depth + 1) for v in list(value)[:2000]]
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return printable(str(value), 4096)


def _fit(value: Any, budget: int) -> Any:
    """Shrink a JSON value to fit ``budget`` bytes by trimming the longest lists/strings first."""
    data = json.loads(json.dumps(value, default=str))
    for _ in range(40):
        size = len(json.dumps(data, default=str))
        if size <= budget:
            return data
        biggest_key, biggest_len, parent = None, 0, None

        def walk(node):
            nonlocal biggest_key, biggest_len, parent
            if isinstance(node, dict):
                for k, v in node.items():
                    n = len(json.dumps(v, default=str))
                    if isinstance(v, (list, str)) and n > biggest_len:
                        biggest_key, biggest_len, parent = k, n, node
                    walk(v)
            elif isinstance(node, list):
                for v in node:
                    walk(v)

        walk(data)
        if parent is None:
            return {"_truncated": True}
        current = parent[biggest_key]
        if isinstance(current, list):
            parent[biggest_key] = current[: max(len(current) // 2, 1) if len(current) > 1 else 0]
        else:
            parent[biggest_key] = current[: max(len(current) // 2, 16)]
        data["_truncated"] = True
    return {"_truncated": True}


@dataclass
class TargetOutcome:
    target: str
    status: str
    error: str | None = None
    duration_ms: int = 0
    assets: int = 0
    counted: bool = True  # False for endpoint-level detail rows (network): counts are per address


@dataclass
class JobContext:
    job_id: int
    attempt: int
    run_id: int | None
    kind: str  # collect | test_connection | discovery
    source_kind: str | None
    scrubber: Scrubber
    never_scan: NeverScan
    deadline: float  # time.monotonic() value
    deadline_reason: str = "skipped_deadline"  # or skipped_window
    cancel: threading.Event = field(default_factory=threading.Event)
    stop_network: threading.Event = field(default_factory=threading.Event)
    poster: Callable[[list[dict], str], dict] | None = None  # (assets, batch_id) -> server counters
    state_dir: str = "/var/lib/zs-node"
    node_private_key_path: str | None = None
    vault_prefix: str | None = None
    agent_mode: bool = False  # ZS_MODE=agent: only host_agent jobs, never a job that carries credentials
    started: float = field(default_factory=time.monotonic)
    _buffer: list[dict] = field(default_factory=list)
    _seq: int = 0
    _lock: threading.Lock = field(default_factory=threading.Lock)
    sent: int = 0
    lost: int = 0  # assets the server never accepted (refused batch, API down past retries)
    _buffer_bytes: int = 0
    _last_flush: float = field(default_factory=time.monotonic)
    accepted: int = 0
    rejected: int = 0
    duplicate: int = 0
    cap_reached: bool = False
    truncated: bool = False
    outcomes: list[TargetOutcome] = field(default_factory=list)
    samples: list[dict] = field(default_factory=list)
    coverage_seen: set = field(default_factory=set)
    collected: list[dict] = field(default_factory=list)  # CLI mode only (poster is None)
    cancel_reason: str | None = None
    # A network range: addresses swept so far of the addresses in scope, posted with the asset batches (at least every
    # FLUSH_INTERVAL_S) so ZeroShield shows "N of M addresses" while the job runs.  None: not reported.
    progress_total: int | None = None
    progress_done: int = 0
    _progress_sent: dict | None = None
    # an older ZeroShield refuses the unknown "progress" field (422): stop sending it and resend the batch without it
    _progress_refused: bool = False
    # F1.4: () -> {"certificate", "expires_in_s", ...}, a fresh SSH CA certificate for this job (agent.start_job)
    cert_refresher: Callable[[], dict] | None = None
    # CB-10: the lockout guard for this job's credential (collectors that log in with a password call login_gate)
    breaker: CredentialBreaker = field(default_factory=CredentialBreaker)
    # #150: ids of the admins' host key decisions (accept / forget) this job applied, reported in the result
    host_key_resets_applied: list[int] = field(default_factory=list)

    def host_key_reset_applied(self, reset_id: int) -> None:
        with self._lock:
            if reset_id not in self.host_key_resets_applied:
                self.host_key_resets_applied.append(reset_id)

    # ------------------------------------------------------------------ progress
    def set_progress_total(self, total: int) -> None:
        with self._lock:
            self.progress_total, self.progress_done = max(0, int(total)), 0

    def address_done(self, n: int = 1) -> None:
        """``n`` more addresses finished (swept or skipped).  Posts the count, with any buffered assets, once
        FLUSH_INTERVAL_S has passed since the last post: a sparse range has few assets to carry it."""
        with self._lock:
            self.progress_done += n
            due = time.monotonic() - self._last_flush >= FLUSH_INTERVAL_S
            if due:
                self._last_flush = time.monotonic()  # this thread posts; the others wait for the next interval
        if due:
            self.flush()

    def _progress_now(self) -> dict | None:
        if self.progress_total is None or self._progress_refused:
            return None
        return {"done": min(self.progress_done, self.progress_total), "total": self.progress_total}

    # ------------------------------------------------------------------ control
    def time_left(self) -> float:
        return self.deadline - time.monotonic()

    def window_closes(self, at_epoch: float) -> bool:
        """The scan window ends at ``at_epoch`` (wall clock, seconds; in the past = closed now), as ZeroShield said in a
        heartbeat (N4: the customer closed the window while the job ran).  Moves the job's deadline earlier, never
        later; the remaining targets are then ``skipped_window`` at the next connection.  True when it moved."""
        at = time.monotonic() + (float(at_epoch) - time.time())
        if at >= self.deadline:
            return False
        self.deadline_reason = "skipped_window"  # set first: a reader that sees the new deadline sees this reason
        self.deadline = at
        return True

    def should_stop(self, network: bool = False) -> str | None:
        """None to continue, else the skip status for the remaining targets."""
        if self.cancel.is_set():
            return "skipped_cancelled"
        if network and self.stop_network.is_set():
            return "skipped_stop"
        if time.monotonic() >= self.deadline:
            return self.deadline_reason
        return None

    def login_gate(self) -> str | None:
        """Before logging in to a target with the job's credential: None to go ahead (then call ``login_done`` with
        the target's status, always), else the status to record for the target instead (``credential_skip_note``
        says why)."""
        return self.breaker.acquire(self.should_stop)

    def login_done(self, status: str) -> None:
        self.breaker.release(status)

    def credential_skip_note(self, status: str) -> str | None:
        return self.breaker.reason() if status == CREDENTIAL_REFUSED else None

    def log(self, msg: str, **fields) -> None:
        log(msg, self.scrubber, job=self.job_id, run=self.run_id, attempt=self.attempt, **fields)

    # ------------------------------------------------------------------ assets
    def emit(self, asset_type: str, target: str, location: str, name: str = "", algorithm: str | None = None,
             key_size: int | None = None, protocol: str | None = None, facts: dict | None = None) -> None:
        if asset_type not in ASSET_TYPES:
            raise ValueError(f"unknown asset type {asset_type}")
        asset = {
            "type": asset_type,
            "target": printable(str(target), 255),
            "location": printable(str(location), 512),
            "name": printable(str(name or ""), 255),
            "algorithm": printable(str(algorithm), 64) if algorithm else None,
            "key_size": int(key_size) if isinstance(key_size, (int, float)) and key_size and key_size > 0 else None,
            "protocol": printable(str(protocol), 32) if protocol else None,
            "facts": _fit(_clean(self.scrubber.obj(facts or {})), MAX_FACTS_BYTES),
        }
        asset = self.scrubber.obj(asset)
        size = len(json.dumps(asset, separators=(",", ":"), default=str)) + 1
        with self._lock:
            self._buffer.append(asset)
            self._buffer_bytes += size
            full = (len(self._buffer) >= BATCH or self._buffer_bytes >= MAX_BATCH_BYTES
                    or time.monotonic() - self._last_flush >= FLUSH_INTERVAL_S)
        if full:
            self.flush()

    def coverage(self, target: str, check: str, status: str, detail: str = "", once: bool = False,
                 scope: list[str] | None = None, incomplete: bool | None = None) -> None:
        """A check that could not read everything.  ``scope``: location prefixes within the target that the gap
        covers (none = the whole target); ``incomplete``: assets under it are still listed, with facts missing.
        Drift reads these: what a gap covers is "not read", never removed or resolved."""
        key = (check, status) if once else (target, check, status)
        if key in self.coverage_seen:
            return
        self.coverage_seen.add(key)
        facts: dict[str, Any] = {"check": check, "status": status, "detail": printable(detail, 1000)}
        if scope is not None:
            facts["scope"] = [str(p) for p in scope[:200]]
        if incomplete is not None:
            facts["incomplete"] = bool(incomplete)
        self.emit("coverage", target, f"{target}#{check}" if target else check, name=check, facts=facts)

    def flush(self) -> None:
        with self._lock:
            batch, self._buffer, self._buffer_bytes = self._buffer, [], 0
            self._last_flush = time.monotonic()
            progress = self._progress_now()
            # no assets: post only a progress count that changed (an empty batch carries it)
            if not batch and (progress is None or progress == self._progress_sent):
                return
            self._progress_sent = progress
            self._seq += 1
            batch_id = f"{self.job_id}-{self.attempt}-{self._seq}"
        self.sent += len(batch)
        if self.poster is None:
            self.collected.extend(batch)
            self.accepted += len(batch)
            return
        self._post(batch, batch_id, progress)

    def _post(self, batch: list[dict], batch_id: str, progress: dict | None = None) -> None:
        """Post one batch; a body the server finds too large is split and retried, so no asset is dropped for size.
        Raises LeaseLost.  Any other refusal is counted in ``lost`` and reported, never silently ignored."""
        from zs_scan_node.api import ApiError  # local import: api imports this module

        try:
            # only network ranges report progress; other jobs post exactly what they always posted
            counters = self.poster(batch, batch_id) if progress is None else self.poster(batch, batch_id, progress)
        except ApiError as exc:
            if exc.status == 422 and progress is not None:
                # a server that predates progress reporting validates the body strictly: keep the assets, drop the count
                with self._lock:
                    self._progress_refused = True
                self.log("server does not take progress counts; sending assets without them", batch=batch_id, level="warn")
                if batch:
                    self._post(batch, batch_id, None)
                return
            if exc.status == 413 and len(batch) > 1:
                half = len(batch) // 2
                self._post(batch[:half], f"{batch_id}a", progress)
                self._post(batch[half:], f"{batch_id}b", progress)
                return
            if not batch:  # only a progress count: nothing collected was lost, the next post carries a newer count
                self.log("progress not accepted", batch=batch_id, error=str(exc)[:200], level="warn")
                return
            with self._lock:
                self.lost += len(batch)
                self.truncated = True
            self.log("asset batch not accepted", batch=batch_id, assets=len(batch), error=str(exc)[:200], level="error")
            return
        with self._lock:
            self.accepted += int(counters.get("accepted", 0))
            self.duplicate += int(counters.get("duplicate", 0))
            self.rejected += int(counters.get("rejected", 0))
            if counters.get("cap_reached"):
                self.cap_reached = True
                self.truncated = True

    # ------------------------------------------------------------------ outcomes
    def outcome(self, target: str, status: str, error: str | None = None, started: float | None = None,
                assets: int = 0, counted: bool = True) -> None:
        if status not in TARGET_STATUSES:
            status = "error"
        duration = int((time.monotonic() - started) * 1000) if started else 0
        self.outcomes.append(TargetOutcome(printable(target, 255), status,
                                           printable(self.scrubber.text(error), 256) if error else None,
                                           duration, assets, counted))

    def result(self, summary: str | None = None) -> dict:
        counted = [o for o in self.outcomes if o.counted]
        counts = {"total": len(counted), "ok": 0, "failed": 0, "skipped": 0}
        for o in counted:
            if o.status == "ok":
                counts["ok"] += 1
            elif o.status.startswith("skipped_"):
                counts["skipped"] += 1
            else:
                counts["failed"] += 1
        rows = [o.__dict__ for o in self.outcomes[:MAX_TARGET_ROWS]]
        if len(self.outcomes) > MAX_TARGET_ROWS:
            by_status: dict[str, int] = {}
            for o in self.outcomes[MAX_TARGET_ROWS:]:
                by_status[o.status] = by_status.get(o.status, 0) + 1
            rows.append({"target": f"+{len(self.outcomes) - MAX_TARGET_ROWS} more", "status": "summary",
                         "error": json.dumps(by_status), "duration_ms": 0, "assets": 0})
        if summary is None:
            summary = (f"{counts['ok']} of {counts['total']} targets collected, {counts['failed']} failed, "
                       f"{counts['skipped']} skipped; {self.accepted} assets")
        window = sum(1 for o in counted if o.status == "skipped_window")
        if window:  # N4: say why the rest was not read, where the UI shows the job
            note = (f"the scan window closed: {window} target{'s were' if window > 1 else ' was'} not scanned; what "
                    "was read before is kept")
            summary = f"{summary[:500 - len(note) - 2]}; {note}"
        held = self.never_scan.held_names() if hasattr(self.never_scan, "held_names") else []
        if held:  # listed host names the node could not resolve held targets back: say so where the UI looks
            names = ", ".join(held[:5]) + (f" and {len(held) - 5} more" if len(held) > 5 else "")
            note = (f"never-scan: {len(held)} listed host name{'s' if len(held) > 1 else ''} did not resolve from the "
                    f"scan node ({names}); targets were held, not scanned, while unresolved")[:400]
            summary = f"{summary[:500 - len(note) - 2]}; {note}"
        out = {
            "summary": self.scrubber.text(summary)[:500],
            "counts": counts,
            "asset_count": self.accepted,
            "targets": rows,
            "truncated": bool(self.truncated),
            "assets_lost": self.lost,
            # CB-31 (R4 OBS-5): what this node sent, and what the server answered for it; the server derives the
            # asset-count mismatch from these (asset_count alone is its own accepted count and cannot show a loss)
            "sent": self.sent, "rejected": self.rejected, "duplicate": self.duplicate,
            "duration_s": int(time.monotonic() - self.started),
        }
        if held:
            out["never_scan_unresolved"] = held[:100]
        # whether any address was checked against the listed host names: only then does a missing
        # never_scan_unresolved mean "they resolved" (a job that checked no address says nothing; #298 review)
        out["never_scan_checked"] = bool(getattr(self.never_scan, "names_checked", False))
        if window:
            out["stopped"] = "window_closed"
        refused = self.breaker.refused()
        if refused:
            out["credential_refused"] = refused
        if self.kind == "test_connection":
            out["samples"] = self.scrubber.obj(self.samples)
        if self.host_key_resets_applied:
            out["host_key_resets_applied"] = list(self.host_key_resets_applied[:200])
        return out
