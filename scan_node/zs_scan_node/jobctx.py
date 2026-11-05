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
    "identity_unverified",
    "sudoers_missing", "sudo_denied", "rbac_denied", "winrm_denied", "tls_unavailable", "not_supported", "error",
    "skipped_never_scan", "skipped_window", "skipped_stop", "skipped_deadline", "skipped_cancelled",
})
FAILED = frozenset({"unreachable", "refused", "timeout", "no_route", "auth_failed", "mfa_required", "host_key_changed",
                    "identity_unverified",
                    "sudoers_missing", "sudo_denied", "rbac_denied", "winrm_denied", "tls_unavailable", "not_supported",
                    "error"})
MAX_FACTS_BYTES = 16 * 1024
MAX_TARGET_ROWS = 1000
BATCH = 500
MAX_BATCH_BYTES = 768 * 1024  # the server refuses asset bodies over 1 MB


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

    # ------------------------------------------------------------------ control
    def time_left(self) -> float:
        return self.deadline - time.monotonic()

    def should_stop(self, network: bool = False) -> str | None:
        """None to continue, else the skip status for the remaining targets."""
        if self.cancel.is_set():
            return "skipped_cancelled"
        if network and self.stop_network.is_set():
            return "skipped_stop"
        if time.monotonic() >= self.deadline:
            return self.deadline_reason
        return None

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
            full = len(self._buffer) >= BATCH or self._buffer_bytes >= MAX_BATCH_BYTES
        if full:
            self.flush()

    def coverage(self, target: str, check: str, status: str, detail: str = "", once: bool = False) -> None:
        key = (check, status) if once else (target, check, status)
        if key in self.coverage_seen:
            return
        self.coverage_seen.add(key)
        self.emit("coverage", target, f"{target}#{check}" if target else check, name=check,
                  facts={"check": check, "status": status, "detail": printable(detail, 1000)})

    def flush(self) -> None:
        with self._lock:
            batch, self._buffer, self._buffer_bytes = self._buffer, [], 0
            if not batch:
                return
            self._seq += 1
            batch_id = f"{self.job_id}-{self.attempt}-{self._seq}"
        self.sent += len(batch)
        if self.poster is None:
            self.collected.extend(batch)
            self.accepted += len(batch)
            return
        self._post(batch, batch_id)

    def _post(self, batch: list[dict], batch_id: str) -> None:
        """Post one batch; a body the server finds too large is split and retried, so no asset is dropped for size.
        Raises LeaseLost.  Any other refusal is counted in ``lost`` and reported, never silently ignored."""
        from zs_scan_node.api import ApiError  # local import: api imports this module

        try:
            counters = self.poster(batch, batch_id)
        except ApiError as exc:
            if exc.status == 413 and len(batch) > 1:
                half = len(batch) // 2
                self._post(batch[:half], f"{batch_id}a")
                self._post(batch[half:], f"{batch_id}b")
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
        out = {
            "summary": self.scrubber.text(summary)[:500],
            "counts": counts,
            "asset_count": self.accepted,
            "targets": rows,
            "truncated": bool(self.truncated),
            "assets_lost": self.lost,
            "duration_s": int(time.monotonic() - self.started),
        }
        if self.kind == "test_connection":
            out["samples"] = self.scrubber.obj(self.samples)
        return out
