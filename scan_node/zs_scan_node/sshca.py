"""SSH CA certificates on the node (F1.4): the node's own Ed25519 key plus a short-lived user certificate.

ZeroShield signs the node's PUBLIC key (the private key never leaves the node).  The first certificate comes with the
claim (``source.secrets.ssh_certificate`` and ``source.config.ssh_ca``), or from the certificate route before the first
login (``fetch``); before it runs out, ``CertSource.key()`` asks ZeroShield for the next one
(``POST /cbom/node/jobs/{id}/ssh-cert``, through ``JobContext.cert_refresher``), so a job that runs for hours keeps
logging in.  A session already open is not affected by its certificate expiring (OpenSSH checks a certificate when it
authenticates).

Renewal (PR #65 review round 7):
* single flight, outside the lock: one background thread renews; the parallel logins keep using the current
  certificate while it has more than ``MIN_LEFT_S`` left, and only wait when nothing usable is left;
* after a failed renewal, no new attempt before ``min(30 s, half of what is left)`` (at least 2 s), so a slow or
  failing ZeroShield gets one call per back-off period, not one per login;
* ``LeaseLost`` (the route's 409 "Stop this job: …": cancelled, source changed, a certificate of this run revoked) and
  ``Unauthorized`` (the node's token was revoked) are remembered and raised by every later ``key()`` without calling
  the route again; the collector then stops the job.

A certificate is used only when it is a user certificate for this node's own key and is not about to expire; the
node's clock is not trusted for that (``expires_in_s`` from the server, measured with the monotonic clock).
"""
from __future__ import annotations

import base64
import datetime as _dt
import threading
import time
from typing import Any, Callable

import paramiko

MIN_LEFT_S = 10  # a certificate with less than this left is never used for a new login
BACKOFF_MAX_S = 30.0
BACKOFF_MIN_S = 2.0
WAIT_S = 150.0  # the longest a login waits for a renewal in flight (Api.ssh_cert retries a hanging server ~96 s)


class CertUnavailable(Exception):
    """No usable certificate (safe to show)."""


def _blob(line: str) -> bytes:
    parts = (line or "").strip().split()
    if len(parts) < 2:
        raise CertUnavailable("ZeroShield sent an SSH certificate that cannot be read")
    try:
        return base64.b64decode(parts[1], validate=True)
    except ValueError:
        raise CertUnavailable("ZeroShield sent an SSH certificate that cannot be read") from None


def _read_string(data: bytes, offset: int) -> tuple[bytes, int]:
    if offset + 4 > len(data):
        raise CertUnavailable("ZeroShield sent an SSH certificate that cannot be read")
    size = int.from_bytes(data[offset:offset + 4], "big")
    end = offset + 4 + size
    if end > len(data):
        raise CertUnavailable("ZeroShield sent an SSH certificate that cannot be read")
    return data[offset + 4:end], end


def check_cert_for_key(cert_line: str, key: paramiko.PKey) -> None:
    """The certificate is an Ed25519 USER certificate for ``key`` (the node's own key).  The CA signature, principals
    and validity are the servers' to judge; this only stops the node from offering a certificate meant for another
    key or another purpose."""
    blob = _blob(cert_line)
    kind, off = _read_string(blob, 0)
    if kind != b"ssh-ed25519-cert-v01@openssh.com" or key.get_name() != "ssh-ed25519":
        raise CertUnavailable("the SSH certificate is not an Ed25519 certificate for the scan node's key")
    _nonce, off = _read_string(blob, off)
    pk, off = _read_string(blob, off)
    if pk != key.asbytes()[-32:]:
        raise CertUnavailable("the SSH certificate was issued for another key than this scan node's")
    off += 8  # serial
    if off + 4 > len(blob) or int.from_bytes(blob[off:off + 4], "big") != 1:  # SSH2_CERT_TYPE_USER
        raise CertUnavailable("the SSH certificate is not a user certificate")


def cert_facts(cert_line: str) -> dict[str, Any]:
    """Serial, principals, source-address and validity of an Ed25519 user certificate (for messages only)."""
    try:
        blob = _blob(cert_line)
        _kind, off = _read_string(blob, 0)
        _nonce, off = _read_string(blob, off)
        _pk, off = _read_string(blob, off)
        serial = int.from_bytes(blob[off:off + 8], "big")
        off += 12  # serial, type
        _key_id, off = _read_string(blob, off)
        packed, off = _read_string(blob, off)
        principals, p = [], 0
        while p < len(packed):
            name, p = _read_string(packed, p)
            principals.append(name.decode(errors="replace"))
        valid_before = int.from_bytes(blob[off + 8:off + 16], "big")
        off += 16
        options, off = _read_string(blob, off)
        source, o = None, 0
        while o < len(options):
            name, o = _read_string(options, o)
            value, o = _read_string(options, o)
            if name == b"source-address":
                inner, _ = _read_string(value, 0)
                source = inner.decode(errors="replace")
        return {"serial": serial, "principals": principals, "source_address": source, "valid_before": valid_before}
    except (CertUnavailable, IndexError, ValueError):
        return {}


class CertSource:
    """The current (key + certificate) of one job, renewed in the background shortly before it expires."""

    def __init__(self, key_path: str, cert_line: str | None, expires_in_s: float | None, refresh_before_s: float,
                 refresher: Callable[[], dict[str, Any]] | None, on_secret: Callable[[str], None] | None = None,
                 clock: Callable[[], float] = time.monotonic):
        self.key_path = key_path
        self.refresher = refresher
        self.refresh_before_s = max(MIN_LEFT_S, float(refresh_before_s or 120))
        self.clock = clock
        self._lock = threading.Lock()
        self._done = threading.Event()
        self._done.set()  # no renewal in flight
        self._renewing = False
        self._retry_at = 0.0  # negative cache: no renewal attempt before this (self.clock)
        self._fatal: BaseException | None = None  # LeaseLost / Unauthorized: raised by every later key()
        self._problem: str | None = None
        self._key: paramiko.PKey | None = None
        self._expires_at = 0.0
        self.renewals = 0
        self.attempts = 0
        self.serial: int | None = None
        self.facts: dict[str, Any] = {}
        if cert_line:
            self._install(self._load(cert_line), cert_line, float(expires_in_s or 0))

    def _load(self, cert_line: str) -> paramiko.PKey:
        try:
            key = paramiko.Ed25519Key.from_private_key_file(self.key_path)
        except Exception as exc:
            raise CertUnavailable(f"the scan node's own SSH key is not available ({exc.__class__.__name__})") from None
        check_cert_for_key(cert_line, key)
        try:
            key.load_certificate(cert_line.strip())
        except Exception as exc:
            raise CertUnavailable(f"the SSH certificate does not match the key ({exc.__class__.__name__})") from None
        return key

    def _install(self, key: paramiko.PKey, cert_line: str, expires_in_s: float) -> None:
        self._key, self._expires_at = key, self.clock() + max(0.0, expires_in_s)
        self.facts = cert_facts(cert_line)
        if self.facts.get("serial") is not None:
            self.serial = self.facts["serial"]

    def left(self) -> float:
        return self._expires_at - self.clock()

    def wait_renewal(self, timeout: float | None = None) -> bool:
        """Wait for a renewal in flight (tests, and logins with nothing usable left)."""
        return self._done.wait(timeout)

    def _renew(self) -> None:
        from zs_scan_node.api import Unauthorized
        from zs_scan_node.jobctx import LeaseLost

        problem = None
        try:
            fresh = self.refresher() or {}  # type: ignore[misc]
            cert_line = str(fresh.get("certificate") or "")
            key = self._load(cert_line)
            with self._lock:
                self._install(key, cert_line, float(fresh.get("expires_in_s") or 0))
                if fresh.get("serial") is not None:
                    self.serial = fresh.get("serial")
                self.renewals += 1
                self._problem, self._retry_at = None, 0.0
        except (LeaseLost, Unauthorized) as exc:  # the job must stop: never ask again
            with self._lock:
                self._fatal = exc
        except CertUnavailable as exc:
            problem = str(exc)
        except Exception as exc:  # the API said no (400 with a reason), 503, or could not be reached
            problem = str(getattr(exc, "detail", "") or exc.__class__.__name__)[:300]
        finally:
            with self._lock:
                if problem is not None:
                    self._problem = problem
                    self._retry_at = self.clock() + max(BACKOFF_MIN_S, min(BACKOFF_MAX_S, self.left() / 2))
                self._renewing = False
                self._done.set()

    def key(self) -> paramiko.PKey:
        """A key with a certificate good for a new login now (renewal started in the background when it is about to
        expire; this call waits for it only when the current certificate is not usable any more)."""
        with self._lock:
            if self._fatal is not None:
                raise self._fatal
            left = self.left()
            if self._key is not None and left > self.refresh_before_s:
                return self._key
            start = (not self._renewing and self.refresher is not None and self.clock() >= self._retry_at)
            if start:
                self._renewing = True
                self.attempts += 1
                self._done.clear()
            usable = self._key if self._key is not None and left > MIN_LEFT_S else None
            in_flight = self._renewing
        if start:
            threading.Thread(target=self._renew, name="zs-ssh-cert-renew", daemon=True).start()
        if usable is not None:
            return usable  # the current certificate still works for this login
        if in_flight:
            self._done.wait(WAIT_S)
        with self._lock:
            if self._fatal is not None:
                raise self._fatal
            if self._key is not None and self.left() > MIN_LEFT_S:
                return self._key
            problem = self._problem or ("no SSH certificate was issued for this job" if self.refresher is None
                                        else "ZeroShield did not answer in time")
        raise CertUnavailable(f"could not get an SSH certificate from ZeroShield: {problem}")

    def refusal_detail(self, user: str) -> str:
        """What the server had to accept, when it refused the certificate login (SSH does not say why)."""
        facts = self.facts
        principals = ", ".join(facts.get("principals") or []) or "?"
        source = facts.get("source_address") or "any address"
        until = "?"
        if facts.get("valid_before"):
            until = _dt.datetime.fromtimestamp(int(facts["valid_before"]), _dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        return (f"login as {user} with the SSH CA certificate (serial {facts.get('serial', self.serial)}, principals "
                f"{principals}, from {source}, valid until {until}) was refused: check that TrustedUserCAKeys has "
                f"this team's CA keys (trusted keys), that the principals file for {user} lists {principals}, that "
                f"the server sees this scan node as {source}, that the server's clock is within 60 s of real time, "
                "and that RevokedKeys (the KRL) is current and does not list it")
