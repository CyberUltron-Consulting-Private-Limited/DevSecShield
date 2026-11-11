"""SSH CA certificates on the node (F1.4): the node's own Ed25519 key plus a short-lived user certificate.

ZeroShield signs the node's PUBLIC key (the private key never leaves the node).  The first certificate comes with the
claim (``source.secrets.ssh_certificate`` and ``source.config.ssh_ca``); before it runs out, ``CertSource.key()``
asks ZeroShield for the next one (``POST /cbom/node/jobs/{id}/ssh-cert``, through ``JobContext.cert_refresher``), so a
job that runs for hours keeps logging in.  A session already open is not affected by its certificate expiring
(OpenSSH checks a certificate when it authenticates).

A certificate is used only when it is a user certificate for this node's own key and is not about to expire; the
node's clock is not trusted for that (``expires_in_s`` from the server, measured with the monotonic clock).
"""
from __future__ import annotations

import base64
import threading
import time
from typing import Any, Callable

import paramiko

MIN_LEFT_S = 10  # a certificate with less than this left is never used for a new login


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


class CertSource:
    """The current (key + certificate) of one job, renewed under a lock shortly before it expires."""

    def __init__(self, key_path: str, cert_line: str | None, expires_in_s: float | None, refresh_before_s: float,
                 refresher: Callable[[], dict[str, Any]] | None, on_secret: Callable[[str], None] | None = None,
                 clock: Callable[[], float] = time.monotonic):
        self.key_path = key_path
        self.refresher = refresher
        self.refresh_before_s = max(MIN_LEFT_S, float(refresh_before_s or 120))
        self.clock = clock
        self._lock = threading.Lock()
        self._key: paramiko.PKey | None = None
        self._expires_at = 0.0
        self.renewals = 0
        self.serial: int | None = None
        if cert_line:
            self._install(cert_line, float(expires_in_s or 0))

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

    def _install(self, cert_line: str, expires_in_s: float) -> None:
        key = self._load(cert_line)
        self._key, self._expires_at = key, self.clock() + max(0.0, expires_in_s)

    def left(self) -> float:
        return self._expires_at - self.clock()

    def key(self) -> paramiko.PKey:
        """A key with a certificate good for a new login now (renewed first when it is about to expire)."""
        with self._lock:
            if self._key is not None and self.left() > self.refresh_before_s:
                return self._key
            problem = None
            if self.refresher is not None:
                try:
                    fresh = self.refresher() or {}
                    self._install(str(fresh.get("certificate") or ""), float(fresh.get("expires_in_s") or 0))
                    self.serial = fresh.get("serial")
                    self.renewals += 1
                except CertUnavailable as exc:
                    problem = str(exc)
                except Exception as exc:  # the API said no (400 with a reason) or could not be reached
                    problem = str(getattr(exc, "detail", "") or exc.__class__.__name__)[:300]
            else:
                problem = "no SSH certificate was issued for this job"
            if self._key is not None and self.left() > MIN_LEFT_S:
                return self._key  # renewal failed but the current certificate still works for this login
            raise CertUnavailable(f"could not get an SSH certificate from ZeroShield: {problem}")
