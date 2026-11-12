"""F1.4 review round 7 on the node (PR #65, code/QA review 5871788632).

* ``sshca.py:104``: one renewal at a time, outside the lock; the other logins keep using the current certificate while
  it has more than ``MIN_LEFT_S`` left; after a failure, no new attempt before the back-off (negative cache).
* ``sshca.py:116``: ``LeaseLost`` (the route's 409 "Stop this job") and ``Unauthorized`` are not swallowed: the job
  stops instead of calling the route at every login.
* ``linux_ssh.py:310``: a refused certificate login says what the server had to accept (serial kept).
"""
from __future__ import annotations

import secrets
import threading
import time
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    SSHCertificateBuilder,
    SSHCertificateType,
)

from zs_scan_node import api as node_api
from zs_scan_node import sshca
from zs_scan_node.jobctx import LeaseLost

CA = ed25519.Ed25519PrivateKey.generate()


def _node_key(tmp_path: Path) -> tuple[Path, ed25519.Ed25519PrivateKey]:
    key = ed25519.Ed25519PrivateKey.generate()
    path = tmp_path / "id_ed25519"
    path.write_bytes(key.private_bytes(Encoding.PEM, PrivateFormat.OpenSSH, NoEncryption()))
    path.chmod(0o600)
    return path, key


def _cert(key, serial: int = 1) -> str:
    now = int(time.time())
    return (SSHCertificateBuilder().public_key(key.public_key()).serial(serial).type(SSHCertificateType.USER)
            .key_id(b"zs:1:2:3:1").valid_principals([b"zs-1-prod"]).valid_after(now - 60).valid_before(now + 300)
            .add_critical_option(b"source-address", b"10.0.0.5").sign(CA).public_bytes().decode())


class Clock:
    def __init__(self, t: float = 1000.0):
        self.t = t

    def __call__(self) -> float:
        return self.t


def _logins(src: sshca.CertSource, n: int) -> tuple[list[str], list[float]]:
    results: list[str] = []
    waits: list[float] = []
    lock = threading.Lock()

    def one():
        t = time.monotonic()
        try:
            src.key()
            r = "ok"
        except sshca.CertUnavailable:
            r = "refused"
        with lock:
            results.append(r)
            waits.append(time.monotonic() - t)

    threads = [threading.Thread(target=one) for _ in range(n)]
    for th in threads:
        th.start()
    for th in threads:
        th.join()
    return results, waits


def test_a_slow_failing_renewal_is_single_flight_and_nobody_waits_while_the_cert_is_usable(tmp_path):
    """QA E/C scenarios: 16 workers, 100 s left (inside the 120 s window), the server hangs 0.5 s then fails."""
    path, key = _node_key(tmp_path)
    calls: list[float] = []

    def refresher():
        calls.append(time.monotonic())
        time.sleep(0.5)
        raise node_api.ApiError(503, "busy")

    src = sshca.CertSource(str(path), _cert(key), 100, 120, refresher)
    results, waits = _logins(src, 16)
    assert results == ["ok"] * 16
    assert max(waits) < 0.25, max(waits)  # nobody queued behind the slow renewal
    deadline = time.monotonic() + 3
    while len(calls) < 1 and time.monotonic() < deadline:
        time.sleep(0.01)
    time.sleep(0.7)  # the renewal finished (and failed)
    results, waits = _logins(src, 16)  # inside the back-off: no new call
    assert results == ["ok"] * 16 and len(calls) == 1, len(calls)


def test_after_a_failure_the_next_attempt_waits_for_the_back_off(tmp_path):
    path, key = _node_key(tmp_path)
    clock = Clock()
    calls: list[float] = []
    answers: list = [node_api.ApiError(503, "busy"), {"certificate": _cert(key, 2), "expires_in_s": 300, "serial": 2}]

    def refresher():
        calls.append(clock())
        answer = answers.pop(0)
        if isinstance(answer, Exception):
            raise answer
        return answer

    src = sshca.CertSource(str(path), _cert(key), 100, 120, refresher, clock=clock)
    src.key()
    src.wait_renewal(2)
    assert len(calls) == 1
    for step in (5, 10, 20):  # 100 s left: back-off min(30, 50) = 30 s
        clock.t = 1000 + step
        src.key()
        src.wait_renewal(2)
        assert len(calls) == 1, step
    clock.t = 1031
    src.key()
    src.wait_renewal(2)
    assert len(calls) == 2 and src.serial == 2


def test_with_nothing_usable_left_everyone_waits_for_the_one_renewal(tmp_path):
    path, key = _node_key(tmp_path)
    calls: list[int] = []

    def refresher():
        calls.append(1)
        time.sleep(0.3)
        return {"certificate": _cert(key, 9), "expires_in_s": 300, "serial": 9}

    src = sshca.CertSource(str(path), _cert(key), 5, 120, refresher)  # 5 s left: below MIN_LEFT_S
    results, _waits = _logins(src, 12)
    assert results == ["ok"] * 12 and calls == [1] and src.serial == 9


def test_lease_lost_and_unauthorized_are_raised_and_remembered(tmp_path):
    """QA exp/lease_lost.py: 12 refresh calls that all got 409 'Stop this job'; now one, then raised at once."""
    path, key = _node_key(tmp_path)
    for exc in (LeaseLost("Stop this job: the source was deleted"), node_api.Unauthorized("/cbom/node/jobs/1/ssh-cert")):
        clock = Clock()
        calls: list[int] = []

        def refresher(exc=exc):
            calls.append(1)
            raise exc

        src = sshca.CertSource(str(path), _cert(key), 100, 120, refresher, clock=clock)
        with pytest.raises(type(exc)):
            src.key()
            src.wait_renewal(2)
            src.key()
        for step in range(5):
            clock.t += 10
            with pytest.raises(type(exc)):
                src.key()
        assert calls == [1], type(exc)


def test_open_session_stops_the_job_when_the_route_says_stop(tmp_path):
    """The collector's per-target ``except Exception`` must not turn LeaseLost into one error per target."""
    from zs_scan_node.collectors import linux_ssh as L

    assert hasattr(L, "_cert_login_key")
    path, key = _node_key(tmp_path)

    def refresher():
        raise LeaseLost("Stop this job: Cancelled by alice")

    class Ctx:
        def __init__(self):
            self.cancel = threading.Event()
            self.cancel_reason = None

    ctx = Ctx()
    src = sshca.CertSource(str(path), _cert(key), 5, 120, refresher)
    with pytest.raises(L.TargetFail) as err:
        L._cert_login_key(ctx, src)
    assert ctx.cancel.is_set() and "Cancelled by alice" in (ctx.cancel_reason or "")
    assert "Stop" in err.value.error


def test_a_refused_certificate_login_says_what_the_server_had_to_accept(tmp_path):
    """QA linux_ssh.py:310: serial, principals, source address, validity and the checklist."""
    path, key = _node_key(tmp_path)
    src = sshca.CertSource(str(path), _cert(key, 42), 300, 120, None)
    text = src.refusal_detail("zs-cbom")
    for needle in ("serial 42", "zs-1-prod", "10.0.0.5", "TrustedUserCAKeys", "principals file", "clock",
                   "RevokedKeys", "valid until"):
        assert needle in text, (needle, text)


# ============================================================================ code/QA re-check 5874197917 (e913f46)
def _short_cert(key, serial: int, ttl: int) -> str:
    now = int(time.time())
    skew = min(60, ttl // 5)
    return (SSHCertificateBuilder().public_key(key.public_key()).serial(serial).type(SSHCertificateType.USER)
            .key_id(b"zs:1:2:3:1").valid_principals([b"zs-1-prod"]).valid_after(now - skew)
            .valid_before(now - skew + ttl).add_critical_option(b"source-address", b"10.0.0.5")
            .sign(CA).public_bytes().decode())


def test_the_clock_tolerance_in_the_refusal_comes_from_the_certificate(tmp_path):
    """QA nit sshca.py:232: 60 s only for TTL >= 300; at TTL 60 the server may be 12 s off."""
    path, key = _node_key(tmp_path)
    long = sshca.CertSource(str(path), _short_cert(key, 1, 300), 240, 120, None).refusal_detail("zs-cbom")
    short = sshca.CertSource(str(path), _short_cert(key, 2, 60), 48, 24, None).refusal_detail("zs-cbom")
    assert "within 60 s" in long and "within 12 s" in short, short


def test_open_session_reports_a_refused_certificate_with_its_serial(tmp_path, monkeypatch):
    """QA nit linux_ssh.py:356 (mutant NK5): the transport refuses the certificate login."""
    import socket

    import paramiko as pk

    from zs_scan_node import netutil
    from zs_scan_node.collectors import linux_ssh as L
    from zs_scan_node.jobctx import JobContext
    from zs_scan_node.netutil import NeverScan, Target
    from zs_scan_node.scrub import Scrubber

    path, key = _node_key(tmp_path)
    host = pk.Ed25519Key.generate() if hasattr(pk.Ed25519Key, "generate") else None
    host_key = host or pk.Ed25519Key.from_private_key_file(str(path))

    class FakeTransport:
        _key_info = {}
        banner_timeout = auth_timeout = 0

        def __init__(self, sock):
            self.closed = False

        def get_security_options(self):
            return type("O", (), {"key_types": ()})()

        def start_client(self, timeout=None):
            return None

        def get_remote_server_key(self):
            return host_key

        def auth_publickey(self, user, k):
            raise pk.AuthenticationException("refused")

        def is_authenticated(self):
            return False

        def close(self):
            self.closed = True

    a, b = socket.socketpair()
    monkeypatch.setattr(netutil, "connect", lambda *args, **kw: a)
    monkeypatch.setattr(L.paramiko, "Transport", FakeTransport)
    ctx = JobContext(job_id=7, attempt=1, run_id=None, kind="collect", source_kind="linux_servers",
                     scrubber=Scrubber([]), never_scan=NeverScan(), deadline=time.monotonic() + 60,
                     state_dir=str(tmp_path), node_private_key_path=str(path))
    src = sshca.CertSource(str(path), _short_cert(key, 77, 300), 240, 120, None)
    with pytest.raises(L.TargetFail) as err:
        L.open_session(ctx, Target("10.0.0.9", "10.0.0.9"), {"host_key_policy": "tofu"}, {"cert_source": src})
    a.close()
    b.close()
    assert err.value.status == "auth_failed"
    assert "serial 77" in err.value.error and "TrustedUserCAKeys" in err.value.error, err.value.error


def test_with_nothing_usable_left_renewal_backs_off_exponentially_and_honours_retry_after(tmp_path):
    """QA nit sshca.py:186: 62 calls in a 400 s outage before; now 2, 4, 8 ... 30 s apart, never sooner than the
    route's Retry-After."""
    path, key = _node_key(tmp_path)
    clock = Clock(0.0)
    calls: list[float] = []

    def refresher():
        calls.append(clock())
        raise node_api.ApiError(503, "AWS KMS is not answering right now", retry_after=None) \
            if len(calls) % 2 else node_api.ApiError(400, "refused")

    src = sshca.CertSource(str(path), None, None, 120, refresher, clock=clock)
    for second in range(0, 400):
        clock.t = float(second)
        try:
            src.key()
        except sshca.CertUnavailable:
            pass
        src.wait_renewal(2)
    gaps = [b - a for a, b in zip(calls, calls[1:])]
    assert len(calls) <= 18, (len(calls), calls)
    assert gaps[:4] == [2.0, 4.0, 8.0, 16.0] and max(gaps) == 30.0, gaps

    clock2 = Clock(0.0)
    calls2: list[float] = []

    def busy():
        calls2.append(clock2())
        raise node_api.ApiError(503, "AWS KMS is not answering right now", retry_after=15.0)

    src2 = sshca.CertSource(str(path), None, None, 120, busy, clock=clock2)
    for second in range(0, 60):
        clock2.t = float(second)
        try:
            src2.key()
        except sshca.CertUnavailable:
            pass
        src2.wait_renewal(2)
    gaps2 = [b - a for a, b in zip(calls2, calls2[1:])]
    assert gaps2 and min(gaps2) >= 15.0, gaps2


def test_the_certificate_route_is_called_once_per_renewal_with_its_retry_after():
    """The node's call itself does not retry a 503 (the renewal back-off does) and keeps the Retry-After."""
    import httpx

    seen: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(1)
        return httpx.Response(503, json={"detail": "AWS KMS is not answering right now"}, headers={"Retry-After": "15"})

    client = node_api.Api("https://zs.example", "zsn_" + secrets.token_hex(20))  # generated at run time
    client.client = httpx.Client(base_url="https://zs.example", transport=httpx.MockTransport(handler))
    client._wait = lambda seconds: None
    with pytest.raises(node_api.ApiError) as err:
        client.ssh_cert(42, 2, "lease-abc")
    assert len(seen) == 1 and err.value.status == 503 and err.value.retry_after == 15.0
