"""F1.4 review round 7 on the node (PR #65, code/QA review 5871788632).

* ``sshca.py:104``: one renewal at a time, outside the lock; the other logins keep using the current certificate while
  it has more than ``MIN_LEFT_S`` left; after a failure, no new attempt before the back-off (negative cache).
* ``sshca.py:116``: ``LeaseLost`` (the route's 409 "Stop this job") and ``Unauthorized`` are not swallowed: the job
  stops instead of calling the route at every login.
* ``linux_ssh.py:310``: a refused certificate login says what the server had to accept (serial kept).
"""
from __future__ import annotations

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
