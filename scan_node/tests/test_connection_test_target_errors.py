"""A connection test never ends as "scan node error" because one target raised (the pattern #250 fixed for appliances,
N6): Linux servers, Windows servers, and through the dispatcher every one-target collector.  The failing target's
sample says what happened ("SSH error on this target (SSHException: ...)"), the other targets are still tested, and
the job succeeds with its samples.  Reachable only when the target spoke SSH."""
from __future__ import annotations

import time

import paramiko
import pytest
from zs_scan_node import collectors as C
from zs_scan_node.collectors import database as D
from zs_scan_node.collectors import linux_ssh as L
from zs_scan_node.collectors import windows_winrm as W
from zs_scan_node.jobctx import JobContext
from zs_scan_node.netutil import NeverScan
from zs_scan_node.scrub import Scrubber

PASSWORD = {"credential_type": "password", "host_key_policy": "pinned", "known_hosts": "x"}


def _ctx() -> JobContext:
    return JobContext(job_id=3, attempt=1, run_id=None, kind="test_connection", source_kind="linux_servers",
                      scrubber=Scrubber(), never_scan=NeverScan([]), deadline=time.monotonic() + 120)


class _Session:
    def __init__(self):
        self.host_key = {"key_type": "ssh-ed25519", "fingerprint": "SHA256:abc", "first_use": False}

    def close(self):
        pass


def _by_target(ctx):
    return {s["target"]: s for s in ctx.samples}


@pytest.mark.parametrize("exc, reachable", [
    (paramiko.SSHException("Error reading SSH protocol banner"), True),
    (paramiko.ssh_exception.IncompatiblePeer("no acceptable kex algorithm"), True),
    (EOFError(), True),
    (ConnectionResetError(104, "Connection reset by peer"), False),
    (ValueError("unexpected"), None),
])
def test_an_error_on_one_linux_server_fails_that_server_only(monkeypatch, exc, reachable):
    def open_session(ctx, target, config, creds):
        if target.ip == "192.0.2.1":
            raise exc
        return _Session()

    monkeypatch.setattr(L, "open_session", open_session)
    ctx = _ctx()
    summary = L.test(ctx, PASSWORD, {"password": "pw"}, {"targets": ["192.0.2.1", "192.0.2.2"]})
    got = _by_target(ctx)
    assert got["192.0.2.1"]["status"] == "error" and got["192.0.2.1"]["reachable"] is reachable
    assert exc.__class__.__name__ in got["192.0.2.1"]["note"] and "other targets are tested" in got["192.0.2.1"]["note"]
    assert got["192.0.2.2"]["status"] == "ready" and "SHA256:abc" in got["192.0.2.2"]["note"]
    assert summary == "1 of 2 samples ready"


def test_an_ssh_error_mid_session_fails_that_server_and_closes_its_session(monkeypatch):
    closed = []

    class Session(_Session):
        def close(self):
            closed.append(True)

    monkeypatch.setattr(L, "open_session", lambda *a, **k: Session())

    def tier2(sess, name):
        raise paramiko.SSHException("Channel closed.")

    monkeypatch.setattr(L, "run_tier2", tier2)
    ctx = _ctx()
    L.test(ctx, {**PASSWORD, "tier": 2}, {"password": "pw"}, {"targets": ["192.0.2.1"]})
    (sample,) = ctx.samples
    assert sample["status"] == "error" and sample["reachable"] is True and "Channel closed" in sample["note"]
    assert closed == [True]


def test_the_linux_test_job_succeeds_with_the_failing_servers_sample(monkeypatch):
    monkeypatch.setattr(L, "open_session", lambda *a, **k: (_ for _ in ()).throw(paramiko.SSHException("banner")))
    ctx = _ctx()
    status, error, summary = C.run_job(ctx, {"kind": "test_connection"}, {"targets": ["192.0.2.1"]},
                                       {"kind": "linux_servers", "config": PASSWORD, "secrets": {"password": "pw"}})
    assert (status, error) == ("success", None) and summary == "0 of 1 samples ready"
    assert [s["status"] for s in ctx.samples] == ["error"]


def test_an_error_on_one_windows_server_fails_that_server_only(monkeypatch):
    def session(ctx, target, config, password, ca_path):
        if target.ip == "192.0.2.1":
            raise TimeoutError("timed out")
        return object()

    monkeypatch.setattr(W, "_session", session)
    monkeypatch.setattr(W, "_run", lambda sess, name: (0, '[{"Caption": "Windows Server 2022", "Version": "10.0"}]', ""))
    ctx = _ctx()
    summary = W.test(ctx, {"credential_type": "password"}, {"password": "pw"}, {"targets": ["192.0.2.1", "192.0.2.2"]})
    got = _by_target(ctx)
    assert got["192.0.2.1"]["status"] == "error" and got["192.0.2.1"]["reachable"] is False
    assert "TimeoutError: timed out" in got["192.0.2.1"]["note"]
    assert got["192.0.2.2"]["status"] == "ready" and "Windows Server 2022" in got["192.0.2.2"]["note"]
    assert summary == "1 of 2 samples ready"


def test_a_one_target_collector_that_raises_gets_an_error_sample_not_a_crashed_job(monkeypatch):
    def boom(ctx, config, secrets, scope):
        raise paramiko.SSHException("Error reading SSH protocol banner")

    monkeypatch.setattr(D, "test", boom)
    ctx = _ctx()
    status, error, summary = C.run_job(ctx, {"kind": "test_connection"}, {},
                                       {"kind": "database", "name": "pg-prod", "config": {"host": "db.internal"},
                                        "secrets": {}})
    assert (status, error) == ("success", None) and summary == "0 of 1 samples ready"
    (sample,) = ctx.samples
    assert sample["target"] == "db.internal" and sample["status"] == "error" and sample["reachable"] is True
    assert "SSHException: Error reading SSH protocol banner" in sample["note"]


def test_a_collection_still_reports_an_unexpected_error_as_the_jobs_error(monkeypatch):
    def boom(ctx, config, secrets, scope):
        raise RuntimeError("bug")

    monkeypatch.setattr(D, "collect", boom)
    ctx = _ctx()
    ctx.kind = "collect"
    with pytest.raises(RuntimeError):
        C.run_job(ctx, {"kind": "collect"}, {}, {"kind": "database", "config": {"host": "db"}, "secrets": {}})
