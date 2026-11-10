"""Tier 2 on a server without iproute2 (local lab, round 5, u1).

The sudoers file was installed and sudo allowed every line, but /usr/bin/ss is not on a minimal Debian 12 server:
`sudo -n /usr/bin/ss -H -tlnp` answers "command not found" (a line sudo does not allow gets "a password is required"
instead).  The connection test probed with ss only and told the customer "the zs-cbom sudoers file is missing or does
not match"; collection reported the missing program as "denied".
"""
import time

from zs_scan_node import commands as C
from zs_scan_node.collectors import linux_ssh as L
from zs_scan_node.jobctx import JobContext
from zs_scan_node.netutil import NeverScan
from zs_scan_node.scrub import Scrubber


class FakeSession:
    """sudo as on Debian 12 with the zs-cbom sudoers file: allowed lines run, missing programs are "not found"."""

    host_key = {"key_type": "ssh-ed25519", "fingerprint": "SHA256:abc", "first_use": False}

    def __init__(self, sudoers=True, programs=("/usr/sbin/sshd", "/usr/bin/find", "/usr/bin/lsblk")):
        self.sudoers, self.programs, self.lines = sudoers, set(programs), []

    def run(self, command, timeout=None, binary=False):
        self.lines.append(command)
        if command.startswith(C.SUDO):
            program = command.split()[2]
            if not self.sudoers:
                return 1, "", "sudo: a password is required\n", False
            if program not in self.programs:
                return 1, "", f"sudo: {program}: command not found\n", False
            return 0, "Port 22\n", "", False
        return 0, "", "", False

    def close(self):
        pass


def _ctx():
    return JobContext(job_id=1, attempt=1, run_id=2, kind="test_connection", source_kind="linux_servers",
                      scrubber=Scrubber([]), never_scan=NeverScan([]), deadline=time.monotonic() + 60)


def _test(monkeypatch, sess):
    monkeypatch.setattr(L, "open_session", lambda ctx, target, config, creds: sess)
    monkeypatch.setattr(L, "_credentials", lambda ctx, config, secrets: {"key": object()})
    ctx = _ctx()
    L.test(ctx, {"tier": 2, "credential_type": "node_key"}, {}, {"targets": ["10.0.0.5"]})
    return ctx.samples[0]


def test_missing_ss_is_not_a_missing_sudoers_file(monkeypatch):
    sample = _test(monkeypatch, FakeSession())
    assert sample["status"] == "ready" and sample["privilege"] is True
    assert "ss is not installed" in sample["note"] and "sudoers" not in sample["note"]


def test_a_missing_sudoers_file_is_still_reported(monkeypatch):
    sample = _test(monkeypatch, FakeSession(sudoers=False))
    assert sample["status"] == "sudo_denied" and sample["privilege"] is False


def test_run_tier2_says_missing_for_command_not_found():
    sess = FakeSession(programs=())
    state, _out, detail = L.run_tier2(sess, "listening_sockets")
    assert state == "missing" and "command not found" in detail
    assert L.run_tier2(FakeSession(sudoers=False), "listening_sockets")[0] == "password"
    assert L.run_tier2(FakeSession(), "sshd_effective_config")[0] == "ok"
