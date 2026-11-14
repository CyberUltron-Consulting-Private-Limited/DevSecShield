"""Session.run must not return before the server has sent all of a command's output.

OpenSSH sends ``exit-status`` when it reaps the command, which can be before it has read the last stderr/stdout
bytes from the command's pipes; those arrive as channel data after the status, followed by EOF.  Returning on the
status alone lost sudo's "command not found" once in 20 hosts during the F1.3 parity run (a missing dmsetup then read
as "ok" with no output, and the coverage row was missing).  The loop now drains until EOF (or close), with a short
grace for servers that never send EOF.
"""
from __future__ import annotations

import time

from zs_scan_node.collectors import linux_ssh as L


class LateStderrChannel:
    """exit-status first, the stderr bytes two polls later, then EOF (what a busy OpenSSH server does)."""

    def __init__(self, stderr=b"sudo: /usr/sbin/dmsetup: command not found\n", eof=True, late_polls=2):
        self.polls = 0
        self.stderr = stderr
        self.late_polls = late_polls
        self.eof = eof
        self.eof_received = 0
        self.closed = False
        self._err_ready = False

    # what Session.run calls
    def settimeout(self, _t):
        pass

    def exec_command(self, _cmd):
        pass

    def shutdown_write(self):
        pass

    def exit_status_ready(self):
        self.polls += 1
        if self.polls == self.late_polls and self.stderr:
            self._err_ready = True
        if self.polls > self.late_polls + 1 and self.eof and not self._err_ready:
            self.eof_received = 1
        return True

    def recv_ready(self):
        return False

    def recv(self, _n):
        return b""

    def recv_stderr_ready(self):
        return self._err_ready

    def recv_stderr(self, _n):
        data, self.stderr, self._err_ready = self.stderr, b"", False
        return data

    def recv_exit_status(self):
        return 1

    def close(self):
        self.closed = True


class FakeTransport:
    """One fresh channel per command, as paramiko opens one per exec."""

    def __init__(self, make):
        self.make = make

    def open_session(self, timeout=None):
        return self.make()


def test_output_after_exit_status_is_not_lost():
    sess = L.Session(FakeTransport(LateStderrChannel), {})
    status, out, err, timed_out = sess.run("/usr/bin/sudo -n /usr/sbin/dmsetup table --target crypt")
    assert status == 1 and not timed_out
    assert "command not found" in err
    # what this cost before: a missing dmsetup read as "ok" with no output, so its coverage row was never written
    assert L.run_tier2(sess, "disk_encryption")[0] == "missing"


def test_a_server_that_never_sends_eof_costs_only_the_grace_period():
    t0 = time.monotonic()
    sess = L.Session(FakeTransport(lambda: LateStderrChannel(stderr=b"", eof=False)), {})
    status, out, err, timed_out = sess.run("true", timeout=30)
    assert status == 1 and not timed_out and err == ""
    assert time.monotonic() - t0 < L.EOF_GRACE_S + 1.0
