"""#370 review: the SNI pre-resolution (up to SNI_DNS_BUDGET_S, before a range job's first address) obeys the job.

* It waits at most min(SNI_DNS_BUDGET_S, the job's time left): a job that starts with 1 s left does not overrun by 20 s.
* It ends as soon as the job is stopped: cancel, the stop-all switch, or the scan window closing (N4, a heartbeat
  moving the deadline earlier) while a black-holed resolver keeps every lookup hanging.
* A job that is already stopped looks nothing up.
* Names cut off this way stay unresolved: they tie nothing and are never sent (nothing becomes allowed), and the
  "SNI names left out" row says how long the lookups had.
"""
from __future__ import annotations

import threading
import time

import pytest
from zs_scan_node import netutil
from zs_scan_node import tlsprobe as T
from zs_scan_node.collectors import network as N
from zs_scan_node.jobctx import JobContext
from zs_scan_node.netutil import NeverScan
from zs_scan_node.scrub import Scrubber


def _ctx(seconds_left: float = 600.0) -> JobContext:
    return JobContext(job_id=1, attempt=1, run_id=None, kind="collect", source_kind="network_range",
                      scrubber=Scrubber(), never_scan=NeverScan([]), deadline=time.monotonic() + seconds_left)


@pytest.fixture()
def black_hole(monkeypatch):
    """Every lookup hangs until the test ends (a black-holed resolver); the names looked up are recorded."""
    release = threading.Event()
    asked: list[str] = []

    def resolve(name, *a, **k):
        asked.append(name)
        release.wait(60)
        return ["10.0.0.5", "fd00::5"]

    monkeypatch.setattr(netutil, "resolve", resolve)
    yield asked
    release.set()


SCOPE = {"sni_hostnames": ["a.internal", "b.internal"], "ranges": ["192.0.2.1/32"],
         "ports": [{"port": 443, "protocol": "tls"}]}


def _timed(fn) -> float:
    started = time.monotonic()
    fn()
    return time.monotonic() - started


def test_the_lookups_wait_no_longer_than_the_job_has_left(black_hole):
    ctx = _ctx(seconds_left=1.0)
    scan = N.NetworkScan(ctx, SCOPE)
    took = _timed(lambda: scan.learn_sni_names(report=True))
    assert took < 3.0  # not SNI_DNS_BUDGET_S (20 s)
    assert scan._sni_addresses == {"a.internal": set(), "b.internal": set()}  # unresolved: they match no address
    assert "within 1 s" in scan.sni_left_out


@pytest.mark.parametrize("stop", ["cancel", "stop_network", "window"])
def test_the_lookups_end_when_the_job_is_stopped(black_hole, stop):
    ctx = _ctx()
    scan = N.NetworkScan(ctx, SCOPE)

    def later():
        time.sleep(0.4)
        if stop == "cancel":
            ctx.cancel.set()
        elif stop == "stop_network":
            ctx.stop_network.set()
        else:
            ctx.window_closes(time.time())  # N4: the customer closed the scan window while the job ran

    threading.Thread(target=later, daemon=True).start()
    took = _timed(lambda: scan.learn_sni_names(report=False))
    assert took < 3.0
    assert black_hole  # the lookups had started
    assert ctx.never_scan.match_ip("fd00::5") is None  # nothing learned, nothing tied, nothing sent
    assert scan.sni_names_for("10.0.0.5") == []


def test_a_stopped_job_looks_nothing_up(black_hole):
    ctx = _ctx()
    ctx.cancel.set()
    scan = N.NetworkScan(ctx, SCOPE)
    assert _timed(lambda: scan.learn_sni_names(report=False)) < 1.0
    assert black_hole == []


def test_a_range_job_out_of_time_does_not_wait_for_dns(black_hole, monkeypatch):
    contacted: list[str] = []

    def tcp(ip, port, never, timeout):
        contacted.append(ip)
        raise T.ProbeError("refused", "connection refused")

    monkeypatch.setattr(N, "_tcp", tcp)
    ctx = _ctx(seconds_left=0.5)
    took = _timed(lambda: N.run_network(ctx, SCOPE))
    assert took < 3.0
    assert contacted == []  # the window had ended by the time the lookups were given up
    assert {o.status for o in ctx.outcomes} <= {"skipped_deadline"}


def test_a_range_connection_test_does_not_wait_past_a_cancel(black_hole):
    ctx = _ctx()
    threading.Timer(0.3, ctx.cancel.set).start()
    assert _timed(lambda: N.test_range(ctx, SCOPE)) < 3.0
