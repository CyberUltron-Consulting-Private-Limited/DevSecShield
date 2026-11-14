"""N9 (owner bug list 14 Nov 2026): "Save and test" on a network range probed only the first 5 addresses, so a /25 with
25+ live hosts further up the range showed "Partly ready" (or nothing answered at all).  The connection test now
probes TEST_SAMPLES (25) addresses spread evenly over the whole range after the never-scan list, the same addresses on
every re-test, a few at a time."""
from __future__ import annotations

import ipaddress
import threading
import time

from zs_scan_node.collectors import network as N
from zs_scan_node import tlsprobe as T
from zs_scan_node.jobctx import JobContext
from zs_scan_node.netutil import NeverScan
from zs_scan_node.scrub import Scrubber

SCOPE = {"ports": [{"port": 443, "protocol": "tls"}], "rate_limits": {"connections_per_second": 1000,
                                                                     "parallel_per_server": 4}}


def _ctx(never: list[str] | None = None) -> JobContext:
    return JobContext(job_id=9, attempt=1, run_id=None, kind="test_connection", source_kind="network_range",
                      scrubber=Scrubber(), never_scan=NeverScan(never or []), deadline=time.monotonic() + 600)


def _fake_tcp(monkeypatch, live: set[str]):
    probed: list[str] = []
    lock = threading.Lock()

    def tcp(ip, port, never, timeout):
        with lock:
            probed.append(ip)
        if ip in live:
            raise T.ProbeError("refused", "refused")  # the host answered
        raise T.ProbeError("timeout", "no answer")

    monkeypatch.setattr(N, "_tcp", tcp)
    return probed


def _last_octet(ip: str) -> int:
    return int(ipaddress.ip_address(ip)) & 0xFF


def test_a_25_sample_spread_over_the_whole_range(monkeypatch):
    # the reported shape: a /25 whose first addresses are unused and whose live hosts sit further up (.40 - .126)
    live = {f"10.232.0.{i}" for i in range(40, 127)}
    probed = _fake_tcp(monkeypatch, live)
    ctx = _ctx()
    summary = N.test_range(ctx, {**SCOPE, "ranges": [{"cidr": "10.232.0.0/25", "mode": "full"}]})
    targets = [s["target"] for s in ctx.samples]
    assert len(targets) == 25 == len(set(targets)) and sorted(set(probed)) == sorted(targets)
    octets = [_last_octet(t) for t in targets]
    assert octets == sorted(octets) and octets[0] == 1 and octets[-1] == 126  # first and last host of the /25
    assert max(b - a for a, b in zip(octets, octets[1:])) <= 6  # evenly spread, not bunched at the start
    ready = sum(s["status"] == "ready" for s in ctx.samples)
    assert ready == sum(t in live for t in targets) >= 17  # the old first-5 sample saw 0 of these hosts
    assert summary == f"{ready} of 25 sample addresses answered (spread across 126 addresses)"


def test_the_sample_is_the_same_on_every_retest(monkeypatch):
    _fake_tcp(monkeypatch, set())
    first, second = _ctx(), _ctx()
    N.test_range(first, {**SCOPE, "ranges": [{"cidr": "10.9.0.0/24", "mode": "full"}]})
    N.test_range(second, {**SCOPE, "ranges": [{"cidr": "10.9.0.0/24", "mode": "full"}]})
    assert [s["target"] for s in first.samples] == [s["target"] for s in second.samples]


def test_a_small_range_is_probed_whole(monkeypatch):
    _fake_tcp(monkeypatch, {"10.0.0.3"})
    ctx = _ctx()
    summary = N.test_range(ctx, {**SCOPE, "ranges": [{"cidr": "10.0.0.0/29", "mode": "full"}]})
    assert [s["target"] for s in ctx.samples] == [f"10.0.0.{i}" for i in range(1, 7)]
    assert summary == "1 of 6 sample addresses answered"


def test_never_scan_addresses_are_never_sampled(monkeypatch):
    probed = _fake_tcp(monkeypatch, set())
    ctx = _ctx(["10.232.0.0/26", "10.232.0.100"])
    N.test_range(ctx, {**SCOPE, "ranges": [{"cidr": "10.232.0.0/25", "mode": "full"}]})
    octets = [_last_octet(s["target"]) for s in ctx.samples]
    assert len(octets) == 25 and min(octets) == 64 and max(octets) == 126 and 100 not in octets
    assert all(_last_octet(ip) >= 64 and _last_octet(ip) != 100 for ip in probed)


def test_spread_sample_edges():
    assert N.spread_sample([], 25) == [] and N.spread_sample([1, 2], 25) == [1, 2]
    assert N.spread_sample(list(range(100)), 1) == [50] and N.spread_sample(list(range(100)), 0) == []
    picked = N.spread_sample(list(range(65534)), 25)
    assert len(picked) == 25 and picked[0] == 0 and picked[-1] == 65533 and picked == sorted(set(picked))
