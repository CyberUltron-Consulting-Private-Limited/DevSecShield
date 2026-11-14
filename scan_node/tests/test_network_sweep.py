"""Network range collection: bounded time on silent ranges, coverage for what did not answer, progress while running.

Round 5 (local lab, u3): a /29 with two absent addresses took 31 s, 30.7 s per silent address (16 TCP ports swept one
after the other, 2 s connect timeout each), so a sparse /24 took ~15 minutes with nothing posted until the end, and
the silent addresses were recorded as "ok" with no coverage row (a host that went quiet read as "everything fixed").
"""
from __future__ import annotations

import socket
import threading
import time

from zs_scan_node import jobctx
from zs_scan_node import tlsprobe as T
from zs_scan_node.collectors import network as N
from zs_scan_node.jobctx import JobContext
from zs_scan_node.netutil import NeverScan
from zs_scan_node.scrub import Scrubber

TCP16 = [{"port": p, "protocol": "tls", "label": ""} for p in
         (443, 8443, 636, 465, 993, 995, 9093, 8883, 10443, 11443, 12443, 13443, 14443, 15443, 16443, 17443)]
SILENT_S = 0.2  # a silent port's connect time in these tests (2 s in a real sweep)


def _ctx(seconds: float = 120) -> JobContext:
    return JobContext(job_id=1, attempt=1, run_id=None, kind="collect", source_kind="network_range",
                      scrubber=Scrubber(), never_scan=NeverScan([]), deadline=time.monotonic() + seconds)


class _Sock:
    def close(self):
        pass


def _fake_tcp(open_ports=(), refused_ports=(), live=()):
    """Addresses in ``live`` answer: open_ports accept, refused_ports refuse, every other port is silent (filtered).
    Every other address is silent on every port.  Silence costs SILENT_S, like a connect timeout."""
    lock = threading.Lock()
    state = {"now": 0, "peak": 0, "calls": 0}

    def tcp(ip, port, never, timeout):
        with lock:
            state["now"] += 1
            state["calls"] += 1
            state["peak"] = max(state["peak"], state["now"])
        try:
            if ip in live and port in open_ports:
                return _Sock()
            if ip in live and port in refused_ports:
                raise T.ProbeError("refused", "connection refused")
            time.sleep(SILENT_S)
            raise T.ProbeError("timeout", "connect timed out")
        finally:
            with lock:
                state["now"] -= 1
    return tcp, state


def _cov(ctx, check=None):
    ctx.flush()  # CLI-style context (no poster): rows land in ctx.collected when flushed
    return [a for a in ctx.collected if a["type"] == "coverage" and (check is None or a["facts"]["check"] == check)]


def test_silent_range_is_swept_in_bounded_time_with_a_coverage_row_per_address(monkeypatch):
    tcp, state = _fake_tcp()
    monkeypatch.setattr(N, "_tcp", tcp)
    ctx = _ctx()
    scope = {"ranges": [{"cidr": "192.0.2.0/27", "mode": "full"}], "ports": TCP16,
             "rate_limits": {"connections_per_second": 1000, "parallel_per_server": 2}}
    started = time.monotonic()
    N.run_network(ctx, scope)
    elapsed = time.monotonic() - started
    # 30 addresses x 16 silent ports: one port at a time and 16 addresses at once took 30*16*0.2/16 = 6 s;
    # now each address sweeps 2 ports at a time and every address runs at once: 8 rounds of 0.2 s
    assert elapsed < 3.5, elapsed
    assert state["calls"] == 30 * 16
    assert state["peak"] > 16  # more connects in flight than the old 16 addresses x 1 port
    rows = _cov(ctx, "no answer")
    assert sorted(a["target"] for a in rows) == sorted(f"192.0.2.{i}" for i in range(1, 31))
    assert all(a["facts"]["status"] == "unreachable" and "scope" not in a["facts"] for a in rows)  # whole target
    outcomes = {o.target: o.status for o in ctx.outcomes}
    assert len(outcomes) == 30 and set(outcomes.values()) == {"ok"}  # sparse ranges are normal: swept, not failed


def test_sweep_keeps_the_per_server_cap(monkeypatch):
    seen: dict[str, int] = {}
    now: dict[str, int] = {}
    lock = threading.Lock()

    def tcp(ip, port, never, timeout):
        with lock:
            now[ip] = now.get(ip, 0) + 1
            seen[ip] = max(seen.get(ip, 0), now[ip])
        time.sleep(0.05)
        with lock:
            now[ip] -= 1
        raise T.ProbeError("refused", "connection refused")

    monkeypatch.setattr(N, "_tcp", tcp)
    ctx = _ctx()
    N.run_network(ctx, {"ranges": ["192.0.2.0/30"], "ports": TCP16,
                        "rate_limits": {"connections_per_second": 1000, "parallel_per_server": 3}})
    assert seen and max(seen.values()) <= 3


def test_live_host_filtered_ports_and_failed_endpoint_get_scoped_coverage(monkeypatch):
    tcp, _state = _fake_tcp(open_ports=(443, 8443), refused_ports=(636,), live=("192.0.2.5",))
    monkeypatch.setattr(N, "_tcp", tcp)

    def fake_endpoint(self, ep, mode):
        if ep.port == 8443:
            return "timeout", "no TLS answer", 0
        self.ctx.emit("tls_endpoint", ep.ip, ep.where, name="x", protocol="TLSv1.2", facts={})
        return "ok", None, 1

    monkeypatch.setattr(N.NetworkScan, "scan_endpoint", fake_endpoint)
    ctx = _ctx()
    N.run_network(ctx, {"ranges": ["192.0.2.5/32"], "ports": TCP16,
                        "rate_limits": {"connections_per_second": 1000, "parallel_per_server": 2}})
    assert not _cov(ctx, "no answer")  # the host answered
    filtered = _cov(ctx, "ports not answering")
    assert len(filtered) == 1
    scope = filtered[0]["facts"]["scope"]
    assert "192.0.2.5:993" in scope and "192.0.2.5:443" not in scope and "192.0.2.5:636" not in scope
    assert filtered[0]["facts"]["incomplete"] is False
    failed = _cov(ctx, "endpoint 192.0.2.5:8443")
    assert len(failed) == 1 and failed[0]["facts"]["scope"] == ["192.0.2.5:8443"]
    assert failed[0]["facts"]["status"] == "timeout"
    assert [o.status for o in ctx.outcomes if o.target == "192.0.2.5"] == ["ok"]


def test_ike_only_gateway_is_not_reported_as_silent(monkeypatch):
    tcp, _state = _fake_tcp()
    monkeypatch.setattr(N, "_tcp", tcp)
    monkeypatch.setattr(N.NetworkScan, "scan_ike", lambda self, ep, mode, primary: ("ok", None, 1))
    ctx = _ctx()
    N.run_network(ctx, {"ranges": ["192.0.2.7/32"], "ports": TCP16[:2] + [{"port": 500, "protocol": "ike"}],
                        "rate_limits": {"connections_per_second": 1000, "parallel_per_server": 2}})
    assert not _cov(ctx, "no answer")
    assert len(_cov(ctx, "ports not answering")) == 1


def test_discovery_assets_are_only_open_ports(monkeypatch):
    """The Network TLS tab shows a discovery job's asset count as "N open endpoints": no coverage rows there."""
    tcp, _state = _fake_tcp(open_ports=(443,), live=("192.0.2.1",))
    monkeypatch.setattr(N, "_tcp", tcp)
    ctx = _ctx()
    ctx.kind = "discovery"
    N.run_network(ctx, {"ranges": ["192.0.2.0/30"], "ports": TCP16[:3],
                        "rate_limits": {"connections_per_second": 1000, "parallel_per_server": 2}},
                  discovery_only=True)
    ctx.flush()
    assert [a["location"] for a in ctx.collected] == ["192.0.2.1:443"]
    assert {o.target: o.status for o in ctx.outcomes} == {"192.0.2.1": "ok", "192.0.2.2": "ok"}


def test_silent_rows_are_capped_with_one_job_wide_row(monkeypatch):
    tcp, _state = _fake_tcp()
    monkeypatch.setattr(N, "_tcp", tcp)
    monkeypatch.setattr(N, "MAX_NO_ANSWER_ROWS", 3)
    ctx = _ctx()
    N.run_network(ctx, {"ranges": ["192.0.2.0/29"], "ports": TCP16[:1],
                        "rate_limits": {"connections_per_second": 1000, "parallel_per_server": 1}})
    rows = _cov(ctx, "no answer")
    assert len([r for r in rows if r["target"]]) == 3
    assert len([r for r in rows if not r["target"]]) == 1


def test_tls_checks_that_could_not_run_are_an_incomplete_gap(monkeypatch):
    """A version probe that timed out reads as None: the finding it would show must not read as fixed."""
    full = T.FullHandshake(ok=True, version="TLSv1.2", cipher="ECDHE-RSA-AES128-GCM-SHA256", tool="openssl")
    monkeypatch.setattr(T, "have_openssl", lambda: True)
    monkeypatch.setattr(T, "s_client", lambda *a, **k: full)

    def probe(ip, port, protocol, hello, timeout=8.0, want_kex=False):
        if hello[9:11] == b"\x03\x01":  # the TLS 1.0 ClientHello
            raise T.ProbeError("timeout", "server too slow")
        return T.HelloResult(closed=True, error="closed")

    monkeypatch.setattr(T, "probe", probe)
    ctx = _ctx()
    scan = N.NetworkScan(ctx, {"rate_limits": {"connections_per_second": 1000}})
    status, _err, _n = scan.scan_endpoint(N.Endpoint("192.0.2.9", 443, "tls", "HTTPS"), "fragile")
    assert status == "ok"
    gap = _cov(ctx, "TLS checks 192.0.2.9:443")
    assert len(gap) == 1 and gap[0]["facts"]["incomplete"] is True and gap[0]["facts"]["scope"] == ["192.0.2.9:443"]
    assert "TLSv1.0: timeout" in gap[0]["facts"]["detail"]
    ctx.flush()
    ep = next(a for a in ctx.collected if a["type"] == "tls_endpoint")
    assert ep["facts"]["versions"]["TLSv1.0"] is None and "TLSv1.0: timeout" in ep["facts"]["checks_not_run"]


def test_a_reset_is_a_refusal_not_a_gap(monkeypatch):
    full = T.FullHandshake(ok=True, version="TLSv1.2", cipher="x", tool="openssl")
    monkeypatch.setattr(T, "have_openssl", lambda: True)
    monkeypatch.setattr(T, "s_client", lambda *a, **k: full)

    def probe(ip, port, protocol, hello, timeout=8.0, want_kex=False):
        raise T.ConnectionReset()  # what tlsprobe raises for a reset after the hello (CB-12: not a refused connect)

    monkeypatch.setattr(T, "probe", probe)
    ctx = _ctx()
    N.NetworkScan(ctx, {"rate_limits": {"connections_per_second": 1000}}).scan_endpoint(
        N.Endpoint("192.0.2.9", 443, "tls", ""), "fragile")
    assert not _cov(ctx)


def test_a_long_job_posts_assets_while_it_runs(monkeypatch):
    posted: list[int] = []
    ctx = _ctx()
    ctx.poster = lambda batch, batch_id: posted.append(len(batch)) or {"accepted": len(batch)}
    ctx.emit("coverage", "192.0.2.1", "a", facts={"check": "x", "status": "unreachable"})
    assert posted == []  # a fresh batch waits for more
    ctx._last_flush -= jobctx.FLUSH_INTERVAL_S + 1
    ctx.emit("coverage", "192.0.2.2", "b", facts={"check": "x", "status": "unreachable"})
    assert posted == [2] and ctx.accepted == 2  # the job's asset count in ZeroShield grows: the customer's progress
    ctx.emit("coverage", "192.0.2.3", "c", facts={"check": "x", "status": "unreachable"})
    assert posted == [2]  # the interval starts again


def test_real_sockets_silent_and_refused(monkeypatch):
    """The real gate: a refused port on 127.0.0.1 is 'closed', a listening one 'open'."""
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(4)
    port = srv.getsockname()[1]
    closed = socket.socket()
    closed.bind(("127.0.0.1", 0))
    free = closed.getsockname()[1]
    closed.close()
    ctx = _ctx()
    scan = N.NetworkScan(ctx, {"rate_limits": {"connections_per_second": 1000}})
    try:
        assert scan.tcp_open("127.0.0.1", port) == "open"
        assert scan.tcp_open("127.0.0.1", free) == "closed"
    finally:
        srv.close()
