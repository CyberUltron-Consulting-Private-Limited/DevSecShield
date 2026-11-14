"""Owner-reported Network TLS bugs of 14 Nov 2026 (N1, N2, N3, N4, N6, N8, N10), proved on the scan node.

* N1: an SNI-only server (Python ``ssl`` with an ``sni_callback`` that refuses a hello without a name, and every name
  it does not serve) is read with each configured name that resolves to its address, not only the first three, with
  or without the ``openssl`` binary, and every name's result is recorded on the endpoint.
* N2: a host name on the never-scan list protects its address in a range sweep: 0 connections reach it.
* N3: a /24 split into two /25s scans .127 and .128 (only a /24-or-larger CIDR leaves out its own network and
  broadcast address).
* N4: a scan window that closes while a job runs stops it at the next connection, with "window closed" outcomes for
  the rest and what was read kept.
* N6: an SSH error on one appliance fails that appliance only (test and collect), with the error named.
* N8: the node's rate limiter never lets more than the configured connections start in any one-second window.
* N10: an appliance on a never-scan address tests as skipped, with the reason.
"""
from __future__ import annotations

import socket
import ssl
import subprocess
import threading
import time
from pathlib import Path

import paramiko
import pytest

from zs_scan_node import agent as A
from zs_scan_node import netutil
from zs_scan_node import tlsprobe as T
from zs_scan_node.collectors import appliance as AP
from zs_scan_node.collectors import network as N
from zs_scan_node.jobctx import JobContext
from zs_scan_node.netutil import NeverScan, RateLimiter
from zs_scan_node.scrub import Scrubber

REAL_GAI = socket.getaddrinfo


def _ctx(never=(), deadline_s: float = 300) -> JobContext:
    return JobContext(job_id=1, attempt=1, run_id=None, kind="collect", source_kind="network_range",
                      scrubber=Scrubber(), never_scan=NeverScan(list(never)), deadline=time.monotonic() + deadline_s)


# ----------------------------------------------------------------------------- N1: SNI-only servers, real TLS
class SniOnlyServer:
    """A real TLS server (Python ssl) that serves only ``served`` names: a hello without a name, or with any other
    name, is refused by the ``sni_callback`` with ``alert`` (unrecognized_name, as nginx ``ssl_reject_handshake``)."""

    def __init__(self, tmp: Path, served: list[str], alert: int = ssl.ALERT_DESCRIPTION_UNRECOGNIZED_NAME):
        self.contexts = {name: self._context(tmp, name) for name in served}
        self.seen: list[str | None] = []
        self._lock = threading.Lock()

        def pick(sslobj, name, _ctx):
            with self._lock:
                self.seen.append(name)
            if name not in self.contexts:
                return alert
            sslobj.context = self.contexts[name]
            return None

        self.base = self._context(tmp, "default.invalid")
        self.base.sni_callback = pick
        self.srv = socket.socket()
        self.srv.bind(("127.0.0.1", 0))
        self.srv.listen(64)
        self.port = self.srv.getsockname()[1]
        threading.Thread(target=self._loop, daemon=True).start()

    @staticmethod
    def _context(tmp: Path, name: str) -> ssl.SSLContext:
        key, crt = tmp / f"{name}.key", tmp / f"{name}.crt"
        if not crt.exists():
            subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
                            "-days", "2", "-subj", f"/CN={name}", "-addext", f"subjectAltName=DNS:{name}",
                            "-keyout", str(key), "-out", str(crt)], check=True, capture_output=True)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(str(crt), str(key))
        return ctx

    def _loop(self):
        while True:
            try:
                conn, _ = self.srv.accept()
            except OSError:
                return
            threading.Thread(target=self._one, args=(conn,), daemon=True).start()

    def _one(self, conn):
        conn.settimeout(5)
        try:
            tls = self.base.wrap_socket(conn, server_side=True)
            try:
                tls.recv(1)
            except (OSError, ssl.SSLError):
                pass
            tls.close()
        except (OSError, ssl.SSLError):
            conn.close()

    def close(self):
        self.srv.close()


needs_openssl = pytest.mark.skipif(not T.have_openssl(), reason="needs the openssl binary (the node image has it)")


@pytest.fixture
def sni_lab(tmp_path, monkeypatch):
    servers: list[SniOnlyServer] = []

    def make(served, names, resolve_to="127.0.0.1"):
        srv = SniOnlyServer(tmp_path, served)
        servers.append(srv)
        monkeypatch.setattr(netutil, "resolve", lambda name, *a, **k: [resolve_to] if name in names else [])
        return srv
    yield make
    for s in servers:
        s.close()


def _scan_sni(srv: SniOnlyServer, names: list[str], budget: int = 40):
    ctx = _ctx()
    scan = N.NetworkScan(ctx, {"sni_hostnames": names, "rate_limits": {
        "connections_per_second": 500, "parallel_per_server": 4, "handshakes_per_endpoint": budget}})
    result = scan.scan_endpoint(N.Endpoint("127.0.0.1", srv.port, "tls", "https"), "full")
    ctx.flush()
    return result, ctx.collected


def _of(rows, kind):
    return [r for r in rows if r["type"] == kind]


NAMES = ["a.lab", "b.lab", "c.lab", "shop.lab", "pay.lab"]  # the server serves only the 4th and 5th


@needs_openssl
def test_n1_an_sni_only_server_is_read_with_a_name_past_the_first_three(sni_lab):
    srv = sni_lab(["shop.lab", "pay.lab"], NAMES)
    (status, err, n), rows = _scan_sni(srv, NAMES)
    assert status == "ok", (status, err, rows)
    tls = _of(rows, "tls_endpoint")
    assert len(tls) == 1 and tls[0]["facts"]["tls"] is True and tls[0]["facts"]["sni"] == "shop.lab"
    certs = {r["facts"].get("sni"): r["name"] for r in _of(rows, "certificate")}
    assert certs == {"shop.lab": "CN=shop.lab", "pay.lab": "CN=pay.lab"}, certs
    # every name's result is on the endpoint: the refused ones, the one it was read with, the other one served
    attempts = {a["name"]: a["result"] for a in tls[0]["facts"]["sni_attempts"]}
    assert attempts == {"a.lab": "rejected", "b.lab": "rejected", "c.lab": "rejected", "shop.lab": "read",
                        "pay.lab": "read"}, attempts
    assert None in srv.seen and "c.lab" in srv.seen  # it was tried without a name first, then name by name
    assert not [r for r in _of(rows, "coverage") if r["facts"]["status"] in ("sni_required", "not_tls")]


def test_n1_without_the_openssl_binary_the_names_are_tried_with_python_ssl(sni_lab, monkeypatch):
    monkeypatch.setattr(T, "have_openssl", lambda: False)
    srv = sni_lab(["pay.lab"], NAMES)
    (status, err, n), rows = _scan_sni(srv, NAMES)
    assert status == "ok", (status, err, rows)
    tls = _of(rows, "tls_endpoint")[0]
    assert tls["facts"]["sni"] == "pay.lab" and tls["facts"]["handshake_tool"] == "python-ssl"
    assert [r["name"] for r in _of(rows, "certificate")] == ["CN=pay.lab"]
    attempts = {a["name"]: a["result"] for a in tls["facts"]["sni_attempts"]}
    assert attempts["pay.lab"] == "read" and attempts["shop.lab"] == "rejected"


@needs_openssl
def test_n1_a_server_that_takes_none_of_the_names_says_so_name_by_name(sni_lab):
    srv = sni_lab(["other.lab"], NAMES)
    (status, err, n), rows = _scan_sni(srv, NAMES)
    assert status == "tls_unavailable"
    tls = _of(rows, "tls_endpoint")[0]["facts"]
    assert tls["negotiation"] == "sni_required"
    assert [(a["name"], a["result"]) for a in tls["sni_attempts"]] == [(n_, "rejected") for n_ in NAMES]
    for name in NAMES:  # the detail names every name tried, not only the first three
        assert name in tls["detail"], tls["detail"]
    assert set(srv.seen) >= set(NAMES) | {None}


@needs_openssl
def test_n1_names_not_tried_for_the_budget_are_recorded_as_not_tried(sni_lab):
    srv = sni_lab(["pay.lab"], NAMES)
    (status, err, n), rows = _scan_sni(srv, NAMES, budget=6)
    tls = _of(rows, "tls_endpoint")[0]["facts"]
    results = [a["result"] for a in tls["sni_attempts"]]
    assert "not_tried" in results and set(results) <= {"rejected", "read", "not_tried"}, tls["sni_attempts"]
    assert [a["name"] for a in tls["sni_attempts"]] == NAMES  # every name has a result, in the team's order


# ----------------------------------------------------------------------------- N2: a listed host name, range sweep
class Listener:
    """Accepts TCP on 127.0.0.1 and 127.0.0.2 (one port) and records the local address of every connection."""

    def __init__(self):
        self.hits: list[str] = []
        self.socks = []
        port = 0
        for address in ("127.0.0.1", "127.0.0.2"):
            s = socket.socket()
            s.bind((address, port))
            port = s.getsockname()[1]
            s.listen(64)
            s.settimeout(0.1)
            self.socks.append(s)
        self.port = port
        self.stop = threading.Event()
        self.threads = [threading.Thread(target=self._loop, args=(s,), daemon=True) for s in self.socks]
        for t in self.threads:
            t.start()

    def _loop(self, s):
        while not self.stop.is_set():
            try:
                conn, _peer = s.accept()
            except OSError:
                continue
            self.hits.append(conn.getsockname()[0])
            conn.close()

    def close(self):
        time.sleep(0.3)
        self.stop.set()
        for t in self.threads:
            t.join()
        for s in self.socks:
            s.close()


def test_n2_a_host_name_on_the_team_list_gets_zero_connections_from_a_range_sweep(monkeypatch):
    def gai(host, port=None, family=0, type=0, proto=0, flags=0):  # noqa: A002 - socket's own signature
        if str(host).lower().rstrip(".") == "shop.lab":
            return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("192.0.2.10", int(port or 0))),
                    (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("127.0.0.2", int(port or 0)))]
        return REAL_GAI(host, port, family, type, proto, flags)

    monkeypatch.setattr(socket, "getaddrinfo", gai)
    lis = Listener()
    try:
        ctx = _ctx(["shop.lab"])  # what the planner sends: the team list as stored, host names included
        N.run_network(ctx, {"ranges": [{"cidr": "127.0.0.0/30", "mode": "full"}],
                            "ports": [{"port": lis.port, "protocol": "tls"}],
                            "rate_limits": {"connections_per_second": 1000, "parallel_per_server": 2}},
                      discovery_only=True)
    finally:
        lis.close()
    assert lis.hits.count("127.0.0.2") == 0, lis.hits
    assert "127.0.0.1" in lis.hits  # the sweep ran; only the listed host was left alone
    assert [o.target for o in ctx.outcomes if o.status == "skipped_never_scan"] == ["127.0.0.2"]


# ----------------------------------------------------------------------------- N3: split ranges
def test_n3_a_24_split_into_two_25s_scans_127_and_128():
    targets, _ = netutil.expand_targets(["10.232.0.0/25", "10.232.0.128/25"], NeverScan([]))
    ips = [t.ip for t in targets]
    assert "10.232.0.127" in ips and "10.232.0.128" in ips and len(ips) == 254  # only the /24's .0 and .255 out
    whole = list(netutil.iter_line_ips("10.232.0.0/24"))  # a /24 on its own leaves out its network and broadcast
    assert len(whole) == 254 and "10.232.0.0" not in whole and "10.232.0.255" not in whole


def test_n3_a_split_range_sweep_reaches_127_and_128(monkeypatch):
    swept: list[str] = []
    monkeypatch.setattr(N.NetworkScan, "tcp_open", lambda self, ip, port: swept.append(ip) or "silent")
    # what ZeroShield sends for the two halves of one /24: each range's outer edge only (jobs.claim_next)
    for cidr, skip in (("10.232.0.0/25", ["10.232.0.0"]), ("10.232.0.128/25", ["10.232.0.255"])):
        ctx = _ctx()
        N.run_network(ctx, {"ranges": [{"cidr": cidr, "mode": "full", "skip_addresses": skip}],
                            "ports": [{"port": 443, "protocol": "tls"}],
                            "rate_limits": {"connections_per_second": 500, "parallel_per_server": 2}})
    assert "10.232.0.127" in swept and "10.232.0.128" in swept and len(swept) == 254


# ----------------------------------------------------------------------------- N4: the window closes while a job runs
def test_n4_a_window_that_closes_while_a_range_runs_stops_it_at_the_next_address(monkeypatch):
    ctx = _ctx()
    seen: list[str] = []

    def tcp_open(self, ip, port):
        gate = self._gate(ip)
        if gate:
            return gate
        seen.append(ip)
        if len(seen) == 10:  # ZeroShield says the window is closed (heartbeat) after 10 addresses
            ctx.window_closes(time.time() - 1)
        return "silent"

    monkeypatch.setattr(N.NetworkScan, "tcp_open", tcp_open)
    started = time.monotonic()
    N.run_network(ctx, {"ranges": [{"cidr": "10.9.0.0/24", "mode": "full"}], "ports": [{"port": 443, "protocol": "tls"}],
                        "rate_limits": {"connections_per_second": 50, "parallel_per_server": 1}})
    assert time.monotonic() - started < 5  # 254 addresses at 50/s would take 5 s: it stopped
    assert len(seen) < 40, len(seen)  # the sweeps already in flight finish their one connection, nothing more
    statuses = [o.status for o in ctx.outcomes]
    assert statuses.count("skipped_window") >= 254 - 40
    result = ctx.result()
    assert result["stopped"] == "window_closed"
    assert "scan window closed" in result["summary"], result["summary"]


def test_n4_the_heartbeat_moves_a_running_jobs_deadline_to_the_window_end():
    ctx = _ctx(deadline_s=3600)
    agent = A.Agent.__new__(A.Agent)  # only the control fields: no enrollment, no threads
    agent.lock = threading.Lock()
    agent.never_sent = agent.stop_sent = 0.0
    agent.team_never = None
    agent.stop_network = threading.Event()
    agent.job_window_ends = {}
    agent.running = {7: A.Running(7, "lease", ctx, True, [])}
    closed = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 5))
    agent.apply_control({"window_ends": {"7": closed, "8": closed}}, time.monotonic())
    agent.apply_windows(agent.running[7])
    assert ctx.should_stop() == "skipped_window"
    # a window end later than the job's own deadline never extends it
    ctx2 = _ctx(deadline_s=60)
    agent.running[9] = A.Running(9, "lease", ctx2, True, [])
    later = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + 7200))
    agent.apply_control({"window_ends": {"9": later}}, time.monotonic())
    before = ctx2.deadline
    agent.apply_windows(agent.running[9])
    assert ctx2.deadline == before and ctx2.deadline_reason == "skipped_deadline"


# ----------------------------------------------------------------------------- N6 / N10: appliances
def _appliance_ctx(never=()):
    ctx = _ctx(never)
    ctx.kind, ctx.source_kind = "test_connection", "appliance"
    return ctx


def test_n6_an_ssh_error_on_one_appliance_fails_that_appliance_only_in_a_test(monkeypatch):
    def outputs(ctx, target, vendor, config, creds):
        if target.ip == "192.0.2.1":
            raise paramiko.SSHException("Error reading SSH protocol banner")
        return {c: "" for c in AP.COMMANDS[vendor]}, {}

    monkeypatch.setattr(AP, "_ssh_outputs", outputs)
    ctx = _appliance_ctx()
    summary = AP.test(ctx, {"vendor": "cisco_ios", "credential_type": "password"}, {"password": "pw"},
                      {"targets": ["192.0.2.1", "192.0.2.2"]})
    by_target = {s["target"]: s for s in ctx.samples}
    assert by_target["192.0.2.1"]["status"] == "error"
    assert "SSHException" in by_target["192.0.2.1"]["note"] and "protocol banner" in by_target["192.0.2.1"]["note"]
    assert by_target["192.0.2.2"]["status"] == "ready"
    assert summary == "1 of 2 samples ready"


def test_n6_an_ssh_error_on_one_appliance_fails_that_appliance_only_in_a_collection(monkeypatch):
    def outputs(ctx, target, vendor, config, creds):
        if target.ip == "192.0.2.1":
            raise paramiko.SSHException("Incompatible ssh peer (no acceptable kex algorithm)")
        return {c: "" for c in AP.COMMANDS[vendor]}, {}

    monkeypatch.setattr(AP, "_ssh_outputs", outputs)
    ctx = _ctx()
    ctx.source_kind = "appliance"
    AP.collect(ctx, {"vendor": "cisco_ios", "credential_type": "password"}, {"password": "pw"},
               {"targets": ["192.0.2.1", "192.0.2.2"]})
    by_target = {o.target: o for o in ctx.outcomes}
    assert by_target["192.0.2.1"].status == "error"
    assert "SSHException" in by_target["192.0.2.1"].error and "no acceptable kex" in by_target["192.0.2.1"].error
    assert by_target["192.0.2.2"].status == "ok"


def test_n10_an_appliance_on_a_never_scan_address_is_a_skipped_sample_with_the_reason():
    ctx = _appliance_ctx(["192.0.2.9"])
    summary = AP.test(ctx, {"vendor": "fortios", "credential_type": "password"}, {"password": "pw"},
                      {"targets": ["192.0.2.9"]})
    assert [(s["target"], s["status"]) for s in ctx.samples] == [("192.0.2.9", "skipped_never_scan")]
    assert "never-scan" in ctx.samples[0]["note"]
    assert summary.startswith("0 of 1")


# ----------------------------------------------------------------------------- N8: rate limiter
def test_n8_no_one_second_window_starts_more_connections_than_the_rate():
    rate = 20
    stamps: list[float] = []  # the limiter's own start times, taken under its lock (a busy CI box cannot skew them)

    class Recording(RateLimiter):
        def _wait(self, now):
            wait = super()._wait(now)
            if wait <= 0:
                stamps.append(now)
            return wait

    limiter = Recording(per_second=rate, per_server=64)
    end = time.monotonic() + 2.6

    def worker():
        while time.monotonic() < end:
            limiter.acquire()

    threads = [threading.Thread(target=worker) for _ in range(16)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    stamps.sort()
    worst = max(sum(1 for s in stamps if t0 <= s < t0 + 1.0) for t0 in stamps)
    assert worst <= rate, f"{worst} connections started within one second at {rate}/s"
    assert len(stamps) >= int(rate * 2.6 * 0.8), len(stamps)  # and the average is still about the agreed rate


def test_n8_a_lower_rate_after_a_burst_is_never_exceeded_either():
    limiter = RateLimiter(per_second=50, per_server=8)
    stamps = [time.monotonic() for _ in range(10) if limiter.acquire()]
    limiter.configure(5, 8)  # the newest job carries the team's lower rate
    end = time.monotonic() + 1.5
    while time.monotonic() < end:
        if limiter.acquire(deadline=end):
            stamps.append(time.monotonic())
    late = [s for s in stamps[10:]]
    worst = max((sum(1 for s in late if t0 <= s < t0 + 1.0) for t0 in late), default=0)
    assert worst <= 5, worst
