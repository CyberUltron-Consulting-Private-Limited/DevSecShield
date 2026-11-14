"""N3 follow-up (review of #250): network and broadcast addresses follow the network the customer entered, not the
prefix size, plus three review nits.

* A /23 entered as two /24s keeps x.x.0.255 and x.x.1.0; a real /25 ... /30 subnet skips its own network/broadcast.
* A network range sweeps exactly its ``skip_addresses`` out (ZeroShield computes them over every range of the team);
  a job without them (an older ZeroShield) treats the range as a network of its own.
* SNI: a name already refused while the endpoint was read is not handshaked again.
* Appliances: only an SSH-level error marks the device reachable.
* Agent: window ends are kept only for jobs that still run, and dropped when a job ends.
"""
from __future__ import annotations

import socket
import threading
import time

import paramiko
import pytest
import test_tls_fidelity as F  # FakeTls servers and the fake s_client
from zs_scan_node import agent as A
from zs_scan_node import netutil
from zs_scan_node import tlsprobe as T
from zs_scan_node.collectors import appliance as AP
from zs_scan_node.collectors import network as N
from zs_scan_node.jobctx import JobContext
from zs_scan_node.netutil import NeverScan, expand_targets
from zs_scan_node.scrub import Scrubber


def _ctx(kind: str = "collect") -> JobContext:
    return JobContext(job_id=1, attempt=1, run_id=None, kind=kind, source_kind="network_range", scrubber=Scrubber(),
                      never_scan=NeverScan([]), deadline=time.monotonic() + 300)


@pytest.mark.parametrize("lines, kept, skipped", [
    (["10.1.0.0/24", "10.1.1.0/24"], ["10.1.0.255", "10.1.1.0"], ["10.1.0.0", "10.1.1.255"]),
    (["10.9.0.8/29"], ["10.9.0.9", "10.9.0.14"], ["10.9.0.8", "10.9.0.15"]),
    (["10.9.0.4/30"], ["10.9.0.5", "10.9.0.6"], ["10.9.0.4", "10.9.0.7"]),
    (["10.9.1.0/25"], ["10.9.1.1", "10.9.1.126"], ["10.9.1.0", "10.9.1.127"]),
    (["10.0.3.0/24", "10.0.3.255"], ["10.0.3.255"], ["10.0.3.0"]),  # an address written out is always scanned
])
def test_a_target_list_skips_network_and_broadcast_only_at_the_edges_of_what_was_entered(lines, kept, skipped):
    targets, _ = expand_targets(lines, NeverScan([]))
    ips = {t.ip for t in targets}
    assert set(kept) <= ips and not set(skipped) & ips, (lines, sorted(ips)[:3])


def _sweep(monkeypatch, ranges) -> list[str]:
    swept: list[str] = []
    lock = threading.Lock()

    def tcp_open(self, ip, port):
        with lock:
            swept.append(ip)
        return "silent"

    monkeypatch.setattr(N.NetworkScan, "tcp_open", tcp_open)
    N.run_network(_ctx(), {"ranges": ranges, "ports": [{"port": 443, "protocol": "tls"}],
                           "rate_limits": {"connections_per_second": 1000, "parallel_per_server": 2}})
    return swept


def test_a_range_sweeps_exactly_its_skip_addresses_out(monkeypatch):
    # the second /24 of a /23 entered as two ranges: ZeroShield says only its .255 is the /23's broadcast
    swept = _sweep(monkeypatch, [{"cidr": "10.1.1.0/24", "mode": "full", "skip_addresses": ["10.1.1.255"]}])
    assert "10.1.1.0" in swept and "10.1.1.255" not in swept and len(swept) == 255


def test_a_range_from_an_older_zeroshield_is_a_network_of_its_own(monkeypatch):
    swept = _sweep(monkeypatch, [{"cidr": "10.9.0.8/29", "mode": "full"}])  # no skip_addresses key
    assert sorted(swept, key=lambda ip: int(ip.split(".")[-1])) == [f"10.9.0.{i}" for i in range(9, 15)]


def test_a_range_test_samples_follow_the_skip_addresses(monkeypatch):
    monkeypatch.setattr(N, "_tcp", lambda ip, port, never, timeout: (_ for _ in ()).throw(T.ProbeError("refused", "x")))
    ctx = _ctx("test_connection")
    N.test_range(ctx, {"ranges": [{"cidr": "10.1.1.0/24", "mode": "full", "skip_addresses": ["10.1.1.255"]}],
                       "ports": [{"port": 443, "protocol": "tls"}],
                       "rate_limits": {"connections_per_second": 1000, "parallel_per_server": 2}})
    targets = [s["target"] for s in ctx.samples]
    assert targets[0] == "10.1.1.0" and targets[-1] == "10.1.1.254"


# ----------------------------------------------------------------------------- nit: SNI names already refused
def test_a_name_with_no_tls_answer_is_not_handshaked_again(monkeypatch):
    srv = F.CloseWithoutSni(suites={T.TLS12: F.TLS12_SUITES[:2]}, sni="pay.lab")
    full = F._fake_s_client(srv)
    named: list[str | None] = []

    def counting(ip, port, protocol, sni, timeout=15.0):
        named.append(sni)
        return full(ip, port, protocol, sni, timeout)

    monkeypatch.setattr(T, "s_client", counting)
    monkeypatch.setattr(T, "have_openssl", lambda: True)
    monkeypatch.setattr(netutil, "resolve", lambda name, *a, **k: ["127.0.0.1"])
    try:
        (status, err, _n), rows, _scan = F._scan(srv, sni_names=["shop.lab", "pay.lab"])
    finally:
        srv.close()
    assert status == "ok", (status, err)
    tls = next(r for r in rows if r["type"] == "tls_endpoint")["facts"]
    assert tls["sni"] == "pay.lab"
    assert {a["name"]: a["result"] for a in tls["sni_attempts"]} == {"shop.lab": "not_tls", "pay.lab": "read"}
    assert named.count("shop.lab") == 0, named  # it gave no TLS answer with this name: no full handshake with it
    assert named.count("pay.lab") == 1, named


# ----------------------------------------------------------------------------- nit: appliance reachability
@pytest.mark.parametrize("exc, reachable", [
    (paramiko.SSHException("Error reading SSH protocol banner"), True),
    (EOFError(), True),
    (ConnectionResetError(104, "Connection reset by peer"), False),
    (socket.gaierror(-2, "Name or service not known"), False),
    (ValueError("parser"), False),
])
def test_an_appliance_error_marks_it_reachable_only_when_it_spoke_ssh(monkeypatch, exc, reachable):
    def outputs(ctx, target, vendor, config, creds):
        raise exc

    monkeypatch.setattr(AP, "_ssh_outputs", outputs)
    ctx = _ctx("test_connection")
    AP.test(ctx, {"vendor": "cisco_ios", "credential_type": "password"}, {"password": "pw"}, {"targets": ["192.0.2.1"]})
    assert [(s["status"], s["reachable"]) for s in ctx.samples] == [("error", reachable)]


# ----------------------------------------------------------------------------- nit: window ends of ended jobs
def _agent(running: dict) -> A.Agent:
    agent = A.Agent.__new__(A.Agent)
    agent.lock = threading.Lock()
    agent.never_sent = agent.stop_sent = 0.0
    agent.team_never = None
    agent.stop_network = threading.Event()
    agent.job_window_ends = {}
    agent.running = running
    return agent


def test_window_ends_are_kept_only_for_running_jobs_and_dropped_when_a_job_ends():
    ctx = _ctx()
    running = A.Running(7, "lease", ctx, True, [])
    agent = _agent({7: running})
    soon = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + 600))
    agent.apply_control({"window_ends": {"7": soon, "8": soon}}, time.monotonic())  # job 8 already ended here
    assert set(agent.job_window_ends) == {7}
    agent._done(running)  # job 7 ends before the watcher's next tick
    assert agent.job_window_ends == {}
