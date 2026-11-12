"""Never-scan proved at socket level (PR #32 security review): real local listeners record every connection that is
accepted, so a test fails on any connection attempt to a listed address, not just when a mocked gate is called.

Names are answered at ``socket.getaddrinfo`` (what netutil, urllib3 and the drivers call).  The runner may have no
IPv6, so a dual-stack host is modelled as a name that answers 127.0.0.2 (allowed) and 127.0.0.1 (listed).
"""
from __future__ import annotations

import socket
import threading
import time

import pytest

import test_wp8b_agent_registry as registry_lab  # a TLS server with its own CA (Lab)

from zs_scan_node import netutil
from zs_scan_node.collectors import container_images as CI
from zs_scan_node.collectors import database as D
from zs_scan_node.collectors import linux_ssh as L
from zs_scan_node.collectors import network as N
from zs_scan_node.collectors import windows_winrm as W
from zs_scan_node.jobctx import JobContext
from zs_scan_node.netutil import Blocked, NeverScan
from zs_scan_node.scrub import Scrubber

REAL_GAI = socket.getaddrinfo
PROXY_VARS = ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy")


class Listener:
    """TCP listeners on ``addresses`` (one port for all); records the local address of every accepted connection."""

    def __init__(self, addresses=("127.0.0.1", "127.0.0.2")):
        self.hits: list[str] = []
        self.socks: list[socket.socket] = []
        port = 0
        for address in addresses:
            s = socket.socket()
            s.bind((address, port))
            port = s.getsockname()[1]
            s.listen(16)
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
                conn, _ = s.accept()
            except OSError:
                continue
            self.hits.append(conn.getsockname()[0])
            conn.close()

    def close(self):
        time.sleep(0.2)  # let a connection that is on its way be accepted and recorded
        self.stop.set()
        for t in self.threads:
            t.join()
        for s in self.socks:
            s.close()


@pytest.fixture()
def lis():
    listener = Listener()
    yield listener
    listener.close()


@pytest.fixture()
def dns(monkeypatch):
    """Answers for *.internal names (and the short name ``db``); an answer may depend on the lookup number."""
    table: dict = {}
    calls: list[str] = []

    def gai(host, port=None, family=0, type=0, proto=0, flags=0):  # noqa: A002 - socket's own signature
        h = str(host).lower().rstrip(".")
        if h not in table:
            return REAL_GAI(host, port, family, type, proto, flags)
        calls.append(h)
        ans = table[h]
        if callable(ans):
            ans = ans(calls.count(h))
        out = []
        for ip in ans:
            fam = socket.AF_INET6 if ":" in ip else socket.AF_INET
            if family and family != fam:
                continue
            sa = (ip, int(port or 0), 0, 0) if fam == socket.AF_INET6 else (ip, int(port or 0))
            out.append((fam, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", sa))
        if not out:
            raise socket.gaierror(socket.EAI_NONAME, "no address")
        return out

    monkeypatch.setattr(socket, "getaddrinfo", gai)
    return table, calls


def _ctx(never):
    return JobContext(job_id=1, attempt=1, run_id=None, kind="collect", source_kind=None, scrubber=Scrubber(),
                      never_scan=NeverScan(never), deadline=time.monotonic() + 600)


# ----------------------------------------------------------------------------- a name with one listed address
def test_a_name_with_one_listed_address_is_never_contacted_by_any_collector(lis, dns):
    table, _ = dns
    for name in ("srv.internal", "reg.internal", "db.internal"):
        table[name] = ["127.0.0.2", "127.0.0.1"]
    never = ["127.0.0.1"]
    ctx = _ctx(never)
    assert L._targets(ctx, {"targets": ["srv.internal"]}) == []  # Linux SSH and SSH appliances
    ctx_w = _ctx(never)
    W.collect(ctx_w, {"port": lis.port}, {"password": "pw"}, {"targets": ["srv.internal"]})
    reg = CI.Registry(_ctx(never), CI.parse_ref(f"reg.internal:{lis.port}/app:1"), {}, None)
    with pytest.raises(CI.ImageError) as err:
        reg.get("/v2/")
    _t, status, why, _n = D._one(_ctx(never), {"engine": "postgres", "host": "db.internal", "port": lis.port}, {})
    assert err.value.status == "skipped_never_scan" and status == "skipped_never_scan"
    assert [(o.target, o.status) for o in ctx.outcomes + ctx_w.outcomes] == [("srv.internal", "skipped_never_scan")] * 2
    assert all("127.0.0.1" in text for text in (why, err.value.detail, ctx.outcomes[0].error, ctx_w.outcomes[0].error))
    assert lis.hits == []  # no connection to either address


def test_control_the_listener_records_a_connection(lis, dns):
    table, _ = dns
    table["reg.internal"] = ["127.0.0.2", "127.0.0.1"]
    reg = CI.Registry(_ctx([]), CI.parse_ref(f"reg.internal:{lis.port}/app:1"), {}, None)
    with pytest.raises(CI.ImageError):
        reg.get("/v2/")  # the TLS handshake fails: the listener closes the connection
    assert lis.hits == ["127.0.0.1"]  # IPv4 first, sorted: the first address is connected to


# ----------------------------------------------------------------------------- a name that answers differently later
def _rebind(n):  # the first two lookups answer the allowed address, every later one the listed address
    return ["127.0.0.2"] if n <= 2 else ["127.0.0.1"]


def test_winrm_connects_only_to_the_checked_address_and_never_through_a_proxy(lis, dns, monkeypatch):
    table, calls = dns
    table["win.internal"] = _rebind
    proxy = Listener(("127.0.0.3",))
    try:
        for var in PROXY_VARS:
            monkeypatch.setenv(var, f"http://127.0.0.3:{proxy.port}")
        monkeypatch.delenv("NO_PROXY", raising=False)
        monkeypatch.delenv("no_proxy", raising=False)
        ctx = _ctx(["127.0.0.1"])
        W.collect(ctx, {"port": lis.port}, {"password": "pw"}, {"targets": ["win.internal"]})
    finally:
        proxy.close()
    assert proxy.hits == []  # the environment's proxy is never used
    assert lis.hits and set(lis.hits) == {"127.0.0.2"}  # the checked address, not a later DNS answer
    assert calls == ["win.internal", "win.internal"]  # expansion + the check before the session; WinRM did not resolve
    assert ctx.outcomes[0].status != "skipped_never_scan"  # it was allowed when checked; the listener then hung up


def test_ad_cs_winrm_session_is_pinned_too(lis, dns, monkeypatch):
    from zs_scan_node.collectors import ca as CA

    for var in PROXY_VARS:  # no proxy at all: this test is about the later DNS answer only
        monkeypatch.delenv(var, raising=False)
    table, _ = dns
    table["adcs.internal"] = _rebind
    with pytest.raises(CA.CaFail):
        CA.collect_adcs(_ctx(["127.0.0.1"]), {"host": "adcs.internal", "port": lis.port, "login": "u"}, "pw")
    assert lis.hits and set(lis.hits) == {"127.0.0.2"}


def test_ssh_and_registry_are_pinned_to_the_checked_address(lis, dns):
    table, calls = dns
    table["srv.internal"] = _rebind
    ctx = _ctx(["127.0.0.1"])
    [target] = L._targets(ctx, {"targets": ["srv.internal"]})
    for _ in range(2):
        with pytest.raises(L.TargetFail):
            L.open_session(ctx, target, {"port": lis.port}, {"key": "unused"})
    table["reg.internal"] = _rebind
    reg = CI.Registry(_ctx(["127.0.0.1"]), CI.parse_ref(f"reg.internal:{lis.port}/app:1"), {}, None)
    for _ in range(2):
        with pytest.raises(CI.ImageError):
            reg.get("/v2/")
    assert set(lis.hits) == {"127.0.0.2"} and calls == ["srv.internal", "reg.internal"]


def test_an_open_http_client_applies_a_never_scan_change(lis, dns):
    table, _ = dns
    table["reg.internal"] = ["127.0.0.2"]
    ctx = _ctx([])
    reg = CI.Registry(ctx, CI.parse_ref(f"reg.internal:{lis.port}/app:1"), {}, None)
    with pytest.raises(CI.ImageError) as err:
        reg.get("/v2/")
    assert err.value.status != "skipped_never_scan"
    ctx.never_scan.update(["127.0.0.2"])  # listed while the pull runs: the client that is already open stops
    with pytest.raises(CI.ImageError) as err:
        reg.get("/v2/")
    assert err.value.status == "skipped_never_scan" and "127.0.0.2" in err.value.detail
    assert lis.hits == ["127.0.0.2"]


@pytest.fixture()
def tls_lab(tmp_path):
    lab = registry_lab.Lab(tmp_path)  # a TLS server on 127.0.0.1 whose certificate names localhost and 127.0.0.1
    yield lab
    lab.close()


def test_the_pinned_requests_adapter_checks_the_certificate_by_name_and_never_resolves(tls_lab, dns, tmp_path):
    import requests

    lab = tls_lab
    ca = tmp_path / "ca.pem"
    ca.write_text(lab.ca_pem)
    table, calls = dns
    table["localhost"] = ["127.0.0.3"]  # if the client resolved the name it would go to the wrong address
    table["reg.internal"] = ["127.0.0.3"]
    port = lab.registry.server_port
    never = NeverScan()
    pinned = requests.Session()
    pinned.mount("https://", netutil.requests_adapter("localhost", "127.0.0.1", never))
    assert pinned.get(f"https://localhost:{port}/v2/", verify=str(ca), timeout=5).status_code < 500
    wrong_name = requests.Session()
    wrong_name.mount("https://", netutil.requests_adapter("reg.internal", "127.0.0.1", never))
    with pytest.raises(requests.exceptions.SSLError):  # the certificate does not name reg.internal
        wrong_name.get(f"https://reg.internal:{port}/v2/", verify=str(ca), timeout=5)
    with pytest.raises(requests.exceptions.ConnectionError, match="not localhost"):  # only the checked host
        pinned.get(f"https://127.0.0.1:{port}/v2/", verify=str(ca), timeout=5)
    never.update(["127.0.0.1"])  # listed while the session is open
    with pytest.raises(Blocked):
        pinned.get(f"https://localhost:{port}/v2/", verify=str(ca), timeout=5)
    assert calls == []  # requests never looked a name up


# ----------------------------------------------------------------------------- the unspecified address
def test_the_unspecified_address_never_reaches_the_node_itself(lis, dns):
    table, _ = dns
    table["sinkholed.internal"] = ["0.0.0.0"]  # what DNS sinkholes answer
    for never in ([], ["127.0.0.1"]):
        with pytest.raises(Blocked, match="unspecified"):
            netutil.connect("0.0.0.0", lis.port, NeverScan(never), 2)
        ctx = _ctx(never)
        assert L._targets(ctx, {"targets": ["sinkholed.internal", "0.0.0.0"]}) == []
        assert [(o.status, "unspecified" in (o.error or "")) for o in ctx.outcomes] == [
            ("skipped_never_scan", True)] * 2
    assert lis.hits == []


# ----------------------------------------------------------------------------- a host listed by its name
def test_a_host_listed_by_name_is_not_contacted_by_alias_address_range_or_sni(lis, dns):
    table, _ = dns
    table["db.corp.internal"] = ["127.0.0.2"]
    table["db"] = ["127.0.0.2"]  # the short name of the same host (resolver search domain)
    table["alias.internal"] = ["127.0.0.2"]  # a CNAME to it
    ctx = _ctx(["db.corp.internal"])
    assert L._targets(ctx, {"targets": ["db", "alias.internal", "127.0.0.2"]}) == []
    assert [o.status for o in ctx.outcomes] == ["skipped_never_scan"] * 3
    assert "db.corp.internal" in ctx.outcomes[0].error
    assert N._sni_for({"sni_hostnames": ["db.corp.internal", "db"]}, "127.0.0.1", {}, ctx.never_scan) == []
    sweep = _ctx(["db.corp.internal"])
    sweep.source_kind = "network_range"
    N.run_network(sweep, {"ranges": ["127.0.0.0/30"], "ports": [{"port": lis.port, "protocol": "tls"}],
                          "rate_limits": {"connections_per_second": 1000, "parallel_per_server": 2}},
                  discovery_only=True)
    assert [o.target for o in sweep.outcomes if o.status == "skipped_never_scan"] == ["127.0.0.2"]
    assert "127.0.0.2" not in lis.hits and "127.0.0.1" in lis.hits  # the sweep ran; it skipped the listed host
