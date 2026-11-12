"""Issue #17: the never-scan list applies to the whole name.

* A name is skipped as ``skipped_never_scan`` when the name is listed or when ANY address it resolves to is listed
  (a dual-stack host excluded by its IPv4 address is not scanned over IPv6, and the other way round).  This holds
  for every name a collector connects to: servers, the registry, its token service, blob redirects, database
  redirects.
* An IP literal is checked as itself.  CIDR and ``a-b`` ranges stay per address: only the listed addresses inside
  a range are skipped.
* The list can change while a job runs: the re-check before connecting covers every address the name resolved to.
"""
from __future__ import annotations

import socket
import time

import pytest

from zs_scan_node import drivergate, netutil
from zs_scan_node.collectors import container_images as CI
from zs_scan_node.collectors import linux_ssh as L
from zs_scan_node.collectors import network as N
from zs_scan_node import tlsprobe as T
from zs_scan_node.jobctx import JobContext
from zs_scan_node.netutil import Blocked, NeverScan, Target, expand_targets, resolve_checked
from zs_scan_node.scrub import Scrubber

DNS = {
    "db.internal": ["10.0.0.5", "fd00::5"],  # dual stack
    "v6first.internal": ["fd00::5", "10.0.0.5"],  # the same host, the resolver answering IPv6 first
    "mapped.internal": ["::ffff:10.0.0.5"],  # an IPv4-mapped IPv6 answer
    "registry.example.com": ["203.0.113.11", "2001:db8::11"],
    "auth.example.com": ["203.0.113.12", "2001:db8::12"],
    "cdn.example.com": ["203.0.113.20", "2001:db8::20"],
    "nothing.internal": [],
}


def _ctx(never: list[str] | None = None, source_kind: str | None = None) -> JobContext:
    return JobContext(job_id=1, attempt=1, run_id=None, kind="collect", source_kind=source_kind, scrubber=Scrubber(),
                      never_scan=NeverScan(never or []), deadline=time.monotonic() + 600)


@pytest.fixture()
def dns(monkeypatch):
    """netutil.resolve answers from DNS (in the resolver's order); every lookup is recorded.  A test may add names
    to DNS; they are removed again afterwards."""
    looked_up: list[str] = []
    saved = dict(DNS)

    def resolve(name, timeout=5.0):
        looked_up.append(name)
        if name not in DNS:
            raise socket.gaierror(socket.EAI_NONAME, "unknown name")
        return list(DNS[name])

    monkeypatch.setattr(netutil, "resolve", resolve)
    yield looked_up
    DNS.clear()
    DNS.update(saved)


# ----------------------------------------------------------------------------- the rule for names
@pytest.mark.parametrize("name", ["db.internal", "v6first.internal"])
def test_name_with_excluded_ipv4_and_allowed_ipv6_is_skipped(dns, name):
    never = NeverScan(["10.0.0.5"])
    with pytest.raises(Blocked) as err:
        resolve_checked(name, never)
    assert err.value.status == "skipped_never_scan"
    assert str(err.value) == f"{name} resolves to 10.0.0.5, which is on the never-scan list"
    targets, skipped = expand_targets([name], never)  # Linux SSH, appliance and WinRM targets
    assert targets == [] and skipped == [name]


@pytest.mark.parametrize("listed", ["fd00::5", "fd00::/64", "FD00::5"])
def test_name_with_excluded_ipv6_only_is_skipped(dns, listed):
    never = NeverScan([listed])
    with pytest.raises(Blocked) as err:
        resolve_checked("db.internal", never)
    assert "fd00::5" in str(err.value)
    assert expand_targets(["db.internal"], never) == ([], ["db.internal"])


def test_an_ipv4_mapped_answer_matches_the_listed_ipv4_address(dns):
    with pytest.raises(Blocked):
        resolve_checked("mapped.internal", NeverScan(["10.0.0.0/24"]))


def test_name_without_excluded_address_is_scanned(dns):
    never = NeverScan(["10.0.0.6", "fd00::6", "other.internal"])
    assert resolve_checked("db.internal", never) == ["10.0.0.5", "fd00::5"]
    targets, skipped = expand_targets(["db.internal"], never)
    assert skipped == []
    assert targets == [Target("db.internal", "10.0.0.5", addresses=("10.0.0.5", "fd00::5"))]


def test_a_listed_name_is_skipped_without_a_lookup(dns):
    never = NeverScan(["db.internal"])
    assert dns == ["db.internal"]  # the list's own names are looked up once, when the list is set
    with pytest.raises(Blocked) as err:
        resolve_checked("DB.Internal.", never)
    assert str(err.value) == "db.internal is on the never-scan list" and dns == ["db.internal"]  # no target lookup


def test_a_name_with_no_address_is_unreachable_not_never_scan(dns):
    with pytest.raises(OSError) as err:
        resolve_checked("nothing.internal", NeverScan())
    assert not isinstance(err.value, Blocked)
    targets, skipped = expand_targets(["nothing.internal", "gone.internal"], NeverScan())
    assert skipped == [] and [(t.label, t.ip) for t in targets] == [("nothing.internal", None), ("gone.internal", None)]
    assert all(t.error and t.error.startswith(f"could not resolve {t.label}") for t in targets)


# ----------------------------------------------------------------------------- IP literals and ranges: per address
def test_ip_literals_are_checked_as_themselves(dns):
    never = NeverScan(["10.0.0.5"])
    assert resolve_checked("fd00::5", never) == ["fd00::5"]  # the other address of a listed host, written as an IP
    assert resolve_checked("[fd00::5]", never) == ["fd00::5"]
    with pytest.raises(Blocked):
        resolve_checked("10.0.0.5", never)
    assert dns == []  # no lookup for an address


def test_ranges_keep_per_address_skipping(dns):
    never = NeverScan(["10.0.0.3", "2001:db8::2", "10.0.1.5-10.0.1.6", "2001:db8::a-2001:db8::b"])
    targets, skipped = expand_targets(["10.0.0.0/29", "2001:db8::/126", "10.0.1.4-10.0.1.7", "10.0.0.3",
                                       "2001:db8::8/125"], never)
    assert [t.ip for t in targets] == ["10.0.0.1", "10.0.0.2", "10.0.0.4", "10.0.0.5", "10.0.0.6",
                                       "2001:db8::", "2001:db8::1", "2001:db8::3", "10.0.1.4", "10.0.1.7",
                                       "2001:db8::8", "2001:db8::9", "2001:db8::c", "2001:db8::d", "2001:db8::e",
                                       "2001:db8::f"]
    assert skipped == ["10.0.0.3", "2001:db8::2", "10.0.1.5", "10.0.1.6", "2001:db8::a", "2001:db8::b"]
    assert all(t.addresses == () for t in targets)  # an address target is only itself
    DNS["in-v6-range.internal"] = ["10.9.9.9", "2001:db8::b"]  # a name whose IPv6 answer is inside the IPv6 a-b entry
    with pytest.raises(Blocked, match="2001:db8::b"):
        resolve_checked("in-v6-range.internal", never)


@pytest.mark.parametrize("entry, inside, outside", [
    ("fd00::1-fd00::5", "fd00::3", "fd00::6"),  # IPv6 a-b: the node used to store it as a host name
    ("fd00::a-fd00::f", "fd00::c", "fd00::10"),  # first address ending in a hex letter
    ("FD00::A - FD00::F", "fd00::f", "fd00::9"),
    ("10.0.0.250-10.0.1.5", "10.0.1.0", "10.0.1.6"),
    ("::ffff:10.0.0.1-::ffff:10.0.0.3", "10.0.0.2", "10.0.0.4"),  # IPv4-mapped entries are their IPv4 addresses
    ("::ffff:10.0.0.5", "10.0.0.5", "10.0.0.6"),
    ("::ffff:10.0.0.0/120", "10.0.0.77", "10.0.1.1"),
    ("10.0.0.5", "64:ff9b::a00:5", "64:ff9b::a00:6"),  # a NAT64 answer reaches its embedded IPv4 address
    ("64:ff9b::/96", "64:ff9b::a00:5", "10.0.0.5"),
    ("10.0.0.9-10.0.0.7", "10.0.0.8", "10.0.0.10"),  # a reversed range (the backend refuses it) never fails open
    ("fe80::1", "fe80::1%eth0", "fe80::2%eth0"),  # an answer's zone names the interface, not another host
])
def test_never_scan_entries_of_every_form_apply_on_the_node(entry, inside, outside):
    never = NeverScan([entry])
    assert never.blocks_ip(inside) and not never.blocks_ip(outside)
    if "." in inside:
        assert never.blocks_ip(f"::ffff:{inside}")  # and its IPv4-mapped form


def test_host_names_with_dashes_stay_host_entries(dns):
    never = NeverScan(["web-01.corp", "a-b", "10.0.0.1-foo"])
    assert all(never.blocks_host(n) for n in ("web-01.corp", "a-b", "10.0.0.1-foo"))
    assert not never.blocks_ip("10.0.0.1")


@pytest.mark.parametrize("address", ["0.0.0.0", "0.1.2.3", "::", "::ffff:0.0.0.0", "64:ff9b::"])
def test_unspecified_addresses_are_never_scanned_whatever_the_list_says(dns, address):
    with pytest.raises(Blocked, match="unspecified address"):
        netutil.checked_ip(address, NeverScan())
    DNS["sinkholed.internal"] = [address]  # what a DNS sinkhole answers
    with pytest.raises(Blocked) as err:
        resolve_checked("sinkholed.internal", NeverScan())
    assert str(err.value) == (f"sinkholed.internal resolves to {address}, which is an unspecified address "
                              "(0.0.0.0/8 or ::) and is never scanned")


# ----------------------------------------------------------------------------- never-scan entries written as names
def test_a_listed_name_covers_every_address_it_resolves_to(dns):
    DNS.update({"db.corp.internal": ["10.0.0.5", "fd00::5"], "db": ["10.0.0.5"], "alias.internal": ["fd00::5"]})
    never = NeverScan(["db.corp.internal"])
    assert never.blocks_ip("10.0.0.5") and never.blocks_ip("fd00::5") and never.unresolved == []
    assert never.blocks_ip("fd00::5%eth0") and never.blocks_ip("::ffff:10.0.0.5")
    with pytest.raises(Blocked) as err:
        resolve_checked("db", never)  # the short name of the same host
    assert str(err.value) == ("db resolves to 10.0.0.5, which is on the never-scan list "
                              "(an address of db.corp.internal)")
    with pytest.raises(Blocked):
        resolve_checked("alias.internal", never)  # a CNAME to it
    reasons: dict[str, str] = {}
    targets, skipped = expand_targets(["10.0.0.4/30", "fd00::5"], never, reasons=reasons)
    assert [t.ip for t in targets] == ["10.0.0.6"] and skipped == ["10.0.0.5", "fd00::5"]
    assert reasons["10.0.0.5"] == "10.0.0.5 is on the never-scan list (an address of db.corp.internal)"


def test_listed_names_are_looked_up_again_when_the_list_changes(dns):
    DNS["moving.internal"] = ["10.0.0.5"]
    never = NeverScan(["moving.internal"])
    DNS["moving.internal"] = ["10.0.0.9"]
    never.update(["moving.internal", "10.1.0.0/16"])  # a heartbeat brings a changed list
    assert never.blocks_ip("10.0.0.9") and never.blocks_ip("10.0.0.5")  # never narrower within the job
    never.update(["10.1.0.0/16"])  # the name was taken off the list
    assert not never.blocks_ip("10.0.0.9") and not never.blocks_ip("10.0.0.5")


def test_an_unresolved_listed_name_is_reported_and_retried(dns, monkeypatch):
    monkeypatch.setattr(netutil, "NAME_RETRY_S", 0.3)
    never = NeverScan(["later.internal", "10.1.0.0/16"])
    assert never.unresolved == ["later.internal"] and never.blocks_host("later.internal")
    DNS["later.internal"] = ["10.0.0.8"]
    never.refresh()  # not due yet: a failed lookup is retried after NAME_RETRY_S
    assert not never.blocks_ip("10.0.0.8") and dns.count("later.internal") == 1
    time.sleep(0.35)
    never.refresh()  # the job's watcher calls this on every pass
    assert never.blocks_ip("10.0.0.8") and never.unresolved == []


def test_looking_up_the_listed_names_is_bounded(monkeypatch):
    def slow(name, timeout=5.0):
        time.sleep(2)
        return ["10.0.0.5"]

    monkeypatch.setattr(netutil, "resolve", slow)
    monkeypatch.setattr(netutil, "NAME_LOOKUP_S", 0.2)
    started = time.monotonic()
    never = NeverScan(["slow.internal"])
    assert time.monotonic() - started < 1.5 and never.unresolved == ["slow.internal"]


def test_sni_names_that_are_listed_or_have_a_listed_address_are_not_sent(dns):
    never = NeverScan(["listed.internal", "fd00::7"])  # listed.internal does not resolve yet when the list is set
    DNS.update({"listed.internal": ["10.0.0.8"], "web.internal": ["10.0.0.8"],
                "dual.internal": ["10.0.0.8", "fd00::7"]})
    scope = {"sni_hostnames": ["listed.internal", "web.internal", "dual.internal"]}
    assert N._sni_for(scope, "10.0.0.8", {}, never) == ["web.internal"]


def test_network_range_sweep_skips_only_the_listed_addresses(monkeypatch):
    contacted: set[str] = set()

    def tcp(ip, port, never, timeout):
        contacted.add(ip)
        raise T.ProbeError("refused", "connection refused")

    monkeypatch.setattr(N, "_tcp", tcp)
    ctx = _ctx(["192.0.2.3", "2001:db8::2"], source_kind="network_range")
    N.run_network(ctx, {"ranges": ["192.0.2.0/29", "2001:db8::/126"], "ports": [{"port": 443, "protocol": "tls"}],
                        "rate_limits": {"connections_per_second": 1000, "parallel_per_server": 2}},
                  discovery_only=True)
    skipped = sorted(o.target for o in ctx.outcomes if o.status == "skipped_never_scan")
    assert skipped == ["192.0.2.3", "2001:db8::2"]
    assert contacted == {"192.0.2.1", "192.0.2.2", "192.0.2.4", "192.0.2.5", "192.0.2.6",
                         "2001:db8::", "2001:db8::1", "2001:db8::3"}


def test_a_skipped_server_name_says_which_address_matched(dns):
    from zs_scan_node.collectors import windows_winrm as W

    want = [("db.internal", "skipped_never_scan", "db.internal resolves to fd00::5, which is on the never-scan list"),
            ("fd00::5", "skipped_never_scan", "fd00::5 is on the never-scan list")]
    ctx = _ctx(["fd00::/64"])
    assert L._targets(ctx, {"targets": ["db.internal", "fd00::5"]}) == []  # Linux SSH and appliances
    assert [(o.target, o.status, o.error) for o in ctx.outcomes] == [(t, s, e + " (fd00::/64)") for t, s, e in want]
    ctx = _ctx(["fd00::5"])
    W.collect(ctx, {}, {"password": "unused"}, {"targets": ["db.internal", "fd00::5"]})
    assert [(o.target, o.status, o.error) for o in ctx.outcomes] == want


def test_connection_tests_show_skipped_names_as_samples(dns):
    from zs_scan_node.collectors import appliance as A
    from zs_scan_node.collectors import windows_winrm as W

    scope = {"targets": ["db.internal"]}
    why = "db.internal resolves to fd00::5, which is on the never-scan list"
    want = [("db.internal", "skipped_never_scan", None, why)]
    password = {"credential_type": "password"}
    for run in (lambda ctx: W.test(ctx, {}, {"password": "pw"}, scope),
                lambda ctx: L.test(ctx, password, {"password": "pw"}, scope),
                lambda ctx: A.test(ctx, {"vendor": "fortios", **password}, {"password": "pw"}, scope)):
        ctx = _ctx(["fd00::5"])
        run(ctx)
        assert [(s["target"], s["status"], s["reachable"], s["note"]) for s in ctx.samples] == want
        assert [(o.target, o.status) for o in ctx.outcomes] == [("db.internal", "skipped_never_scan")]


# ----------------------------------------------------------------------------- the list changes while a job runs
def test_ssh_recheck_covers_every_address_of_a_name(dns, monkeypatch):
    connected: list[str] = []

    def connect(ip, port, never, timeout):
        connected.append(ip)
        raise ConnectionRefusedError()

    monkeypatch.setattr(netutil, "connect", connect)
    ctx = _ctx()
    [target], _ = expand_targets(["db.internal"], ctx.never_scan)
    assert target.ip == "10.0.0.5"
    ctx.never_scan.update(["fd00::5"])  # the other address is listed after the job started
    with pytest.raises(L.TargetFail) as err:
        L.open_session(ctx, target, {"port": 22}, {"key": "unused"})
    assert err.value.status == "skipped_never_scan" and "fd00::5" in err.value.error
    ctx.never_scan.update(["db.internal"])  # ... or the name itself
    with pytest.raises(L.TargetFail) as err:
        L.open_session(ctx, target, {"port": 22}, {"key": "unused"})
    assert err.value.status == "skipped_never_scan"
    assert connected == []
    # an address target is only itself: listing another address of its host (not its name) does not skip it
    ctx.never_scan.update(["fd00::5"])
    with pytest.raises(L.TargetFail) as err:
        L.open_session(ctx, Target("10.0.0.5", "10.0.0.5"), {"port": 22}, {"key": "unused"})
    assert err.value.status == "refused" and connected == ["10.0.0.5"]


# ----------------------------------------------------------------------------- registry, token service, redirects
class _Client:
    """An HTTP client pinned by netutil.http_client; blob requests are redirected to ``redirect_to``."""

    made: list[tuple[str, str]] = []
    redirect_to: str | None = None

    def __init__(self, url, ip):
        self.url, self.ip = url, ip
        _Client.made.append((url, ip))

    def build_request(self, method, path, headers=None):
        return path

    def send(self, path, stream=False):
        if _Client.redirect_to and "/blobs/" in path:
            return type("R", (), {"status_code": 307, "headers": {"location": _Client.redirect_to},
                                  "close": lambda self: None})()
        return type("R", (), {"status_code": 200, "headers": {}, "close": lambda self: None})()

    def close(self):
        pass


@pytest.fixture()
def registry_net(dns, monkeypatch):
    _Client.made, _Client.redirect_to = [], None
    monkeypatch.setattr(netutil, "http_client", lambda url, ip, never, **kw: _Client(url, ip))
    return _Client


@pytest.mark.parametrize("listed", ["203.0.113.11", "2001:db8::11"])
def test_a_registry_with_one_listed_address_is_skipped(registry_net, listed):
    reg = CI.Registry(_ctx([listed]), CI.parse_ref("registry.example.com/app:1"), {}, None)
    with pytest.raises(CI.ImageError) as err:
        reg.get("/v2/app/manifests/1")
    assert err.value.status == "skipped_never_scan" and listed in err.value.detail
    assert registry_net.made == []


@pytest.mark.parametrize("listed", ["203.0.113.12", "2001:db8::12"])
def test_a_token_service_with_one_listed_address_is_skipped(registry_net, listed):
    reg = CI.Registry(_ctx([listed]), CI.parse_ref("registry.example.com/app:1"), {}, None)
    reg._client(reg.base + "/v2/")  # the registry is contacted first, as fetch_manifest does
    with pytest.raises(CI.ImageError) as err:
        reg._authenticate('Bearer realm="https://auth.example.com/token"')
    assert err.value.status == "skipped_never_scan" and listed in err.value.detail
    assert [url for url, _ip in registry_net.made] == ["https://registry.example.com:443"]


@pytest.mark.parametrize("listed", ["203.0.113.20", "2001:db8::20"])
def test_a_redirect_target_with_one_listed_address_is_skipped(registry_net, listed):
    reg = CI.Registry(_ctx([listed]), CI.parse_ref("registry.example.com/app:1"), {}, None)
    registry_net.redirect_to = "https://cdn.example.com/blob/abc"
    with pytest.raises(CI.ImageError) as err:
        reg.get("/v2/app/blobs/sha256:" + "a" * 64, stream=True)
    assert err.value.status == "skipped_never_scan" and "cdn.example.com" in err.value.detail
    assert [url for url, _ip in registry_net.made] == ["https://registry.example.com:443"]  # the CDN: never


def test_a_redirect_target_without_a_listed_address_is_followed(registry_net):
    reg = CI.Registry(_ctx(["203.0.113.21"]), CI.parse_ref("registry.example.com/app:1"), {}, None)
    registry_net.redirect_to = "https://cdn.example.com/blob/abc"
    assert reg.get("/v2/app/blobs/sha256:" + "a" * 64, stream=True).status_code == 200
    assert registry_net.made == [("https://registry.example.com:443", "203.0.113.11"),
                                 ("https://cdn.example.com:443", "203.0.113.20")]


def test_a_database_redirect_to_a_name_with_one_listed_address_is_refused(dns):
    """SQL Server routing / Oracle REDIRECT: the driver looks the new name up through the gate."""
    with drivergate.scope(NeverScan(["fd00::5"]), {"primary.internal": "10.0.0.9"}):
        assert drivergate.getaddrinfo("primary.internal", 1433)[0][4] == ("10.0.0.9", 1433)
        with pytest.raises(Blocked):
            drivergate.getaddrinfo("db.internal", 1433)
        with pytest.raises(Blocked):
            drivergate.create_connection(("db.internal", 1433), timeout=1)


def test_a_database_name_is_rechecked_by_every_address_before_each_connection(dns, monkeypatch):
    from zs_scan_node.collectors import database as D

    DNS["dbx.internal"] = ["127.0.0.9", "fd00::5"]
    ctx = _ctx()

    def tls_offered(ip, port, engine, never):  # the other address is listed after the name was resolved
        ctx.never_scan.update(["fd00::5"])
        return True, {}

    monkeypatch.setattr(D, "_tls_offered", tls_offered)
    target, status, why, _n = D._one(ctx, {"engine": "postgres", "host": "dbx.internal", "port": 1}, {})
    assert target.addresses == ("127.0.0.9", "fd00::5")
    assert status == "skipped_never_scan" and why == "dbx.internal resolves to fd00::5, which is on the never-scan list"


def test_kubernetes_outcome_and_sample_name_the_matched_address(dns, monkeypatch, tmp_path):
    from zs_scan_node.collectors import kubernetes as K

    real = K.Api

    def api_for(ctx):
        api = real.__new__(real)
        api.ctx, api.api_url, api.host, api.port = ctx, "https://db.internal:6443", "db.internal", 6443
        api.client, api._tmp = None, str(tmp_path)
        return api

    monkeypatch.setattr(K, "Api", lambda ctx, config, secrets: api_for(ctx))
    why = "db.internal resolves to fd00::5, which is on the never-scan list"
    ctx = _ctx(["fd00::5"])
    assert K.collect(ctx, {}, {}, {}) == why  # the job summary too, not "the API server is on the list"
    assert [(o.status, o.error) for o in ctx.outcomes] == [("skipped_never_scan", why)]
    ctx = _ctx(["fd00::5"])
    K.test(ctx, {"api_url": "https://db.internal:6443"}, {}, {})
    assert [(s["status"], s["note"]) for s in ctx.samples] == [("skipped_never_scan", why)]
