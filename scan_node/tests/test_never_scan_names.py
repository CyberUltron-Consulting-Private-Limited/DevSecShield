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
    """netutil.resolve answers from DNS (in the resolver's order); every lookup is recorded."""
    looked_up: list[str] = []

    def resolve(name, timeout=5.0):
        looked_up.append(name)
        if name not in DNS:
            raise socket.gaierror(socket.EAI_NONAME, "unknown name")
        return list(DNS[name])

    monkeypatch.setattr(netutil, "resolve", resolve)
    return looked_up


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
    with pytest.raises(Blocked) as err:
        resolve_checked("DB.Internal.", NeverScan(["db.internal"]))
    assert str(err.value) == "db.internal is on the never-scan list" and dns == []


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


def test_ranges_keep_per_address_skipping():
    never = NeverScan(["10.0.0.3", "2001:db8::2", "10.0.1.5-10.0.1.6"])
    targets, skipped = expand_targets(["10.0.0.0/29", "2001:db8::/126", "10.0.1.4-10.0.1.7", "10.0.0.3"], never)
    assert [t.ip for t in targets] == ["10.0.0.1", "10.0.0.2", "10.0.0.4", "10.0.0.5", "10.0.0.6",
                                       "2001:db8::", "2001:db8::1", "2001:db8::3", "10.0.1.4", "10.0.1.7"]
    assert skipped == ["10.0.0.3", "2001:db8::2", "10.0.1.5", "10.0.1.6"]
    assert all(t.addresses == () for t in targets)  # an address target is only itself


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
            ("fd00::5", "skipped_never_scan", None)]  # an address line: its own row, as before
    ctx = _ctx(["fd00::5"])
    assert L._targets(ctx, {"targets": ["db.internal", "fd00::5"]}) == []  # Linux SSH and appliances
    assert [(o.target, o.status, o.error) for o in ctx.outcomes] == want
    ctx = _ctx(["fd00::5"])
    W.collect(ctx, {}, {"password": "unused"}, {"targets": ["db.internal", "fd00::5"]})
    assert [(o.target, o.status, o.error) for o in ctx.outcomes] == want


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
    # an address target is only itself: listing another address of its host does not skip it
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
