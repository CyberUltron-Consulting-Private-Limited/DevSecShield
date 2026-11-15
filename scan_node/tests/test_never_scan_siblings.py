"""Issue #17, the part a per-name check misses: an address the job KNOWS belongs to a never-scan host.

A name the job resolves (a server target name, a registry or redirect host, a team SNI hostname) ties its addresses
together: ``db.internal`` -> 10.0.0.5 and fd00::5 is one host.  When 10.0.0.5 is listed, the name is skipped, and so
is fd00::5 wherever else it appears in the same job: as an IP target, inside a CIDR or ``a-b`` range, in a network
range sweep.  The reason names the host and the listed address.  Order does not matter (the names are resolved before
any target is checked), the rule follows the list while the job runs, and a name that is not excluded ties nothing.

The limit, kept as a test so it stays documented: a range carries no names.  An IPv6 address of a host listed only by
its IPv4 address cannot be recognised unless some name the job resolves answers both; list the host by name (or both
addresses) to cover it.
"""
from __future__ import annotations

import socket
import time

import pytest
from zs_scan_node import netutil
from zs_scan_node import tlsprobe as T
from zs_scan_node.collectors import linux_ssh as L
from zs_scan_node.collectors import network as N
from zs_scan_node.jobctx import JobContext
from zs_scan_node.netutil import Blocked, NeverScan, expand_targets, resolve_checked
from zs_scan_node.scrub import Scrubber

DNS = {
    "db.internal": ["10.0.0.5", "fd00::5"],  # dual stack: one host
    "only6.internal": ["fd00::5"],  # another name of the same host, IPv6 only
    "web.internal": ["10.0.0.8", "fd00::8"],  # dual stack, not listed
    "listed.internal": ["10.0.0.9"],  # what the node-wide resolver answers for a listed name
}
WHY_DB = "an address of db.internal, which also resolves to 10.0.0.5, on the never-scan list"


def _ctx(never: list[str] | None = None, source_kind: str | None = None) -> JobContext:
    return JobContext(job_id=1, attempt=1, run_id=None, kind="collect", source_kind=source_kind, scrubber=Scrubber(),
                      never_scan=NeverScan(never or []), deadline=time.monotonic() + 600)


@pytest.fixture()
def dns(monkeypatch):
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


# ----------------------------------------------------------------------------- server targets (SSH, WinRM, appliances)
@pytest.mark.parametrize("lines", [
    ["db.internal", "fd00::4/126"],  # the name first
    ["fd00::4/126", "db.internal"],  # the range first: names are resolved before any target is checked
    ["fd00::4-fd00::7", "db.internal"],
])
def test_a_range_address_of_an_excluded_name_is_skipped(dns, lines):
    never = NeverScan(["10.0.0.5"])
    reasons: dict[str, str] = {}
    targets, skipped = expand_targets(lines, never, reasons=reasons)
    assert sorted(t.ip for t in targets) == ["fd00::4", "fd00::6", "fd00::7"]
    assert sorted(skipped) == ["db.internal", "fd00::5"]
    assert reasons["fd00::5"] == f"fd00::5 is {WHY_DB}"
    assert reasons["db.internal"] == "db.internal resolves to 10.0.0.5, which is on the never-scan list"


def test_an_ip_target_of_an_excluded_name_is_skipped_with_the_reason(dns):
    ctx = _ctx(["10.0.0.0/24"])
    assert L._targets(ctx, {"targets": ["fd00::5", "db.internal", "fd00::8"]}) != []
    got = {o.target: (o.status, o.error) for o in ctx.outcomes}
    assert got["fd00::5"] == ("skipped_never_scan", f"fd00::5 is {WHY_DB} (10.0.0.0/24)")
    assert got["db.internal"][0] == "skipped_never_scan"
    assert "fd00::8" not in got  # not tied to any excluded name: scanned


def test_another_name_of_the_same_host_is_skipped_whatever_the_order(dns):
    for lines in (["only6.internal", "db.internal"], ["db.internal", "only6.internal"]):
        never = NeverScan(["10.0.0.5"])
        reasons: dict[str, str] = {}
        assert expand_targets(lines, never, reasons=reasons) == ([], lines)
        assert reasons["only6.internal"] == f"only6.internal resolves to fd00::5, {WHY_DB}"


def test_a_name_that_is_not_excluded_ties_nothing(dns):
    never = NeverScan(["10.0.0.5"])
    targets, skipped = expand_targets(["web.internal", "fd00::8"], never)
    assert [t.label for t in targets] == ["web.internal", "fd00::8"]
    assert skipped == []
    assert never.match_ip("fd00::8") is None


def test_an_excluded_redirect_host_ties_its_addresses_for_the_rest_of_the_job(dns):
    never = NeverScan(["10.0.0.5"])
    with pytest.raises(Blocked):
        resolve_checked("db.internal", never)  # a registry, token service or blob redirect host
    with pytest.raises(Blocked, match="an address of db.internal"):
        resolve_checked("fd00::5", never)  # the same host by its other address


# ----------------------------------------------------------------------------- the list changes while a job runs
def test_the_tie_follows_the_list_while_the_job_runs(dns):
    never = NeverScan([])
    assert resolve_checked("db.internal", never) == ["10.0.0.5", "fd00::5"]
    assert never.match_ip("fd00::5") is None
    never.update(["10.0.0.5"])  # a heartbeat adds the IPv4 address: the IPv6 address is that host too
    assert never.match_ip("fd00::5") == WHY_DB
    never.update([])  # and taken off again: nothing is tied any more
    assert never.match_ip("fd00::5") is None


def test_a_learned_name_that_is_itself_listed_ties_every_address_it_answered(dns):
    never = NeverScan(["listed.internal"])
    never.learn("listed.internal", ["10.0.0.7", "fd00::7"])  # e.g. the SNI lookup saw a different answer
    assert never.match_ip("fd00::7") == "an address of listed.internal, which is on the never-scan list"


def test_held_name_reporting_is_unchanged_by_a_tie(dns):
    """#298: ``names_checked`` / ``held_by`` move only when an address reached the listed names' check."""
    never = NeverScan(["10.0.0.5", "never-answers.internal"])
    never._hold_until.clear()  # no wait for the unresolved name's lookup in this test
    never._index()
    never.learn("db.internal", ["10.0.0.5", "fd00::5"])
    assert never.match_ip("fd00::5") == WHY_DB  # a definite match wins over "held"
    assert never.names_checked is False and never.held_names() == []
    assert never.match_ip("fd00::8").names == ("never-answers.internal",)  # an untied address is held as before
    assert never.names_checked is True and never.held_names() == ["never-answers.internal"]


# ----------------------------------------------------------------------------- network range sweeps (SNI names)
def _sweep(monkeypatch, never, scope_extra, discovery_only=True):
    contacted: set[str] = set()

    def tcp(ip, port, never_, timeout):
        contacted.add(ip)
        raise T.ProbeError("refused", "connection refused")

    monkeypatch.setattr(N, "_tcp", tcp)
    ctx = _ctx(never, source_kind="network_range")
    N.run_network(ctx, {"ranges": ["fd00::4/126"], "ports": [{"port": 443, "protocol": "tls"}],
                        "rate_limits": {"connections_per_second": 1000, "parallel_per_server": 2}, **scope_extra},
                  discovery_only=discovery_only)
    return ctx, contacted


@pytest.mark.parametrize("discovery_only", [True, False])
def test_a_range_sweep_skips_the_ipv6_address_of_an_sni_host_listed_by_ipv4(dns, monkeypatch, discovery_only):
    ctx, contacted = _sweep(monkeypatch, ["10.0.0.5"], {"sni_hostnames": ["db.internal", "web.internal"]},
                            discovery_only)
    assert contacted == {"fd00::4", "fd00::6", "fd00::7"}
    skips = [(o.target, o.error) for o in ctx.outcomes if o.status == "skipped_never_scan"]
    assert skips == [("fd00::5", f"fd00::5 is {WHY_DB}")]


def test_a_range_connection_test_does_not_sample_a_tied_address(dns, monkeypatch):
    probed: list[str] = []

    def tcp(ip, port, never_, timeout):
        probed.append(ip)
        raise T.ProbeError("refused", "connection refused")

    monkeypatch.setattr(N, "_tcp", tcp)
    ctx = _ctx(["10.0.0.5"], source_kind="network_range")
    N.test_range(ctx, {"ranges": ["fd00::5/128"], "sni_hostnames": ["db.internal"],
                       "ports": [{"port": 443, "protocol": "tls"}]})
    assert probed == []


def test_the_limit_an_untied_ipv6_address_of_a_host_listed_by_ipv4_is_scanned(dns, monkeypatch):
    """Documented limit (scan_node/README.md, Never-scan rule): without a name the job resolves, the node cannot know
    that fd00::5 is the host listed as 10.0.0.5."""
    contacted = _sweep(monkeypatch, ["10.0.0.5"], {})[1]
    assert "fd00::5" in contacted
    assert expand_targets(["fd00::5"], NeverScan(["10.0.0.5"]))[1] == []
