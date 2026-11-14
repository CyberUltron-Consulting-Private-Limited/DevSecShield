"""The never-scan list as the backend counts it and as the scan node applies it must agree (PR #32 security review).

The backend parses each entry (``targets.parse_exclusions``), counts what is left of a source for estimates and
credits, and sends ``exclusions.normalized`` to the node.  The node's ``NeverScan`` must block exactly the addresses
the backend subtracted, for every entry form: single addresses, CIDRs, IPv4 and IPv6 ``a-b`` ranges (including
ones whose first address ends in a hex letter) and IPv4-mapped forms.  Host-name entries are matched by the node
only (the backend cannot resolve names on the customer's network).

The same holds for the targets: what the backend counts (estimates, credits) and offers as connection-test samples
is exactly what the node's ``expand_targets`` scans for every address target form, including the addresses the
node never scans whatever the list says (network and broadcast addresses of an IPv4 /30 or larger, 0.0.0.0/8, ::,
and the NAT64 form of an excluded IPv4 address).  Host-name targets are counted once each: the node may scan fewer
(two names of one host, or a name with a listed address), never more.
"""
from __future__ import annotations

import ipaddress
import json
import re
import sys
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]
for path in (str(_REPO_ROOT), str(_REPO_ROOT / "scan_node")):
    if path not in sys.path:
        sys.path.insert(0, path)

from backend.utilities.cbom_sources import targets as T  # noqa: E402
from zs_scan_node.netutil import NeverScan, expand_targets  # noqa: E402

ENTRIES = [
    "10.0.0.5", "10.0.1.0/30", "10.0.2.250-10.0.3.5", "::ffff:10.0.4.7", "::ffff:10.0.5.0/126",
    "::ffff:10.0.6.1-::ffff:10.0.6.3", "fd00::1-fd00::5", "fd00::a-fd00::f", "FD00:1::A - FD00:1::C", "fd00:2::/126",
    "2001:db8::7", "fe80::1%br-ab12", "fe80::a%vlan-10",  # a zone with a dash is still an address (Docker br-<hash>)
]
PROBES = (
    [f"10.0.0.{i}" for i in range(3, 8)] + [f"10.0.1.{i}" for i in range(0, 6)]
    + [f"10.0.2.{i}" for i in (249, 250, 255)]
    + [f"10.0.3.{i}" for i in range(0, 7)] + ["10.0.4.6", "10.0.4.7", "10.0.4.8"] + [f"10.0.5.{i}" for i in range(0, 6)]
    + [f"10.0.6.{i}" for i in range(0, 5)] + [f"fd00::{i:x}" for i in range(0, 0x12)]
    + [f"fd00:1::{i:x}" for i in range(8, 0xe)] + [f"fd00:2::{i}" for i in range(0, 6)] + ["2001:db8::6", "2001:db8::7"]
    + [f"fe80::{i:x}" for i in range(0, 0xc)]
)


def _backend_excludes(excl: T.ParsedTargets, address: str) -> bool:
    addr = ipaddress.ip_address(address)
    return any(version == addr.version and start <= int(addr) <= end for version, start, end in excl.intervals)


def test_backend_accepts_ranges_whose_first_address_ends_in_a_hex_letter():
    kind, interval, canonical = T.parse_line("fd00::a-fd00::f")
    assert kind == "net" and canonical == "fd00::a-fd00::f"
    assert interval == (6, int(ipaddress.ip_address("fd00::a")), int(ipaddress.ip_address("fd00::f")))
    assert T.parse_line("FD00::A - FD00::F")[2] == "fd00::a-fd00::f"
    assert T.parse_line("web-01.corp")[0] == "host"  # host names with dashes are still host names
    with pytest.raises(T.TargetError):
        T.parse_line("fd00::f-fd00::a")  # the range ends before it starts


@pytest.mark.parametrize("node_input", ["normalized", "as_entered"])
def test_every_address_the_backend_subtracts_is_blocked_by_the_node_and_no_other(node_input):
    excl = T.parse_exclusions(ENTRIES)
    never = NeverScan(excl.normalized if node_input == "normalized" else ENTRIES)
    disagree = [a for a in PROBES if _backend_excludes(excl, a) != never.blocks_ip(a)]
    assert disagree == []
    assert sum(_backend_excludes(excl, a) for a in PROBES) > 30  # the probes do hit the entries


@pytest.mark.parametrize("source, entries, expected", [
    ("fd00::/125", ["fd00::1-fd00::5"], 3),  # the security review's example: the node used to scan all 8
    ("fd00::/124", ["fd00::a-fd00::f"], 10),
    ("10.0.0.10-10.0.0.29", ["10.0.0.12-10.0.0.14", "::ffff:10.0.0.20"], 16),
])
def test_the_backend_count_matches_what_the_node_scans(source, entries, expected):
    excl = T.parse_exclusions(entries)
    assert T.count_in_scope(T.parse_targets([source]), excl) == expected
    targets, _skipped = expand_targets([source], NeverScan(excl.normalized))
    assert len(targets) == expected


@pytest.mark.parametrize("source, entries", [
    (["10.0.0.0/24"], []),  # the node skips the network and broadcast addresses of an IPv4 /30 or larger
    (["10.0.0.0/29"], ["10.0.0.1"]),
    (["10.0.1.0/30", "10.0.1.4/31", "10.0.1.9", "10.0.1.16/32"], []),  # a /31 and a /32 keep every address
    (["10.0.2.0/25", "10.0.2.128/25"], []),
    (["10.0.3.0/24", "10.0.3.255", "10.0.3.0/25"], []),  # an address written out is scanned, even a broadcast one
    (["::ffff:10.0.4.0/126"], []),  # stored (and sent to the node) as 10.0.4.0/30
    (["10.0.5.0-10.0.5.9", "10.0.5.8/29"], ["10.0.5.2", "::ffff:10.0.5.12"]),
    (["0.0.0.0"], []), (["0.0.0.0/29"], []), (["0.255.255.250-1.0.0.3"], []),  # 0.0.0.0/8 reaches the node itself
    (["::"], []), (["::/125"], []), (["64:ff9b::/125"], []),  # ::, and NAT64 of 0.0.0.0/8
    (["64:ff9b::a00:5", "64:ff9b::a00:6", "64:ff9b::a00:7"], ["10.0.0.5"]),  # NAT64 reaches the excluded IPv4 host
    (["fd00::/125"], ["fd00::1-fd00::5"]),
    (["fe80::/125"], ["fe80::1%br-ab12"]),
    # a name that is loopback by definition (re-review 5879769432): both leave out the loopback, in every form, only
    (["127.0.0.0/29", "10.0.7.0/30"], ["localhost"]),
    (["::1", "::ffff:127.0.0.5", "64:ff9b::7f00:5", "64:ff9b::a00:9", "10.0.7.9"], ["ip6-localhost"]),
    (["127.255.255.248/29", "::/126"], ["db.localhost", "10.0.7.1"]),
    (["127.0.0.0/30", "10.0.7.4/30"], ["LOCALHOST6.LOCALDOMAIN6."]),
])
def test_the_backend_count_and_samples_match_what_the_node_scans_for_every_target_form(source, entries):
    """Security re-review 5871690938: the count, the credits and the connection-test samples are the node's targets."""
    parsed, excl = T.parse_targets(source), T.parse_exclusions(entries)
    targets, _skipped = expand_targets(parsed.normalized, NeverScan(excl.normalized))  # the node gets the stored lines
    scanned = {t.ip for t in targets}
    assert T.count_in_scope(parsed, excl) == len(scanned)
    samples = T.sample_targets(parsed, excl, 5)
    assert set(samples) <= scanned and len(samples) == min(5, len(scanned))


# ----------------------------------------------------------------------------- one rule, one wording (re-review 5879769432)
FRONTEND = _REPO_ROOT / "frontend" / "components" / "cbom" / "sources" / "teamNeverScan.ts"


def _ts_constant(name: str) -> str:
    """The value of ``export const <name> = ...;`` in teamNeverScan.ts, as source text."""
    match = re.search(rf"^export const {name}\b[^=]*=\s*(.+?);\s*$", FRONTEND.read_text(encoding="utf-8"), re.M | re.S)
    assert match, f"{name} is not exported from {FRONTEND.name}"
    return match.group(1)


def test_the_node_the_backend_and_the_ui_know_the_same_loopback_names():
    from zs_scan_node import netutil

    assert T.LOOPBACK_NAMES == netutil.LOOPBACK_NAMES
    ui = json.loads(_ts_constant("LOOPBACK_NAMES").replace("new Set(", "").rstrip(")"))
    assert sorted(ui) == sorted(T.LOOPBACK_NAMES)
    for name in sorted(T.LOOPBACK_NAMES) + ["LocalHost.", "db.localhost", "a.b.localhost", "localhost.corp", "notlocalhost",
                                            "localhostx", "my-localhost", "ip6-localnet", "localhost5", "x.localhost.corp"]:
        assert T.is_loopback_name(name) == netutil.is_loopback_name(name), name
    assert T.is_loopback_name("db.localhost") and not T.is_loopback_name("localhost.corp")


def test_the_ui_and_the_api_say_the_same_words_for_a_host_name_in_the_team_list():
    """Re-review 5879769432 (teamNeverScan.ts:64): a typed entry (the UI's check) and a refused save (the API's 422)
    read the same, so a drift on either side fails here, in the backend suite (which runs on frontend changes too)."""
    assert json.loads(_ts_constant("HOST_NAME_NOT_ALLOWED")) == T.HOST_NAME_NOT_ALLOWED
    assert T.HOST_NAME_NOT_ALLOWED.count("{entry}") == 1 and T.HOST_NAME_NOT_ALLOWED.startswith("{entry} ")


# ----------------------------------------------------------------------------- one text form for an address (#126)
def _str_of(python: str, monkeypatch) -> None:
    """Put a CPython's IPv6Address.__str__ in place, whatever runs the tests: 3.12.3 and older print an IPv4-mapped
    address in hex (::ffff:7f00:9); 3.12.16 and 3.13 (gh-87799) print it dotted (::ffff:127.0.0.9)."""
    if python == "this interpreter":
        return
    current = ipaddress.IPv6Address.__str__

    def emulated(self):
        mapped = self.ipv4_mapped
        if mapped is None or self.scope_id:
            return current(self)
        if python == "CPython 3.12.3 str()":
            return f"::ffff:{int(mapped) >> 16:x}:{int(mapped) & 0xFFFF:x}"
        return f"::ffff:{mapped}"

    monkeypatch.setattr(ipaddress.IPv6Address, "__str__", emulated)
    want = "::ffff:7f00:9" if python == "CPython 3.12.3 str()" else "::ffff:127.0.0.9"
    assert str(ipaddress.ip_address("::ffff:127.0.0.9")) == want


PYTHONS = ["this interpreter", "CPython 3.12.3 str()", "CPython 3.13 str()"]
TEXT_FORMS = [
    ("::ffff:7f00:9", "::ffff:127.0.0.9"),  # IPv4-mapped: RFC 5952 section 5, the IPv4 part dotted
    ("::FFFF:10.0.0.4", "::ffff:10.0.0.4"),
    ("::ffff:0.0.0.0", "::ffff:0.0.0.0"),
    ("::7f00:1", "::7f00:1"),  # IPv4-compatible (deprecated): not mapped, stays hex
    ("64:ff9b::7f00:1", "64:ff9b::7f00:1"),  # NAT64: hex, as every CPython prints it
    ("fe80::1%eth0", "fe80::1%eth0"),
    ("2001:DB8::1", "2001:db8::1"),
    ("10.0.0.1", "10.0.0.1"),
]


@pytest.mark.parametrize("python", PYTHONS)
def test_the_backend_and_the_node_write_one_text_form_for_an_address(monkeypatch, python):
    from zs_scan_node import netutil

    _str_of(python, monkeypatch)
    for written, text in TEXT_FORMS:
        address = ipaddress.ip_address(written)
        assert T.ip_text(address) == netutil.ip_text(address) == text, written


@pytest.mark.parametrize("python", PYTHONS)
def test_connection_test_samples_are_labelled_the_same_on_every_python(monkeypatch, python):
    """sample_targets wrote str(ipaddress...): an IPv4-mapped sample was ::ffff:a00:4 on CPython 3.12.3 and
    ::ffff:10.0.0.4 on 3.12.16, the form the node labels (netutil.ip_text) and getaddrinfo answers."""
    _str_of(python, monkeypatch)
    mapped = T.ParsedTargets()
    first = int(ipaddress.ip_address("::ffff:10.0.0.4"))
    mapped.intervals = [(6, first, first + 2), (4, int(ipaddress.ip_address("10.0.9.1")), int(ipaddress.ip_address("10.0.9.1")))]
    assert T.sample_targets(mapped, None, 5) == ["10.0.9.1", "::ffff:10.0.0.4", "::ffff:10.0.0.5", "::ffff:10.0.0.6"]
    assert T.sample_targets(T.parse_targets(["fd00::/126"]), None, 2) == ["fd00::", "fd00::1"]


@pytest.mark.parametrize("python", PYTHONS)
def test_a_node_reports_its_source_addresses_in_the_same_form(monkeypatch, python):
    from backend.routers import cbom_node

    _str_of(python, monkeypatch)
    assert cbom_node._ips(["::ffff:7f00:9", " ::FFFF:10.0.0.1 ", "10.0.0.1", "not an address", "2001:DB8::1"]) == [
        "::ffff:127.0.0.9", "::ffff:10.0.0.1", "10.0.0.1", "2001:db8::1"]
