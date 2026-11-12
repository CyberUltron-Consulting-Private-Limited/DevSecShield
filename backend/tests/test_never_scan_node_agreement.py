"""The never-scan list as the backend counts it and as the scan node applies it must agree (PR #32 security review).

The backend parses each entry (``targets.parse_exclusions``), counts what is left of a source for estimates and
credits, and sends ``exclusions.normalized`` to the node.  The node's ``NeverScan`` must block exactly the addresses
the backend subtracted, for every entry form: single addresses, CIDRs, IPv4 and IPv6 ``a-b`` ranges (including
ones whose first address ends in a hex letter) and IPv4-mapped forms.  Host-name entries are matched by the node
only (the backend cannot resolve names on the customer's network).
"""
from __future__ import annotations

import ipaddress
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
    "2001:db8::7",
]
PROBES = (
    [f"10.0.0.{i}" for i in range(3, 8)] + [f"10.0.1.{i}" for i in range(0, 6)]
    + [f"10.0.2.{i}" for i in (249, 250, 255)]
    + [f"10.0.3.{i}" for i in range(0, 7)] + ["10.0.4.6", "10.0.4.7", "10.0.4.8"] + [f"10.0.5.{i}" for i in range(0, 6)]
    + [f"10.0.6.{i}" for i in range(0, 5)] + [f"fd00::{i:x}" for i in range(0, 0x12)]
    + [f"fd00:1::{i:x}" for i in range(8, 0xe)] + [f"fd00:2::{i}" for i in range(0, 6)] + ["2001:db8::6", "2001:db8::7"]
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
