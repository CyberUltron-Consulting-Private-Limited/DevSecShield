"""N3 follow-up (review of #250, minor 1): network and broadcast addresses are judged on the network the customer
entered, not on prefix size.

* A /23 entered as two /24 ranges keeps x.x.0.255 and x.x.1.0 (hosts of the /23); a /24 as two /25s keeps .127/.128.
* A real /25 ... /30 subnet entered on its own skips its own network and broadcast addresses.
* The node sweeps exactly what the backend counts: each network range's claim carries ``skip_addresses`` computed over
  every range of the team, and the estimate (credits), the per-range count and "Before the first run" use them.
"""
from __future__ import annotations

import ipaddress

import pytest
import test_cbom_sources_api as SA

from backend.utilities.cbom_sources import targets as T

api, world, enroll_node = SA.api, SA.world, SA.enroll_node  # the shared fixtures (pytest finds them by name here)

ALL_HOURS = [[True] * 24 for _ in range(7)]


def _range(api, node_id, cidr, name):
    r = api("POST", "/1/cbom/sources/items", json={"kind": "network_range", "name": name, "node_id": node_id,
                                                  "config": {"cidr": cidr, "mode": "full"}})
    assert r.status_code == 201, r.text
    return r.json()["source"]


@pytest.mark.parametrize("lines, kept, skipped", [
    (["10.1.0.0/24", "10.1.1.0/24"], ["10.1.0.255", "10.1.1.0"], ["10.1.0.0", "10.1.1.255"]),
    (["10.232.0.0/25", "10.232.0.128/25"], ["10.232.0.127", "10.232.0.128"], ["10.232.0.0", "10.232.0.255"]),
    (["10.9.0.8/29"], ["10.9.0.9", "10.9.0.14"], ["10.9.0.8", "10.9.0.15"]),  # a real /29 subnet
    (["10.9.0.4/30"], ["10.9.0.5", "10.9.0.6"], ["10.9.0.4", "10.9.0.7"]),
    (["10.9.1.0/25"], ["10.9.1.1", "10.9.1.126"], ["10.9.1.0", "10.9.1.127"]),  # a /25 on its own is a subnet
])
def test_network_and_broadcast_follow_the_network_entered_not_the_prefix(lines, kept, skipped):
    parsed = T.parse_targets(lines)
    scanned = {a for _v, first, last in parsed.intervals for a in range(first, last + 1)}
    assert all(int(ipaddress.IPv4Address(ip)) in scanned for ip in kept), kept
    assert not any(int(ipaddress.IPv4Address(ip)) in scanned for ip in skipped), skipped


def test_a_23_split_into_two_24_ranges_is_claimed_and_counted_with_its_inner_edges(api, world):
    node_id, token, _ = enroll_node(api)
    api("PATCH", "/1/cbom/sources/settings", json={"scan_window": ALL_HOURS})
    low, high = _range(api, node_id, "10.1.0.0/24", "low"), _range(api, node_id, "10.1.1.0/24", "high")
    got = {s["id"]: s["target_count"] for s in api("GET", "/1/cbom/sources/items?group=network").json()["sources"]}
    assert got == {low["id"]: 255, high["id"]: 255}  # each keeps its inner edge
    body = api("GET", "/1/cbom/sources/items?group=network").json()
    assert body["network_totals"]["addresses"] == 510
    plan = api("POST", "/1/cbom/sources/estimate", json={"include": {"network": True}}).json()
    assert sorted(i["units"] for i in plan["items"] if i["kind"] == "network_range") == [255, 255]
    # what the node is told to leave out, per range: only the /23's own network and broadcast
    assert api("POST", "/1/cbom/sources/discovery").status_code == 200
    claim = api("POST", "/cbom/node/jobs/claim", None, headers={"X-ZS-Node-Token": token}).json()
    skips = {r["cidr"]: r["skip_addresses"] for r in claim["scope"]["ranges"]}
    assert skips == {"10.1.0.0/24": ["10.1.0.0"], "10.1.1.0/24": ["10.1.1.255"]}


def test_a_lone_29_subnet_is_claimed_and_counted_without_its_network_and_broadcast(api, world):
    node_id, token, _ = enroll_node(api)
    api("PATCH", "/1/cbom/sources/settings", json={"scan_window": ALL_HOURS})
    src = _range(api, node_id, "10.9.0.8/29", "p2p")
    assert src["target_count"] == 6
    run = api("POST", "/1/cbom/sources/runs", json={"include": {"network": True}, "source_ids": [src["id"]],
                                                   "client_request_id": "n3-lone-29-run", "soc_ack": True})
    assert run.status_code == 201, run.text
    claim = api("POST", "/cbom/node/jobs/claim", None, headers={"X-ZS-Node-Token": token}).json()
    assert claim["scope"]["ranges"] == [{"cidr": "10.9.0.8/29", "mode": "full",
                                         "skip_addresses": ["10.9.0.8", "10.9.0.15"]}]


# ----------------------------------------------------------------------------- cost (review of #273, major)
def _many_ranges(engine, user_id: int, node_id: int, n: int, start: int = 0) -> None:
    """Ranges ``start`` .. ``start + n - 1`` (adjacent /24s, so they form one block), written straight to the database."""
    from sqlmodel import Session

    from backend.new_models import CbomCollectionSource

    with Session(engine) as s:
        for i in range(start, start + n):
            cidr = f"10.{100 + i // 256}.{i % 256}.0/24"
            s.add(CbomCollectionSource(team_id=1, owner_user_id=user_id, kind="network_range", name=f"r{i}",
                                       name_lower=f"r{i}", node_id=node_id, config={"cidr": cidr, "mode": "full"}))
        s.commit()


def _queries_of(engine, call) -> int:
    from sqlalchemy import event

    seen = [0]

    def count(*_a, **_k):
        seen[0] += 1

    event.listen(engine, "before_cursor_execute", count)
    try:
        call()
    finally:
        event.remove(engine, "before_cursor_execute", count)
    return seen[0]


PATHS = ("/1/cbom/sources/items?group=network", "/1/cbom/sources/items", "/1/cbom/sources/overview",
         "/1/cbom/sources/nodes")


def test_listing_ranges_costs_the_same_number_of_queries_for_3_or_300_ranges(api, world):
    engine, ids = world
    node_id, _t, _ = enroll_node(api)
    _many_ranges(engine, ids["alice"], node_id, 3)
    for path in PATHS:  # first calls create the team's rows (evidence areas, settings): not what is measured
        api("GET", path)
    few = {path: _queries_of(engine, lambda p=path: api("GET", p)) for path in PATHS}
    _many_ranges(engine, ids["alice"], node_id, 297, start=3)
    many = {path: _queries_of(engine, lambda p=path: api("GET", p)) for path in PATHS}
    assert many == few, (few, many)  # no query per range, on any of the lists that count ranges
    # and the counts are the rule: 300 adjacent /24s form one block; only its first and last address are left out
    body = api("GET", "/1/cbom/sources/items?group=network").json()
    assert body["network_totals"]["addresses"] == 300 * 256 - 2
    assert sorted({s["target_count"] for s in body["sources"]}) == [255, 256]


def test_counting_1000_ranges_stays_well_under_a_second():
    import time

    from backend.new_models import CbomCollectionSettings, CbomCollectionSource
    from backend.utilities.cbom_sources.planning import (
        RangeContext,
        network_sweep_totals,
        source_targets,
    )

    settings = CbomCollectionSettings(team_id=1, network_exclusions=[{"cidr": "10.100.7.0/24", "reason": "x"}])
    sources = [CbomCollectionSource(id=i + 1, team_id=1, owner_user_id=1, kind="network_range", name=f"r{i}",
                                    name_lower=f"r{i}", enabled=True,
                                    config={"cidr": f"10.{100 + i // 256}.{i % 256}.0/24", "mode": "full"})
               for i in range(1000)]
    started = time.perf_counter()
    ctx = RangeContext.of_sources(sources, settings)
    units = [source_targets(s, settings, ctx)["units"] for s in sources]
    totals = network_sweep_totals(sources, settings, ctx)
    elapsed = time.perf_counter() - started
    assert elapsed < 0.5, f"{elapsed:.2f} s for 1,000 ranges"
    assert units[0] == 255 and units[1] == 256 and units[999] == 255 and units[7] == 0  # block edges, never-scan
    assert totals["addresses"] == 1000 * 256 - 2 - 256
