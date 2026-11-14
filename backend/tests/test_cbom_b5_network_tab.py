"""Owner bug list 14 Nov 2026, Network TLS tab (lane B5).

N7: "Before the first run" showed 510 addresses for a disabled /24 plus overlapping ranges the nodes sweep at most
    ~252 of.  The sources list now carries ``network_totals``: unique addresses after the never-scan list, over enabled
    ranges only, from the same intervals plan_run charges (planning.network_sweep_totals).
N12: starting a run while Stop all is on said "every selected source is skipped" without saying why; it now says
    "Scanning is stopped (Stop all). Resume scanning to start a run."
"""
from __future__ import annotations

import ipaddress

import test_cbom_sources_api as SA  # noqa: E402

from backend.utilities.cbom_sources import targets as T

api, world = SA.api, SA.world  # the shared fixtures (pytest finds them by name in this module)
enroll_node, linux_body = SA.enroll_node, SA.linux_body

STOPPED = "Scanning is stopped (Stop all). Resume scanning to start a run."
# the reported case: the /24 was split into two /25s (and disabled); two small ranges overlap the /25s
REPORTED = ["10.232.0.0/24", "10.232.0.0/25", "10.232.0.128/25", "10.232.0.0/30", "10.232.0.128/30"]


def _add_range(api, node_id: int, cidr: str, name: str) -> dict:
    r = api("POST", "/1/cbom/sources/items", json={"kind": "network_range", "name": name, "node_id": node_id,
                                                  "config": {"cidr": cidr, "mode": "full"}})
    assert r.status_code == 201, r.text
    return r.json()["source"]


def _disable(api, source: dict) -> None:
    r = api("PATCH", f"/1/cbom/sources/items/{source['id']}", json={"enabled": False, "expected_version": source["row_version"]})
    assert r.status_code == 200, r.text


def _swept(cidr: str) -> set[int]:
    """Addresses one range's sweep visits, enumerated one by one (not through merge/size)."""
    kind, interval, canonical = T.parse_line(cidr)
    scanned = T.scanned_interval(interval, canonical)
    return set(range(scanned[1], scanned[2] + 1)) if scanned else set()


# ----------------------------------------------------------------------------- N7
def test_reported_case_counts_unique_addresses_of_enabled_ranges(api, world):
    node_id, _t, _ = enroll_node(api)
    made = [_add_range(api, node_id, cidr, f"r{i}") for i, cidr in enumerate(REPORTED)]
    _disable(api, made[0])  # the /24
    body = api("GET", "/1/cbom/sources/items?group=network").json()
    old_sum = sum(s["target_count"] for s in body["sources"] if s["kind"] == "network_range")
    expected = len(set().union(*(_swept(c) for c in REPORTED[1:])))
    assert old_sum == 510  # what the tab showed (the per-range counts, disabled /24 and overlaps included)
    assert body["network_totals"] == {"addresses": expected, "ranges_enabled": 4, "ranges_disabled": 1}
    assert 252 <= expected <= 256 < old_sum  # at most the two /25s, never the 510
    # the same number plan_run charges for: Review & Run's network units for these ranges, overlaps once
    est = api("POST", "/1/cbom/sources/estimate", json={"include": {"network": True}}).json()
    queued = [i for i in est["items"] if i["kind"] == "network_range" and i["status"] == "queued"]
    assert len(queued) == 4 and all(i["source_id"] != made[0]["id"] for i in queued)


def test_network_totals_apply_the_never_scan_list_and_ignore_other_kinds(api, world):
    node_id, _t, _ = enroll_node(api)
    _add_range(api, node_id, "10.40.0.0/24", "a")
    _add_range(api, node_id, "10.40.0.0/25", "b")  # inside a
    assert api("PATCH", "/1/cbom/sources/settings", json={"network_exclusions": [
        {"cidr": "10.40.0.0/26", "reason": "OT"}]}).status_code == 200
    totals = api("GET", "/1/cbom/sources/items?group=network").json()["network_totals"]
    never = {int(a) for a in ipaddress.ip_network("10.40.0.0/26")}
    assert totals == {"addresses": len(_swept("10.40.0.0/24") - never), "ranges_enabled": 2, "ranges_disabled": 0}
    assert totals["addresses"] == 254 - 63
    # an unfiltered list carries the totals too; another group's list does not
    assert api("GET", "/1/cbom/sources/items").json()["network_totals"]["addresses"] == 191
    assert "network_totals" not in api("GET", "/1/cbom/sources/items?group=servers").json()


def test_no_ranges_means_zero(api, world):
    assert api("GET", "/1/cbom/sources/items?group=network").json()["network_totals"] == {
        "addresses": 0, "ranges_enabled": 0, "ranges_disabled": 0}


# ----------------------------------------------------------------------------- N12
def test_start_while_stopped_says_scanning_is_stopped(api, world):
    node_id, _t, _ = enroll_node(api)
    _add_range(api, node_id, "10.50.0.0/24", "dc")
    assert api("POST", "/1/cbom/sources/settings/stop-all", json={"on": True}).status_code == 200
    r = api("POST", "/1/cbom/sources/runs", json={"include": {"network": True}, "soc_ack": True,
                                                 "client_request_id": "b5-stopped-0001"})
    assert r.status_code == 400 and r.json()["detail"] == STOPPED
    assert "every selected source is skipped" not in r.json()["detail"]


def test_stopped_refusal_also_counts_other_skipped_sources(api, world):
    node_id, _t, _ = enroll_node(api)
    _add_range(api, node_id, "10.51.0.0/24", "dc")
    src = api("POST", "/1/cbom/sources/items", json=linux_body(node_id=node_id)).json()["source"]
    _disable(api, src)
    api("POST", "/1/cbom/sources/settings/stop-all", json={"on": True})
    r = api("POST", "/1/cbom/sources/runs", json={"include": {"network": True, "servers": True}, "soc_ack": True,
                                                 "client_request_id": "b5-stopped-0002"})
    assert r.status_code == 400
    assert r.json()["detail"] == STOPPED + " 1 other selected source is skipped too (see 'Will be skipped')."


def test_resumed_scanning_starts_and_other_refusals_keep_their_words(api, world):
    node_id, _t, _ = enroll_node(api)
    src = api("POST", "/1/cbom/sources/items", json=linux_body(node_id=node_id)).json()["source"]
    _disable(api, src)
    api("POST", "/1/cbom/sources/settings/stop-all", json={"on": True})  # stopped, but no network source selected
    r = api("POST", "/1/cbom/sources/runs", json={"include": {"servers": True}, "client_request_id": "b5-stopped-0003"})
    assert r.status_code == 400 and r.json()["detail"].startswith("Nothing to scan: every selected source is skipped")
    _add_range(api, node_id, "10.52.0.0/24", "dc")
    api("POST", "/1/cbom/sources/settings/stop-all", json={"on": False})
    ok = api("POST", "/1/cbom/sources/runs", json={"include": {"network": True}, "soc_ack": True,
                                                  "client_request_id": "b5-stopped-0004"})
    assert ok.status_code in (200, 201), ok.text
