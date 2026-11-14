"""Minor 2 of the #250 review: a never-scan host name that a scan node cannot resolve holds every job of the team on
that node (fail closed).  The settings answer now says so (``never_scan_held``), from what the node already reports
in each job result (``never_scan_unresolved``): which name, which node, since when, and the latest job."""
from __future__ import annotations

import datetime as dt

import test_cbom_sources_api as SA

api, world, enroll_node = SA.api, SA.world, SA.enroll_node  # the shared fixtures (pytest finds them by name here)
ALL_HOURS = [[True] * 24 for _ in range(7)]


def _run_discovery(api, token, unresolved):
    assert api("POST", "/1/cbom/sources/discovery").status_code == 200
    hdr = {"X-ZS-Node-Token": token}
    claim = api("POST", "/cbom/node/jobs/claim", None, headers=hdr).json()
    result = {"summary": "0 of 254 targets collected", "counts": {"total": 254, "ok": 0, "failed": 0, "skipped": 254},
              "asset_count": 0}
    if unresolved:
        result["never_scan_unresolved"] = unresolved
    r = api("POST", f"/cbom/node/jobs/{claim['job']['id']}/result", None, headers=hdr,
            json={"lease_id": claim["job"]["lease_id"], "status": "success", "result": result})
    assert r.status_code == 200, r.text
    return claim["job"]["id"]


def _held(api):
    return api("GET", "/1/cbom/sources/settings").json()["settings"]["never_scan_held"]


def test_a_name_a_node_cannot_resolve_shows_as_held_on_that_node_since_its_first_held_job(api, world):
    node_id, token, _ = enroll_node(api)
    api("PATCH", "/1/cbom/sources/settings", json={"scan_window": ALL_HOURS, "network_exclusions": [
        {"cidr": "shop.lab", "reason": "payments"}, {"cidr": "localhost", "reason": "node"},
        {"cidr": "10.20.99.0/24", "reason": "OT"}]})
    api("POST", "/1/cbom/sources/items", json={"kind": "network_range", "name": "lab", "node_id": node_id,
                                              "config": {"cidr": "10.232.0.0/24", "mode": "full"}})
    assert _held(api) == []  # nothing reported yet
    before = dt.datetime.now(dt.UTC).replace(microsecond=0, tzinfo=None)
    first = _run_discovery(api, token, ["shop.lab", "other.source.name"])  # a source-only name is not the team's
    second = _run_discovery(api, token, ["shop.lab"])
    (held,) = _held(api)
    assert held["name"] == "shop.lab" and held["node_id"] == node_id and held["node_name"] == "dc-mumbai-01"
    assert held["job_id"] == second and first != second
    since = dt.datetime.fromisoformat(held["since"].rstrip("Z"))
    assert before - dt.timedelta(seconds=2) <= since <= dt.datetime.now(dt.UTC).replace(tzinfo=None)
    # the PATCH answer carries it too (the tab replaces its settings with it)
    patched = api("PATCH", "/1/cbom/sources/settings", json={"soc_email": "soc@bank.test"}).json()["settings"]
    assert [h["name"] for h in patched["never_scan_held"]] == ["shop.lab"]
    # the name resolves on the node again: its next job does not name it, and the hold is gone
    _run_discovery(api, token, [])
    assert _held(api) == []


def test_a_name_removed_from_the_team_list_is_no_longer_shown_as_held(api, world):
    node_id, token, _ = enroll_node(api)
    api("PATCH", "/1/cbom/sources/settings", json={"scan_window": ALL_HOURS, "network_exclusions": [
        {"cidr": "shop.lab", "reason": "payments"}]})
    api("POST", "/1/cbom/sources/items", json={"kind": "network_range", "name": "lab", "node_id": node_id,
                                              "config": {"cidr": "10.232.0.0/24", "mode": "full"}})
    _run_discovery(api, token, ["shop.lab"])
    assert [h["name"] for h in _held(api)] == ["shop.lab"]
    api("PATCH", "/1/cbom/sources/settings", json={"network_exclusions": []})
    assert _held(api) == []
