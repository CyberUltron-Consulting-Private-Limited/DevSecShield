"""Owner-reported Network TLS bugs of 14 Nov 2026, the backend half (planning, settings API, heartbeat, test results).

* N2: the team never-scan list stores a host name, and every node job (range sweeps, discovery, servers, tests) and
  the heartbeat carry it with the addresses, so the node resolves it and keeps its addresses out.
* N3: what the backend counts (estimates, credits) is what the node sweeps: a /24 split into two /25s keeps .127 and
  .128 (test_cbom_n3_range_boundaries.py has the rule in full).
* N4: the heartbeat tells the node when each running job's scan window ends, and that it has ended when the
  customer closes the window while the job runs.
* N10: a connection test whose every target is on the never-scan list reads "skipped: on the never-scan list", never
  "passed: 0 of 0 samples ready".

Run like test_cbom_sources_api.py (SQLite, real routers).
"""
from __future__ import annotations

import datetime as dt
import zoneinfo

import pytest

from tests.test_cbom_sources_api import PASSWORD, api, enroll_node, world  # noqa: F401 - pytest fixtures
from backend.utilities.cbom_sources import targets as T

KNOWN_HOSTS = "10.20.0.9 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIE0Bq1hQ0j7lC1n6x3o0b9Z7w2YtqXxw9i6ZQ5mM2kHq"
ALL_HOURS = [[True] * 24 for _ in range(7)]


def _hdr(token: str) -> dict:
    return {"X-ZS-Node-Token": token}


# ----------------------------------------------------------------------------- N2
def test_n2_the_team_list_stores_a_host_name_and_every_node_job_carries_it(api, world):
    node_id, token, _ = enroll_node(api)
    api("PATCH", "/1/cbom/sources/settings", json={"scan_window": ALL_HOURS})
    r = api("PATCH", "/1/cbom/sources/settings", json={"network_exclusions": [
        {"cidr": "10.20.99.0/24", "reason": "OT plant"}, {"cidr": " Shop.Lab. ", "reason": "payments"}]})
    assert r.status_code == 200, r.text
    stored = r.json()["settings"]["network_exclusions"]
    assert [e["cidr"] for e in stored] == ["10.20.99.0/24", "shop.lab"]
    rng = api("POST", "/1/cbom/sources/items", json={"kind": "network_range", "name": "lab", "node_id": node_id,
                                                    "config": {"cidr": "10.232.0.0/24", "mode": "full"}})
    assert rng.status_code == 201, rng.text
    assert api("POST", "/1/cbom/sources/discovery").status_code == 200
    claim = api("POST", "/cbom/node/jobs/claim", None, headers=_hdr(token)).json()
    assert claim["job"]["kind"] == "discovery"
    assert set(claim["scope"]["never_scan"]) == {"10.20.99.0/24", "shop.lab"}  # both: the node resolves the name
    hb = api("POST", "/cbom/node/heartbeat", None, headers=_hdr(token), json={}).json()
    assert set(hb["never_scan"]) == {"10.20.99.0/24", "shop.lab"}
    # a range collection (the run's job) carries it too
    run = api("POST", "/1/cbom/sources/runs", json={"include": {"network": True}, "source_ids": [rng.json()["source"]["id"]],
                                                   "client_request_id": "n2-range-run-01", "soc_ack": True})
    assert run.status_code == 201, run.text
    claim = api("POST", "/cbom/node/jobs/claim", None, headers=_hdr(token)).json()
    assert claim["job"]["kind"] == "collect" and "shop.lab" in claim["scope"]["never_scan"]
    # a duplicate name (any case, trailing dot) is stored once; a malformed one is still refused
    again = api("PATCH", "/1/cbom/sources/settings", json={"network_exclusions": [
        {"cidr": "shop.lab", "reason": "a"}, {"cidr": "SHOP.LAB.", "reason": "b"}]})
    assert [e["cidr"] for e in again.json()["settings"]["network_exclusions"]] == ["shop.lab"]
    bad = api("PATCH", "/1/cbom/sources/settings", json={"network_exclusions": [{"cidr": "*.corp", "reason": "x"}]})
    assert bad.status_code == 400 and bad.json()["detail"].startswith("network_exclusions: ")
    # a mistyped range is not taken as a host name (it would never resolve and hold every job of the team)
    for typo in ("10.0.0.0-24", "0x0a000001"):
        bad = api("PATCH", "/1/cbom/sources/settings", json={"network_exclusions": [{"cidr": typo, "reason": "x"}]})
        assert bad.status_code == 400 and "mistyped address" in bad.json()["detail"], (typo, bad.text)
    assert [e["cidr"] for e in api("GET", "/1/cbom/sources/settings").json()["settings"]["network_exclusions"]] == [
        "shop.lab"]


# ----------------------------------------------------------------------------- N3
@pytest.mark.parametrize("lines, count", [
    (["10.232.0.0/25", "10.232.0.128/25"], 254),  # the split halves of one /24: .127 and .128 are hosts
    (["10.232.0.0/24"], 254),  # a network on its own leaves out its network and broadcast address
    (["10.232.0.0/23"], 510),
    (["10.232.0.0/29"], 6), (["10.232.0.0/30"], 2), (["10.232.0.0/31"], 2),
])
def test_n3_the_backend_counts_what_the_node_sweeps(lines, count):
    assert T.count_in_scope(T.parse_targets(lines), None) == count


def test_n3_two_25s_of_one_24_count_127_and_128(api, world):
    node_id, _t, _ = enroll_node(api)
    units = {}
    for name, cidr in (("low", "10.232.0.0/25"), ("high", "10.232.0.128/25")):
        r = api("POST", "/1/cbom/sources/items", json={"kind": "network_range", "name": name, "node_id": node_id,
                                                      "config": {"cidr": cidr, "mode": "full"}})
        assert r.status_code == 201, r.text
        units[name] = r.json()["source"]["id"]
    plan = api("POST", "/1/cbom/sources/estimate", json={"include": {"network": True}}).json()
    got = {i["source_id"]: i["units"] for i in plan["items"] if i["kind"] == "network_range"}
    assert got == {units["low"]: 127, units["high"]: 127}  # each keeps its inner edge (.127 / .128)


# ----------------------------------------------------------------------------- N4
def _grid_closed_now(tz: str = "UTC") -> list[list[bool]]:
    local = dt.datetime.now(zoneinfo.ZoneInfo(tz))
    grid = [[True] * 24 for _ in range(7)]
    grid[local.weekday()][local.hour] = False
    return grid


def test_n4_the_heartbeat_says_a_running_jobs_window_has_closed(api, world):
    node_id, token, _ = enroll_node(api)
    api("PATCH", "/1/cbom/sources/settings", json={"scan_window": ALL_HOURS, "window_timezone": "UTC"})
    api("POST", "/1/cbom/sources/items", json={"kind": "network_range", "name": "lab", "node_id": node_id,
                                              "config": {"cidr": "10.232.0.0/24", "mode": "full"}})
    assert api("POST", "/1/cbom/sources/discovery").status_code == 200
    claim = api("POST", "/cbom/node/jobs/claim", None, headers=_hdr(token)).json()
    job = claim["job"]
    running = {"running": [{"job_id": job["id"], "lease_id": job["lease_id"]}]}
    hb = api("POST", "/cbom/node/heartbeat", None, headers=_hdr(token), json=running).json()
    assert str(job["id"]) not in (hb.get("window_ends") or {})  # every hour allowed: no window end to apply
    # the customer closes the current hour while the sweep runs
    r = api("PATCH", "/1/cbom/sources/settings", json={"scan_window": _grid_closed_now()})
    assert r.status_code == 200, r.text
    before = dt.datetime.now(dt.timezone.utc)
    hb = api("POST", "/cbom/node/heartbeat", None, headers=_hdr(token), json=running).json()
    end = dt.datetime.fromisoformat(hb["window_ends"][str(job["id"])].replace("Z", "+00:00"))
    assert end <= before + dt.timedelta(seconds=1)  # closed now: the node stops at its next connection
    assert job["id"] not in hb["cancel_job_ids"]  # not cancelled: what it read is kept, the rest is skipped_window


def test_n4_a_shortened_window_moves_the_end_the_node_gets(api, world):
    node_id, token, _ = enroll_node(api)
    local = dt.datetime.now(dt.timezone.utc)
    grid = [[True] * 24 for _ in range(7)]
    nxt = local + dt.timedelta(hours=1)
    grid[nxt.weekday()][nxt.hour] = False  # the window now ends at the top of the next hour
    api("PATCH", "/1/cbom/sources/settings", json={"scan_window": ALL_HOURS, "window_timezone": "UTC"})
    api("POST", "/1/cbom/sources/items", json={"kind": "network_range", "name": "lab", "node_id": node_id,
                                              "config": {"cidr": "10.232.0.0/24", "mode": "full"}})
    assert api("POST", "/1/cbom/sources/discovery").status_code == 200
    job = api("POST", "/cbom/node/jobs/claim", None, headers=_hdr(token)).json()["job"]
    api("PATCH", "/1/cbom/sources/settings", json={"scan_window": grid})
    hb = api("POST", "/cbom/node/heartbeat", None, headers=_hdr(token),
             json={"running": [{"job_id": job["id"], "lease_id": job["lease_id"]}]}).json()
    end = dt.datetime.fromisoformat(hb["window_ends"][str(job["id"])].replace("Z", "+00:00"))
    assert end == nxt.replace(minute=0, second=0, microsecond=0)


# ----------------------------------------------------------------------------- N10
def _appliance(api, node_id, targets):
    return api("POST", "/1/cbom/sources/items", json={
        "kind": "appliance", "name": "edge-fw", "node_id": node_id,
        "config": {"vendor": "fortios", "targets": targets, "credential_type": "password", "login_user": "zs-cbom",
                   "host_key_policy": "pinned", "known_hosts": KNOWN_HOSTS},
        "secrets": {"password": PASSWORD}})


def test_n10_an_appliance_on_a_never_scan_address_tests_as_skipped(api, world):
    node_id, token, _ = enroll_node(api)
    api("PATCH", "/1/cbom/sources/settings", json={"network_exclusions": [{"cidr": "10.20.0.9", "reason": "core fw"}]})
    r = _appliance(api, node_id, ["10.20.0.9"])
    assert r.status_code == 201, r.text
    src = r.json()["source"]
    job_id = api("POST", f"/1/cbom/sources/items/{src['id']}/test").json()["job"]["id"]
    claim = api("POST", "/cbom/node/jobs/claim", None, headers=_hdr(token)).json()
    assert claim["job"]["id"] == job_id
    # the node gets the listed target so it can say why it was skipped (it never connects: never-scan wins there)
    assert claim["scope"]["targets"] == ["10.20.0.9"] and "10.20.0.9" in claim["scope"]["never_scan"]
    sample = {"target": "10.20.0.9", "status": "skipped_never_scan", "reachable": None,
              "note": "10.20.0.9 is on the never-scan list (10.20.0.9)"}
    done = api("POST", f"/cbom/node/jobs/{job_id}/result", None, headers=_hdr(token), json={
        "lease_id": claim["job"]["lease_id"], "status": "success",
        "result": {"summary": "0 of 1 samples ready", "samples": [sample]}})
    assert done.status_code == 200, done.text
    got = api("GET", f"/1/cbom/sources/items/{src['id']}").json()["source"]
    assert got["last_test_status"] == "skipped", got
    assert got["last_test_summary"].startswith("Skipped: on the never-scan list"), got["last_test_summary"]
    assert "passed" not in got["last_test_summary"] and "0 of 0" not in got["last_test_summary"]


def test_n10_a_test_with_no_samples_at_all_never_reads_as_passed(api, world):
    node_id, token, _ = enroll_node(api)
    src = _appliance(api, node_id, ["10.20.0.10"]).json()["source"]
    job_id = api("POST", f"/1/cbom/sources/items/{src['id']}/test").json()["job"]["id"]
    claim = api("POST", "/cbom/node/jobs/claim", None, headers=_hdr(token)).json()
    api("POST", f"/cbom/node/jobs/{job_id}/result", None, headers=_hdr(token), json={
        "lease_id": claim["job"]["lease_id"], "status": "success",
        "result": {"summary": "0 of 0 samples ready", "samples": []}})
    got = api("GET", f"/1/cbom/sources/items/{src['id']}").json()["source"]
    assert got["last_test_status"] != "passed" and "0 of 0" not in got["last_test_summary"], got
