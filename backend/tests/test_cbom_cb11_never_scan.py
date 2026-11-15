"""CB-11: a target on the never-scan list is EXCLUDED BY POLICY everywhere, not only on the scan node (#250).

* Outcome and drift: a never-scan skip never makes a collection incomplete. The source stays comparable (KF-12: a
  range with a never-scan entry was never compared again). An asset of a target that went onto the list is
  "excluded", never removed, and its findings stay open. An asset of a target that came off the list is "back in
  scope", never a new asset. A real fix on another target still resolves.
* Pricing: the estimate already leaves out what the server can match (addresses, exact names). A listed host name
  that the node resolves to a charged target is refunded when the job ends (R2: 8 targets charged, 1 blocked: 7).
* Q0 scope items and exports: never-scan targets are ``excluded_by_policy`` ("excluded by policy"), never a gap.

Every test names what dev 72aa591e2 gives. Real routers on SQLite, the node's calls made as the node makes them.

    /home/claude/work/bt.sh <worktree> -q tests/test_cbom_cb11_never_scan.py
"""
from __future__ import annotations

import json

from tests import test_cbom_sources_api as H
from tests.test_cbom_sources_api import KNOWN_HOSTS, PASSWORD, enroll_node

api, world = H.api, H.world  # the harness's fixtures: SQLite + real routers + real JWTs

ALL_HOURS = [[True] * 24 for _ in range(7)]
WEAK = {"protocols": ["TLSv1.0", "TLSv1.2"], "group": "x25519"}
FIXED = {"protocols": ["TLSv1.2", "TLSv1.3"], "group": "x25519"}
RANGE = "10.232.0.0/30"  # four addresses, all scanned (N3)
ADDRS = [f"10.232.0.{i}" for i in range(4)]
_runs = {"n": 0}


def _hdr(token: str) -> dict:
    return {"X-ZS-Node-Token": token}


def _tls(ip: str, facts: dict) -> dict:
    return {"type": "tls_endpoint", "target": ip, "location": f"{ip}:443", "name": f"HTTPS {ip}:443", "facts": facts}


def _never_scan(api, *entries: str) -> None:
    r = api("PATCH", "/1/cbom/sources/settings", json={
        "scan_window": ALL_HOURS, "network_exclusions": [{"cidr": e, "reason": "OT"} for e in entries]})
    assert r.status_code == 200, r.text


def _range(api) -> tuple[int, str]:
    node_id, token, _ = enroll_node(api)
    _never_scan(api)
    src = api("POST", "/1/cbom/sources/items", json={"kind": "network_range", "name": "lab", "node_id": node_id,
                                                     "config": {"cidr": RANGE, "mode": "full"}})
    assert src.status_code == 201, src.text
    return src.json()["source"]["id"], token


def _run(api, source_id: int, group: str, token: str, assets: list[dict], targets: list[dict]) -> int:
    """One run of the source: the node claims, posts its assets and its result (counts as jobctx.result counts)."""
    _runs["n"] += 1
    body = {"include": {group: True}, "source_ids": [source_id], "client_request_id": f"cb11-run-{_runs['n']:04d}"}
    if group == "network":
        body["soc_ack"] = True
    run = api("POST", "/1/cbom/sources/runs", json=body)
    assert run.status_code == 201, run.text
    claim = api("POST", "/cbom/node/jobs/claim", None, headers=_hdr(token)).json()
    job, lease = claim["job"], claim["job"]["lease_id"]
    if assets:
        r = api("POST", f"/cbom/node/jobs/{job['id']}/assets", None, headers=_hdr(token),
                json={"lease_id": lease, "batch_id": "b1", "assets": assets})
        assert r.status_code == 200, r.text
    counts = {"total": len(targets), "ok": 0, "failed": 0, "skipped": 0}
    for t in targets:
        status = t["status"]
        counts["ok" if status == "ok" else "skipped" if status.startswith("skipped_") or status == "summary" else
               "failed"] += int(json.loads(t["error"])["skipped_never_scan"]) if status == "summary" else 1
    if any(t["status"] == "summary" for t in targets):
        counts["total"] = counts["ok"] + counts["failed"] + counts["skipped"]
    done = api("POST", f"/cbom/node/jobs/{job['id']}/result", None, headers=_hdr(token), json={
        "lease_id": lease, "status": "success",
        "result": {"counts": counts, "asset_count": len(assets), "targets": targets}})
    assert done.status_code == 200, done.text
    return run.json()["run"]["id"]


def _ok(*ips: str) -> list[dict]:
    return [{"target": ip, "status": "ok"} for ip in ips]


def _skipped(ip: str, why: str | None = None) -> dict:
    return {"target": ip, "status": "skipped_never_scan", "error": why or f"{ip} is on the never-scan list"}


def _changes(api, run_id: int) -> dict:
    r = api("GET", f"/1/cbom/sources/runs/{run_id}/changes")
    assert r.status_code == 200, r.text
    return r.json()


def _kinds(changes: dict) -> list[tuple[str, str | None, str | None]]:
    return sorted((e["kind"], (e.get("detail") or {}).get("target"), e.get("code")) for e in changes["events"]
                  if e["kind"] != "cert_expiring")


# ----------------------------------------------------------------------------- outcome and drift
def test_f1_a_never_scan_address_in_a_range_keeps_the_range_comparable_and_a_fix_resolves(api, world):
    """KF-12 / R3 test_f1. dev: the job is ``partial`` (``skipped 1``), not comparable, so ``events []``: the fix of
    .1 is never recorded, and the run reads "partial" because of the customer's own list."""
    sid, token = _range(api)
    first = _run(api, sid, "network", token, [_tls("10.232.0.1", WEAK), _tls("10.232.0.2", WEAK)], _ok(*ADDRS))
    _changes(api, first)
    _never_scan(api, "10.232.0.2")
    second = _run(api, sid, "network", token, [_tls("10.232.0.1", FIXED)],
                  _ok("10.232.0.0", "10.232.0.1", "10.232.0.3") + [_skipped("10.232.0.2")])
    run = api("GET", f"/1/cbom/sources/runs/{second}").json()["run"]
    assert run["status"] == "done" and run["jobs"][0]["outcome"] == "ok"
    assert run["jobs"][0]["result"].get("excluded_by_policy") == 1
    changes = _changes(api, second)
    # .1 was fixed: resolved. .2 went onto the list: not removed, its finding not resolved
    assert _kinds(changes) == [("resolved", "10.232.0.1", "PROTO_TLS10")]
    excluded = changes["excluded"]
    assert [e["target"] for e in excluded] == ["10.232.0.2"] and changes["excluded_count"] == 1
    assert excluded[0]["reason"].startswith("excluded by policy") and "PROTO_TLS10" in excluded[0]["codes"]
    assert changes["not_read"] == []
    diff = api("GET", f"/1/cbom/sources/runs/{second}/diff?against={first}").json()
    assert diff["sources"][0]["status"] == "compared"
    assert diff["removed"] == [] and [r["target"] for r in diff["resolved"]] == ["10.232.0.1"]
    assert [e["target"] for e in diff["excluded"]] == ["10.232.0.2"] and diff["counts"]["excluded"] == 1


def test_a_target_back_off_the_list_is_back_in_scope_not_new_and_its_finding_not_reopened(api, world):
    """dev: the run with the exclusion is not comparable, so the run after it compares with the run before it and
    nothing is said about the exclusion at all. Now: the excluded run is the baseline; .2 is carried through it at its
    last known state, so when it is read again nothing about it is new, opened or resolved."""
    sid, token = _range(api)
    first = _run(api, sid, "network", token, [_tls("10.232.0.1", WEAK), _tls("10.232.0.2", WEAK)], _ok(*ADDRS))
    _changes(api, first)
    _never_scan(api, "10.232.0.2")
    second = _run(api, sid, "network", token, [_tls("10.232.0.1", WEAK)],
                  _ok("10.232.0.0", "10.232.0.1", "10.232.0.3") + [_skipped("10.232.0.2")])
    assert _kinds(_changes(api, second)) == []
    _never_scan(api)
    third = _run(api, sid, "network", token, [_tls("10.232.0.1", WEAK), _tls("10.232.0.2", WEAK)], _ok(*ADDRS))
    changes = _changes(api, third)
    assert _kinds(changes) == [] and changes["excluded"] == []
    diff = api("GET", f"/1/cbom/sources/runs/{third}/diff").json()
    assert diff["against_run_id"] == second  # the excluded run is a baseline now (dev: run 1)
    assert diff["added"] == [] and diff["opened"] == [] and diff["removed"] == []


def test_a_target_never_read_before_its_exclusion_is_back_in_scope_not_a_new_asset(api, world):
    """A target excluded from the very first run is read for the first time once it leaves the list: its asset is
    "back in scope" (no ``new_asset`` event); its findings are opened, labelled with the reason. dev: the first run is
    not comparable, so nothing is compared and nothing says why the asset appeared."""
    sid, token = _range(api)
    _never_scan(api, "10.232.0.2")
    first = _run(api, sid, "network", token, [_tls("10.232.0.1", WEAK)],
                 _ok("10.232.0.0", "10.232.0.1", "10.232.0.3") + [_skipped("10.232.0.2")])
    _changes(api, first)
    _never_scan(api)
    second = _run(api, sid, "network", token, [_tls("10.232.0.1", WEAK), _tls("10.232.0.2", WEAK)], _ok(*ADDRS))
    changes = _changes(api, second)
    kinds = _kinds(changes)
    assert ("opened", "10.232.0.2", "PROTO_TLS10") in kinds and {k for k, _t, _c in kinds} == {"opened"}
    assert all(e["detail"]["reason"].startswith("back in scope") for e in changes["events"] if e["kind"] == "opened")
    diff = api("GET", f"/1/cbom/sources/runs/{second}/diff").json()
    assert diff["added"] == [] and [a["target"] for a in diff["entered_scope"]] == ["10.232.0.2"]


def test_never_scan_addresses_past_the_nodes_target_rows_are_excluded_too(api, world):
    """The node lists 1,000 target rows and folds the rest into one "summary" row. An address on the list beyond them
    is matched by the job's never-scan snapshot: still excluded, never removed. dev: the job is partial, not compared."""
    sid, token = _range(api)
    first = _run(api, sid, "network", token, [_tls("10.232.0.1", WEAK), _tls("10.232.0.2", WEAK)], _ok(*ADDRS))
    _changes(api, first)
    _never_scan(api, "10.232.0.2/31")
    summary = {"target": "+2 more", "status": "summary", "error": json.dumps({"skipped_never_scan": 2})}
    second = _run(api, sid, "network", token, [_tls("10.232.0.1", WEAK)], _ok("10.232.0.0", "10.232.0.1") + [summary])
    changes = _changes(api, second)
    assert _kinds(changes) == [] and [e["target"] for e in changes["excluded"]] == ["10.232.0.2"]
    job = api("GET", f"/1/cbom/sources/runs/{second}").json()["run"]["jobs"][0]
    assert job["outcome"] == "ok" and job["result"]["excluded_by_policy"] == 2


def test_a_real_failure_still_makes_the_job_partial_and_not_comparable(api, world):
    """Only the customer's list is excused: a refused or skipped-for-the-window target still counts."""
    sid, token = _range(api)
    _run(api, sid, "network", token, [_tls("10.232.0.1", WEAK)], _ok(*ADDRS))
    _never_scan(api, "10.232.0.2")
    second = _run(api, sid, "network", token, [_tls("10.232.0.1", FIXED)],
                  _ok("10.232.0.0", "10.232.0.1") + [_skipped("10.232.0.2"),
                                                     {"target": "10.232.0.3", "status": "skipped_window"}])
    job = api("GET", f"/1/cbom/sources/runs/{second}").json()["run"]["jobs"][0]
    assert job["outcome"] == "partial"
    diff = api("GET", f"/1/cbom/sources/runs/{second}/diff").json()
    assert "against_run_id" in diff and diff.get("against_run_id") is None  # nothing comparable: no baseline


# ----------------------------------------------------------------------------- pricing
def _servers(api, targets: list[str]) -> tuple[int, str]:
    node_id, token, _ = enroll_node(api)
    _never_scan(api)
    src = api("POST", "/1/cbom/sources/items", json={
        "kind": "linux_servers", "name": "linux-dc", "node_id": node_id,
        "config": {"targets": targets, "window": "any", "credential_type": "password", "login_user": "zs-cbom",
                   "host_key_policy": "pinned", "known_hosts": KNOWN_HOSTS},
        "secrets": {"password": PASSWORD}})
    assert src.status_code == 201, src.text
    return src.json()["source"]["id"], token


EIGHT = [f"10.20.0.{i}" for i in range(1, 9)]


def test_r2_a_listed_host_name_the_node_resolves_to_a_target_is_not_charged(api, world):
    """R2's estimate test. dev: 8 targets charged (1.60), the node blocks 10.20.0.8 (canary.lab), and the run keeps
    the whole charge with the job ``partial``. Now the blocked target is refunded when the job ends: 7 charged."""
    sid, token = _servers(api, ["10.20.0.1-10.20.0.8"])
    _never_scan(api, "canary.lab")
    plan = api("POST", "/1/cbom/sources/estimate", json={"include": {"servers": True}, "source_ids": [sid]})
    assert plan.status_code == 200, plan.text
    item = plan.json()["items"][0]
    assert item["units"] == 8 and item["credits"] == 1.6  # the server cannot resolve the name: the node does
    assert "never-scan" in (item.get("note") or "") and "refunded" in item["note"]
    run_id = _run(api, sid, "servers", token, [], _ok(*EIGHT[:7]) + [
        _skipped("10.20.0.8", "10.20.0.8 is an address of canary.lab, which is on the never-scan list")])
    run = api("GET", f"/1/cbom/sources/runs/{run_id}").json()["run"]
    job = run["jobs"][0]
    assert job["outcome"] == "ok" and job["result"]["excluded_by_policy"] == 1
    assert run["credits"] == {"charged": 1.6, "refunded": 0.2, "net": 1.4}  # 7 targets


def test_a_target_the_estimate_already_left_out_is_not_refunded_twice(api, world):
    """An address on the list is subtracted before the charge (7 units); the node still reports it skipped. No
    refund: it was never charged."""
    sid, token = _servers(api, ["10.20.0.1-10.20.0.8"])
    _never_scan(api, "10.20.0.8")
    run_id = _run(api, sid, "servers", token, [], _ok(*EIGHT[:7]) + [_skipped("10.20.0.8")])
    run = api("GET", f"/1/cbom/sources/runs/{run_id}").json()["run"]
    assert run["credits"] == {"charged": 1.4, "refunded": 0, "net": 1.4}
    assert run["jobs"][0]["outcome"] == "ok"


# ----------------------------------------------------------------------------- Q0 scope items and exports
def _excluded_run(api) -> int:
    sid, token = _range(api)
    _never_scan(api, "10.232.0.2/31")
    summary = {"target": "+1 more", "status": "summary", "error": json.dumps({"skipped_never_scan": 1})}
    return _run(api, sid, "network", token, [_tls("10.232.0.1", WEAK)],
                _ok("10.232.0.0", "10.232.0.1") + [_skipped("10.232.0.2"), summary])


def test_q0_scope_items_say_excluded_by_policy_not_gap(api, world):
    """dev: the listed address is an ``excluded_by_choice`` item with the detail "on the never-scan list", like a
    disabled source, and the never-scan count in the node's summary row is dropped. Now both are labelled
    "excluded by policy" (``policy`` true). The reason code stays the signed model's rule 1 code (OA-10a)."""
    run_id = _excluded_run(api)
    p = api("GET", f"/1/cbom/sources/runs/{run_id}/posture").json()["posture"]
    items = [i for i in p["q0_items"] if i.get("policy")]
    assert sorted((i["target"], i["count"]) for i in items) == [("*", 1), ("10.232.0.2", 1)]
    assert all(i["label"] == "excluded by policy" and i["detail"].startswith("excluded by policy") for i in items)
    assert all(i["reason"] == "excluded_by_choice" for i in items)
    assert not [i for i in p["q0_items"] if i["reason"] == "coverage_gap"]


def test_the_cyclonedx_export_marks_never_scan_targets_excluded_not_gaps(api, world):
    """dev: ``zs:gap`` = "lab: 10.232.0.2 skipped_never_scan" (a gap), no exclusion property."""
    run_id = _excluded_run(api)
    bom = api("GET", f"/1/cbom/sources/runs/{run_id}/cbom").json()
    props = bom["metadata"]["properties"]
    gaps = [p["value"] for p in props if p["name"] == "zs:gap"]
    assert not [g for g in gaps if "never_scan" in g or "10.232.0.2" in g]
    excluded = [json.loads(p["value"]) for p in props if p["name"] == "zs:excluded"]
    assert {"source": "lab", "target": "10.232.0.2", "reason": "excluded by policy: on the never-scan list"} in excluded
    assert {"name": "zs:excluded_count", "value": "2"} in props  # the listed one and the one in the summary row
    q0 = [json.loads(p["value"]) for p in props if p["name"] == "zs:q0_gap"]
    listed = [g for g in q0 if g["key"].endswith(":10.232.0.2:excluded") or g["key"].endswith(":*:excluded")]
    assert len(listed) == 2 and all(g["policy"] is True and g["label"] == "excluded by policy" for g in listed)
