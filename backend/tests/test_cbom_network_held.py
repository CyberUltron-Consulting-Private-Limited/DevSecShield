"""Minor 2 of the #250 review: a never-scan host name that a scan node cannot resolve holds every job of the team on
that node (fail closed).  The settings answer now says so (``never_scan_held``), from what the node already reports
in each job result (``never_scan_unresolved``): which name, which node, since when, and the latest job."""
from __future__ import annotations

import datetime as dt
import re

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


# --------------------------------------------------------------------------- #298 review
def _setup_held(api, name="dc-mumbai-01"):
    node_id, token, _ = enroll_node(api, name=name)
    api("PATCH", "/1/cbom/sources/settings", json={"scan_window": ALL_HOURS, "network_exclusions": [
        {"cidr": "shop.lab", "reason": "payments"}]})
    api("POST", "/1/cbom/sources/items", json={"kind": "network_range", "name": f"lab-{node_id}", "node_id": node_id,
                                              "config": {"cidr": "10.232.0.0/24", "mode": "full"}})
    return node_id, token


def _add_job(world, node_id, *, status="success", result=None, kind="collect", source_kind=None, at=None):
    """A finished job of the node written straight to the store (Stop all, expiry and other kinds of source)."""
    from backend.new_models import CbomCollectionJob, CbomCollectionSource
    from sqlmodel import Session
    engine, ids = world
    at = at or dt.datetime.now(dt.UTC).replace(tzinfo=None)
    with Session(engine) as s:
        source_id = None
        if source_kind:
            src = CbomCollectionSource(team_id=1, kind=source_kind, name=f"{source_kind}-{at.timestamp()}",
                                       name_lower=f"{source_kind}-{at.timestamp()}", node_id=node_id, owner_user_id=ids["alice"],
                                       config={"provider": "pkcs11"} if source_kind == "key_manager" else {})
            s.add(src)
            s.flush()
            source_id = src.id
        job = CbomCollectionJob(team_id=1, node_id=node_id, source_id=source_id, kind=kind, status=status,
                                claimed_at=at, finished_at=at, result=result)
        s.add(job)
        s.commit()
        return job.id


def test_jobs_that_checked_no_address_neither_end_a_hold_nor_restart_its_since(api, world):
    """Stop all (no result), an expired job, a PKCS#11 token job and a new node's job that reached no address say
    nothing about the name: the badge stays, from the first held job."""
    node_id, token = _setup_held(api)
    first = _run_discovery(api, token, ["shop.lab"])
    since = _held(api)[0]["since"]
    later = dt.datetime.now(dt.UTC).replace(tzinfo=None) + dt.timedelta(minutes=5)
    _add_job(world, node_id, kind="discovery", status="cancelled", result=None, at=later)  # Stop all
    second = _run_discovery(api, token, ["shop.lab"])  # the hold goes on across the stopped job
    _add_job(world, node_id, kind="discovery", status="expired", result=None, at=later + dt.timedelta(minutes=1))
    _add_job(world, node_id, source_kind="key_manager", at=later + dt.timedelta(minutes=2),
             result={"summary": "1 of 1 tokens ready", "counts": {"total": 1, "ok": 1, "failed": 0, "skipped": 0}})
    _add_job(world, node_id, kind="discovery", at=later + dt.timedelta(minutes=3),
             result={"counts": {"total": 254, "ok": 0, "failed": 0, "skipped": 254}, "never_scan_checked": False})
    (held,) = _held(api)
    assert held["name"] == "shop.lab" and held["job_id"] == second and held["since"] == since and first != second
    # a job that did check addresses and no longer names it still ends the hold
    _add_job(world, node_id, kind="discovery", at=later + dt.timedelta(minutes=4),
             result={"counts": {"total": 254, "ok": 254, "failed": 0, "skipped": 0}, "never_scan_checked": True})
    assert _held(api) == []


def test_the_held_query_reads_two_json_fields_never_the_whole_result(api, world):
    from backend.utilities.cbom_sources import held as H
    from sqlalchemy import event
    from sqlalchemy.dialects import postgresql

    pg = str(H.held_jobs_query(1).compile(dialect=postgresql.dialect()))
    assert "cbomcollectionjob.result -> " in pg and "cbomcollectionjob.result #> " in pg
    assert "row_number() OVER (PARTITION BY cbomcollectionjob.node_id" in pg
    selected = re.sub(r"cbomcollectionjob\.result (->|#>) %\(\w+\)s", "<path>", pg.split(" FROM ", 1)[0])
    assert selected.count("<path>") == 3 and "cbomcollectionjob.result" not in selected  # never the whole column
    _node_id, token = _setup_held(api)
    _run_discovery(api, token, ["shop.lab"])
    engine, _ids = world
    seen: list[str] = []
    listener = lambda conn, cursor, statement, *a: seen.append(statement)
    event.listen(engine, "before_cursor_execute", listener)
    try:
        assert [h["name"] for h in _held(api)] == ["shop.lab"]
    finally:
        event.remove(engine, "before_cursor_execute", listener)
    (query,) = [q for q in seen if "row_number()" in q]  # the JSON paths themselves are bound parameters
    selected = query.split(" FROM ", 1)[0].replace("JSON_EXTRACT(cbomcollectionjob.result, ?)", "<path>")
    assert selected.count("<path>") == 3 and "cbomcollectionjob.result" not in selected


def test_a_busy_node_does_not_push_a_quiet_nodes_hold_out_of_the_window(api, world):
    quiet, token = _setup_held(api)
    busy, _token, _reg = enroll_node(api, name="dc-pune-02")
    _run_discovery(api, token, ["shop.lab"])
    from backend.new_models import CbomCollectionJob
    from sqlmodel import Session
    engine, _ids = world
    now = dt.datetime.now(dt.UTC).replace(tzinfo=None) + dt.timedelta(minutes=1)
    with Session(engine) as s:  # 600 newer jobs on the other node (more than the old team-wide window of 500)
        s.add_all([CbomCollectionJob(team_id=1, node_id=busy, kind="discovery", status="success",
                                     claimed_at=now + dt.timedelta(seconds=i), finished_at=now + dt.timedelta(seconds=i),
                                     result={"counts": {"total": 1, "ok": 1}, "never_scan_checked": True})
                   for i in range(600)])
        s.commit()
    assert [(h["name"], h["node_id"]) for h in _held(api)] == [("shop.lab", quiet)]
