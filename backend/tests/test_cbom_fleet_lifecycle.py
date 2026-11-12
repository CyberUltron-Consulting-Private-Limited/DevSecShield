"""F1.2 fleet lifecycle (PR #80 review 5874269505): deletes stop collection, removal never waits for a busy source and
deferred additions are retried, fair inventory syncs, evaluation kept off the request path for large teams, preview
equal to save, one owner per external id, and the AWS lister's edges (fail-fast, tail regions, caps).

Real routers, real JWTs, SQLite (``test_cbom_sources_api`` world); moto 5 for AWS.
"""
from __future__ import annotations

import datetime as dt
import json
import random
from types import SimpleNamespace

import pytest
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine, select

from test_cbom_sources_api import api, enroll_node, world
from test_cbom_fleet_policies import FLEET, INV, _credential, _managed, _policy, _targets
from backend.new_models import CbomCollectionJob, CbomCollectionSchedule, CbomCollectionSettings
from backend.utilities.cbom_sources.fleet import aws_inventory, store
from backend.utilities.cbom_sources.fleet import sync as SYNC
from backend.utilities.cbom_sources.fleet.inventory_sources import InventoryError, normalize
from backend.utilities.cbom_sources.fleet.models import CbomFleetTeamState, CbomInventorySource, CbomInventoryTarget
from backend.utilities.cbom_sources.fleet.policy import PolicyEngine, Refs, compile_selector, matches, validate_selector
from backend.workers import cbom_inventory_sync

FIXTURES = (api, world)


@pytest.fixture(autouse=True)
def _flags(monkeypatch):
    for name in ("CBOM_FLEET_TRANSPORTS", "CBOM_SSH_CA", "CBOM_FLEET_INLINE_EVAL_MAX"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("CBOM_FLEET_INVENTORY", "1")
    monkeypatch.setenv("CBOM_FLEET_POLICIES", "1")
    monkeypatch.setenv("CBOM_FLEET_MATERIALIZE", "1")


def _addresses_in_managed(engine) -> set[str]:
    return {line for s in _managed(engine) for line in (s.config or {}).get("targets", [])}


def _collect_all(api, **extra):
    node_id, _tok, _reg = enroll_node(api)
    cred = _credential(api)
    return node_id, cred, _policy(api, "collect-all", 10, {}, {"transport": "ssh", "credential_id": cred["id"],
                                                                 "node_id": node_id, **extra})


def _target(api, external_id):
    return next(t for t in api("GET", f"{INV}/targets", params={"missing": "all"}).json()["targets"]
                if t["external_id"] == external_id)


# ----------------------------------------------------------------------------- deletes (major 1)
def test_a_deleted_target_leaves_its_managed_source_and_comes_back_only_when_listed_again(api, world):
    engine, _ = world
    _targets(api, 3)
    _collect_all(api)
    api("POST", f"{FLEET}/reconcile")
    assert "10.2.0.1" in _addresses_in_managed(engine)
    h0 = _target(api, "h0")
    assert api("DELETE", f"{INV}/targets/{h0['id']}").status_code == 200
    out = api("POST", f"{FLEET}/reconcile").json()
    detail = api("GET", f"{INV}/targets/{h0['id']}").json()
    assert "10.2.0.1" not in _addresses_in_managed(engine), out
    assert detail["decision"]["action"] == "unmanaged" and "removed from the inventory" in detail["decision"]["reason"]
    assert detail["target"]["deleted_at"] is not None and detail["target"]["managed_source_id"] is None
    # unlike a target a sync missed (7 days of grace), a deleted one is out at once; its source listing it again
    # brings it back
    _targets(api, 3)
    api("POST", f"{FLEET}/reconcile")
    assert "10.2.0.1" in _addresses_in_managed(engine) and _target(api, "h0")["deleted_at"] is None


def test_deleting_an_inventory_source_stops_collecting_its_targets(api, world):
    engine, _ = world
    _targets(api, 3)
    _collect_all(api)
    api("POST", f"{FLEET}/reconcile")
    assert len(_addresses_in_managed(engine)) == 3
    sid = api("GET", f"{INV}/sources").json()["sources"][0]["id"]
    gone = api("DELETE", f"{INV}/sources/{sid}").json()
    assert gone["targets_removed"] == 3
    api("POST", f"{FLEET}/reconcile")
    assert _addresses_in_managed(engine) == set() and _managed(engine) == []
    assert {t["decision"]["action"] for t in api("GET", f"{INV}/targets", params={"missing": "all"}).json()["targets"]} \
        == {"unmanaged"}


# ----------------------------------------------------------------------------- busy sources (major 2)
def test_a_never_scan_policy_takes_targets_out_of_a_busy_source_at_once(api, world):
    """Removal never waits behind a busy source: the source is edited (or removed) now and its open job, created for
    the old target list, is cancelled, so neither the job nor the policy's schedule collects a never-scan target."""
    engine, _ = world
    _targets(api, 3)
    _node, _cred, a = _collect_all(api, schedule={"frequency": "daily", "time_of_day": "02:00"})
    api("POST", f"{FLEET}/reconcile")
    src = _managed(engine)[0]
    with Session(engine) as s:
        s.add(CbomCollectionJob(team_id=1, run_id=None, source_id=src.id, node_id=src.node_id, kind="collect",
                                status="pending", params={}))
        s.commit()
    _policy(api, "prod-never", 90, {"tag": "env", "op": "eq", "value": "prod"}, {"never_scan": True})
    out = api("POST", f"{FLEET}/reconcile").json()
    shown = {t["decision"]["action"] for t in api("GET", f"{INV}/targets").json()["targets"]}
    assert shown == {"never_scan"} and _addresses_in_managed(engine) == set(), out
    with Session(engine) as s:
        assert s.exec(select(CbomCollectionJob).where(CbomCollectionJob.status == "pending")).all() == []
        assert s.exec(select(CbomCollectionSchedule).where(CbomCollectionSchedule.policy_id == a["id"])).all() == []
    assert out["deferred"] == 0 and out["sources_removed"] == 1


def test_an_addition_deferred_by_a_busy_source_is_retried_by_the_fleet_worker(api, world):
    engine, _ = world
    _targets(api, 3)
    _collect_all(api)
    api("POST", f"{FLEET}/reconcile")
    src = _managed(engine)[0]
    with Session(engine) as s:
        job = CbomCollectionJob(team_id=1, run_id=None, source_id=src.id, node_id=src.node_id, kind="collect",
                                status="claimed", params={})
        s.add(job)
        s.commit()
        job_id = job.id
    _targets(api, 4)  # h3 arrives while the source's job runs
    out = api("POST", f"{FLEET}/reconcile").json()
    assert out["deferred"] == 1 and "10.2.0.4" not in _addresses_in_managed(engine)
    assert _target(api, "h3")["pending"] is True
    with Session(engine) as s:
        st = s.exec(select(CbomFleetTeamState).where(CbomFleetTeamState.team_id == 1)).one()
        assert st.reconcile_requested_at is not None  # the worker will try again
        retry_at = st.reconcile_requested_at
    assert cbom_inventory_sync.fleet_tick(engine, now=retry_at - dt.timedelta(seconds=1)) == []  # not yet
    still_busy = cbom_inventory_sync.fleet_tick(engine, now=retry_at)
    assert still_busy[0]["status"] == "reconciled" and still_busy[0]["deferred"] == 1
    with Session(engine) as s:  # the job ends
        s.get(CbomCollectionJob, job_id).status = "success"
        s.commit()
        retry_at = s.exec(select(CbomFleetTeamState)).one().reconcile_requested_at
    done = cbom_inventory_sync.fleet_tick(engine, now=retry_at)
    assert done[0]["deferred"] == 0 and done[0]["sources_updated"] == 1
    assert "10.2.0.4" in _addresses_in_managed(engine) and _target(api, "h3")["pending"] is False
    with Session(engine) as s:
        assert s.exec(select(CbomFleetTeamState)).one().reconcile_requested_at is None


def test_a_policy_write_asks_the_fleet_worker_to_reconcile(api, world):
    engine, _ = world
    _targets(api, 2)
    _collect_all(api)
    assert _managed(engine) == []  # the write did not materialise anything in the request
    ran = cbom_inventory_sync.fleet_tick(engine, now=dt.datetime.now(dt.timezone.utc).replace(tzinfo=None))
    assert ran[0]["status"] == "reconciled" and ran[0]["sources_created"] == 1
    assert len(_addresses_in_managed(engine)) == 2


def test_the_daily_pass_takes_a_target_out_after_its_seven_days_without_any_write(api, world):
    """The 7-day rule moves with time: the worker re-evaluates and reconciles a team it last evaluated a day ago, so a
    target its sync stopped listing more than 7 days ago leaves its managed source though nobody touched the team."""
    engine, _ = world
    _targets(api, 3)
    _collect_all(api)
    api("POST", f"{FLEET}/reconcile")
    assert "10.2.0.1" in _addresses_in_managed(engine)
    now = dt.datetime.now(dt.timezone.utc).replace(tzinfo=None)
    with Session(engine) as s:
        row = s.exec(select(CbomInventoryTarget).where(CbomInventoryTarget.external_id == "h0")).one()
        row.missing_since = now - dt.timedelta(days=8)
        st = s.exec(select(CbomFleetTeamState)).one()
        st.eval_requested_at = st.reconcile_requested_at = None
        st.evaluated_at = now - dt.timedelta(hours=23)
        s.commit()
    assert cbom_inventory_sync.fleet_tick(engine, now=now) == []  # evaluated less than a day ago: nothing due
    with Session(engine) as s:
        s.exec(select(CbomFleetTeamState)).one().evaluated_at = now - dt.timedelta(hours=25)
        s.commit()
    ran = cbom_inventory_sync.fleet_tick(engine, now=now)
    assert ran[0]["status"] == "reconciled" and ran[0]["sources_updated"] == 1, ran
    assert "10.2.0.1" not in _addresses_in_managed(engine) and len(_addresses_in_managed(engine)) == 2
    assert "more than 7 days" in _target(api, "h0")["decision"]["reason"]
    assert cbom_inventory_sync.fleet_tick(engine, now=now) == []  # done for the day


# ----------------------------------------------------------------------------- stickiness (M21) and ownership (M13)
def test_removing_a_target_from_the_first_batch_moves_nothing_else(api, world):
    engine, _ = world
    _targets(api, 75)
    _collect_all(api, batch_size=25)
    api("POST", f"{FLEET}/reconcile")
    before = {s.id: list(s.config["targets"]) for s in _managed(engine)}
    assert [len(v) for v in before.values()] == [25, 25, 25]
    first = min(before)
    victim = _target(api, "h0")
    api("DELETE", f"{INV}/targets/{victim['id']}")
    out = api("POST", f"{FLEET}/reconcile").json()
    after = {s.id: list(s.config["targets"]) for s in _managed(engine)}
    assert out["sources_updated"] == 1 and out["targets_assigned"] == 0, out
    assert after[first] == [a for a in before[first] if a != "10.2.0.1"]
    assert {k: v for k, v in after.items() if k != first} == {k: v for k, v in before.items() if k != first}
    _targets(api, 76, start=0)  # h0 back plus h75: they fill the batch with room; batches 2..n are untouched
    api("POST", f"{FLEET}/reconcile")
    again = {s.id: list(s.config["targets"]) for s in _managed(engine)}
    assert {k: v for k, v in again.items() if k != first and k in before} == \
        {k: v for k, v in before.items() if k != first}


def test_one_owner_per_external_id(api, world):
    row = {"external_id": "shared-1", "address": "10.8.0.1", "tags": {"env": "prod"}}
    csv_file = "external_id,address,tag:env\nshared-1,10.8.0.1,prod\n"
    first = api("POST", f"{INV}/import", json={"format": "csv", "content": csv_file}).json()
    put = api("PUT", f"{INV}/targets", json={"source_name": "cmdb", "targets": [row]}).json()
    again = api("POST", f"{INV}/import", json={"format": "csv", "content": csv_file}).json()
    put2 = api("PUT", f"{INV}/targets", json={"source_name": "cmdb", "targets": [row]}).json()
    assert first["created"] == 1 and (again["updated"], again["unchanged"]) == (0, 1)
    assert (put["created"], put["updated"], put["skipped"]) == (0, 0, 1) and put2["skipped"] == 1
    assert "belongs to inventory source 'CSV import'" in put["errors"][0]["error"]
    # the owner stops listing it: the other source takes it over at its next import
    empty = api("POST", f"{INV}/import", json={"format": "csv", "content": "external_id,address\nother,10.8.0.2\n"}).json()
    assert empty["missing"] == 1
    taken = api("PUT", f"{INV}/targets", json={"source_name": "cmdb", "targets": [row]}).json()
    assert (taken["updated"], taken["skipped"]) == (1, 0)
    sources = {s["name"]: s["id"] for s in api("GET", f"{INV}/sources").json()["sources"]}
    assert _target(api, "shared-1")["inventory_source_id"] == sources["cmdb"]
    assert api("PUT", f"{INV}/targets", json={"source_name": "cmdb", "targets": [row]}).json()["unchanged"] == 1


# ----------------------------------------------------------------------------- evaluation off the request path (major 4)
def test_a_large_team_is_evaluated_by_the_worker_and_reads_serve_the_stored_decisions(api, world, monkeypatch):
    engine, _ = world
    monkeypatch.setenv("CBOM_FLEET_MATERIALIZE", "0")
    monkeypatch.setenv("CBOM_FLEET_INLINE_EVAL_MAX", "2")  # "large": more than 2 targets
    _targets(api, 5)
    node_id, _tok, _reg = enroll_node(api)
    cred = _credential(api)
    calls = {"n": 0}
    real = store.refresh_decisions

    def counting(*a, **k):
        calls["n"] += 1
        return real(*a, **k)

    monkeypatch.setattr(store, "refresh_decisions", counting)
    r = api("POST", f"{FLEET}/policies", json={"name": "prod", "priority": 10,
                                               "selector": {"tag": "env", "op": "eq", "value": "prod"},
                                               "action": {"transport": "ssh", "credential_id": cred["id"],
                                                          "node_id": node_id}})
    assert r.status_code == 201 and r.json()["evaluation"] == "queued" and calls["n"] == 0
    listed = api("GET", f"{FLEET}/policies").json()
    assert listed["evaluation"]["stale"] is True and listed["policies"][0]["matched_targets"] == 0
    page = api("GET", f"{INV}/targets", params={"decision": "collect"}).json()
    assert page["total"] == 0 and page["evaluation"]["stale"] is True and calls["n"] == 0  # no evaluation in reads
    ran = cbom_inventory_sync.fleet_tick(engine)
    assert ran[0]["status"] == "evaluated" and ran[0]["decisions_changed"] == 5 and calls["n"] == 1
    listed = api("GET", f"{FLEET}/policies").json()
    assert listed["evaluation"]["stale"] is False
    assert (listed["policies"][0]["matched_targets"], listed["policies"][0]["won_targets"]) == (5, 5)
    page = api("GET", f"{INV}/targets", params={"decision": "collect", "limit": 2}).json()
    assert page["total"] == 5 and len(page["targets"]) == 2 and page["next_cursor"] is not None
    assert cbom_inventory_sync.fleet_tick(engine) == []  # nothing asked for any more


def test_preview_equals_what_saving_decides(api, world):
    """Preview evaluates only the targets the draft matches; whatever the draft, its numbers equal what saving it
    makes of the targets (random tags, random selectors, ties, an edit and a new draft)."""
    rng = random.Random(812)
    node_id, _tok, _reg = enroll_node(api)
    cred = _credential(api)
    rows = [{"external_id": f"r{i}", "address": f"10.5.{i // 250}.{i % 250 + 1}",
             "tags": {k: rng.choice(["a", "b", "c"]) for k in rng.sample(["env", "team", "app", "zone"], 3)}}
            for i in range(120)]
    api("POST", f"{INV}/import", json={"format": "json", "content": json.dumps(rows)})
    ssh = {"transport": "ssh", "credential_id": cred["id"], "node_id": node_id}

    def sel():
        leaves = [{"tag": rng.choice(["env", "team", "app", "zone"]), "op": rng.choice(["eq", "ne", "exists"]),
                   "value": rng.choice(["a", "b", "c"])} for _ in range(rng.randint(1, 2))]
        for leaf in leaves:
            if leaf["op"] == "exists":
                leaf.pop("value")
        return {"all": leaves} if len(leaves) > 1 else leaves[0]

    for i in range(6):
        _policy(api, f"p{i}", rng.choice([10, 20, 30]), sel(), {"never_scan": True} if i % 3 == 0 else ssh)
    for trial in range(6):
        body = {"name": f"d{trial}", "priority": rng.choice([10, 20, 30]), "selector": sel(),
                "action": {"never_scan": True} if trial % 2 else ssh}
        edit = trial >= 3
        target_id = api("GET", f"{FLEET}/policies").json()["policies"][trial]["id"] if edit else None
        prev = api("POST", f"{FLEET}/policies/preview",
                   json={"policy": body, **({"policy_id": target_id} if edit else {})}).json()
        if edit:
            saved = api("PATCH", f"{FLEET}/policies/{target_id}", json={k: body[k] for k in ("priority", "selector", "action")})
            pid = saved.json()["policy"]["id"]
        else:
            pid = api("POST", f"{FLEET}/policies", json=body).json()["policy"]["id"]
        targets = api("GET", f"{INV}/targets", params={"limit": 500}).json()["targets"]
        mine = [t for t in targets if pid in t["decision"]["matched_policy_ids"]]
        assert prev["matched"] == len(mine), (trial, prev)
        assert prev["would_collect"] == sum(1 for t in mine if t["decision"]["policy_id"] == pid
                                            and t["decision"]["action"] == "collect"), trial
        assert prev["never_scan"] == sum(1 for t in mine if t["decision"]["action"] == "never_scan"), trial
        if not edit:  # keep the number of policies small
            api("DELETE", f"{FLEET}/policies/{pid}")


def test_preview_from_the_stored_decisions_equals_preview_by_evaluating_every_policy(api, world, monkeypatch):
    """While the stored decisions are current, preview takes the other policies' matches from them and runs only the
    draft's selector; the answer is the one evaluating every policy gives (new drafts, edits, ties, disabled drafts,
    a never-scan list).  Once an evaluation is pending, preview evaluates."""
    from backend.routers import cbom_fleet_policies as POL
    from backend.utilities.cbom_sources import http as cbom_http
    from backend.utilities.cbom_sources.fleet.policy import PolicyEngine

    rng = random.Random(2024)
    node_id, _tok, _reg = enroll_node(api)
    cred = _credential(api)
    keys, vals = ["env", "team", "app", "aws:cloudformation:stack-name"], ["a", "b", "c"]
    rows = [{"external_id": f"s{i}", "address": f"10.6.{i // 250}.{i % 250 + 1}",
             "tags": {k: rng.choice(vals) for k in rng.sample(keys, rng.randint(0, 4))}} for i in range(150)]
    api("POST", f"{INV}/import", json={"format": "json", "content": json.dumps(rows)})
    with Session(world[0]) as s:  # a never-scan list (the policy writes below evaluate with it)
        settings = s.exec(select(CbomCollectionSettings).where(CbomCollectionSettings.team_id == 1)).one()
        settings.network_exclusions = [{"cidr": "10.6.0.7"}]
        s.add(settings)
        s.commit()
    ssh = {"transport": "ssh", "credential_id": cred["id"], "node_id": node_id}

    def sel():
        def leaf():
            op = rng.choice(["eq", "ne", "in", "exists", "prefix"])
            node = {"tag": rng.choice(keys), "op": op}
            if op == "in":
                node["value"] = rng.sample(vals, 2)
            elif op != "exists":
                node["value"] = rng.choice(vals)
            return node
        return rng.choice([leaf(), {"all": [leaf(), leaf()]}, {"any": [leaf(), leaf()]}, {"not": leaf()}, {}])

    for i in range(10):
        _policy(api, f"p{i}", rng.choice([10, 20, 30]), sel(), {"never_scan": True} if i % 3 == 0 else ssh)
    saved_ids = [p["id"] for p in api("GET", f"{FLEET}/policies").json()["policies"]]
    calls = {"evaluate": 0}
    real = PolicyEngine.evaluate

    def counting(self, target):
        calls["evaluate"] += 1
        return real(self, target)

    monkeypatch.setattr(PolicyEngine, "evaluate", counting)
    for trial in range(30):
        draft = {"name": f"d{trial}", "priority": rng.choice([10, 20, 30]), "selector": sel(),
                 "action": {"never_scan": True} if trial % 2 else ssh}
        if rng.random() < 0.3:
            draft["enabled"] = rng.random() < 0.5
        body = {"policy": draft}
        if trial % 3 == 1:
            body["policy_id"] = rng.choice(saved_ids)
        elif trial % 3 == 2:
            body = {"policy_id": rng.choice(saved_ids)}  # a saved policy as it is
        cbom_http.write_limiter.requests.clear()  # 60 writes a minute per user; this test sends 60 previews
        monkeypatch.setattr(POL, "PREVIEW_FROM_STORED", True)
        calls["evaluate"] = 0
        fast = api("POST", f"{FLEET}/policies/preview", json=body)
        used_stored = calls["evaluate"] == 0
        monkeypatch.setattr(POL, "PREVIEW_FROM_STORED", False)
        slow = api("POST", f"{FLEET}/policies/preview", json=body)
        assert fast.status_code == slow.status_code == 200, (trial, fast.text)
        assert fast.json() == slow.json(), (trial, body)
        assert used_stored, trial  # the decisions are current: no policy was evaluated against a target
    # a large team's write leaves the stored decisions behind until the worker runs: preview evaluates, and answers
    # with the policies as they are now
    monkeypatch.setenv("CBOM_FLEET_INLINE_EVAL_MAX", "0")
    cbom_http.write_limiter.requests.clear()
    queued = api("PATCH", f"{FLEET}/policies/{saved_ids[0]}", json={"selector": {}, "priority": 40}).json()
    assert queued["evaluation"] == "queued"
    monkeypatch.setattr(POL, "PREVIEW_FROM_STORED", True)
    calls["evaluate"] = 0
    body = {"policy": {"name": "late", "priority": 20, "selector": {}, "action": ssh}}
    pending = api("POST", f"{FLEET}/policies/preview", json=body).json()
    assert calls["evaluate"] > 0
    monkeypatch.setattr(POL, "PREVIEW_FROM_STORED", False)
    assert pending == api("POST", f"{FLEET}/policies/preview", json=body).json()


def test_preview_of_an_edit_to_a_disabled_policy_equals_saving_it(api, world):
    node_id, _tok, _reg = enroll_node(api)
    cred = _credential(api)
    _targets(api, 3)
    ssh = {"transport": "ssh", "credential_id": cred["id"], "node_id": node_id}
    p = _policy(api, "off", 10, {}, ssh)
    r = api("PATCH", f"{FLEET}/policies/{p['id']}", json={"enabled": False, "expected_version": p["row_version"]})
    assert r.status_code == 200, r.text
    body = {"name": "off", "priority": 20, "selector": {}, "action": ssh}  # the body #81's PoliciesSection sends
    prev = api("POST", f"{FLEET}/policies/preview", json={"policy": body, "policy_id": p["id"]}).json()
    saved = api("PATCH", f"{FLEET}/policies/{p['id']}", json={"priority": 20}).json()
    won = sum(1 for t in api("GET", f"{INV}/targets").json()["targets"] if t["decision"]["policy_id"] == p["id"])
    assert saved["policy"]["enabled"] is False and prev["would_collect"] == won == 0
    assert prev["enabled"] is False and prev["matched_if_enabled"] == 3
    on = api("POST", f"{FLEET}/policies/preview", json={"policy": {**body, "enabled": True}, "policy_id": p["id"]}).json()
    assert on["would_collect"] == 3


def test_compiled_selectors_match_exactly_like_the_reference_matcher():
    rng = random.Random(5)
    keys, vals = ["env", "team", "aws:cloudformation:stack-name"], ["a", "b", "ap-x"]
    for _ in range(1500):
        def leaf():
            op = rng.choice(["eq", "ne", "in", "exists", "prefix"])
            node = ({"tag": rng.choice(keys)} if rng.random() < 0.7
                    else {"field": rng.choice(["kind", "region", "platform", "account_id"])})
            node["op"] = op
            if op == "in":
                node["value"] = rng.sample(vals + ["linux_host"], 2)
            elif op != "exists":
                node["value"] = rng.choice(vals + ["linux_host"]) if op != "prefix" else rng.choice(["a", "ap-"])
            return node
        raw = rng.choice([leaf(), {"all": [leaf(), leaf()]}, {"all": [leaf(), leaf(), leaf()]},
                          {"all": [leaf(), leaf(), leaf(), leaf()]}, {"any": [leaf(), {"not": leaf()}]},
                          {"any": [leaf(), leaf(), leaf()]}, {}])
        try:
            selector = validate_selector(raw)
        except Exception:
            continue
        tags = {k: rng.choice(vals) for k in rng.sample(keys, rng.randint(0, 3))}
        target = SimpleNamespace(tags=tags, kind=rng.choice(["linux_host", "database"]), region=rng.choice([None, "ap-x"]),
                                 platform=None, account_id=rng.choice([None, "a"]))
        fields = {f: getattr(target, f) for f in ("kind", "account_id", "region", "platform")}
        assert compile_selector(selector)(tags, target) == matches(selector, tags, fields), (selector, tags, fields)


def test_the_engine_index_skips_only_policies_that_cannot_match():
    """The engine tests a target only against the policies its tags can satisfy (index_entry): the matches, their
    order and so the winner are the same as testing every policy."""
    rng = random.Random(11)
    keys, vals = ["env", "team", "app", "aws:cloudformation:stack-name"], ["a", "b", "c", "ap-x"]

    def leaf():
        op = rng.choice(["eq", "ne", "in", "exists", "prefix"])
        node = {"tag": rng.choice(keys)} if rng.random() < 0.8 else {"field": rng.choice(["region", "account_id"])}
        node["op"] = op
        if op == "in":
            node["value"] = rng.sample(vals, rng.randint(1, 3))
        elif op != "exists":
            node["value"] = rng.choice(vals) if op != "prefix" else rng.choice(["a", "ap-"])
        return node

    for _ in range(30):
        rows = []
        for i in range(1, 41):
            raw = rng.choice([leaf(), {"all": [leaf(), leaf()]}, {"all": [leaf(), leaf(), leaf()]},
                              {"any": [leaf(), leaf()]}, {"not": leaf()}, {}])
            try:
                selector = validate_selector(raw)
            except Exception:
                continue
            rows.append(SimpleNamespace(id=i, name=f"p{i}", enabled=True, deleted_at=None, priority=rng.randint(0, 5),
                                        selector=selector, action={"never_scan": True}))
        engine = PolicyEngine(rows, None)
        for _ in range(40):
            tags = {k: rng.choice(vals) for k in rng.sample(keys, rng.randint(0, 4))}
            target = SimpleNamespace(tags=tags, region=rng.choice([None, "ap-x"]), account_id=rng.choice([None, "a"]))
            every = [p.id for p in engine.policies if p.test(tags, target)]
            assert [p.id for p in engine.matching(target)] == every, (tags, every)


# ----------------------------------------------------------------------------- inventory routes (minors)
def test_tag_filter_with_a_colon_in_the_key_and_a_literal_search(api, world):
    rows = [{"external_id": "e1", "address": "10.9.0.1", "tags": {"aws:cloudformation:stack-name": "web:blue"}},
            {"external_id": "e_2", "address": "10.9.0.2", "tags": {"env": "prod"}},
            {"external_id": "e%3", "address": "10.9.0.3", "tags": {"env": "prod"}}]
    assert api("PUT", f"{INV}/targets", json={"source_name": "api", "targets": rows}).status_code == 200
    got = api("GET", f"{INV}/targets", params={"tag_key": "aws:cloudformation:stack-name", "tag_value": "web:blue"}).json()
    assert got["total"] == 1 and got["targets"][0]["external_id"] == "e1"
    assert api("GET", f"{INV}/targets", params={"tag_key": "aws:cloudformation:stack-name"}).json()["total"] == 1
    # % and _ are literal in the search box
    assert [t["external_id"] for t in api("GET", f"{INV}/targets", params={"q": "_"}).json()["targets"]] == ["e_2"]
    assert [t["external_id"] for t in api("GET", f"{INV}/targets", params={"q": "%"}).json()["targets"]] == ["e%3"]


def test_deeply_nested_json_import_is_a_400(api, world):
    r = api("POST", f"{INV}/import", json={"format": "json", "content": "[" * 200_000})
    assert r.status_code == 400 and "nested" in r.json()["detail"]


def test_attribute_names_longer_than_64_characters_are_refused():
    with pytest.raises(InventoryError, match="at most 64"):
        normalize({"address": "10.0.0.1", "attributes": {"k" * 65: 1}})
    assert dict(normalize({"address": "10.0.0.1", "attributes": {"k" * 64: 1}}).attributes) == {"k" * 64: 1}


def test_a_member_put_is_refused_before_the_rows_are_normalised(api, world, monkeypatch):
    from backend.routers import cbom_fleet_inventory as ROUTES

    seen = []
    real = ROUTES._collect
    monkeypatch.setattr(ROUTES, "_collect", lambda *a, **k: seen.append(1) or real(*a, **k))
    r = api("PUT", f"{INV}/targets", "bob", json={"source_name": "api", "targets": [{"address": "10.0.0.1"}]})
    assert r.status_code == 400 and seen == []


def test_an_ssm_target_without_an_instance_id_is_not_collected():
    refs = Refs(transports={7: None}, nodes={})
    engine = PolicyEngine([SimpleNamespace(id=1, name="ssm", priority=1, selector={}, enabled=True, deleted_at=None,
                                           action={"transport": "ssm", "transport_id": 7})], None, refs=refs)
    base = {"kind": "linux_host", "address": "10.0.0.1", "addresses": ["10.0.0.1"], "hostname": None, "tags": {},
            "missing_since": None, "deleted_at": None}
    assert engine.evaluate(SimpleNamespace(**base, handles={})).reason.endswith("no SSM instance id (handles.ssm) to "
                                                                                 "send the command to")
    assert engine.evaluate(SimpleNamespace(**base, handles={"ssm": "i-0abc"})).action == "collect"


def test_fleet_kinds_get_every_address_of_each_line(monkeypatch):
    """F1.3's FleetHostsConfig reads config['addresses'][label] for the whole-target never-scan check at dispatch."""
    from pydantic import BaseModel

    from backend.utilities.cbom_sources.fleet import materialize as M

    class FleetHosts(BaseModel):
        transport_id: int
        targets: list[str]
        handles: dict[str, str]
        addresses: dict[str, list[str]] = {}
        tier: int = 1

    monkeypatch.setitem(M.KINDS, "awx_hosts", SimpleNamespace(model=FleetHosts))
    d = SimpleNamespace(transport_id=3, tier=1)
    cfg = M._config("awx_hosts", d, ["10.0.0.1"], {"10.0.0.1": "web-1"}, None, {"10.0.0.1": ["10.0.0.1", "2001:db8::1"]})
    assert cfg.addresses == {"10.0.0.1": ["10.0.0.1", "2001:db8::1"]}


def test_a_removed_managed_source_is_removed_like_a_hand_deleted_one(api, world, monkeypatch):
    """One removal path (removal.remove_source): open jobs end, discoveries using it stop, runs stay."""
    from backend.utilities.cbom_sources import jobs as J

    engine, _ = world
    _targets(api, 2)
    _node, _cred, p = _collect_all(api)
    api("POST", f"{FLEET}/reconcile")
    stopped = []
    real = J.stop_discoveries_using
    monkeypatch.setattr(J, "stop_discoveries_using", lambda *a, **k: stopped.append(a[1].id) or real(*a, **k))
    src = _managed(engine)[0]
    api("DELETE", f"{FLEET}/policies/{p['id']}")
    assert api("POST", f"{FLEET}/reconcile").json()["sources_removed"] == 1
    assert stopped == [src.id] and _managed(engine) == []


# ----------------------------------------------------------------------------- syncs: fairness and caps (major 3, minors)
def test_every_aws_source_syncs_and_none_starves():
    """30 sources due every 15 minutes, one sync taking 150 s (the live 17-region run): one worker cannot keep up,
    but fair ordering gives every source its turn (before: sources 27-30 never synced in 6 h)."""
    db = create_engine("sqlite://", poolclass=StaticPool, connect_args={"check_same_thread": False})
    import backend.new_models  # noqa: F401

    SQLModel.metadata.create_all(db)
    t = dt.datetime(2026, 11, 12)
    with Session(db) as s:
        from backend.new_models import Team

        for i in range(30):
            s.add(Team(id=i + 1, name=f"t{i}", credit_balance=0.0))
        s.commit()
        for i in range(30):
            s.add(CbomInventorySource(team_id=i + 1, kind="aws", name=f"a{i}", config={}, sync_every_min=15))
        s.commit()
    runs: dict[int, int] = {}
    end = t + dt.timedelta(hours=6)
    while t < end:
        with Session(db) as s:
            ids = SYNC.due_ids(s, t, limit=1)
        if not ids:
            t += dt.timedelta(seconds=30)
            continue
        t += dt.timedelta(seconds=150)
        with Session(db) as s:
            row = s.get(CbomInventorySource, ids[0])
            row.last_sync_at, row.last_sync_status = t, "ok"
            s.add(row)
            s.commit()
        runs[ids[0]] = runs.get(ids[0], 0) + 1
    assert len(runs) == 30 and max(runs.values()) - min(runs.values()) <= 1, runs
    # a queued "Sync now" goes first
    with Session(db) as s:
        row = s.get(CbomInventorySource, 30)
        row.last_sync_status = "queued"
        s.add(row)
        s.commit()
        assert SYNC.due_ids(s, end + dt.timedelta(hours=1), limit=1) == [30]


def test_regions_a_sync_could_not_finish_go_first_next_time():
    cov = {"eu-west-1": {"ec2": "ok"}, "us-east-1": {"ec2": "cancelled"}, "us-west-2": {"ec2": "cancelled"}}
    assert SYNC._region_order(["eu-west-1", "us-east-1", "us-west-2"], cov) == ["us-east-1", "us-west-2", "eu-west-1"]
    assert SYNC._region_order(["eu-west-1", "us-east-1"], {}) == ["eu-west-1", "us-east-1"]


def test_an_unreachable_region_without_ec2_in_the_services_costs_one_call():
    from botocore.exceptions import ConnectTimeoutError, EndpointConnectionError

    calls = []

    class Client:
        def __init__(self, service):
            self.service = service

        def get_paginator(self, _method):
            calls.append(self.service)
            raise ConnectTimeoutError(endpoint_url=f"https://{self.service}.me-south-1.amazonaws.com/")

    acct = SimpleNamespace(account="111122223333", role_arn="arn:aws:iam::111122223333:role/r",
                           client=lambda service, region: Client(service))
    out = aws_inventory.discover_account(acct, ["me-south-1"], ["acm", "kms", "secretsmanager", "rds"])
    assert calls == ["acm"] and out.coverage["me-south-1"] == {
        "acm": "unreachable", "kms": "skipped:region_unreachable", "secretsmanager": "skipped:region_unreachable",
        "rds": "skipped:region_unreachable"}

    class NoEndpoint(Client):  # a service with no endpoint there: only that service
        def get_paginator(self, _method):
            calls.append(self.service)
            if self.service == "eks":
                raise EndpointConnectionError(endpoint_url="https://eks.x.amazonaws.com/")
            return SimpleNamespace(paginate=lambda **k: [])

    calls.clear()
    acct.client = lambda service, region: NoEndpoint(service)
    out = aws_inventory.discover_account(acct, ["x-1"], ["eks", "rds"])
    assert calls == ["eks", "rds"] and out.coverage["x-1"] == {"eks": "not_available", "rds": "ok"}


def test_the_ec2_cap_counts_instances_not_reservations(monkeypatch):
    monkeypatch.setattr(aws_inventory, "PER_SERVICE_CAP", 3)
    page = {"Reservations": [{"Instances": [{"InstanceId": f"i-{n}", "PrivateIpAddress": f"10.0.0.{n + 1}"}
                                            for n in range(5)]}]}
    client = SimpleNamespace(get_paginator=lambda _m: SimpleNamespace(paginate=lambda **k: [page]))
    acct = SimpleNamespace(account="111122223333", client=lambda service, region: client)
    rows, cut = aws_inventory._Lister(acct, "us-east-1", "aws").ec2()
    assert len(rows) == 3 and cut is True


def test_an_aws_sync_respects_the_team_cap(world, monkeypatch):
    engine, _ = world
    monkeypatch.setattr(store, "MAX_TARGETS_PER_TEAM", 3)
    with Session(engine) as s:
        src = CbomInventorySource(team_id=1, kind="aws", name="lab", config={})
        s.add(src)
        s.commit()
        s.refresh(src)
        sid = src.id
    found = aws_inventory.Discovery(account_id="1", coverage={"us-east-1": {"ec2": "ok"}})
    found.targets = [normalize({"external_id": f"arn:aws:ec2:us-east-1:1:instance/i-{n}", "address": f"10.0.0.{n + 1}",
                                "attributes": {"service": "ec2"}}) for n in range(5)]
    out = SYNC.save_discovery(engine, sid, found, dt.datetime(2026, 11, 12), sync_id="s1")
    assert (out["created"], out["capped"], out["status"]) == (3, 2, "partial") and "50,000" not in out["capped_reason"]
    with Session(engine) as s:
        assert len(s.exec(select(CbomInventoryTarget)).all()) == 3
