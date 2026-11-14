"""F1.2 tag policies: the selector grammar, the deterministic engine (never-scan first, priority then id, every match
reported), the policy / credential / preview routes, the materializer (sticky batches, no edit of a source with an
open job, managed schedules, own caps) and the claim plugin.

Real routers, real JWTs, SQLite (``test_cbom_sources_api`` world).
"""
from __future__ import annotations

import datetime as dt
import json
import random
from types import SimpleNamespace

import pytest
from sqlmodel import Session, select

from test_cbom_sources_api import KNOWN_HOSTS, PASSWORD, api, enroll_node, world
from backend.new_models import CbomCollectionJob, CbomCollectionSchedule, CbomCollectionSettings, CbomCollectionSource
from backend.utilities.cbom_sources import jobs as J
from backend.utilities.cbom_sources import runs as RUNS
from backend.utilities.cbom_sources.fleet import claim as CLAIM
from backend.utilities.cbom_sources.fleet.models import CbomCredential, CbomInventoryTarget
from backend.utilities.cbom_sources.fleet.policy import (
    PolicyEngine, PolicyError, Refs, matches, validate_action, validate_selector)
from backend.utilities.cbom_sources.schemas import Include, RunCreate
from backend.utilities.cbom_sources.settings import get_or_create_settings

FIXTURES = (api, world)
FLEET = "/1/cbom/sources/fleet"
INV = FLEET + "/inventory"


@pytest.fixture(autouse=True)
def _flags(monkeypatch):
    for name in ("CBOM_FLEET_TRANSPORTS", "CBOM_SSH_CA", "CBOM_FLEET_MATERIALIZE"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("CBOM_FLEET_INVENTORY", "1")
    monkeypatch.setenv("CBOM_FLEET_POLICIES", "1")


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc).replace(tzinfo=None)


def P(pid, priority, selector, action=None, name=None, enabled=True):
    return SimpleNamespace(id=pid, name=name or f"p{pid}", priority=priority, selector=selector, enabled=enabled,
                           deleted_at=None, action=action or {"transport": "ssh", "credential_id": 1, "node_id": 1})


def T(**kw):
    base = {"id": 1, "kind": "linux_host", "address": "10.0.0.5", "addresses": ["10.0.0.5"], "hostname": None,
            "tags": {}, "account_id": None, "region": None, "platform": None, "missing_since": None}
    base.update(kw)
    return SimpleNamespace(**base)


REFS = Refs(credentials={1: None}, credential_types={1: "node_key"}, nodes={1: None})


def _settings(*cidrs: str):
    return SimpleNamespace(network_exclusions=[{"cidr": c} for c in cidrs])


# ----------------------------------------------------------------------------- grammar and matching
def test_selector_grammar_is_validated_and_normalised():
    sel = validate_selector({"all": [{"tag": "Env", "op": "eq", "value": "prod"},
                                     {"not": {"field": "region", "op": "in", "value": ["eu-west-1", "us-east-1"]}}]})
    assert sel["all"][0] == {"tag": "env", "op": "eq", "value": "prod"}
    assert sel["all"][1]["not"]["value"] == ["eu-west-1", "us-east-1"]
    assert validate_selector({}) == {}
    for bad, match in [({"tag": "env", "op": "regex", "value": ".*"}, "op must be"),
                       ({"field": "owner", "op": "eq", "value": "x"}, "field must be"),
                       ({"any": []}, "non-empty"), ({"tag": "env", "op": "in", "value": "prod"}, "list"),
                       ({"all": [{"tag": f"k{i}", "op": "exists"} for i in range(21)]}, "at most 20"),
                       ({"field": "kind", "op": "eq", "value": "router"}, "kind must be"),
                       ({"tag": "env", "op": "exists", "value": "x"}, "takes no value"),
                       ({"tag": "env", "op": "prefix", "value": ""}, "needs a value"),
                       ({"foo": 1}, "use all, any, not")]:
        with pytest.raises(PolicyError, match=match):
            validate_selector(bad)


def test_leaf_operators():
    tags = {"env": "prod", "team": "pay-ops"}
    fields = {"kind": "linux_host", "account_id": "123", "region": "ap-south-1", "platform": None}
    check = lambda sel: matches(validate_selector(sel), tags, fields)  # noqa: E731
    assert check({"tag": "ENV", "op": "eq", "value": "prod"}) and not check({"tag": "env", "op": "eq", "value": "Prod"})
    assert check({"tag": "owner", "op": "ne", "value": "x"}) and not check({"tag": "env", "op": "ne", "value": "prod"})
    assert check({"tag": "team", "op": "prefix", "value": "pay-"}) and check({"tag": "env", "op": "in", "value": ["dev", "prod"]})
    assert check({"tag": "env", "op": "exists"}) and not check({"tag": "owner", "op": "exists"})
    assert check({"field": "region", "op": "prefix", "value": "ap-"}) and not check({"field": "platform", "op": "exists"})
    assert check({"any": [{"tag": "x", "op": "exists"}, {"field": "kind", "op": "eq", "value": "linux_host"}]})
    assert not check({"not": {"tag": "env", "op": "exists"}})


def test_action_validation():
    assert validate_action({"never_scan": True, "transport": "salt"}) == {"never_scan": True}
    ok = validate_action({"transport": "ssh", "credential_id": 3, "node_id": 7,
                          "schedule": {"frequency": "weekly", "time_of_day": "02:30", "weekday": 6}})
    assert ok["batch_size"] == 100 and ok["tier"] == 1 and ok["schedule"]["weekday"] == 6
    for bad, match in [({"transport": "ssh", "node_id": 1}, "credential"),
                       ({"transport": "awx", "node_id": 1}, "AWX transport"),
                       ({"transport": "ssh", "credential_id": 1}, "scan node or a node segment"),
                       ({"transport": "ssh", "credential_id": 1, "node_id": 1, "node_segment": "dc"}, "either"),
                       ({"transport": "ssm", "transport_id": 1, "node_id": 2}, "cloud worker"),
                       ({"transport": "ssh", "credential_id": 1, "node_id": 1, "batch_size": 5000}, "25 to 1000"),
                       ({"transport": "ssh", "credential_id": 1, "node_id": 1, "schedule": {"frequency": "hourly"}}, "frequency"),
                       ({"transport": "ssh", "credential_id": 1, "node_id": 1,
                         "schedule": {"frequency": "daily", "time_of_day": "25:00"}}, "HH:MM"),
                       ({"transport": "ftp"}, "transport must be")]:
        with pytest.raises(PolicyError, match=match):
            validate_action(bad)


# ----------------------------------------------------------------------------- engine
def test_precedence_priority_then_id_and_every_match_reported():
    prod = {"tag": "env", "op": "eq", "value": "prod"}
    policies = [P(5, 10, prod, name="low"), P(3, 50, {}, name="catch-all"), P(2, 50, prod, name="tie-older"),
                P(9, 90, {"tag": "env", "op": "eq", "value": "dev"})]
    engine = PolicyEngine(policies, _settings(), refs=REFS)
    d = engine.evaluate(T(tags={"env": "prod"}))
    assert d.action == "collect" and d.policy_id == 2 and d.matched_policy_ids == (2, 3, 5)
    assert "'tie-older' (priority 50)" in d.reason
    assert engine.evaluate(T(tags={"env": "qa"})).policy_id == 3
    assert PolicyEngine([P(5, 10, prod)], _settings(), refs=REFS).evaluate(T(tags={})).action == "unmanaged"
    disabled = PolicyEngine([P(2, 50, prod, enabled=False), P(5, 10, prod)], _settings(), refs=REFS)
    assert disabled.evaluate(T(tags={"env": "prod"})).policy_id == 5


def test_the_never_scan_list_wins_for_any_address_or_the_host_name():
    engine = PolicyEngine([P(1, 100, {})], _settings("10.0.0.0/30", "secret.bank.local"), refs=REFS)
    dual = engine.evaluate(T(address="2001:db8::5", addresses=["2001:db8::5", "10.0.0.2"]))  # the T1 rule
    assert dual.action == "never_scan" and dual.policy_id is None and dual.matched_policy_ids == (1,)
    assert "10.0.0.2" in dual.reason
    assert engine.evaluate(T(address=None, addresses=[], hostname="secret.bank.local")).action == "never_scan"
    assert engine.evaluate(T(address="10.0.0.9", addresses=["10.0.0.9"])).action == "collect"
    never = PolicyEngine([P(1, 100, {}, action={"never_scan": True}), P(2, 1, {})], _settings(), refs=REFS)
    d = never.evaluate(T())
    assert d.action == "never_scan" and d.policy_id == 1 and d.matched_policy_ids == (1, 2)


def test_what_a_policy_cannot_use_gives_unmanaged_with_the_reason():
    now = _now()
    refs = Refs(credentials={1: None, 2: "credential 'old' was deleted"}, credential_types={1: "node_key", 2: "password"},
                nodes={1: None, 4: "scan node 'k8s-a' is an agent-mode node (it collects only its own host)"})
    def decide(action, target=None):
        return PolicyEngine([P(1, 1, {}, action=action)], _settings(), refs=refs, now=now).evaluate(target or T())
    assert "was deleted" in decide({"transport": "ssh", "credential_id": 2, "node_id": 1}).reason
    assert "#9 not found" in decide({"transport": "ssh", "credential_id": 9, "node_id": 1}).reason
    assert "agent-mode" in decide({"transport": "ssh", "credential_id": 1, "node_id": 4}).reason
    assert "AWX transport #3 not found" in decide({"transport": "awx", "transport_id": 3, "node_id": 1}).reason
    assert "database targets are not collected" in decide({"transport": "ssh", "credential_id": 1, "node_id": 1},
                                                          T(kind="database")).reason
    assert "no address" in decide({"transport": "ssh", "credential_id": 1, "node_id": 1},
                                  T(address=None, addresses=[], hostname=None)).reason
    old = T(missing_since=now - dt.timedelta(days=8))
    assert "more than 7 days" in decide({"transport": "ssh", "credential_id": 1, "node_id": 1}, old).reason
    assert decide({"transport": "ssh", "credential_id": 1, "node_id": 1},
                  T(missing_since=now - dt.timedelta(days=2))).action == "collect"


def test_evaluation_is_deterministic_whatever_the_input_order():
    rng = random.Random(20261111)
    keys, values = ["env", "team", "tier"], ["prod", "stage", "dev", "pay", "1", "2"]

    def leaf():
        op = rng.choice(["eq", "ne", "in", "exists", "prefix"])
        if rng.random() < 0.2:
            return {"field": "region", "op": "prefix", "value": rng.choice(["ap-", "us-"])}
        node = {"tag": rng.choice(keys), "op": op}
        if op == "in":
            node["value"] = rng.sample(values, 2)
        elif op != "exists":
            node["value"] = rng.choice(values)[:1] if op == "prefix" else rng.choice(values)
        return node

    for _round in range(30):
        policies = [P(i, rng.choice([1, 5, 5, 10, 50]), rng.choice([leaf(), {"all": [leaf(), leaf()]},
                                                                      {"any": [leaf(), {"not": leaf()}]}]),
                      action=rng.choice([{"never_scan": True}, {"transport": "ssh", "credential_id": 1, "node_id": 1}]))
                    for i in range(1, 12)]
        targets = [T(id=n, address=f"10.0.{n // 250}.{n % 250 + 1}", addresses=[f"10.0.{n // 250}.{n % 250 + 1}"],
                     region=rng.choice(["ap-south-1", "us-east-1", None]),
                     tags={k: rng.choice(values) for k in rng.sample(keys, rng.randint(0, 3))}) for n in range(200)]
        settings = _settings("10.0.0.10/31")
        base = {t.id: PolicyEngine(policies, settings, refs=REFS).evaluate(t) for t in targets}
        for _shuffle in range(3):
            shuffled = policies[:]
            rng.shuffle(shuffled)
            order = targets[:]
            rng.shuffle(order)
            engine = PolicyEngine(shuffled, settings, refs=REFS)
            assert {t.id: engine.evaluate(t) for t in order} == base


# ----------------------------------------------------------------------------- routes
def _credential(api, **kw):
    body = {"name": "fleet-key", "credential_type": "node_key", "config": {"login_user": "zs-cbom"}}
    body.update(kw)
    r = api("POST", f"{FLEET}/credentials", json=body)
    assert r.status_code == 201, r.text
    return r.json()["credential"]


def _targets(api, n, env="prod", start=0):
    rows = [{"external_id": f"h{i}", "address": f"10.2.{i // 250}.{i % 250 + 1}", "tags": {"env": env, "team": "pay"}}
            for i in range(start, start + n)]
    r = api("POST", f"{INV}/import", json={"format": "json", "content": json.dumps(rows)})
    assert r.status_code == 200, r.text
    return r.json()


def _policy(api, name, priority, selector, action, who="alice", status=201):
    r = api("POST", f"{FLEET}/policies", who, json={"name": name, "priority": priority, "selector": selector,
                                                    "action": action})
    assert r.status_code == status, r.text
    return r.json().get("policy")


def test_policy_routes_show_which_policy_won(api, world):
    node_id, _tok, _reg = enroll_node(api)
    cred = _credential(api)
    _targets(api, 5)
    ssh = {"transport": "ssh", "credential_id": cred["id"], "node_id": node_id}
    assert api("POST", f"{FLEET}/policies", "bob", json={"name": "x", "action": ssh}).status_code == 400  # admins only
    broad = _policy(api, "all-pay", 10, {"tag": "team", "op": "eq", "value": "pay"}, ssh)
    prod = _policy(api, "prod-never", 90, {"tag": "env", "op": "eq", "value": "prod"}, {"never_scan": True})
    listed = api("GET", f"{FLEET}/policies", "bob").json()
    assert [p["name"] for p in listed["policies"]] == ["prod-never", "all-pay"]
    assert [(p["precedence"], p["matched_targets"], p["won_targets"]) for p in listed["policies"]] == [(1, 5, 5), (2, 5, 0)]
    tid = api("GET", f"{INV}/targets").json()["targets"][0]["id"]
    detail = api("GET", f"{INV}/targets/{tid}").json()
    assert detail["decision"]["action"] == "never_scan" and detail["decision"]["policy_id"] == prod["id"]
    assert detail["matched_policies"] == [
        {"id": prod["id"], "name": "prod-never", "priority": 90, "won": True},
        {"id": broad["id"], "name": "all-pay", "priority": 10, "won": False}]
    # lower the never-scan policy: the broad one wins; the cached decisions follow
    stale = api("PATCH", f"{FLEET}/policies/{prod['id']}", json={"priority": 1, "expected_version": 99})
    assert stale.status_code == 409
    moved = api("PATCH", f"{FLEET}/policies/{prod['id']}", json={"priority": 1, "expected_version": prod["row_version"]})
    assert moved.status_code == 200 and moved.json()["decisions_changed"] == 5
    listing = api("GET", f"{INV}/targets", params={"decision": "collect"}).json()
    assert listing["total"] == 5 and listing["targets"][0]["decision"]["policy_id"] == broad["id"]
    assert listing["policies"][str(broad["id"])]["name"] == "all-pay"
    assert api("DELETE", f"{FLEET}/policies/{broad['id']}").json()["decisions_changed"] == 5
    assert api("GET", f"{INV}/targets/{tid}").json()["decision"]["policy_id"] == prod["id"]


def test_preview_reports_matches_conflicts_and_writes_nothing(api, world):
    engine, _ = world
    node_id, _tok, _reg = enroll_node(api)
    cred = _credential(api)
    _targets(api, 4, env="prod")
    stage_rows = [{"external_id": f"s{i}", "address": f"10.3.0.{i}", "tags": {"env": "stage", "team": "pay"}}
                  for i in range(1, 4)]
    assert api("PUT", f"{INV}/targets", json={"source_name": "api", "targets": stage_rows}).status_code == 200
    ssh = {"transport": "ssh", "credential_id": cred["id"], "node_id": node_id}
    stage = _policy(api, "stage", 50, {"tag": "env", "op": "eq", "value": "stage"}, ssh)
    draft = {"name": "everything", "priority": 10, "selector": {"tag": "team", "op": "eq", "value": "pay"},
             "action": {"never_scan": True}}
    out = api("POST", f"{FLEET}/policies/preview", json={"policy": draft}).json()
    assert (out["matched"], out["would_collect"], out["never_scan"]) == (7, 0, 4)
    assert out["conflicts"] == [{"winner_policy_id": stage["id"], "winner": "stage", "loser_policy_id": None,
                                 "loser": "everything", "targets": 3}]
    assert sum(1 for s in out["sample"] if s["won"]) == 4
    saved = api("POST", f"{FLEET}/policies/preview", json={"policy_id": stage["id"]}).json()
    assert (saved["matched"], saved["would_collect"]) == (3, 3)
    assert api("POST", f"{FLEET}/policies/preview", json={}).status_code == 400
    assert len(api("GET", f"{FLEET}/policies").json()["policies"]) == 1


def test_preview_shows_the_winner_saving_would_give_on_a_tie_and_for_an_edit(api, world):
    """Which policy won must not depend on whether it was previewed or saved: a draft is the newest policy (it loses a
    priority tie, as it will once saved), and a draft that edits a saved policy replaces it in the preview (it does
    not overlap with itself)."""
    node_id, _tok, _reg = enroll_node(api)
    cred = _credential(api)
    _targets(api, 3)
    prod = {"tag": "env", "op": "eq", "value": "prod"}
    old = _policy(api, "old", 50, prod, {"transport": "ssh", "credential_id": cred["id"], "node_id": node_id})
    tie = {"name": "tie", "priority": 50, "selector": prod, "action": {"never_scan": True}}
    out = api("POST", f"{FLEET}/policies/preview", json={"policy": tie}).json()
    assert (out["matched"], out["would_collect"], out["never_scan"]) == (3, 0, 0)  # it loses the tie: decides nothing
    assert not any(s["won"] for s in out["sample"])
    assert out["conflicts"] == [{"winner_policy_id": old["id"], "winner": "old", "loser_policy_id": None,
                                 "loser": "tie", "targets": 3}]
    saved = _policy(api, "tie", 50, prod, {"never_scan": True})  # saved: the preview was right
    tid = api("GET", f"{INV}/targets").json()["targets"][0]["id"]
    assert api("GET", f"{INV}/targets/{tid}").json()["decision"]["policy_id"] == old["id"]
    edit = {"name": "old", "priority": 50, "selector": prod, "action": {"never_scan": True}}
    out = api("POST", f"{FLEET}/policies/preview", json={"policy": edit, "policy_id": old["id"]}).json()
    assert (out["matched"], out["would_collect"], out["never_scan"]) == (3, 0, 3)
    assert all(s["won"] for s in out["sample"])
    assert out["conflicts"] == [{"winner_policy_id": old["id"], "winner": "old", "loser_policy_id": saved["id"],
                                 "loser": "tie", "targets": 3}]  # the edit keeps its id (and its tie-break); no self
    other = api("POST", f"{FLEET}/policies/preview", "carol", json={"policy": edit, "policy_id": old["id"]})
    assert other.status_code == 403  # carol is not in team 1
    gone = api("POST", f"{FLEET}/policies/preview", json={"policy": edit, "policy_id": 999_999})
    assert gone.status_code == 404
    assert [p["name"] for p in api("GET", f"{FLEET}/policies").json()["policies"]] == ["old", "tie"]  # nothing written
    assert api("GET", f"{FLEET}/policies").json()["policies"][0]["action"]["never_scan"] is False


def test_credentials_are_typed_and_write_only(api, world):
    engine, _ = world
    bad = api("POST", f"{FLEET}/credentials", json={"name": "pw", "credential_type": "password",
                                                     "config": {"host_key_policy": "tofu"}, "secrets": {"password": PASSWORD}})
    assert bad.status_code == 400 and "pinned host keys" in bad.json()["detail"]
    missing = api("POST", f"{FLEET}/credentials", json={"name": "pw", "credential_type": "password", "config": {
        "host_key_policy": "pinned", "known_hosts": KNOWN_HOSTS}})
    assert missing.status_code == 400 and "enter password" in missing.json()["detail"]
    cred = _credential(api, name="pw", credential_type="password",
                       config={"host_key_policy": "pinned", "known_hosts": KNOWN_HOSTS}, secrets={"password": PASSWORD})
    assert cred["secrets_set"] == ["password"]
    keep = api("PATCH", f"{FLEET}/credentials/{cred['id']}", json={"name": "pw2", "secrets": {"password": ""}})
    assert keep.status_code == 200 and keep.json()["credential"]["secrets_set"] == ["password"]
    moved = api("PATCH", f"{FLEET}/credentials/{cred['id']}", json={"config": {
        "host_key_policy": "pinned", "known_hosts": KNOWN_HOSTS.replace("10.20.0.1", "10.20.0.2")}})
    assert moved.status_code == 400 and "enter password" in moved.json()["detail"]  # the login target changed
    assert api("GET", f"{FLEET}/credentials", "bob").status_code == 200
    assert all(PASSWORD not in text for text in api.seen)
    with Session(engine) as s:
        assert PASSWORD not in (s.get(CbomCredential, cred["id"]).secret_encrypted or "")
    assert api("DELETE", f"{FLEET}/credentials/{cred['id']}").status_code == 200
    with Session(engine) as s:
        row = s.get(CbomCredential, cred["id"])
        assert row.deleted_at and row.secret_encrypted is None
    assert api("GET", f"{FLEET}/credentials").json()["credentials"] == []


def test_policy_routes_do_not_exist_while_the_flag_is_off(api, monkeypatch):
    monkeypatch.setenv("CBOM_FLEET_POLICIES", "0")
    for method, path in [("GET", "/policies"), ("POST", "/reconcile"), ("GET", "/credentials")]:
        assert api(method, FLEET + path).status_code == 404


# ----------------------------------------------------------------------------- materializer
def _managed(engine):
    with Session(engine) as s:
        return sorted(s.exec(select(CbomCollectionSource).where(CbomCollectionSource.managed_by_policy_id.is_not(None))).all(),
                      key=lambda r: r.id)


def test_reconcile_without_the_materialize_flag_writes_no_source(api, world):
    engine, _ = world
    node_id, _tok, _reg = enroll_node(api)
    cred = _credential(api)
    _targets(api, 3)
    _policy(api, "prod", 10, {}, {"transport": "ssh", "credential_id": cred["id"], "node_id": node_id})
    out = api("POST", f"{FLEET}/reconcile").json()
    assert out["materialize"] is False and out["sources_created"] == 0 and _managed(engine) == []


def test_materializer_batches_sticky_defers_busy_sources_and_manages_the_schedule(api, world, monkeypatch):
    engine, _ = world
    monkeypatch.setenv("CBOM_FLEET_MATERIALIZE", "1")
    node_id, _tok, _reg = enroll_node(api)
    cred = _credential(api)
    _targets(api, 250)
    policy = _policy(api, "prod-weekly", 10, {"tag": "env", "op": "eq", "value": "prod"},
                     {"transport": "ssh", "credential_id": cred["id"], "node_id": node_id, "batch_size": 100,
                      "schedule": {"frequency": "weekly", "time_of_day": "02:00", "weekday": 6}})
    assert api("POST", f"{FLEET}/reconcile", "bob").status_code == 400
    first = api("POST", f"{FLEET}/reconcile").json()
    assert (first["sources_created"], first["targets_assigned"], first["schedules_created"]) == (3, 250, 1), first
    sources = _managed(engine)
    assert [len(s.config["targets"]) for s in sources] == [100, 100, 50]
    assert {s.kind for s in sources} == {"linux_servers"} and {s.node_id for s in sources} == {node_id}
    assert {s.credential_id for s in sources} == {cred["id"]} and all(s.secret_encrypted is None for s in sources)
    assert sources[0].name == f"fleet-{policy['id']}-1" and sources[0].config["credential_type"] == "node_key"
    again = api("POST", f"{FLEET}/reconcile").json()
    assert again["sources_created"] == again["sources_updated"] == again["targets_assigned"] == 0  # idempotent
    # a new target fills the batch with room; nothing else moves
    _targets(api, 251)
    before = {s.id: s.config["targets"] for s in _managed(engine)}
    added = api("POST", f"{FLEET}/reconcile").json()
    assert (added["sources_created"], added["sources_updated"], added["targets_assigned"]) == (0, 1, 1)
    after = {s.id: s.config["targets"] for s in _managed(engine)}
    assert [sid for sid in after if after[sid] != before[sid]] == [sources[2].id]
    # a source with an open job is never edited: its change waits
    with Session(engine) as s:
        s.add(CbomCollectionJob(team_id=1, run_id=None, source_id=sources[0].id, node_id=node_id, kind="collect",
                                status="pending", params={}))
        s.commit()
    # h0 moves to another address while sources[0] has an open job: the old address leaves at once (removal never
    # waits; the job, made for the old list, is cancelled) and the new one waits for the next reconcile (pending)
    rows = [{"external_id": f"h{i}", "address": "10.2.9.9" if i == 0 else f"10.2.{i // 250}.{i % 250 + 1}",
             "tags": {"env": "prod", "team": "pay"}} for i in range(251)]
    api("POST", f"{INV}/import", json={"format": "json", "content": json.dumps(rows)})
    busy = api("POST", f"{FLEET}/reconcile").json()
    assert busy["deferred"] == 1 and busy["sources_updated"] == 1, busy
    first_source = _managed(engine)[0]
    assert "10.2.0.1" not in first_source.config["targets"] and "10.2.9.9" not in first_source.config["targets"]
    with Session(engine) as s:
        job = s.exec(select(CbomCollectionJob).where(CbomCollectionJob.source_id == sources[0].id)).one()
        assert job.status == "cancelled"
    h0 = next(t for t in api("GET", f"{INV}/targets").json()["targets"] if t["external_id"] == "h0")
    assert h0["pending"] is True and h0["managed_source_id"] is None
    placed = api("POST", f"{FLEET}/reconcile").json()  # the source is free now: the waiting address goes in
    assert (placed["deferred"], placed["sources_updated"]) == (0, 1), placed
    assert "10.2.9.9" in _managed(engine)[0].config["targets"]
    h0 = next(t for t in api("GET", f"{INV}/targets").json()["targets"] if t["external_id"] == "h0")
    assert h0["pending"] is False and h0["managed_source_id"] == sources[0].id
    with Session(engine) as s:
        sched = s.exec(select(CbomCollectionSchedule).where(CbomCollectionSchedule.policy_id == policy["id"])).one()
        assert sched.source_ids == [x.id for x in sources] and sched.include == {"servers": True}
        assert sched.frequency == "weekly" and sched.weekday == 6 and sched.next_run_at is not None
    # managed schedules do not count toward the 20 a team can make by hand
    for i in range(20):
        r = api("POST", "/1/cbom/sources/schedules", json={"name": f"s{i}", "frequency": "daily", "time_of_day": "03:00",
                                                           "include": {"servers": True}})
        assert r.status_code == 201, r.text
    assert api("POST", "/1/cbom/sources/schedules", json={"name": "s21", "frequency": "daily", "time_of_day": "03:00",
                                                           "include": {"servers": True}}).status_code == 400
    # the policy goes: its sources and its schedule go, a busy one too (its open job is cancelled: nothing a policy
    # no longer collects is collected)
    with Session(engine) as s:
        s.add(CbomCollectionJob(team_id=1, run_id=None, source_id=sources[1].id, node_id=node_id, kind="collect",
                                status="pending", params={}))
        s.commit()
    api("DELETE", f"{FLEET}/policies/{policy['id']}")
    gone = api("POST", f"{FLEET}/reconcile").json()
    assert (gone["sources_removed"], gone["deferred"], gone["schedules_removed"]) == (3, 0, 1), gone
    assert _managed(engine) == []
    with Session(engine) as s:
        job = s.exec(select(CbomCollectionJob).where(CbomCollectionJob.status == "pending")).all()
        assert job == []
    assert api("GET", f"{INV}/targets", params={"limit": 1}).json()["targets"][0]["managed_source_id"] is None


def test_a_managed_source_charges_credits_like_a_hand_made_one(api, world, monkeypatch):
    engine, _ = world
    monkeypatch.setenv("CBOM_FLEET_MATERIALIZE", "1")
    node_id, _tok, _reg = enroll_node(api)
    cred = _credential(api)
    _targets(api, 30)
    _policy(api, "prod", 10, {}, {"transport": "ssh", "credential_id": cred["id"], "node_id": node_id, "batch_size": 25})
    api("POST", f"{FLEET}/reconcile")
    sources = _managed(engine)
    with Session(engine) as s:
        settings = get_or_create_settings(s, 1)
        run, _ = RUNS.queue_run(s, 1, 1, RunCreate(include=Include(servers=True), source_ids=[x.id for x in sources],
                                                   client_request_id="fleet-credits"), settings, _now())
        assert run.credits_charged_c == 20 * 30  # 0.2 credits per target, as RATES_C["server"]
        jobs = s.exec(select(CbomCollectionJob).where(CbomCollectionJob.run_id == run.id)).all()
        assert sorted(j.source_id for j in jobs) == [x.id for x in sources]
        s.rollback()


def test_a_password_credential_materialises_with_pinned_host_keys_and_reaches_the_claim_plugin(api, world, monkeypatch):
    engine, _ = world
    monkeypatch.setenv("CBOM_FLEET_MATERIALIZE", "1")
    node_id, _tok, _reg = enroll_node(api)
    cred = _credential(api, name="pw", credential_type="password",
                       config={"host_key_policy": "pinned", "known_hosts": KNOWN_HOSTS, "login_user": "svc-cbom"},
                       secrets={"password": PASSWORD})
    _targets(api, 2)
    _policy(api, "prod", 10, {}, {"transport": "ssh", "credential_id": cred["id"], "node_id": node_id})
    assert api("POST", f"{FLEET}/reconcile").json()["sources_created"] == 1
    src = _managed(engine)[0]
    assert src.config["credential_type"] == "password" and src.config["host_key_policy"] == "pinned"
    assert src.config["login_user"] == "svc-cbom" and src.secret_encrypted is None
    with Session(engine) as s:
        extras = CLAIM.claim_extras(s, src, None, _now(), {"config": {"a": 1}, "secrets": {}})
        assert extras == {"config": {"a": 1}, "secrets": {"password": PASSWORD}}
        v1 = CLAIM.version_input(s, src)
        assert CLAIM.known_secrets(s, src) == [PASSWORD]
        assert CLAIM.claim_extras(s, SimpleNamespace(credential_id=None, team_id=1), None, _now(), {}) is None
    api("PATCH", f"{FLEET}/credentials/{cred['id']}", json={"secrets": {"password": PASSWORD + "-new"}})
    with Session(engine) as s:
        assert CLAIM.version_input(s, src) != v1  # a new password changes the connection version
        other = SimpleNamespace(credential_id=cred["id"], team_id=2)
        assert CLAIM.claim_extras(s, other, None, _now(), {"config": {}, "secrets": {}})["secrets"] == {}


def test_settings_never_scan_change_is_seen_by_the_next_evaluation(api, world, monkeypatch):
    engine, _ = world
    node_id, _tok, _reg = enroll_node(api)
    cred = _credential(api)
    _targets(api, 3)
    _policy(api, "all", 10, {}, {"transport": "ssh", "credential_id": cred["id"], "node_id": node_id})
    with Session(engine) as s:
        settings = s.exec(select(CbomCollectionSettings).where(CbomCollectionSettings.team_id == 1)).one()
        settings.network_exclusions = [{"cidr": "10.2.0.1"}]
        s.add(settings)
        s.commit()
    # the never-scan list is one of the evaluation's inputs: the next read sees its digest change and re-evaluates
    # this small team in place, so the stored decision (and the SQL filter on it) is current at once
    listing = api("GET", f"{INV}/targets", params={"decision": "never_scan"}).json()
    assert listing["total"] == 1 and listing["targets"][0]["address"] == "10.2.0.1"
    assert listing["evaluation"]["stale"] is False
    api("POST", f"{FLEET}/reconcile")
    with Session(engine) as s:
        assert s.exec(select(CbomInventoryTarget).where(CbomInventoryTarget.address == "10.2.0.1")).one().decision["action"] == "never_scan"


def test_open_jobs_helper_matches_the_jobs_module():
    assert J.OPEN == ("pending", "claimed")
