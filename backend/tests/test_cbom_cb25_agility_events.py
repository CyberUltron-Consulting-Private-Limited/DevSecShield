"""CB-25 PR-C: the agility estate hook is incremental, and the baseline emits agility events.

* An observation re-read unchanged in a new run keeps its stored class (only its job pointer moves): nothing is loaded
  or judged; a changed row is judged again, alone.
* ``agility_asset_moved`` (an asset's class changed under the same model) and ``agility_system_changed`` (a system's
  class mix changed between consecutive baselines) are drift events of scope ``agility``, forwarded by the
  integrations dispatcher like ``q0_closed`` (CB-23's contract: integration type, allowlisted detail, run id in the
  detail, one event per change through the dedupe key, nothing on the first baseline or across a model change).
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest
from sqlmodel import Session, select

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_cbom_sources_api as HARNESS  # noqa: E402
from test_cbom_sources_api import enroll_node, linux_body  # noqa: E402
from test_cbom_wp10_outputs import _claim, _collect, _run  # noqa: E402

from backend.new_models import CbomDriftEvent, CbomEstateAsset, CbomEstateObservation  # noqa: E402
from backend.utilities.cbom_sources import agility_rollup as ROLLUP  # noqa: E402
from backend.utilities.cbom_sources import agility_store as STORE  # noqa: E402
from backend.utilities.cbom_sources import drift as DRIFT  # noqa: E402
from backend.utilities.integrations import events as EV  # noqa: E402

api, world = HARNESS.api, HARNESS.world  # the harness's fixtures, used by name below

TLS10 = {"type": "tls_endpoint", "target": "10.20.0.1", "location": "10.20.0.1:443",
         "facts": {"protocols": ["TLSv1.0", "TLSv1.2", "TLSv1.3"], "pq_group_supported": True}}
NO_PQ = {"type": "tls_endpoint", "target": "10.20.0.1", "location": "10.20.0.1:8443",
         "facts": {"protocols": ["TLSv1.2", "TLSv1.3"], "pq_group_supported": False}}
AES = {"type": "kms_key", "target": "10.20.0.1", "location": "vault:transit/aes", "name": "aes",
       "algorithm": "AES", "key_size": 256, "facts": {"key_spec": "SYMMETRIC_DEFAULT"}}
# the TLS 1.0 endpoint after an upgrade that dropped TLS 1.0 but has no post-quantum group: configurable -> vendor-fixed
TLS10_NOW_NO_PQ = {**TLS10, "facts": {"protocols": ["TLSv1.2", "TLSv1.3"], "pq_group_supported": False}}


@pytest.fixture(autouse=True)
def _fresh():
    ROLLUP.clear_cache()
    yield
    ROLLUP.clear_cache()


@pytest.fixture()
def source(api, world):
    engine, _ = world
    node_id, token, _ = enroll_node(api)
    api("POST", "/1/cbom/sources/items", json=linux_body("src-a", node_id=node_id, targets=["10.20.0.1"], window="any",
                                                         application="Payments"))
    return {"engine": engine, "hdr": {"X-ZS-Node-Token": token}, "n": 0}


def _one_run(api, source, assets: list[dict]) -> int:
    import datetime as dt

    source["n"] += 1
    run = _run(api, f"cb25c-run-{source['n']:04d}")
    _collect(api, source["hdr"], _claim(api, source["hdr"]), assets)
    DRIFT.record_pending_drift(source["engine"], dt.datetime.utcnow())  # drift -> estate write -> agility hook
    return run["id"]


@pytest.fixture()
def judged(monkeypatch):
    """How many observations each hook re-judged (``judge_observations`` returns their asset keys)."""
    calls: list[int] = []
    original = STORE.judge_observations

    def spy(*a, **k):
        keys = original(*a, **k)
        calls.append(len(keys))
        return keys

    monkeypatch.setattr(STORE, "judge_observations", spy)
    return calls


def _events(engine, kind: str | None = None) -> list[CbomDriftEvent]:
    with Session(engine) as s:
        q = select(CbomDriftEvent).where(CbomDriftEvent.scope == STORE.EVENT_SCOPE)
        if kind:
            q = q.where(CbomDriftEvent.kind == kind)
        return list(s.exec(q.order_by(CbomDriftEvent.id)).all())


# ---------------------------------------------------------------------------------------------- incremental
def test_an_unchanged_re_read_is_carried_and_a_changed_row_is_judged_alone(api, source, judged):
    _one_run(api, source, [TLS10, NO_PQ, AES])
    assert sum(judged) == 3  # the first write judges every observation
    judged.clear()
    _one_run(api, source, [TLS10, NO_PQ, AES])
    assert sum(judged) == 0  # same rows in a new job: carried, nothing loaded or judged
    with Session(source["engine"]) as s:
        from backend.new_models import CbomEstateSource

        obs = s.exec(select(CbomEstateObservation)).all()
        latest = s.exec(select(CbomEstateSource)).one().latest_job_id
        assert {o.fix_job_id for o in obs} == {latest}  # every pointer moved to the new job
    judged.clear()
    _one_run(api, source, [TLS10_NOW_NO_PQ, NO_PQ, AES])
    assert sum(judged) == 1  # only the endpoint whose facts changed
    body = api("GET", "/1/cbom/agility").json()
    assert body["inputs"]["read_from"] == "estate_store"
    assert body["counts"]["vendor-fixed"] == 2 and body["counts"]["configurable"] == 0


def test_a_changed_job_context_re_judges_its_source(api, source, judged):
    _one_run(api, source, [TLS10, AES])
    with Session(source["engine"]) as s:  # the application metadata changed: a new system for every asset
        from backend.new_models import CbomCollectionSource

        src = s.exec(select(CbomCollectionSource)).one()
        src.config = {**src.config, "application": "Cards"}
        s.add(src)
        s.commit()
    judged.clear()
    _one_run(api, source, [TLS10, AES])
    assert sum(judged) == 2
    labels = {s["label"] for s in api("GET", "/1/cbom/agility").json()["systems"]["items"]}
    assert labels == {"Cards"}


# ---------------------------------------------------------------------------------------------- events
def test_the_event_contract_is_the_q0_closed_one():
    for kind, typ in (("agility_asset_moved", "agility.asset_moved"),
                      ("agility_system_changed", "agility.system_changed")):
        assert EV.TYPES[kind] == typ and kind in EV.EVENT_KINDS and kind in DRIFT.EVENT_KINDS
        assert len(kind) <= 24  # CbomDriftEvent.kind
    for key in ("old_class", "new_class", "system_key", "system_label", "system_kind", "old_counts", "new_counts",
                "old_hardest", "new_hardest", "old_self_fixable_pct", "new_self_fixable_pct", "baseline_run_id",
                "run_id"):
        assert key in EV._DETAIL_KEYS, key
    from backend.utilities.integrations.registry import SPECS

    assert {"agility_asset_moved", "agility_system_changed"} <= set(SPECS["webhook"].default_events)


def test_a_class_change_emits_one_move_and_one_system_change_and_nothing_twice(api, source):
    engine = source["engine"]
    _one_run(api, source, [TLS10, NO_PQ, AES])
    assert _events(engine) == []  # the first baseline: nothing to compare with
    second = _one_run(api, source, [TLS10_NOW_NO_PQ, NO_PQ, AES])
    [moved] = _events(engine, STORE.ASSET_MOVED)
    assert (moved.detail["old_class"], moved.detail["new_class"]) == ("configurable", "vendor-fixed")
    assert moved.detail["run_id"] == second and moved.run_id is None  # CB-23's rule: the run is in the detail
    assert moved.detail["system_label"] == "Payments" and moved.severity == "Info" and moved.forwarded_at is None
    [system] = _events(engine, STORE.SYSTEM_CHANGED)
    assert system.asset_label == "Payments" and system.detail["baseline_run_id"] < second
    assert system.detail["old_counts"]["configurable"] == 1 and system.detail["new_counts"]["configurable"] == 0
    payload = EV.drift_payload(system)
    assert payload["type"] == "agility.system_changed" and payload["detail"]["new_counts"]["vendor-fixed"] == 2
    payload = EV.drift_payload(moved)
    assert payload["type"] == "agility.asset_moved" and payload["detail"]["new_class"] == "vendor-fixed"
    _one_run(api, source, [TLS10_NOW_NO_PQ, NO_PQ, AES])
    assert len(_events(engine)) == 2  # an unchanged run: no new event
    r = api("GET", "/1/cbom/sources/drift", params={"kind": "agility_asset_moved"})
    assert r.status_code == 200, r.text
    hist = api("GET", "/1/cbom/agility/history").json()["items"]
    assert [h["run_id"] for h in hist][:2] == sorted([h["run_id"] for h in hist], reverse=True)[:2]


def test_a_model_change_is_not_a_move(api, source):
    import datetime as dt

    import sqlalchemy as sa

    engine = source["engine"]
    _one_run(api, source, [TLS10, AES])
    with Session(engine) as s:  # every stored class as if another model version wrote it, and a different class
        s.execute(sa.update(CbomEstateAsset.__table__).values(fix_version="fx-1+old", fix_class="hardware-fixed"))
        s.execute(sa.update(CbomEstateObservation.__table__).values(fix_version="fx-1+old"))
        s.commit()
        moves: list = []
        STORE.heal(s, 1, dt.datetime.now(dt.timezone.utc), moves=moves)
        s.commit()
    assert moves == []


def test_system_changes_compare_like_with_like():
    class B:
        def __init__(self, version, systems, truncated=False, run_id=1):
            self.agility_version, self.systems, self.systems_truncated, self.run_id = version, systems, truncated, run_id

    a = {"key": "application:pay", "label": "Pay", "kind": "application", "hardest": "configurable",
         "counts": {"configurable": 1}, "self_fixable_pct": 100.0}
    b = {**a, "hardest": "vendor-fixed", "counts": {"vendor-fixed": 1}, "self_fixable_pct": 0.0}
    gone = {**a, "key": "source:x", "label": "x", "kind": "source"}
    assert STORE.system_changes(B("v", [a]), B("v", [a])) == []
    [c] = STORE.system_changes(B("v", [a]), B("v", [b]))
    assert (c["old_hardest"], c["new_hardest"]) == ("configurable", "vendor-fixed")
    assert [c["key"] for c in STORE.system_changes(B("v", [a, gone]), B("v", [a]))] == ["source:x"]  # a system left
    assert STORE.system_changes(B("v1", [a]), B("v2", [b])) == []  # another model version: not comparable
    assert STORE.system_changes(B("v", [a], truncated=True), B("v", [b])) == []
    assert STORE.system_changes(None, B("v", [b])) == []
