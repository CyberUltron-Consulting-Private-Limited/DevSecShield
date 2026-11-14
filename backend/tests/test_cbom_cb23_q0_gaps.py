"""CB-23 PR-A: the Q0 gap lifecycle of the quantum risk register (CB-19 PLAN §2.5 ``cb23q0gap001``, §2.6, §2.10, §4).

* evidence closure (PATCH area / vendor answer / vendor deleted -> ``removed``) and the day-366 tick (an E2/E3 area
  becomes E0 without a write);
* scope / asset / inputs Q0 items of each source's latest run (recorded with the run's drift);
* the ``q0_closed`` integration event: one per opening, delivered signed to a local webhook receiver, never for a
  ``model_change`` closure;
* ``GET /{team}/cbom/register/q0`` (keyset, team-scoped) lists every Q0 item with its reason (DA-6, evidence part);
* migration ``cb23q0gap001`` up / down / up on a populated SQLite database, chained on the one head.

    cd backend && PYTHONPATH=.. python -m pytest tests/test_cbom_cb23_q0_gaps.py -q
"""
from __future__ import annotations

import datetime as dt
import importlib.util
import re
import sys
from pathlib import Path

import pytest
import sqlalchemy as sa
from sqlmodel import Session, select

sys.path.insert(0, str(Path(__file__).resolve().parent))
from live_receivers import ReceiverLab, local_address  # noqa: E402
from test_cbom_sources_api import api, enroll_node, linux_body, world  # noqa: E402,F401
from test_cbom_wp10_outputs import two_runs  # noqa: E402,F401

from backend.new_models import (CbomCollectedAsset, CbomCollectionJob, CbomCollectionSettings,  # noqa: E402
                                CbomDriftEvent, CbomQ0Gap)
from backend.routers import cbom_sources as ROUTER  # noqa: E402
from backend.utilities.cbom_sources import drift as DRIFT  # noqa: E402
from backend.utilities.cbom_sources import identity as ID  # noqa: E402
from backend.utilities.cbom_sources import q0register as REG  # noqa: E402
from backend.utilities.integrations import dispatch as D  # noqa: E402
from backend.utilities.integrations import events as EV  # noqa: E402
from backend.utilities.integrations import outbound  # noqa: E402

_FIXTURES = (api, world, two_runs)
ROOT = Path(__file__).resolve().parents[2]
VERSIONS = ROOT / "prod_database_migrations" / "migrations" / "versions"
MIGRATION = VERSIONS / "cb23q0gap001_q0_gap_lifecycle.py"
ADDRESS = local_address()
DOC = {"evidence_title": "Key policy", "evidence_url": "https://intranet.example/policy.pdf"}
T0 = dt.datetime(2030, 1, 1, 12, 0, 0)  # dispatcher clock


def q0(api, team=1, who="alice", **params):
    r = api("GET", f"/{team}/cbom/register/q0", who, params=params)
    assert r.status_code == 200, r.text
    return r.json()


def items(api, **params) -> list[dict]:
    out, after = [], None
    while True:
        page = q0(api, **({**params, "after": after} if after else params))
        out += page["items"]
        after = page["next_after"]
        if not after:
            return out


def closed_events(engine) -> list[CbomDriftEvent]:
    with Session(engine) as s:
        return list(s.exec(select(CbomDriftEvent).where(CbomDriftEvent.kind == "q0_closed")
                           .order_by(CbomDriftEvent.id)).all())


def gaps(engine, key: str) -> list[CbomQ0Gap]:
    with Session(engine) as s:
        return list(s.exec(select(CbomQ0Gap).where(CbomQ0Gap.item_key == key).order_by(CbomQ0Gap.id)).all())


@pytest.fixture()
def lab(tmp_path, monkeypatch):
    if ADDRESS is None:
        pytest.skip("this host has no usable non-loopback IPv4 address")
    monkeypatch.setenv(outbound.ENV_ALLOWED_PRIVATE, f"{ADDRESS}/32")
    monkeypatch.delenv("CBOM_EXTRA_CA_FILE", raising=False)
    for name in ("HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY", "https_proxy", "http_proxy", "all_proxy"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("NO_PROXY", "*")
    with ReceiverLab(tmp_path, ADDRESS) as receivers:
        yield receivers


# ----------------------------------------------------------------------------- the event contract
def test_q0_closed_is_an_event_kind_with_allowlisted_detail():
    assert EV.TYPES["q0_closed"] == "register.q0_closed" and "q0_closed" in EV.EVENT_KINDS
    assert "q0_closed" in DRIFT.EVENT_KINDS
    for key in ("item_kind", "item_key", "reason", "sub_reason", "cause", "new_grade", "opened_at", "run_id"):
        assert key in EV._DETAIL_KEYS, key
    from backend.utilities.integrations.registry import SPECS

    assert "q0_closed" in SPECS["webhook"].default_events  # forwarded to ALL_FORWARDED destinations automatically


# ----------------------------------------------------------------------------- evidence closure (§4 CB-23 PR-A)
def test_e0_area_answered_e1_delivers_one_signed_q0_closed(api, world, lab):
    engine, _ = world
    r = api("PUT", "/1/integrations/webhook", json={
        "enabled": True, "config": {"url": lab.url("webhook", "/hook"), "ca_pem": lab.ca_pem},
        "secrets": {"signing_secret": lab.hook_secret}})
    assert r.status_code == 200, r.text
    before = {i["item_key"]: i for i in items(api, kind="evidence")}
    gap = before["evidence:area:key_hierarchy"]
    assert (gap["reason"], gap["sub_reason"], gap["status"]) == ("evidence_e0", "no_answer", "open")

    r = api("PATCH", "/1/cbom/sources/evidence/key_hierarchy", json={"confidence": "E1", "answers": {"roots": "HSM"}})
    assert r.status_code == 200, r.text
    [row] = gaps(engine, "evidence:area:key_hierarchy")
    assert row.closed_at is not None and row.close_cause == "evidence" and row.closed_grade is None
    # a second edit of the same (closed) item emits nothing more
    assert api("PATCH", "/1/cbom/sources/evidence/key_hierarchy",
               json={"answers": {"roots": "HSM", "policy": "PKI-1"}}).status_code == 200
    events = closed_events(engine)
    assert len(events) == 1
    e = events[0]
    assert (e.scope, e.code, e.severity, e.asset_key) == ("register", "evidence_e0", "Info",
                                                          "evidence:area:key_hierarchy")
    assert e.detail["cause"] == "evidence" and e.detail["sub_reason"] == "no_answer"

    assert D.tick(engine, T0)["delivered"] == 1
    [got] = [g for g in lab.got("webhook") if g["event_type"] == "register.q0_closed"]
    assert got["verified"]  # the documented receiver snippet accepts the signature
    body = got["json"]
    assert body["kind"] == "q0_closed" and body["type"] == "register.q0_closed"
    assert body["detail"]["item_key"] == "evidence:area:key_hierarchy"
    assert (body["detail"]["cause"], body["detail"]["reason"], body["detail"]["item_kind"]) == (
        "evidence", "evidence_e0", "evidence")
    assert body["id"] == EV.event_uid("drift", 1, e.dedupe_key)
    # the closure shows in the register's closed list with its cause
    closed = {i["item_key"]: i for i in items(api, status="closed")}
    assert closed["evidence:area:key_hierarchy"]["close_cause"] == "evidence"
    assert D.tick(engine, T0 + dt.timedelta(minutes=1))["delivered"] == 0  # exactly once


def test_vendor_answer_closes_and_vendor_deleted_is_removed(api, world):
    engine, _ = world
    v1 = api("POST", "/1/cbom/sources/evidence/vendors", json={"name": "Core banking"}).json()["vendor"]
    v2 = api("POST", "/1/cbom/sources/evidence/vendors", json={"name": "HSM vendor"}).json()["vendor"]
    open_ = {i["item_key"]: i for i in items(api, kind="evidence")}
    assert open_[f"evidence:vendor:{v1['id']}"]["sub_reason"] == "vendor_not_asked"
    # the vendor answers through its link: evidence closure
    token = api("POST", f"/1/cbom/sources/evidence/vendors/{v1['id']}/link").json()["path"].rsplit("/", 1)[-1]
    assert api("POST", f"/cbom/vendor-questionnaire/{token}", None, json={"answers": {"tls": "TLS 1.3"}}).status_code == 200
    [row1] = gaps(engine, f"evidence:vendor:{v1['id']}")
    assert row1.close_cause == "evidence"
    # the other vendor is deleted while at E0: removed
    assert api("DELETE", f"/1/cbom/sources/evidence/vendors/{v2['id']}").status_code == 200
    [row2] = gaps(engine, f"evidence:vendor:{v2['id']}")
    assert row2.closed_at is not None and row2.close_cause == "removed"
    causes = {e.asset_key: e.detail["cause"] for e in closed_events(engine)}
    assert causes == {f"evidence:vendor:{v1['id']}": "evidence", f"evidence:vendor:{v2['id']}": "removed"}
    assert f"evidence:vendor:{v2['id']}" not in {i["item_key"] for i in items(api)}


def test_day_366_reopens_with_a_new_opened_at_and_a_second_closure_has_a_new_dedupe_key(api, world, monkeypatch):
    engine, _ = world
    now = dt.datetime.utcnow().replace(microsecond=0)
    monkeypatch.setattr(ROUTER, "utcnow", lambda: now)
    key = "evidence:area:hsm_firmware"
    q0(api)  # first sight: opened as no_answer
    dated = (now.date() - dt.timedelta(days=365)).isoformat()  # day 365: still E2
    r = api("PATCH", "/1/cbom/sources/evidence/hsm_firmware",
            json={"confidence": "E2", "evidence_date": dated, "answers": {"model": "Luna 7"}, **DOC})
    assert r.status_code == 200 and r.json()["area"]["effective_confidence"] == "E2", r.text
    assert [g.close_cause for g in gaps(engine, key)] == ["evidence"]
    # day 366: no write, the daily tick reopens it
    day366 = now + dt.timedelta(days=1)
    out = REG.tick(engine, day366)
    assert out["opened"] >= 1
    assert REG.tick(engine, day366)["opened"] == 0  # idempotent
    rows = gaps(engine, key)
    assert len(rows) == 2 and rows[1].closed_at is None and rows[1].opened_at == day366
    assert rows[1].detail["sub_reason"] == "evidence_expired"
    assert len(closed_events(engine)) == 1  # opening is not an event
    # renewed on day 368: a second closure, a second event with another dedupe key
    later = now + dt.timedelta(days=3)
    monkeypatch.setattr(ROUTER, "utcnow", lambda: later)
    r = api("PATCH", "/1/cbom/sources/evidence/hsm_firmware", json={"evidence_date": later.date().isoformat()})
    assert r.status_code == 200 and r.json()["area"]["effective_confidence"] == "E2", r.text
    rows = gaps(engine, key)
    assert [g.close_cause for g in rows] == ["evidence", "evidence"] and rows[1].closed_at == later
    events = [e for e in closed_events(engine) if e.asset_key == key]
    assert len(events) == 2 and events[0].dedupe_key != events[1].dedupe_key
    assert events[0].detail["opened_at"] != events[1].detail["opened_at"]
    assert events[1].detail["sub_reason"] == "evidence_expired"


def test_the_scheduler_tick_runs_the_register_tick(world, monkeypatch):
    from backend.workers import cbom_scheduler

    engine, _ = world
    seen = []
    monkeypatch.setattr(REG, "tick_due", lambda eng, now: seen.append(now) or {"opened": 0})
    out = cbom_scheduler.tick(engine, T0)
    assert seen == [T0] and "q0_register" in out


# ----------------------------------------------------------------------------- run items (DA-6) and model change
def _posture(api, run_id):
    r = api("GET", f"/1/cbom/sources/runs/{run_id}/posture")
    assert r.status_code == 200, r.text
    return r.json()["posture"]


def test_register_lists_every_gate_q0_with_its_reason(api, two_runs):
    engine = two_runs["engine"]
    assert DRIFT.record_pending_drift(engine, T0) == 2
    listed = items(api, status="open")
    by_key = {i["item_key"]: i for i in listed}
    assert len(by_key) == len(listed)  # keyset pages never repeat an item
    # evidence: every counted gap of the Evidence tab, with its reason
    evidence = api("GET", "/1/cbom/sources/evidence").json()
    want = {f"evidence:{g['id']}": g["reason"] for g in evidence["q0_gaps"] if g["counted"]}
    got = {k: i["sub_reason"] for k, i in by_key.items() if i["item_kind"] == "evidence"}
    assert got == want and len(want) == evidence["q0_gap_count"]
    # scope / asset / inputs: the latest run's Q0 items, with the run's reasons
    posture = _posture(api, two_runs["run2"]["id"])
    run_items = {i["key"]: i["reason"] for i in posture["q0_items"]}
    assert run_items, posture["q0_reasons"]
    got_run = {k: i["reason"] for k, i in by_key.items() if i["item_kind"] != "evidence"}
    assert got_run == run_items
    assert all(by_key[k]["run_id"] == two_runs["run2"]["id"] for k in run_items)
    # filters and paging
    small = q0(api, limit=2)
    assert len(small["items"]) == 2 and small["next_after"]
    assert {i["item_key"] for i in items(api, reason="evidence_e0")} == set(want)
    assert all(i["item_kind"] == "evidence" for i in items(api, kind="evidence"))
    # run 2 no longer has run 1's DSA host key (class unknown): a comparable collection closed it (observation)
    closed = items(api, status="closed")
    assert closed and {(i["item_kind"], i["close_cause"]) for i in closed} == {("asset", "observation")}
    assert {e.asset_key for e in closed_events(engine)} == {i["item_key"] for i in closed}
    assert q0(api)["counts"]["open"] == len(listed)
    assert api("GET", "/1/cbom/register/q0", params={"status": "bogus"}).status_code in (400, 422)
    assert api("GET", "/1/cbom/register/q0", params={"after": "not-a-cursor"}).status_code == 400
    # another team never sees team 1's register
    assert api("GET", "/1/cbom/register/q0", "carol").status_code in (403, 404)
    assert all(not i["item_key"].startswith(("source:", "coverage:", "asset:")) for i in items_team2(api))


def items_team2(api):
    r = api("GET", "/2/cbom/register/q0", "carol")
    assert r.status_code == 200, r.text
    return r.json()["items"]


def test_model_only_change_closes_nothing_that_is_forwarded(api, two_runs):
    """An asset Q0 recorded under another grade model that the current model grades: closed as ``model_change``,
    kept in the register, never a ``q0_closed`` event."""
    engine = two_runs["engine"]
    run1, run2 = two_runs["run1"]["id"], two_runs["run2"]["id"]
    with Session(engine) as s:
        assert DRIFT.record_run_drift(s, s.get(CbomCollectionRun_(), run1), T0) is not None
        s.commit()
        job = s.exec(select(CbomCollectionJob).where(CbomCollectionJob.run_id == run2,
                                                     CbomCollectionJob.source_id == two_runs["a"]["id"])).one()
        row = s.exec(select(CbomCollectedAsset).where(CbomCollectedAsset.job_id == job.id,
                                                      CbomCollectedAsset.asset_type == "tls_endpoint")).first()
        key = "asset:" + ID.stable_key("node", job.params["source_uid"], ID.node_identity(row))
        settings = s.exec(select(CbomCollectionSettings).where(CbomCollectionSettings.team_id == 1)).one()
        settings.risk_model = {"data_shelf_life_years": 10, "migration_years": 5, "threat_years": 12}
        s.add(settings)
        s.add(CbomQ0Gap(team_id=1, item_kind="asset", item_key=key, reason="unknown_verdict", run_id=run1,
                        opened_at=T0 - dt.timedelta(days=1), last_seen_at=T0 - dt.timedelta(days=1),
                        detail={"source_id": two_runs["a"]["id"], "model_version": "qg-0+000000000000"}))
        s.commit()
    before = len(closed_events(engine))
    assert DRIFT.record_pending_drift(engine, T0) == 1  # run 2
    [gap] = gaps(engine, key)
    assert gap.closed_at is not None and gap.close_cause == "model_change" and gap.closed_grade in ("Q1", "Q2", "Q3", "Q4")
    events = closed_events(engine)
    assert key not in {e.asset_key for e in events}  # not forwarded
    # the other closures of the same sync are real ones, and forwarded: Mosca set (inputs), the DSA key gone
    assert {e.detail["cause"] for e in events[before:]} == {"inputs", "observation"}
    closed = {i["item_key"]: i for i in items(api, status="closed")}
    assert closed[key]["close_cause"] == "model_change" and closed[key]["forwarded"] is False


def CbomCollectionRun_():
    from backend.new_models import CbomCollectionRun

    return CbomCollectionRun


def test_a_deleted_source_closes_its_items_as_removed(api, two_runs):
    engine = two_runs["engine"]
    assert DRIFT.record_pending_drift(engine, T0) == 2
    b = two_runs["b"]
    mine = [i for i in items(api, status="open") if i.get("source_id") == b["id"]]
    assert mine, "source B left something unread in run 2"
    assert api("DELETE", f"/1/cbom/sources/items/{b['id']}").status_code == 200
    REG.tick(engine, T0 + dt.timedelta(hours=1))
    for item in mine:
        [row] = [g for g in gaps(engine, item["item_key"]) if g.id == item["id"]]
        assert row.close_cause == "removed"


# ----------------------------------------------------------------------------- migration
def _migration():
    spec = importlib.util.spec_from_file_location("cb23q0gap001", MIGRATION)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


def test_migration_is_the_one_head():
    mod = _migration()
    revisions, parents = set(), set()
    for path in VERSIONS.glob("*.py"):
        text = path.read_text()
        rev = re.search(r"^revision(?::\s*str)?\s*=\s*['\"]([^'\"]+)['\"]", text, re.M)
        down = re.search(r"^down_revision[^=]*=\s*['\"]([^'\"]+)['\"]", text, re.M)
        if rev:
            revisions.add(rev.group(1))
        if down:
            parents.add(down.group(1))
    assert mod.revision == "cb23q0gap001" and mod.down_revision in revisions
    assert revisions - parents == {"cb23q0gap001"}


def test_migration_up_down_up_keeps_open_and_closed_gaps(tmp_path):
    from alembic.migration import MigrationContext
    from alembic.operations import Operations

    engine = sa.create_engine(f"sqlite:///{tmp_path / 'm.db'}")

    def run(step):
        with engine.begin() as conn:
            with Operations.context(MigrationContext.configure(conn)):
                getattr(_migration(), step)()

    with engine.begin() as conn:
        conn.execute(sa.text("CREATE TABLE team (id integer PRIMARY KEY)"))
        conn.execute(sa.text("INSERT INTO team (id) VALUES (1)"))
    run("upgrade")
    ins = sa.text("INSERT INTO cbomq0gap (team_id, item_kind, item_key, reason, detail, opened_at, closed_at, "
                  "close_cause) VALUES (1, 'evidence', 'evidence:area:x', 'evidence_e0', '{}', :o, :c, :cause)")
    with engine.begin() as conn:
        conn.execute(ins, {"o": "2026-01-01 00:00:00", "c": "2026-02-01 00:00:00", "cause": "evidence"})
        conn.execute(ins, {"o": "2026-03-01 00:00:00", "c": None, "cause": None})
        with pytest.raises(sa.exc.IntegrityError):  # one open row per item
            with conn.begin_nested():
                conn.execute(ins, {"o": "2026-04-01 00:00:00", "c": None, "cause": None})
        rows = conn.execute(sa.text("SELECT item_key, close_cause FROM cbomq0gap ORDER BY id")).all()
    assert [tuple(r) for r in rows] == [("evidence:area:x", "evidence"), ("evidence:area:x", None)]
    run("downgrade")
    assert "cbomq0gap" not in sa.inspect(engine).get_table_names()
    run("upgrade")
    assert "cbomq0gap" in sa.inspect(engine).get_table_names()
    names = {i["name"] for i in sa.inspect(engine).get_indexes("cbomq0gap")}
    assert {"uq_cbomq0gap_open_item", "ix_cbomq0gap_team_closed_opened"} <= names
    engine.dispose()
