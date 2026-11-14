"""CB-19 PR-2: a per-run snapshot of the grade inputs, taken at Start (PLAN §2.3-§2.8, §4 PR-2).

The run records the team's Mosca X/Y/Z and the evidence levels and Q0 gaps it was started with
(``cbomcollectionrun.grade_inputs``, ``grade_model_version``). Run views show the record grade; when the team's
inputs change afterwards, the run says so (``inputs_changed``) and gives the current grade beside it (``q_now``,
``q_grades_now``) without touching the record. The export names the snapshot's Q0 gaps (KF-14-snapshot).

    cd backend && PYTHONPATH=.. python -m pytest tests/test_cbom_cb19_grade_snapshot.py -q
"""
from __future__ import annotations

import datetime as dt
import hashlib
import importlib.util
import json
import os
import re
import sys
from pathlib import Path

import pytest
import sqlalchemy as sa
from sqlmodel import Session, select

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_cbom_sources_api as _base  # noqa: E402  (shared fixtures: SQLite world + real routers)

from backend.new_models import (  # noqa: E402
    CbomCollectedAsset,
    CbomCollectionJob,
    CbomCollectionRun,
    CbomCollectionSchedule,
    CbomEvidenceArea,
    CbomEvidenceVendor,
)
from backend.utilities.cbom_sources import inventory as INV  # noqa: E402
from backend.utilities.cbom_sources import qgrade as QG  # noqa: E402
from backend.utilities.cbom_sources import runs as RUNS  # noqa: E402
from backend.utilities.cbom_sources import schedules as S  # noqa: E402
from backend.utilities.cbom_sources.classify import classify  # noqa: E402
from backend.utilities.cbom_sources.schemas import RunCreate  # noqa: E402
from backend.utilities.cbom_sources.settings import get_or_create_settings  # noqa: E402

world = _base.world
api = _base.api
ROOT = Path(__file__).resolve().parents[2]
VERSIONS = ROOT / "prod_database_migrations" / "migrations" / "versions"
MIGRATION = VERSIONS / "cb19grade001_run_grade_inputs.py"
PG = os.environ.get("CBOM_TEST_PG_URL")
MOSCA = {"data_shelf_life_years": 10, "migration_years": 5, "threat_years": 12}
QV_TLS = {"protocols": ["TLSv1.2", "TLSv1.3"], "group": "x25519"}


# ----------------------------------------------------------------------------- helpers
def _settings(api) -> dict:
    return api("GET", "/1/cbom/sources/settings").json()["settings"]


def set_mosca(api, **values) -> dict:
    r = api("PATCH", "/1/cbom/sources/settings",
            json={"risk_model": values, "expected_version": _settings(api)["row_version"]})
    assert r.status_code == 200, r.text
    return r.json()["settings"]


def source(api, name="linux-dc", targets=("10.20.0.1",)) -> dict:
    node_id = getattr(source, "node", None)
    if node_id is None:
        node_id, _token, _ = _base.enroll_node(api)
        source.node = node_id  # type: ignore[attr-defined]
    r = api("POST", "/1/cbom/sources/items", json=_base.linux_body(name=name, node_id=node_id, targets=list(targets),
                                                                    window="any"))
    assert r.status_code == 201, r.text
    return r.json()["source"]


@pytest.fixture(autouse=True)
def _fresh_node():
    source.node = None  # type: ignore[attr-defined]
    yield


def start(api, request_id: str, source_ids=None) -> dict:
    body = {"include": {"servers": True}, "client_request_id": request_id}
    if source_ids:
        body["source_ids"] = source_ids
    r = api("POST", "/1/cbom/sources/runs", json=body)
    assert r.status_code == 201, r.text
    return r.json()["run"]


def run_row(engine, run_id: int) -> CbomCollectionRun:
    with Session(engine) as s:
        row = s.get(CbomCollectionRun, run_id)
        s.expunge(row)
        return row


def evidence(engine, today: dt.date) -> int:
    """key_hierarchy answered at E2 with a document 400 days old (expired -> E0), escrow_recovery at E1, one vendor
    that has never been sent a link. Returns the vendor id."""
    with Session(engine) as s:
        s.add(CbomEvidenceArea(team_id=1, area_key="key_hierarchy", confidence="E2", answers={"roots": "vault-zq7 in rack 4"},
                               evidence_title="Key policy", evidence_url="https://intranet.example/kp.pdf",
                               evidence_date=(today - dt.timedelta(days=400)).isoformat()))
        s.add(CbomEvidenceArea(team_id=1, area_key="escrow_recovery", confidence="E1", answers={"escrow": "none"}))
        vendor = CbomEvidenceVendor(team_id=1, name="Acme KMS", contact_email="kms@acme.example")
        s.add(vendor)
        s.commit()
        s.refresh(vendor)
        return int(vendor.id)


def add_asset(engine, run_id: int, location="10.20.0.1:443", type_="tls_endpoint", facts=None, target="10.20.0.1",
              algorithm=None, key_size=None) -> int:
    facts = dict(QV_TLS if facts is None else facts)
    with Session(engine) as s:
        job = s.exec(select(CbomCollectionJob).where(CbomCollectionJob.run_id == run_id)).first()
        v = classify(type_, algorithm, key_size, None, facts, dt.datetime.utcnow())
        row = CbomCollectedAsset(
            team_id=1, run_id=run_id, job_id=job.id, source_id=job.source_id, attempt=1,
            asset_key=hashlib.sha256(location.encode()).hexdigest(), asset_type=type_, cdx_type=v["cdx_type"],
            target=target, location=location, name=None, algorithm=algorithm, key_size=key_size,
            quantum_vulnerable=v["quantum_vulnerable"], impact=v["impact"], finding_codes=v["finding_codes"],
            finding=v["finding"], facts=facts)
        s.add(row)
        s.commit()
        s.refresh(row)
        return int(row.id)


def by_id(snapshot: dict) -> dict[str, dict]:
    return {item["id"]: item for item in snapshot["evidence"]["items"]}


# ----------------------------------------------------------------------------- the snapshot at Start
def test_snapshot_written_at_start_equals_the_settings_at_start(api, world):
    engine, _ids = world
    today = dt.datetime.utcnow().date()
    vendor_id = evidence(engine, today)
    settings = set_mosca(api, **MOSCA)
    src = source(api)
    run = start(api, "cb19-snap-0001")
    row = run_row(engine, run["id"])
    snap = row.grade_inputs
    assert row.grade_model_version == QG.GRADE_MODEL_VERSION == snap["model_version"]
    assert snap["model"] == "qg-1"
    assert snap["mosca"] == {"x": 10, "y": 5, "z": 12}
    assert snap["settings_row_version"] == settings["row_version"]
    assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", snap["captured_at"])
    assert re.fullmatch(r"[0-9a-f]{16}", snap["digest"])
    items = by_id(snap)
    # KF-14-snapshot: the run names key_hierarchy, expired, at E0; escrow is recorded with its level only
    kh = items["area:key_hierarchy"]
    assert (kh["kind"], kh["key"], kh["level"], kh["reason"]) == ("area", "key_hierarchy", "E0", "evidence_expired")
    assert kh["evidence_date"] == (today - dt.timedelta(days=400)).isoformat()
    assert (items["area:escrow_recovery"]["level"], items["area:escrow_recovery"]["reason"]) == ("E1", None)
    assert items["area:key_ceremonies"]["reason"] == "no_answer"  # never opened: no row, still recorded
    v = items[f"vendor:{vendor_id}"]
    assert (v["kind"], v["key"], v["level"], v["reason"]) == ("vendor", str(vendor_id), "E0", "vendor_not_asked")
    # the vendor-area roll-up is not an item (FP-8): the vendor carries the gap
    assert "area:third_party_vendors" not in items
    # the same count the Evidence tab shows
    ev = api("GET", "/1/cbom/sources/evidence").json()
    assert snap["evidence"]["gap_count"] == ev["q0_gap_count"] == sum(1 for i in items.values() if i["level"] == "E0")
    assert snap["evidence"]["as_of"] == today.isoformat()
    # no answers, e-mails or evidence URLs leave the evidence tables
    text = json.dumps(snap)
    assert "kms@acme.example" not in text and "intranet.example" not in text and "vault-zq7" not in text
    # the run API serves it
    grades = api("GET", f"/1/cbom/sources/runs/{run['id']}").json()["run"]["grades"]
    assert grades["inputs"] == snap and grades["inputs_digest"] == snap["digest"]
    assert grades["inputs_source"] == "snapshot" and grades["model_version"] == QG.GRADE_MODEL_VERSION
    assert grades["inputs_changed"] is False and grades["model_changed"] is False and grades["mosca_now"] is None
    assert src["id"]


def test_mosca_patch_after_start_leaves_the_record_and_sets_inputs_changed(api, world):
    engine, _ids = world
    set_mosca(api, **MOSCA)
    source(api)
    run = start(api, "cb19-snap-0002")
    asset = add_asset(engine, run["id"])  # quantum-vulnerable TLS endpoint on a private address: Q2 at 10 + 5 > 12
    before = run_row(engine, run["id"]).grade_inputs
    one = api("GET", f"/1/cbom/sources/assets/{asset}").json()["asset"]
    assert (one["q_grade"], one["q_reason"], one["q_now"]) == ("Q2", "qv_exceeds", None)

    set_mosca(api, threat_years=20)  # 10 + 5 <= 20: Q3 with the team's inputs now
    assert run_row(engine, run["id"]).grade_inputs == before  # the record never moves
    grades = api("GET", f"/1/cbom/sources/runs/{run['id']}").json()["run"]["grades"]
    assert grades["inputs_changed"] is True and grades["inputs"]["mosca"] == {"x": 10, "y": 5, "z": 12}
    assert grades["mosca_now"] == {"x": 10, "y": 5, "z": 20}
    detail = api("GET", f"/1/cbom/sources/assets/{asset}").json()["asset"]
    assert (detail["q_grade"], detail["q_reason"]) == ("Q2", "qv_exceeds")  # the record
    assert detail["q_explain"]["inputs_source"] == "snapshot" and detail["q_explain"]["z"] == 12
    assert detail["q_now"] == {"q_grade": "Q3", "q_label": "Medium", "q_reason": "qv_within"}
    listed = api("GET", f"/1/cbom/sources/runs/{run['id']}/assets").json()
    assert [i["q_grade"] for i in listed["items"]] == ["Q2"] and listed["grade_inputs"]["source"] == "snapshot"
    p = api("GET", f"/1/cbom/sources/runs/{run['id']}/posture").json()["posture"]
    assert p["q_grades"]["Q2"] == 1 and p["q_grades_now"]["Q3"] == 1 and p["q_grades_now"]["Q2"] == 0
    assert p["q_changed_now"] == 1 and p["inputs_changed"] is True
    assert (p["mosca"]["z"], p["mosca_now"]["z"]) == (12, 20)
    assert p["grade_inputs"]["source"] == "snapshot" and p["grade_inputs"]["mosca"]["z"] == 12

    set_mosca(api, threat_years=12)  # back to what the run recorded: nothing to show beside the record
    p = api("GET", f"/1/cbom/sources/runs/{run['id']}/posture").json()["posture"]
    assert p["q_grades_now"] is None and p["q_changed_now"] is None and p["inputs_changed"] is False
    assert api("GET", f"/1/cbom/sources/assets/{asset}").json()["asset"]["q_now"] is None


def test_a_run_from_before_the_snapshot_is_graded_with_current_inputs(api, world):
    engine, _ids = world
    set_mosca(api, **MOSCA)
    source(api)
    run = start(api, "cb19-snap-0003")
    with Session(engine) as s:  # what a run created before cb19grade001 looks like
        row = s.get(CbomCollectionRun, run["id"])
        row.grade_inputs, row.grade_model_version = None, None
        s.add(row)
        s.commit()
    asset = add_asset(engine, run["id"])
    set_mosca(api, threat_years=20)
    grades = api("GET", f"/1/cbom/sources/runs/{run['id']}").json()["run"]["grades"]
    assert grades == {"model_version": None, "inputs": None, "inputs_digest": None, "inputs_source": "current",
                      "inputs_changed": False, "model_changed": True, "mosca_now": None}
    detail = api("GET", f"/1/cbom/sources/assets/{asset}").json()["asset"]
    assert (detail["q_grade"], detail["q_now"], detail["q_explain"]["inputs_source"]) == ("Q3", None, "current")


def test_two_concurrent_starts_around_a_patch_each_snapshot_what_they_read(api, world):
    engine, ids = world
    set_mosca(api, **MOSCA)
    first, second = source(api, "linux-a"), source(api, "linux-b", targets=("10.20.0.2",))
    now = dt.datetime.utcnow()
    with Session(engine) as a:
        read_a = get_or_create_settings(a, 1)  # Start A has read the settings ...
        version_a = read_a.row_version
        patched = set_mosca(api, threat_years=30)  # ... an admin saves new inputs ...
        with Session(engine) as b:  # ... Start B reads after the save
            run_b, _ = RUNS.queue_run(b, 1, ids["alice"], RunCreate(include={"servers": True},
                                                                    client_request_id="cb19-conc-b",
                                                                    source_ids=[second["id"]]),
                                      get_or_create_settings(b, 1), now)
            b.commit()
            snap_b = dict(run_b.grade_inputs)
        run_a, _ = RUNS.queue_run(a, 1, ids["alice"], RunCreate(include={"servers": True},
                                                                client_request_id="cb19-conc-a",
                                                                source_ids=[first["id"]]), read_a, now)
        a.commit()
        snap_a = dict(run_a.grade_inputs)
    assert (snap_a["mosca"]["z"], snap_a["settings_row_version"]) == (12, version_a)
    assert (snap_b["mosca"]["z"], snap_b["settings_row_version"]) == (30, patched["row_version"])
    assert snap_a["digest"] != snap_b["digest"]


def test_a_scheduled_run_snapshots_at_its_slot(api, world):
    engine, _ids = world
    source(api)
    set_mosca(api, **MOSCA)
    r = api("POST", "/1/cbom/sources/schedules", json={"name": "nightly", "frequency": "daily", "time_of_day": "02:00",
                                                        "include": {"servers": True}})
    assert r.status_code == 201, r.text
    sched = r.json()["schedule"]
    set_mosca(api, threat_years=25)  # changed after the schedule was saved, before its slot
    slot = dt.datetime(2026, 11, 5, 2, 0)
    with Session(engine) as s:
        row = s.get(CbomCollectionSchedule, sched["id"])
        row.next_run_at = slot
        s.add(row)
        s.commit()
    fired = S.fire_due(engine, slot + dt.timedelta(seconds=30))
    assert len(fired) == 1 and fired[0]["status"] == "queued", fired
    with Session(engine) as s:
        run = s.exec(select(CbomCollectionRun).where(CbomCollectionRun.schedule_id == sched["id"])).one()
        snap = run.grade_inputs
    assert snap["mosca"] == {"x": 10, "y": 5, "z": 25}
    assert snap["captured_at"] == "2026-11-05T02:00:30Z"
    assert run.grade_model_version == QG.GRADE_MODEL_VERSION


def test_gap_identity_is_stable_when_the_reason_changes(world):
    engine, _ids = world
    now = dt.datetime.utcnow()
    with Session(engine) as s:
        settings = get_or_create_settings(s, 1)
        first = QG.snapshot_inputs(s, 1, settings, now)
        area = CbomEvidenceArea(team_id=1, area_key="key_hierarchy", confidence="E0", answers={"roots": "HSM"})
        s.add(area)
        s.commit()
        second = QG.snapshot_inputs(s, 1, settings, now)
    a, b = by_id(first)["area:key_hierarchy"], by_id(second)["area:key_hierarchy"]
    assert (a["reason"], b["reason"]) == ("no_answer", "rated_unknown")
    assert (a["id"], a["kind"], a["key"]) == (b["id"], b["kind"], b["key"])
    assert first["digest"] != second["digest"]  # the inputs differ, so does their digest
    # captured_at is not part of the digest: the same inputs a minute later give the same digest
    with Session(engine) as s:
        later = QG.snapshot_inputs(s, 1, get_or_create_settings(s, 1), now + dt.timedelta(minutes=1))
    assert later["digest"] == second["digest"] and later["captured_at"] != second["captured_at"]


# ----------------------------------------------------------------------------- the export (KF-14-snapshot)
def _meta(doc: dict) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for p in doc["metadata"]["properties"]:
        out.setdefault(p["name"], []).append(p["value"])
    return out


def test_export_names_the_snapshot_gaps_and_the_unread_scope(api, world):
    engine, _ids = world
    today = dt.datetime.utcnow().date()
    vendor_id = evidence(engine, today)
    set_mosca(api, **MOSCA)
    source(api)
    run = start(api, "cb19-snap-0004")
    add_asset(engine, run["id"])
    add_asset(engine, run["id"], location="10.20.0.1#BitLocker", type_="coverage", target="10.20.0.1",
              facts={"check": "TPM", "status": "denied", "detail": "access denied"})
    # an evidence answer after Start changes nothing in this run's export
    with Session(engine) as s:
        job = s.exec(select(CbomCollectionJob).where(CbomCollectionJob.run_id == run["id"])).one()
        job.status, job.outcome = "success", "ok"  # read: the only unread scope is the denied check
        s.add(job)
        area = s.exec(select(CbomEvidenceArea).where(CbomEvidenceArea.area_key == "key_hierarchy")).one()
        area.evidence_date = today.isoformat()
        s.add(area)
        s.commit()
    r = api("GET", f"/1/cbom/sources/runs/{run['id']}/cbom")
    assert r.status_code == 200, r.text
    meta = _meta(r.json())
    gaps = [json.loads(v) for v in meta["zs:q0_gap"]]
    keyed = {(g["kind"], g["key"]): g for g in gaps}
    kh = keyed[("area", "key_hierarchy")]
    assert kh["reason"] == "evidence_expired" and kh["as_of"] == today.isoformat() and kh["level"] == "E0"
    assert keyed[("vendor", str(vendor_id))]["reason"] == "vendor_not_asked"
    assert ("area", "escrow_recovery") not in keyed  # E1: recorded in the snapshot, not a gap
    assert ("area", "third_party_vendors") not in keyed
    scope = [g for g in gaps if g["kind"] == "scope"]
    assert [g["reason"] for g in scope] == ["coverage_gap"] and scope[0]["key"].endswith(":10.20.0.1:TPM")
    snap = run_row(engine, run["id"]).grade_inputs
    assert int(meta["zs:q0_gap_count"][0]) == len(gaps) == snap["evidence"]["gap_count"] + len(scope)
    # the same in XML
    x = api("GET", f"/1/cbom/sources/runs/{run['id']}/cbom?format=xml")
    assert x.status_code == 200 and x.text.count('name="zs:q0_gap"') == len(gaps)


def test_export_gap_cap_keeps_the_count_exact(world, monkeypatch):
    monkeypatch.setattr(INV, "Q0_GAP_CAP", 2)
    items = [{"id": f"area:a{i}", "kind": "area", "key": f"a{i}", "level": "E0", "reason": "no_answer",
              "detail": None} for i in range(5)]
    props = INV.q0_gap_properties({"evidence": {"as_of": "2026-11-14", "items": items}}, [])
    assert props[0] == {"name": "zs:q0_gap_count", "value": "5"}
    assert [p["name"] for p in props[1:]] == ["zs:q0_gap", "zs:q0_gap"]
    assert INV.Q0_GAP_CAP == 2 and QG.GRADE_MODEL == "qg-1"


def test_export_of_a_run_without_snapshot_lists_only_the_scope(world):
    props = INV.q0_gap_properties(None, [{"key": "source:abc", "kind": "scope", "reason": "source_not_read",
                                          "detail": "collection failure", "count": 1}])
    assert props[0]["value"] == "1"
    assert json.loads(props[1]["value"]) == {"key": "source:abc", "kind": "scope", "reason": "source_not_read",
                                             "detail": "collection failure", "as_of": None, "count": 1}


# ----------------------------------------------------------------------------- the migration
def _migration():
    spec = importlib.util.spec_from_file_location("cb19grade001", MIGRATION)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


def test_migration_is_the_one_head():
    mod = _migration()
    assert mod.revision == "cb19grade001"
    revisions, parents = set(), set()
    for path in VERSIONS.glob("*.py"):
        text = path.read_text()
        rev = re.search(r"^revision(?::\s*str)?\s*=\s*['\"]([^'\"]+)['\"]", text, re.M)
        down = re.search(r"^down_revision[^=]*=\s*['\"]([^'\"]+)['\"]", text, re.M)
        if rev:
            revisions.add(rev.group(1))
        if down:
            parents.add(down.group(1))
    assert mod.down_revision in revisions
    assert revisions - parents == {"cb19grade001"}


def _columns(conn) -> set[str]:
    return {c["name"] for c in sa.inspect(conn).get_columns("cbomcollectionrun")}


def _rows(conn) -> list[tuple]:
    return [tuple(r) for r in conn.execute(sa.text(
        "SELECT id, status, kb_version, last_updated FROM cbomcollectionrun ORDER BY id"))]


def _up_down_up(engine):
    from alembic.migration import MigrationContext
    from alembic.operations import Operations

    def run(step):
        with engine.begin() as conn:
            with Operations.context(MigrationContext.configure(conn)):
                getattr(_migration(), step)()
        with engine.begin() as conn:
            return _columns(conn), _rows(conn)

    with engine.begin() as conn:
        conn.execute(sa.text("DROP TABLE IF EXISTS cbomcollectionrun"))
        conn.execute(sa.text("CREATE TABLE cbomcollectionrun (id integer PRIMARY KEY, status varchar(16) NOT NULL, "
                             "kb_version varchar(32), last_updated varchar(32))"))
        for i in range(1, 4):
            conn.execute(sa.text("INSERT INTO cbomcollectionrun (id, status, kb_version, last_updated) "
                                 "VALUES (:i, 'finished', 'kb-1', '2026-11-01T00:00:00Z')"), {"i": i})
        before = _rows(conn)
    try:
        cols, rows = run("upgrade")
        assert {"grade_model_version", "grade_inputs"} <= cols and rows == before
        with engine.begin() as conn:  # old runs read NULL (served as inputs_source: current); a new run writes one
            assert conn.execute(sa.text("SELECT count(*) FROM cbomcollectionrun WHERE grade_inputs IS NULL "
                                        "AND grade_model_version IS NULL")).scalar() == 3
            conn.execute(sa.text("UPDATE cbomcollectionrun SET grade_model_version = :v, grade_inputs = :j "
                                 "WHERE id = 3"), {"v": "qg-1+0123456789ab", "j": json.dumps({"mosca": {"x": 1}})})
        cols, rows = run("downgrade")
        assert not ({"grade_model_version", "grade_inputs"} & cols) and rows == before
        cols, rows = run("upgrade")
        assert {"grade_model_version", "grade_inputs"} <= cols and rows == before
    finally:
        with engine.begin() as conn:
            conn.execute(sa.text("DROP TABLE IF EXISTS cbomcollectionrun"))
        engine.dispose()


def test_migration_up_down_up_on_sqlite(tmp_path):
    _up_down_up(sa.create_engine(f"sqlite:///{tmp_path / 'm.db'}"))


@pytest.mark.skipif(not PG, reason="set CBOM_TEST_PG_URL to run against PostgreSQL")
def test_migration_up_down_up_on_postgresql():
    _up_down_up(sa.create_engine(PG))
