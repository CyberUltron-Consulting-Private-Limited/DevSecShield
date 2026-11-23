"""SOW S4 in the delivered files (FIX-D1): drift between a run and the previous comparable run is in the run report
PDF and the evidence pack (``drift.json``), from the same comparison ``GET /runs/{id}/diff`` answers (Rule P); a run
records what started it (``trigger`` "scheduled" / "manual" with ``schedule_id``), shown by the run API and the run
list; ``weekly_drift`` exposes recorded drift per week for D12.

Failing first on dev 214d3ca1e: the report and the pack carry no drift (audit-D D-S4-1: grep "drift" in
cbom_run_pdf.py finds nothing), the pack has no drift.json, the run API and the run list have no ``trigger`` or
``schedule_id`` (run 53 on staging: "schedule_id None, trigger None"), and ``drift_report`` does not exist.
Same SQLite + real-router harness as test_cbom_sources_api.py.
"""
from __future__ import annotations

import datetime as dt
import io
import json
import re
import sys
import zipfile
from pathlib import Path

import pytest
import sqlalchemy as sa
from sqlmodel import Session

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_cbom_sources_api as SOURCES_API  # noqa: E402
from test_cbom_sources_api import enroll_node, linux_body  # noqa: E402
from test_cbom_wp10_outputs import make_two_runs  # noqa: E402
from test_cbom_run_deliverables import _finish, _pdf_text  # noqa: E402

from backend.new_models import CbomCollectionRun, CbomCollectionSchedule, CbomDriftEvent  # noqa: E402

# the shared SQLite + real-router fixtures, registered without a module-level name the test parameters shadow
globals().update(api=SOURCES_API.api, world=SOURCES_API.world)
ROOT = Path(__file__).resolve().parents[2]
VERSIONS = ROOT / "prod_database_migrations" / "migrations" / "versions"


def _flat(text: str) -> str:
    return " ".join(text.split())


@pytest.fixture()
def finished_two_runs(api, world):
    runs = make_two_runs(api, world)
    for key in ("run1", "run2"):
        _finish(runs["engine"], runs[key]["id"])
    return runs


# ----------------------------------------------------------------------------- run report PDF
def test_report_pdf_carries_the_diff_numbers_since_the_previous_comparable_run(api, finished_two_runs, tmp_path):
    r1, r2 = finished_two_runs["run1"]["id"], finished_two_runs["run2"]["id"]
    diff = api("GET", f"/1/cbom/sources/runs/{r2}/diff").json()
    assert diff["against_run_id"] == r1
    counts = diff["counts"]
    assert counts["added"] >= 1 and counts["removed"] >= 1 and counts["compared_sources"] >= 1
    r = api("GET", f"/1/cbom/sources/runs/{r2}/report.pdf")
    assert r.status_code == 200, r.text
    text = _flat(_pdf_text(r.content, tmp_path))
    assert f"Changes since run #{r1}" in text
    for label, key in (("Assets added", "added"), ("Assets removed", "removed"), ("Assets changed", "changed"),
                       ("Findings opened (new)", "opened"), ("Findings resolved (closed)", "resolved")):
        assert f"{label} {counts[key]}" in text, label  # Rule P: the /diff number, not a recount
    assert f"{counts['compared_sources']} compared, {counts['not_compared_sources']} not compared" in text
    ready = diff["readiness"]
    if ready["before"] is not None and ready["after"] is not None:
        assert f"{ready['before']:.1f}% → {ready['after']:.1f}%" in text
    assert "Q0 Unknown closed" in text and "Risk-register Q0 gaps this run closed" in text


def test_first_run_report_says_there_is_nothing_to_compare(api, finished_two_runs, tmp_path):
    text = _flat(_pdf_text(api("GET", f"/1/cbom/sources/runs/{finished_two_runs['run1']['id']}/report.pdf").content,
                           tmp_path))
    assert "Changes since the previous comparable run" in text
    assert "nothing to compare yet" in text


def test_a_drift_failure_never_costs_the_report(api, finished_two_runs, tmp_path, monkeypatch):
    from backend.utilities.cbom_sources import drift_report

    def boom(*_a, **_k):
        raise RuntimeError("diff exploded")

    monkeypatch.setattr(drift_report.DRIFT, "run_diff", boom)
    r = api("GET", f"/1/cbom/sources/runs/{finished_two_runs['run2']['id']}/report.pdf")
    assert r.status_code == 200 and r.content.startswith(b"%PDF")
    assert "Drift could not be computed" in _flat(_pdf_text(r.content, tmp_path))


# ----------------------------------------------------------------------------- evidence pack
def test_evidence_pack_has_drift_json_equal_to_the_diff(api, finished_two_runs):
    r1, r2 = finished_two_runs["run1"]["id"], finished_two_runs["run2"]["id"]
    diff = api("GET", f"/1/cbom/sources/runs/{r2}/diff").json()
    pack = api("GET", f"/1/cbom/sources/runs/{r2}/evidence-pack")
    assert pack.status_code == 200, pack.text
    zf = zipfile.ZipFile(io.BytesIO(pack.content))
    manifest = json.loads(zf.read("manifest.json"))
    entry = next(f for f in manifest["files"] if f["name"] == "drift.json")
    assert entry["endpoint"] == f"/1/cbom/sources/runs/{r2}/diff" and entry["endpoint_same_bytes"] is False
    doc = json.loads(zf.read("drift.json"))
    assert doc["format"] == "zeroshield-cbom-run-drift/1"
    assert doc["run"]["id"] == r2 and doc["baseline"]["id"] == r1
    for key in ("added", "removed", "changed", "opened", "resolved", "not_read", "compared_sources",
                "not_compared_sources"):
        assert doc["counts"][key] == diff["counts"][key], key
    assert doc["readiness"] == diff["readiness"]
    assert [i["key"] for i in doc["added"]] == [i["key"] for i in diff["added"][:doc["top"]]]
    assert set(doc["q0"]) >= {"closed", "opened", "removed", "register_closed", "register_closed_total"}
    assert doc["run"]["trigger"] == "manual" and doc["baseline"]["trigger"] == "manual"
    # a finished run's pack is the same bytes on every download, drift.json included
    assert api("GET", f"/1/cbom/sources/runs/{r2}/evidence-pack").content == pack.content


# ----------------------------------------------------------------------------- drift_report units
def test_q0_transitions_read_the_diff_lists():
    from backend.utilities.cbom_sources.drift_report import q0_transitions

    diff = {"changed": [{"changes": {"q_grade": ["Q0", "Q2"]}}, {"changes": {"q_grade": ["Q3", "Q0"]}},
                        {"changes": {"q_grade": ["Q2", "Q1"]}}, {"changes": {"key_size": [1024, 2048]}}],
            "added": [{"q_grade": "Q0"}, {"q_grade": "Q4"}], "removed": [{"q_grade": "Q0"}, {"q_grade": None}]}
    assert q0_transitions(diff) == {"closed": 1, "opened": 2, "removed": 1}
    assert q0_transitions({}) == {"closed": 0, "opened": 0, "removed": 0}


def test_register_closures_count_only_this_runs_q0_closed_events(world):
    from backend.utilities.cbom_sources.drift_report import register_closures

    engine, _ = world
    now = dt.datetime.utcnow()
    with Session(engine) as s:
        run = CbomCollectionRun(team_id=1, owner_user_id=1, client_request_id="drift-q0", status="done",
                                created_at=now - dt.timedelta(minutes=5), last_updated=now)
        s.add(run)
        s.commit()
        s.refresh(run)
        for i, (rid, cause) in enumerate(((run.id, "observation"), (run.id, "observation"), (run.id, "removed"),
                                          (run.id + 999, "observation"))):
            s.add(CbomDriftEvent(team_id=1, at=now, scope="register", kind="q0_closed", dedupe_key=f"q0-{i}",
                                 detail={"run_id": rid, "cause": cause}))
        s.add(CbomDriftEvent(team_id=2, at=now, scope="register", kind="q0_closed", dedupe_key="other-team",
                             detail={"run_id": run.id, "cause": "observation"}))
        s.commit()
        assert register_closures(s, run) == {"observation": 2, "removed": 1}


def test_weekly_drift_buckets_recorded_events_by_iso_week(world):
    from backend.utilities.cbom_sources.drift_report import WEEKLY_KINDS, weekly_drift

    engine, _ = world
    now = dt.datetime(2026, 11, 23, 12, 0)  # a Monday
    with Session(engine) as s:
        for i, (days, kind) in enumerate(((0, "opened"), (1, "resolved"), (7, "q0_closed"), (8, "q0_closed"),
                                          (9, "new_asset"), (200, "opened"), (0, "cert_expiring"))):
            s.add(CbomDriftEvent(team_id=1, at=now - dt.timedelta(days=days), kind=kind, dedupe_key=f"wk-{i}"))
        s.add(CbomDriftEvent(team_id=2, at=now, kind="opened", dedupe_key="wk-other"))
        s.commit()
        series = weekly_drift(s, 1, now, weeks=4)
    assert [w["week"] for w in series] == ["2026-11-02", "2026-11-09", "2026-11-16", "2026-11-23"]
    assert set(series[0]) == {"week", *WEEKLY_KINDS}
    assert series[-1]["opened"] == 1 and series[-1]["resolved"] == 0
    # a day back is Sunday 22nd (last week), a week back is Monday 16th, 8 and 9 days back fall in the week of the 9th
    assert series[-2] == {"week": "2026-11-16", "opened": 0, "resolved": 1, "new_asset": 0, "removed_asset": 0,
                          "q0_closed": 1}
    assert series[-3] == {"week": "2026-11-09", "opened": 0, "resolved": 0, "new_asset": 1, "removed_asset": 0,
                          "q0_closed": 1}
    assert sum(w["opened"] for w in series) == 1  # 200 days ago is outside the window; team 2 never counted


# ----------------------------------------------------------------------------- what started the run
def test_a_manual_run_says_manual_in_the_run_api_and_the_run_list(api, finished_two_runs):
    from backend.utilities.cbom_sources.run_list import list_run_rows

    rid = finished_two_runs["run2"]["id"]
    run = api("GET", f"/1/cbom/sources/runs/{rid}").json()["run"]
    assert (run["trigger"], run["schedule_id"], run["schedule_name"]) == ("manual", None, None)
    with Session(finished_two_runs["engine"]) as s:
        row = next(r for r in list_run_rows(s, 1)["runs_list_data"] if r["id"] == rid)
    assert (row["trigger"], row["schedule_id"], row["schedule_name"]) == ("manual", None, None)


def test_a_scheduled_run_records_its_schedule_and_shows_its_name(api, world):
    from backend.utilities.cbom_sources import schedules as S
    from backend.utilities.cbom_sources.run_list import list_run_rows

    engine, _ = world
    node_id, _token, _ = enroll_node(api)
    assert api("POST", "/1/cbom/sources/items",
               json=linux_body(node_id=node_id, targets=["10.20.0.1"], window="any")).status_code == 201
    sched = api("POST", "/1/cbom/sources/schedules", json={
        "name": "nightly re-scan", "frequency": "daily", "time_of_day": "02:00", "include": {"servers": True}}
                ).json()["schedule"]
    with Session(engine) as s:
        row = s.get(CbomCollectionSchedule, sched["id"])
        row.next_run_at = dt.datetime(2026, 11, 5, 2, 0)
        s.add(row)
        s.commit()
    fired = S.fire_due(engine, dt.datetime(2026, 11, 5, 2, 1))
    assert fired and fired[0]["status"] == "queued"
    rid = fired[0]["run_id"]
    with Session(engine) as s:
        stored = s.get(CbomCollectionRun, rid)
        assert (stored.trigger, stored.schedule_id) == ("scheduled", sched["id"])
    run = api("GET", f"/1/cbom/sources/runs/{rid}").json()["run"]
    assert (run["trigger"], run["schedule_id"], run["schedule_name"]) == ("scheduled", sched["id"], "nightly re-scan")
    with Session(engine) as s:
        row = next(r for r in list_run_rows(s, 1)["runs_list_data"] if r["id"] == rid)
    assert (row["trigger"], row["schedule_id"], row["schedule_name"]) == ("scheduled", sched["id"], "nightly re-scan")
    # the schedule is deleted: the run keeps saying scheduled, with the id and no name
    assert api("DELETE", f"/1/cbom/sources/schedules/{sched['id']}").status_code == 200
    run = api("GET", f"/1/cbom/sources/runs/{rid}").json()["run"]
    assert (run["trigger"], run["schedule_id"], run["schedule_name"]) == ("scheduled", sched["id"], None)


def test_run_trigger_falls_back_to_schedule_id_for_unbackfilled_rows():
    from backend.utilities.cbom_sources.serialize import run_trigger

    assert run_trigger(CbomCollectionRun(team_id=1, owner_user_id=1, client_request_id="a", schedule_id=7)) \
        == "scheduled"
    assert run_trigger(CbomCollectionRun(team_id=1, owner_user_id=1, client_request_id="b")) == "manual"


# ----------------------------------------------------------------------------- migration
def _migration():
    import importlib.util

    path = VERSIONS / "rsched1trig001_run_trigger.py"
    spec = importlib.util.spec_from_file_location("rsched1trig001", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_migration_is_the_one_head_after_rpdf1brand001():
    mod = _migration()
    assert (mod.revision, mod.down_revision) == ("rsched1trig001", "rpdf1brand001")
    revisions, parents = set(), set()
    for path in VERSIONS.glob("*.py"):
        text = path.read_text()
        rev = re.search(r"^revision(?::\s*str)?\s*=\s*['\"]([^'\"]+)['\"]", text, re.M)
        down = re.search(r"^down_revision[^=]*=\s*(.+)$", text, re.M)
        if rev:
            revisions.add(rev.group(1))
        if down:
            parents.update(re.findall(r"""['"]([^'"]+)['"]""", down.group(1)))
    assert revisions - parents == {"rsched1trig001"}


def test_migration_up_down_up_backfills_from_schedule_id(tmp_path):
    from alembic.migration import MigrationContext
    from alembic.operations import Operations

    engine = sa.create_engine(f"sqlite:///{tmp_path / 'm.db'}")

    def step(name):
        with engine.begin() as conn:
            with Operations.context(MigrationContext.configure(conn)):
                getattr(_migration(), name)()

    def rows():
        with engine.begin() as conn:
            cols = {c["name"] for c in sa.inspect(conn).get_columns("cbomcollectionrun")}
            if "trigger" not in cols:
                return cols, None
            return cols, [tuple(r) for r in conn.execute(sa.text(
                "SELECT id, schedule_id, trigger FROM cbomcollectionrun ORDER BY id"))]

    with engine.begin() as conn:
        conn.execute(sa.text("CREATE TABLE cbomcollectionrun (id integer PRIMARY KEY, status varchar(16) NOT NULL, "
                             "schedule_id integer)"))
        conn.execute(sa.text("INSERT INTO cbomcollectionrun (id, status, schedule_id) VALUES "
                             "(1, 'done', NULL), (2, 'done', 4), (3, 'queued', NULL)"))
    step("upgrade")
    cols, got = rows()
    assert "trigger" in cols and got == [(1, None, "manual"), (2, 4, "scheduled"), (3, None, "manual")]
    with engine.begin() as conn:  # the default applies to rows written without it; the check refuses others
        conn.execute(sa.text("INSERT INTO cbomcollectionrun (id, status) VALUES (4, 'queued')"))
        with pytest.raises(sa.exc.IntegrityError):
            with conn.begin_nested():
                conn.execute(sa.text("UPDATE cbomcollectionrun SET trigger = 'cron' WHERE id = 4"))
    assert rows()[1][-1] == (4, None, "manual")
    step("downgrade")
    assert "trigger" not in rows()[0]
    step("upgrade")
    assert rows()[1] == [(1, None, "manual"), (2, 4, "scheduled"), (3, None, "manual"), (4, None, "manual")]
    engine.dispose()
