"""Staging QA round 2, lane Q1 minors on the run lifecycle and S4:

* Q1-10: a schedule's "Last" said "Run #58 queued" for a run that had finished: ``last_status`` was written once, at
  the slot; the list now reads the run's status.
* Q1-12: a run held by the scan window had no ``status_reason``.
* Q1-14: drift's "not compared" said "collected completely in only one of the two runs" for a source outside the
  run's scope and for one collected for the first time; the per-source reason and the counts now tell them apart.
* Q1-15: every D14 download became an issue, so a quick look became the next report's "previous issue"; now only a
  formal issue is recorded (``issue=1``, or the first download of the day while no run is active; never a preview).
"""
from __future__ import annotations

import datetime as dt
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from backend.new_models import CbomCollectionAuditEvent, CbomCollectionRun  # noqa: E402
from backend.utilities.cbom_sources import drift as D  # noqa: E402
from backend.utilities.cbom_sources import schedules as SCHED  # noqa: E402
from backend.utilities.cbom_sources.run_status import WINDOW_WAIT, status_reason  # noqa: E402
from backend.utilities.dashboard import cbom_board_issues as ISSUES  # noqa: E402
from backend.utilities.pdf.cbom_run_pdf import not_compared_text  # noqa: E402
from sqlmodel import Session, select  # noqa: E402


# ----------------------------------------------------------------------------- Q1-10
def _schedule(status: str, message: str, run_id: int | None = 58) -> SimpleNamespace:
    return SimpleNamespace(last_status=status, last_message=message, last_run_id=run_id)


@pytest.mark.parametrize(("run_status", "expected"), [
    ("done", ("done", "Run #58 done")), ("partial", ("partial", "Run #58 partly done")),
    ("failed", ("failed", "Run #58 failed")), ("running", ("running", "Run #58 running")),
    ("queued", ("queued", "Run #58 queued")), (None, ("queued", "Run #58 queued")),
])
def test_the_schedule_reads_its_last_runs_final_status(run_status, expected):
    assert SCHED.last_outcome(_schedule("queued", "Run #58 queued"), run_status) == expected


def test_a_skipped_slot_and_a_catch_up_note_are_kept():
    skipped = _schedule("skipped", "No source matches the schedule's sources and criticality", None)
    assert SCHED.last_outcome(skipped, "done") == ("skipped", skipped.last_message)
    caught = _schedule("queued", "Run #58 queued (catch-up: 2 earlier slot(s) not run)")
    assert SCHED.last_outcome(caught, "done") == ("done", "Run #58 done (catch-up: 2 earlier slot(s) not run)")


# ----------------------------------------------------------------------------- Q1-12
def test_a_run_waiting_for_the_scan_window_says_so():
    jobs = [{"id": 508, "status": "pending", "source_name": "range-8.8.8.8", "waiting_reason": WINDOW_WAIT}]
    out = status_reason("queued", jobs)
    assert out["status_reason"] == ("1 of 1 jobs wait for the scan window: it starts when the window opens "
                                    "(Settings, scan window)")
    assert out["status_reason_jobs"][0]["category"] == "waiting"
    both = status_reason("running", [*jobs, {"id": 509, "status": "pending", "source_name": "n",
                                             "waiting_reason": "Scan node x is offline since 2026-11-15 08:34 UTC; "
                                                               "the job expires at 2026-11-24 11:37 UTC unless it "
                                                               "comes back"}])
    assert both["status_reason"].startswith("1 of 2 jobs wait for an offline scan node")
    assert "1 of 2 jobs wait for the scan window" in both["status_reason"]
    assert status_reason("queued", [{"id": 1, "status": "pending", "waiting_reason": "Waiting for the scan node to "
                                     "pick it up"}])["status_reason"] is None


# ----------------------------------------------------------------------------- Q1-14
def test_the_pdf_line_separates_the_reasons():
    assert not_compared_text({"not_compared_sources": 3, "not_compared_outside_scope": 2,
                              "not_compared_first_collection": 1}) == (
        " (2 outside this run's scope, 1 collected only once)")
    assert not_compared_text({"not_compared_sources": 0}) == ""
    assert not_compared_text({"not_compared_sources": 1}) == " (collected completely in only one of the two runs)"


from test_cbom_cb20_estate import World, _sqlite, endpoint  # noqa: E402


@pytest.fixture
def estate(tmp_path):
    engine = _sqlite(tmp_path / "estate.db")
    yield World(engine)
    engine.dispose()


def _diff(w: World, run_id: int, base_id: int) -> dict:
    with Session(w.engine) as s:
        return D.run_diff(s, s.get(CbomCollectionRun, run_id), s.get(CbomCollectionRun, base_id))


def test_run_diff_tells_outside_scope_from_collected_only_once(estate: World):
    lab, new = estate.source("network", "Lab network"), estate.source("database", "PostgreSQL 16")
    r1 = estate.run({lab: {"rows": [endpoint("10.0.0.5")]}})
    r2 = estate.run({lab: {"rows": [endpoint("10.0.0.5")]}, new: {"rows": [endpoint("10.0.0.20", 5432)]}})
    r3 = estate.run({lab: {"rows": [endpoint("10.0.0.5")]}})  # a scheduled run whose scope is the lab only
    r4 = estate.run({lab: {"rows": [endpoint("10.0.0.5")]}, new: {"rows": [endpoint("10.0.0.20", 5432)]}})
    first = {s["name"]: s for s in _diff(estate, r2, r1)["sources"]}["PostgreSQL 16"]
    assert (first["reason_code"], first["reason"]) == ("first_collection",
                                                       f"collected only once: run #{r2} is its first collection")
    outside = _diff(estate, r3, r2)
    entry = {s["name"]: s for s in outside["sources"]}["PostgreSQL 16"]
    assert entry["reason_code"] == "outside_scope" and entry["reason"].startswith("outside this run's scope")
    assert outside["counts"]["not_compared_outside_scope"] == 1 and outside["counts"]["not_compared_sources"] == 1
    back = {s["name"]: s for s in _diff(estate, r4, r3)["sources"]}["PostgreSQL 16"]
    assert back["reason_code"] == "outside_baseline_scope"


# ----------------------------------------------------------------------------- Q1-15
@pytest.mark.parametrize(("explicit", "preview", "active", "expected"), [
    (False, False, 0, ISSUES.FIRST_DOWNLOAD), (False, False, 1, None), (True, False, 1, ISSUES.EXPLICIT),
    (False, True, 0, None), (True, True, 0, None),
])
def test_a_formal_issue_is_explicit_or_the_first_stable_download(explicit, preview, active, expected):
    assert ISSUES.formal_issue(explicit=explicit, preview=preview, active_runs=active) == expected


import test_cbom_pr485_review as R485  # noqa: E402
from test_cbom_pr485_review import api, seeded, world  # noqa: E402, F401


def _issues(engine) -> int:
    with Session(engine) as s:
        return len(s.exec(select(CbomCollectionAuditEvent).where(
            CbomCollectionAuditEvent.action == ISSUES.ACTION)).all())


def test_a_preview_is_never_an_issue_and_a_run_in_progress_holds_the_plain_download(api, seeded):  # noqa: F811
    engine, _w = seeded
    with Session(engine) as s:
        active = s.exec(select(CbomCollectionRun).where(CbomCollectionRun.status.in_(("queued", "running")))).all()
    assert api("GET", R485.D14 + "?preview=1").status_code == 200
    assert _issues(engine) == 0  # a preview never becomes the "previous issue"
    if active:
        assert api("GET", R485.D14).status_code == 200 and _issues(engine) == 0
    assert api("GET", R485.D14 + "?issue=1").status_code == 200
    assert _issues(engine) == 1
    assert api("GET", R485.D14).status_code == 200 and _issues(engine) == 1  # a re-download: the same issue


def test_a_run_stuck_for_days_never_holds_a_formal_issue_back(tmp_path):
    """#497 review m1: staging run #50 has been "running" since 18 Nov (an offline node); only an open run that
    changed in the last 24 hours makes a plain download a draft."""
    from sqlmodel import SQLModel, create_engine

    from backend.routers.cbom_deliverables import ACTIVE_RUN_WINDOW, _active_runs

    engine = create_engine(f"sqlite:///{tmp_path / 'runs.db'}")
    SQLModel.metadata.create_all(engine, tables=[CbomCollectionRun.__table__])
    now = dt.datetime(2026, 11, 24, 12, 0, tzinfo=dt.timezone.utc)
    with Session(engine) as s:
        s.add(CbomCollectionRun(team_id=1, owner_user_id=1, client_request_id="stuck", status="running",
                                created_at=dt.datetime(2026, 11, 18, 5, 11), last_updated=dt.datetime(2026, 11, 18, 5, 12)))
        s.commit()
        assert _active_runs(s, 1, now) == 0
        assert ISSUES.formal_issue(explicit=False, preview=False, active_runs=_active_runs(s, 1, now)) == \
            ISSUES.FIRST_DOWNLOAD
        s.add(CbomCollectionRun(team_id=1, owner_user_id=1, client_request_id="live", status="queued",
                                created_at=now.replace(tzinfo=None) - ACTIVE_RUN_WINDOW / 2,
                                last_updated=now.replace(tzinfo=None) - ACTIVE_RUN_WINDOW / 2))
        s.commit()
        assert _active_runs(s, 1, now) == 1
