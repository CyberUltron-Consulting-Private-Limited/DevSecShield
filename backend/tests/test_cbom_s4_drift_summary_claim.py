"""Follow-up to review 6030475121 on #486 (S4 drift): the stored drift summary is claimed, bounded and retried, and
a run's own register closures survive a late estate write.

* Minor A: ``drift.store_pending_summaries`` claims a run before computing it (``{"v":1,"pending":true,...}``), writes
  the document or the failure marker only while the claim is still its own, retries a failure after an hour (3 tries),
  bounds each pass (one run above 50k assets with its baseline; none once the tick has spent 10 s) and never runs on
  the scheduling thread of ``loop()``.
* Minor B: ``drift_report.register_closures`` counts a run's ``closed_by_run_id`` events whenever they were written
  (an estate write deferred or replayed after ``drift_at``); a backfill replay of an already-written run runs no
  hooks; a stale team's runs wait for the repair before their document is stored.
* Nits: methodology step 4 names library components; the run report's drift box is as wide as its tables; a changed
  baseline (an earlier run that finished or was cancelled later) clears the stored document so the pass re-stores it.

Failing first on dev bd3e48adb (see the PR body). Same SQLite + real-router harness as test_cbom_sources_api.py; the
reviewer's harness is cb38/qa/486b/harness/test_rev486b_drift_store.py.
"""
from __future__ import annotations

import datetime as dt
import sys
import threading
import time
from pathlib import Path

import pytest
import sqlalchemy as sa
from sqlmodel import Session

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_cbom_sources_api as SOURCES_API
from test_cbom_run_deliverables import _finish
from test_cbom_wp10_outputs import make_two_runs

from backend.new_models import (
    CbomCollectionJob,
    CbomCollectionRun,
    CbomEstateTeam,
    CbomQ0Gap,
)

globals().update(api=SOURCES_API.api, world=SOURCES_API.world)


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc).replace(tzinfo=None)


@pytest.fixture()
def recorded(api, world):
    """Two finished runs of the same sources, drift recorded for both (no document stored yet)."""
    from backend.utilities.cbom_sources import drift as DRIFT

    runs = make_two_runs(api, world)
    for key in ("run1", "run2"):
        _finish(runs["engine"], runs[key]["id"])
    now = _now()
    assert DRIFT.record_pending_drift(runs["engine"], now) == 2
    return runs["engine"], runs["run1"]["id"], runs["run2"]["id"], now


def _held(engine, rid):
    with Session(engine) as s:
        return s.get(CbomCollectionRun, rid).drift_summary


def _set(engine, rid, value):
    with Session(engine) as s:
        s.exec(sa.update(CbomCollectionRun).where(CbomCollectionRun.id == rid).values(drift_summary=value))
        s.commit()


def _count_diffs(monkeypatch):
    from backend.utilities.cbom_sources import drift as DRIFT

    real, calls = DRIFT.run_diff, []

    def counted(*a, **k):
        calls.append(threading.current_thread().name)
        return real(*a, **k)

    monkeypatch.setattr(DRIFT, "run_diff", counted)
    return calls


# ============================================================================ minor A: claim
def test_two_concurrent_passes_compute_a_run_once(recorded, monkeypatch):
    """Reviewer's race (REV486B RACE: run_diff called by sched-A and sched-B for run 2): B starts while A is inside
    run 2's comparison. A's claim keeps run 2 out of B's pass, so the comparison runs once and both documents are
    stored once."""
    from backend.utilities.cbom_sources import drift as DRIFT

    engine, r1, r2, now = recorded
    real, calls, out = DRIFT.run_diff, [], {}

    def run_b():
        out["B"] = DRIFT.store_pending_summaries(engine, now)

    def diff(session, run, base):
        calls.append((threading.current_thread().name, run.id))
        if threading.current_thread().name == "sched-A":
            b = threading.Thread(target=run_b, name="sched-B")
            b.start()
            b.join(30)  # B's whole pass runs while A holds run 2's claim
        return real(session, run, base)

    monkeypatch.setattr(DRIFT, "run_diff", diff)
    a = threading.Thread(target=lambda: out.__setitem__("A", DRIFT.store_pending_summaries(engine, now)),
                         name="sched-A")
    a.start()
    a.join(60)
    assert calls == [("sched-A", r2)]  # one comparison: B never computed run 2
    assert out["A"] + out["B"] == 2  # run 1 and run 2, each stored by exactly one pass
    for rid in (r1, r2):
        held = _held(engine, rid)
        assert isinstance(held.get("doc"), dict) and "pending" not in held and "failed" not in held, held


def test_a_failure_marker_never_overwrites_a_good_document(recorded, monkeypatch):
    """Reviewer's REV486B RACE-MARKER: A's claim on run 2 goes stale (A stalls past 15 min), B takes it over and
    stores the document, then A fails. A's marker is written only while the claim is A's: the document stays."""
    from backend.utilities.cbom_sources import drift as DRIFT

    engine, r1, r2, now = recorded
    _set(engine, r1, None)
    real = DRIFT.run_diff
    later = now + dt.timedelta(minutes=16)

    def diff(session, run, base):
        if threading.current_thread().name == "sched-A":
            b = threading.Thread(target=lambda: DRIFT.store_pending_summaries(engine, later), name="sched-B")
            b.start()
            b.join(30)  # B stores the document under its own (newer) claim
            raise MemoryError("second copy")
        return real(session, run, base)

    monkeypatch.setattr(DRIFT, "run_diff", diff)
    a = threading.Thread(target=lambda: DRIFT.store_pending_summaries(engine, now), name="sched-A")
    a.start()
    a.join(60)
    held = _held(engine, r2)
    assert isinstance(held.get("doc"), dict) and held["baseline_id"] == r1, held
    assert "failed" not in held and "pending" not in held


def test_a_document_or_marker_is_written_only_under_the_writers_claim(recorded):
    from backend.utilities.cbom_sources import drift as DRIFT

    engine, _r1, r2, now = recorded
    with Session(engine) as s:
        token = DRIFT.claim_summary(s, r2, now)
        s.commit()
    assert token and _held(engine, r2)["pending"] is True
    with Session(engine) as s:  # a second claim while the first is fresh is refused
        assert DRIFT.claim_summary(s, r2, now + dt.timedelta(minutes=14)) is None
    good = {"v": 1, "baseline_id": None, "doc": {"format": "x"}}
    with Session(engine) as s:
        assert DRIFT.write_summary(s, r2, "not-my-claim", good) is False
        assert DRIFT.write_summary(s, r2, token, good) is True
        s.commit()
        # the claim is gone with the document: a late marker under the same token changes nothing
        assert DRIFT.write_summary(s, r2, token, {"v": 1, "failed": True, "at": "x", "tries": 1}) is False
        s.commit()
    assert _held(engine, r2) == good


def test_a_stale_claim_is_free_after_15_minutes(recorded, monkeypatch):
    from backend.utilities.cbom_sources import drift as DRIFT

    engine, r1, r2, now = recorded
    _set(engine, r1, {"v": 1, "baseline_id": None, "doc": {"format": "x"}})
    with Session(engine) as s:  # a pass that died (OOM kill, restart) after claiming run 2
        assert DRIFT.claim_summary(s, r2, now)
        s.commit()
    calls = _count_diffs(monkeypatch)
    assert DRIFT.store_pending_summaries(engine, now + dt.timedelta(minutes=10)) == 0
    assert calls == []
    assert DRIFT.store_pending_summaries(engine, now + dt.timedelta(minutes=16)) == 1
    assert calls and isinstance(_held(engine, r2).get("doc"), dict)


# ============================================================================ minor A: retry
def test_a_transient_error_is_retried_after_an_hour(recorded, monkeypatch):
    """Reviewer's REV486B MARKER: one statement timeout gave {"v":1,"failed":true} for good. Now the marker has
    ``at`` and ``tries`` and the run is retried after an hour."""
    from backend.utilities.cbom_sources import drift as DRIFT
    from backend.workers.cbom_scheduler import tick

    engine, r1, r2, now = recorded
    real = DRIFT.run_diff

    def timeout(*_a, **_k):
        raise sa.exc.OperationalError("SELECT", {}, Exception("canceling statement due to statement timeout"))

    monkeypatch.setattr(DRIFT, "run_diff", timeout)
    assert tick(engine, now)["drift_summaries"] == 1  # run 1 (no baseline) stored; run 2 failed
    held = _held(engine, r2)
    assert held["failed"] is True and held["tries"] == 1 and held["at"] == DRIFT.summary_stamp(now), held
    monkeypatch.setattr(DRIFT, "run_diff", real)
    calls = _count_diffs(monkeypatch)
    assert tick(engine, now + dt.timedelta(minutes=30))["drift_summaries"] == 0  # not due yet
    assert calls == []
    assert tick(engine, now + dt.timedelta(minutes=61))["drift_summaries"] == 1  # retried: healthy now
    assert len(calls) == 1
    assert _held(engine, r2)["baseline_id"] == r1


def test_a_run_that_keeps_failing_stops_after_three_tries(recorded, monkeypatch):
    from backend.utilities.cbom_sources import drift as DRIFT

    engine, r1, r2, now = recorded
    _set(engine, r1, {"v": 1, "baseline_id": None, "doc": {"format": "x"}})
    calls = []

    def boom(*_a, **_k):
        calls.append(1)
        raise RuntimeError("always")

    monkeypatch.setattr(DRIFT, "run_diff", boom)
    for hours in (0, 1.1, 2.2, 3.3, 4.4, 30):
        DRIFT.store_pending_summaries(engine, now + dt.timedelta(hours=hours))
    assert len(calls) == DRIFT.SUMMARY_MAX_TRIES == 3
    held = _held(engine, r2)
    assert held["failed"] is True and held["tries"] == 3


def test_a_legacy_marker_without_time_or_tries_is_retried(recorded, monkeypatch):
    """Markers stored by #486 ({"v":1,"failed":true}) count as one try made long ago."""
    from backend.utilities.cbom_sources import drift as DRIFT

    engine, r1, r2, now = recorded
    _set(engine, r1, {"v": 1, "baseline_id": None, "doc": {"format": "x"}})
    _set(engine, r2, {"v": 1, "failed": True})
    assert DRIFT.store_pending_summaries(engine, now) == 1
    assert _held(engine, r2)["baseline_id"] == r1


# ============================================================================ minor A: bounds
def test_the_pass_is_skipped_once_the_tick_has_spent_its_budget(recorded, monkeypatch):
    from backend.utilities.cbom_sources import drift as DRIFT

    engine, r1, r2, now = recorded
    calls = _count_diffs(monkeypatch)
    spent = time.monotonic() - DRIFT.SUMMARY_BUDGET_S - 0.5
    assert DRIFT.store_pending_summaries(engine, now, started=spent) == 0
    assert calls == [] and _held(engine, r1) is None and _held(engine, r2) is None
    assert DRIFT.store_pending_summaries(engine, now, started=time.monotonic()) == 2


def test_a_pass_stops_starting_runs_after_the_budget(recorded, monkeypatch):
    from backend.utilities.cbom_sources import drift as DRIFT

    engine, r1, r2, now = recorded
    real = DRIFT.run_diff
    clock = {"t": 1000.0}
    monkeypatch.setattr(DRIFT, "_monotonic", lambda: clock["t"])

    def slow(*a, **k):  # run 2 (newest first) takes 11 s
        clock["t"] += DRIFT.SUMMARY_BUDGET_S + 1
        return real(*a, **k)

    monkeypatch.setattr(DRIFT, "run_diff", slow)
    assert DRIFT.store_pending_summaries(engine, now, started=1000.0) == 1
    assert _held(engine, r2)["baseline_id"] == r1 and _held(engine, r1) is None


def test_a_large_run_is_the_only_run_of_its_pass(recorded, monkeypatch):
    """Above SUMMARY_LARGE_ASSETS (the run's assets plus its baseline's) a pass computes that run alone."""
    from backend.utilities.cbom_sources import drift as DRIFT

    engine, r1, r2, now = recorded
    with Session(engine) as s:
        sizes = {rid: DRIFT.summary_assets(s, s.get(CbomCollectionRun, rid)) for rid in (r1, r2)}
    assert sizes[r2] > sizes[r1] > 0  # run 2 counts its baseline (run 1) too
    monkeypatch.setattr(DRIFT, "SUMMARY_LARGE_ASSETS", sizes[r2] - 1)  # run 2 is "large", run 1 is not
    assert DRIFT.store_pending_summaries(engine, now) == 1
    assert _held(engine, r2)["baseline_id"] == r1 and _held(engine, r1) is None
    assert DRIFT.store_pending_summaries(engine, now) == 1  # run 1 next time
    monkeypatch.setattr(DRIFT, "SUMMARY_LARGE_ASSETS", 0)
    _set(engine, r1, None)
    _set(engine, r2, None)
    assert DRIFT.store_pending_summaries(engine, now) == 1  # newest first, alone


def test_the_scheduling_loop_never_waits_for_the_summary_pass(monkeypatch):
    """loop() fires schedules every TICK_S while a summary pass is still running: the pass has its own thread."""
    from backend.utilities.cbom_sources import drift as DRIFT
    from backend.utilities.cbom_sources import schedules
    from backend.workers import cbom_scheduler as SCHED

    release, fired, passes = threading.Event(), [], []
    monkeypatch.setattr(SCHED, "TICK_S", 0.05)
    monkeypatch.setattr(schedules, "fire_due", lambda engine, now: fired.append(now) or [])
    monkeypatch.setattr(DRIFT, "record_pending_drift", lambda engine, now: 0)

    def stuck(engine, now, **_k):
        passes.append(threading.current_thread().name)
        release.wait(10)
        return 0

    monkeypatch.setattr(DRIFT, "store_pending_summaries", stuck)
    stop = threading.Event()
    t = threading.Thread(target=SCHED.loop, args=(None, stop), daemon=True)
    t.start()
    try:
        deadline = time.monotonic() + 5
        while len(fired) < 4 and time.monotonic() < deadline:
            time.sleep(0.02)
        assert len(passes) == 1 and not release.is_set()  # one pass, still stuck
        assert len(fired) >= 4  # schedules kept firing meanwhile
        assert passes[0] != t.name
    finally:
        release.set()
        stop.set()
        t.join(5)


# ============================================================================ minor B
def _seed_mosca_closable(engine, r1):
    """Reviewer's seed: run 1 recorded (its write opens inputs:mosca); the team's Mosca inputs are then saved directly
    (no close_mosca), so run 2's own estate hook (sync_mosca, run_id=run 2) is what closes the gap."""
    from backend.utilities.cbom_sources import drift as DRIFT
    from backend.utilities.cbom_sources.settings import get_or_create_settings

    with Session(engine) as s:
        assert DRIFT.record_run_drift(s, s.get(CbomCollectionRun, r1), _now()) is not None
        s.commit()
    with Session(engine) as s:
        st = get_or_create_settings(s, 1)
        st.risk_model = {**(st.risk_model or {}), "data_shelf_life_years": 10, "migration_years": 5,
                         "threat_years": 12}
        s.add(st)
        s.commit()
        gap = s.exec(sa.select(CbomQ0Gap).where(CbomQ0Gap.item_key == "inputs:mosca")).scalars().first()
        assert gap is not None and gap.closed_at is None


@pytest.fixture()
def finished(api, world):
    runs = make_two_runs(api, world)
    for key in ("run1", "run2"):
        _finish(runs["engine"], runs[key]["id"])
    return runs["engine"], runs["run1"]["id"], runs["run2"]["id"]


def test_control_the_runs_own_write_closes_the_mosca_gap(finished):
    from backend.utilities.cbom_sources import drift as DRIFT
    from backend.utilities.cbom_sources import drift_report as DR

    engine, r1, r2 = finished
    _seed_mosca_closable(engine, r1)
    assert DRIFT.record_pending_drift(engine, _now()) == 1
    with Session(engine) as s:
        assert DR.register_closures(s, s.get(CbomCollectionRun, r2)) == {"inputs": 1}


def test_a_failed_estate_write_repaired_30s_later_keeps_the_runs_closures(finished, monkeypatch):
    """Reviewer's minor B repro: the same seed, run 2's estate write fails once and tick() repairs it 30 s later.
    The closure is stamped after drift_at but caused by run 2: register_closures and the stored document say 1."""
    from backend.utilities.cbom_sources import drift as DRIFT
    from backend.utilities.cbom_sources import drift_report as DR
    from backend.utilities.cbom_sources import estate as ESTATE
    from backend.workers.cbom_scheduler import tick

    engine, r1, r2 = finished
    _seed_mosca_closable(engine, r1)
    real, state = ESTATE.record_run, {"fail_run": r2}

    def flaky(session, run, now, **kw):
        if run.id == state["fail_run"]:
            state["fail_run"] = None
            raise RuntimeError("estate write failed once")
        return real(session, run, now, **kw)

    monkeypatch.setattr(ESTATE, "record_run", flaky)
    t0 = _now()
    assert DRIFT.record_pending_drift(engine, t0) == 1
    with Session(engine) as s:  # the store is stale from run 2 on
        team = s.exec(sa.select(CbomEstateTeam).where(CbomEstateTeam.team_id == 1)).scalars().one()
        assert team.stale and team.stale_run_id == r2
    # a pass before the repair leaves run 2 alone (its closures are not written yet)
    assert DRIFT.store_pending_summaries(engine, t0) == 1  # run 1 only
    assert _held(engine, r2) is None
    out = tick(engine, t0 + dt.timedelta(seconds=30))  # repair_due replays run 2 with hooks, then the summary pass
    assert out["estate_repair"]["teams"] == 1 and out["drift_summaries"] == 1
    with Session(engine) as s:
        run = s.get(CbomCollectionRun, r2)
        assert DR.register_closures(s, run) == {"inputs": 1}
        assert run.drift_summary["doc"]["q0"]["register_closed"] == {"inputs": 1}


def test_a_download_while_the_team_is_stale_is_not_cached(finished, monkeypatch):
    """Before the repair a download computes the document live (no LRU entry), so after the repair the same process
    serves the repaired number."""
    from backend.utilities.cbom_sources import drift as DRIFT
    from backend.utilities.cbom_sources import drift_report as DR
    from backend.utilities.cbom_sources import estate as ESTATE

    engine, r1, r2 = finished
    _seed_mosca_closable(engine, r1)
    real, state = ESTATE.record_run, {"fail_run": r2}

    def flaky(session, run, now, **kw):
        if run.id == state["fail_run"]:
            state["fail_run"] = None
            raise RuntimeError("estate write failed once")
        return real(session, run, now, **kw)

    monkeypatch.setattr(ESTATE, "record_run", flaky)
    t0 = _now()
    DRIFT.record_pending_drift(engine, t0)
    DR._CACHE.clear()
    with Session(engine) as s:
        before = DR.run_drift(s, s.get(CbomCollectionRun, r2))
    assert before["q0"]["register_closed"] == {} and not DR._CACHE
    ESTATE.repair_due(engine, t0 + dt.timedelta(seconds=30))
    with Session(engine) as s:
        after = DR.run_drift(s, s.get(CbomCollectionRun, r2))
    assert after["q0"]["register_closed"] == {"inputs": 1}


def test_a_backfill_replay_of_a_written_run_closes_nothing_in_its_name(finished):
    """Run 2 is written (its hook closed inputs:mosca). A later gap is open when the backfill replays run 2: the
    replay writes nothing for run 2, so it runs no hooks and closes nothing in run 2's name."""
    from backend.utilities.cbom_sources import drift as DRIFT
    from backend.utilities.cbom_sources import drift_report as DR
    from backend.utilities.cbom_sources import estate as ESTATE

    engine, r1, r2 = finished
    _seed_mosca_closable(engine, r1)
    t0 = _now()
    assert DRIFT.record_pending_drift(engine, t0) == 1
    with Session(engine) as s:
        assert DR.register_closures(s, s.get(CbomCollectionRun, r2)) == {"inputs": 1}
        run = s.get(CbomCollectionRun, r2)
        s.add(CbomQ0Gap(team_id=1, item_kind="inputs", item_key="inputs:mosca", reason="mosca_missing", detail={},
                        opened_at=t0 + dt.timedelta(hours=1), run_id=r2))
        s.commit()
        assert run.id == r2
    ESTATE.backfill(engine, t0 + dt.timedelta(hours=2), team_id=1, hooks=True, since_run_id=r2)
    with Session(engine) as s:
        assert DR.register_closures(s, s.get(CbomCollectionRun, r2)) == {"inputs": 1}
        still_open = s.exec(sa.select(CbomQ0Gap).where(CbomQ0Gap.item_key == "inputs:mosca",
                                                       CbomQ0Gap.closed_at.is_(None))).scalars().all()
        assert len(still_open) == 1


# ============================================================================ nit 3: baseline changes
def _jobs_status(engine, rid, status):
    with Session(engine) as s:
        s.exec(sa.update(CbomCollectionJob).where(CbomCollectionJob.run_id == rid).values(status=status))
        s.commit()


def test_an_earlier_run_finishing_later_clears_the_stored_document(api, world, monkeypatch):
    """Run 1 is still collecting when run 2's document is stored (no baseline). Run 1 then finishes and its drift is
    recorded: run 2's stored document is for the wrong baseline, so it is cleared and the next pass re-stores it."""
    from backend.utilities.cbom_sources import drift as DRIFT

    runs = make_two_runs(api, world)
    engine, r1, r2 = runs["engine"], runs["run1"]["id"], runs["run2"]["id"]
    _finish(engine, r2)
    _jobs_status(engine, r1, "claimed")  # run 1 still collecting: not comparable yet
    with Session(engine) as s:
        s.exec(sa.update(CbomCollectionRun).where(CbomCollectionRun.id == r1).values(status="running",
                                                                                      finished_at=None))
        s.commit()
    now = _now()
    assert DRIFT.record_pending_drift(engine, now) == 1  # run 2 only
    assert DRIFT.store_pending_summaries(engine, now) == 1
    assert _held(engine, r2)["baseline_id"] is None
    _jobs_status(engine, r1, "success")
    _finish(engine, r1)
    assert DRIFT.record_pending_drift(engine, now + dt.timedelta(minutes=5)) == 1  # run 1: the event
    assert _held(engine, r2) is None
    assert DRIFT.store_pending_summaries(engine, now + dt.timedelta(minutes=5)) == 2
    assert _held(engine, r2)["baseline_id"] == r1


def test_cancelling_the_baseline_run_re_stores_the_document(api, recorded):
    engine, r1, r2, now = recorded
    from backend.utilities.cbom_sources import drift as DRIFT

    assert DRIFT.store_pending_summaries(engine, now) == 2
    assert _held(engine, r2)["baseline_id"] == r1
    _jobs_status(engine, r1, "cancelled")  # what the cancel leaves: run 1 is no longer comparable
    r = api("POST", f"/1/cbom/sources/runs/{r1}/cancel")
    assert r.status_code == 200, r.text
    assert _held(engine, r2) is None
    assert DRIFT.store_pending_summaries(engine, now) == 1
    assert _held(engine, r2)["baseline_id"] is None


def test_an_unchanged_baseline_keeps_the_stored_document(recorded):
    from backend.utilities.cbom_sources import drift as DRIFT
    from backend.utilities.cbom_sources import drift_report as DR

    engine, r1, r2, now = recorded
    assert DRIFT.store_pending_summaries(engine, now) == 2
    held = _held(engine, r2)
    with Session(engine) as s:
        assert DR.refresh_baselines(s, 1, r1, now) == 0
        s.commit()
    assert _held(engine, r2) == held


# ============================================================================ nits 1 and 2
def test_d2_evidence_chain_step_4_names_library_components():
    from backend.utilities.pdf import cbom_methodology_text as M

    step = next(text for title, text in M.EVIDENCE_CHAIN if title.startswith("4."))
    assert "crypto libraries as library components" in step


def test_run_report_drift_box_is_as_wide_as_its_tables():
    from reportlab.platypus import Table

    from backend.utilities.pdf import cbom_run_pdf as PDF
    from backend.utilities.pdf.report_branding import get_report_styles

    drift = {"baseline": {"id": 1, "status": "done", "trigger": "manual", "finished_at": "2026-11-23T00:00:00Z"},
             "run": {"id": 2, "trigger": "manual"}, "recorded_at": "2026-11-23T00:01:00Z",
             "counts": {"added": 1, "compared_sources": 1}, "readiness": {}, "q0": {}, "rules": {},
             "added": [{"key": "k", "label": "a", "type": "certificate", "source_name": "s", "q_grade": "Q2"}]}
    story: list = []
    PDF.append_drift_section(story, drift, get_report_styles())
    widths = {round(sum(t._colWidths), 2) for t in story if isinstance(t, Table)}
    assert len(widths) == 1, widths
