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


@pytest.fixture(autouse=True)
def _no_tick_waiting():
    """DRIFT.TICK_WANTS_HEAVY is process-wide: no test starts with a tick asking for the lock."""
    from backend.utilities.cbom_sources import drift as DRIFT

    DRIFT.TICK_WANTS_HEAVY.clear()
    yield
    DRIFT.TICK_WANTS_HEAVY.clear()


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
class _OwnLock:
    """DRIFT.HEAVY is per process; threads that stand for two scheduler PROCESSES each get their own."""

    def __init__(self):
        self._locks: dict[int, threading.Lock] = {}

    def _mine(self) -> threading.Lock:
        return self._locks.setdefault(threading.get_ident(), threading.Lock())

    def acquire(self, *a, **k):
        return self._mine().acquire(*a, **k)

    def release(self):
        self._mine().release()


@pytest.fixture()
def two_processes(monkeypatch):
    from backend.utilities.cbom_sources import drift as DRIFT

    monkeypatch.setattr(DRIFT, "HEAVY", _OwnLock())


def test_two_concurrent_passes_compute_a_run_once(recorded, monkeypatch, two_processes):
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


def test_a_failure_marker_never_overwrites_a_good_document(recorded, monkeypatch, two_processes):
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


def test_a_summary_comparison_and_the_ticks_heavy_steps_never_overlap(recorded, monkeypatch):
    """Review 6032466269 major 1: while the summary pass compares a run (under DRIFT.HEAVY), a tick fires schedules
    but skips its drift recording and estate repair; the pass yields before its next run, and the next tick runs them."""
    from backend.utilities.cbom_sources import drift as DRIFT
    from backend.utilities.cbom_sources import estate as ESTATE
    from backend.utilities.cbom_sources import schedules
    from backend.workers.cbom_scheduler import tick

    engine, r1, _r2, now = recorded
    inside, peak, fired = [0], [0], []
    in_diff, release = threading.Event(), threading.Event()
    real_diff, real_record, real_repair = DRIFT.run_diff, DRIFT.record_pending_drift, ESTATE.repair_due

    def enter():
        inside[0] += 1
        peak[0] = max(peak[0], inside[0])

    def diff(*a, **k):
        enter()
        try:
            in_diff.set()
            release.wait(10)
            return real_diff(*a, **k)
        finally:
            inside[0] -= 1

    def heavy(real):
        def wrapped(*a, **k):
            enter()
            try:
                return real(*a, **k)
            finally:
                inside[0] -= 1
        return wrapped

    monkeypatch.setattr(DRIFT, "run_diff", diff)
    monkeypatch.setattr(DRIFT, "record_pending_drift", heavy(real_record))
    monkeypatch.setattr(ESTATE, "repair_due", heavy(real_repair))
    monkeypatch.setattr(schedules, "fire_due", lambda engine_, now_: fired.append(now_) or [])
    out = {}
    t = threading.Thread(target=lambda: out.__setitem__("pass", DRIFT.store_pending_summaries(engine, now)))
    t.start()
    assert in_diff.wait(10)
    busy = tick(engine, now, summaries=False)  # the summary thread holds HEAVY: heavy steps deferred, schedules fire
    assert len(fired) == 1 and busy["drift_runs"] == "busy" and DRIFT.TICK_WANTS_HEAVY.is_set()
    release.set()
    t.join(30)
    assert out["pass"] == 1  # run 2 stored; it yielded before run 1 (the tick asked for HEAVY)
    assert _held(engine, r1) is None
    free = tick(engine, now, summaries=False)
    assert free["drift_runs"] == 0 and not DRIFT.TICK_WANTS_HEAVY.is_set()
    assert peak[0] == 1  # never two heavy steps at once
    assert DRIFT.store_pending_summaries(engine, now) == 1  # run 1 next


def test_a_stop_before_the_next_run_starts_nothing(recorded):
    from backend.utilities.cbom_sources import drift as DRIFT

    engine, r1, r2, now = recorded
    stop = threading.Event()
    stop.set()
    assert DRIFT.store_pending_summaries(engine, now, stop=stop) == 0
    assert _held(engine, r1) is None and _held(engine, r2) is None  # no claim taken


def test_a_shutdown_mid_comparison_releases_the_claim_without_a_try(recorded, monkeypatch):
    """Review 6032466269 minor 4: loop() returns only after its summary thread (bounded wait); a comparison still
    running then has its claim released, so the next process takes the run without counting a try, and the
    interrupted pass's late write changes nothing."""
    from backend.utilities.cbom_sources import drift as DRIFT
    from backend.utilities.cbom_sources import schedules
    from backend.workers import cbom_scheduler as SCHED

    engine, r1, r2, now = recorded
    _set(engine, r1, {"v": 1, "baseline_id": None, "doc": {"format": "x"}})
    in_diff, release = threading.Event(), threading.Event()
    real = DRIFT.run_diff

    def diff(*a, **k):
        in_diff.set()
        release.wait(20)
        return real(*a, **k)

    monkeypatch.setattr(DRIFT, "run_diff", diff)
    monkeypatch.setattr(SCHED, "TICK_S", 0.05)
    monkeypatch.setattr(SCHED, "SHUTDOWN_WAIT_S", 0.5)
    monkeypatch.setattr(SCHED, "utcnow", lambda: now)
    monkeypatch.setattr(schedules, "fire_due", lambda engine_, now_: [])
    stop = threading.Event()
    loop = threading.Thread(target=SCHED.loop, args=(engine, stop), daemon=True)
    loop.start()
    assert in_diff.wait(20)
    assert _held(engine, r2)["pending"] is True and _held(engine, r2)["tries"] == 1
    stop.set()
    loop.join(10)
    assert not loop.is_alive()
    assert _held(engine, r2) is None  # released: as before the claim (no try counted)
    release.set()  # the interrupted comparison finishes: its write finds no claim
    for thread, _eng in list(SCHED._SUMMARY_THREADS):
        thread.join(10)
    assert _held(engine, r2) is None
    monkeypatch.setattr(DRIFT, "run_diff", real)
    assert DRIFT.store_pending_summaries(engine, now) == 1
    assert _held(engine, r2)["baseline_id"] == r1


def test_the_budget_is_checked_after_a_failed_run_too(recorded, monkeypatch):
    """Review 6032466269 nit 5: a first run that fails after a long statement timeout ends the pass."""
    from backend.utilities.cbom_sources import drift as DRIFT

    engine, r1, r2, now = recorded
    clock = {"t": 1000.0}
    monkeypatch.setattr(DRIFT, "_monotonic", lambda: clock["t"])

    def timeout(*_a, **_k):
        clock["t"] += DRIFT.SUMMARY_BUDGET_S + 1
        raise sa.exc.OperationalError("SELECT", {}, Exception("canceling statement due to statement timeout"))

    monkeypatch.setattr(DRIFT, "run_diff", timeout)
    assert DRIFT.store_pending_summaries(engine, now, started=1000.0) == 0
    assert _held(engine, r2)["failed"] is True and _held(engine, r1) is None  # run 1 not started


def test_refresh_baselines_checks_the_newest_later_runs_first(recorded, monkeypatch):
    """Review 6032466269 nit 6: with more later runs than REFRESH_RUNS, the newest are the ones checked."""
    from backend.utilities.cbom_sources import drift as DRIFT
    from backend.utilities.cbom_sources import drift_report as DR

    engine, r1, r2, now = recorded
    assert DRIFT.store_pending_summaries(engine, now) == 2
    _jobs_status(engine, r1, "failure")  # run 2's stored baseline (run 1) no longer holds
    with Session(engine) as s:  # an older later run would be checked first if the order were ascending
        assert DR.refresh_baselines(s, 1, 0, now) == 1
        s.commit()
    monkeypatch.setattr(DR, "REFRESH_RUNS", 1)
    _set(engine, r2, {"v": 1, "baseline_id": r1, "doc": {"format": "x"}})
    _set(engine, r1, {"v": 1, "baseline_id": 999, "doc": {"format": "x"}})
    with Session(engine) as s:
        assert DR.refresh_baselines(s, 1, 0, now) == 1
        s.commit()
    assert _held(engine, r2) is None and _held(engine, r1)["baseline_id"] == 999  # the newest (run 2) was checked


# ============================================================================ minor B
def _seed_mosca_closable(engine, r1):
    """Reviewer's seed: run 1 recorded with the inputs:mosca item open (its write opened it before #490's documented
    defaults; now the item is opened here); the team's Mosca inputs are saved directly (no close_mosca), so run 2's
    own estate hook (sync_mosca, run_id=run 2) is what closes the gap."""
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
        if gap is None:  # #490: documented Mosca defaults, so a write no longer opens the item; open it as before
            run1 = s.get(CbomCollectionRun, r1)
            s.add(CbomQ0Gap(team_id=1, item_kind="inputs", item_key="inputs:mosca", reason="mosca_missing",
                            detail={"count": 1}, opened_at=run1.drift_at, run_id=r1))
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


def test_a_download_while_the_team_is_stale_is_cached_and_recomputed_once_after_the_repair(finished, monkeypatch):
    """Review 6032466269 major 2: while the store is stale a download computes once per process (not on every
    download); after the repair the same process computes once more and serves the repaired number."""
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
    calls = _count_diffs(monkeypatch)
    for _ in range(5):
        with Session(engine) as s:
            before = DR.run_drift(s, s.get(CbomCollectionRun, r2))
    assert before["q0"]["register_closed"] == {} and len(calls) == 1
    ESTATE.repair_due(engine, t0 + dt.timedelta(seconds=30))
    for _ in range(3):
        with Session(engine) as s:
            after = DR.run_drift(s, s.get(CbomCollectionRun, r2))
    assert after["q0"]["register_closed"] == {"inputs": 1} and len(calls) == 2


def test_a_repair_that_keeps_failing_neither_starves_the_team_nor_blocks_others(finished, monkeypatch):
    """Review 6032466269 major 2 (reviewer's REV492 STARVE): run 2's estate write fails every time. The repair failure
    is caught per team and moves the team to the back, so another stale team is repaired on the next tick; after
    SUMMARY_STALE_WAIT run 2's document is stored anyway."""
    from backend.utilities.cbom_sources import drift as DRIFT
    from backend.utilities.cbom_sources import estate as ESTATE
    from backend.workers.cbom_scheduler import tick

    engine, r1, r2 = finished
    real = ESTATE.record_run

    def poisoned(session, run, now, **kw):
        if run.id == r2:
            raise RuntimeError("estate write fails every time (poisoned row)")
        return real(session, run, now, **kw)

    monkeypatch.setattr(ESTATE, "record_run", poisoned)
    t0 = _now()
    assert DRIFT.record_pending_drift(engine, t0) == 2
    with Session(engine) as s:  # a second team, marked stale just after team 1 (a deferred write, say)
        ESTATE.mark_stale(s, 2, 10**6, "run #1000000 deferred to the scheduler", t0 + dt.timedelta(seconds=1))
        s.commit()
    first = tick(engine, t0 + dt.timedelta(seconds=10))
    assert first["estate_repair"] == {"teams": 0, "runs": 0, "failed": 1}  # team 1 first (oldest), fails, no raise
    second = tick(engine, t0 + dt.timedelta(seconds=40))
    assert second["estate_repair"]["teams"] == 1  # team 2, behind the failing team, is repaired
    with Session(engine) as s:
        teams = {t.team_id: t.stale for t in s.exec(sa.select(CbomEstateTeam)).scalars()}
    assert teams == {1: True, 2: False}
    assert _held(engine, r2) is None  # still within SUMMARY_STALE_WAIT: waiting for the repair
    later = t0 + DRIFT.SUMMARY_STALE_WAIT + dt.timedelta(minutes=1)
    out = tick(engine, later)
    assert out["estate_repair"]["failed"] == 1 and out["drift_summaries"] == 1
    assert _held(engine, r2)["baseline_id"] == r1


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
