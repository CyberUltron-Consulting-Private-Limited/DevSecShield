"""CBOM collection schedules (WP10): DST-safe slots in the team's window time zone, catch-up runs once, a slot fires
exactly once across two processes, credits and SOC acknowledgement like a manual run, the API.

Uses the same SQLite + real-router harness as test_cbom_sources_api.py; the two-process test runs two OS processes
against one SQLite file (``CBOM_TEST_PG_URL`` also runs it against PostgreSQL when set).
"""
from __future__ import annotations

import datetime as dt
import multiprocessing
import os
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine
from sqlmodel import Session, select

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_cbom_sources_api import api, enroll_node, linux_body, world  # noqa: E402,F401

from backend.new_models import (  # noqa: E402
    CbomCollectionAuditEvent,
    CbomCollectionRun,
    CbomCollectionSchedule,
    CbomDriftEvent,
    Team,
)
from backend.utilities.cbom_sources import schedules as S  # noqa: E402

UTC = dt.timezone.utc


def _sched(frequency="daily", time_of_day="02:30", weekday=None, monthday=None):
    return SimpleNamespace(frequency=frequency, time_of_day=time_of_day, weekday=weekday, monthday=monthday)


# ------------------------------------------------------------------------------------------- slots (pure)
def test_spring_forward_gap_runs_once_just_after_the_gap():
    s = _sched(time_of_day="02:30")
    # 2026-03-08: New York clocks jump 02:00 EST -> 03:00 EDT; 02:30 does not exist
    key, at = S.next_slot(s, "America/New_York", dt.datetime(2026, 3, 8, 0, 0))
    assert key == "2026-03-08T02:30" and at == dt.datetime(2026, 3, 8, 7, 30)  # = 03:30 EDT, once
    key2, at2 = S.next_slot(s, "America/New_York", at)
    assert key2 == "2026-03-09T02:30" and at2 == dt.datetime(2026, 3, 9, 6, 30)  # 02:30 EDT
    before = S.next_slot(s, "America/New_York", dt.datetime(2026, 3, 7, 0, 0))
    assert before == ("2026-03-07T02:30", dt.datetime(2026, 3, 7, 7, 30))  # 02:30 EST


def test_fall_back_overlap_runs_once_at_the_first_occurrence():
    s = _sched(time_of_day="01:30")
    # 2026-11-01: 01:00-02:00 happens twice in New York (EDT, then EST)
    key, at = S.next_slot(s, "America/New_York", dt.datetime(2026, 11, 1, 0, 0))
    assert key == "2026-11-01T01:30" and at == dt.datetime(2026, 11, 1, 5, 30)  # 01:30 EDT
    key2, at2 = S.next_slot(s, "America/New_York", at)
    assert key2 == "2026-11-02T01:30" and at2 == dt.datetime(2026, 11, 2, 6, 30)  # never 06:30 on 11-01 (01:30 EST)
    # London and Kolkata (no DST) behave
    assert S.next_slot(s, "Europe/London", dt.datetime(2026, 10, 25, 0, 0))[1] == dt.datetime(2026, 10, 25, 0, 30)
    assert S.next_slot(_sched(time_of_day="02:00"), "Asia/Kolkata", dt.datetime(2026, 11, 2))[1] == dt.datetime(2026, 11, 2, 20, 30)


def test_weekly_and_monthly_slots():
    weekly = _sched("weekly", "09:00", weekday=0)  # Mondays
    key, at = S.next_slot(weekly, "UTC", dt.datetime(2026, 11, 3, 12))  # Tuesday
    assert key == "2026-11-09T09:00" and at.weekday() == 0
    monthly = _sched("monthly", "23:15", monthday=28)
    assert S.next_slot(monthly, "UTC", dt.datetime(2026, 2, 28, 23, 15))[0] == "2026-03-28T23:15"
    latest = S.latest_slot(_sched(time_of_day="02:00"), "UTC", dt.datetime(2026, 11, 5, 1, 0))
    assert latest == ("2026-11-04T02:00", dt.datetime(2026, 11, 4, 2, 0))
    assert S.missed_between(_sched(time_of_day="02:00"), "UTC", dt.datetime(2026, 11, 1, 2), dt.datetime(2026, 11, 4, 2)) == 3


# ------------------------------------------------------------------------------------------- API + firing
def _setup(api, world, *, tz="UTC"):
    engine, _ids = world
    node_id, _token, _ = enroll_node(api)
    src = api("POST", "/1/cbom/sources/items", json=linux_body(node_id=node_id, targets=["10.20.0.1"], window="any"))
    assert src.status_code == 201, src.text
    cur = api("GET", "/1/cbom/sources/settings").json()["settings"]
    r = api("PATCH", "/1/cbom/sources/settings", json={"window_timezone": tz, "expected_version": cur["row_version"]})
    assert r.status_code == 200, r.text
    return engine, src.json()["source"]


def test_schedule_api_validation_and_permissions(api, world):
    _engine, src = _setup(api, world)
    base = {"name": "nightly", "frequency": "daily", "time_of_day": "02:00", "include": {"servers": True}}
    r = api("POST", "/1/cbom/sources/schedules", json=base)
    assert r.status_code == 201, r.text
    sched = r.json()["schedule"]
    assert sched["next_run_at"].endswith("Z") and sched["soc_ack"] is False
    for bad, msg in (({"time_of_day": "25:00"}, "time_of_day"), ({"frequency": "weekly"}, "weekday"),
                     ({"frequency": "monthly", "monthday": 31}, "Day of month"), ({"include": {}}, "include"),
                     ({"include": {"network": True}}, "soc_ack"), ({"source_ids": [999]}, "source_ids"),
                     ({"name": "<b>"}, "name")):
        bad_r = api("POST", "/1/cbom/sources/schedules", json={**base, **bad})
        assert bad_r.status_code == 400 and msg in bad_r.json()["detail"], (bad, bad_r.text)
    ok = api("POST", "/1/cbom/sources/schedules", json={**base, "name": "net", "include": {"network": True}, "soc_ack": True})
    assert ok.status_code == 201 and ok.json()["schedule"]["soc_ack"] is True
    # bob (member) cannot edit alice's schedule (400, never 403); a stale version is a 409
    assert api("PATCH", f"/1/cbom/sources/schedules/{sched['id']}", "bob", json={"enabled": False}).status_code == 400
    assert api("PATCH", f"/1/cbom/sources/schedules/{sched['id']}", json={"enabled": False, "expected_version": 99}).status_code == 409
    paused = api("PATCH", f"/1/cbom/sources/schedules/{sched['id']}", json={"enabled": False, "expected_version": sched["row_version"]})
    assert paused.status_code == 200 and paused.json()["schedule"]["next_run_at"] is None
    assert api("GET", "/2/cbom/sources/schedules", "carol").json()["schedules"] == []
    assert api("DELETE", f"/2/cbom/sources/schedules/{sched['id']}", "carol").status_code == 404
    assert api("DELETE", f"/1/cbom/sources/schedules/{sched['id']}").status_code == 200
    assert [s["name"] for s in api("GET", "/1/cbom/sources/schedules").json()["schedules"]] == ["net"]


def _due(engine, schedule_id: int, when: dt.datetime) -> None:
    with Session(engine) as s:
        row = s.get(CbomCollectionSchedule, schedule_id)
        row.next_run_at = when
        s.add(row)
        s.commit()


def test_missed_slots_catch_up_once_and_the_run_is_the_owners(api, world):
    engine, src = _setup(api, world)
    sched = api("POST", "/1/cbom/sources/schedules", json={
        "name": "nightly", "frequency": "daily", "time_of_day": "02:00", "include": {"servers": True},
        "min_criticality": "medium"}).json()["schedule"]
    now = dt.datetime(2026, 11, 5, 9, 0)
    _due(engine, sched["id"], dt.datetime(2026, 11, 2, 2, 0))  # the scheduler was down for three nights
    fired = S.fire_due(engine, now)
    assert len(fired) == 1 and fired[0]["status"] == "queued" and fired[0]["slot"] == "2026-11-05T02:00"
    assert fired[0]["missed"] == 3 and "catch-up: 3" in fired[0]["message"]
    assert S.fire_due(engine, now) == [] and S.fire_due(engine, now + dt.timedelta(hours=10)) == []
    with Session(engine) as s:
        runs = s.exec(select(CbomCollectionRun).where(CbomCollectionRun.schedule_id == sched["id"])).all()
        assert len(runs) == 1 and runs[0].client_request_id == f"sched-{sched['id']}-20261105T0200"
        assert runs[0].owner_user_id == world[1]["alice"] and runs[0].credits_charged_c == 20
        row = s.get(CbomCollectionSchedule, sched["id"])
        assert row.next_run_at == dt.datetime(2026, 11, 6, 2, 0) and row.last_run_id == runs[0].id
        audit = s.exec(select(CbomCollectionAuditEvent).where(CbomCollectionAuditEvent.action == "schedule.fire")).one()
        assert audit.actor_type == "system"
    # the next slot: the source is still queued in that run, so plan_run skips it (no second charge)
    nxt = S.fire_due(engine, dt.datetime(2026, 11, 6, 2, 1))
    assert nxt[0]["status"] == "skipped" and "already queued" in nxt[0]["message"]


def test_a_slot_without_credits_is_skipped_with_an_event(api, world):
    engine, _src = _setup(api, world)
    sched = api("POST", "/1/cbom/sources/schedules", json={
        "name": "nightly", "frequency": "daily", "time_of_day": "02:00", "include": {"servers": True}}).json()["schedule"]
    with Session(engine) as s:
        team = s.get(Team, 1)
        team.credit_balance = 0.05
        s.add(team)
        s.commit()
    _due(engine, sched["id"], dt.datetime(2026, 11, 5, 2, 0))
    out = S.fire_due(engine, dt.datetime(2026, 11, 5, 2, 0, 30))
    assert out[0]["status"] == "skipped" and "Not enough credits" in out[0]["message"]
    with Session(engine) as s:
        assert s.exec(select(CbomCollectionRun)).all() == []
        assert s.get(Team, 1).credit_balance == pytest.approx(0.05)
        ev = s.exec(select(CbomDriftEvent).where(CbomDriftEvent.kind == "schedule_skipped")).one()
        assert "Not enough credits" in ev.detail["reason"]
        assert s.get(CbomCollectionSchedule, sched["id"]).last_status == "skipped"
    listed = api("GET", "/1/cbom/sources/schedules").json()["schedules"][0]
    assert listed["last_status"] == "skipped" and listed["next_run_at"] == "2026-11-06T02:00:00Z"


def test_criticality_filter_keeps_only_matching_sources(api, world):
    engine, src = _setup(api, world)
    sched = api("POST", "/1/cbom/sources/schedules", json={
        "name": "crown jewels", "frequency": "daily", "time_of_day": "02:00", "include": {"servers": True},
        "min_criticality": "high"}).json()["schedule"]
    _due(engine, sched["id"], dt.datetime(2026, 11, 5, 2, 0))
    out = S.fire_due(engine, dt.datetime(2026, 11, 5, 2, 1))
    assert out[0]["status"] == "skipped" and "criticality" in out[0]["message"]


def _fire_in_child(url: str, schedule_id: int, now_iso: str, barrier, results) -> None:
    from sqlalchemy import create_engine as ce

    from backend.utilities.cbom_sources import schedules as SS

    engine = ce(url, connect_args={"check_same_thread": False, "timeout": 15} if url.startswith("sqlite") else {})
    barrier.wait(timeout=30)
    out = SS.fire_due(engine, dt.datetime.fromisoformat(now_iso))
    results.put([r["status"] for r in out])


def test_one_slot_fires_once_across_two_processes(api, world, tmp_path):
    engine, _src = _setup(api, world)
    sched = api("POST", "/1/cbom/sources/schedules", json={
        "name": "nightly", "frequency": "daily", "time_of_day": "02:00", "include": {"servers": True}}).json()["schedule"]
    _due(engine, sched["id"], dt.datetime(2026, 11, 5, 2, 0))
    url = str(engine.url)
    ctx = multiprocessing.get_context("fork")
    barrier, results = ctx.Barrier(2), ctx.Queue()
    procs = [ctx.Process(target=_fire_in_child, args=(url, sched["id"], "2026-11-05T02:00:05", barrier, results))
             for _ in range(2)]
    for p in procs:
        p.start()
    for p in procs:
        p.join(60)
        assert p.exitcode == 0
    statuses = [results.get(timeout=5) for _ in procs]
    assert sorted(len(s) for s in statuses) == [0, 1] and ["queued"] in statuses  # one process fired, one did not
    with Session(engine) as s:
        runs = s.exec(select(CbomCollectionRun)).all()
        assert len(runs) == 1 and runs[0].schedule_id == sched["id"]
        assert s.get(Team, 1).credit_balance == pytest.approx(100.0 - 0.2)  # charged once
        assert s.get(CbomCollectionSchedule, sched["id"]).next_run_at == dt.datetime(2026, 11, 6, 2, 0)


@pytest.mark.skipif(not os.environ.get("CBOM_TEST_PG_URL"), reason="set CBOM_TEST_PG_URL to run against PostgreSQL")
def test_one_slot_fires_once_across_two_processes_on_postgres(tmp_path):
    """The same race on PostgreSQL (FOR UPDATE SKIP LOCKED + compare-and-set + unique client_request_id)."""
    from sqlmodel import SQLModel

    from backend.new_models import CbomCollectionSource, CbomScanNode, TeamMembership, User

    url = os.environ["CBOM_TEST_PG_URL"]
    engine = create_engine(url)
    SQLModel.metadata.drop_all(engine)
    SQLModel.metadata.create_all(engine)
    now = dt.datetime(2026, 11, 5, 2, 0)
    with Session(engine) as s:
        s.add(Team(id=1, name="T", credit_balance=10.0))
        s.commit()
        user = User(email="a@t.test", password="x", first_name="a", last_name="b", profile_photo=None, default_team_id=1)
        s.add(user)
        s.commit()
        s.add(TeamMembership(team_id=1, user_id=user.id, role="admin"))
        node = CbomScanNode(team_id=1, owner_user_id=user.id, name="n", node_token_hash="h" * 64,
                            last_heartbeat_at=now)
        s.add(node)
        s.commit()
        s.add(CbomCollectionSource(team_id=1, owner_user_id=user.id, kind="linux_servers", name="s", name_lower="s",
                                   node_id=node.id, config={"targets": ["10.0.0.1"], "window": "any"}))
        s.add(CbomCollectionSchedule(team_id=1, owner_user_id=user.id, name="n", frequency="daily", time_of_day="02:00",
                                     include={"servers": True}, next_run_at=now))
        s.commit()
    ctx = multiprocessing.get_context("fork")
    barrier, results = ctx.Barrier(2), ctx.Queue()
    procs = [ctx.Process(target=_fire_in_child, args=(url, 1, "2026-11-05T02:00:05", barrier, results)) for _ in range(2)]
    for p in procs:
        p.start()
    for p in procs:
        p.join(60)
    statuses = [results.get(timeout=5) for _ in procs]
    assert sorted(len(s) for s in statuses) == [0, 1]
    with Session(engine) as s:
        assert len(s.exec(select(CbomCollectionRun)).all()) == 1
        assert s.get(Team, 1).credit_balance == pytest.approx(9.8)
    SQLModel.metadata.drop_all(engine)
