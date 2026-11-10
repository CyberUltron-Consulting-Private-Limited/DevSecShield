"""Editing a CBOM schedule from the UI (round 5 customer testing: a schedule could only be paused, resumed or deleted).

The Review & Run edit form PATCHes the same fields as the add form (frontend scheduleForm.ts scheduleBody): the server
must apply the add form's checks to an edit, and a new time or day must move the next run to the new slot in the
TEAM's time zone (not UTC, not the browser's).  Same SQLite + real-router harness as test_cbom_sources_api.py.
"""
from __future__ import annotations

import datetime as dt
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_cbom_review5_jobs_schedules import _schedule_world  # noqa: E402
from test_cbom_sources_api import api, world  # noqa: E402,F401

SCHED = "/1/cbom/sources/schedules"


def _form(**overrides):
    """What the edit form sends (scheduleBody with a schedule being edited)."""
    body = {"name": "nightly", "frequency": "daily", "time_of_day": "09:00", "weekday": None, "monthday": None,
            "include": {"servers": True, "kubernetes": False, "databases": False, "cloud": False, "network": False},
            "min_criticality": None}
    body.update(overrides)
    return body


def test_an_edit_moves_the_next_run_to_the_new_slot_in_the_team_zone(api, world, monkeypatch):
    engine, clock = _schedule_world(api, world, monkeypatch, dt.datetime(2026, 12, 1, 1, 0), "Asia/Kolkata")
    sched = api("POST", SCHED, json=_form()).json()["schedule"]
    assert sched["next_run_at"] == "2026-12-01T03:30:00Z"  # 09:00 IST
    # 06:30 IST now: today's 07:15 IST slot is still ahead
    r = api("PATCH", f"{SCHED}/{sched['id']}", json=_form(time_of_day="07:15", expected_version=sched["row_version"]))
    assert r.status_code == 200, r.text
    moved = r.json()["schedule"]
    assert moved["time_of_day"] == "07:15" and moved["next_run_at"] == "2026-12-01T01:45:00Z"
    # weekly on Sunday (6) at 02:00 IST -> Saturday 20:30 UTC
    r = api("PATCH", f"{SCHED}/{sched['id']}", json=_form(frequency="weekly", weekday=6, time_of_day="02:00",
                                                          expected_version=moved["row_version"]))
    assert r.status_code == 200, r.text
    weekly = r.json()["schedule"]
    assert weekly["frequency"] == "weekly" and weekly["weekday"] == 6
    assert weekly["next_run_at"] == "2026-12-05T20:30:00Z"
    # back to daily: the stored day is cleared, the next run is tomorrow 02:00 IST (today's has passed)
    r = api("PATCH", f"{SCHED}/{sched['id']}", json=_form(time_of_day="02:00", expected_version=weekly["row_version"]))
    daily = r.json()["schedule"]
    assert daily["weekday"] is None and daily["next_run_at"] == "2026-12-01T20:30:00Z"
    listed = api("GET", SCHED).json()
    assert listed["timezone"] == "Asia/Kolkata" and listed["schedules"][0]["next_run_at"] == "2026-12-01T20:30:00Z"


def test_an_edit_is_checked_like_a_new_schedule(api, world, monkeypatch):
    _schedule_world(api, world, monkeypatch, dt.datetime(2026, 12, 1, 1, 0), "UTC")
    sched = api("POST", SCHED, json=_form()).json()["schedule"]
    for bad, msg in (({"time_of_day": "25:00"}, "time_of_day"), ({"frequency": "weekly"}, "weekday"),
                     ({"frequency": "monthly", "monthday": 31}, "monthday"), ({"frequency": "monthly"}, "monthday"),
                     ({"include": {"servers": False}}, "include"), ({"include": {"network": True}}, "soc_ack"),
                     ({"name": "<b>"}, "name"), ({"name": ""}, "name")):
        r = api("PATCH", f"{SCHED}/{sched['id']}", json=_form(**bad, expected_version=sched["row_version"]))
        assert r.status_code == 400 and msg in r.json()["detail"], (bad, r.text)
    # nothing above was saved
    assert api("GET", SCHED).json()["schedules"][0] == sched
    # network with the acknowledgement saves; a later edit that leaves the box alone keeps it
    r = api("PATCH", f"{SCHED}/{sched['id']}", json=_form(include={"network": True}, soc_ack=True,
                                                          expected_version=sched["row_version"]))
    assert r.status_code == 200 and r.json()["schedule"]["soc_ack"] is True
    v = r.json()["schedule"]["row_version"]
    r = api("PATCH", f"{SCHED}/{sched['id']}", json=_form(name="net-renamed", include={"network": True}, expected_version=v))
    assert r.status_code == 200 and r.json()["schedule"]["soc_ack"] is True
    assert r.json()["schedule"]["name"] == "net-renamed"
