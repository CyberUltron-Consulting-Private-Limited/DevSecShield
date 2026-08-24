"""IST wall-clock next-run for DAST profile schedules."""
from __future__ import annotations

import os
import sys
from datetime import datetime
from zoneinfo import ZoneInfo

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from backend.utilities.dast.schedule import compute_next_run_at

IST = ZoneInfo("Asia/Kolkata")
UTC = ZoneInfo("UTC")


def _ist(y, m, d, hh, mm) -> datetime:
    return datetime(y, m, d, hh, mm, tzinfo=IST)


def _utc(dt_ist: datetime) -> datetime:
    return dt_ist.astimezone(UTC)


def test_daily_09_ist_rolls_to_next_morning() -> None:
    # 12:00 UTC = 17:30 IST on 24 Aug → next 09:00 IST is 25 Aug 03:30 UTC
    now = datetime(2026, 8, 24, 12, 0, tzinfo=UTC)
    nxt = compute_next_run_at("daily", "09:00", None, now=now)
    assert nxt == _utc(_ist(2026, 8, 25, 9, 0))


def test_daily_two_times_picks_later_same_day() -> None:
    now = _ist(2026, 8, 24, 10, 0).astimezone(UTC)
    nxt = compute_next_run_at(
        "daily",
        "09:00",
        None,
        now=now,
        config={"kind": "daily", "times": ["09:00", "21:00"]},
    )
    assert nxt == _utc(_ist(2026, 8, 24, 21, 0))


def test_hourly_uses_minute_offset() -> None:
    now = _ist(2026, 8, 24, 10, 15).astimezone(UTC)
    nxt = compute_next_run_at(
        "hourly",
        None,
        None,
        now=now,
        config={"kind": "hourly", "times": ["00:15"]},
    )
    assert nxt == _utc(_ist(2026, 8, 24, 11, 15))


def test_every_n_hours_aligns_from_midnight_ist() -> None:
    now = _ist(2026, 8, 24, 10, 0).astimezone(UTC)
    nxt = compute_next_run_at(
        "every_n_hours",
        "00:00",
        None,
        now=now,
        config={"kind": "every_n_hours", "interval_hours": 4, "times": ["00:00"]},
    )
    assert nxt == _utc(_ist(2026, 8, 24, 12, 0))


def test_weekdays_skips_saturday_to_monday() -> None:
    now = _ist(2026, 8, 22, 10, 0).astimezone(UTC)  # Saturday
    nxt = compute_next_run_at(
        "weekdays",
        "09:00",
        None,
        now=now,
        config={"kind": "weekdays", "times": ["09:00"]},
    )
    assert nxt == _utc(_ist(2026, 8, 24, 9, 0))  # Monday


def test_monthly_rolls_to_next_month() -> None:
    now = _ist(2026, 8, 24, 10, 0).astimezone(UTC)
    nxt = compute_next_run_at(
        "monthly",
        "09:00",
        None,
        now=now,
        config={"kind": "monthly", "monthday": 15, "times": ["09:00"]},
    )
    assert nxt == _utc(_ist(2026, 9, 15, 9, 0))


def test_once_future_returns_that_instant() -> None:
    now = _ist(2026, 8, 24, 10, 0).astimezone(UTC)
    nxt = compute_next_run_at(
        "once",
        None,
        None,
        now=now,
        config={"kind": "once", "once_at": "2026-08-25T09:00:00+05:30"},
    )
    assert nxt == _utc(_ist(2026, 8, 25, 9, 0))


def test_once_past_returns_none() -> None:
    now = _ist(2026, 8, 24, 10, 0).astimezone(UTC)
    nxt = compute_next_run_at(
        "once",
        None,
        None,
        now=now,
        config={"kind": "once", "once_at": "2026-08-20T09:00:00+05:30"},
    )
    assert nxt is None


def test_cron_weekdays_9am_ist() -> None:
    now = _ist(2026, 8, 22, 10, 0).astimezone(UTC)  # Saturday
    nxt = compute_next_run_at(
        "cron",
        None,
        None,
        now=now,
        config={"kind": "cron", "cron": "0 9 * * 1-5"},
    )
    assert nxt == _utc(_ist(2026, 8, 24, 9, 0))


def test_off_is_none() -> None:
    now = datetime(2026, 8, 24, 12, 0, tzinfo=UTC)
    assert compute_next_run_at("off", "09:00", None, now=now) is None
