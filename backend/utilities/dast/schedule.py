"""Compute next_run_at for DAST profiles (UTC)."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone


def compute_next_run_at(
    kind: str,
    schedule_time: str | None,
    weekday: int | None,
    now: datetime | None = None,
) -> datetime | None:
    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    kind = (kind or "off").lower()
    if kind not in ("daily", "weekly"):
        return None
    hh, mm = 0, 0
    if schedule_time and ":" in schedule_time:
        parts = schedule_time.strip().split(":")
        try:
            hh, mm = int(parts[0]), int(parts[1])
        except (TypeError, ValueError):
            hh, mm = 0, 0
    candidate = now.replace(hour=hh, minute=mm, second=0, microsecond=0)
    if kind == "daily":
        if candidate <= now:
            candidate += timedelta(days=1)
        return candidate
    wd = 0 if weekday is None else int(weekday) % 7
    days_ahead = (wd - candidate.weekday()) % 7
    candidate = candidate + timedelta(days=days_ahead)
    if candidate <= now:
        candidate += timedelta(days=7)
    return candidate
