"""Compute next_run_at for DAST profiles in Asia/Kolkata (stored as UTC)."""
from __future__ import annotations

from calendar import monthrange
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

IST = ZoneInfo("Asia/Kolkata")
UTC = timezone.utc

SCHEDULE_KINDS = frozenset(
    {
        "off",
        "hourly",
        "every_n_hours",
        "daily",
        "weekdays",
        "weekly",
        "monthly",
        "once",
        "cron",
    }
)


def parse_hhmm(value: str | None) -> tuple[int, int]:
    if not value or ":" not in str(value):
        return 0, 0
    parts = str(value).strip().split(":")
    try:
        hh = int(parts[0])
        mm = int(parts[1])
    except (TypeError, ValueError):
        return 0, 0
    return max(0, min(23, hh)), max(0, min(59, mm))


def _as_utc(now: datetime) -> datetime:
    if now.tzinfo is None:
        return now.replace(tzinfo=UTC)
    return now.astimezone(UTC)


def _as_ist(now: datetime) -> datetime:
    return _as_utc(now).astimezone(IST)


def _to_utc(ist_dt: datetime) -> datetime:
    return ist_dt.astimezone(UTC)


def times_from(schedule_time: str | None, config: dict | None) -> list[tuple[int, int]]:
    raw: list[str] = []
    if isinstance(config, dict):
        times = config.get("times")
        if isinstance(times, list):
            raw = [str(t) for t in times if t is not None and str(t).strip()]
    if not raw and schedule_time:
        raw = [schedule_time]
    if not raw:
        raw = ["00:00"]
    parsed = [parse_hhmm(item) for item in raw]
    parsed.sort()
    return parsed


def normalize_schedule_config(
    kind: str | None,
    schedule_time: str | None = None,
    weekday: int | None = None,
    config: dict | None = None,
) -> dict:
    cfg = dict(config or {}) if isinstance(config, dict) else {}
    resolved = str(cfg.get("kind") or kind or "off").lower()
    if resolved not in SCHEDULE_KINDS:
        resolved = "off"
    cfg["kind"] = resolved
    parsed_times = times_from(schedule_time, cfg)
    cfg["times"] = [f"{hh:02d}:{mm:02d}" for hh, mm in parsed_times]
    if weekday is not None and cfg.get("weekday") is None:
        cfg["weekday"] = int(weekday) % 7
    if cfg.get("weekday") is not None:
        try:
            cfg["weekday"] = int(cfg["weekday"]) % 7
        except (TypeError, ValueError):
            cfg.pop("weekday", None)
    if cfg.get("interval_hours") is not None:
        try:
            cfg["interval_hours"] = max(1, min(24, int(cfg["interval_hours"])))
        except (TypeError, ValueError):
            cfg["interval_hours"] = 1
    if cfg.get("monthday") is not None:
        try:
            cfg["monthday"] = max(1, min(28, int(cfg["monthday"])))
        except (TypeError, ValueError):
            cfg["monthday"] = 1
    cron = cfg.get("cron")
    if cron is not None:
        cfg["cron"] = str(cron).strip()
    return cfg


def mirror_from_config(config: dict | None) -> tuple[str, str | None, int | None]:
    cfg = config or {}
    kind = str(cfg.get("kind") or "off")
    times = cfg.get("times") or []
    time_s = times[0] if times else None
    weekday = cfg.get("weekday")
    try:
        weekday_i = int(weekday) if weekday is not None else None
    except (TypeError, ValueError):
        weekday_i = None
    return kind, time_s, weekday_i


def _parse_once_at(value: str | None) -> datetime | None:
    if not value or not str(value).strip():
        return None
    raw = str(value).strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(raw)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=IST)
    return parsed.astimezone(UTC)


def _next_on_days(
    now_ist: datetime,
    hhmm: list[tuple[int, int]],
    allowed_weekdays: set[int] | None,
) -> datetime | None:
    for day_offset in range(0, 8):
        day = (now_ist + timedelta(days=day_offset)).date()
        if allowed_weekdays is not None and day.weekday() not in allowed_weekdays:
            continue
        for hh, mm in hhmm:
            candidate = datetime(day.year, day.month, day.day, hh, mm, tzinfo=IST)
            if candidate > now_ist:
                return _to_utc(candidate)
    return None


def _next_monthly(now_ist: datetime, hhmm: list[tuple[int, int]], monthday: int) -> datetime | None:
    year, month = now_ist.year, now_ist.month
    for _ in range(0, 14):
        last = monthrange(year, month)[1]
        day = min(monthday, last)
        for hh, mm in hhmm:
            candidate = datetime(year, month, day, hh, mm, tzinfo=IST)
            if candidate > now_ist:
                return _to_utc(candidate)
        if month == 12:
            year += 1
            month = 1
        else:
            month += 1
    return None


def _cron_field_matches(value: int, spec: str, minimum: int, maximum: int) -> bool:
    spec = spec.strip()
    if spec == "*":
        return True
    for chunk in spec.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        step = 1
        if "/" in chunk:
            base, step_s = chunk.split("/", 1)
            try:
                step = max(1, int(step_s))
            except ValueError:
                return False
            chunk = base
        if chunk in ("*", ""):
            start, end = minimum, maximum
        elif "-" in chunk:
            a, b = chunk.split("-", 1)
            try:
                start, end = int(a), int(b)
            except ValueError:
                return False
        else:
            try:
                start = end = int(chunk)
            except ValueError:
                return False
        if start < minimum or end > maximum:
            continue
        if start <= value <= end and (value - start) % step == 0:
            return True
    return False


def _cron_dow_matches(ist_dt: datetime, spec: str) -> bool:
    # Standard cron: 0 and 7 = Sunday, 1 = Monday. Python weekday: Monday = 0.
    python_wd = ist_dt.weekday()
    cron_wd = (python_wd + 1) % 7  # Sunday=0 … Saturday=6
    if _cron_field_matches(cron_wd, spec, 0, 7):
        return True
    if "7" in spec and cron_wd == 0:
        return _cron_field_matches(7, spec, 0, 7)
    return False


def next_cron(expr: str, now_ist: datetime) -> datetime | None:
    parts = expr.split()
    if len(parts) != 5:
        return None
    minute_s, hour_s, dom_s, month_s, dow_s = parts
    cursor = now_ist.replace(second=0, microsecond=0) + timedelta(minutes=1)
    limit = cursor + timedelta(days=400)
    while cursor <= limit:
        if (
            _cron_field_matches(cursor.month, month_s, 1, 12)
            and _cron_field_matches(cursor.day, dom_s, 1, 31)
            and _cron_field_matches(cursor.hour, hour_s, 0, 23)
            and _cron_field_matches(cursor.minute, minute_s, 0, 59)
            and _cron_dow_matches(cursor, dow_s)
        ):
            return _to_utc(cursor)
        cursor += timedelta(minutes=1)
    return None


def compute_next_run_at(
    kind: str,
    schedule_time: str | None,
    weekday: int | None,
    now: datetime | None = None,
    *,
    config: dict | None = None,
) -> datetime | None:
    now_utc = _as_utc(now or datetime.now(UTC))
    cfg = normalize_schedule_config(kind, schedule_time, weekday, config)
    resolved = cfg["kind"]
    if resolved == "off":
        return None
    now_ist = _as_ist(now_utc)
    hhmm = times_from(schedule_time, cfg)

    if resolved == "hourly":
        minute = hhmm[0][1] if hhmm else 0
        candidate = now_ist.replace(minute=minute, second=0, microsecond=0)
        if candidate <= now_ist:
            candidate += timedelta(hours=1)
        return _to_utc(candidate)

    if resolved == "every_n_hours":
        interval = int(cfg.get("interval_hours") or 1)
        minute = hhmm[0][1] if hhmm else 0
        start = now_ist.replace(hour=0, minute=minute, second=0, microsecond=0)
        if start > now_ist:
            return _to_utc(start)
        elapsed = now_ist - start
        hours = int(elapsed.total_seconds() // 3600)
        steps = hours // interval
        candidate = start + timedelta(hours=(steps + 1) * interval)
        return _to_utc(candidate)

    if resolved == "daily":
        return _next_on_days(now_ist, hhmm, None)

    if resolved == "weekdays":
        return _next_on_days(now_ist, hhmm, {0, 1, 2, 3, 4})

    if resolved == "weekly":
        wd = cfg.get("weekday")
        if wd is None:
            wd = weekday if weekday is not None else 0
        return _next_on_days(now_ist, hhmm, {int(wd) % 7})

    if resolved == "monthly":
        monthday = int(cfg.get("monthday") or 1)
        return _next_monthly(now_ist, hhmm, monthday)

    if resolved == "once":
        once_at = _parse_once_at(cfg.get("once_at"))
        if once_at is None or once_at <= now_utc:
            return None
        return once_at

    if resolved == "cron":
        return next_cron(str(cfg.get("cron") or ""), now_ist)

    return None
