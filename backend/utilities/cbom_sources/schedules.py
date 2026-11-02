"""Recurring collection runs: when a schedule's slots fall, and firing a due slot exactly once.

* Slots are wall-clock times in the team's ``window_timezone`` (zoneinfo, so daylight saving is handled): a slot in a
  spring-forward gap (02:30 that does not exist) runs at the first instant after the gap, a slot in a fall-back overlap
  (01:30 that happens twice) runs once, at the first occurrence. A slot is named by its LOCAL date and time, so the
  same local slot can never fire twice.
* Firing happens on a separate scheduler thread / process (``backend.workers.cbom_scheduler``), never inside the cloud
  worker's job loop (an AWS collection can hold that loop for hours).
* Exactly once across replicas: the schedule row is locked ``FOR UPDATE SKIP LOCKED`` (PostgreSQL), its ``next_run_at``
  is advanced with a compare-and-set in the same transaction as the run, and the run's ``client_request_id`` is
  deterministic per (schedule, slot), so the existing unique constraint (team, client_request_id) refuses a second run.
* Catch-up: after downtime only the LATEST missed slot runs (once), never one run per missed slot; the number of slots
  skipped is reported.
* The run is queued by ``runs.queue_run`` (the browser's path): sources already queued are skipped, credits are charged
  like a manual run, network ranges need the SOC acknowledgement stored on the schedule, and the run belongs to the
  schedule's owner. When it cannot start (not enough credits, nothing to scan, owner left the team) the slot is
  recorded as skipped with the reason and a ``schedule_skipped`` event.
"""
from __future__ import annotations

import calendar
import datetime as _dt
import zoneinfo
from typing import Any

from fastapi import HTTPException
from sqlalchemy import update
from sqlmodel import Session, select

from backend.new_models import CbomCollectionSchedule, CbomCollectionSource, TeamMembership
from backend.utilities.cbom_sources.common import audit, iso_z, log
from backend.utilities.cbom_sources.drift import _event, insert_events
from backend.utilities.cbom_sources.runs import queue_run
from backend.utilities.cbom_sources.schemas import Include, RunCreate
from backend.utilities.cbom_sources.settings import get_or_create_settings

FREQUENCIES = ("daily", "weekly", "monthly")
CRITICALITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}
MAX_SCHEDULES = 20
_UTC = _dt.timezone.utc


def _tz(name: str | None) -> zoneinfo.ZoneInfo:
    try:
        return zoneinfo.ZoneInfo(name or "UTC")
    except Exception:
        return zoneinfo.ZoneInfo("UTC")


def _hhmm(text: str) -> tuple[int, int]:
    hh, mm = (text or "00:00").split(":", 1)
    return int(hh), int(mm)


def _matches(day: _dt.date, frequency: str, weekday: int | None, monthday: int | None) -> bool:
    if frequency == "daily":
        return True
    if frequency == "weekly":
        return day.weekday() == (weekday if weekday is not None else 0)
    wanted = min(monthday or 1, calendar.monthrange(day.year, day.month)[1])
    return day.day == wanted


def wall_to_utc(wall: _dt.datetime, tz: zoneinfo.ZoneInfo) -> _dt.datetime:
    """Local wall time -> naive UTC. fold=0: a time in a spring-forward gap is read with the offset before the
    transition (so it lands just after the gap); a repeated fall-back time is its first occurrence."""
    return wall.replace(tzinfo=tz, fold=0).astimezone(_UTC).replace(tzinfo=None)


def slot_key(wall: _dt.datetime) -> str:
    return wall.strftime("%Y-%m-%dT%H:%M")


def _slots_around(s: Any, tz: zoneinfo.ZoneInfo, moment_utc: _dt.datetime, days: range):
    hh, mm = _hhmm(s.time_of_day)
    local_day = moment_utc.replace(tzinfo=_UTC).astimezone(tz).date()
    for offset in days:
        day = local_day + _dt.timedelta(days=offset)
        if _matches(day, s.frequency, s.weekday, s.monthday):
            wall = _dt.datetime(day.year, day.month, day.day, hh, mm)
            yield slot_key(wall), wall_to_utc(wall, tz)


def next_slot(s: Any, tz_name: str, after_utc: _dt.datetime) -> tuple[str, _dt.datetime]:
    """The first slot strictly after ``after_utc`` (naive UTC)."""
    tz = _tz(tz_name)
    for key, at in _slots_around(s, tz, after_utc, range(-1, 64)):
        if at > after_utc:
            return key, at
    raise ValueError("no slot in the next two months")  # unreachable for daily / weekly / monthly (day <= 28)


def latest_slot(s: Any, tz_name: str, at_or_before_utc: _dt.datetime) -> tuple[str, _dt.datetime] | None:
    tz = _tz(tz_name)
    for key, at in _slots_around(s, tz, at_or_before_utc, range(1, -64, -1)):
        if at <= at_or_before_utc:
            return key, at
    return None


def missed_between(s: Any, tz_name: str, first_utc: _dt.datetime, last_utc: _dt.datetime, cap: int = 1000) -> int:
    """Slots in [first, last) — the ones a catch-up does not run."""
    count, cursor = 0, first_utc - _dt.timedelta(seconds=1)
    while count < cap:
        _key, at = next_slot(s, tz_name, cursor)
        if at >= last_utc:
            break
        count += 1
        cursor = at
    return count


def _source_ids(session: Session, s: CbomCollectionSchedule) -> list[int] | None:
    """None: every source of the included groups; otherwise the sources the schedule's filters keep."""
    wanted = {int(i) for i in (s.source_ids or []) if isinstance(i, int)}
    if not wanted and not s.min_criticality:
        return None
    floor = CRITICALITY_RANK.get(s.min_criticality or "low", 0)
    out = []
    for src in session.exec(select(CbomCollectionSource).where(CbomCollectionSource.team_id == s.team_id)
                            .order_by(CbomCollectionSource.id)).all():
        if wanted and src.id not in wanted:
            continue
        crit = str((src.config or {}).get("business_criticality") or "medium")
        if CRITICALITY_RANK.get(crit, 1) < floor:
            continue
        out.append(src.id)
    return out


def _owner_in_team(session: Session, s: CbomCollectionSchedule) -> bool:
    return session.exec(select(TeamMembership).where(TeamMembership.team_id == s.team_id,
                                                     TeamMembership.user_id == s.owner_user_id)).first() is not None


def fire_one(engine, schedule_id: int, now: _dt.datetime) -> dict[str, Any] | None:
    """Fire the schedule's due slot if this process wins it. Returns what happened, or None (not due / lost)."""
    with Session(engine) as session:
        query = select(CbomCollectionSchedule).where(CbomCollectionSchedule.id == schedule_id)
        if session.get_bind().dialect.name == "postgresql":
            query = query.with_for_update(skip_locked=True)
        s = session.exec(query).first()
        if s is None or not s.enabled or s.next_run_at is None or s.next_run_at > now:
            return None
        settings = get_or_create_settings(session, s.team_id)
        tz_name = settings.window_timezone
        due_next = s.next_run_at
        latest = latest_slot(s, tz_name, now)
        if latest is None or latest[1] < due_next:  # the time zone or the time changed since next_run_at was set
            local = due_next.replace(tzinfo=_UTC).astimezone(_tz(tz_name)).replace(tzinfo=None)
            latest = (slot_key(local), due_next)
        key, slot_at = latest
        missed = missed_between(s, tz_name, due_next, slot_at)
        upcoming_key, upcoming = next_slot(s, tz_name, now)
        won = session.exec(update(CbomCollectionSchedule).where(
            CbomCollectionSchedule.id == s.id, CbomCollectionSchedule.next_run_at == due_next)
            .values(next_run_at=upcoming, last_slot=key, last_fired_at=now, last_updated=now,
                    row_version=CbomCollectionSchedule.row_version + 1)).rowcount == 1
        if not won:
            session.rollback()
            return None
        request_id = f"sched-{s.id}-{key.replace('-', '').replace(':', '')}"
        status, message, run_id = "queued", None, None
        try:
            if not _owner_in_team(session, s):
                raise HTTPException(status_code=400, detail="The schedule's owner is no longer a member of the team")
            ids = _source_ids(session, s)
            if ids is not None and not ids:
                raise HTTPException(status_code=400, detail="No source matches the schedule's sources and criticality")
            body = RunCreate(include=Include(**{k: bool(v) for k, v in (s.include or {}).items() if k in Include.model_fields}),
                             source_ids=ids, client_request_id=request_id, soc_ack=s.soc_ack_at is not None)
            run, replayed = queue_run(session, s.team_id, s.owner_user_id, body, settings, now, schedule_id=s.id)
            if replayed:  # another process queued this slot first (its transaction also advanced the schedule)
                session.rollback()
                return None
            run_id = run.id
            message = f"Run #{run.id} queued" + (f" (catch-up: {missed} earlier slot(s) not run)" if missed else "")
        except HTTPException as exc:
            status, message = "skipped", str(exc.detail)[:400]
            insert_events(session, [_event(s.team_id, now, "schedule_skipped",
                                           {"label": s.name, "reason": message}, scope="node",
                                           source_ref=f"schedule:{s.id}", source_name=s.name,
                                           key_parts=("schedule", s.id, key))])
        session.exec(update(CbomCollectionSchedule).where(CbomCollectionSchedule.id == s.id).values(
            last_status=status, last_message=message, last_run_id=run_id))
        audit(session, team_id=s.team_id, actor_type="system", actor_id=s.owner_user_id,
              action="schedule.fire" if status == "queued" else "schedule.skipped", object_type="schedule",
              object_id=s.id, changed_fields=[f"slot:{key}"] + ([f"run:{run_id}"] if run_id else []))
        session.commit()
        log("schedule fired", team=s.team_id, schedule=s.id, slot=key, status=status, run=run_id,
            missed=missed or None, next=iso_z(upcoming))
        return {"schedule_id": s.id, "slot": key, "status": status, "run_id": run_id, "message": message,
                "missed": missed, "next_run_at": iso_z(upcoming), "next_slot": upcoming_key}


def fire_due(engine, now: _dt.datetime, *, limit: int = 50) -> list[dict[str, Any]]:
    with Session(engine) as session:
        ids = session.exec(select(CbomCollectionSchedule.id).where(
            CbomCollectionSchedule.enabled == True,  # noqa: E712
            CbomCollectionSchedule.next_run_at.is_not(None),  # type: ignore[union-attr]
            CbomCollectionSchedule.next_run_at <= now).order_by(CbomCollectionSchedule.next_run_at).limit(limit)).all()
    out = []
    for schedule_id in ids:
        try:
            result = fire_one(engine, schedule_id, now)
        except Exception as exc:  # one schedule must not stop the others (a lost race on SQLite is "locked")
            log("schedule FAILED", schedule=schedule_id, error=type(exc).__name__)
            continue
        if result is not None:
            out.append(result)
    return out


def public_schedule(s: CbomCollectionSchedule) -> dict[str, Any]:
    return {"id": s.id, "name": s.name, "enabled": s.enabled, "frequency": s.frequency, "time_of_day": s.time_of_day,
            "weekday": s.weekday, "monthday": s.monthday, "include": s.include or {}, "source_ids": s.source_ids or [],
            "min_criticality": s.min_criticality, "soc_ack": s.soc_ack_at is not None, "soc_ack_at": iso_z(s.soc_ack_at),
            "owner_user_id": s.owner_user_id, "next_run_at": iso_z(s.next_run_at), "last_slot": s.last_slot,
            "last_fired_at": iso_z(s.last_fired_at), "last_run_id": s.last_run_id, "last_status": s.last_status,
            "last_message": s.last_message, "row_version": s.row_version}


__all__ = ["FREQUENCIES", "MAX_SCHEDULES", "fire_due", "fire_one", "latest_slot", "missed_between", "next_slot",
           "public_schedule", "wall_to_utc"]
