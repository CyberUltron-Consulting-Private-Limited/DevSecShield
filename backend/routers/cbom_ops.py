"""CBOM outputs B: diff and drift, schedules, remediation waves, heat-map and certificate calendar, SBOM links.

Routes follow the CBOM Sources conventions (``backend/utilities/cbom_sources/http.py``): team members only, another
team's or a missing record is a 404, changes need the creator or a team admin (400, never 403), stale forms get 409,
validation errors are a 400 that never echoes input.
"""
from __future__ import annotations

import re
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, Header, HTTPException, Query
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from sqlalchemy import func
from sqlmodel import Session, select

from backend.new_models import (
    CbomCollectedAsset,
    CbomCollectionRun,
    CbomCollectionSchedule,
    CbomCollectionSource,
    CbomDriftEvent,
    Scan,
)
from backend.utilities.cbom_sources import drift as DRIFT
from backend.utilities.cbom_sources import heatmap as HEAT
from backend.utilities.cbom_sources import sbom_link as SBOM
from backend.utilities.cbom_sources import schedules as SCHED
from backend.utilities.cbom_sources import waves as WAVES
from backend.utilities.cbom_sources.common import NAME_RE, audit, iso_z, log, utcnow
from backend.utilities.cbom_sources.http import (
    PRIVATE,
    CbomRoute,
    ObjectId,
    TeamId,
    authorize,
    bump_version,
    check_version,
    read_limiter,
    require_owner_or_admin,
    server_error,
    write_limiter,
)
from backend.utilities.cbom_sources.schemas import Include
from backend.utilities.cbom_sources.settings import get_or_create_settings

router = APIRouter(tags=["cbom-ops"], route_class=CbomRoute)
AuthHeader = Annotated[str | None, Header()]
READ = [Depends(read_limiter)]
WRITE = [Depends(write_limiter)]
SRC = "/{team_id}/cbom/sources"
CODE = "/{team_id}/cbom/code-scans"


async def _run(what: str, team_id: int, fn, *args) -> Any:
    try:
        return await run_in_threadpool(fn, *args)
    except HTTPException:
        raise
    except Exception as exc:
        raise server_error(f"cbom ops {what}", exc, team=team_id) from None


def _ok(payload: Any, status_code: int = 200) -> JSONResponse:
    return JSONResponse(payload, status_code=status_code, headers=PRIVATE)


def _owned_run(session: Session, team_id: int, run_id: int) -> CbomCollectionRun:
    run = session.get(CbomCollectionRun, run_id)
    if run is None or run.team_id != team_id:
        raise HTTPException(status_code=404, detail="Run not found")
    return run


def _code_scan(session: Session, team_id: int, scan_id: int) -> Scan:
    scan = session.get(Scan, scan_id)
    if scan is None or scan.team_id != team_id or scan.scan_type != "cbom":
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.scan_status != "success":
        raise HTTPException(status_code=409, detail="Only a completed scan can be compared")
    return scan


# ============================================================================ diff and drift
def _run_diff(engine, team_id: int, run_id: int, against: int | None) -> dict:
    with Session(engine) as session:
        run = _owned_run(session, team_id, run_id)
        base = _owned_run(session, team_id, against) if against else DRIFT.previous_comparable_run(session, run)
        if base is None:
            return {"run_id": run.id, "against_run_id": None,
                    "message": "No earlier run collected any of these sources completely; nothing to compare yet"}
        if base.id == run.id:
            raise HTTPException(status_code=400, detail="against: choose another run")
        older, newer = (base, run) if base.id < run.id else (run, base)
        return DRIFT.run_diff(session, newer, older)


@router.get(SRC + "/runs/{run_id}/diff", dependencies=READ,
            summary="Compare two runs: assets added / removed / changed, findings opened / resolved, readiness delta")
async def run_diff(team_id: TeamId, run_id: ObjectId, against: int | None = Query(default=None, ge=1, le=2_147_483_647),
                   Authorization: AuthHeader = None):
    engine, _user = await authorize(team_id, Authorization)
    return _ok(await _run("run diff", team_id, _run_diff, engine, team_id, run_id, against))


def _events(session: Session, team_id: int, *, run_id: int | None = None, scan_id: int | None = None,
            kind: str | None = None, before_id: int | None = None, limit: int = 200) -> list[dict]:
    query = select(CbomDriftEvent).where(CbomDriftEvent.team_id == team_id)
    if run_id is not None:
        query = query.where(CbomDriftEvent.run_id == run_id)
    if scan_id is not None:
        query = query.where(CbomDriftEvent.scan_id == scan_id)
    if kind:
        query = query.where(CbomDriftEvent.kind == kind)
    if before_id:
        query = query.where(CbomDriftEvent.id < before_id)
    rows = session.exec(query.order_by(CbomDriftEvent.id.desc()).limit(limit)).all()  # type: ignore[union-attr]
    return [DRIFT.public_event(e) for e in rows]


def _counts(session: Session, team_id: int, **where: int) -> dict[str, int]:
    query = select(CbomDriftEvent.kind, func.count()).where(CbomDriftEvent.team_id == team_id)
    for column, value in where.items():
        query = query.where(getattr(CbomDriftEvent, column) == value)
    return {k: int(n) for k, n in session.exec(query.group_by(CbomDriftEvent.kind)).all()}


def _run_changes(engine, team_id: int, run_id: int, limit: int) -> dict:
    now = utcnow()
    with Session(engine) as session:
        run = _owned_run(session, team_id, run_id)
        if run.drift_at is None and run.status in DRIFT.FINISHED:
            DRIFT.record_run_drift(session, run, now)  # the scheduler may not have reached it yet
            session.commit()
            session.refresh(run)
        return {"run_id": run.id, "status": run.status, "recorded": run.drift_at is not None,
                "recorded_at": iso_z(run.drift_at), "counts": _counts(session, team_id, run_id=run.id),
                "events": _events(session, team_id, run_id=run.id, limit=limit)}


@router.get(SRC + "/runs/{run_id}/changes", dependencies=READ,
            summary="What changed in this run against each source's previous complete collection (drift events)")
async def run_changes(team_id: TeamId, run_id: ObjectId, limit: int = Query(default=200, ge=1, le=1000),
                      Authorization: AuthHeader = None):
    engine, _user = await authorize(team_id, Authorization)
    return _ok(await _run("run changes", team_id, _run_changes, engine, team_id, run_id, limit))


def _team_drift(engine, team_id: int, kind: str | None, before_id: int | None, limit: int) -> dict:
    with Session(engine) as session:
        events = _events(session, team_id, kind=kind, before_id=before_id, limit=limit)
        return {"events": events, "next_before_id": events[-1]["id"] if len(events) == limit else None}


@router.get(SRC + "/drift", dependencies=READ, summary="Recent drift events of the team (newest first; page with before_id)")
async def team_drift(team_id: TeamId, kind: str | None = Query(default=None, max_length=24),
                     before_id: int | None = Query(default=None, ge=1, le=2_147_483_647),
                     limit: int = Query(default=100, ge=1, le=500), Authorization: AuthHeader = None):
    engine, _user = await authorize(team_id, Authorization)
    if kind is not None and kind not in DRIFT.EVENT_KINDS:
        raise HTTPException(status_code=400, detail="kind: unknown event kind")
    return _ok(await _run("drift", team_id, _team_drift, engine, team_id, kind, before_id, limit))


def _code_diff(engine, team_id: int, scan_id: int, against: int | None) -> dict:
    with Session(engine) as session:
        scan = _code_scan(session, team_id, scan_id)
        base = _code_scan(session, team_id, against) if against else DRIFT.previous_code_scan(session, scan)
        if base is None:
            return {"scan_id": scan.id, "against_scan_id": None,
                    "message": "No earlier completed scan of the same repository and branch to compare with"}
        if base.id == scan.id:
            raise HTTPException(status_code=400, detail="against: choose another scan")
        older, newer = (base, scan) if (base.created_at, base.id) < (scan.created_at, scan.id) else (scan, base)
        out = DRIFT.code_scan_diff(newer, older)
        out.pop("_views", None)
        out["events"] = _events(session, team_id, scan_id=newer.id, limit=200)
        return out


@router.get(CODE + "/{scan_id}/diff", dependencies=READ,
            summary="Compare two CBOM code scans of a repository and branch (line-independent identity)")
async def code_diff(team_id: TeamId, scan_id: ObjectId, against: int | None = Query(default=None, ge=1, le=2_147_483_647),
                    Authorization: AuthHeader = None):
    engine, _user = await authorize(team_id, Authorization)
    return _ok(await _run("code diff", team_id, _code_diff, engine, team_id, scan_id, against))


# ============================================================================ heat-map and certificates
def _heatmap(engine, team_id: int, run_id: int, by: str) -> dict:
    with Session(engine) as session:
        run = _owned_run(session, team_id, run_id)
        return {"run_id": run.id, **HEAT.run_heatmap(session, team_id, run.id, by=by)}


@router.get(SRC + "/runs/{run_id}/heatmap", dependencies=READ,
            summary="Algorithm family x source (or asset type) by worst impact, and the certificates with expiry dates")
async def run_heatmap(team_id: TeamId, run_id: ObjectId, by: str = Query(default="source", pattern="^(source|type)$"),
                      Authorization: AuthHeader = None):
    engine, _user = await authorize(team_id, Authorization)
    return _ok(await _run("heatmap", team_id, _heatmap, engine, team_id, run_id, by))


# ============================================================================ schedules
_TIME = re.compile(r"^([01]\d|2[0-3]):[0-5]\d$")


class _ScheduleFields(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    name: str | None = Field(default=None, min_length=1, max_length=64)
    enabled: bool | None = None
    frequency: Literal["daily", "weekly", "monthly"] | None = None
    time_of_day: str | None = Field(default=None, max_length=5)
    weekday: int | None = Field(default=None, ge=0, le=6)
    monthday: int | None = Field(default=None, ge=1, le=28)
    include: Include | None = None
    source_ids: list[int] | None = Field(default=None, max_length=500)
    min_criticality: Literal["low", "medium", "high", "critical"] | None = None
    soc_ack: bool | None = None

    @field_validator("name")
    @classmethod
    def _name(cls, v: str | None) -> str | None:
        if v is not None and not NAME_RE.match(v):
            raise ValueError("name: letters, digits, spaces and . _ - (64 at most)")
        return v

    @field_validator("time_of_day")
    @classmethod
    def _time(cls, v: str | None) -> str | None:
        if v is not None and not _TIME.match(v):
            raise ValueError("time_of_day: use HH:MM (24-hour)")
        return v


class ScheduleCreate(_ScheduleFields):
    name: str = Field(min_length=1, max_length=64)
    frequency: Literal["daily", "weekly", "monthly"]
    time_of_day: str = Field(max_length=5)
    include: Include

    @model_validator(mode="after")
    def _shape(self) -> "ScheduleCreate":
        if self.frequency == "weekly" and self.weekday is None:
            raise ValueError("weekday: choose the day of the week (0 = Monday)")
        if self.frequency == "monthly" and self.monthday is None:
            raise ValueError("monthday: choose the day of the month (1-28)")
        return self


class ScheduleUpdate(_ScheduleFields):
    expected_version: int | None = None


def _timing(s: CbomCollectionSchedule) -> tuple:
    return s.enabled, s.frequency, s.time_of_day, s.weekday, s.monthday


def _apply_schedule(session: Session, team_id: int, user_id: int, s: CbomCollectionSchedule, fields: dict[str, Any],
                    now) -> None:
    timing = _timing(s)
    for key in ("name", "enabled", "frequency", "time_of_day", "weekday", "monthday", "min_criticality"):
        if key in fields:
            setattr(s, key, fields[key])
    if "include" in fields and fields["include"] is not None:
        s.include = fields["include"]
    if "source_ids" in fields:
        ids = sorted({int(i) for i in fields["source_ids"] or []})
        if ids:
            found = set(session.exec(select(CbomCollectionSource.id).where(
                CbomCollectionSource.team_id == team_id, CbomCollectionSource.id.in_(ids))).all())  # type: ignore[union-attr]
            if found != set(ids):
                raise HTTPException(status_code=400, detail="source_ids: a source was not found in this team")
        s.source_ids = ids
    if s.frequency == "weekly" and s.weekday is None:
        raise HTTPException(status_code=400, detail="weekday: choose the day of the week (0 = Monday)")
    if s.frequency == "monthly" and s.monthday is None:
        raise HTTPException(status_code=400, detail="monthday: choose the day of the month (1-28)")
    if not any((s.include or {}).values()):
        raise HTTPException(status_code=400, detail="include: choose at least one group to scan")
    if "soc_ack" in fields and fields["soc_ack"] is not None:
        s.soc_ack_by, s.soc_ack_at = (user_id, now) if fields["soc_ack"] else (None, None)
    if (s.include or {}).get("network") and s.soc_ack_at is None:
        raise HTTPException(status_code=400, detail="soc_ack: scheduled network scans need your SOC's agreement to the "
                                                    "ranges and scan windows")
    # Only a change of WHEN it runs (or pausing / resuming) moves the next run: a rename or a change of scope keeps
    # it, so a slot that is due right now still fires instead of being dropped without a run or a "skipped" record.
    if s.id is None or _timing(s) != timing:
        tz = get_or_create_settings(session, team_id).window_timezone
        s.next_run_at = SCHED.next_slot(s, tz, now)[1] if s.enabled else None


def _list_schedules(engine, team_id: int) -> dict:
    with Session(engine) as session:
        settings = get_or_create_settings(session, team_id)
        rows = session.exec(select(CbomCollectionSchedule).where(CbomCollectionSchedule.team_id == team_id)
                            .order_by(CbomCollectionSchedule.id)).all()
        return {"schedules": [SCHED.public_schedule(s) for s in rows], "timezone": settings.window_timezone,
                "server_time": iso_z(utcnow())}


@router.get(SRC + "/schedules", dependencies=READ, summary="Recurring collection runs")
async def list_schedules(team_id: TeamId, Authorization: AuthHeader = None):
    engine, _user = await authorize(team_id, Authorization)
    return _ok(await _run("list schedules", team_id, _list_schedules, engine, team_id))


def _create_schedule(engine, team_id: int, user_id: int, body: ScheduleCreate) -> dict:
    now = utcnow()
    with Session(engine) as session:
        total = session.exec(select(func.count()).select_from(CbomCollectionSchedule)
                             .where(CbomCollectionSchedule.team_id == team_id)).one()
        if total >= SCHED.MAX_SCHEDULES:
            raise HTTPException(status_code=400, detail=f"A team can have at most {SCHED.MAX_SCHEDULES} schedules")
        s = CbomCollectionSchedule(team_id=team_id, owner_user_id=user_id, updated_by_user_id=user_id, name=body.name,
                                   frequency=body.frequency, time_of_day=body.time_of_day, created_at=now,
                                   last_updated=now)
        fields = body.model_dump(exclude_unset=True)
        fields["include"] = body.include.model_dump()
        fields.setdefault("enabled", True)
        _apply_schedule(session, team_id, user_id, s, fields, now)
        session.add(s)
        session.flush()
        audit(session, team_id=team_id, actor_type="user", actor_id=user_id, action="schedule.create",
              object_type="schedule", object_id=s.id, changed_fields=fields.keys())
        session.commit()
        session.refresh(s)
        log("schedule created", team=team_id, schedule=s.id, frequency=s.frequency, by=user_id)
        return {"schedule": SCHED.public_schedule(s)}


@router.post(SRC + "/schedules", dependencies=WRITE, summary="Add a recurring run (credits are charged when it fires)")
async def create_schedule(team_id: TeamId, body: ScheduleCreate, Authorization: AuthHeader = None):
    engine, user = await authorize(team_id, Authorization)
    return _ok(await _run("create schedule", team_id, _create_schedule, engine, team_id, user.id, body), 201)


def _owned_schedule(session: Session, team_id: int, schedule_id: int) -> CbomCollectionSchedule:
    s = session.get(CbomCollectionSchedule, schedule_id)
    if s is None or s.team_id != team_id:
        raise HTTPException(status_code=404, detail="Schedule not found")
    return s


def _update_schedule(engine, team_id: int, user_id: int, schedule_id: int, body: ScheduleUpdate) -> dict:
    now = utcnow()
    with Session(engine) as session:
        s = _owned_schedule(session, team_id, schedule_id)
        require_owner_or_admin(session, user_id, team_id, s.owner_user_id, "schedule")
        check_version(s, body.expected_version)
        fields = body.model_dump(exclude_unset=True, exclude={"expected_version"})
        if "include" in fields and body.include is not None:
            fields["include"] = body.include.model_dump()
        _apply_schedule(session, team_id, user_id, s, fields, now)
        bump_version(session, s)
        s.updated_by_user_id, s.last_updated = user_id, now
        session.add(s)
        audit(session, team_id=team_id, actor_type="user", actor_id=user_id, action="schedule.update",
              object_type="schedule", object_id=s.id, changed_fields=fields.keys())
        session.commit()
        session.refresh(s)
        return {"schedule": SCHED.public_schedule(s)}


@router.patch(SRC + "/schedules/{schedule_id}", dependencies=WRITE, summary="Edit, pause or resume a schedule")
async def update_schedule(team_id: TeamId, schedule_id: ObjectId, body: ScheduleUpdate, Authorization: AuthHeader = None):
    engine, user = await authorize(team_id, Authorization)
    return _ok(await _run("update schedule", team_id, _update_schedule, engine, team_id, user.id, schedule_id, body))


def _delete_schedule(engine, team_id: int, user_id: int, schedule_id: int) -> dict:
    with Session(engine) as session:
        s = _owned_schedule(session, team_id, schedule_id)
        require_owner_or_admin(session, user_id, team_id, s.owner_user_id, "schedule")
        audit(session, team_id=team_id, actor_type="user", actor_id=user_id, action="schedule.delete",
              object_type="schedule", object_id=s.id)
        session.delete(s)
        session.commit()
        log("schedule deleted", team=team_id, schedule=schedule_id, by=user_id)
        return {"deleted": schedule_id}


@router.delete(SRC + "/schedules/{schedule_id}", dependencies=WRITE, summary="Delete a schedule (its runs stay)")
async def delete_schedule(team_id: TeamId, schedule_id: ObjectId, Authorization: AuthHeader = None):
    engine, user = await authorize(team_id, Authorization)
    return _ok(await _run("delete schedule", team_id, _delete_schedule, engine, team_id, user.id, schedule_id))


# ============================================================================ remediation waves
def _waves_summary(items: list[dict]) -> dict:
    by_wave: dict[str, int] = {}
    for item in items:
        by_wave[str(item["wave"] or "none")] = by_wave.get(str(item["wave"] or "none"), 0) + 1
    return {"by_wave": by_wave, "labels": {str(k): v for k, v in WAVES.WAVE_LABEL.items()}}


def _run_remediation(engine, team_id: int, run_id: int) -> dict:
    with Session(engine) as session:
        run = _owned_run(session, team_id, run_id)
        items = WAVES.node_items(session, team_id, run)
        return {"run_id": run.id, "items": items, **_waves_summary(items)}


@router.get(SRC + "/runs/{run_id}/remediation", dependencies=READ,
            summary="Suggested and assigned remediation wave, owner and target date per asset of a run")
async def run_remediation(team_id: TeamId, run_id: ObjectId, Authorization: AuthHeader = None):
    engine, _user = await authorize(team_id, Authorization)
    return _ok(await _run("run remediation", team_id, _run_remediation, engine, team_id, run_id))


def _code_remediation(engine, team_id: int, scan_id: int) -> dict:
    with Session(engine) as session:
        scan = _code_scan(session, team_id, scan_id)
        items = WAVES.code_items(session, team_id, scan)
        return {"scan_id": scan.id, "items": items, **_waves_summary(items)}


@router.get(CODE + "/{scan_id}/remediation", dependencies=READ,
            summary="Suggested and assigned remediation wave, owner and target date per asset of a code scan")
async def code_remediation(team_id: TeamId, scan_id: ObjectId, Authorization: AuthHeader = None):
    engine, _user = await authorize(team_id, Authorization)
    return _ok(await _run("code remediation", team_id, _code_remediation, engine, team_id, scan_id))


def _put_remediation(engine, team_id: int, user_id: int, body: WAVES.AssignmentBulk) -> dict:
    now = utcnow()
    with Session(engine) as session:
        out = WAVES.upsert(session, team_id, user_id, body, now)
        if out["updated"]:
            audit(session, team_id=team_id, actor_type="user", actor_id=user_id, action="remediation.assign",
                  object_type="run" if body.run_id else "scan", object_id=body.run_id or body.scan_id,
                  changed_fields=sorted({f for i in body.items for f in i.model_fields_set if f != "asset_key"}))
        session.commit()
        log("remediation assigned", team=team_id, items=out["updated"], by=user_id)
        return out


@router.put("/{team_id}/cbom/remediation", dependencies=WRITE,
            summary="Assign wave, owner, target date, status or note to assets (bulk; fields left out are kept)")
async def put_remediation(team_id: TeamId, body: WAVES.AssignmentBulk, Authorization: AuthHeader = None):
    engine, user = await authorize(team_id, Authorization)
    return _ok(await _run("assign remediation", team_id, _put_remediation, engine, team_id, user.id, body))


# ============================================================================ SBOM link
def _asset_sbom(engine, team_id: int, asset_id: int) -> dict:
    with Session(engine) as session:
        row = session.get(CbomCollectedAsset, asset_id)
        if row is None or row.team_id != team_id:
            raise HTTPException(status_code=404, detail="Asset not found")
        if row.cdx_type != "library":
            return {"asset_id": row.id, "purl": None, "matches": []}
        facts = row.facts or {}
        name, version = str(facts.get("package") or facts.get("name") or row.name or ""), str(facts.get("version") or "")
        purl = SBOM.library_purl(name, version, SBOM.ecosystem_of(facts.get("ecosystem") or facts.get("language")))
        matches = SBOM.match(SBOM.sbom_index(session, team_id), name=name, version=version, purl=purl)
        return {"asset_id": row.id, "purl": purl or None, "matches": matches}


@router.get(SRC + "/assets/{asset_id}/sbom", dependencies=READ, summary="SBOM scans of the team that list this library")
async def asset_sbom(team_id: TeamId, asset_id: ObjectId, Authorization: AuthHeader = None):
    engine, _user = await authorize(team_id, Authorization)
    return _ok(await _run("asset sbom", team_id, _asset_sbom, engine, team_id, asset_id))


def _code_sbom(engine, team_id: int, scan_id: int) -> dict:
    with Session(engine) as session:
        scan = _code_scan(session, team_id, scan_id)
        data = scan.scan_data if isinstance(scan.scan_data, dict) else {}
        bom = SBOM.with_library_purls(data.get("cbom_json") if isinstance(data.get("cbom_json"), dict) else {})
        libs = [c for c in bom.get("components") or [] if isinstance(c, dict) and c.get("type") == "library"][:500]
        index = SBOM.sbom_index(session, team_id) if libs else []
        return {"scan_id": scan.id, "libraries": [
            {"bom_ref": c.get("bom-ref"), "name": c.get("name"), "version": c.get("version"), "purl": c.get("purl"),
             "matches": SBOM.match(index, name=str(c.get("name") or ""), version=str(c.get("version") or ""),
                                   purl=c.get("purl"))} for c in libs]}


@router.get(CODE + "/{scan_id}/sbom-links", dependencies=READ,
            summary="Library components of a CBOM scan with their purl and the SBOM scans that list them")
async def code_sbom(team_id: TeamId, scan_id: ObjectId, Authorization: AuthHeader = None):
    engine, _user = await authorize(team_id, Authorization)
    return _ok(await _run("code sbom", team_id, _code_sbom, engine, team_id, scan_id))
