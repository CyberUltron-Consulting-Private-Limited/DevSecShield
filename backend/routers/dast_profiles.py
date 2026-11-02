"""JWT-authenticated DAST profile CRUD + Run now."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException, status
from backend.utilities.ratelimit import RateLimiter
from rich.console import Console
from sqlmodel import Session, select

from backend.get_db import get_db
from backend.new_models import DastScanProfile
from backend.utilities.auth.auth_utils import get_user_from_header_or_raise_exception
from backend.utilities.dast.auth_crypto import decrypt_auth, encrypt_auth
from backend.utilities.dast.dispatch import run_dast_from_profile
from backend.utilities.dast.schedule import compute_next_run_at, mirror_from_config, normalize_schedule_config
from backend.utilities.dast.schemas import DastAuthWrite, DastProfileCreate, DastProfileUpdate
from backend.utilities.dast.serialize import public_profile
from backend.utilities.dast.ssrf import DastSsrfError, host_from_url
from backend.utilities.team import check_if_user_is_admin_of_team, check_if_user_is_in_team

console = Console()
router = APIRouter(tags=["dast-profiles"])
# Per verified user, per worker (backend/utilities/ratelimit.py).
read_limiter = RateLimiter("dast_profiles.read", times=120, seconds=60)
write_limiter = RateLimiter("dast_profiles.write", times=30, seconds=60)
start_limiter = RateLimiter("dast_profiles.run", times=10, seconds=60)


def _require_mutate(user, profile, engine) -> None:
    if user.id == profile.owner_user_id:
        return
    try:
        check_if_user_is_admin_of_team(user.id, profile.team_id, engine)
    except HTTPException:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only the profile owner or a team admin can change this profile",
        )


def _auth_from_write(auth: DastAuthWrite, existing: dict | None = None) -> dict:
    payload = auth.model_dump()
    if not payload.get("password"):
        if existing:
            decrypted = decrypt_auth(existing)
            payload["password"] = decrypted.get("password") or ""
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Password is required when creating a DAST profile",
            )
    if not payload.get("password"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password is required when creating a DAST profile",
        )
    return encrypt_auth(payload)


def _config_from_body(schedule_kind, schedule_time, schedule_weekday, schedule_config) -> dict:
    cfg = schedule_config.model_dump() if schedule_config is not None else {}
    if schedule_kind and not cfg.get("kind"):
        cfg["kind"] = schedule_kind
    if schedule_time and not cfg.get("times"):
        cfg["times"] = [schedule_time]
    if schedule_weekday is not None and cfg.get("weekday") is None:
        cfg["weekday"] = schedule_weekday
    return normalize_schedule_config(schedule_kind, schedule_time, schedule_weekday, cfg)


def _apply_schedule(profile: DastScanProfile, extra_config: dict | None = None) -> None:
    cfg = normalize_schedule_config(
        profile.schedule_kind,
        profile.schedule_time,
        profile.schedule_weekday,
        extra_config if extra_config is not None else profile.schedule_config,
    )
    kind, time_s, weekday = mirror_from_config(cfg)
    profile.schedule_config = cfg
    profile.schedule_kind = kind
    profile.schedule_time = time_s
    profile.schedule_weekday = weekday
    profile.next_run_at = compute_next_run_at(kind, time_s, weekday, config=cfg)


def _default_hosts(target_url: str, allowed_hosts: list[str] | None) -> list[str]:
    if allowed_hosts:
        return [h.strip().lower() for h in allowed_hosts if h and h.strip()]
    try:
        return [host_from_url(target_url)]
    except DastSsrfError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@router.get("/{team_id}/dast/profiles", summary="List DAST profiles for a team", dependencies=[Depends(read_limiter)])
async def list_dast_profiles(
    team_id: int,
    Authorization: Annotated[str | None, Header()] = None,
):
    engine = get_db()
    user = await get_user_from_header_or_raise_exception(engine, Authorization)
    check_if_user_is_in_team(user.id, team_id, engine)
    with Session(engine) as session:
        rows = session.exec(
            select(DastScanProfile).where(DastScanProfile.team_id == team_id)
        ).all()
        return {"profiles": [public_profile(row) for row in rows]}


@router.post("/{team_id}/dast/profiles", summary="Create a DAST profile", dependencies=[Depends(write_limiter)])
async def create_dast_profile(
    team_id: int,
    body: DastProfileCreate,
    Authorization: Annotated[str | None, Header()] = None,
):
    engine = get_db()
    user = await get_user_from_header_or_raise_exception(engine, Authorization)
    check_if_user_is_in_team(user.id, team_id, engine)
    now = datetime.now(timezone.utc)
    profile = DastScanProfile(
        team_id=team_id,
        owner_user_id=user.id,
        title=body.title,
        enabled=body.enabled,
        target_url=body.target_url.strip(),
        allowed_hosts=_default_hosts(body.target_url, body.allowed_hosts),
        auth_encrypted=_auth_from_write(body.auth),
        scan_speed=body.scan_speed,
        max_urls=body.max_urls,
        additional_urls_to_scan=body.additional_urls_to_scan,
        exclude_url_patterns=body.exclude_url_patterns,
        include_url_patterns=body.include_url_patterns,
        schedule_kind=body.schedule_kind,
        schedule_time=body.schedule_time,
        schedule_weekday=body.schedule_weekday,
        schedule_config=_config_from_body(
            body.schedule_kind,
            body.schedule_time,
            body.schedule_weekday,
            body.schedule_config,
        ),
        consent_ok=body.consent_ok,
        created_at=now,
        last_updated=now,
    )
    _apply_schedule(profile)
    with Session(engine) as session:
        session.add(profile)
        session.commit()
        session.refresh(profile)
        return public_profile(profile)


@router.get("/{team_id}/dast/profiles/{profile_id}", summary="Get a DAST profile", dependencies=[Depends(read_limiter)])
async def get_dast_profile(
    team_id: int,
    profile_id: int,
    Authorization: Annotated[str | None, Header()] = None,
):
    engine = get_db()
    user = await get_user_from_header_or_raise_exception(engine, Authorization)
    check_if_user_is_in_team(user.id, team_id, engine)
    with Session(engine) as session:
        profile = session.exec(
            select(DastScanProfile).where(
                DastScanProfile.id == profile_id,
                DastScanProfile.team_id == team_id,
            )
        ).first()
        if profile is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="DAST profile not found")
        return public_profile(profile)


@router.put("/{team_id}/dast/profiles/{profile_id}", summary="Update a DAST profile", dependencies=[Depends(write_limiter)])
async def update_dast_profile(
    team_id: int,
    profile_id: int,
    body: DastProfileUpdate,
    Authorization: Annotated[str | None, Header()] = None,
):
    engine = get_db()
    user = await get_user_from_header_or_raise_exception(engine, Authorization)
    check_if_user_is_in_team(user.id, team_id, engine)
    with Session(engine) as session:
        profile = session.exec(
            select(DastScanProfile).where(
                DastScanProfile.id == profile_id,
                DastScanProfile.team_id == team_id,
            )
        ).first()
        if profile is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="DAST profile not found")
        _require_mutate(user, profile, engine)
        data = body.model_dump(exclude_unset=True)
        if "auth" in data:
            auth_write = body.auth
            if auth_write is None:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="auth cannot be null")
            profile.auth_encrypted = _auth_from_write(auth_write, profile.auth_encrypted)
            data.pop("auth")
        if "target_url" in data and data["target_url"]:
            profile.target_url = data["target_url"].strip()
            data.pop("target_url")
        if "allowed_hosts" in data:
            profile.allowed_hosts = _default_hosts(profile.target_url, data["allowed_hosts"])
            data.pop("allowed_hosts")
        extra_config = None
        if "schedule_config" in data:
            extra_config = _config_from_body(
                data.get("schedule_kind", profile.schedule_kind),
                data.get("schedule_time", profile.schedule_time),
                data.get("schedule_weekday", profile.schedule_weekday),
                body.schedule_config,
            )
            data.pop("schedule_config")
        for key, value in data.items():
            setattr(profile, key, value)
        _apply_schedule(profile, extra_config)
        profile.last_updated = datetime.now(timezone.utc)
        session.add(profile)
        session.commit()
        session.refresh(profile)
        return public_profile(profile)


@router.delete("/{team_id}/dast/profiles/{profile_id}", summary="Delete a DAST profile", dependencies=[Depends(write_limiter)])
async def delete_dast_profile(
    team_id: int,
    profile_id: int,
    Authorization: Annotated[str | None, Header()] = None,
):
    engine = get_db()
    user = await get_user_from_header_or_raise_exception(engine, Authorization)
    check_if_user_is_in_team(user.id, team_id, engine)
    with Session(engine) as session:
        profile = session.exec(
            select(DastScanProfile).where(
                DastScanProfile.id == profile_id,
                DastScanProfile.team_id == team_id,
            )
        ).first()
        if profile is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="DAST profile not found")
        _require_mutate(user, profile, engine)
        session.delete(profile)
        session.commit()
    return {"ok": True, "deleted_id": profile_id}


@router.post("/{team_id}/dast/profiles/{profile_id}/run", summary="Run a DAST profile now", dependencies=[Depends(start_limiter)])
async def run_dast_profile_now(
    team_id: int,
    profile_id: int,
    Authorization: Annotated[str | None, Header()] = None,
):
    engine = get_db()
    user = await get_user_from_header_or_raise_exception(engine, Authorization)
    check_if_user_is_in_team(user.id, team_id, engine)
    with Session(engine) as session:
        profile = session.exec(
            select(DastScanProfile).where(
                DastScanProfile.id == profile_id,
                DastScanProfile.team_id == team_id,
            )
        ).first()
        if profile is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="DAST profile not found")
        _require_mutate(user, profile, engine)
    result = run_dast_from_profile(
        profile_id,
        trigger="manual",
        engine=engine,
        owner_user_id=user.id,
    )
    if result.status == "skipped_in_flight":
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=result.message)
    return {
        "status": result.status,
        "scan_id": result.scan_id,
        "task_id": result.task_id,
        "credits": result.credits,
        "message": result.message,
    }
