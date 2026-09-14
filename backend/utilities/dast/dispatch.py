"""Shared automatic-DAST dispatcher (scheduler, Run now, Jenkins)."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Literal, Optional

from fastapi import HTTPException, status
from sqlalchemy import update
from sqlalchemy.engine import Engine
from sqlmodel import Session, select

from backend.get_db import get_db
from backend.new_models import DastScanProfile, Scan
from backend.utilities.celery.celery_connection import get_celery_app
from backend.utilities.dast.auth_crypto import decrypt_auth, redact_auth
from backend.utilities.dast.credits import credits_for_auto_dast
from backend.utilities.dast.ssrf import DastSsrfError, assert_urls_allowed, host_from_url
from backend.utilities.team.credits import deduct_credits_from_team, refund_credits_to_team
from rich.console import Console

console = Console()

_INFLIGHT = {"pending", "started", "NOT_STARTED"}


@dataclass
class DispatchResult:
    status: Literal["started", "skipped_in_flight"]
    scan_id: Optional[int] = None
    task_id: Optional[str] = None
    credits: Optional[float] = None
    message: str = ""


def clear_inflight_for_scan(session: Session, scan_id: int) -> None:
    profiles = session.exec(
        select(DastScanProfile).where(DastScanProfile.inflight_scan_id == scan_id)
    ).all()
    for profile in profiles:
        profile.inflight_scan_id = None
        session.add(profile)


def _inflight_blocks(session: Session, profile: DastScanProfile) -> bool:
    if not profile.inflight_scan_id:
        return False
    scan = session.get(Scan, profile.inflight_scan_id)
    if scan is None:
        return False
    if scan.scan_status in ("success", "failure"):
        return False
    if scan.scan_status == "NOT_STARTED" and not scan.task_id:
        return False
    return scan.scan_status in _INFLIGHT


def run_dast_from_profile(
    profile_id: int,
    *,
    trigger: str,
    engine: Engine | None = None,
    target_url_override: str | None = None,
    owner_user_id: int | None = None,
    integration_settings: dict | None = None,
) -> DispatchResult:
    engine = engine or get_db()
    now = datetime.now(timezone.utc)

    with Session(engine) as session:
        query = select(DastScanProfile).where(DastScanProfile.id == profile_id)
        dialect_name = ""
        try:
            dialect_name = engine.dialect.name
        except Exception:
            pass
        if dialect_name == "postgresql":
            query = query.with_for_update(skip_locked=True)
        elif dialect_name and dialect_name != "sqlite":
            query = query.with_for_update()
        profile = session.exec(query).first()
        if profile is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="DAST profile not found")
        if not profile.consent_ok:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Written consent is required to run automatic DAST",
            )
        if _inflight_blocks(session, profile):
            return DispatchResult(status="skipped_in_flight", message="A DAST scan is already in flight for this profile")

        target_url = (target_url_override or profile.target_url or "").strip()
        allowed = list(profile.allowed_hosts or [])
        if not allowed and target_url:
            allowed = [host_from_url(target_url)]
        auth = decrypt_auth(profile.auth_encrypted or {})
        login_url = (auth.get("login_url") or "").strip()
        try:
            assert_urls_allowed([target_url, login_url], allowed)
        except DastSsrfError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

        credits = credits_for_auto_dast(profile.max_urls)
        owner = owner_user_id or profile.owner_user_id
        redacted_meta = {
            "target_url": target_url,
            "auth": redact_auth(auth),
            "scan_speed": profile.scan_speed,
            "max_urls": profile.max_urls,
            "additional_urls_to_scan": profile.additional_urls_to_scan,
            "exclude_url_patterns": profile.exclude_url_patterns,
            "include_url_patterns": profile.include_url_patterns,
            "profile_id": profile.id,
            "trigger": trigger,
        }
        scan = Scan(
            team_id=profile.team_id,
            owner_user_id=owner,
            scan_type="dast",
            title=f"{profile.title} ({trigger})",
            scan_status="NOT_STARTED",
            credit_consumed=credits,
            scan_metadata=redacted_meta,
            integration_settings=integration_settings or {},
        )
        session.add(scan)
        session.commit()
        session.refresh(scan)
        scan_id = scan.id
        team_id = profile.team_id
        max_urls = profile.max_urls
        scan_speed = profile.scan_speed
        extra = profile.additional_urls_to_scan
        exclude = profile.exclude_url_patterns
        include = profile.include_url_patterns
        profile_pk = profile.id

    claim = None
    with Session(engine) as session:
        claim = session.exec(
            update(Scan)
            .where(
                Scan.id == scan_id,
                Scan.team_id == team_id,
                Scan.scan_status == "NOT_STARTED",
                Scan.task_id == None,  # noqa: E711
            )
            .values(scan_status="pending")
        )
        session.commit()
        if claim.rowcount == 0:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Scan has already started or is not ready")

    try:
        deduct_credits_from_team(team_id=team_id, credits=credits)
    except Exception:
        with Session(engine) as session:
            session.exec(
                update(Scan)
                .where(Scan.id == scan_id, Scan.scan_status == "pending", Scan.task_id == None)  # noqa: E711
                .values(scan_status="NOT_STARTED")
            )
            session.commit()
        raise

    dast_dict_context = {
        "target_url": target_url,
        "auth": auth,
        "scan_speed": scan_speed,
        "max_urls": max_urls,
        "additional_urls_to_scan": extra,
        "exclude_url_patterns": exclude,
        "include_url_patterns": include,
    }
    try:
        simple_app = get_celery_app()
        if simple_app is None:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error in getting celery app")
        task_result = simple_app.send_task(
            name="dast_worker.dast",
            kwargs={"dast_dict_context": dast_dict_context},
            queue="dast_worker_queue",
        )
        task_id = task_result.id
        celery_state = str(simple_app.AsyncResult(task_id).state).lower()
    except Exception as exc:
        console.print(f"DAST auto dispatch failed, refunding {credits}: {exc}", style="bold yellow")
        try:
            refund_credits_to_team(team_id=team_id, credits=credits)
        except Exception:
            pass
        with Session(engine) as session:
            session.exec(
                update(Scan)
                .where(Scan.id == scan_id, Scan.scan_status == "pending", Scan.task_id == None)  # noqa: E711
                .values(scan_status="NOT_STARTED")
            )
            session.commit()
        raise

    with Session(engine) as session:
        scan = session.get(Scan, scan_id)
        scan.task_id = task_id
        scan.scan_status = celery_state if celery_state else "pending"
        scan.scan_metadata = redacted_meta
        session.add(scan)
        profile = session.get(DastScanProfile, profile_pk)
        profile.inflight_scan_id = scan_id
        profile.last_scan_id = scan_id
        profile.last_run_at = now
        profile.last_updated = now
        session.add(profile)
        session.commit()

    console.print(f"DAST auto-scan {scan_id} dispatched trigger={trigger} target={target_url}", style="bold green")
    return DispatchResult(status="started", scan_id=scan_id, task_id=task_id, credits=credits, message="started")
