"""CBOM Sources ticketing (CB-38 PR-4): Jira issues for the findings of a run, and the team's Jira project for them.

Conventions of every CBOM Sources route (``backend/utilities/cbom_sources/http.py``): team members only (403 for
non-members), another team's or a missing run is a 404, team settings need a team admin (400, never 403), a stale form
gets a 409, validation errors are a 400 that never echoes input. Creating tickets is open to every team member, as on
the code-scan results page.
"""
from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, Header, HTTPException
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse
from sqlmodel import Session

from backend.new_models import Team
from backend.utilities.cbom_sources import run_tickets as TICKETS
from backend.utilities.cbom_sources.common import audit, log, utcnow
from backend.utilities.cbom_sources.http import (
    PRIVATE,
    CbomRoute,
    ObjectId,
    TeamId,
    authorize,
    bump_version,
    check_version,
    is_team_admin,
    read_limiter,
    require_admin,
    server_error,
    write_limiter,
)
from backend.utilities.cbom_sources.settings import get_or_create_settings

router = APIRouter(tags=["cbom-sources"], route_class=CbomRoute)
AuthHeader = Annotated[str | None, Header()]
READ = [Depends(read_limiter)]
WRITE = [Depends(write_limiter)]
BASE = "/{team_id}/cbom/sources"


async def _run(what: str, team_id: int, fn, *args) -> Any:
    try:
        return await run_in_threadpool(fn, *args)
    except HTTPException:
        raise
    except Exception as exc:
        raise server_error(f"cbom sources {what}", exc, team=team_id) from None


def _ok(payload: Any, status_code: int = 200) -> JSONResponse:
    return JSONResponse(payload, status_code=status_code, headers=PRIVATE)


def _get_ticketing(engine, team_id: int, user_id: int) -> dict:
    with Session(engine) as session:
        settings = get_or_create_settings(session, team_id)
        return {"ticketing": TICKETS.public_jira_settings(settings, session.get(Team, team_id),
                                                          is_admin=is_team_admin(session, user_id, team_id))}


@router.get(BASE + "/ticketing", dependencies=READ,
            summary="Jira for CBOM Sources: whether the team's Jira is connected, the project and the issue type")
async def get_ticketing(team_id: TeamId, Authorization: AuthHeader = None):
    engine, user = await authorize(team_id, Authorization)
    return _ok(await _run("get ticketing", team_id, _get_ticketing, engine, team_id, user.id))


def _put_ticketing(engine, team_id: int, user_id: int, body: TICKETS.JiraSettingsBody) -> dict:
    with Session(engine) as session:
        require_admin(session, user_id, team_id, "the Jira project for CBOM Sources")
        settings = get_or_create_settings(session, team_id)
        check_version(settings, body.expected_version)
        changed = sorted(f for f in ("jira_project_key", "jira_issue_type") if f in body.model_fields_set)
        is_team = session.get(Team, team_id)
        if not changed:  # nothing to save: no version bump, no audit row
            return {"ticketing": TICKETS.public_jira_settings(settings, is_team, is_admin=True)}
        for field in changed:
            setattr(settings, field, getattr(body, field))
        settings.updated_by_user_id, settings.last_updated = user_id, utcnow()
        bump_version(session, settings)
        session.add(settings)
        audit(session, team_id=team_id, actor_type="user", actor_id=user_id, action="settings.ticketing",
              object_type="settings", object_id=settings.id, changed_fields=changed)
        session.commit()
        session.refresh(settings)
        log("ticketing settings saved", team=team_id, by=user_id, fields=",".join(changed) or None)
        return {"ticketing": TICKETS.public_jira_settings(settings, session.get(Team, team_id), is_admin=True)}


@router.put(BASE + "/ticketing", dependencies=WRITE,
            summary="Set the Jira project and issue type for CBOM Sources tickets (team admin)")
async def put_ticketing(team_id: TeamId, body: TICKETS.JiraSettingsBody, Authorization: AuthHeader = None):
    engine, user = await authorize(team_id, Authorization)
    return _ok(await _run("put ticketing", team_id, _put_ticketing, engine, team_id, user.id, body))


@router.post(BASE + "/runs/{run_id}/tickets", dependencies=WRITE,
             summary="Open one Jira issue per finding asset of a run (idempotent per stable asset key)")
async def create_run_tickets(team_id: TeamId, run_id: ObjectId, body: TICKETS.TicketBody,
                             Authorization: AuthHeader = None):
    engine, user = await authorize(team_id, Authorization)
    return _ok(await _run("run tickets", team_id, TICKETS.create_tickets, engine, team_id, user.id, run_id, body))
