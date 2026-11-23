"""Ticketing in Settings > Integrations (SOW S2): Jira next to ServiceNow, and "Raise test ticket" for both.

Conventions of the integrations API (``routers/integrations.py``): team members read (403 for non-members); a change
needs a team admin (400, never 403); validation errors are a 400 that never echoes input; a stale form gets 409.
Secrets are write-only (the Jira API token is stored encrypted and never returned; ``api_token_set`` says whether one
is stored). Included in the app BEFORE the generic ``/{team_id}/integrations/{kind}`` routes.

Jira's connection is the team's Jira (``team.integration_settings["jira"]``), the one code-scan and CBOM Sources
tickets use; its project and issue type are the CBOM Sources ticketing settings. So the card configures, in one place,
everything a CBOM ticket needs.

``POST /{team_id}/integrations/{kind}/test-ticket`` (``jira`` or ``servicenow``) with ``{"click_id": <uuid>}`` raises
one clearly labelled test ticket and returns its key and link. It is idempotent per click: the click is claimed in
``integrationtestticket`` (unique per team, kind and click) before anything is sent; the same click again returns the
same ticket, a click still in flight gets 409, and a click whose outcome is unknown (timeout) is retried with a lookup
first (Jira: by label; ServiceNow: by correlation id), so it never makes a second ticket.
"""
from __future__ import annotations

import datetime as dt
import re
import uuid
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, Header, HTTPException, Query
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator
from sqlalchemy.exc import IntegrityError
from sqlmodel import Session, select

from backend.cbom_gate_models import IntegrationTestTicket
from backend.new_models import Team, TeamIntegration
from backend.utilities.cbom_sources import http as _cbom_http
from backend.utilities.cbom_sources import run_tickets as TICKETS
from backend.utilities.cbom_sources.common import audit, iso_z, log, utcnow
from backend.utilities.cbom_sources.http import (
    PRIVATE,
    CbomRoute,
    TeamId,
    authorize,
    bad_request,
    bump_version,
    check_version,
    is_team_admin,
    read_limiter,
    require_admin,
    server_error,
    write_limiter,
)
from backend.utilities.cbom_sources.kinds import check_http_url
from backend.utilities.cbom_sources.settings import get_or_create_settings
from backend.utilities.db.encryption import decrypt_if_encrypted, prepare_secret_for_storage
from backend.utilities.integrations import jira as JIRA
from backend.utilities.integrations import jira_test as JT
from backend.utilities.integrations import servicenow as SN
from backend.utilities.integrations.dispatch import context_for
from backend.utilities.integrations.registry import SPECS
from backend.utilities.rbac.policy import Access

router = APIRouter(tags=["integrations"], route_class=CbomRoute)
access = Access(lambda: _cbom_http.get_db())
AuthHeader = Annotated[str | None, Header()]
READ = [Depends(read_limiter)]
WRITE = [Depends(write_limiter)]
BASE = "/{team_id}/integrations"
# A claimed click older than this is taken as abandoned (a worker restart) and may be retried. It must outlast the
# slowest attempt: a retried Jira click makes up to three calls (search/jql, the /search fallback, create), each bounded
# by jira.REQUEST_TIMEOUT (5 s connect + 30 s read), so 3 x 35 = 105 s; doubled for headroom and Jira's eventually
# consistent search: 210 s.
IN_FLIGHT_S = 2 * 3 * sum(JIRA.REQUEST_TIMEOUT)
_EMAIL = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,190}\.[^@\s]{1,63}$")
_CTRL = re.compile(r"[\x00-\x1f\x7f]")


async def _run(what: str, team_id: int, fn, *args) -> Any:
    try:
        return await run_in_threadpool(fn, *args)
    except HTTPException:
        raise
    except Exception as exc:
        raise server_error(f"integrations {what}", exc, team=team_id) from None


def _ok(payload: Any) -> JSONResponse:
    return JSONResponse(payload, headers=PRIVATE)


# ============================================================================ Jira connection
class JiraSave(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    url: str = Field(min_length=1, max_length=500)
    email: str = Field(min_length=3, max_length=254)
    api_token: str | None = Field(default=None, max_length=4096)
    project_key: str | None = Field(default=None, max_length=32)
    issue_type: str | None = Field(default=None, max_length=64)
    expected_version: int | None = Field(default=None, ge=1)

    @field_validator("url")
    @classmethod
    def _url(cls, v: str) -> str:
        text = check_http_url(v, https_only=True)
        if not text:
            raise ValueError("enter the https:// address of your Jira site, e.g. https://bank.atlassian.net")
        return text.rstrip("/")

    @field_validator("email")
    @classmethod
    def _email(cls, v: str) -> str:
        if not _EMAIL.match(v):
            raise ValueError("enter the email of the Jira account")
        return v

    @field_validator("api_token")
    @classmethod
    def _token(cls, v: str | None) -> str | None:
        if v is not None and _CTRL.search(v):
            raise ValueError("printable characters only")
        return v or None


def _jira_stored(team: Team | None) -> dict[str, Any]:
    jira = ((team.integration_settings or {}) if team is not None else {}).get("jira")
    return jira if isinstance(jira, dict) else {}


def _public_jira(session: Session, team_id: int, user_id: int) -> dict[str, Any]:
    team = session.get(Team, team_id)
    stored = _jira_stored(team)
    settings = get_or_create_settings(session, team_id)
    last = stored.get("last_test") if isinstance(stored.get("last_test"), dict) else None
    return {
        "kind": "jira", "label": "Jira",
        "configured": bool(stored.get("url") and stored.get("email") and stored.get("api_token")),
        "url": stored.get("url") or None, "email": stored.get("email") or None,
        "api_token_set": bool(stored.get("api_token")),
        "project_key": settings.jira_project_key, "issue_type": settings.jira_issue_type or TICKETS.DEFAULT_ISSUE_TYPE,
        "issue_type_default": TICKETS.DEFAULT_ISSUE_TYPE, "row_version": settings.row_version,
        "last_test": last, "last_test_ticket": _last_ticket(session, team_id, "jira"),
        "is_admin": is_team_admin(session, user_id, team_id),
    }


def _get_jira(engine, team_id: int, user_id: int) -> dict:
    with Session(engine) as session:
        out = _public_jira(session, team_id, user_id)
        session.commit()  # get_or_create_settings may have created the team's settings row
        return {"jira": out}


@router.get(BASE + "/jira", dependencies=[*READ, access.team("integrations.read")],
            summary="The team's Jira: site, account, whether a token is stored, CBOM project (never the token)")
async def get_jira(team_id: TeamId, Authorization: AuthHeader = None):
    engine, user = await authorize(team_id, Authorization)
    return _ok(await _run("jira get", team_id, _get_jira, engine, team_id, user.id))


def _save_jira(engine, team_id: int, user_id: int, body: JiraSave) -> dict:
    try:
        ticketing = TICKETS.JiraSettingsBody(jira_project_key=body.project_key, jira_issue_type=body.issue_type)
    except ValidationError as exc:
        raise bad_request(exc) from None
    with Session(engine) as session:
        require_admin(session, user_id, team_id, "the Jira integration")
        team = session.get(Team, team_id)
        if team is None:
            raise HTTPException(status_code=404, detail="Team not found")
        settings = get_or_create_settings(session, team_id)
        check_version(settings, body.expected_version)
        stored = _jira_stored(team)
        moved = (stored.get("url") or "") != body.url or (stored.get("email") or "") != body.email
        if not body.api_token:
            if not stored.get("api_token"):
                raise HTTPException(status_code=400, detail="api_token: enter the Jira API token")
            if moved:
                raise HTTPException(status_code=400, detail="api_token: re-enter the Jira API token; a stored token is "
                                                            "never sent to a changed Jira URL or account")
        changed = [f for f, new in (("url", body.url), ("email", body.email)) if (stored.get(f) or "") != new]
        if body.api_token:
            changed.append("api_token")
        jira = {"email": body.email, "url": body.url,
                "api_token": prepare_secret_for_storage(body.api_token, stored.get("api_token"))}
        if not changed and isinstance(stored.get("last_test"), dict):
            jira["last_test"] = stored["last_test"]  # nothing about the connection changed: the last test still holds
        team.integration_settings = {**(team.integration_settings or {}), "jira": jira}
        session.add(team)
        ticket_changed = [f for f in ("jira_project_key", "jira_issue_type")
                          if getattr(settings, f) != getattr(ticketing, f)]
        if ticket_changed:
            for field in ticket_changed:
                setattr(settings, field, getattr(ticketing, field))
            settings.updated_by_user_id, settings.last_updated = user_id, utcnow()
            bump_version(session, settings)
            session.add(settings)
        audit(session, team_id=team_id, actor_type="user", actor_id=user_id, action="integration.save",
              object_type="integration", object_id=None, changed_fields=["jira." + f for f in changed + ticket_changed])
        session.commit()
        log("integration saved", team=team_id, kind="jira", by=user_id, fields=len(changed) + len(ticket_changed))
        return {"jira": _public_jira(session, team_id, user_id)}


@router.put(BASE + "/jira", dependencies=[*WRITE, access.team("team.integrations.manage")],
            summary="Connect Jira and set the CBOM project (admin; the API token is write-only)")
async def save_jira(team_id: TeamId, body: JiraSave, Authorization: AuthHeader = None):
    engine, user = await authorize(team_id, Authorization)
    return _ok(await _run("jira save", team_id, _save_jira, engine, team_id, user.id, body))


def _delete_jira(engine, team_id: int, user_id: int) -> dict:
    with Session(engine) as session:
        require_admin(session, user_id, team_id, "the Jira integration")
        team = session.get(Team, team_id)
        if team is None or not _jira_stored(team):
            raise HTTPException(status_code=404, detail="Jira is not connected")
        team.integration_settings = {**(team.integration_settings or {}), "jira": None}  # as the team settings did
        session.add(team)
        audit(session, team_id=team_id, actor_type="user", actor_id=user_id, action="integration.delete",
              object_type="integration", object_id=None, changed_fields=["jira"])
        session.commit()
        log("integration deleted", team=team_id, kind="jira", by=user_id)
        return {"deleted": "jira"}


@router.delete(BASE + "/jira", dependencies=[*WRITE, access.team("team.integrations.manage")],
               summary="Disconnect Jira (admin): the stored token is removed")
async def delete_jira(team_id: TeamId, Authorization: AuthHeader = None):
    engine, user = await authorize(team_id, Authorization)
    return _ok(await _run("jira delete", team_id, _delete_jira, engine, team_id, user.id))


def _jira_target(session: Session, team_id: int) -> tuple[str, str, str, str | None, str]:
    """(url, email, token, project, issue type) of a connected Jira, or a 400 saying what is missing."""
    stored = _jira_stored(session.get(Team, team_id))
    token = decrypt_if_encrypted(stored.get("api_token")) if stored.get("api_token") else ""
    if not (stored.get("url") and stored.get("email") and token):
        raise HTTPException(status_code=400, detail="Save the Jira URL, email and API token first")
    settings = get_or_create_settings(session, team_id)
    return (stored["url"], stored["email"], token, settings.jira_project_key,
            settings.jira_issue_type or TICKETS.DEFAULT_ISSUE_TYPE)


def _test_jira(engine, team_id: int, user_id: int) -> dict:
    with Session(engine) as session:
        require_admin(session, user_id, team_id, "the Jira integration")
        url, email, token, project, _issue_type = _jira_target(session, team_id)
    result = JT.connection_test(url, email, token, project)
    now = utcnow()
    status = "ok" if result.status == "ok" else "failed"
    with Session(engine) as session:
        team = session.get(Team, team_id)
        stored = _jira_stored(team)
        if team is not None and stored:
            team.integration_settings = {**(team.integration_settings or {}), "jira": {
                **stored, "last_test": {"status": status, "at": iso_z(now), "message": result.message[:255]}}}
            session.add(team)
        audit(session, team_id=team_id, actor_type="user", actor_id=user_id, action="integration.test",
              object_type="integration", object_id=None, changed_fields=["jira.last_test"])
        session.commit()
    log("integration tested", team=team_id, kind="jira", by=user_id, ok=status == "ok")
    return {"ok": status == "ok", "confirmed": status == "ok", "status": status, "message": result.message,
            "at": iso_z(now)}


@router.post(BASE + "/jira/test", dependencies=[*WRITE, access.team("team.integrations.manage")],
             summary="Sign in to Jira and check the CBOM project is visible; creates nothing (admin)")
async def test_jira(team_id: TeamId, Authorization: AuthHeader = None):
    engine, user = await authorize(team_id, Authorization)
    return _ok(await _run("jira test", team_id, _test_jira, engine, team_id, user.id))


# ============================================================================ test tickets
class TestTicketBody(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    click_id: str = Field(min_length=36, max_length=36)

    @field_validator("click_id")
    @classmethod
    def _uuid(cls, v: str) -> str:
        try:
            return str(uuid.UUID(v))
        except ValueError:
            raise ValueError("a UUID made by the page for this click") from None


def _public_ticket(row: IntegrationTestTicket | None) -> dict[str, Any] | None:
    if row is None:
        return None
    return {"kind": row.kind, "status": row.status, "ticket_key": row.ticket_key, "ticket_url": row.ticket_url,
            "message": row.message, "at": iso_z(row.updated_at), "click_id": row.click_id}


def _last_ticket(session: Session, team_id: int, kind: str) -> dict[str, Any] | None:
    row = session.exec(select(IntegrationTestTicket).where(
        IntegrationTestTicket.team_id == team_id, IntegrationTestTicket.kind == kind,
        IntegrationTestTicket.status == "created").order_by(IntegrationTestTicket.id.desc())).first()  # type: ignore[union-attr]
    return _public_ticket(row)


def _claim(engine, team_id: int, user_id: int, kind: str, click_id: str) -> tuple[str, dict | None]:
    """("new" | "retry", None) when this request must raise the ticket, or ("done", answer) for a finished click."""
    now = utcnow()
    for _ in range(2):
        with Session(engine) as session:
            require_admin(session, user_id, team_id, "integrations")
            row = session.exec(select(IntegrationTestTicket).where(
                IntegrationTestTicket.team_id == team_id, IntegrationTestTicket.kind == kind,
                IntegrationTestTicket.click_id == click_id)).first()
            if row is None:
                session.add(IntegrationTestTicket(team_id=team_id, kind=kind, click_id=click_id, status="pending",
                                                  created_at=now, updated_at=now, user_id=user_id))
                try:
                    session.commit()
                    return "new", None
                except IntegrityError:  # the same click arrived twice at once: read the other request's claim
                    session.rollback()
                    continue
            if row.status == "created":
                return "done", {**(_public_ticket(row) or {}), "ok": True, "repeated": True,
                                "message": f"Already raised for this click: {row.ticket_key}"}
            if row.status == "pending" and (now - row.updated_at) < dt.timedelta(seconds=IN_FLIGHT_S):
                raise HTTPException(status_code=409, detail="This test ticket is still being raised. Wait a moment.")
            row.status, row.updated_at = "pending", now
            session.add(row)
            session.commit()
            return "retry", None
    raise HTTPException(status_code=409, detail="This test ticket is still being raised. Wait a moment.")


def _raise(engine, team_id: int, user_id: int, kind: str, click_id: str, search_first: bool):
    """(status, key, url, message) from the connector. Configuration problems are a 400 before anything is sent."""
    if kind == "jira":
        with Session(engine) as session:
            url, email, token, project, issue_type = _jira_target(session, team_id)
        if not project:
            raise HTTPException(status_code=400, detail="Set the Jira project for CBOM tickets, save, then raise a "
                                                        "test ticket")
        result = JT.raise_test_ticket(url, email, token, project, issue_type, team_id, click_id,
                                      search_first=search_first)
        return result.status, result.key, result.url, result.message
    with Session(engine) as session:
        row = session.exec(select(TeamIntegration).where(TeamIntegration.team_id == team_id,
                                                         TeamIntegration.kind == "servicenow")).first()
        if row is None:
            raise HTTPException(status_code=400, detail="Save the ServiceNow integration first")
        try:
            ctx = context_for(row, engine)
        except (ValidationError, ValueError) as exc:
            raise bad_request(exc) from None
        missing = sorted(SPECS["servicenow"].secret_fields(ctx.config) - set(ctx.secrets))
        if missing:
            raise HTTPException(status_code=400, detail=f"secrets.{missing[0]}: required before raising a test ticket")
    outcome, link = SN.raise_test_ticket(ctx, click_id)
    return ("ok" if outcome.status == "ok" else "failed"), outcome.ref, link, outcome.reason


def _test_ticket(engine, team_id: int, user_id: int, kind: str, body: TestTicketBody) -> dict:
    state, answer = _claim(engine, team_id, user_id, kind, body.click_id)
    if state == "done":
        return answer or {}
    try:
        status, key, link, message = _raise(engine, team_id, user_id, kind, body.click_id, state == "retry")
    except HTTPException:
        with Session(engine) as session:  # nothing was sent: release the claim so the next click starts clean
            row = session.exec(select(IntegrationTestTicket).where(
                IntegrationTestTicket.team_id == team_id, IntegrationTestTicket.kind == kind,
                IntegrationTestTicket.click_id == body.click_id)).first()
            if row is not None:
                session.delete(row)
                session.commit()
        raise
    except Exception as exc:  # a connector bug: the outcome is unknown, the next try of this click looks up first
        status, key, link, message = "uncertain", None, None, f"the test ticket could not be raised ({type(exc).__name__})"
    now = utcnow()
    final = "created" if status == "ok" and key else ("uncertain" if status in ("uncertain", "ok") else "failed")
    with Session(engine) as session:
        row = session.exec(select(IntegrationTestTicket).where(
            IntegrationTestTicket.team_id == team_id, IntegrationTestTicket.kind == kind,
            IntegrationTestTicket.click_id == body.click_id)).one()
        row.status, row.ticket_key, row.ticket_url = final, key, link
        row.message, row.updated_at = (message or "")[:255], now
        session.add(row)
        audit(session, team_id=team_id, actor_type="user", actor_id=user_id, action="integration.test_ticket",
              object_type="integration", object_id=row.id, changed_fields=[f"{kind}.{final}"])
        session.commit()
        session.refresh(row)
        out = _public_ticket(row) or {}
    log("integration test ticket", team=team_id, kind=kind, by=user_id, status=final, ticket=key)
    return {**out, "ok": final == "created", "repeated": False}


@router.post(BASE + "/{kind}/test-ticket", dependencies=[*WRITE, access.team("team.integrations.manage")],
             summary="Raise one clearly labelled test ticket in Jira or ServiceNow and return its key and link (admin; "
                     "idempotent per click_id)")
async def raise_test_ticket(team_id: TeamId, kind: Literal["jira", "servicenow"], body: TestTicketBody,
                            Authorization: AuthHeader = None):
    engine, user = await authorize(team_id, Authorization)
    return _ok(await _run("test ticket", team_id, _test_ticket, engine, team_id, user.id, kind, body))


def _list_tickets(engine, team_id: int, kind: str | None) -> dict:
    with Session(engine) as session:
        query = select(IntegrationTestTicket).where(IntegrationTestTicket.team_id == team_id)
        if kind:
            query = query.where(IntegrationTestTicket.kind == kind)
        rows = session.exec(query.order_by(IntegrationTestTicket.id.desc()).limit(20)).all()  # type: ignore[union-attr]
        return {"test_tickets": [_public_ticket(r) for r in rows]}


@router.get(BASE + "/test-tickets", dependencies=[*READ, access.team("integrations.read")],
            summary="The team's latest test tickets (Jira and ServiceNow), newest first")
async def list_test_tickets(team_id: TeamId, kind: Literal["jira", "servicenow"] | None = Query(default=None),
                            Authorization: AuthHeader = None):
    engine, _user = await authorize(team_id, Authorization)
    return _ok(await _run("test tickets", team_id, _list_tickets, engine, team_id, kind))
