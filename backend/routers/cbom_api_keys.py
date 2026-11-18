"""CBOM API keys of a team (issue #226): list, create (the secret is returned once), revoke.

These routes need a signed-in user (a JWT session): an API key can never list, create or revoke keys (a ``zsk_``
bearer is not a JWT, so it gets the session check's 401).  Members see the keys (never a secret or a hash); only
team admins create and revoke them (400 otherwise, never a 403, which signs the frontend out).  See
``backend/utilities/cbom_sources/api_keys.py`` for how a key is checked and ``docs/cbom/api-keys.md`` for the guide.
"""
from __future__ import annotations

import datetime as _dt
from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse
from pydantic import Field, field_validator
from sqlmodel import Session, select

from backend.get_db import get_db
from backend.new_models import User
from backend.utilities.auth.auth_utils import get_user_from_header_or_raise_exception
from backend.utilities.cbom_sources import api_keys as AK
from backend.utilities.cbom_sources.common import audit, log, sha256_hex, utcnow
from backend.utilities.cbom_sources import http as _cbom_http
from backend.utilities.rbac.policy import Access
from backend.utilities.cbom_sources.http import (PRIVATE, CbomRoute, ObjectId, TeamId, is_team_admin, read_limiter,
                                                 server_error, write_limiter)
from backend.utilities.cbom_sources.schemas import _Body, _name
from backend.utilities.team import check_if_user_is_in_team

router = APIRouter(tags=["cbom-api-keys"], route_class=CbomRoute)
access = Access(lambda: _cbom_http.get_db())  # route policies (utilities/rbac): the same database as authorize()
AuthHeader = Annotated[str | None, Header()]
BASE = "/{team_id}/cbom/api-keys"
ONLY_ADMINS = "Only a team admin can create or revoke API keys"


class KeyCreate(_Body):
    name: str = Field(min_length=1, max_length=64)
    scopes: list[str] = Field(min_length=1, max_length=len(AK.SCOPES))
    expires_in_days: int | None = Field(default=None, ge=1, le=AK.MAX_EXPIRY_DAYS)

    @field_validator("name")
    @classmethod
    def _n(cls, v: str) -> str:
        return _name(v)

    @field_validator("scopes")
    @classmethod
    def _s(cls, v: list[str]) -> list[str]:
        unknown = [s for s in v if s not in AK.SCOPES]
        if unknown:
            raise ValueError(f"unknown scope {unknown[0][:40]!r}; use {', '.join(AK.SCOPES)}")
        return sorted(set(v), key=list(AK.SCOPES).index)


async def _session_user(team_id: int, authorization: str | None):
    """A signed-in member of the team: a JWT session only, never an API key."""
    engine = get_db()
    user = await get_user_from_header_or_raise_exception(engine, authorization)
    await run_in_threadpool(check_if_user_is_in_team, user.id, team_id, engine)
    return engine, user


def _emails(session: Session, rows: list[AK.CbomApiKey]) -> dict[int, str]:
    ids = {r.created_by_user_id for r in rows}
    if not ids:
        return {}
    return {u.id: u.email for u in session.exec(select(User).where(User.id.in_(ids))).all()}  # type: ignore[union-attr]


def _list(engine, team_id: int, user_id: int) -> dict:
    now = utcnow()
    with Session(engine) as session:
        rows = session.exec(select(AK.CbomApiKey).where(AK.CbomApiKey.team_id == team_id)
                            .order_by(AK.CbomApiKey.id.desc())).all()  # type: ignore[union-attr]
        emails = _emails(session, list(rows))
        return {"api_keys": [AK.public_key(r, now, emails.get(r.created_by_user_id)) for r in rows],
                "scopes": [{"name": k, "description": v} for k, v in AK.SCOPES.items()],
                "can_manage": is_team_admin(session, user_id, team_id), "prefix": AK.PREFIX,
                "max_expiry_days": AK.MAX_EXPIRY_DAYS, "server_time": AK.iso_z(now)}


def _create(engine, team_id: int, user: User, body: KeyCreate) -> dict:
    now = utcnow()
    with Session(engine) as session:
        if not is_team_admin(session, user.id, team_id):
            raise HTTPException(status_code=400, detail=ONLY_ADMINS)
        live = [r for r in session.exec(select(AK.CbomApiKey).where(AK.CbomApiKey.team_id == team_id,
                                                                      AK.CbomApiKey.revoked_at.is_(None))).all()  # type: ignore[union-attr]
                if AK.status_of(r, now) == "active"]
        if len(live) >= AK.MAX_ACTIVE_KEYS:
            raise HTTPException(status_code=400,
                                detail=f"A team can have at most {AK.MAX_ACTIVE_KEYS} active API keys; revoke one first")
        secret = AK.new_secret()
        row = AK.CbomApiKey(team_id=team_id, name=body.name, scopes=body.scopes, key_hash=sha256_hex(secret),
                            hint=secret[-4:], created_by_user_id=user.id, created_at=now,
                            expires_at=now + _dt.timedelta(days=body.expires_in_days) if body.expires_in_days else None)
        session.add(row)
        session.flush()
        audit(session, team_id=team_id, actor_type="user", actor_id=user.id, action="api_key.create",
              object_type="api_key", object_id=row.id, changed_fields=["name", "scopes", "expires_at"])
        session.commit()
        session.refresh(row)
        log("api key created", team=team_id, key=row.id, scopes=",".join(body.scopes), by=user.id,
            expires=AK.iso_z(row.expires_at))
        return {"api_key": AK.public_key(row, now, user.email), "secret": secret}


def _revoke(engine, team_id: int, user: User, key_id: int) -> dict:
    now = utcnow()
    with Session(engine) as session:
        if not is_team_admin(session, user.id, team_id):
            raise HTTPException(status_code=400, detail=ONLY_ADMINS)
        row = session.get(AK.CbomApiKey, key_id)
        if row is None or row.team_id != team_id:
            raise HTTPException(status_code=404, detail="API key not found")
        if row.revoked_at is None:
            row.revoked_at, row.revoked_by_user_id = now, user.id
            session.add(row)
            audit(session, team_id=team_id, actor_type="user", actor_id=user.id, action="api_key.revoke",
                  object_type="api_key", object_id=row.id, changed_fields=["revoked_at"])
            session.commit()
            session.refresh(row)
            log("api key revoked", team=team_id, key=row.id, by=user.id)
        creator = session.get(User, row.created_by_user_id)
        return {"api_key": AK.public_key(row, now, creator.email if creator else None)}


async def _run(what: str, team_id: int, fn, *args):
    try:
        return await run_in_threadpool(fn, *args)
    except HTTPException:
        raise
    except Exception as exc:
        raise server_error(f"cbom api keys {what}", exc, team=team_id) from None


@router.get(BASE, dependencies=[Depends(read_limiter), access.team("cbom.read")],
            summary="The team's CBOM API keys (name, scopes, expiry, last use; never a secret)")
async def list_keys(team_id: TeamId, Authorization: AuthHeader = None):
    engine, user = await _session_user(team_id, Authorization)
    return JSONResponse(await _run("list", team_id, _list, engine, team_id, user.id), headers=PRIVATE)


@router.post(BASE, dependencies=[Depends(write_limiter), access.team("cbom.api_keys.manage")],
             summary="Create a CBOM API key (team admins; the secret is in this response only)")
async def create_key(team_id: TeamId, body: KeyCreate, Authorization: AuthHeader = None):
    engine, user = await _session_user(team_id, Authorization)
    return JSONResponse(await _run("create", team_id, _create, engine, team_id, user, body), status_code=201,
                        headers=PRIVATE)


@router.post(BASE + "/{key_id}/revoke", dependencies=[Depends(write_limiter), access.team("cbom.api_keys.manage")],
             summary="Revoke a CBOM API key (team admins; immediate, idempotent)")
async def revoke_key(team_id: TeamId, key_id: ObjectId, Authorization: AuthHeader = None):
    engine, user = await _session_user(team_id, Authorization)
    return JSONResponse(await _run("revoke", team_id, _revoke, engine, team_id, user, key_id), headers=PRIVATE)
