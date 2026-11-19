"""The team's report logo: the client logo every PDF export draws next to the ZeroShield logo (plan v2 section 5).

    PUT    /team/{team_id}/branding/logo   team.branding.manage (admin, audited)  raw image body, at most 2 MiB
    DELETE /team/{team_id}/branding/logo   team.branding.manage (admin, audited)  204, also when no logo was set
    GET    /team/{team_id}/branding        team.read (viewer)                     metadata, never the bytes
    GET    /team/{team_id}/branding/logo   team.read (viewer)                     the stored PNG

The upload is the raw image (not multipart): PNG, JPEG (MPO: its first picture) or WebP, with Content-Type
image/png, image/jpeg, image/webp, application/octet-stream or none; the magic bytes decide the format.  It is
decoded and normalised in the threadpool (``utilities/team/logo_image.py``): 413 over 2 MiB, 415 for another format or
a Content-Type that disagrees with the bytes, 422 for an image that cannot be a logo (too large, animated, fully
transparent, too narrow or too wide, too small, too detailed).  Only the normalised PNG is stored.

A change takes the team row lock, upserts (two first uploads at once never answer 500: the last one wins) and writes
its audit event (``team.branding.logo.set`` / ``team.branding.logo.removed``) in the same transaction.
"""
from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import Response
from sqlmodel import Session
from starlette.concurrency import run_in_threadpool

from backend.get_db import get_db
from backend.utilities.cbom_sources.common import frames, new_ref
from backend.utilities.cbom_sources.http import read_capped_body
from backend.utilities.ratelimit import RateLimiter
from backend.utilities.rbac import audit
from backend.utilities.rbac.policy import Access, request_meta
from backend.utilities.team import branding
from backend.utilities.team.logo_image import MAX_UPLOAD_BYTES, LogoError, NormalizedLogo, normalize_logo
from backend.utilities.team.roles import lock_team

router = APIRouter(tags=["team"])
# Per verified user, per worker; the same budgets as routers/team.py (team.read / team.write).
read_limiter = RateLimiter("team.branding.read", times=120, seconds=60)
write_limiter = RateLimiter("team.branding.write", times=20, seconds=60)
# Route policies (utilities/rbac): bound to this module's get_db, which the tests replace.
access = Access(lambda: get_db())

LOGO_PATH = "/team/{team_id}/branding/logo"
NO_LOGO = "No logo is set for this team"
log = logging.getLogger(__name__)


def _server_error(what: str, exc: BaseException, team_id: int) -> HTTPException:
    """A generic 500 with a ref; the log line has the ref, the exception class and its frames, never its message."""
    ref = new_ref()
    log.error("team branding %s FAILED ref=%s team=%s error=%s frames=%s", what, ref, team_id, type(exc).__name__,
              frames(exc))
    return HTTPException(status_code=500, detail=f"Something went wrong; please try again (ref {ref})")


def _audit_fields(request: Request) -> dict:
    meta = request_meta(request)
    return {"ip": meta["ip"], "user_agent": meta["user_agent"],
            **audit.actor_fields(request.state.access.principal)}


def _store(engine, team_id: int, logo: NormalizedLogo, user_id: int | None, fields: dict) -> dict:
    with Session(engine) as session:
        lock_team(session, team_id)
        metadata = branding.upsert_logo(session, team_id, logo, user_id=user_id)
        audit.record(session, action="team.branding.logo.set", team_id=team_id, object_type="team",
                     object_id=team_id, details={"sha256": logo.sha256, "bytes": logo.size_bytes, "w": logo.width,
                                                 "h": logo.height, "tone": logo.tone, "format_in": logo.format_in},
                     **fields)
        session.commit()
        return metadata


def _remove(engine, team_id: int, fields: dict) -> bool:
    with Session(engine) as session:
        lock_team(session, team_id)
        removed = branding.delete_logo(session, team_id)
        if removed is None:
            return False
        audit.record(session, action="team.branding.logo.removed", team_id=team_id, object_type="team",
                     object_id=team_id, details={"sha256": removed["sha256"], "bytes": removed["bytes"]}, **fields)
        session.commit()
        return True


@router.put(LOGO_PATH, summary="Set the team's report logo (admins; raw PNG, JPEG or WebP body, at most 2 MiB)",
            dependencies=[Depends(write_limiter), access.team("team.branding.manage")])
async def set_team_logo(team_id: int, request: Request):
    raw = await read_capped_body(request, MAX_UPLOAD_BYTES)  # 413 before the whole body is buffered
    try:
        logo = await run_in_threadpool(normalize_logo, raw, request.headers.get("content-type"))
    except LogoError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.message) from None
    principal = request.state.access.principal
    try:
        metadata = await run_in_threadpool(_store, get_db(), team_id, logo, principal.user_id, _audit_fields(request))
    except HTTPException:
        raise
    except Exception as exc:
        raise _server_error("set", exc, team_id) from None
    audit.mark_written(request)
    return metadata


@router.delete(LOGO_PATH, summary="Remove the team's report logo (admins; 204 also when none is set)",
               status_code=status.HTTP_204_NO_CONTENT, response_class=Response,
               dependencies=[Depends(write_limiter), access.team("team.branding.manage")])
async def remove_team_logo(team_id: int, request: Request) -> Response:
    try:
        removed = await run_in_threadpool(_remove, get_db(), team_id, _audit_fields(request))
    except HTTPException:
        raise
    except Exception as exc:
        raise _server_error("remove", exc, team_id) from None
    if removed:
        audit.mark_written(request)  # else the middleware's generic event closes the attempt
    return Response(status_code=status.HTTP_204_NO_CONTENT)


def _read(engine, reader, team_id: int):
    with Session(engine) as session:
        return reader(session, team_id)


@router.get("/team/{team_id}/branding", summary="The team's report logo: whether one is set, and its metadata",
            dependencies=[Depends(read_limiter), access.team("team.read")])
async def get_team_branding(team_id: int):
    return await run_in_threadpool(_read, get_db(), branding.branding_metadata, team_id)


@router.get(LOGO_PATH, summary="The team's report logo as PNG (404 when none is set)", response_class=Response,
            dependencies=[Depends(read_limiter), access.team("team.read")])
async def get_team_logo(team_id: int) -> Response:
    found = await run_in_threadpool(_read, get_db(), branding.logo_png, team_id)
    if found is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=NO_LOGO)
    png, sha256 = found
    return Response(content=png, media_type="image/png", headers={
        "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff", "ETag": f'"{sha256}"'})
