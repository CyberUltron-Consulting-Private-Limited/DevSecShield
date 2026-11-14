"""The team's estate store (CB-20): one row per cross-source asset key, its latest observation per source.

``GET /{team_id}/cbom/estate`` (keyset pages of at most 500, filters ``source`` / ``type`` / ``presence``) and
``GET /{team_id}/cbom/estate/{asset_key}`` (the asset and its observation per source). Same conventions as the other
CBOM routes (``backend/utilities/cbom_sources/http.py``): team members only, another team's or a missing key is a
404, validation errors are a 400 that never echoes input.
"""
from __future__ import annotations

from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Header, HTTPException, Path, Query
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse
from sqlmodel import Session

from backend.utilities.cbom_sources import estate as ESTATE
from backend.utilities.cbom_sources.http import PRIVATE, CbomRoute, TeamId, authorize, read_limiter, server_error

router = APIRouter(tags=["cbom-estate"], route_class=CbomRoute)
AuthHeader = Annotated[str | None, Header()]
READ = [Depends(read_limiter)]
KEY_PATTERN = r"^[a-z]{2,8}:[0-9a-f]{40}$"
AssetKey = Annotated[str, Path(min_length=10, max_length=64, pattern=KEY_PATTERN)]
MAX_PAGE = 500


async def _run(what: str, team_id: int, fn, *args, **kwargs):
    try:
        return await run_in_threadpool(fn, *args, **kwargs)
    except HTTPException:
        raise
    except Exception as exc:
        raise server_error(f"cbom estate {what}", exc, team=team_id) from None


def _list(engine, team_id: int, **kw) -> dict:
    with Session(engine) as session:
        return ESTATE.list_estate(session, team_id, **kw)


def _one(engine, team_id: int, asset_key: str) -> dict:
    with Session(engine) as session:
        out = ESTATE.get_estate_asset(session, team_id, asset_key)
    if out is None:
        raise HTTPException(status_code=404, detail="Asset not found")
    return out


@router.get("/{team_id}/cbom/estate", dependencies=READ,
            summary="The team's estate: one row per asset key with its presence and latest observation (keyset pages)")
async def list_estate(team_id: TeamId,
                      after: str | None = Query(default=None, max_length=64, pattern=KEY_PATTERN),
                      limit: int = Query(default=200, ge=1, le=MAX_PAGE),
                      source: str | None = Query(default=None, min_length=1, max_length=255),
                      type: str | None = Query(default=None, min_length=1, max_length=32,  # noqa: A002
                                               pattern=r"^[a-z0-9_]+$"),
                      presence: Literal["present", "not_read", "removed"] | None = Query(default=None),
                      Authorization: AuthHeader = None):
    engine, _user = await authorize(team_id, Authorization)
    payload = await _run("list", team_id, _list, engine, team_id, after=after, limit=limit, source=source,
                         asset_type=type, presence=presence)
    return JSONResponse(payload, headers=PRIVATE)


@router.get("/{team_id}/cbom/estate/{asset_key}", dependencies=READ,
            summary="One estate asset with its latest observation per source")
async def get_estate_asset(team_id: TeamId, asset_key: AssetKey, Authorization: AuthHeader = None):
    engine, _user = await authorize(team_id, Authorization)
    return JSONResponse(await _run("asset", team_id, _one, engine, team_id, asset_key), headers=PRIVATE)
