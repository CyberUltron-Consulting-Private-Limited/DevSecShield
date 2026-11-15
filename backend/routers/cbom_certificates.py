"""Orphaned and unmanaged certificates of the team's estate (diagram output 04): ``GET /{team_id}/cbom/certificates/
hygiene`` (keyset pages, filters ``flag`` / ``source`` / ``q`` / ``all`` / ``stale_runs``) and ``.../hygiene.csv``
(every selected row). Read-only, team-scoped, computed from the estate store (``cert_hygiene``)."""
from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, Header, HTTPException, Query
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse, StreamingResponse
from sqlmodel import Session

from backend.utilities.cbom_sources import cert_hygiene as HYG
from backend.utilities.cbom_sources.common import utcnow
from backend.utilities.cbom_sources import http as _cbom_http
from backend.utilities.rbac.policy import Access
from backend.utilities.cbom_sources.http import PRIVATE, CbomRoute, TeamId, authorize, read_limiter, server_error

router = APIRouter(tags=["cbom-certificates"], route_class=CbomRoute)
access = Access(lambda: _cbom_http.get_db())  # route policies (utilities/rbac): the same database as authorize()
AuthHeader = Annotated[str | None, Header()]
READ = [Depends(read_limiter)]
FlagQ = Query(default=None, pattern="^(" + "|".join(HYG.FLAGS) + ")$")
SourceQ = Query(default=None, max_length=255)
TextQ = Query(default=None, max_length=128)
StaleQ = Query(default=HYG.STALE_RUNS, ge=1, le=100)


async def _call(what: str, team_id: int, fn, *args) -> Any:
    try:
        return await run_in_threadpool(fn, *args)
    except HTTPException:
        raise
    except Exception as exc:
        raise server_error(f"cbom certificates {what}", exc, team=team_id) from None


def _view(engine, team_id: int, stale_runs: int) -> HYG.View:
    with Session(engine) as session:
        return HYG.cached(session, team_id, stale_runs=stale_runs)


def _page(engine, team_id: int, stale_runs: int, filters: dict[str, Any], after: str | None, limit: int) -> dict:
    return HYG.page(_view(engine, team_id, stale_runs), **filters, after=after, limit=limit)


@router.get("/{team_id}/cbom/certificates/hygiene", dependencies=[*READ, access.team("cbom.read")],
            summary="Orphaned and unmanaged certificates of the estate: flags per certificate, keyset pages")
async def certificate_hygiene(team_id: TeamId, flag: str | None = FlagQ, source: str | None = SourceQ,
                              q: str | None = TextQ, all: bool = False, stale_runs: int = StaleQ,
                              after: str | None = Query(default=None, max_length=512),
                              limit: int = Query(default=100, ge=1, le=HYG.MAX_LIMIT),
                              Authorization: AuthHeader = None):
    engine, _user = await authorize(team_id, Authorization)
    try:
        HYG.decode_after(after)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from None
    filters = {"flag": flag, "source": source, "q": q, "flagged_only": not all}
    return JSONResponse(await _call("hygiene", team_id, _page, engine, team_id, stale_runs, filters, after, limit),
                        headers=PRIVATE)


@router.get("/{team_id}/cbom/certificates/hygiene.csv", dependencies=[*READ, access.team("cbom.read")],
            summary="Orphaned and unmanaged certificates as CSV (filters as the list, every row)")
async def certificate_hygiene_csv(team_id: TeamId, flag: str | None = FlagQ, source: str | None = SourceQ,
                                  q: str | None = TextQ, all: bool = False, stale_runs: int = StaleQ,
                                  Authorization: AuthHeader = None):
    engine, _user = await authorize(team_id, Authorization)
    view = await _call("hygiene csv", team_id, _view, engine, team_id, stale_runs)
    name = f"certificate-hygiene-team{team_id}-{utcnow().date().isoformat()}.csv"
    return StreamingResponse(HYG.csv_rows(view, flag=flag, source=source, q=q, flagged_only=not all),
                             media_type="text/csv; charset=utf-8",
                             headers={**PRIVATE, "Content-Disposition": f'attachment; filename="{name}"'})
