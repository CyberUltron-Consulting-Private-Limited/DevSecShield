"""CBOM quantum risk register (CB-23): the Q0 gap list.

``GET /{team_id}/cbom/register/q0?status=open|closed&kind&reason&after&limit`` lists the team's Q0 items with their
lifecycle (opened, last seen, closed, cause), newest opening first, keyset-paged by ``after`` (the opaque
``next_after`` of the previous page). Team members only (the CBOM Sources conventions,
``backend/utilities/cbom_sources/http.py``). Evidence gaps are re-judged before the list is read (an E2/E3 area
turns E0 on day 366 with no write); scope / asset / inputs items come from each source's latest run.
"""
from __future__ import annotations

import binascii
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Header, HTTPException, Query
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse
from sqlmodel import Session

from backend.utilities.cbom_sources import q0register as REG
from backend.utilities.cbom_sources.common import utcnow
from backend.utilities.cbom_sources.http import PRIVATE, CbomRoute, TeamId, authorize, read_limiter, server_error

router = APIRouter(tags=["cbom-register"], route_class=CbomRoute)
AuthHeader = Annotated[str | None, Header()]
READ = [Depends(read_limiter)]


def _q0(engine, team_id: int, status: str, kind: str | None, reason: str | None, after: str | None,
        limit: int) -> dict[str, Any]:
    cursor = None
    if after:
        try:
            cursor = REG.decode_after(after)
        except (ValueError, UnicodeDecodeError, binascii.Error):
            raise HTTPException(status_code=400, detail="after: not a cursor from this list") from None
    now = utcnow()
    with Session(engine) as session:
        REG.sync_evidence_safely(session, team_id, now)  # the list is never a day behind the evidence (day 366)
        session.commit()
        return REG.list_gaps(session, team_id, now, status=status, kind=kind, reason=reason, after=cursor,
                             limit=limit)


@router.get("/{team_id}/cbom/register/q0", dependencies=READ,
            summary="Q0 gaps of the quantum risk register (open or closed; keyset paging with after)")
async def register_q0(team_id: TeamId,
                      status: str = Query(default="open", pattern="^(open|closed)$"),
                      kind: str | None = Query(default=None, pattern="^(evidence|scope|asset|inputs)$"),
                      reason: str | None = Query(default=None, max_length=32, pattern="^[a-z0-9_]+$"),
                      after: str | None = Query(default=None, max_length=128),
                      limit: int = Query(default=100, ge=1, le=REG.LIMIT_MAX),
                      Authorization: AuthHeader = None):
    engine, _user = await authorize(team_id, Authorization)
    try:
        payload = await run_in_threadpool(_q0, engine, team_id, status, kind, reason, after, limit)
    except HTTPException:
        raise
    except Exception as exc:
        raise server_error("cbom register q0", exc, team=team_id) from None
    return JSONResponse(payload, headers=PRIVATE)
