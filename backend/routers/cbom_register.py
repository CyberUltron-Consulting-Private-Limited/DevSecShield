"""CBOM quantum risk register (CB-23): the register (PR-B) and its Q0 gap list (PR-A).

``GET /{team_id}/cbom/register`` lists one row per estate asset key with its current grade, worst first (Q1 .. Q4,
then Q0, then no grade), keyset-paged by ``after``, filtered by grade, reason, kind, source, application, family,
exposure, type or presence; ``…/register/summary`` gives the distribution, Q0 by reason, the algorithm family x grade
counts, closures per week and what is still to re-grade; ``…/register/items/{key}`` one row with its observations
and Q0 history; ``…/register.csv`` the filtered register, streamed.

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
from fastapi.responses import JSONResponse, StreamingResponse
from sqlmodel import Session

from backend.utilities.cbom_sources import q0register as REG
from backend.utilities.cbom_sources import risk_register as RISK
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


# ----------------------------------------------------------------------------- the register (CB-23 PR-B)
GradeQ = Query(default=None, pattern="^(Q0|Q1|Q2|Q3|Q4|none)$")
TextQ = Query(default=None, max_length=255)


def _filters(**values: Any) -> dict[str, Any]:
    return {k: v for k, v in values.items() if v}


def _cursor(after: str | None) -> tuple[int, str] | None:
    if not after:
        return None
    try:
        return RISK.decode_after(after)
    except (ValueError, UnicodeDecodeError, binascii.Error):
        raise HTTPException(status_code=400, detail="after: not a cursor from this list") from None


def _list(engine, team_id: int, filters: dict[str, Any], after: str | None, limit: int) -> dict[str, Any]:
    cursor = _cursor(after)
    with Session(engine) as session:
        return RISK.list_register(session, team_id, filters, after=cursor, limit=limit)


async def _call(what: str, team_id: int, fn, *args) -> Any:
    try:
        return await run_in_threadpool(fn, *args)
    except HTTPException:
        raise
    except Exception as exc:
        raise server_error(f"cbom register {what}", exc, team=team_id) from None


@router.get("/{team_id}/cbom/register", dependencies=READ,
            summary="Quantum risk register: one row per asset with its current grade (worst first, keyset paging)")
async def register_list(team_id: TeamId, grade: str | None = GradeQ, reason: str | None = Query(default=None, max_length=32),
                        kind: str | None = Query(default=None, max_length=16), source: str | None = TextQ,
                        application: str | None = Query(default=None, max_length=128),
                        family: str | None = Query(default=None, max_length=32),
                        exposure: str | None = Query(default=None, max_length=16),
                        type: str | None = Query(default=None, max_length=32),
                        presence: str | None = Query(default=None, pattern="^(present|not_read)$"),
                        after: str | None = Query(default=None, max_length=512),
                        limit: int = Query(default=100, ge=1, le=RISK.LIMIT_MAX),
                        Authorization: AuthHeader = None):
    engine, _user = await authorize(team_id, Authorization)
    filters = _filters(grade=grade, reason=reason, kind=kind, source=source, application=application, family=family,
                       exposure=exposure, type=type, presence=presence)
    return JSONResponse(await _call("list", team_id, _list, engine, team_id, filters, after, limit), headers=PRIVATE)


def _summary(engine, team_id: int) -> dict[str, Any]:
    with Session(engine) as session:
        return RISK.summary(session, team_id, utcnow())


@router.get("/{team_id}/cbom/register/summary", dependencies=READ,
            summary="Register distribution, Q0 by reason, family x grade, closures per week, re-grade backlog")
async def register_summary(team_id: TeamId, Authorization: AuthHeader = None):
    engine, _user = await authorize(team_id, Authorization)
    return JSONResponse(await _call("summary", team_id, _summary, engine, team_id), headers=PRIVATE)


def _item(engine, team_id: int, key: str) -> dict[str, Any]:
    with Session(engine) as session:
        out = RISK.get_item(session, team_id, key)
    if out is None:
        raise HTTPException(status_code=404, detail="Register item not found")
    return out


@router.get("/{team_id}/cbom/register/items/{item_key}", dependencies=READ,
            summary="One register row with its observations per source and its Q0 history")
async def register_item(team_id: TeamId, item_key: str, Authorization: AuthHeader = None):
    engine, _user = await authorize(team_id, Authorization)
    if len(item_key) > 64:
        raise HTTPException(status_code=404, detail="Register item not found")
    return JSONResponse(await _call("item", team_id, _item, engine, team_id, item_key), headers=PRIVATE)


@router.get("/{team_id}/cbom/register.csv", dependencies=READ, summary="The register as CSV (filters as the list)")
async def register_csv(team_id: TeamId, grade: str | None = GradeQ, reason: str | None = Query(default=None, max_length=32),
                       source: str | None = TextQ, application: str | None = Query(default=None, max_length=128),
                       family: str | None = Query(default=None, max_length=32),
                       exposure: str | None = Query(default=None, max_length=16),
                       type: str | None = Query(default=None, max_length=32), Authorization: AuthHeader = None):
    engine, _user = await authorize(team_id, Authorization)
    filters = _filters(grade=grade, reason=reason, source=source, application=application, family=family,
                       exposure=exposure, type=type)
    name = f"quantum-risk-register-team{team_id}-{utcnow().date().isoformat()}.csv"
    return StreamingResponse(RISK.csv_rows(engine, team_id, filters), media_type="text/csv; charset=utf-8",
                             headers={**PRIVATE, "Content-Disposition": f'attachment; filename="{name}"'})
