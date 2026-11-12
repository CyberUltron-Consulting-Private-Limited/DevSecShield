"""Agent pool registration tokens: one token, many agent-mode scan nodes (the Helm DaemonSet, one pod per Kubernetes
node).  Routes are ``/{team_id}/cbom/sources/node-pools`` and follow the CBOM Sources rules (members of the team;
another team's pool is a 404; revoking needs the pool's creator or a team admin, else a 400).

The token (``zsp_...``) is shown once, at creation; only its SHA-256 is stored.  It expires, caps its enrollments
and can be revoked.  Nodes that enrolled keep their own credentials after the token expires or is revoked.  While
the token is active, a pod whose node is reset on the Scan nodes tab enrolls again by itself and takes that node
back, and a pod whose node is deleted enrolls as a new node (within the cap); after the token expires or is revoked
those pods stay offline, and enroll as new nodes once a new pool token is installed (``helm upgrade --set
agent.poolToken=...``; the pods restart with it).  To stop a node for good, remove its pod (the DaemonSet's node
selector) and delete the node.
Agent nodes collect only their own host and never receive a credential (see ``utilities/cbom_sources/agents.py``).
"""
from __future__ import annotations

import datetime as _dt
from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse
from sqlalchemy import update
from sqlmodel import Session, select

from backend.new_models import CbomNodePool, CbomScanNode
from backend.utilities.cbom_sources import agents as AG
from backend.utilities.cbom_sources import limits as LIM
from backend.utilities.cbom_sources.common import audit, iso_z, log, new_token, sha256_hex, utcnow
from backend.utilities.cbom_sources.http import (
    PRIVATE,
    CbomRoute,
    ObjectId,
    TeamId,
    authorize,
    read_limiter,
    require_owner_or_admin,
    server_error,
    write_limiter,
)
from backend.utilities.cbom_sources.schemas import PoolCreate
from backend.utilities.cbom_sources.settings import get_or_create_settings

router = APIRouter(tags=["cbom-sources"], route_class=CbomRoute)
AuthHeader = Annotated[str | None, Header()]
BASE = "/{team_id}/cbom/sources/node-pools"


async def _run(what: str, team_id: int, fn, *args):
    try:
        return await run_in_threadpool(fn, *args)
    except HTTPException:
        raise
    except Exception as exc:
        raise server_error(f"cbom node pools {what}", exc, team=team_id) from None


def _nodes_by_pool(session: Session, team_id: int) -> dict[int, list[CbomScanNode]]:
    out: dict[int, list[CbomScanNode]] = {}
    for node in session.exec(select(CbomScanNode).where(CbomScanNode.team_id == team_id,
                                                        CbomScanNode.pool_id.is_not(None))  # type: ignore[union-attr]
                             .order_by(CbomScanNode.id)).all():
        out.setdefault(int(node.pool_id), []).append(node)  # type: ignore[arg-type]
    return out


def _list(engine, team_id: int) -> dict:
    now = utcnow()
    with Session(engine) as session:
        pools = session.exec(select(CbomNodePool).where(CbomNodePool.team_id == team_id)
                             .order_by(CbomNodePool.id.desc())).all()  # type: ignore[union-attr]
        nodes = _nodes_by_pool(session, team_id)
        return {"server_time": iso_z(now), "pools": [AG.public_pool(p, now, nodes.get(p.id or 0)) for p in pools]}


@router.get(BASE, dependencies=[Depends(read_limiter)], summary="Agent pool tokens (never the token itself)")
async def list_pools(team_id: TeamId, Authorization: AuthHeader = None):
    engine, _user = await authorize(team_id, Authorization)
    return JSONResponse(await _run("list", team_id, _list, engine, team_id), headers=PRIVATE)


def _create(engine, team_id: int, user_id: int, body: PoolCreate) -> dict:
    now = utcnow()
    token = new_token(AG.POOL_PREFIX)
    with Session(engine) as session:
        get_or_create_settings(session, team_id)
        AG.lock_team(session, team_id)  # held to the commit: two creations count one after the other
        live = [p for p in session.exec(select(CbomNodePool).where(CbomNodePool.team_id == team_id)).all()
                if AG.pool_status(p, now) == "active"]
        if body.max_enrollments > LIM.max_pool_enrollments():
            raise HTTPException(status_code=400, detail=f"max_enrollments: at most {LIM.max_pool_enrollments()} per "
                                                        "agent pool token (CBOM_MAX_POOL_ENROLLMENTS)")
        if len(live) >= LIM.max_pools():
            raise HTTPException(status_code=400, detail=f"A team can have at most {LIM.max_pools()} active agent pool "
                                                        "tokens; revoke one first")
        pool = CbomNodePool(team_id=team_id, owner_user_id=user_id, name=body.name, segment=body.segment,
                            token_hash=sha256_hex(token), expires_at=now + _dt.timedelta(hours=body.expires_in_hours),
                            max_enrollments=body.max_enrollments, enrollments=0, created_at=now)
        session.add(pool)
        session.flush()
        audit(session, team_id=team_id, actor_type="user", actor_id=user_id, action="node_pool.create",
              object_type="node_pool", object_id=pool.id,
              changed_fields=["name", "segment", "expires_at", "max_enrollments"])
        session.commit()
        session.refresh(pool)
        log("agent pool token created", team=team_id, pool=pool.id, by=user_id, max_enrollments=pool.max_enrollments,
            hours=body.expires_in_hours)
        return {"pool": AG.public_pool(pool, now), "registration_token": token}


@router.post(BASE, dependencies=[Depends(write_limiter)],
             summary="Create an agent pool token (shown once) for a DaemonSet of agent-mode scan nodes")
async def create_pool(team_id: TeamId, body: PoolCreate, Authorization: AuthHeader = None):
    engine, user = await authorize(team_id, Authorization)
    return JSONResponse(await _run("create", team_id, _create, engine, team_id, user.id, body), status_code=201,
                        headers=PRIVATE)


def _revoke(engine, team_id: int, user_id: int, pool_id: int) -> dict:
    now = utcnow()
    with Session(engine) as session:
        pool = session.get(CbomNodePool, pool_id)
        if pool is None or pool.team_id != team_id:
            raise HTTPException(status_code=404, detail="Agent pool token not found")
        require_owner_or_admin(session, user_id, team_id, pool.owner_user_id, "agent pool token")
        session.exec(update(CbomNodePool).where(CbomNodePool.id == pool.id, CbomNodePool.revoked_at.is_(None))  # type: ignore[union-attr]
                     .values(revoked_at=now, revoked_by_user_id=user_id))
        audit(session, team_id=team_id, actor_type="user", actor_id=user_id, action="node_pool.revoke",
              object_type="node_pool", object_id=pool.id)
        session.commit()
        session.refresh(pool)
        log("agent pool token revoked", team=team_id, pool=pool.id, by=user_id)
        return {"pool": AG.public_pool(pool, now, _nodes_by_pool(session, team_id).get(pool.id or 0))}


@router.post(BASE + "/{pool_id}/revoke", dependencies=[Depends(write_limiter)],
             summary="Revoke an agent pool token (no enrollment with it any more; enrolled nodes keep working)")
async def revoke_pool(team_id: TeamId, pool_id: ObjectId, Authorization: AuthHeader = None):
    engine, user = await authorize(team_id, Authorization)
    return JSONResponse(await _run("revoke", team_id, _revoke, engine, team_id, user.id, pool_id), headers=PRIVATE)
