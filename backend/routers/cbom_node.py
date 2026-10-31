"""Scan-node API: enroll, heartbeat, claim a job, post its result.

A scan node runs inside the customer's network and only ever calls out to these routes over HTTPS.
It authenticates with ``X-ZS-Node-Token`` (issued once at enrollment; only its SHA-256 is stored).
Enrollment itself carries the single-use registration token in the body instead.

* An unknown, missing or revoked token is a 401 with no detail about why.
* A job can only be claimed by the node its source points at, in the same team, at the same source
  version; the claim response is the only place stored secrets are ever decrypted.
* Bodies are size-capped before they are parsed.
"""
from __future__ import annotations

import datetime as _dt
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Request, Security
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse, Response
from fastapi.security import APIKeyHeader
from pydantic import ValidationError
from sqlalchemy import update
from sqlmodel import Session, select

from backend.get_db import get_db
from backend.new_models import CbomCollectionJob, CbomScanNode
from backend.utilities.cbom_sources import jobs as J
from backend.utilities.cbom_sources.common import audit, clean_text, iso_z, log, new_token, sha256_hex, utcnow
from backend.utilities.cbom_sources.crypto import scrub
from backend.utilities.cbom_sources.http import (
    PRIVATE,
    CbomRoute,
    bad_request,
    client_ip,
    enroll_limiter,
    node_limiter,
    read_capped_json,
    server_error,
)
from backend.utilities.cbom_sources.schemas import EnrollBody, HeartbeatBody, ResultBody
from backend.utilities.cbom_sources.settings import get_or_create_settings

router = APIRouter(tags=["cbom-node"], route_class=CbomRoute)
node_token_header = APIKeyHeader(name="X-ZS-Node-Token", auto_error=False)
HEARTBEAT_SECONDS = 30
SMALL_BODY = 16 * 1024
RESULT_BODY = 256 * 1024
_UNAUTHORIZED = HTTPException(status_code=401, detail="Invalid node token")


def _parse(model, data: Any):
    try:
        return model.model_validate(data)
    except ValidationError as exc:
        raise bad_request(exc) from None


def _clock_skew(value: str | None, now: _dt.datetime) -> int | None:
    if not value:
        return None
    try:
        moment = _dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if moment.tzinfo is not None:
        moment = moment.astimezone(_dt.timezone.utc).replace(tzinfo=None)
    return int((moment - now).total_seconds())


def _ips(values: list[str]) -> list[str]:
    import ipaddress

    out: list[str] = []
    for value in values[:32]:
        try:
            out.append(str(ipaddress.ip_address(str(value).strip())))
        except ValueError:
            continue
    return out


def _node_for(token: str | None, session: Session) -> CbomScanNode:
    if not token or not token.startswith("zsn_") or len(token) > 128:
        raise _UNAUTHORIZED
    node = session.exec(select(CbomScanNode).where(CbomScanNode.node_token_hash == sha256_hex(token))).first()
    if node is None:
        raise _UNAUTHORIZED
    return node


async def _guard(what: str, fn, *args):
    try:
        return await run_in_threadpool(fn, *args)
    except HTTPException:
        raise
    except Exception as exc:
        raise server_error(f"cbom node {what}", exc) from None


# ----------------------------------------------------------------------------- enroll
def _enroll(body: EnrollBody, ip: str) -> dict:
    now = utcnow()
    engine = get_db()
    token = new_token("zsn_")
    with Session(engine) as session:
        node = session.exec(select(CbomScanNode).where(
            CbomScanNode.registration_token_hash == sha256_hex(body.registration_token))).first()
        if node is None:
            raise HTTPException(status_code=401, detail="Registration token is invalid or expired")
        changed = session.exec(
            update(CbomScanNode)
            .where(CbomScanNode.id == node.id,
                   CbomScanNode.registration_token_hash == sha256_hex(body.registration_token),
                   CbomScanNode.enrolled_at.is_(None),  # type: ignore[union-attr]
                   CbomScanNode.registration_expires_at > now)
            .values(enrolled_at=now, node_token_hash=sha256_hex(token), registration_token_hash=None,
                    hostname=clean_text(body.hostname, 255), node_version=clean_text(body.version, 32),
                    source_ips=_ips(body.source_ips), ssh_public_key=clean_text(body.ssh_public_key, 8192),
                    capabilities=scrub(body.capabilities), clock_skew_s=_clock_skew(body.clock, now),
                    last_heartbeat_at=now, last_seen_ip=ip, row_version=node.row_version + 1, last_updated=now)
        ).rowcount
        if changed != 1:
            raise HTTPException(status_code=401, detail="Registration token is invalid or expired")
        audit(session, team_id=node.team_id, actor_type="node", actor_id=node.id, action="node.enroll",
              object_type="node", object_id=node.id)
        session.commit()
        log("node enrolled", team=node.team_id, node=node.id)
        return {"node_id": node.id, "team_id": node.team_id, "node_token": token,
                "heartbeat_interval_s": HEARTBEAT_SECONDS, "server_time": iso_z(now)}


@router.post("/cbom/node/enroll", dependencies=[Depends(enroll_limiter)],
             summary="Exchange a single-use registration token for a node token")
async def enroll(request: Request):
    body = _parse(EnrollBody, await read_capped_json(request, SMALL_BODY))
    return JSONResponse(await _guard("enroll", _enroll, body, client_ip(request)), headers=PRIVATE)


# ----------------------------------------------------------------------------- heartbeat
def _heartbeat(token: str | None, body: HeartbeatBody, ip: str) -> dict:
    now = utcnow()
    with Session(get_db()) as session:
        node = _node_for(token, session)
        gap = (now - node.last_heartbeat_at).total_seconds() if node.last_heartbeat_at else None
        node.hostname = clean_text(body.hostname, 255) or node.hostname
        node.node_version = clean_text(body.version, 32) or node.node_version
        if body.source_ips:
            node.source_ips = _ips(body.source_ips)
        if body.capabilities:
            node.capabilities = scrub(body.capabilities)
        skew = _clock_skew(body.clock, now)
        if skew is not None:
            node.clock_skew_s = skew
        node.last_node_error = clean_text(scrub(body.last_error), 512) if body.last_error else None
        node.last_heartbeat_at = now
        node.last_seen_ip = ip
        session.add(node)
        J.renew_leases(session, node, now)
        J.reap(session, now, node_id=node.id)
        settings = get_or_create_settings(session, node.team_id)
        cancel_ids: list[int] = []
        if settings.stop_all_network:
            claimed = session.exec(select(CbomCollectionJob).where(
                CbomCollectionJob.node_id == node.id, CbomCollectionJob.status == "claimed")).all()
            from backend.new_models import CbomCollectionSource

            for job in claimed:
                source = session.get(CbomCollectionSource, job.source_id) if job.source_id else None
                if job.kind == "discovery" or (source is not None and source.kind == "network_range"):
                    cancel_ids.append(job.id)
        pending = len(session.exec(select(CbomCollectionJob.id).where(
            CbomCollectionJob.node_id == node.id, CbomCollectionJob.status == "pending")).all())
        session.commit()
        if gap is not None and gap > 120:
            log("node back", team=node.team_id, node=node.id, gap_s=int(gap))
        return {"server_time": iso_z(now), "stop_all_network": settings.stop_all_network,
                "pending_jobs": pending, "cancel_job_ids": cancel_ids, "heartbeat_interval_s": HEARTBEAT_SECONDS}


@router.post("/cbom/node/heartbeat", dependencies=[Depends(node_limiter)], summary="Report that the node is alive")
async def heartbeat(request: Request, token: Annotated[str | None, Security(node_token_header)] = None):
    body = _parse(HeartbeatBody, await read_capped_json(request, SMALL_BODY))
    return JSONResponse(await _guard("heartbeat", _heartbeat, token, body, client_ip(request)), headers=PRIVATE)


# ----------------------------------------------------------------------------- claim
def _claim(token: str | None, ip: str) -> dict | None:
    now = utcnow()
    with Session(get_db()) as session:
        node = _node_for(token, session)
        node.last_seen_ip = ip
        node.last_heartbeat_at = now
        session.add(node)
        settings = get_or_create_settings(session, node.team_id)
        payload = J.claim_next(session, node, settings, now)
        session.commit()
        return payload


@router.post("/cbom/node/jobs/claim", dependencies=[Depends(node_limiter)],
             summary="Claim the next job (204 when there is nothing to do)")
async def claim(request: Request, token: Annotated[str | None, Security(node_token_header)] = None):
    payload = await _guard("claim", _claim, token, client_ip(request))
    if payload is None:
        return Response(status_code=204, headers=PRIVATE)
    return JSONResponse(payload, headers=PRIVATE)


# ----------------------------------------------------------------------------- result
def _result(token: str | None, job_id: int, body: ResultBody) -> dict:
    now = utcnow()
    with Session(get_db()) as session:
        node = _node_for(token, session)
        job = J.finish_job(session, node, job_id, body.lease_id, body.status, body.result, body.error, now)
        session.commit()
        return {"job_id": job.id, "status": job.status, "server_time": iso_z(now)}


@router.post("/cbom/node/jobs/{job_id}/result", dependencies=[Depends(node_limiter)],
             summary="Report a job's result (must echo the lease id from the claim)")
async def result(job_id: int, request: Request, token: Annotated[str | None, Security(node_token_header)] = None):
    if job_id < 1 or job_id > 2_147_483_647:
        raise HTTPException(status_code=404, detail="Job not found")
    body = _parse(ResultBody, await read_capped_json(request, RESULT_BODY))
    return JSONResponse(await _guard("result", _result, token, job_id, body), headers=PRIVATE)
