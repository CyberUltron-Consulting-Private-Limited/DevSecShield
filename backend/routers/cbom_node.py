"""Scan-node API: enroll, heartbeat, claim a job, post its result.

A scan node runs inside the customer's network and only ever calls out to these routes over HTTPS.
It authenticates with ``X-ZS-Node-Token`` (issued once at enrollment; only its SHA-256 is stored).
Enrollment itself carries the single-use registration token in the body instead.

* An unknown, missing or revoked token is a 401 with no detail about why.
* A job can only be claimed by the node its source points at, in the same team, at the same source
  version; the claim response is the only place stored secrets are ever decrypted.
* Bodies are size-capped before they are parsed, and a signed request's signature is checked on the raw bytes
  before anything parses them (``node_auth``: Ed25519 signatures, replay nonces, mTLS headers; refusals are 403
  with ``X-ZS-Refused``, never 401).  Every response carries ``X-ZS-Deployment`` (``node_auth.NodeDeploymentHeader``).
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
from backend.new_models import CbomCollectionJob, CbomNodePool, CbomScanNode
from backend.utilities.cbom_sources import agents as AG
from backend.utilities.cbom_sources import jobs as J
from backend.utilities.cbom_sources import node_auth as NA
from backend.utilities.cbom_sources.common import audit, clean_text, iso_z, log, new_token, sha256_hex, utcnow
from backend.utilities.cbom_sources.crypto import scrub
from backend.utilities.cbom_sources.http import (
    PRIVATE,
    CbomRoute,
    bad_request,
    client_ip,
    enroll_limiter,
    node_limiter,
    parse_json,
    read_capped_body,
    server_error,
)
from backend.utilities.cbom_sources.schemas import AssetIn, AssetsBody, ClaimBody, EnrollBody, HeartbeatBody, ResultBody
from backend.utilities.cbom_sources.settings import get_or_create_settings, team_exclusions

router = APIRouter(tags=["cbom-node"], route_class=CbomRoute)
node_token_header = APIKeyHeader(name="X-ZS-Node-Token", auto_error=False)
HEARTBEAT_SECONDS = 30
BUSY_HEARTBEAT_SECONDS = 5
SMALL_BODY = 16 * 1024
RESULT_BODY = 256 * 1024
ASSETS_BODY = 1024 * 1024
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


def _authenticate(session: Session, token: str | None, req: NA.NodeRequest, raw: bytes,
                  now: _dt.datetime) -> CbomScanNode:
    """Token (401), then client certificate and request signature (403 with a refusal code), all before the body is
    parsed.  A node with a signing key must sign; a legacy node is refused when its team requires signed nodes."""
    node = _node_for(token, session)
    NA.check_mtls(node, req)
    if node.signing_public_key:
        NA.verify_signature(session, node.id, node.signing_public_key, req, raw, now)  # type: ignore[arg-type]
        return node
    if get_or_create_settings(session, node.team_id).require_signed_nodes:
        message = ("Refused: this team requires signed scan nodes. Reset the node in ZeroShield and enroll it again "
                   "with scan node 1.1 or later")
        if node.last_node_error != message:
            node.last_node_error = message
            session.add(node)
            session.commit()
        log("node request refused", team=node.team_id, node=node.id, reason="signed_nodes_required", path=req.path)
        raise NA.refuse("signed_nodes_required", message)
    return node


async def _guard(what: str, fn, *args):
    try:
        return await run_in_threadpool(fn, *args)
    except HTTPException:
        raise
    except Exception as exc:
        raise server_error(f"cbom node {what}", exc) from None


# ----------------------------------------------------------------------------- enroll
def _rebind_pool_node(session: Session, pool: CbomNodePool, node: CbomScanNode, body: EnrollBody,
                      req: NA.NodeRequest, raw: bytes, ip: str, token: str, fingerprint: str | None,
                      now: _dt.datetime) -> dict:
    """A pod enrolling again with its pool token after its node was reset: the same node gets a new credential and
    signing key (no enrollment is used; any registration token the reset issued stops working)."""
    changed = session.exec(
        update(CbomScanNode)
        .where(CbomScanNode.id == node.id, CbomScanNode.pool_id == pool.id,
               CbomScanNode.node_token_hash.is_(None))  # type: ignore[union-attr]
        .values(node_token_hash=sha256_hex(token), enrolled_at=now, registration_token_hash=None,
                hostname=clean_text(body.hostname, 255), node_version=clean_text(body.version, 32),
                source_ips=_ips(body.source_ips), ssh_public_key=clean_text(body.ssh_public_key, 8192),
                capabilities=scrub(body.capabilities), clock_skew_s=_clock_skew(body.clock, now),
                last_heartbeat_at=now, last_seen_ip=ip, row_version=node.row_version + 1, last_updated=now,
                signing_public_key=body.signing_public_key, client_cert_sha256=fingerprint, last_node_error=None,
                mode=AG.AGENT)
    ).rowcount
    if changed != 1:  # another request took this node back at the same moment; the pod retries
        raise HTTPException(status_code=409, detail="This node is enrolling from another request; retry")
    AG.ensure_host_source(session, node, pool.owner_user_id, now)
    if body.signing_public_key:  # proof that the node holds the key it registers (nothing is kept if it fails)
        NA.verify_signature(session, node.id, body.signing_public_key, req, raw, now)  # type: ignore[arg-type]
    audit(session, team_id=node.team_id, actor_type="node", actor_id=node.id, action="node.enroll",
          object_type="node", object_id=node.id, changed_fields=["node_token", "pool_id"])
    session.commit()
    signing = "required" if body.signing_public_key else "legacy"
    log("agent node enrolled again", team=node.team_id, node=node.id, pool=pool.id, signing=signing)
    return {"node_id": node.id, "team_id": node.team_id, "node_token": token,
            "heartbeat_interval_s": HEARTBEAT_SECONDS, "server_time": iso_z(now),
            "deployment_id": NA.deployment_id(get_db()), "signing": signing, "mode": AG.AGENT}


def _enroll_pool(body: EnrollBody, req: NA.NodeRequest, raw: bytes, ip: str) -> dict:
    """Enroll one agent-mode node with an agent pool token (a DaemonSet pod): a new node named after its Kubernetes
    node, in agent mode, with its own host_agent source.  The pool's enrollment count is taken with one conditional
    UPDATE, so pods enrolling at once cannot pass the cap; the team's agent-node cap is counted under the team lock;
    a refused enrollment changes nothing.  A pod whose node was reset takes that node back (``AG.node_to_rebind``)
    while the token is neither expired nor revoked, even when every enrollment is used."""
    now = utcnow()
    engine = get_db()
    token = new_token("zsn_")
    refused = HTTPException(status_code=401, detail="Registration token is invalid or expired")
    with Session(engine) as session:
        pool = session.exec(select(CbomNodePool).where(
            CbomNodePool.token_hash == sha256_hex(body.registration_token))).first()
        status = AG.pool_status(pool, now) if pool is not None else None
        if pool is None or status in ("revoked", "expired"):
            if pool is not None:
                log("agent pool enroll refused", team=pool.team_id, pool=pool.id, reason=status)
            raise refused
        fingerprint = NA.check_mtls(None, req)
        settings = get_or_create_settings(session, pool.team_id)
        if not body.signing_public_key and settings.require_signed_nodes:
            log("node enroll refused", team=pool.team_id, pool=pool.id, reason="signed_nodes_required")
            raise NA.refuse("signed_nodes_required", "This team requires signed scan nodes: install scan node 1.1 or "
                                                     "later and enroll with this registration token")
        previous = AG.node_to_rebind(session, pool, body.node_id, body.node_name or body.hostname)
        if previous is not None:
            return _rebind_pool_node(session, pool, previous, body, req, raw, ip, token, fingerprint, now)
        if status != "active":
            log("agent pool enroll refused", team=pool.team_id, pool=pool.id, reason=status)
            raise refused
        AG.lock_team(session, pool.team_id)  # held to the commit: concurrent enrollments count one after another
        agents = session.exec(select(CbomScanNode.id).where(CbomScanNode.team_id == pool.team_id,
                                                            CbomScanNode.mode == AG.AGENT)).all()
        if len(agents) >= AG.MAX_AGENT_NODES:
            raise HTTPException(status_code=400, detail=f"A team can have at most {AG.MAX_AGENT_NODES} agent nodes")
        # the slot first: verify_signature commits (to record the nonce), so the slot, the node and its source are
        # committed together or, when anything before that fails, not at all
        taken = session.exec(
            update(CbomNodePool)
            .where(CbomNodePool.id == pool.id, CbomNodePool.revoked_at.is_(None),  # type: ignore[union-attr]
                   CbomNodePool.expires_at > now, CbomNodePool.enrollments < CbomNodePool.max_enrollments)
            .values(enrollments=CbomNodePool.enrollments + 1, last_enrolled_at=now)
        ).rowcount
        if taken != 1:
            raise refused
        name = AG.unique_node_name(session, pool.team_id,
                                   AG.node_name_from(body.node_name or body.hostname, f"agent-{pool.id}"))
        node = CbomScanNode(
            team_id=pool.team_id, owner_user_id=pool.owner_user_id, updated_by_user_id=pool.owner_user_id, name=name,
            segment=pool.segment, timezone="UTC", deployment="helm", mode=AG.AGENT, pool_id=pool.id, enrolled_at=now,
            node_token_hash=sha256_hex(token), hostname=clean_text(body.hostname, 255),
            node_version=clean_text(body.version, 32), source_ips=_ips(body.source_ips),
            ssh_public_key=clean_text(body.ssh_public_key, 8192), capabilities=scrub(body.capabilities),
            clock_skew_s=_clock_skew(body.clock, now), last_heartbeat_at=now, last_seen_ip=ip,
            signing_public_key=body.signing_public_key, client_cert_sha256=fingerprint, created_at=now,
            last_updated=now)
        session.add(node)
        session.flush()
        AG.ensure_host_source(session, node, pool.owner_user_id, now)
        if body.signing_public_key:  # proof that the node holds the key it registers (nothing is kept if it fails)
            NA.verify_signature(session, node.id, body.signing_public_key, req, raw, now)  # type: ignore[arg-type]
        audit(session, team_id=node.team_id, actor_type="node", actor_id=node.id, action="node.enroll",
              object_type="node", object_id=node.id, changed_fields=["mode", "pool_id"])
        session.commit()
        signing = "required" if body.signing_public_key else "legacy"
        log("agent node enrolled", team=node.team_id, node=node.id, pool=pool.id, signing=signing)
        return {"node_id": node.id, "team_id": node.team_id, "node_token": token,
                "heartbeat_interval_s": HEARTBEAT_SECONDS, "server_time": iso_z(now),
                "deployment_id": NA.deployment_id(engine), "signing": signing, "mode": AG.AGENT}


def _enroll(body: EnrollBody, req: NA.NodeRequest, raw: bytes, ip: str) -> dict:
    if body.registration_token.startswith(AG.POOL_PREFIX):
        return _enroll_pool(body, req, raw, ip)
    now = utcnow()
    engine = get_db()
    token = new_token("zsn_")
    mode = AG.AGENT if body.mode == AG.AGENT else AG.AGENTLESS
    with Session(engine) as session:
        node = session.exec(select(CbomScanNode).where(
            CbomScanNode.registration_token_hash == sha256_hex(body.registration_token))).first()
        if (node is None or node.enrolled_at is not None or node.registration_expires_at is None
                or node.registration_expires_at <= now):
            raise HTTPException(status_code=401, detail="Registration token is invalid or expired")
        # Checked before the token is used, so a refused enrollment leaves the registration token valid.
        fingerprint = NA.check_mtls(None, req)
        if body.signing_public_key:  # proof that the node holds the key it registers; the nonce is recorded
            NA.verify_signature(session, node.id, body.signing_public_key, req, raw, now)  # type: ignore[arg-type]
        elif get_or_create_settings(session, node.team_id).require_signed_nodes:
            log("node enroll refused", team=node.team_id, node=node.id, reason="signed_nodes_required")
            raise NA.refuse("signed_nodes_required", "This team requires signed scan nodes: install scan node 1.1 or "
                                                     "later and enroll with this registration token")
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
                    last_heartbeat_at=now, last_seen_ip=ip, row_version=node.row_version + 1, last_updated=now,
                    signing_public_key=body.signing_public_key, client_cert_sha256=fingerprint, last_node_error=None,
                    mode=mode)
        ).rowcount
        if changed != 1:
            raise HTTPException(status_code=401, detail="Registration token is invalid or expired")
        if mode == AG.AGENT:  # a single host agent (docker run / AMI with ZS_MODE=agent): its own host source
            session.refresh(node)
            AG.ensure_host_source(session, node, node.owner_user_id, now)
        audit(session, team_id=node.team_id, actor_type="node", actor_id=node.id, action="node.enroll",
              object_type="node", object_id=node.id)
        session.commit()
        signing = "required" if body.signing_public_key else "legacy"
        log("node enrolled", team=node.team_id, node=node.id, signing=signing, client_cert=bool(fingerprint), mode=mode)
        return {"node_id": node.id, "team_id": node.team_id, "node_token": token,
                "heartbeat_interval_s": HEARTBEAT_SECONDS, "server_time": iso_z(now),
                "deployment_id": NA.deployment_id(engine), "signing": signing, "mode": mode}


@router.post("/cbom/node/enroll", dependencies=[Depends(enroll_limiter)],
             summary="Exchange a single-use registration token for a node token")
async def enroll(request: Request):
    raw = await read_capped_body(request, SMALL_BODY)
    body = _parse(EnrollBody, parse_json(raw))  # the key to verify with is in the body
    return JSONResponse(await _guard("enroll", _enroll, body, NA.NodeRequest.of(request), raw, client_ip(request)),
                        headers=PRIVATE)


# ----------------------------------------------------------------------------- heartbeat
def _heartbeat(token: str | None, req: NA.NodeRequest, raw: bytes, ip: str) -> dict:
    now = utcnow()
    with Session(get_db()) as session:
        node = _authenticate(session, token, req, raw, now)
        body = _parse(HeartbeatBody, parse_json(raw))
        NA.sweep_nonces(session, now)
        gap = (now - node.last_heartbeat_at).total_seconds() if node.last_heartbeat_at else None
        node.hostname = clean_text(body.hostname, 255) or node.hostname
        node.node_version = clean_text(body.version, 32) or node.node_version
        if body.source_ips:
            node.source_ips = _ips(body.source_ips)
        if body.capabilities:
            node.capabilities = scrub(body.capabilities)
        mode_note = AG.reconcile_mode(session, node, (body.capabilities or {}).get("mode"), now)
        skew = _clock_skew(body.clock, now)
        if skew is not None:
            node.clock_skew_s = skew
        node.last_node_error = clean_text(scrub(body.last_error), 512) if body.last_error else mode_note
        if node.last_node_error:
            log("node error", team=node.team_id, node=node.id, error=node.last_node_error)
        node.last_heartbeat_at = now
        node.last_seen_ip = ip
        session.add(node)
        running = None if body.running is None else [(r.job_id, r.lease_id) for r in body.running]
        released = J.renew_leases(session, node, now, running)
        J.reap(session, now, node_id=node.id)
        settings = get_or_create_settings(session, node.team_id)
        cancel_ids = J.cancel_ids_for_node(session, node, settings)
        if running is not None:
            # jobs the node runs but the server already ended (released, reaped, cancelled) must stop too
            live = {job_id for job_id, _lease in running}
            for job_id, lease in running:
                job = session.get(CbomCollectionJob, job_id)
                if job is None or job.node_id != node.id or job.status != "claimed" or job.lease_id != lease:
                    cancel_ids.append(job_id)
            cancel_ids = sorted(set(cancel_ids) | (set(released) & live))
        pending = len(session.exec(select(CbomCollectionJob.id).where(
            CbomCollectionJob.node_id == node.id, CbomCollectionJob.status == "pending")).all())
        busy = session.exec(select(CbomCollectionJob.id).where(
            CbomCollectionJob.node_id == node.id, CbomCollectionJob.status == "claimed")).first() is not None
        exclusions = team_exclusions(settings)
        session.commit()
        if gap is not None and gap > 120:
            log("node back", team=node.team_id, node=node.id, gap_s=int(gap))
        return {"server_time": iso_z(now), "stop_all_network": settings.stop_all_network,
                "never_scan": exclusions.normalized, "pending_jobs": pending, "cancel_job_ids": cancel_ids,
                # while a job runs, beat faster so a cancel or a network stop reaches the node within seconds
                "heartbeat_interval_s": BUSY_HEARTBEAT_SECONDS if busy else HEARTBEAT_SECONDS}


@router.post("/cbom/node/heartbeat", dependencies=[Depends(node_limiter)], summary="Report that the node is alive")
async def heartbeat(request: Request, token: Annotated[str | None, Security(node_token_header)] = None):
    raw = await read_capped_body(request, SMALL_BODY)
    return JSONResponse(await _guard("heartbeat", _heartbeat, token, NA.NodeRequest.of(request), raw, client_ip(request)),
                        headers=PRIVATE)


# ----------------------------------------------------------------------------- claim
def _claim(token: str | None, req: NA.NodeRequest, raw: bytes, ip: str) -> dict | None:
    now = utcnow()
    with Session(get_db()) as session:
        node = _authenticate(session, token, req, raw, now)
        body = _parse(ClaimBody, parse_json(raw)) if raw else None  # older nodes send no body
        node.last_seen_ip = ip
        node.last_heartbeat_at = now
        session.add(node)
        # a node restarted in agent mode may claim before its first heartbeat: it is never given a secret again
        AG.reconcile_mode(session, node, body.mode if body else None, now)
        settings = get_or_create_settings(session, node.team_id)
        payload = J.claim_next(session, node, settings, now)
        session.commit()
        return payload


@router.post("/cbom/node/jobs/claim", dependencies=[Depends(node_limiter)],
             summary="Claim the next job (204 when there is nothing to do)")
async def claim(request: Request, token: Annotated[str | None, Security(node_token_header)] = None):
    raw = await read_capped_body(request, SMALL_BODY)
    payload = await _guard("claim", _claim, token, NA.NodeRequest.of(request), raw, client_ip(request))
    if payload is None:
        return Response(status_code=204, headers=PRIVATE)
    return JSONResponse(payload, headers=PRIVATE)


# ----------------------------------------------------------------------------- assets
def _assets(token: str | None, job_id: int, req: NA.NodeRequest, raw: bytes) -> dict:
    now = utcnow()
    with Session(get_db()) as session:
        node = _authenticate(session, token, req, raw, now)
        body = _parse(AssetsBody, parse_json(raw))
        valid: list[dict[str, Any]] = []
        rejected = 0
        for item in body.assets:
            try:
                valid.append(AssetIn.model_validate(item).model_dump())
            except (ValidationError, TypeError):
                rejected += 1
        out = J.add_assets(session, node, job_id, body.lease_id, valid, now)
        session.commit()
        out["rejected"] += rejected
        out["batch_id"] = body.batch_id
        return out


@router.post("/cbom/node/jobs/{job_id}/assets", dependencies=[Depends(node_limiter)],
             summary="Report a batch of collected assets for a leased job")
async def assets(job_id: int, request: Request, token: Annotated[str | None, Security(node_token_header)] = None):
    if job_id < 1 or job_id > 2_147_483_647:
        raise HTTPException(status_code=404, detail="Job not found")
    raw = await read_capped_body(request, ASSETS_BODY)
    return JSONResponse(await _guard("assets", _assets, token, job_id, NA.NodeRequest.of(request), raw), headers=PRIVATE)


# ----------------------------------------------------------------------------- result
def _result(token: str | None, job_id: int, req: NA.NodeRequest, raw: bytes) -> dict:
    now = utcnow()
    with Session(get_db()) as session:
        node = _authenticate(session, token, req, raw, now)
        body = _parse(ResultBody, parse_json(raw))
        job = J.finish_job(session, node, job_id, body.lease_id, body.status, body.result, body.error, now)
        session.commit()
        return {"job_id": job.id, "status": job.status, "server_time": iso_z(now)}


@router.post("/cbom/node/jobs/{job_id}/result", dependencies=[Depends(node_limiter)],
             summary="Report a job's result (must echo the lease id from the claim)")
async def result(job_id: int, request: Request, token: Annotated[str | None, Security(node_token_header)] = None):
    if job_id < 1 or job_id > 2_147_483_647:
        raise HTTPException(status_code=404, detail="Job not found")
    raw = await read_capped_body(request, RESULT_BODY)
    return JSONResponse(await _guard("result", _result, token, job_id, NA.NodeRequest.of(request), raw), headers=PRIVATE)
