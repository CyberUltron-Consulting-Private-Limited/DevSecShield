"""Scan-node API: enroll, heartbeat, claim a job, post its result.

A scan node runs inside the customer's network and only ever calls out to these routes over HTTPS.
It authenticates with ``X-ZS-Node-Token`` (issued once at enrollment; only its SHA-256 is stored).
Enrollment itself carries the single-use registration token in the body instead.

* An unknown, missing or revoked token is a 401 with no detail about why, and a code a node can act on in
  ``X-ZS-Refused``: ``node_token_revoked`` when a well-formed node token arrived and no node has it (reset or
  deleted), ``node_token_missing`` when none arrived (a proxy dropped it: the node keeps its token),
  ``registration_token_refused`` for a refused enrollment.
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
from fastapi.responses import JSONResponse, Response
from fastapi.security import APIKeyHeader
from pydantic import ValidationError
from sqlalchemy import func, update
from sqlmodel import Session, select

from backend.get_db import get_db
from backend.new_models import CbomNodePool, CbomScanNode
from backend.utilities import request_timing as RT
from backend.utilities.cbom_sources import agents as AG
from backend.utilities.cbom_sources import dispatch as D
from backend.utilities.cbom_sources import jobs as J
from backend.utilities.cbom_sources import limits as LIM
from backend.utilities.cbom_sources import node_auth as NA
from backend.utilities.cbom_sources import node_obs as OBS
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
# Node protocol this server speaks.  2 (F1.1): server-driven heartbeat with jitter (limits.heartbeat_seconds), a
# ``claim`` grant (how many claims the node may make now, ``dispatch``) in every heartbeat, claim and result answer
# (a protocol-2 node claims only then), sequence nonces checked against a per-node replay window.  Protocol-1 nodes
# (scan node 1.0/1.1) are served as before, except that their claims draw on the same dispatch rate (204 when none).
PROTOCOL = 2
SMALL_BODY = 16 * 1024
RESULT_BODY = 256 * 1024
ASSETS_BODY = 1024 * 1024
_UNAUTHORIZED = HTTPException(status_code=401, detail="Invalid node token",
                              headers={NA.REFUSED_HEADER: "node_token_revoked"})
_TOKEN_MISSING = HTTPException(status_code=401, detail="Invalid node token",
                               headers={NA.REFUSED_HEADER: "node_token_missing"})


def _registration_refused() -> HTTPException:
    return HTTPException(status_code=401, detail="Registration token is invalid or expired",
                         headers={NA.REFUSED_HEADER: "registration_token_refused"})


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
        raise _TOKEN_MISSING  # no node token arrived intact: never a revocation
    node = session.exec(select(CbomScanNode).where(CbomScanNode.node_token_hash == sha256_hex(token))).first()
    if node is None:
        raise _UNAUTHORIZED
    return node


def _authenticate(session: Session, token: str | None, req: NA.NodeRequest, raw: bytes,
                  now: _dt.datetime, touch: dict[str, Any] | None = None) -> tuple[CbomScanNode, bool]:
    """Token (401), then client certificate and request signature (403 with a refusal code), all before the body is
    parsed.  A node with a signing key must sign; a legacy node is refused when its team requires signed nodes.

    ``touch``: node columns (last seen) written in the same statement as the replay check when the node uses
    protocol-2 sequence nonces.  Returns (node, written): the caller writes ``touch`` itself when not written.  The
    replay-window step is bound to this token and key (a Reset in between refuses the request)."""
    node = _node_for(token, session)
    RT.note(node_id=node.id)
    NA.check_mtls(node, req)
    if node.signing_public_key:
        written = NA.verify_signature(session, node.id, node.signing_public_key, req, raw, now,  # type: ignore[arg-type]
                                      touch=touch, token_hash=sha256_hex(token or ""))
        return node, written
    if get_or_create_settings(session, node.team_id, commit=False).require_signed_nodes:
        message = ("Refused: this team requires signed scan nodes. Reset the node in ZeroShield and enroll it again "
                   "with scan node 1.1 or later")
        if node.last_node_error != message:
            node.last_node_error = message
            session.add(node)
            session.commit()
        log("node request refused", team=node.team_id, node=node.id, reason="signed_nodes_required", path=req.path)
        raise NA.refuse("signed_nodes_required", message)
    return node, False


def authenticate_node(session: Session, token: str | None, req: NA.NodeRequest, raw: bytes,
                      now: _dt.datetime) -> CbomScanNode:
    """The authenticated node of a node request (token, client certificate, signature and replay check), for routes
    other parts add (F1 contract, section 3).  The node's last-seen stamp is not touched."""
    return _authenticate(session, token, req, raw, now)[0]


async def _guard(what: str, fn, *args):
    """Run a route's synchronous body on the node thread limiter (``node_obs``; DA E2), mapping errors to a 500."""
    try:
        return await OBS.to_node_thread(fn, *args)
    except HTTPException:
        raise
    except Exception as exc:
        raise server_error(f"cbom node {what}", exc) from None


# ----------------------------------------------------------------------------- enroll
def _rebind_pool_node(session: Session, pool: CbomNodePool, node: CbomScanNode, body: EnrollBody,
                      req: NA.NodeRequest, raw: bytes, ip: str, token: str, fingerprint: str | None,
                      now: _dt.datetime) -> dict:
    """A pod enrolling again with its pool token after its node was reset: the same node gets a new credential and
    signing key (no enrollment is used; any registration token the reset issued stops working).  The request is
    verified BEFORE anything changes (S2): a replayed re-bind is refused and changes nothing.  The replay window starts
    again for the new credential (S1)."""
    if body.signing_public_key:  # proof that the node holds the key it registers; the nonce is recorded with it
        NA.verify_signature(session, node.id, body.signing_public_key, req, raw, now,  # type: ignore[arg-type]
                            enrollment=True)
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
                mode=AG.AGENT, replay_hwm=0, replay_bits=0)
    ).rowcount
    if changed != 1:  # another request took this node back at the same moment; the pod retries
        session.rollback()
        raise HTTPException(status_code=409, detail="This node is enrolling from another request; retry")
    AG.ensure_host_source(session, node, pool.owner_user_id, now)
    audit(session, team_id=node.team_id, actor_type="node", actor_id=node.id, action="node.enroll",
          object_type="node", object_id=node.id, changed_fields=["node_token", "pool_id"])
    session.commit()
    signing = "required" if body.signing_public_key else "legacy"
    log("agent node enrolled again", team=node.team_id, node=node.id, pool=pool.id, signing=signing)
    return {"node_id": node.id, "team_id": node.team_id, "node_token": token,
            "heartbeat_interval_s": LIM.heartbeat_seconds(), "server_time": iso_z(now), "protocol": PROTOCOL,
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
    refused = _registration_refused()
    with Session(engine) as session:
        pool = session.exec(select(CbomNodePool).where(
            CbomNodePool.token_hash == sha256_hex(body.registration_token))).first()
        status = AG.pool_status(pool, now) if pool is not None else None
        if pool is None or status in ("revoked", "expired"):
            if pool is not None:
                log("agent pool enroll refused", team=pool.team_id, pool=pool.id, reason=status)
            raise refused
        fingerprint = NA.check_mtls(None, req)
        settings = get_or_create_settings(session, pool.team_id, commit=False)
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
        agents = session.exec(select(func.count()).select_from(CbomScanNode).where(
            CbomScanNode.team_id == pool.team_id, CbomScanNode.mode == AG.AGENT)).one()
        cap = LIM.max_agent_nodes()  # CBOM_MAX_AGENT_NODES
        if agents >= cap:
            raise HTTPException(status_code=400, detail=f"A team can have at most {cap} agent nodes "
                                                        "(CBOM_MAX_AGENT_NODES)")
        # the slot, the node, its source and the enrollment's nonce are committed together, or (a refusal, a replay)
        # not at all
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
            NA.verify_signature(session, node.id, body.signing_public_key, req, raw, now,  # type: ignore[arg-type]
                                enrollment=True)
        audit(session, team_id=node.team_id, actor_type="node", actor_id=node.id, action="node.enroll",
              object_type="node", object_id=node.id, changed_fields=["mode", "pool_id"])
        session.commit()
        signing = "required" if body.signing_public_key else "legacy"
        log("agent node enrolled", team=node.team_id, node=node.id, pool=pool.id, signing=signing)
        return {"node_id": node.id, "team_id": node.team_id, "node_token": token,
                "heartbeat_interval_s": LIM.heartbeat_seconds(), "server_time": iso_z(now), "protocol": PROTOCOL,
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
            raise _registration_refused()
        # Checked before the token is used, so a refused enrollment leaves the registration token valid.
        fingerprint = NA.check_mtls(None, req)
        if body.signing_public_key:  # proof that the node holds the key it registers; the nonce is recorded with it
            NA.verify_signature(session, node.id, body.signing_public_key, req, raw, now,  # type: ignore[arg-type]
                                enrollment=True)
        elif get_or_create_settings(session, node.team_id, commit=False).require_signed_nodes:
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
                    mode=mode, replay_hwm=0, replay_bits=0)
        ).rowcount
        if changed != 1:
            session.rollback()
            raise _registration_refused()
        if mode == AG.AGENT:  # a single host agent (docker run / AMI with ZS_MODE=agent): its own host source
            session.refresh(node)
            AG.ensure_host_source(session, node, node.owner_user_id, now)
        audit(session, team_id=node.team_id, actor_type="node", actor_id=node.id, action="node.enroll",
              object_type="node", object_id=node.id)
        session.commit()
        signing = "required" if body.signing_public_key else "legacy"
        log("node enrolled", team=node.team_id, node=node.id, signing=signing, client_cert=bool(fingerprint), mode=mode)
        return {"node_id": node.id, "team_id": node.team_id, "node_token": token,
                "heartbeat_interval_s": LIM.heartbeat_seconds(), "server_time": iso_z(now), "protocol": PROTOCOL,
                "deployment_id": NA.deployment_id(engine), "signing": signing, "mode": mode}


@router.post("/cbom/node/enroll", dependencies=[Depends(enroll_limiter)],
             summary="Exchange a single-use registration token for a node token")
async def enroll(request: Request):
    raw = await read_capped_body(request, SMALL_BODY)
    body = _parse(EnrollBody, parse_json(raw))  # the key to verify with is in the body
    return JSONResponse(await _guard("enroll", _enroll, body, NA.NodeRequest.of(request), raw, client_ip(request)),
                        headers=PRIVATE)


# ----------------------------------------------------------------------------- heartbeat
def _facts(node: CbomScanNode, body: HeartbeatBody, now: _dt.datetime) -> dict[str, Any]:
    """The node columns this heartbeat changes (only those that differ, so an idle fleet writes nothing but its
    last-seen stamp).  The clock skew is rewritten only when it moved by more than 10 s (request latency jitters it;
    signatures allow 300 s)."""
    out: dict[str, Any] = {}

    def put(column: str, value: Any) -> None:
        if value != getattr(node, column):
            out[column] = value

    put("hostname", clean_text(body.hostname, 255) or node.hostname)
    put("node_version", clean_text(body.version, 32) or node.node_version)
    if body.source_ips:
        put("source_ips", _ips(body.source_ips))
    if body.capabilities:
        put("capabilities", scrub(body.capabilities))
    skew = _clock_skew(body.clock, now)
    if skew is not None and (node.clock_skew_s is None or abs(skew - node.clock_skew_s) > 10):
        out["clock_skew_s"] = skew
    return out


def _protocol(node: CbomScanNode, body_caps: dict | None = None) -> int:
    caps = body_caps if isinstance(body_caps, dict) and body_caps else (node.capabilities or {})
    try:
        return int((caps or {}).get("protocol") or 1)
    except (TypeError, ValueError):
        return 1


def _grant_base(session: Session, node: CbomScanNode, settings, now: _dt.datetime, held: int,
                caps: dict | None = None) -> int:
    """How many more jobs this node could start now: its free slots (``max_jobs`` clamped to 1..8, less the jobs it
    holds) capped by the runnable jobs it could claim.  0 for a protocol-1 node (it polls and ignores grants)."""
    if _protocol(node, caps) < 2:
        return 0
    free = J.max_jobs_of(caps if caps else node.capabilities) - held
    if free <= 0:
        return 0
    return J.claimable_count(session, node, settings, now, cap=free)


def _heartbeat(token: str | None, req: NA.NodeRequest, raw: bytes, ip: str) -> dict:
    """One heartbeat.  An idle node on protocol 2 costs: the node read, ONE UPDATE (replay window + last seen, committed
    with the signature check), the settings read, its claimed jobs (partial index, usually none), a bounded count of
    the jobs it could run now (the runnable predicate), and a read-only commit.  No nonce row, no nonce sweep (the
    reaper's), no reap of the whole queue."""
    now = utcnow()
    seen = {"last_heartbeat_at": now, "last_seen_ip": ip}
    with NA.node_session(get_db()) as session:
        node, stamped = _authenticate(session, token, req, raw, now, touch=seen)
        body = _parse(HeartbeatBody, parse_json(raw))
        gap = (now - node.last_heartbeat_at).total_seconds() if node.last_heartbeat_at else None
        changes = _facts(node, body, now)
        if not stamped:
            changes.update(seen)
        mode_note = AG.reconcile_mode(session, node, (body.capabilities or {}).get("mode"), now)
        error = clean_text(scrub(body.last_error), 512) if body.last_error else mode_note
        if error != node.last_node_error:
            changes["last_node_error"] = error
        if error:
            log("node error", team=node.team_id, node=node.id, error=error)
        if changes:
            session.exec(update(CbomScanNode).where(CbomScanNode.id == node.id).values(**changes)
                         .execution_options(synchronize_session=False))
        running = None if body.running is None else [(r.job_id, r.lease_id) for r in body.running]
        claimed = J.claimed_jobs(session, node)
        released = J.renew_leases(session, node, now, running, claimed)
        J.reap_claimed(session, now, claimed)  # this node's own jobs past their runtime or an unconfirmed cancel
        settings = get_or_create_settings(session, node.team_id, commit=False)
        handed_back = J.requeue_unsigned_segment_jobs(session, node, claimed, now)
        cancel_ids = J.cancel_ids_for_node(session, node, settings, claimed) if claimed else []
        cancel_ids += handed_back
        if running is not None:
            # jobs the node runs but the server already ended (released, reaped, cancelled) must stop too
            live = {job_id for job_id, _lease in running}
            held = {job.id: job for job in claimed if job.status == "claimed"}
            for job_id, lease in running:
                job = held.get(job_id)
                if job is None or job.lease_id != lease:
                    cancel_ids.append(job_id)
            cancel_ids = sorted(set(cancel_ids) | (set(released) & live))
        busy = [job for job in claimed if job.status == "claimed"]
        network = any(J.is_network_job(session, job) for job in busy)
        caps = body.capabilities if isinstance(body.capabilities, dict) else None
        if _protocol(node, caps) >= 2:
            # ONE bounded count, up to the node's free slots: a protocol-2 node acts on ``claim`` only, so counting
            # 100 runnable rows (and then again for the grant) is work no answer uses.  EC2 E2a round 7: with a
            # 10,000-job queue the two counts per heartbeat were the top statement and heartbeats alone outran the box.
            free = J.max_jobs_of(caps if caps else node.capabilities) - len(busy)
            pending = J.claimable_count(session, node, settings, now, cap=max(1, free))
            base = min(pending, free) if free > 0 else 0
        else:
            pending, base = J.claimable_count(session, node, settings, now), 0
        exclusions = team_exclusions(settings)
        J.defer_closers(session)
        session.commit()
        J.run_closers(session, now)
    grant = D.get().grant(node.id, node.team_id, base) if base > 0 else 0
    if gap is not None and gap > 120:
        log("node back", team=node.team_id, node=node.id, gap_s=int(gap))
    return {"server_time": iso_z(now), "stop_all_network": settings.stop_all_network,
            "never_scan": exclusions.normalized, "pending_jobs": pending, "cancel_job_ids": cancel_ids,
            # server-driven cadence with jitter: idle 60 s; while a network job runs, every few seconds so a stop-all
            # reaches it fast; a busy node, or one just granted claims, in between (limits.heartbeat_seconds)
            "heartbeat_interval_s": LIM.heartbeat_seconds(busy=bool(busy) or grant > 0, network=network),
            # protocol 2: how many claims the node may make now (0: wait for the next answer that grants one)
            "claim": grant, "protocol": PROTOCOL}


@router.post("/cbom/node/heartbeat", dependencies=[Depends(node_limiter)], summary="Report that the node is alive")
async def heartbeat(request: Request, token: Annotated[str | None, Security(node_token_header)] = None):
    raw = await read_capped_body(request, SMALL_BODY)
    out = await _guard("heartbeat", _heartbeat, token, NA.NodeRequest.of(request), raw, client_ip(request))
    await OBS.delivered(request)
    return JSONResponse(out, headers=PRIVATE)


# ----------------------------------------------------------------------------- claim
def _claim(token: str | None, req: NA.NodeRequest, raw: bytes, ip: str) -> tuple[dict | None, int]:
    """One claim.  Every node version draws on the worker's dispatch rate before the queue is read (no permit: 204
    without touching the queue; a claim that finds nothing returns its permit).  The node row is written as the
    claim's LAST statement (last seen for protocol 1, ``last_claim_at``), so a claim plugin that mints material never
    holds it (C4).  Returns (payload or None, node id)."""
    now = utcnow()
    seen = {"last_heartbeat_at": now, "last_seen_ip": ip}
    with NA.node_session(get_db()) as session:
        node, stamped = _authenticate(session, token, req, raw, now, touch=seen)
        body = _parse(ClaimBody, parse_json(raw)) if raw else None  # older nodes send no body
        # a node restarted in agent mode may claim before its first heartbeat: it is never given a secret again
        AG.reconcile_mode(session, node, body.mode if body else None, now)
        dispatcher = D.get()
        payload, base = None, 0
        if dispatcher.admit(node.id, node.team_id):
            settings = get_or_create_settings(session, node.team_id, commit=False)
            payload = J.claim_next(session, node, settings, now)
            if payload is None:
                dispatcher.give_back()
            else:
                RT.note(job_id=payload["job"]["id"])
                base = _grant_base(session, node, settings, now, len(J.claimed_jobs(session, node)))
        stamp = {} if stamped else dict(seen)
        if payload is not None:
            stamp["last_claim_at"] = now
        if stamp:
            session.exec(update(CbomScanNode).where(CbomScanNode.id == node.id).values(**stamp)
                         .execution_options(synchronize_session=False))
        J.defer_closers(session)
        session.commit()
        J.run_closers(session, now)
    if payload is not None:
        OBS.STATS.bump("claims_committed")
        payload["claim"] = dispatcher.grant(node.id, node.team_id, base) if base > 0 else 0
    return payload, node.id  # type: ignore[return-value]


def _release_undelivered(node_id: int, payload: dict) -> bool:
    job = payload.get("job") or {}
    with Session(get_db()) as session:
        released = J.release_undelivered(session, node_id, int(job.get("id") or 0), str(job.get("lease_id") or ""),
                                         utcnow())
        session.commit()
    return released


@router.post("/cbom/node/jobs/claim", dependencies=[Depends(node_limiter)],
             summary="Claim the next job (204 when there is nothing to do, or no claim may be made now)")
async def claim(request: Request, token: Annotated[str | None, Security(node_token_header)] = None):
    raw = await read_capped_body(request, SMALL_BODY)
    payload, node_id = await _guard("claim", _claim, token, NA.NodeRequest.of(request), raw, client_ip(request))
    if payload is None:
        return Response(status_code=204, headers=PRIVATE)
    if not await OBS.delivered(request):
        # the node left before the answer was written, so it cannot hold the job: hand it back now (DA D3), without
        # counting an attempt, instead of waiting 120 s for its heartbeat to omit it
        await _guard("claim release", _release_undelivered, node_id, payload)
    return JSONResponse(payload, headers=PRIVATE)


# ----------------------------------------------------------------------------- assets
def _assets(token: str | None, job_id: int, req: NA.NodeRequest, raw: bytes) -> dict:
    now = utcnow()
    RT.note(job_id=job_id)
    with NA.node_session(get_db()) as session:
        node = authenticate_node(session, token, req, raw, now)
        body = _parse(AssetsBody, parse_json(raw))
        valid: list[dict[str, Any]] = []
        rejected = 0
        for item in body.assets:
            try:
                valid.append(AssetIn.model_validate(item).model_dump())
            except (ValidationError, TypeError):
                rejected += 1
        out = J.add_assets(session, node, job_id, body.lease_id, valid, now,
                           progress=body.progress.model_dump() if body.progress else None)
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
    out = await _guard("assets", _assets, token, job_id, NA.NodeRequest.of(request), raw)
    await OBS.delivered(request)
    return JSONResponse(out, headers=PRIVATE)


# ----------------------------------------------------------------------------- result
def _result(token: str | None, job_id: int, req: NA.NodeRequest, raw: bytes) -> dict:
    """A job's end.  No run or team row is locked or written here (the run closer and refund settlement run after
    the commit, ``jobs``); the answer grants the node its next claims."""
    now = utcnow()
    RT.note(job_id=job_id)
    with NA.node_session(get_db()) as session:
        node = authenticate_node(session, token, req, raw, now)
        body = _parse(ResultBody, parse_json(raw))
        job = J.finish_job(session, node, job_id, body.lease_id, body.status, body.result, body.error, now)
        settings = get_or_create_settings(session, node.team_id, commit=False)
        base = _grant_base(session, node, settings, now, len(J.claimed_jobs(session, node)))
        out = {"job_id": job.id, "status": job.status, "server_time": iso_z(now)}
        J.defer_closers(session)
        session.commit()
        J.run_closers(session, now)
    OBS.STATS.bump("results_committed")
    out["claim"] = D.get().grant(node.id, node.team_id, base) if base > 0 else 0
    return out


@router.post("/cbom/node/jobs/{job_id}/result", dependencies=[Depends(node_limiter)],
             summary="Report a job's result (must echo the lease id from the claim)")
async def result(job_id: int, request: Request, token: Annotated[str | None, Security(node_token_header)] = None):
    if job_id < 1 or job_id > 2_147_483_647:
        raise HTTPException(status_code=404, detail="Job not found")
    raw = await read_capped_body(request, RESULT_BODY)
    out = await _guard("result", _result, token, job_id, NA.NodeRequest.of(request), raw)
    await OBS.delivered(request)
    return JSONResponse(out, headers=PRIVATE)
