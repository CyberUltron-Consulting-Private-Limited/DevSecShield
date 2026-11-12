"""CBOM Sources: scan nodes, collection sources, settings, evidence and collection runs for a team.

All routes are ``/{team_id}/cbom/sources/...`` and need a member of that team (the existing 403 for
non-members stays).  Inside a team:

* a record of another team, or a missing record, is a 404;
* changing a source or node needs its creator or a team admin, otherwise a 400 (never a 403, which
  signs the user out of the frontend);
* team settings need an admin, except that any member may *switch on* the network stop;
* a stale form gets a 409 (``expected_version`` does not match ``row_version``).

Secrets are write-only: they are accepted in ``secrets`` on create/update, stored encrypted, and
never returned.  Responses carry ``secrets_set`` (names) instead.
"""
from __future__ import annotations

import datetime as _dt
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Header, HTTPException, Query
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse, Response
from pydantic import ValidationError
from sqlalchemy import func, update
from sqlalchemy.exc import IntegrityError
from sqlmodel import Session, select

from backend.new_models import (
    SCAN_NODE_NAME_INDEX,
    CbomCollectedAsset,
    CbomCollectionAuditEvent,
    CbomCollectionJob,
    CbomCollectionRun,
    CbomCollectionSettings,
    CbomCollectionSource,
    CbomEvidenceArea,
    CbomEvidenceVendor,
    CbomScanNode,
    Scan,
    Team,
)
from backend.utilities.cbom_sources import agents as AG
from backend.utilities.cbom_sources import jobs as J
from backend.utilities.cbom_sources import targets as T
from backend.utilities.cbom_sources.aws_validate import validate_aws_role
from backend.utilities.cbom_sources.common import audit, iso_z, log, new_ref, new_token, sha256_hex, utcnow
from backend.utilities.cbom_sources.crypto import decrypt_secrets, encrypt_secrets, scrub, warn_if_key_is_weak
from backend.utilities.cbom_sources.evidence import AREAS, CONFIDENCE, VENDOR_LINK_DAYS, clean_answers
from backend.utilities.cbom_sources.http import (
    PRIVATE,
    CbomRoute,
    ObjectId,
    TeamId,
    authorize,
    bad_request,
    bump_version,
    check_version,
    is_team_admin,
    read_limiter,
    require_admin,
    require_owner_or_admin,
    server_error,
    write_limiter,
)
from backend.utilities.cbom_sources import cdx_xml as CDX_XML
from backend.utilities.cbom_sources import inventory as INV
from backend.utilities.cbom_sources import posture as POSTURE
from backend.utilities.cbom_sources import runs as RUNS
from backend.utilities.cbom_sources import schedules as SCHED
from backend.utilities.cbom_sources.classify import ASSET_TYPES
from backend.utilities.cbom_sources.kinds import KINDS, METADATA_FIELDS, credential_target_problem, validate_secret_value
from backend.utilities.cbom_sources.planning import RATES_C, credits, node_status, plan_run, source_targets
from backend.utilities.cbom_sources.schemas import (
    AreaUpdate,
    EstimateBody,
    NodeCreate,
    NodeUpdate,
    RunCreate,
    SettingsUpdate,
    SourceCreate,
    SourceUpdate,
    StopAll,
    VendorCreate,
    VendorUpdate,
)
from backend.utilities.cbom_sources.serialize import (
    public_area,
    public_job,
    public_node,
    public_run,
    public_settings,
    public_source,
    public_vendor,
)
from backend.utilities.cbom_sources.settings import ensure_evidence_areas, get_or_create_settings
from backend.utilities.cbom_sources.templates import (
    AWS_NOT_CONFIGURED, TEMPLATE_NAMES, aws_collection_configured, cloudformation_template, template_text)

import os

router = APIRouter(tags=["cbom-sources"], route_class=CbomRoute)
AuthHeader = Annotated[str | None, Header()]
READ = [Depends(read_limiter)]
WRITE = [Depends(write_limiter)]
BASE = "/{team_id}/cbom/sources"
REGISTRATION_TTL = _dt.timedelta(hours=24)
MAX_NODES = 50
MAX_SOURCES = 500
MAX_VENDORS = 100

warn_if_key_is_weak()


async def _run(what: str, team_id: int, fn, *args) -> Any:
    try:
        return await run_in_threadpool(fn, *args)
    except HTTPException:
        raise
    except Exception as exc:
        raise server_error(f"cbom sources {what}", exc, team=team_id) from None


def _ok(payload: Any, status_code: int = 200) -> JSONResponse:
    return JSONResponse(payload, status_code=status_code, headers=PRIVATE)


def _today(now: _dt.datetime) -> _dt.date:
    return now.date()


def _get_owned(session: Session, model, object_id: int, team_id: int, what: str):
    row = session.get(model, object_id)
    if row is None or row.team_id != team_id:
        raise HTTPException(status_code=404, detail=f"{what} not found")
    return row


def _team_node(session: Session, team_id: int, node_id: int | None) -> CbomScanNode | None:
    if node_id is None:
        return None
    node = session.get(CbomScanNode, node_id)
    if node is None or node.team_id != team_id:
        raise HTTPException(status_code=400, detail="node_id: scan node not found in this team")
    return node


def _node_counts(session: Session, team_id: int, settings: CbomCollectionSettings) -> dict[int, dict[str, int]]:
    counts: dict[int, dict[str, int]] = {}
    for source in session.exec(select(CbomCollectionSource).where(CbomCollectionSource.team_id == team_id)).all():
        if source.node_id is None:
            continue
        c = counts.setdefault(source.node_id, {"targets": 0, "sources": 0})
        c["sources"] += 1
        info = source_targets(source, settings)
        if KINDS.get(source.kind) and KINDS[source.kind].group in ("servers", "network"):
            c["targets"] += int(info["units"])
        else:
            c["targets"] += 1
    return counts


# ============================================================================ overview
def _overview(engine, team_id: int, user_id: int) -> dict:
    now = utcnow()
    with Session(engine) as session:
        settings = get_or_create_settings(session, team_id)
        J.safe_reap(session, now, team_id=team_id)
        nodes = session.exec(select(CbomScanNode).where(CbomScanNode.team_id == team_id)).all()
        statuses = [node_status(n, now) for n in nodes]
        sources = session.exec(select(CbomCollectionSource).where(CbomCollectionSource.team_id == team_id)).all()
        groups: dict[str, dict[str, Any]] = {}
        for source in sources:
            spec = KINDS.get(source.kind)
            if spec is None:
                continue
            g = groups.setdefault(spec.group, {"sources": 0, "units": 0, "by_kind": {}, "failed_tests": 0})
            g["sources"] += 1
            g["units"] += int(source_targets(source, settings)["units"])
            g["by_kind"][source.kind] = g["by_kind"].get(source.kind, 0) + 1
            if source.last_test_status == "failed":
                g["failed_tests"] += 1
        everything = {"servers": True, "kubernetes": True, "databases": True, "cloud": True, "network": True}
        plan = plan_run(session, team_id, settings, now, include=everything)
        areas = ensure_evidence_areas(session, team_id)
        vendors = session.exec(select(CbomEvidenceVendor).where(CbomEvidenceVendor.team_id == team_id)).all()
        vendor_levels = [v.confidence if v.answered_at else "Q0" for v in vendors]
        area_rows = [public_area(a, _today(now), vendor_levels) for a in areas]
        by_q = {q: 0 for q in CONFIDENCE}
        for row in area_rows:
            by_q[row["effective_confidence"]] += 1
        skipped = plan.public()["skipped"]
        for node, status in zip(nodes, statuses):
            if status == "offline":
                skipped.append({"kind": "scan_node", "name": node.name, "node_id": node.id, "status": "waiting",
                                "reason": f"Scan node {node.name} is offline; its jobs wait until it reconnects"})
            elif status == "registration_expired":
                skipped.append({"kind": "scan_node", "name": node.name, "node_id": node.id, "status": "skipped",
                                "reason": f"Scan node {node.name}: registration token expired; generate a new one"})
        for row in area_rows:
            if row["effective_confidence"] == "Q0":
                skipped.append({"kind": "evidence", "name": row["title"], "area_key": row["area_key"], "status": "gap",
                                "reason": f"{row['title']} is unanswered and will appear as a Q0 gap"})
        if settings.stop_all_network:
            skipped.append({"kind": "network", "name": "Network TLS", "status": "skipped",
                            "reason": "Network scanning is stopped"})
        code_scans = session.exec(
            select(func.count()).select_from(Scan).where(Scan.team_id == team_id, Scan.scan_type == "cbom")
        ).one()
        team = session.get(Team, team_id)
        return {
            "server_time": iso_z(now),
            "viewer": {"user_id": user_id, "is_admin": is_team_admin(session, user_id, team_id)},
            "credit_balance": round(float(team.credit_balance or 0), 2) if team else 0,
            "rates": {k: credits(v) for k, v in RATES_C.items()},
            "nodes": {"total": len(nodes), "online": statuses.count("online"), "offline": statuses.count("offline"),
                      "pending": statuses.count("pending_registration") + statuses.count("registration_expired")},
            "groups": groups,
            "plan": {**plan.public(), "skipped": skipped},
            "evidence": {"areas": len(area_rows), "answered": sum(1 for r in area_rows if r["effective_confidence"] != "Q0"),
                         "by_confidence": by_q, "vendors": len(vendors)},
            "code": {"cbom_scans": int(code_scans or 0)},
            "settings": {k: v for k, v in public_settings(settings, now).items()
                         if k in ("stop_all_network", "next_window_start", "in_window_now", "window_timezone",
                                  "aws_external_id", "aws_collection_configured")} | {
                "network_exclusions": len(settings.network_exclusions or []),
                "ports": len(settings.ports or []), "sni_hostnames": len(settings.sni_hostnames or []),
                "cert_domains": len(settings.cert_domains or []),
            },
        }


@router.get(BASE + "/overview", dependencies=READ, summary="Counts, skipped items and the estimate for every tab")
async def get_overview(team_id: TeamId, Authorization: AuthHeader = None):
    engine, user = await authorize(team_id, Authorization)
    return _ok(await _run("overview", team_id, _overview, engine, team_id, user.id))


# ============================================================================ nodes
def _list_nodes(engine, team_id: int) -> dict:
    now = utcnow()
    with Session(engine) as session:
        settings = get_or_create_settings(session, team_id)
        counts = _node_counts(session, team_id, settings)
        rows = session.exec(select(CbomScanNode).where(CbomScanNode.team_id == team_id).order_by(CbomScanNode.id)).all()
        return {"server_time": iso_z(now), "nodes": [
            public_node(n, now, assigned_targets=counts.get(n.id, {}).get("targets", 0),
                        sources=counts.get(n.id, {}).get("sources", 0)) for n in rows]}


@router.get(BASE + "/nodes", dependencies=READ, summary="List scan nodes")
async def list_nodes(team_id: TeamId, Authorization: AuthHeader = None):
    engine, _user = await authorize(team_id, Authorization)
    return _ok(await _run("list nodes", team_id, _list_nodes, engine, team_id))


def _raise_if_name_taken(exc: IntegrityError, name: str) -> None:
    """409 when the unique (team, lower(name)) index refused the row (new_models.SCAN_NODE_NAME_INDEX)."""
    if SCAN_NODE_NAME_INDEX in str(exc.orig) or "cbomscannode.team_id, lower(name)" in str(exc.orig).lower():
        raise HTTPException(status_code=409, detail=f"A scan node named {name} already exists") from None


def _create_node(engine, team_id: int, user_id: int, body: NodeCreate) -> dict:
    now = utcnow()
    with Session(engine) as session:
        existing = session.exec(select(CbomScanNode).where(CbomScanNode.team_id == team_id)).all()
        # agent-mode nodes (one per Kubernetes node of a DaemonSet) have their own cap (agents.MAX_AGENT_NODES)
        if sum(1 for n in existing if not AG.is_agent(n)) >= MAX_NODES:
            raise HTTPException(status_code=400, detail=f"A team can have at most {MAX_NODES} scan nodes")
        if any(n.name.lower() == body.name.lower() for n in existing):
            raise HTTPException(status_code=409, detail=f"A scan node named {body.name} already exists")
        token = new_token("zsr_")
        node = CbomScanNode(
            team_id=team_id, owner_user_id=user_id, updated_by_user_id=user_id, name=body.name, segment=body.segment,
            timezone=body.timezone, deployment=body.deployment, proxy_url=body.proxy_url,
            proxy_ca_pem=body.proxy_ca_pem, proxy_tls_inspect=body.proxy_tls_inspect,
            registration_token_hash=sha256_hex(token), registration_issued_at=now,
            registration_expires_at=now + REGISTRATION_TTL, created_at=now, last_updated=now,
        )
        try:
            session.add(node)
            session.flush()
            audit(session, team_id=team_id, actor_type="user", actor_id=user_id, action="node.create",
                  object_type="node", object_id=node.id, changed_fields=body.model_fields_set)
            session.commit()
        except IntegrityError as exc:  # a concurrent create with the same name won (the check above is not atomic)
            session.rollback()
            _raise_if_name_taken(exc, body.name)
            raise
        session.refresh(node)
        log("node created", team=team_id, node=node.id, by=user_id)
        return {"node": public_node(node, now), "registration_token": token}


@router.post(BASE + "/nodes", dependencies=WRITE, summary="Add a scan node; returns a one-time registration token")
async def create_node(team_id: TeamId, body: NodeCreate, Authorization: AuthHeader = None):
    engine, user = await authorize(team_id, Authorization)
    return _ok(await _run("create node", team_id, _create_node, engine, team_id, user.id, body), 201)


def _get_node(engine, team_id: int, node_id: int) -> dict:
    now = utcnow()
    with Session(engine) as session:
        node = _get_owned(session, CbomScanNode, node_id, team_id, "Scan node")
        settings = get_or_create_settings(session, team_id)
        counts = _node_counts(session, team_id, settings).get(node.id, {})
        return {"node": public_node(node, now, assigned_targets=counts.get("targets", 0), sources=counts.get("sources", 0)),
                "server_time": iso_z(now)}


@router.get(BASE + "/nodes/{node_id}", dependencies=READ, summary="Get a scan node")
async def get_node(team_id: TeamId, node_id: ObjectId, Authorization: AuthHeader = None):
    engine, _user = await authorize(team_id, Authorization)
    return _ok(await _run("get node", team_id, _get_node, engine, team_id, node_id))


def _update_node(engine, team_id: int, user_id: int, node_id: int, body: NodeUpdate) -> dict:
    now = utcnow()
    with Session(engine) as session:
        node = _get_owned(session, CbomScanNode, node_id, team_id, "Scan node")
        require_owner_or_admin(session, user_id, team_id, node.owner_user_id, "scan node")
        check_version(node, body.expected_version)
        changes = body.model_dump(exclude_unset=True, exclude={"expected_version"})
        if "name" in changes and changes["name"] and changes["name"].lower() != node.name.lower():
            clash = session.exec(select(CbomScanNode).where(CbomScanNode.team_id == team_id)).all()
            if any(n.id != node.id and n.name.lower() == changes["name"].lower() for n in clash):
                raise HTTPException(status_code=409, detail=f"A scan node named {changes['name']} already exists")
        for key, value in changes.items():
            if key == "name" and not value:
                continue
            setattr(node, key, value)
        node.row_version += 1
        node.updated_by_user_id = user_id
        node.last_updated = now
        session.add(node)
        audit(session, team_id=team_id, actor_type="user", actor_id=user_id, action="node.update",
              object_type="node", object_id=node.id, changed_fields=changes.keys())
        try:
            session.commit()
        except IntegrityError as exc:  # a concurrent create or rename took the name
            session.rollback()
            _raise_if_name_taken(exc, changes.get("name") or node.name)
            raise
        session.refresh(node)
        log("node updated", team=team_id, node=node.id, by=user_id)
        return {"node": public_node(node, now)}


@router.patch(BASE + "/nodes/{node_id}", dependencies=WRITE, summary="Edit a scan node")
async def update_node(team_id: TeamId, node_id: ObjectId, body: NodeUpdate, Authorization: AuthHeader = None):
    engine, user = await authorize(team_id, Authorization)
    return _ok(await _run("update node", team_id, _update_node, engine, team_id, user.id, node_id, body))


POOL_NODE_NO_TOKEN = ("This node belongs to an agent pool: its pod enrolls again by itself with the pool token, so it "
                      "never needs a registration token. Use Reset if its credential may have leaked.")


def _new_registration(engine, team_id: int, user_id: int, node_id: int, reset: bool) -> dict:
    now = utcnow()
    with Session(engine) as session:
        node = _get_owned(session, CbomScanNode, node_id, team_id, "Scan node")
        require_owner_or_admin(session, user_id, team_id, node.owner_user_id, "scan node")
        # A node of an agent pool (a DaemonSet pod) takes itself back with the pool token once its credential is
        # revoked (agents.node_to_rebind), so a reset issues no registration token for it: one would only be shown
        # as a standalone install command for a pod (lab UI r1 N1) and be a second way to take the node.  A node
        # whose pool was deleted (pool_id set to NULL) is a standalone node again and gets a token as before.
        pooled = node.pool_id is not None
        if pooled and not reset:
            raise HTTPException(status_code=409, detail=POOL_NODE_NO_TOKEN)
        token = None if pooled else new_token("zsr_")
        values = dict(registration_token_hash=sha256_hex(token) if token else None,
                      registration_issued_at=now if token else None,
                      registration_expires_at=now + REGISTRATION_TTL if token else None,
                      row_version=node.row_version + 1, updated_by_user_id=user_id, last_updated=now)
        stmt = update(CbomScanNode).where(CbomScanNode.id == node.id, CbomScanNode.team_id == team_id)
        if reset:
            values.update(node_token_hash=None, enrolled_at=None, last_heartbeat_at=None)
        else:
            stmt = stmt.where(CbomScanNode.enrolled_at.is_(None), CbomScanNode.node_token_hash.is_(None))  # type: ignore[union-attr]
        if session.exec(stmt.values(**values)).rowcount != 1:
            raise HTTPException(status_code=409, detail="This node has already registered. Use Reset to register it again.")
        if reset:
            session.exec(
                update(CbomCollectionJob)
                .where(CbomCollectionJob.node_id == node.id, CbomCollectionJob.status == "claimed")
                .values(status="pending", lease_id=None, lease_expires_at=None)
            )
        audit(session, team_id=team_id, actor_type="user", actor_id=user_id,
              action="node.reset" if reset else "node.token", object_type="node", object_id=node.id)
        session.commit()
        session.refresh(node)
        log("node reset" if reset else "node token regenerated", team=team_id, node=node.id, by=user_id,
            pool=node.pool_id)
        # None for a pool node: nothing to copy, its pod enrolls again by itself
        return {"node": public_node(node, now), "registration_token": token}


@router.post(BASE + "/nodes/{node_id}/registration-token", dependencies=WRITE,
             summary="Issue a new registration token for a node that has not registered")
async def regenerate_token(team_id: TeamId, node_id: ObjectId, Authorization: AuthHeader = None):
    engine, user = await authorize(team_id, Authorization)
    return _ok(await _run("node token", team_id, _new_registration, engine, team_id, user.id, node_id, False))


@router.post(BASE + "/nodes/{node_id}/reset", dependencies=WRITE,
             summary="Revoke the node's credential and issue a new registration token (none for an agent pool node)")
async def reset_node(team_id: TeamId, node_id: ObjectId, Authorization: AuthHeader = None):
    engine, user = await authorize(team_id, Authorization)
    return _ok(await _run("node reset", team_id, _new_registration, engine, team_id, user.id, node_id, True))


def _delete_node(engine, team_id: int, user_id: int, node_id: int) -> dict:
    now = utcnow()
    with Session(engine) as session:
        node = _get_owned(session, CbomScanNode, node_id, team_id, "Scan node")
        require_owner_or_admin(session, user_id, team_id, node.owner_user_id, "scan node")
        users = session.exec(select(CbomCollectionSource).where(CbomCollectionSource.node_id == node.id)).all()
        if AG.is_agent(node):  # an agent node's own host source goes with it (it can serve no other node)
            for source in [s for s in users if s.kind == AG.HOST_KIND]:
                _remove_source(session, source, team_id, user_id, now)
            session.flush()
            users = [s for s in users if s.kind != AG.HOST_KIND]
        if users:
            names = ", ".join(s.name for s in users[:5]) + (" and more" if len(users) > 5 else "")
            raise HTTPException(status_code=400, detail=f"Move or delete the sources that use this node first: {names}")
        for job in session.exec(select(CbomCollectionJob).where(CbomCollectionJob.node_id == node.id)).all():
            if job.status in J.OPEN:
                job.status, job.finished_at, job.error = "cancelled", now, "Scan node deleted"
                if job.kind == "collect":
                    J.refund_job(session, job, session.get(CbomCollectionRun, job.run_id) if job.run_id else None)
            job.params = {**(job.params or {}), "node_name": node.name}
            job.node_id = None
            session.add(job)
        session.flush()
        audit(session, team_id=team_id, actor_type="user", actor_id=user_id, action="node.delete",
              object_type="node", object_id=node.id)
        session.delete(node)
        session.commit()
        log("node deleted", team=team_id, node=node_id, by=user_id)
        return {"deleted": node_id}


@router.delete(BASE + "/nodes/{node_id}", dependencies=WRITE, summary="Delete a scan node with no sources")
async def delete_node(team_id: TeamId, node_id: ObjectId, Authorization: AuthHeader = None):
    engine, user = await authorize(team_id, Authorization)
    return _ok(await _run("delete node", team_id, _delete_node, engine, team_id, user.id, node_id))


# ============================================================================ sources
def _validate_config(kind: str, config: dict[str, Any]):
    spec = KINDS[kind]
    try:
        return spec.model.model_validate(config)
    except ValidationError as exc:
        err = bad_request(exc)
        raise err from None
    except ValueError as exc:
        raise bad_request(exc) from None


def _check_refs(session: Session, team_id: int, kind: str, cfg: Any) -> None:
    ref = getattr(cfg, "cloud_source_id", None) if kind == "kubernetes" else getattr(cfg, "aws_source_id", None) if kind == "ca_connector" else None
    if ref is None:
        return
    target = session.get(CbomCollectionSource, ref)
    wanted = ("aws_account", "azure_subscription", "gcp_project") if kind == "kubernetes" else ("aws_account",)
    if target is None or target.team_id != team_id or target.kind not in wanted:
        raise HTTPException(status_code=400, detail="The linked cloud account was not found in this team")


def _merge_secrets(kind: str, cfg: Any, current: dict[str, str], provided: dict[str, str], *,
                   clear: list[str], reset: bool, where_changed: bool) -> dict[str, str]:
    spec = KINDS[kind]
    required = spec.secret_fields(cfg)
    allowed = required | set(spec.optional_secrets)
    result = {} if reset else {k: v for k, v in current.items() if k in allowed}
    for name in clear:
        result.pop(name, None)
    for name, value in provided.items():
        if value == "":
            continue
        if name not in allowed:
            raise HTTPException(status_code=400, detail=f"secrets.{name}: not used by this credential type")
        try:
            result[name] = validate_secret_value(name, value)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=f"secrets.{exc}") from None
    missing = sorted(required - set(result))
    if missing:
        if where_changed and current:
            raise HTTPException(status_code=400, detail=f"secrets.{missing[0]}: re-enter it; stored credentials are cleared when the target or the way its identity is checked changes")
        raise HTTPException(status_code=400, detail=f"secrets.{missing[0]}: required for this credential type")
    return result


def _queue_test(session: Session, source: CbomCollectionSource, settings, user_id: int, now) -> dict | None:
    spec = KINDS[source.kind]
    cfg = spec.model.model_validate(source.config or {})
    if not (spec.needs_node(cfg) and spec.collectable(cfg)):
        return None
    if source.node_id is None:
        raise HTTPException(status_code=400, detail="Assign a scan node before testing")
    job = J.create_test_job(session, source, settings, user_id, now)
    return {"job_id": job.id}


def _create_source(engine, team_id: int, user_id: int, body: SourceCreate) -> dict:
    now = utcnow()
    spec = KINDS[body.kind]
    cfg = _validate_config(body.kind, body.config)
    with Session(engine) as session:
        settings = get_or_create_settings(session, team_id)
        total = session.exec(select(func.count()).select_from(CbomCollectionSource)
                             .where(CbomCollectionSource.team_id == team_id)).one()
        if total >= MAX_SOURCES:
            raise HTTPException(status_code=400, detail=f"A team can have at most {MAX_SOURCES} sources")
        needs_node = spec.needs_node(cfg)
        if needs_node and body.node_id is None:
            raise HTTPException(status_code=400, detail="node_id: choose the scan node that reaches these targets")
        node = _team_node(session, team_id, body.node_id if needs_node else None)
        AG.check_node_for_kind(node, body.kind)
        _check_refs(session, team_id, body.kind, cfg)
        if getattr(cfg, "credential_type", None) == "vault":
            require_admin(session, user_id, team_id, "sources that read their credential from a vault")
        secrets_ = _merge_secrets(body.kind, cfg, {}, body.secrets, clear=[], reset=True, where_changed=False)
        problem = credential_target_problem(body.kind, cfg, secrets_)
        if problem:
            raise HTTPException(status_code=400, detail=problem)
        source = CbomCollectionSource(
            team_id=team_id, owner_user_id=user_id, updated_by_user_id=user_id, kind=body.kind, name=body.name,
            name_lower=body.name.lower(), node_id=node.id if node else None, enabled=body.enabled,
            config=cfg.model_dump(mode="json"), secret_encrypted=encrypt_secrets(secrets_),
            secret_fields=sorted(secrets_), created_at=now, last_updated=now,
            last_test_status="never" if spec.collectable(cfg) or body.kind == "aws_account" else "not_available",
        )
        session.add(source)
        try:
            session.flush()
        except IntegrityError:
            session.rollback()
            raise HTTPException(status_code=409, detail=f"A {spec.label.lower()} named {body.name} already exists") from None
        test = None
        if body.test_after_save and body.kind not in _LIVE_TESTS:
            test = _queue_test(session, source, settings, user_id, now)
        audit(session, team_id=team_id, actor_type="user", actor_id=user_id, action="source.create",
              object_type="source", object_id=source.id,
              changed_fields=["kind", "name", "config", "node_id"] + [f"secrets.{k}" for k in secrets_])
        session.commit()
        session.refresh(source)
        log("source created", team=team_id, source=source.id, kind=source.kind, by=user_id)
        return {"source": public_source(source, settings, node, now), "test": test}


@router.post(BASE + "/items", dependencies=WRITE, summary="Add a source (secrets are write-only)")
async def create_source(team_id: TeamId, body: SourceCreate, Authorization: AuthHeader = None):
    engine, user = await authorize(team_id, Authorization)
    result = await _run("create source", team_id, _create_source, engine, team_id, user.id, body)
    if body.test_after_save and body.kind in _LIVE_TESTS:
        result["test"] = await _run("test source", team_id, _LIVE_TESTS[body.kind], engine, team_id, user.id, result["source"]["id"])
        result["source"] = (await _run("get source", team_id, _get_source, engine, team_id, result["source"]["id"]))["source"]
    return _ok(result, 201)


def _list_sources(engine, team_id: int, kind: str | None, group: str | None) -> dict:
    now = utcnow()
    with Session(engine) as session:
        settings = get_or_create_settings(session, team_id)
        query = select(CbomCollectionSource).where(CbomCollectionSource.team_id == team_id)
        if kind:
            query = query.where(CbomCollectionSource.kind == kind)
        rows = session.exec(query.order_by(CbomCollectionSource.id)).all()
        if group:
            rows = [r for r in rows if KINDS.get(r.kind) and KINDS[r.kind].group == group]
        nodes = {n.id: n for n in session.exec(select(CbomScanNode).where(CbomScanNode.team_id == team_id)).all()}
        return {"server_time": iso_z(now),
                "sources": [public_source(r, settings, nodes.get(r.node_id), now) for r in rows]}


@router.get(BASE + "/items", dependencies=READ, summary="List sources")
async def list_sources(team_id: TeamId, kind: str | None = Query(default=None, max_length=32),
                       group: str | None = Query(default=None, max_length=32), Authorization: AuthHeader = None):
    engine, _user = await authorize(team_id, Authorization)
    if kind is not None and kind not in KINDS:
        raise HTTPException(status_code=400, detail="kind: unknown source kind")
    return _ok(await _run("list sources", team_id, _list_sources, engine, team_id, kind, group))


def _get_source(engine, team_id: int, source_id: int) -> dict:
    now = utcnow()
    with Session(engine) as session:
        source = _get_owned(session, CbomCollectionSource, source_id, team_id, "Source")
        settings = get_or_create_settings(session, team_id)
        node = session.get(CbomScanNode, source.node_id) if source.node_id else None
        return {"source": public_source(source, settings, node, now), "server_time": iso_z(now)}


@router.get(BASE + "/items/{source_id}", dependencies=READ, summary="Get a source")
async def get_source(team_id: TeamId, source_id: ObjectId, Authorization: AuthHeader = None):
    engine, _user = await authorize(team_id, Authorization)
    return _ok(await _run("get source", team_id, _get_source, engine, team_id, source_id))


def _update_source(engine, team_id: int, user_id: int, source_id: int, body: SourceUpdate) -> dict:
    now = utcnow()
    with Session(engine) as session:
        source = _get_owned(session, CbomCollectionSource, source_id, team_id, "Source")
        require_owner_or_admin(session, user_id, team_id, source.owner_user_id, "source")
        check_version(source, body.expected_version)
        if body.kind is not None and body.kind != source.kind:
            raise HTTPException(status_code=400, detail="kind: a source's kind cannot be changed; add a new source")
        settings = get_or_create_settings(session, team_id)
        spec = KINDS[source.kind]
        old_cfg = _validate_config(source.kind, source.config or {}) if source.config else None
        incoming = body.config
        if isinstance(incoming, dict) and old_cfg is not None:
            # the source forms send their own fields only: keep the metadata set elsewhere (business criticality and
            # exposure on Review & Run, ...) unless the request names it (send null to clear)
            incoming = {**{f: getattr(old_cfg, f, None) for f in METADATA_FIELDS if f not in incoming}, **incoming}
        cfg = _validate_config(source.kind, incoming) if incoming is not None else old_cfg
        if cfg is None:
            raise HTTPException(status_code=400, detail="The source settings are required")
        changed: set[str] = set()
        new_node_id = source.node_id
        if body.clear_node:
            new_node_id = None
        elif "node_id" in body.model_fields_set and body.node_id is not None:
            new_node_id = _team_node(session, team_id, body.node_id).id  # type: ignore[union-attr]
        if not spec.needs_node(cfg):
            new_node_id = None
        elif new_node_id is None:
            raise HTTPException(status_code=400, detail="node_id: choose the scan node that reaches these targets")
        if new_node_id != source.node_id:
            AG.check_node_for_kind(session.get(CbomScanNode, new_node_id) if new_node_id else None, source.kind)
        _check_refs(session, team_id, source.kind, cfg)
        old_dump = old_cfg.model_dump(mode="json") if old_cfg else {}
        new_dump = cfg.model_dump(mode="json")
        conn_before = J.connection_version(source)
        where_changed = new_node_id != source.node_id or any(old_dump.get(f) != new_dump.get(f) for f in spec.where_fields)
        credential_changed = old_dump.get("credential_type") != new_dump.get("credential_type") or (
            old_cfg is not None and spec.secret_fields(old_cfg) != spec.secret_fields(cfg))
        current = decrypt_secrets(source.secret_encrypted)
        provided = {k: v for k, v in body.secrets.items() if v != ""}
        reset = credential_changed or (where_changed and bool(current))
        merged = _merge_secrets(source.kind, cfg, current, provided, clear=body.clear_secrets, reset=reset,
                                where_changed=where_changed)
        # Renaming or disabling never needs these checks, so a source saved before the rules can still be turned off.
        relevant = new_dump != old_dump or bool(provided) or new_node_id != source.node_id
        if relevant and new_dump.get("credential_type") == "vault":
            require_admin(session, user_id, team_id, "sources that read their credential from a vault")
        problem = credential_target_problem(source.kind, cfg, merged) if relevant else None
        if problem:
            raise HTTPException(status_code=400, detail=problem)
        if merged != current:
            changed |= {f"secrets.{k}" for k in set(merged) | set(current)}
            source.secret_encrypted = encrypt_secrets(merged)
            source.secret_fields = sorted(merged)
        if new_dump != old_dump:
            changed |= {f"config.{k}" for k in set(new_dump) | set(old_dump) if new_dump.get(k) != old_dump.get(k)}
            source.config = new_dump
        if new_node_id != source.node_id:
            changed.add("node_id")
            source.node_id = new_node_id
        if body.name is not None and body.name != source.name:
            changed.add("name")
            source.name, source.name_lower = body.name, body.name.lower()
        if body.enabled is not None and body.enabled != source.enabled:
            changed.add("enabled")
            source.enabled = body.enabled
        test = None
        if changed:
            source.updated_by_user_id = user_id
            source.last_updated = now
            # a rename or a metadata edit (criticality, exposure, ...) changes neither what a sweep may touch nor how it
            # connects, so queued and running jobs and the connection test are kept
            connection_changed = J.connection_version(source) != conn_before
            if connection_changed or "enabled" in changed:
                J.stop_discoveries_using(session, source, now, "A range in this discovery was changed")
            if connection_changed:
                J.cancel_open_jobs(session, source, now, reason="Source changed")
                source.last_test_status = "never" if spec.collectable(cfg) or source.kind == "aws_account" else "not_available"
                source.last_test_summary, source.last_test_at, source.last_test_job_id = None, None, None
                source.last_test_result = {}
            session.add(source)
            try:
                session.flush()
            except IntegrityError:
                session.rollback()
                raise HTTPException(status_code=409, detail=f"A {spec.label.lower()} named {body.name} already exists") from None
            # the edit version (optimistic locking; jobs check the connection version), after the flush above so a
            # duplicate name is still that 409, not an error inside this compare-and-set
            bump_version(session, source)
            audit(session, team_id=team_id, actor_type="user", actor_id=user_id, action="source.update",
                  object_type="source", object_id=source.id, changed_fields=changed)
        if body.test_after_save and source.kind not in _LIVE_TESTS:
            test = _queue_test(session, source, settings, user_id, now)
        session.commit()
        session.refresh(source)
        node = session.get(CbomScanNode, source.node_id) if source.node_id else None
        if changed:
            log("source updated", team=team_id, source=source.id, by=user_id, fields=len(changed))
        return {"source": public_source(source, settings, node, now), "test": test}


@router.patch(BASE + "/items/{source_id}", dependencies=WRITE, summary="Edit a source (blank secrets keep the stored ones)")
async def update_source(team_id: TeamId, source_id: ObjectId, body: SourceUpdate, Authorization: AuthHeader = None):
    engine, user = await authorize(team_id, Authorization)
    result = await _run("update source", team_id, _update_source, engine, team_id, user.id, source_id, body)
    if body.test_after_save and result["source"]["kind"] in _LIVE_TESTS:
        result["test"] = await _run("test source", team_id, _LIVE_TESTS[result["source"]["kind"]], engine, team_id, user.id, source_id)
        result["source"] = (await _run("get source", team_id, _get_source, engine, team_id, source_id))["source"]
    return _ok(result)


def _delete_source(engine, team_id: int, user_id: int, source_id: int) -> dict:
    now = utcnow()
    with Session(engine) as session:
        source = _get_owned(session, CbomCollectionSource, source_id, team_id, "Source")
        require_owner_or_admin(session, user_id, team_id, source.owner_user_id, "source")
        _remove_source(session, source, team_id, user_id, now)
        session.commit()
        log("source deleted", team=team_id, source=source_id, by=user_id)
        return {"deleted": source_id}


def _remove_source(session: Session, source: CbomCollectionSource, team_id: int, user_id: int, now) -> None:
    """Delete a source in the caller's transaction: its open jobs end, its runs and assets stay (unlinked)."""
    J.cancel_open_jobs(session, source, now, reason="Source deleted")
    J.stop_discoveries_using(session, source, now, "A range in this discovery was deleted")
    for job in session.exec(select(CbomCollectionJob).where(CbomCollectionJob.source_id == source.id)).all():
        # the stable uid stays on the job, so the deleted source's runs still compare with each other
        job.params = {**(job.params or {}), "source_name": source.name,
                      "source_uid": (job.params or {}).get("source_uid") or source.source_uid}
        job.source_id = None
        session.add(job)
    # collected assets stay with their run; only the link to the deleted source goes
    session.exec(update(CbomCollectedAsset).where(CbomCollectedAsset.source_id == source.id).values(source_id=None))
    session.flush()
    audit(session, team_id=team_id, actor_type="user", actor_id=user_id, action="source.delete",
          object_type="source", object_id=source.id)
    session.delete(source)


@router.delete(BASE + "/items/{source_id}", dependencies=WRITE, summary="Delete a source")
async def delete_source(team_id: TeamId, source_id: ObjectId, Authorization: AuthHeader = None):
    engine, user = await authorize(team_id, Authorization)
    return _ok(await _run("delete source", team_id, _delete_source, engine, team_id, user.id, source_id))


def _test_source(engine, team_id: int, user_id: int, source_id: int) -> dict:
    now = utcnow()
    with Session(engine) as session:
        source = _get_owned(session, CbomCollectionSource, source_id, team_id, "Source")
        require_owner_or_admin(session, user_id, team_id, source.owner_user_id, "source")
        settings = get_or_create_settings(session, team_id)
        spec = KINDS[source.kind]
        cfg = _validate_config(source.kind, source.config or {})
        if source.kind == "aws_account":
            return {"aws": True}
        if source.kind == "idp":
            return {"idp": True}
        if source.kind in ("azure_subscription", "gcp_project"):
            return {"cloud_http": True}
        if not (spec.needs_node(cfg) and spec.collectable(cfg)):
            source.last_test_status = "not_available"
            source.last_test_summary = "Validation for this source is not available yet"
            source.last_test_at = now
            session.add(source)
            session.commit()
            return {"status": "not_available", "message": source.last_test_summary}
        job = J.create_test_job(session, source, settings, user_id, now)
        audit(session, team_id=team_id, actor_type="user", actor_id=user_id, action="source.test",
              object_type="source", object_id=source.id)
        session.commit()
        session.refresh(job)
        node = session.get(CbomScanNode, job.node_id) if job.node_id else None
        log("test queued", team=team_id, source=source.id, job=job.id, by=user_id)
        return {"status": "queued", "job": public_job(job, node, settings, now, source)}


def _save_live_test(engine, team_id: int, user_id: int, source_id: int, version: str, action: str, now,
                    status: str, summary: str, result: dict) -> bool:
    """Store a live test's result only while the source still connects the way it did when the test started (its
    connection version): a rename or a metadata save during the test keeps the result, a connection change (which
    reset the test) drops it.  The row is locked while it is checked and written (PostgreSQL), so that edit cannot
    commit in between and have its reset written over."""
    with Session(engine) as session:
        source = session.exec(select(CbomCollectionSource).where(CbomCollectionSource.id == source_id)
                              .with_for_update()).first()
        if source is None or J.connection_version(source) != version:
            return False
        source.last_test_status, source.last_test_summary, source.last_test_at = status, summary[:512], now
        source.last_test_result = result
        session.add(source)
        audit(session, team_id=team_id, actor_type="user", actor_id=user_id, action=action, object_type="source",
              object_id=source_id)
        session.commit()
        return True


def _test_aws(engine, team_id: int, user_id: int, source_id: int) -> dict:
    with Session(engine) as session:
        source = _get_owned(session, CbomCollectionSource, source_id, team_id, "Source")
        require_owner_or_admin(session, user_id, team_id, source.owner_user_id, "source")
        if source.kind != "aws_account":
            raise HTTPException(status_code=400, detail="Not an AWS account")
        settings = get_or_create_settings(session, team_id)
        cfg = dict(source.config or {})
        version, external_id = J.connection_version(source), settings.aws_external_id
    result = validate_aws_role(team_id, cfg.get("role_arn", ""), external_id, cfg.get("regions") or [], cfg.get("scope", "account"),
                               lambda_cmk=bool(cfg.get("decrypt_lambda_cmk")), read_glue=bool(cfg.get("read_glue")))
    now = utcnow()
    passed = sum(1 for c in result["checks"] if c["status"] == "pass")
    _save_live_test(engine, team_id, user_id, source_id, version, "source.validate", now, result["status"],
                    f"{passed} of {len(result['checks'])} checks passed",
                    {k: v for k, v in result.items() if k in ("checks", "member_accounts", "status")})
    log("aws validated", team=team_id, source=source_id, status=result["status"], by=user_id)
    return {"status": result["status"], "checks": result["checks"], "member_accounts": result.get("member_accounts"),
            "validated_at": iso_z(now)}


def _test_idp(engine, team_id: int, user_id: int, source_id: int) -> dict:
    """Read the IdP's public metadata now (no job): it is what collection will read."""
    from backend.utilities.cbom_sources.idp_collect import collect_idp

    with Session(engine) as session:
        source = _get_owned(session, CbomCollectionSource, source_id, team_id, "Source")
        require_owner_or_admin(session, user_id, team_id, source.owner_user_id, "source")
        cfg, version, name = dict(source.config or {}), J.connection_version(source), source.name
    out = collect_idp(cfg, name)
    keys = sum(1 for a in out["assets"] if a["type"] == "signing_key")
    ok = out["counts"]["ok"]
    status = "passed" if ok == out["counts"]["total"] and ok else ("partial" if ok else "failed")
    summary = (f"Read {ok} of {out['counts']['total']} metadata documents; {keys} signing key(s) found"
               if ok else "Could not read the metadata: " + "; ".join(t["error"] or "" for t in out["targets"])[:400])
    now = utcnow()
    _save_live_test(engine, team_id, user_id, source_id, version, "source.test", now, status, summary,
                    {"targets": out["targets"], "signing_keys": keys})
    log("idp tested", team=team_id, source=source_id, status=status, keys=keys, by=user_id)
    return {"status": status, "message": summary, "targets": out["targets"], "tested_at": iso_z(now)}


def _test_cloud_http(engine, team_id: int, user_id: int, source_id: int) -> dict:
    """Azure / Google Cloud: sign in and make one list call now (no job); the same calls collection starts with."""
    from backend.utilities.cbom_sources.azure_collect import test_azure
    from backend.utilities.cbom_sources.gcp_collect import test_gcp

    with Session(engine) as session:
        source = _get_owned(session, CbomCollectionSource, source_id, team_id, "Source")
        require_owner_or_admin(session, user_id, team_id, source.owner_user_id, "source")
        if source.kind not in ("azure_subscription", "gcp_project"):
            raise HTTPException(status_code=400, detail="Not an Azure or Google Cloud source")
        kind, cfg, version = source.kind, dict(source.config or {}), J.connection_version(source)
        secrets_ = decrypt_secrets(source.secret_encrypted)
    known = list(secrets_.values())
    try:
        out = (test_azure if kind == "azure_subscription" else test_gcp)(cfg, secrets_)
    except Exception as exc:  # never a 500 for a provider answer we did not expect
        ref = new_ref()
        log("cloud test FAILED", ref=ref, team=team_id, source=source_id, error=type(exc).__name__)
        out = {"status": "error", "message": f"ZeroShield could not run the checks (ref {ref})", "checks": []}
    secrets_ = {}
    out["message"] = str(scrub(out.get("message") or "", known))[:512]
    out["checks"] = [{**c, "detail": str(scrub(c.get("detail") or "", known))[:300]} for c in out.get("checks") or []]
    now = utcnow()
    passed = sum(1 for c in out["checks"] if c["status"] == "pass")
    _save_live_test(engine, team_id, user_id, source_id, version, "source.validate", now, out["status"],
                    f"{passed} of {len(out['checks'])} checks passed" if out["checks"] else out["message"],
                    {"checks": out["checks"], "status": out["status"]})
    log("cloud source tested", team=team_id, source=source_id, kind=kind, status=out["status"], by=user_id)
    return {"status": out["status"], "message": out["message"], "checks": out["checks"], "validated_at": iso_z(now)}


# Sources whose test runs live from the API (no scan node job).
_LIVE_TESTS = {"aws_account": _test_aws, "azure_subscription": _test_cloud_http, "gcp_project": _test_cloud_http}


@router.post(BASE + "/items/{source_id}/test", dependencies=WRITE,
             summary="Test a source: a job for its scan node, live AWS / Azure / Google Cloud checks, or a read of the IdP's public metadata")
async def test_source(team_id: TeamId, source_id: ObjectId, Authorization: AuthHeader = None):
    engine, user = await authorize(team_id, Authorization)
    result = await _run("test source", team_id, _test_source, engine, team_id, user.id, source_id)
    if result.get("aws"):
        result = await _run("validate aws", team_id, _test_aws, engine, team_id, user.id, source_id)
    elif result.get("idp"):
        result = await _run("test idp", team_id, _test_idp, engine, team_id, user.id, source_id)
    elif result.get("cloud_http"):
        result = await _run("test cloud", team_id, _test_cloud_http, engine, team_id, user.id, source_id)
    return _ok(result)


def _count_targets(body: dict) -> dict:
    try:
        parsed = T.parse_targets(body.get("targets") or [], allow_empty=True)
        excl = T.parse_exclusions(body.get("exclusions") or [])
    except T.TargetError as exc:
        return {"valid": False, "error": str(exc), "count": None}
    return {"valid": True, "error": None, "count": T.count_in_scope(parsed, excl), "lines": len(parsed.normalized),
            "samples": T.sample_targets(parsed, excl, 5)}


@router.post(BASE + "/targets/count", dependencies=READ, summary="Count targets after exclusions (no side effects)")
async def count_targets(team_id: TeamId, body: dict, Authorization: AuthHeader = None):
    await authorize(team_id, Authorization)
    if not isinstance(body.get("targets", []), (list, str)) or not isinstance(body.get("exclusions", []), (list, str)):
        raise HTTPException(status_code=400, detail="targets and exclusions must be lists of lines")
    return _ok(await _run("count targets", team_id, _count_targets, body))


# ============================================================================ jobs
def _get_job(engine, team_id: int, job_id: int) -> dict:
    now = utcnow()
    with Session(engine) as session:
        job = _get_owned(session, CbomCollectionJob, job_id, team_id, "Job")
        J.safe_reap(session, now, team_id=team_id)
        session.refresh(job)
        settings = get_or_create_settings(session, team_id)
        node = session.get(CbomScanNode, job.node_id) if job.node_id else None
        source = session.get(CbomCollectionSource, job.source_id) if job.source_id else None
        return {"job": public_job(job, node, settings, now, source)}


@router.get(BASE + "/jobs/{job_id}", dependencies=READ, summary="Poll a job")
async def get_job(team_id: TeamId, job_id: ObjectId, Authorization: AuthHeader = None):
    engine, _user = await authorize(team_id, Authorization)
    return _ok(await _run("get job", team_id, _get_job, engine, team_id, job_id))


# ============================================================================ settings
def _get_settings(engine, team_id: int) -> dict:
    now = utcnow()
    with Session(engine) as session:
        return {"settings": public_settings(get_or_create_settings(session, team_id), now)}


@router.get(BASE + "/settings", dependencies=READ, summary="Network scope, safety, certificate domains, AWS external ID")
async def get_settings(team_id: TeamId, Authorization: AuthHeader = None):
    engine, _user = await authorize(team_id, Authorization)
    return _ok(await _run("get settings", team_id, _get_settings, engine, team_id))


def _norm_hostnames(values: list[str], what: str) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        text = value.strip()
        if not text:
            continue
        try:
            kind, name, _c = T.parse_line(text)
        except T.TargetError as exc:
            raise HTTPException(status_code=400, detail=f"{what}: {exc}") from None
        if kind != "host":
            raise HTTPException(status_code=400, detail=f"{what}: {text!r} is not a hostname")
        if name not in seen:
            seen.add(name)
            out.append(name)
    return out


def _update_settings(engine, team_id: int, user_id: int, body: SettingsUpdate) -> dict:
    now = utcnow()
    with Session(engine) as session:
        require_admin(session, user_id, team_id, "network scope and team settings")
        row = get_or_create_settings(session, team_id)
        check_version(row, body.expected_version)
        changes = body.model_dump(exclude_unset=True, exclude={"expected_version"})
        if "network_exclusions" in changes:
            items = []
            seen: set[str] = set()
            for item in body.network_exclusions or []:
                try:
                    parsed = T.parse_exclusions([item.cidr])
                except T.TargetError as exc:
                    raise HTTPException(status_code=400, detail=f"network_exclusions: {exc}") from None
                if parsed.hostnames:
                    # Same rule as the UI (NetworkTab rangeError). On the node a listed name that does not resolve
                    # holds every target of the jobs that carry it; at team level that would be every job of the team.
                    raise HTTPException(status_code=422, detail=(
                        f"network_exclusions: {item.cidr.strip()!r} is not an address or range (it reads as a host "
                        "name); the team never-scan list takes addresses and ranges only. List host names in a server "
                        "source's own Never scan field"))
                if not parsed.normalized:
                    continue
                canonical = parsed.normalized[0]
                if canonical in seen:
                    continue
                seen.add(canonical)
                items.append({"cidr": canonical, "reason": item.reason})
            changes["network_exclusions"] = items
        if "risk_model" in changes:
            # merge: a field the request leaves out keeps its value; an explicit null clears it; risk_model: null
            # clears all three
            changes["risk_model"] = ({**(row.risk_model or {}), **body.risk_model.model_dump(exclude_unset=True)}
                                     if body.risk_model is not None else {})
        if "require_signed_nodes" in changes and changes["require_signed_nodes"] is None:
            changes.pop("require_signed_nodes")  # null means "leave as is" (the column is NOT NULL)
        if "cert_domains" in changes:
            changes["cert_domains"] = _norm_hostnames(body.cert_domains or [], "cert_domains")
        if "sni_hostnames" in changes:
            changes["sni_hostnames"] = _norm_hostnames(body.sni_hostnames or [], "sni_hostnames")
        if "ports" in changes:
            ports, seen_ports = [], set()
            for item in body.ports or []:
                key = (item.port, item.protocol)
                if key not in seen_ports:
                    seen_ports.add(key)
                    ports.append(item.model_dump())
            changes["ports"] = ports
        zone_changed = "window_timezone" in changes and changes["window_timezone"] != row.window_timezone
        for key, value in changes.items():
            setattr(row, key, value)
        if changes:
            bump_version(session, row)
            row.updated_by_user_id = user_id
            row.last_updated = now
            session.add(row)
            # schedule slots are wall-clock times in this zone: their next runs move with it, in this transaction
            moved = SCHED.reschedule_team(session, team_id, row.window_timezone, now) if zone_changed else 0
            audit(session, team_id=team_id, actor_type="user", actor_id=user_id, action="settings.update",
                  object_type="settings", object_id=row.id, changed_fields=changes.keys())
            session.commit()
            session.refresh(row)
            log("settings updated", team=team_id, by=user_id, fields=len(changes), schedules_moved=moved or None)
            if "require_signed_nodes" in changes:
                log("signed scan nodes " + ("required" if changes["require_signed_nodes"] else "not required"),
                    team=team_id, by=user_id)
        return {"settings": public_settings(row, now)}


@router.patch(BASE + "/settings", dependencies=WRITE, summary="Update team settings (admin; send only changed sections)")
async def update_settings(team_id: TeamId, body: SettingsUpdate, Authorization: AuthHeader = None):
    engine, user = await authorize(team_id, Authorization)
    return _ok(await _run("update settings", team_id, _update_settings, engine, team_id, user.id, body))


def _stop_all(engine, team_id: int, user_id: int, on: bool) -> dict:
    now = utcnow()
    with Session(engine) as session:
        if not on:
            require_admin(session, user_id, team_id, "network scanning back on")
        row = get_or_create_settings(session, team_id)
        if row.stop_all_network != on:
            row.stop_all_network = on
            row.stop_all_changed_by = user_id
            row.stop_all_changed_at = now
            row.row_version += 1
            row.last_updated = now
            session.add(row)
            audit(session, team_id=team_id, actor_type="user", actor_id=user_id,
                  action="network.stop" if on else "network.resume", object_type="settings", object_id=row.id)
            session.commit()
            session.refresh(row)
            log("network stop" if on else "network resume", team=team_id, by=user_id)
        return {"settings": public_settings(row, now)}


@router.post(BASE + "/settings/stop-all", dependencies=WRITE,
             summary="Stop all network scanning (any member) or resume it (admin)")
async def stop_all(team_id: TeamId, body: StopAll, Authorization: AuthHeader = None):
    engine, user = await authorize(team_id, Authorization)
    return _ok(await _run("stop all", team_id, _stop_all, engine, team_id, user.id, body.on))


# ============================================================================ templates
def _aws_template(engine, team_id: int, scope: str, lambda_cmk: bool = False, glue: bool = False) -> str:
    if not aws_collection_configured():  # a template trusting the placeholder account could never work
        raise HTTPException(status_code=409, detail=AWS_NOT_CONFIGURED)
    with Session(engine) as session:
        return cloudformation_template(get_or_create_settings(session, team_id).aws_external_id, scope,
                                       read_lambda_cmk=lambda_cmk, read_glue=glue)


@router.get(BASE + "/aws/template", dependencies=READ, summary="CloudFormation template for the read-only role")
async def aws_template(team_id: TeamId, scope: str = Query(default="account", pattern="^(account|organization)$"),
                       lambda_cmk: bool = Query(default=False, description="Default of DecryptCustomerKeyLambdaEnvironments"),
                       glue: bool = Query(default=False, description="Default of ReadGlueConnections"),
                       Authorization: AuthHeader = None):
    engine, _user = await authorize(team_id, Authorization)
    text = await _run("aws template", team_id, _aws_template, engine, team_id, scope, lambda_cmk, glue)
    return Response(text, media_type="application/yaml", headers={
        **PRIVATE, "Content-Disposition": f'attachment; filename="zeroshield-cbom-reader-{scope}.yaml"'})


@router.get(BASE + "/templates/{name}", dependencies=READ, summary="Sudoers file, ClusterRoles and database grants")
async def get_template(team_id: TeamId, name: str, Authorization: AuthHeader = None):
    await authorize(team_id, Authorization)
    text = template_text(name)
    if text is None:
        raise HTTPException(status_code=404, detail="Template not found")
    media, filename = TEMPLATE_NAMES[name]
    return Response(text, media_type=media, headers={**PRIVATE, "Content-Disposition": f'attachment; filename="{filename}"'})


# ============================================================================ discovery
def _discovery(engine, team_id: int, user_id: int) -> dict:
    now = utcnow()
    with Session(engine) as session:
        require_admin(session, user_id, team_id, "the network discovery sweep")
        settings = get_or_create_settings(session, team_id)
        if settings.stop_all_network:
            raise HTTPException(status_code=400, detail="Network scanning is stopped; resume it first")
        jobs = J.create_discovery_jobs(session, team_id, settings, user_id, now)
        if not jobs:
            raise HTTPException(status_code=400, detail="Add an allowed network range with a scan node first")
        audit(session, team_id=team_id, actor_type="user", actor_id=user_id, action="network.discovery",
              object_type="settings", object_id=settings.id)
        session.commit()
        nodes = {n.id: n for n in session.exec(select(CbomScanNode).where(CbomScanNode.team_id == team_id)).all()}
        log("discovery queued", team=team_id, jobs=len(jobs), by=user_id)
        return {"jobs": [public_job(j, nodes.get(j.node_id), settings, now) for j in jobs]}


@router.post(BASE + "/discovery", dependencies=WRITE, summary="Queue a discovery sweep on every node with ranges (admin)")
async def discovery(team_id: TeamId, Authorization: AuthHeader = None):
    engine, user = await authorize(team_id, Authorization)
    return _ok(await _run("discovery", team_id, _discovery, engine, team_id, user.id))


# ============================================================================ evidence
def _evidence(engine, team_id: int) -> dict:
    now = utcnow()
    with Session(engine) as session:
        areas = ensure_evidence_areas(session, team_id)
        vendors = session.exec(select(CbomEvidenceVendor).where(CbomEvidenceVendor.team_id == team_id)
                               .order_by(CbomEvidenceVendor.id)).all()
        levels = [v.confidence if v.answered_at else "Q0" for v in vendors]
        rows = [public_area(a, _today(now), levels) for a in areas]
        by_q = {q: 0 for q in CONFIDENCE}
        for row in rows:
            by_q[row["effective_confidence"]] += 1
        return {"server_time": iso_z(now), "areas": rows, "vendors": [public_vendor(v, now) for v in vendors],
                "by_confidence": by_q, "answered": sum(1 for r in rows if r["effective_confidence"] != "Q0")}


@router.get(BASE + "/evidence", dependencies=READ, summary="Evidence areas and vendors")
async def get_evidence(team_id: TeamId, Authorization: AuthHeader = None):
    engine, _user = await authorize(team_id, Authorization)
    return _ok(await _run("evidence", team_id, _evidence, engine, team_id))


def _update_area(engine, team_id: int, user_id: int, area_key: str, body: AreaUpdate) -> dict:
    now = utcnow()
    if area_key not in AREAS:
        raise HTTPException(status_code=404, detail="Evidence area not found")
    with Session(engine) as session:
        ensure_evidence_areas(session, team_id)
        row = session.exec(select(CbomEvidenceArea).where(CbomEvidenceArea.team_id == team_id,
                                                          CbomEvidenceArea.area_key == area_key)).one()
        check_version(row, body.expected_version)
        changes = body.model_dump(exclude_unset=True, exclude={"expected_version"})
        if "answers" in changes:
            try:
                changes["answers"] = clean_answers(area_key, body.answers)
            except ValueError as exc:
                raise HTTPException(status_code=400, detail=f"answers.{exc}") from None
        if changes.get("evidence_date") and changes["evidence_date"] > (now.date() + _dt.timedelta(days=1)).isoformat():
            raise HTTPException(status_code=400, detail="evidence_date: cannot be in the future")
        for key, value in changes.items():
            setattr(row, key, value)
        if row.confidence in ("Q2", "Q3") and not (row.evidence_url or row.evidence_title):
            raise HTTPException(status_code=400, detail="confidence: Documented and Verified need an evidence document")
        if row.confidence in ("Q2", "Q3") and not row.evidence_date:
            raise HTTPException(status_code=400, detail="evidence_date: enter the date of the evidence document")
        if "confidence" in changes:
            row.confidence_set_by = user_id
        if changes:
            row.row_version += 1
            row.updated_by_user_id = user_id
            row.last_updated = now
            session.add(row)
            audit(session, team_id=team_id, actor_type="user", actor_id=user_id, action="evidence.update",
                  object_type="evidence", object_id=row.id, changed_fields=changes.keys())
            session.commit()
            session.refresh(row)
            log("evidence updated", team=team_id, area=area_key, by=user_id)
        vendors = session.exec(select(CbomEvidenceVendor).where(CbomEvidenceVendor.team_id == team_id)).all()
        levels = [v.confidence if v.answered_at else "Q0" for v in vendors]
        return {"area": public_area(row, _today(now), levels)}


@router.patch(BASE + "/evidence/{area_key}", dependencies=WRITE, summary="Answer or update an evidence area")
async def update_area(team_id: TeamId, area_key: str, body: AreaUpdate, Authorization: AuthHeader = None):
    engine, user = await authorize(team_id, Authorization)
    return _ok(await _run("update evidence", team_id, _update_area, engine, team_id, user.id, area_key, body))


def _create_vendor(engine, team_id: int, user_id: int, body: VendorCreate) -> dict:
    now = utcnow()
    with Session(engine) as session:
        total = session.exec(select(func.count()).select_from(CbomEvidenceVendor)
                             .where(CbomEvidenceVendor.team_id == team_id)).one()
        if total >= MAX_VENDORS:
            raise HTTPException(status_code=400, detail=f"A team can have at most {MAX_VENDORS} vendors")
        row = CbomEvidenceVendor(team_id=team_id, name=body.name, contact_email=body.contact_email,
                                 created_by_user_id=user_id, created_at=now, last_updated=now)
        session.add(row)
        session.flush()
        audit(session, team_id=team_id, actor_type="user", actor_id=user_id, action="vendor.create",
              object_type="vendor", object_id=row.id)
        session.commit()
        session.refresh(row)
        log("vendor created", team=team_id, vendor=row.id, by=user_id)
        return {"vendor": public_vendor(row, now)}


@router.post(BASE + "/evidence/vendors", dependencies=WRITE, summary="Add a vendor")
async def create_vendor(team_id: TeamId, body: VendorCreate, Authorization: AuthHeader = None):
    engine, user = await authorize(team_id, Authorization)
    return _ok(await _run("create vendor", team_id, _create_vendor, engine, team_id, user.id, body), 201)


def _update_vendor(engine, team_id: int, user_id: int, vendor_id: int, body: VendorUpdate) -> dict:
    now = utcnow()
    with Session(engine) as session:
        row = _get_owned(session, CbomEvidenceVendor, vendor_id, team_id, "Vendor")
        check_version(row, body.expected_version)
        changes = body.model_dump(exclude_unset=True, exclude={"expected_version"})
        for key, value in changes.items():
            if key == "name" and not value:
                continue
            setattr(row, key, value)
        if changes:
            row.row_version += 1
            row.last_updated = now
            session.add(row)
            audit(session, team_id=team_id, actor_type="user", actor_id=user_id, action="vendor.update",
                  object_type="vendor", object_id=row.id, changed_fields=changes.keys())
            session.commit()
            session.refresh(row)
        return {"vendor": public_vendor(row, now)}


@router.patch(BASE + "/evidence/vendors/{vendor_id}", dependencies=WRITE, summary="Edit a vendor")
async def update_vendor(team_id: TeamId, vendor_id: ObjectId, body: VendorUpdate, Authorization: AuthHeader = None):
    engine, user = await authorize(team_id, Authorization)
    return _ok(await _run("update vendor", team_id, _update_vendor, engine, team_id, user.id, vendor_id, body))


def _delete_vendor(engine, team_id: int, user_id: int, vendor_id: int) -> dict:
    with Session(engine) as session:
        row = _get_owned(session, CbomEvidenceVendor, vendor_id, team_id, "Vendor")
        audit(session, team_id=team_id, actor_type="user", actor_id=user_id, action="vendor.delete",
              object_type="vendor", object_id=row.id)
        session.delete(row)
        session.commit()
        log("vendor deleted", team=team_id, vendor=vendor_id, by=user_id)
        return {"deleted": vendor_id}


@router.delete(BASE + "/evidence/vendors/{vendor_id}", dependencies=WRITE, summary="Delete a vendor (its link stops working)")
async def delete_vendor(team_id: TeamId, vendor_id: ObjectId, Authorization: AuthHeader = None):
    engine, user = await authorize(team_id, Authorization)
    return _ok(await _run("delete vendor", team_id, _delete_vendor, engine, team_id, user.id, vendor_id))


def _vendor_link(engine, team_id: int, user_id: int, vendor_id: int) -> dict:
    now = utcnow()
    token = new_token("zsv_", 24)
    with Session(engine) as session:
        row = _get_owned(session, CbomEvidenceVendor, vendor_id, team_id, "Vendor")
        row.link_token_hash = sha256_hex(token)
        row.link_created_at = now
        row.link_expires_at = now + _dt.timedelta(days=VENDOR_LINK_DAYS)
        row.answered_at = None
        row.answers = {}
        row.confidence = "Q0"
        row.row_version += 1
        row.last_updated = now
        session.add(row)
        audit(session, team_id=team_id, actor_type="user", actor_id=user_id, action="vendor.link",
              object_type="vendor", object_id=row.id)
        session.commit()
        session.refresh(row)
        log("vendor link created", team=team_id, vendor=row.id, by=user_id)
        base = (os.environ.get("CBOM_PUBLIC_APP_URL") or "https://devsecshield.zeroshield.ai").rstrip("/")
        return {"vendor": public_vendor(row, now), "url": f"{base}/q/{token}", "path": f"/q/{token}"}


@router.post(BASE + "/evidence/vendors/{vendor_id}/link", dependencies=WRITE,
             summary="Create a single-use questionnaire link (replaces any previous link)")
async def vendor_link(team_id: TeamId, vendor_id: ObjectId, Authorization: AuthHeader = None):
    engine, user = await authorize(team_id, Authorization)
    return _ok(await _run("vendor link", team_id, _vendor_link, engine, team_id, user.id, vendor_id))


# ============================================================================ estimate and runs
def _estimate(engine, team_id: int, body: EstimateBody) -> dict:
    now = utcnow()
    with Session(engine) as session:
        settings = get_or_create_settings(session, team_id)
        plan = plan_run(session, team_id, settings, now, include=body.include.model_dump(), source_ids=body.source_ids)
        team = session.get(Team, team_id)
        return {**plan.public(), "credit_balance": round(float(team.credit_balance or 0), 2) if team else 0,
                "server_time": iso_z(now)}


@router.post(BASE + "/estimate", dependencies=READ, summary="Credits a run would charge, with skipped sources and reasons")
async def estimate(team_id: TeamId, body: EstimateBody, Authorization: AuthHeader = None):
    engine, _user = await authorize(team_id, Authorization)
    return _ok(await _run("estimate", team_id, _estimate, engine, team_id, body))


def _run_detail(session: Session, run: CbomCollectionRun, settings, now) -> dict:
    jobs = session.exec(select(CbomCollectionJob).where(CbomCollectionJob.run_id == run.id)
                        .order_by(CbomCollectionJob.id)).all()
    nodes = {n.id: n for n in session.exec(select(CbomScanNode).where(CbomScanNode.team_id == run.team_id)).all()}
    sources = {s.id: s for s in session.exec(select(CbomCollectionSource).where(CbomCollectionSource.team_id == run.team_id)).all()}
    return public_run(run, [public_job(j, nodes.get(j.node_id), settings, now, sources.get(j.source_id)) for j in jobs])


def _create_run(engine, team_id: int, user_id: int, body: RunCreate) -> tuple[dict, int]:
    now = utcnow()
    with Session(engine) as session:
        settings = get_or_create_settings(session, team_id)
        # one code path with the scheduler (plan, SOC acknowledgement, credits, idempotency): runs.queue_run
        run, replayed = RUNS.queue_run(session, team_id, user_id, body, settings, now)
        if replayed:
            return {"run": _run_detail(session, run, settings, now), "replayed": True}, 200
        session.commit()
        session.refresh(run)
        log("run created", team=team_id, run=run.id, credits=credits(run.credits_charged_c), by=user_id)
        return {"run": _run_detail(session, run, settings, now), "replayed": False}, 201


@router.post(BASE + "/runs", dependencies=WRITE, summary="Start a collection run (charges credits; idempotent per client_request_id)")
async def create_run(team_id: TeamId, body: RunCreate, Authorization: AuthHeader = None):
    engine, user = await authorize(team_id, Authorization)
    payload, code = await _run("create run", team_id, _create_run, engine, team_id, user.id, body)
    return _ok(payload, code)


def _list_runs(engine, team_id: int, scan_id: int | None) -> dict:
    now = utcnow()
    with Session(engine) as session:
        J.safe_reap(session, now, team_id=team_id)
        query = select(CbomCollectionRun).where(CbomCollectionRun.team_id == team_id)
        if scan_id is not None:
            query = query.where(CbomCollectionRun.scan_id == scan_id)
        runs = session.exec(query.order_by(CbomCollectionRun.id.desc()).limit(50)).all()  # type: ignore[union-attr]
        out = []
        for run in runs:
            counts: dict[str, int] = {}
            for job in session.exec(select(CbomCollectionJob).where(CbomCollectionJob.run_id == run.id)).all():
                counts[job.status] = counts.get(job.status, 0) + 1
            assets = session.exec(select(func.count()).select_from(CbomCollectedAsset)
                                  .where(CbomCollectedAsset.run_id == run.id)).one()
            out.append({**public_run(run), "job_counts": counts, "asset_count": int(assets)})
        return {"runs": out, "server_time": iso_z(now)}


@router.get(BASE + "/runs", dependencies=READ, summary="Recent collection runs")
async def list_runs(team_id: TeamId, scan_id: int | None = Query(default=None, ge=1, le=2_147_483_647),
                    Authorization: AuthHeader = None):
    engine, _user = await authorize(team_id, Authorization)
    return _ok(await _run("list runs", team_id, _list_runs, engine, team_id, scan_id))


def _get_run(engine, team_id: int, run_id: int) -> dict:
    now = utcnow()
    with Session(engine) as session:
        run = _get_owned(session, CbomCollectionRun, run_id, team_id, "Run")
        J.safe_reap(session, now, team_id=team_id)
        session.refresh(run)
        return {"run": _run_detail(session, run, get_or_create_settings(session, team_id), now), "server_time": iso_z(now)}


@router.get(BASE + "/runs/{run_id}", dependencies=READ, summary="A run with its jobs")
async def get_run(team_id: TeamId, run_id: ObjectId, Authorization: AuthHeader = None):
    engine, _user = await authorize(team_id, Authorization)
    return _ok(await _run("get run", team_id, _get_run, engine, team_id, run_id))


def _run_assets(engine, team_id: int, run_id: int, params: dict) -> dict:
    with Session(engine) as session:
        run = _get_owned(session, CbomCollectionRun, run_id, team_id, "Run")
        out = INV.list_assets(session, team_id=team_id, run_id=run.id, **params)
        out["run"] = public_run(run)
        return out


def _asset_params(type: str | None, impact: str | None, quantum: bool | None, q: str | None, source_id: int | None,
                  page: int, page_size: int) -> dict:
    if type is not None and type not in ASSET_TYPES:
        raise HTTPException(status_code=400, detail="type: unknown asset type")
    return {"asset_type": type, "impact": impact, "quantum": quantum, "text": (q or "").strip()[:100] or None,
            "source_id": source_id, "page": page, "page_size": page_size}


@router.get(BASE + "/runs/{run_id}/assets", dependencies=READ, summary="What a run collected: paged assets, facets, per-target results")
async def run_assets(team_id: TeamId, run_id: ObjectId,
                     type: str | None = Query(default=None, max_length=32),
                     impact: str | None = Query(default=None, pattern="^(Critical|High|Medium|Low|none)$"),
                     quantum: bool | None = Query(default=None),
                     q: str | None = Query(default=None, max_length=100),
                     source_id: int | None = Query(default=None, ge=1, le=2_147_483_647),
                     page: int = Query(default=1, ge=1, le=10_000), page_size: int = Query(default=50, ge=1, le=200),
                     Authorization: AuthHeader = None):
    engine, _user = await authorize(team_id, Authorization)
    params = _asset_params(type, impact, quantum, q, source_id, page, page_size)
    return _ok(await _run("run assets", team_id, _run_assets, engine, team_id, run_id, params))


def _run_cbom(engine, team_id: int, run_id: int) -> dict:
    with Session(engine) as session:
        run = _get_owned(session, CbomCollectionRun, run_id, team_id, "Run")
        return INV.cyclonedx(session, run, utcnow())


@router.get(BASE + "/runs/{run_id}/cbom", dependencies=READ,
            summary="CycloneDX 1.6 CBOM of what a run collected (format=json, or xml valid against the official XSD)")
async def run_cbom(team_id: TeamId, run_id: ObjectId, format: str = Query(default="json", pattern="^(json|xml)$"),
                   Authorization: AuthHeader = None):
    engine, _user = await authorize(team_id, Authorization)
    payload = await _run("run cbom", team_id, _run_cbom, engine, team_id, run_id)
    if format == "xml":  # the same document, written as XML (cdx_xml); the signature covers the JSON form only
        body = await _run("run cbom xml", team_id, CDX_XML.to_xml, payload)
        return Response(body, media_type=CDX_XML.XML_MEDIA_TYPE, headers={
            **PRIVATE, "Content-Disposition": f'attachment; filename="cbom-sources-run-{run_id}.cdx.xml"',
            "X-ZS-Signature-Scope": CDX_XML.SIGNATURE_SCOPE})
    return JSONResponse(payload, headers={**PRIVATE, "Content-Disposition": f'attachment; filename="cbom-sources-run-{run_id}.cdx.json"'})


def _run_posture(engine, team_id: int, run_id: int) -> dict:
    with Session(engine) as session:
        run = _get_owned(session, CbomCollectionRun, run_id, team_id, "Run")
        settings = get_or_create_settings(session, team_id)
        return {"run": public_run(run),
                "posture": POSTURE.run_posture(session, team_id=team_id, run_id=run.id, risk_model=settings.risk_model)}


@router.get(BASE + "/runs/{run_id}/posture", dependencies=READ,
            summary="Post-quantum readiness, harvest-now-decrypt-later exposure, Mosca verdict, top risks, compliance")
async def run_posture(team_id: TeamId, run_id: ObjectId, Authorization: AuthHeader = None):
    engine, _user = await authorize(team_id, Authorization)
    return _ok(await _run("run posture", team_id, _run_posture, engine, team_id, run_id))


def _asset_detail(engine, team_id: int, asset_id: int) -> dict:
    with Session(engine) as session:
        row = _get_owned(session, CbomCollectedAsset, asset_id, team_id, "Asset")
        source = session.get(CbomCollectionSource, row.source_id) if row.source_id else None
        if source is not None and source.team_id != team_id:
            source = None
        job = session.get(CbomCollectionJob, row.job_id) if row.job_id else None
        node = session.get(CbomScanNode, source.node_id) if source is not None and source.node_id else None
        if node is not None and node.team_id != team_id:
            node = None
        return {"asset": POSTURE.asset_detail(row, source, job=job if job and job.team_id == team_id else None,
                                              node=node)}


@router.get(BASE + "/assets/{asset_id}", dependencies=READ,
            summary="One collected asset explained: CWE, OWASP, CVEs, remediation and read-only proof commands")
async def asset_detail(team_id: TeamId, asset_id: ObjectId, Authorization: AuthHeader = None):
    engine, _user = await authorize(team_id, Authorization)
    return _ok(await _run("asset detail", team_id, _asset_detail, engine, team_id, asset_id))


def _job_assets(engine, team_id: int, job_id: int, params: dict) -> dict:
    with Session(engine) as session:
        job = _get_owned(session, CbomCollectionJob, job_id, team_id, "Job")
        return INV.list_assets(session, team_id=team_id, job_id=job.id, **params)


@router.get(BASE + "/jobs/{job_id}/assets", dependencies=READ, summary="What one job collected (e.g. a discovery sweep)")
async def job_assets(team_id: TeamId, job_id: ObjectId,
                     type: str | None = Query(default=None, max_length=32),
                     page: int = Query(default=1, ge=1, le=10_000), page_size: int = Query(default=50, ge=1, le=200),
                     Authorization: AuthHeader = None):
    engine, _user = await authorize(team_id, Authorization)
    params = _asset_params(type, None, None, None, None, page, page_size)
    return _ok(await _run("job assets", team_id, _job_assets, engine, team_id, job_id, params))


def _cancel_run(engine, team_id: int, user_id: int, run_id: int) -> dict:
    now = utcnow()
    with Session(engine) as session:
        run = _get_owned(session, CbomCollectionRun, run_id, team_id, "Run")
        require_owner_or_admin(session, user_id, team_id, run.owner_user_id, "run")
        refunded = J.cancel_run(session, run, user_id, now)
        if refunded or run.cancelled_at == now:
            audit(session, team_id=team_id, actor_type="user", actor_id=user_id, action="run.cancel",
                  object_type="run", object_id=run.id)
        session.commit()
        session.refresh(run)
        if refunded:
            log("run cancelled", team=team_id, run=run.id, refunded=credits(refunded), by=user_id)
        return {"run": _run_detail(session, run, get_or_create_settings(session, team_id), now),
                "refunded": credits(refunded)}


@router.post(BASE + "/runs/{run_id}/cancel", dependencies=WRITE,
             summary="Cancel jobs not yet picked up and refund them; jobs already running finish")
async def cancel_run(team_id: TeamId, run_id: ObjectId, Authorization: AuthHeader = None):
    engine, user = await authorize(team_id, Authorization)
    return _ok(await _run("cancel run", team_id, _cancel_run, engine, team_id, user.id, run_id))


# ============================================================================ audit
def _audit_list(engine, team_id: int, limit: int) -> dict:
    with Session(engine) as session:
        rows = session.exec(select(CbomCollectionAuditEvent).where(CbomCollectionAuditEvent.team_id == team_id)
                            .order_by(CbomCollectionAuditEvent.id.desc()).limit(limit)).all()  # type: ignore[union-attr]
        return {"events": [{"id": r.id, "at": iso_z(r.at), "actor_type": r.actor_type, "actor_id": r.actor_id,
                            "action": r.action, "object_type": r.object_type, "object_id": r.object_id,
                            "changed_fields": r.changed_fields or []} for r in rows]}


@router.get(BASE + "/audit", dependencies=READ, summary="Recent changes to CBOM Sources (who, what, when)")
async def audit_list(team_id: TeamId, limit: int = Query(default=100, ge=1, le=500), Authorization: AuthHeader = None):
    engine, _user = await authorize(team_id, Authorization)
    return _ok(await _run("audit", team_id, _audit_list, engine, team_id, limit))
