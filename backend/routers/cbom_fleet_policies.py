"""Fleet policy, credential and reconcile routes (F1.2, contract section 3), behind ``CBOM_FLEET_POLICIES``.

``/{team_id}/cbom/sources/fleet/policies``, ``/credentials`` and ``/reconcile``.  Members read; writes need a team
admin (400, never 403).  A policy or credential change re-evaluates the team's targets (their cached decisions); only
``POST /reconcile`` (and an inventory sync) writes managed sources, and only while ``CBOM_FLEET_MATERIALIZE`` is on.
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse
from pydantic import ValidationError
from sqlalchemy import func
from sqlmodel import Session, select

from backend.new_models import CbomCollectionSource
from backend.utilities.cbom_sources.common import audit, log, utcnow
from backend.utilities.cbom_sources.crypto import decrypt_secrets, encrypt_secrets
from backend.utilities.cbom_sources.fleet import flags as FLAGS
from backend.utilities.cbom_sources.fleet import store
from backend.utilities.cbom_sources.fleet.credentials import (
    CredentialCreate, CredentialUpdate, check_config, public_credential, required_secrets)
from backend.utilities.cbom_sources.fleet.http import FLEET, Member, permission
from backend.utilities.cbom_sources.fleet.materialize import ReconcileResult, reconcile
from backend.utilities.cbom_sources.fleet.models import CbomCredential, CbomFleetPolicy
from backend.utilities.cbom_sources.fleet.policy import PolicyEngine
from backend.utilities.cbom_sources.fleet.refs import build_refs
from backend.utilities.cbom_sources.fleet.schemas import PolicyCreate, PolicyUpdate, PreviewBody, public_policy, public_target
from backend.utilities.cbom_sources.http import (
    PRIVATE, ObjectId, TeamId, bad_request, bump_version, check_version, read_limiter, require_admin,
    server_error, write_limiter)
from backend.utilities.cbom_sources.kinds import validate_secret_value
from backend.utilities.cbom_sources.settings import get_or_create_settings

router = APIRouter(tags=["cbom-fleet"], route_class=FLAGS.route_class("policies"))
READ = [Depends(read_limiter)]
WRITE = [Depends(write_limiter)]
MAX_POLICIES = 200
MAX_CREDENTIALS = 100


async def _run(what: str, team_id: int, fn, *args) -> Any:
    try:
        return await run_in_threadpool(fn, *args)
    except HTTPException:
        raise
    except Exception as exc:
        raise server_error(f"cbom fleet {what}", exc, team=team_id) from None


def _ok(payload: Any, status_code: int = 200) -> JSONResponse:
    return JSONResponse(payload, status_code=status_code, headers=PRIVATE)


def _policies(session: Session, team_id: int) -> list[CbomFleetPolicy]:
    return list(session.exec(select(CbomFleetPolicy).where(CbomFleetPolicy.team_id == team_id)).all())


def _engine(session: Session, team_id: int, policies: list[Any], now) -> PolicyEngine:
    return PolicyEngine(policies, get_or_create_settings(session, team_id), refs=build_refs(session, team_id, policies),
                        now=now)


def _refresh(session: Session, team_id: int, now) -> int:
    return store.refresh_decisions(session, team_id, _engine(session, team_id, _policies(session, team_id), now))


def _check_refs(session: Session, team_id: int, action: dict[str, Any]) -> None:
    cid = action.get("credential_id")
    if cid is not None:
        cred = session.get(CbomCredential, cid)
        if cred is None or cred.team_id != team_id or cred.deleted_at is not None:
            raise HTTPException(status_code=400, detail="credential_id: the credential was not found in this team")
    nid = action.get("node_id")
    if nid is not None:
        from backend.new_models import CbomScanNode

        node = session.get(CbomScanNode, nid)
        if node is None or node.team_id != team_id:
            raise HTTPException(status_code=400, detail="node_id: the scan node was not found in this team")


def _owned_policy(session: Session, team_id: int, policy_id: int) -> CbomFleetPolicy:
    p = session.get(CbomFleetPolicy, policy_id)
    if p is None or p.team_id != team_id or p.deleted_at is not None:
        raise HTTPException(status_code=404, detail="Policy not found")
    return p


# ----------------------------------------------------------------------------- policies
def _list_policies(engine, team_id: int) -> dict:
    now = utcnow()
    with Session(engine) as session:
        rows = [p for p in _policies(session, team_id) if p.deleted_at is None]
        policy_engine = _engine(session, team_id, rows, now)
        won: dict[int, int] = {}
        hits: dict[int, int] = {}
        for view in store.iter_views(session, team_id, present_only=True):
            d = policy_engine.evaluate(view)
            if d.policy_id:
                won[d.policy_id] = won.get(d.policy_id, 0) + 1
            for pid in d.matched_policy_ids:
                hits[pid] = hits.get(pid, 0) + 1
        order = {p.id: i for i, p in enumerate(policy_engine.policies)}
        rows.sort(key=lambda p: (order.get(p.id, len(order)), -p.priority, p.id))
        out = []
        for p in rows:
            item = public_policy(p, hits.get(p.id, 0))
            item["won_targets"] = won.get(p.id, 0)
            item["precedence"] = order.get(p.id) + 1 if p.id in order else None
            out.append(item)
        return {"policies": out, "materialize": FLAGS.materialize_enabled(),
                "order": "priority (highest first), then the older policy (lower id); the first match wins"}


@router.get(FLEET + "/policies", dependencies=READ, openapi_extra=permission("cbom.fleet.read"),
            summary="Policies in the order they are applied, with how many targets each matches and wins")
async def list_policies(team_id: TeamId, ctx: Member):
    engine, _user = ctx
    return _ok(await _run("list policies", team_id, _list_policies, engine, team_id))


def _create_policy(engine, team_id: int, user_id: int, body: PolicyCreate) -> dict:
    now = utcnow()
    with Session(engine) as session:
        require_admin(session, user_id, team_id, "fleet policies")
        total = session.exec(select(func.count()).select_from(CbomFleetPolicy).where(
            CbomFleetPolicy.team_id == team_id, CbomFleetPolicy.deleted_at.is_(None))).one()  # type: ignore[union-attr]
        if total >= MAX_POLICIES:
            raise HTTPException(status_code=400, detail=f"A team can have at most {MAX_POLICIES} policies")
        _check_refs(session, team_id, body.action)
        p = CbomFleetPolicy(team_id=team_id, name=body.name, enabled=body.enabled, priority=body.priority,
                            selector=body.selector, action=body.action, owner_user_id=user_id,
                            updated_by_user_id=user_id, created_at=now, last_updated=now)
        session.add(p)
        session.flush()
        changed = _refresh(session, team_id, now)
        audit(session, team_id=team_id, actor_type="user", actor_id=user_id, action="fleet.policy.create",
              object_type="fleet_policy", object_id=p.id, changed_fields=["name", "priority", "selector", "action"])
        session.commit()
        session.refresh(p)
        log("fleet policy created", team=team_id, policy=p.id, decisions_changed=changed, by=user_id)
        return {"policy": public_policy(p), "decisions_changed": changed}


@router.post(FLEET + "/policies", dependencies=WRITE, openapi_extra=permission("cbom.policies.write"),
             summary="Add a policy: a selector over tags and fields, and what to do with what it matches")
async def create_policy(team_id: TeamId, ctx: Member, body: PolicyCreate):
    engine, user = ctx
    return _ok(await _run("create policy", team_id, _create_policy, engine, team_id, user.id, body), 201)


def _update_policy(engine, team_id: int, user_id: int, policy_id: int, body: PolicyUpdate) -> dict:
    now = utcnow()
    with Session(engine) as session:
        require_admin(session, user_id, team_id, "fleet policies")
        p = _owned_policy(session, team_id, policy_id)
        check_version(p, body.expected_version)
        fields = body.model_dump(exclude_unset=True, exclude={"expected_version"})
        if body.action is not None:
            _check_refs(session, team_id, body.action)
        for name in ("name", "enabled", "priority", "selector", "action"):
            if name in fields and fields[name] is not None:
                setattr(p, name, getattr(body, name))
        bump_version(session, p)
        p.updated_by_user_id, p.last_updated = user_id, now
        session.add(p)
        session.flush()
        changed = _refresh(session, team_id, now)
        audit(session, team_id=team_id, actor_type="user", actor_id=user_id, action="fleet.policy.update",
              object_type="fleet_policy", object_id=p.id, changed_fields=fields.keys())
        session.commit()
        session.refresh(p)
        return {"policy": public_policy(p), "decisions_changed": changed}


@router.patch(FLEET + "/policies/{policy_id}", dependencies=WRITE, openapi_extra=permission("cbom.policies.write"),
              summary="Edit, enable or disable a policy (expected_version: 409 when it changed meanwhile)")
async def update_policy(team_id: TeamId, policy_id: ObjectId, ctx: Member, body: PolicyUpdate):
    engine, user = ctx
    return _ok(await _run("update policy", team_id, _update_policy, engine, team_id, user.id, policy_id, body))


def _delete_policy(engine, team_id: int, user_id: int, policy_id: int) -> dict:
    now = utcnow()
    with Session(engine) as session:
        require_admin(session, user_id, team_id, "fleet policies")
        p = _owned_policy(session, team_id, policy_id)
        p.deleted_at, p.enabled, p.last_updated, p.updated_by_user_id = now, False, now, user_id
        bump_version(session, p)
        session.add(p)
        session.flush()
        changed = _refresh(session, team_id, now)
        audit(session, team_id=team_id, actor_type="user", actor_id=user_id, action="fleet.policy.delete",
              object_type="fleet_policy", object_id=p.id)
        session.commit()
        return {"deleted": policy_id, "decisions_changed": changed}


@router.delete(FLEET + "/policies/{policy_id}", dependencies=WRITE, openapi_extra=permission("cbom.policies.write"),
               summary="Delete a policy (its managed sources go at the next reconcile)")
async def delete_policy(team_id: TeamId, policy_id: ObjectId, ctx: Member):
    engine, user = ctx
    return _ok(await _run("delete policy", team_id, _delete_policy, engine, team_id, user.id, policy_id))


def _preview(engine, team_id: int, body: PreviewBody) -> dict:
    now = utcnow()
    with Session(engine) as session:
        policies = [p for p in _policies(session, team_id) if p.deleted_at is None]
        if body.policy_id is not None:
            draft = _owned_policy(session, team_id, body.policy_id)
            others = policies
        else:
            assert body.policy is not None
            _check_refs(session, team_id, body.policy.action)
            draft = CbomFleetPolicy(id=0, team_id=team_id, name=body.policy.name, enabled=True,
                                    priority=body.policy.priority, selector=body.policy.selector,
                                    action=body.policy.action)
            others = [*policies, draft]
        policy_engine = _engine(session, team_id, others, now)
        views = list(store.iter_views(session, team_id, present_only=True))
        matched = would_collect = never = 0
        sample = []
        for view in views:
            d = policy_engine.evaluate(view)
            if draft.id not in d.matched_policy_ids:
                continue
            matched += 1
            if d.policy_id == draft.id and d.action == "collect":
                would_collect += 1
            if d.action == "never_scan":
                never += 1
            if len(sample) < 50:
                item = public_target(view, d.to_dict())
                item["won"] = d.policy_id == draft.id
                sample.append(item)
        conflicts = [c for c in policy_engine.conflicts(views)
                     if draft.id in (c["winner_policy_id"], c["loser_policy_id"])]
        for c in conflicts:  # the draft has no id yet
            for side in ("winner", "loser"):
                if c[f"{side}_policy_id"] == 0:
                    c[f"{side}_policy_id"] = None
        return {"matched": matched, "would_collect": would_collect, "never_scan": never, "conflicts": conflicts,
                "sample": sample}


@router.post(FLEET + "/policies/preview", dependencies=WRITE, openapi_extra=permission("cbom.fleet.read"),
             summary="What a draft or saved policy would match, collect and skip, and which policies it overlaps")
async def preview_policy(team_id: TeamId, ctx: Member, body: PreviewBody):
    engine, _user = ctx
    return _ok(await _run("preview policy", team_id, _preview, engine, team_id, body))


def _reconcile(engine, team_id: int, user_id: int) -> dict:
    now = utcnow()
    with Session(engine) as session:
        require_admin(session, user_id, team_id, "fleet policies")
        if not FLAGS.materialize_enabled():
            out = ReconcileResult(decisions_changed=_refresh(session, team_id, now))
            session.commit()
            return {**out.public(), "materialize": False}
        out = reconcile(session, team_id, now, actor_id=user_id)
        audit(session, team_id=team_id, actor_type="user", actor_id=user_id, action="fleet.reconcile",
              object_type="fleet_policy", object_id=None,
              changed_fields=[f"{k}:{v}" for k, v in out.public().items() if k != "problems" and v])
        session.commit()
        return {**out.public(), "materialize": True}


@router.post(FLEET + "/reconcile", dependencies=WRITE, openapi_extra=permission("cbom.policies.write"),
             summary="Apply the policies: managed sources, batches and schedules (CBOM_FLEET_MATERIALIZE)")
async def reconcile_route(team_id: TeamId, ctx: Member):
    engine, user = ctx
    return _ok(await _run("reconcile", team_id, _reconcile, engine, team_id, user.id))


# ----------------------------------------------------------------------------- credentials
def _owned_credential(session: Session, team_id: int, credential_id: int) -> CbomCredential:
    c = session.get(CbomCredential, credential_id)
    if c is None or c.team_id != team_id or c.deleted_at is not None:
        raise HTTPException(status_code=404, detail="Credential not found")
    return c


def _secrets(credential_type: str, current: dict[str, str], provided: dict[str, str] | None, *, reset: bool) -> dict[str, str]:
    required = required_secrets(credential_type)
    out = {} if reset else {k: v for k, v in current.items() if k in required}
    for name, value in (provided or {}).items():
        if name not in required:
            raise HTTPException(status_code=400, detail=f"secrets: {name[:40]!r} is not used by a {credential_type} "
                                                        "credential")
        if value == "":
            continue
        try:
            out[name] = validate_secret_value(name, value)
        except ValueError as exc:
            raise bad_request(exc) from None
    missing = sorted(required - set(out))
    if missing:
        raise HTTPException(status_code=400, detail=f"secrets: enter {', '.join(missing)}")
    return out


def _list_credentials(engine, team_id: int) -> dict:
    with Session(engine) as session:
        rows = session.exec(select(CbomCredential).where(CbomCredential.team_id == team_id,
                                                         CbomCredential.deleted_at.is_(None))  # type: ignore[union-attr]
                            .order_by(CbomCredential.id)).all()
        used: dict[int, int] = {}
        for s in session.exec(select(CbomCollectionSource.credential_id).where(
                CbomCollectionSource.team_id == team_id, CbomCollectionSource.credential_id.is_not(None))).all():  # type: ignore[union-attr]
            used[s] = used.get(s, 0) + 1
        out = []
        for c in rows:
            item = public_credential(c)
            item["managed_sources"] = used.get(c.id, 0)
            out.append(item)
        return {"credentials": out}


@router.get(FLEET + "/credentials", dependencies=READ, openapi_extra=permission("cbom.fleet.read"),
            summary="Typed credentials (secrets are never returned)")
async def list_credentials(team_id: TeamId, ctx: Member):
    engine, _user = ctx
    return _ok(await _run("list credentials", team_id, _list_credentials, engine, team_id))


def _create_credential(engine, team_id: int, user_id: int, body: CredentialCreate) -> dict:
    now = utcnow()
    with Session(engine) as session:
        require_admin(session, user_id, team_id, "credentials")
        total = session.exec(select(func.count()).select_from(CbomCredential).where(
            CbomCredential.team_id == team_id, CbomCredential.deleted_at.is_(None))).one()  # type: ignore[union-attr]
        if total >= MAX_CREDENTIALS:
            raise HTTPException(status_code=400, detail=f"A team can have at most {MAX_CREDENTIALS} credentials")
        secrets = _secrets(body.credential_type, {}, body.secrets, reset=True)
        c = CbomCredential(team_id=team_id, name=body.name, credential_type=body.credential_type, config=body.config,
                           secret_encrypted=encrypt_secrets(secrets), secret_fields=sorted(secrets),
                           owner_user_id=user_id, updated_by_user_id=user_id, created_at=now, last_updated=now)
        session.add(c)
        session.flush()
        audit(session, team_id=team_id, actor_type="user", actor_id=user_id, action="fleet.credential.create",
              object_type="credential", object_id=c.id, changed_fields=["name", "credential_type", "config",
                                                                         *[f"secret:{k}" for k in secrets]])
        session.commit()
        session.refresh(c)
        return {"credential": public_credential(c)}


@router.post(FLEET + "/credentials", dependencies=WRITE, openapi_extra=permission("cbom.credentials.write"),
             summary="Add a typed credential (node key, password, SSH certificate, vault, SSH CA)")
async def create_credential(team_id: TeamId, ctx: Member, body: CredentialCreate):
    engine, user = ctx
    return _ok(await _run("create credential", team_id, _create_credential, engine, team_id, user.id, body), 201)


def _update_credential(engine, team_id: int, user_id: int, credential_id: int, body: CredentialUpdate) -> dict:
    now = utcnow()
    with Session(engine) as session:
        require_admin(session, user_id, team_id, "credentials")
        c = _owned_credential(session, team_id, credential_id)
        check_version(c, body.expected_version)
        fields = body.model_dump(exclude_unset=True, exclude={"expected_version", "secrets"})
        if body.config is not None:
            try:
                new_config = check_config(c.credential_type, body.config)
            except (ValidationError, ValueError) as exc:
                raise bad_request(exc) from None
            # where the secret goes (host keys, login) changed: the secret must be entered again
            where_changed = any((c.config or {}).get(k) != new_config.get(k)
                                for k in ("login_user", "port", "host_key_policy", "known_hosts", "vault"))
            c.config = new_config
        else:
            where_changed = False
        current = decrypt_secrets(c.secret_encrypted)
        secrets = _secrets(c.credential_type, current, body.secrets, reset=where_changed)
        c.secret_encrypted, c.secret_fields = encrypt_secrets(secrets), sorted(secrets)
        if body.name is not None:
            c.name = body.name
        bump_version(session, c)
        c.updated_by_user_id, c.last_updated = user_id, now
        session.add(c)
        audit(session, team_id=team_id, actor_type="user", actor_id=user_id, action="fleet.credential.update",
              object_type="credential", object_id=c.id,
              changed_fields=[*fields.keys(), *[f"secret:{k}" for k in (body.secrets or {}) if body.secrets[k]]])
        session.commit()
        session.refresh(c)
        return {"credential": public_credential(c)}


@router.patch(FLEET + "/credentials/{credential_id}", dependencies=WRITE,
              openapi_extra=permission("cbom.credentials.write"),
              summary="Edit a credential (blank secrets keep the stored ones unless the login target changed)")
async def update_credential(team_id: TeamId, credential_id: ObjectId, ctx: Member, body: CredentialUpdate):
    engine, user = ctx
    return _ok(await _run("update credential", team_id, _update_credential, engine, team_id, user.id, credential_id,
                          body))


def _delete_credential(engine, team_id: int, user_id: int, credential_id: int) -> dict:
    now = utcnow()
    with Session(engine) as session:
        require_admin(session, user_id, team_id, "credentials")
        c = _owned_credential(session, team_id, credential_id)
        c.deleted_at, c.secret_encrypted, c.secret_fields, c.last_updated = now, None, [], now
        bump_version(session, c)
        session.add(c)
        session.flush()
        changed = _refresh(session, team_id, now)
        audit(session, team_id=team_id, actor_type="user", actor_id=user_id, action="fleet.credential.delete",
              object_type="credential", object_id=c.id)
        session.commit()
        return {"deleted": credential_id, "decisions_changed": changed}


@router.delete(FLEET + "/credentials/{credential_id}", dependencies=WRITE,
               openapi_extra=permission("cbom.credentials.write"),
               summary="Delete a credential (its secrets are erased; policies that use it stop collecting)")
async def delete_credential(team_id: TeamId, credential_id: ObjectId, ctx: Member):
    engine, user = ctx
    return _ok(await _run("delete credential", team_id, _delete_credential, engine, team_id, user.id, credential_id))
