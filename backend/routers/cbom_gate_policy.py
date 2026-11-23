"""CBOM CI/CD gate policy (SOW S1): the team's policy and per-integration overrides, read by ``POST /cicd/cbom/scan``.

Conventions of the CBOM Sources routes (``backend/utilities/cbom_sources/http.py``): team members read (403 for
non-members); a change needs a team admin (400, never 403, which signs the user out of the frontend); another team's or
a missing integration is a 404; a stale form gets 409; an invalid policy is a 400 naming the field, never echoing the
value. Every change is audited (field names only).

* ``GET  /{team_id}/cbom/gate-policy``: the team policy (or the default), the presets, and each CBOM CI/CD integration
  with its override (or null: it follows the team policy).
* ``PUT  /{team_id}/cbom/gate-policy``, ``DELETE`` (back to the default).
* ``PUT  /{team_id}/cbom/gate-policy/integrations/{integration_id}``, ``DELETE`` (back to the team policy).
"""
from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, Header, HTTPException
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.exc import IntegrityError
from sqlmodel import Session, select

from backend.cbom_gate_models import CbomGatePolicy
from backend.new_models import CicdIntegration
from backend.utilities.cbom_sources import http as _cbom_http
from backend.utilities.cbom_sources.common import audit, iso_z, log, utcnow
from backend.utilities.cbom_sources.http import (
    PRIVATE,
    CHANGED_ELSEWHERE,
    CbomRoute,
    ObjectId,
    TeamId,
    authorize,
    bump_version,
    check_version,
    is_team_admin,
    read_limiter,
    require_admin,
    server_error,
    write_limiter,
)
from backend.utilities.cicd import gate_policy as GP
from backend.utilities.cicd import gate_policy_store as STORE
from backend.utilities.rbac.policy import Access

router = APIRouter(tags=["cicd"], route_class=CbomRoute)
access = Access(lambda: _cbom_http.get_db())  # route policies (utilities/rbac): the same database as authorize()
AuthHeader = Annotated[str | None, Header()]
READ = [Depends(read_limiter)]
WRITE = [Depends(write_limiter)]
BASE = "/{team_id}/cbom/gate-policy"


class PolicyBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    policy: dict[str, Any] = Field(default_factory=dict)
    expected_version: int | None = None


async def _run(what: str, team_id: int, fn, *args) -> Any:
    try:
        return await run_in_threadpool(fn, *args)
    except HTTPException:
        raise
    except Exception as exc:
        raise server_error(f"cbom gate policy {what}", exc, team=team_id) from None


def _ok(payload: Any) -> JSONResponse:
    return JSONResponse(payload, headers=PRIVATE)


def _public(row: CbomGatePolicy | None) -> dict[str, Any] | None:
    if row is None:
        return None
    try:
        policy = GP.validate_policy(row.policy)
        valid = True
    except GP.PolicyError:
        policy, valid = row.policy, False
    return {"policy": policy, "valid": valid, "row_version": row.row_version, "updated_at": iso_z(row.updated_at),
            "digest": GP.policy_digest(policy)}


def _cbom_integration(session: Session, team_id: int, integration_id: int) -> CicdIntegration:
    row = session.get(CicdIntegration, integration_id)
    if row is None or row.team_id != team_id:
        raise HTTPException(status_code=404, detail="CI/CD integration not found")
    if (row.scan_type or "").lower() != "cbom":
        raise HTTPException(status_code=400, detail="Only a CBOM CI/CD integration has a CBOM gate policy")
    return row


def _get(engine, team_id: int, user_id: int) -> dict:
    with Session(engine) as session:
        team_row = STORE.row_for(session, team_id, STORE.TEAM_SCOPE)
        integrations = session.exec(select(CicdIntegration).where(CicdIntegration.team_id == team_id)
                                    .order_by(CicdIntegration.id)).all()  # type: ignore[arg-type]
        overrides = {r.integration_id: r for r in session.exec(
            select(CbomGatePolicy).where(CbomGatePolicy.team_id == team_id,
                                         CbomGatePolicy.integration_id.is_not(None))).all()}  # type: ignore[union-attr]
        return {
            "team": _public(team_row),
            "default": GP.DEFAULT_POLICY,
            "default_digest": GP.policy_digest(GP.DEFAULT_POLICY),
            "presets": GP.PRESETS,
            "rules": list(GP.RULES),
            "key_limits": {k: list(v) for k, v in GP.KEY_LIMITS.items()},
            "max_exception_days": GP.MAX_EXCEPTION_DAYS,
            "file_kind": GP.FILE_KIND,
            "integrations": [{"id": i.id, "title": i.title, "override": _public(overrides.get(i.id))}
                             for i in integrations if (i.scan_type or "").lower() == "cbom"],
            "is_admin": is_team_admin(session, user_id, team_id),
        }


@router.get(BASE, dependencies=[*READ, access.team("cicd.read")],
            summary="CBOM CI/CD gate policy of the team and of each CBOM CI/CD integration")
async def get_gate_policy(team_id: TeamId, Authorization: AuthHeader = None):
    engine, user = await authorize(team_id, Authorization)
    return _ok(await _run("get", team_id, _get, engine, team_id, user.id))


def _validated(body: PolicyBody) -> dict[str, Any]:
    try:
        return GP.validate_policy(body.policy, today=utcnow().date(), for_save=True)
    except GP.PolicyError as exc:
        raise HTTPException(status_code=400, detail=f"policy.{exc.field}: {exc.message}") from None


def _save(engine, team_id: int, user_id: int, integration_id: int | None, body: PolicyBody) -> dict:
    policy = _validated(body)
    now = utcnow()
    with Session(engine) as session:
        require_admin(session, user_id, team_id, "the CBOM gate policy")
        if integration_id is not None:
            _cbom_integration(session, team_id, integration_id)
        scope = STORE.TEAM_SCOPE if integration_id is None else STORE.integration_scope(integration_id)
        row = STORE.row_for(session, team_id, scope)
        if row is None:
            if body.expected_version not in (None, 0):
                raise HTTPException(status_code=409, detail=CHANGED_ELSEWHERE)
            row = CbomGatePolicy(team_id=team_id, scope=scope, integration_id=integration_id, policy=policy,
                                 row_version=1, created_at=now, updated_at=now, updated_by_user_id=user_id)
            session.add(row)
        else:
            check_version(row, body.expected_version)
            if row.policy == policy:
                return {"saved": False, **(_public(row) or {})}
            bump_version(session, row)
            row.policy, row.updated_at, row.updated_by_user_id = policy, now, user_id
            session.add(row)
        try:
            session.flush()
        except IntegrityError:  # two first saves at once: the second sees the first's row
            session.rollback()
            raise HTTPException(status_code=409, detail=CHANGED_ELSEWHERE) from None
        audit(session, team_id=team_id, actor_type="user", actor_id=user_id, action="cicd.gate_policy.save",
              object_type="gate_policy", object_id=row.id, changed_fields=[scope.split(":")[0]])
        session.commit()
        session.refresh(row)
        log("cbom gate policy saved", team=team_id, scope=scope, by=user_id, version=row.row_version,
            digest=GP.policy_digest(policy))
        return {"saved": True, **(_public(row) or {})}


def _delete(engine, team_id: int, user_id: int, integration_id: int | None) -> dict:
    with Session(engine) as session:
        require_admin(session, user_id, team_id, "the CBOM gate policy")
        if integration_id is not None:
            _cbom_integration(session, team_id, integration_id)
        scope = STORE.TEAM_SCOPE if integration_id is None else STORE.integration_scope(integration_id)
        row = STORE.row_for(session, team_id, scope)
        if row is None:
            return {"deleted": False}
        audit(session, team_id=team_id, actor_type="user", actor_id=user_id, action="cicd.gate_policy.delete",
              object_type="gate_policy", object_id=row.id, changed_fields=[scope.split(":")[0]])
        session.delete(row)
        session.commit()
        log("cbom gate policy removed", team=team_id, scope=scope, by=user_id)
        return {"deleted": True}


@router.put(BASE, dependencies=[*WRITE, access.team("cbom.settings")],
            summary="Save the team's CBOM CI/CD gate policy (team admin)")
async def put_team_policy(team_id: TeamId, body: PolicyBody, Authorization: AuthHeader = None):
    engine, user = await authorize(team_id, Authorization)
    return _ok(await _run("save", team_id, _save, engine, team_id, user.id, None, body))


@router.delete(BASE, dependencies=[*WRITE, access.team("cbom.settings")],
               summary="Reset the team's CBOM CI/CD gate policy to the default (team admin)")
async def delete_team_policy(team_id: TeamId, Authorization: AuthHeader = None):
    engine, user = await authorize(team_id, Authorization)
    return _ok(await _run("delete", team_id, _delete, engine, team_id, user.id, None))


@router.put(BASE + "/integrations/{integration_id}", dependencies=[*WRITE, access.team("cbom.settings")],
            summary="Give one CBOM CI/CD integration its own gate policy (team admin)")
async def put_integration_policy(team_id: TeamId, integration_id: ObjectId, body: PolicyBody,
                                 Authorization: AuthHeader = None):
    engine, user = await authorize(team_id, Authorization)
    return _ok(await _run("save", team_id, _save, engine, team_id, user.id, integration_id, body))


@router.delete(BASE + "/integrations/{integration_id}", dependencies=[*WRITE, access.team("cbom.settings")],
               summary="Make one CBOM CI/CD integration follow the team's gate policy again (team admin)")
async def delete_integration_policy(team_id: TeamId, integration_id: ObjectId, Authorization: AuthHeader = None):
    engine, user = await authorize(team_id, Authorization)
    return _ok(await _run("delete", team_id, _delete, engine, team_id, user.id, integration_id))
