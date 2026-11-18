"""Code repositories at scale (F3): org-level SCM connections, the repository inventory, scan policies, bulk runs
with credits shown first, the queue, the cross-repository roll-up, and the signed inbound webhooks.

Conventions of the CBOM Sources API (``backend/utilities/cbom_sources/http.py``): team members read; changes and
anything that spends credits need a team admin (400 with a sentence, never 403, which signs the frontend out); another
team's or a missing record is a 404; a stale form gets 409; validation errors are a 400 that never echoes input.
Credentials are write-only (``secrets_set`` lists the names). Each team route declares its permission in
``openapi_extra["x-zs-permission"]`` with a name of F4's matrix (``backend/utilities/rbac/permissions.py``, which F4
owns; F4's app-level enforcer applies the marker, and tests/test_scm_permissions.py pins the names):

    repos.read     viewer   every GET, estimates and previews (they change nothing)
    repos.manage   admin    connections, filters, sync, webhook secret, bulk include / exclude / pinning, policies,
                            runs (they spend the team's credits) and cancelling them
    (no marker)    public   /scm/webhooks/{provider}/{webhook_uid}: signed with the connection's webhook secret; F4's
                            ``public(...)`` policy is added when F4 (PR #42) and this router are both on dev
"""
from __future__ import annotations

import secrets as pysecrets
from collections import Counter
from typing import Annotated, Any, Literal

from fastapi import APIRouter, BackgroundTasks, Depends, Header, HTTPException, Path, Query, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, ValidationError
from sqlalchemy import func
from sqlmodel import Session, select

from backend.get_db import get_db
from backend.utilities.cbom_sources.common import audit, iso_z, utcnow
from backend.utilities.cbom_sources.crypto import decrypt_secrets, encrypt_secrets
from backend.utilities.cbom_sources.http import (
    PRIVATE,
    CbomRoute,
    ObjectId,
    TeamId,
    authorize,
    bad_request,
    bump_version,
    check_version,
    read_capped_body,
    read_limiter,
    require_admin,
    server_error,
    write_limiter,
)
from backend.utilities.ratelimit import RateLimiter, ip_key
from backend.utilities.scm import filters as F
from backend.utilities.scm import hosts as H
from backend.utilities.scm import inventory as INV
from backend.utilities.scm import policies as P
from backend.utilities.scm import pricing
from backend.utilities.scm import queue as Q
from backend.utilities.scm import rollup as R
from backend.utilities.scm import webhooks as W
from backend.utilities.scm.common import log
from backend.utilities.scm.models import (
    ScmConnection,
    ScmFinding,
    ScmFindingOccurrence,
    ScmRepository,
    ScmScanPolicy,
    ScmScanRequest,
    ScmScanRun,
)
from backend.utilities.scm.providers import ScmError, provider_for_connection

router = APIRouter(tags=["scm"], route_class=CbomRoute)
AuthHeader = Annotated[str | None, Header()]
READ = [Depends(read_limiter)]
WRITE = [Depends(write_limiter)]
webhook_limiter = RateLimiter("scm.webhook", times=600, seconds=60, key_func=ip_key)
BASE = "/{team_id}/scm"
MAX_SECRET = 16384


def perm(name: str) -> dict[str, Any]:
    return {"x-zs-permission": name}


def _ok(payload: Any, status_code: int = 200) -> JSONResponse:
    return JSONResponse(payload, status_code=status_code, headers=PRIVATE)


async def _run(what: str, team_id: int, fn, *args) -> Any:
    try:
        return await run_in_threadpool(fn, *args)
    except HTTPException:
        raise
    except Q.QueueInputError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from None
    except (ValidationError, ValueError) as exc:
        raise bad_request(exc) from None
    except Exception as exc:
        raise server_error(f"scm {what}", exc, team=team_id) from None


class _Body(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


# ============================================================================ serialisers
def public_connection(c: ScmConnection) -> dict[str, Any]:
    return {"id": c.id, "name": c.name, "provider": c.provider, "auth_kind": c.auth_kind, "api_base": c.api_base,
            "scope_kind": c.scope_kind, "scope_name": c.scope_name, "config": c.config or {},
            "filters": c.filters or {}, "secrets_set": sorted(c.secret_fields or []), "enabled": c.enabled,
            "webhook_path": f"/scm/webhooks/{c.provider}/{c.webhook_uid}",
            "webhook_secret_set": bool(c.webhook_secret_encrypted), "sync_interval_min": c.sync_interval_min,
            "sync": {"status": c.sync_status, "last_at": iso_z(c.last_sync_at), "next_at": iso_z(c.next_sync_at),
                     "requested_at": iso_z(c.sync_requested_at), "summary": c.last_sync_summary or {},
                     "error": c.last_sync_error},
            "last_test": {"status": c.last_test_status, "at": iso_z(c.last_test_at), "message": c.last_test_message},
            "row_version": c.row_version, "created_at": iso_z(c.created_at), "updated_at": iso_z(c.last_updated)}


def public_repo(r: ScmRepository, policy: P.PolicyView | None = None, why: str = "none",
                connection_name: str | None = None) -> dict[str, Any]:
    return {"id": r.id, "connection_id": r.connection_id, "connection": connection_name, "full_name": r.full_name,
            "name": r.name, "web_url": r.web_url, "default_branch": r.default_branch, "visibility": r.visibility,
            "archived": r.archived, "fork": r.fork, "language": r.language, "topics": r.topics or [],
            "size_kb": r.size_kb, "pushed_at": iso_z(r.pushed_at), "in_scope": r.in_scope,
            "scope_reason": r.scope_reason, "manual_state": r.manual_state, "pinned_policy_id": r.policy_id,
            "policy": ({"id": policy.id, "name": policy.name, "why": why, "products": policy.products,
                        "on_push": policy.on_push} if policy else None),
            "removed_at": iso_z(r.removed_at), "last_scan_at": iso_z(r.last_scan_at),
            "last_scans": r.last_scan_summary or {}, "first_seen_at": iso_z(r.first_seen_at)}


def public_policy(p: ScmScanPolicy, matched: int | None = None) -> dict[str, Any]:
    return {"id": p.id, "name": p.name, "position": p.position, "enabled": p.enabled, "selector": p.selector or {},
            "products": p.products or [], "branch": p.branch, "on_push": p.on_push, "schedule": p.schedule or {},
            "options": p.options or {}, "next_run_at": iso_z(p.next_run_at), "last_fired_at": iso_z(p.last_fired_at),
            "last_status": p.last_status, "last_message": p.last_message, "last_run_id": p.last_run_id,
            "row_version": p.row_version, "repos_matched": matched}


def public_run(run: ScmScanRun, counts: dict[str, int] | None = None) -> dict[str, Any]:
    return {"id": run.id, "trigger": run.trigger, "policy_id": run.policy_id, "status": run.status,
            "totals": run.totals or {}, "credits": pricing.as_credits(run.credits_c),
            "refunded": pricing.as_credits(run.refunded_c), "requests": counts or {},
            "created_at": iso_z(run.created_at), "finished_at": iso_z(run.finished_at)}


def _estimate_body(est: dict[str, Any]) -> dict[str, Any]:
    skipped = [{"repo_id": r, "product": p, "reason": why} for r, p, why in est["skipped"][:200]]
    return {**est, "skipped": skipped}


def _connection(session: Session, team_id: int, connection_id: int) -> ScmConnection:
    row = session.exec(select(ScmConnection).where(ScmConnection.id == connection_id,
                                                   ScmConnection.team_id == team_id)).first()
    if row is None:
        raise HTTPException(status_code=404, detail="Connection not found")
    return row


def _policy(session: Session, team_id: int, policy_id: int) -> ScmScanPolicy:
    row = session.exec(select(ScmScanPolicy).where(ScmScanPolicy.id == policy_id,
                                                   ScmScanPolicy.team_id == team_id)).first()
    if row is None:
        raise HTTPException(status_code=404, detail="Policy not found")
    return row


# ============================================================================ connections
class ConnectionConfig(_Body):
    app_id: str | None = Field(default=None, max_length=32, pattern=r"^[0-9]*$")
    installation_id: str | None = Field(default=None, max_length=32, pattern=r"^[0-9]*$")
    include_subgroups: bool = True


class ConnectionCreate(_Body):
    name: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$")
    provider: Literal["github", "gitlab", "bitbucket"]
    auth_kind: Literal["github_app", "token"] = "token"
    api_base: str | None = Field(default=None, max_length=255)
    scope_kind: Literal["installation", "org", "user", "group", "workspace"]
    scope_name: str = Field(default="", max_length=255)
    config: ConnectionConfig = Field(default_factory=ConnectionConfig)
    secrets: dict[str, str] = Field(default_factory=dict)
    filters: F.RepoFilters = Field(default_factory=F.RepoFilters)
    sync_interval_min: int = Field(default=360, ge=15, le=10080)


class ConnectionUpdate(_Body):
    name: str | None = Field(default=None, min_length=1, max_length=64, pattern=r"^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$")
    enabled: bool | None = None
    api_base: str | None = Field(default=None, max_length=255)
    scope_name: str | None = Field(default=None, max_length=255)
    config: ConnectionConfig | None = None
    secrets: dict[str, str] = Field(default_factory=dict)
    sync_interval_min: int | None = Field(default=None, ge=15, le=10080)
    expected_version: int | None = None


_SCOPES = {("github", "github_app"): {"installation"}, ("github", "token"): {"org", "user"},
           ("gitlab", "token"): {"group"}, ("bitbucket", "token"): {"workspace"}}
_SECRET_NAMES = {"github_app": ("private_key",), "token": ("token",)}


def _clean_secrets(auth_kind: str, given: dict[str, str]) -> dict[str, str]:
    allowed = _SECRET_NAMES[auth_kind]
    out = {}
    for name, value in given.items():
        if name not in allowed:
            raise HTTPException(status_code=400, detail=f"Secrets: unknown field {name[:32]}")
        if not isinstance(value, str) or len(value) > MAX_SECRET or "\x00" in value:
            raise HTTPException(status_code=400, detail=f"Secrets: {name} is at most {MAX_SECRET} characters")
        if value.strip():
            out[name] = value.strip() if name == "token" else value
    return out


def _check_shape(provider: str, auth_kind: str, scope_kind: str, scope_name: str, config: ConnectionConfig) -> None:
    scopes = _SCOPES.get((provider, auth_kind))
    if not scopes:
        raise HTTPException(status_code=400, detail="Auth kind: a GitHub App is for GitHub; GitLab and Bitbucket use "
                                                    "an access token")
    if scope_kind not in scopes:
        raise HTTPException(status_code=400, detail=f"Scope: use {' or '.join(sorted(scopes))} for this connection")
    if scope_kind != "user" and scope_kind != "installation" and not scope_name.strip():
        raise HTTPException(status_code=400, detail="Scope name: the organisation, group or workspace is required")
    if auth_kind == "github_app" and not (config.app_id and config.installation_id):
        raise HTTPException(status_code=400, detail="Config: a GitHub App needs the App id and the installation id")


def _create_connection(engine, team_id: int, user_id: int, body: ConnectionCreate) -> dict:
    _check_shape(body.provider, body.auth_kind, body.scope_kind, body.scope_name, body.config)
    try:
        api_base = H.check_api_base(body.provider, body.api_base)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=f"API URL: {exc}") from None
    creds = _clean_secrets(body.auth_kind, body.secrets)
    if set(creds) != set(_SECRET_NAMES[body.auth_kind]):
        raise HTTPException(status_code=400, detail="Secrets: the "
                            + ("App private key" if body.auth_kind == "github_app" else "access token") + " is required")
    hook_secret = pysecrets.token_urlsafe(32)
    now = utcnow()
    with Session(engine) as session:
        require_admin(session, user_id, team_id, "repository connections")
        clash = session.exec(select(ScmConnection.id).where(ScmConnection.team_id == team_id,
                                                            ScmConnection.name_lower == body.name.lower())).first()
        if clash is not None:
            raise HTTPException(status_code=409, detail="A connection with this name already exists")
        row = ScmConnection(team_id=team_id, owner_user_id=user_id, updated_by_user_id=user_id, provider=body.provider,
                            auth_kind=body.auth_kind, name=body.name, name_lower=body.name.lower(), api_base=api_base,
                            scope_kind=body.scope_kind, scope_name=body.scope_name.strip(),
                            config=body.config.model_dump(mode="json"), filters=body.filters.model_dump(mode="json"),
                            secret_encrypted=encrypt_secrets(creds), secret_fields=sorted(creds),
                            webhook_uid=pysecrets.token_hex(16), webhook_secret_encrypted=encrypt_secrets(
                                {"webhook_secret": hook_secret}), sync_interval_min=body.sync_interval_min,
                            created_at=now, last_updated=now)
        session.add(row)
        session.flush()
        audit(session, team_id=team_id, actor_type="user", actor_id=user_id, action="scm_connection_created",
              object_type="scm_connection", object_id=row.id,
              changed_fields=["provider", "auth_kind", "scope", "secrets", "filters"])
        session.commit()
        session.refresh(row)
        return {"connection": public_connection(row),
                "webhook": {"path": f"/scm/webhooks/{row.provider}/{row.webhook_uid}", "secret": hook_secret}}


@router.get(BASE + "/connections", dependencies=READ, summary="SCM connections of the team (no secrets)",
            openapi_extra=perm("repos.read"))
async def list_connections(team_id: TeamId, Authorization: AuthHeader = None):
    engine, _user = await authorize(team_id, Authorization)

    def work():
        with Session(engine) as session:
            rows = session.exec(select(ScmConnection).where(ScmConnection.team_id == team_id)
                                .order_by(ScmConnection.id)).all()
            counts = dict(session.exec(select(ScmRepository.connection_id, func.count())
                                       .where(ScmRepository.team_id == team_id, ScmRepository.removed_at == None)  # noqa: E711
                                       .group_by(ScmRepository.connection_id)).all())
            scoped = dict(session.exec(select(ScmRepository.connection_id, func.count())
                                       .where(ScmRepository.team_id == team_id, ScmRepository.in_scope == True)  # noqa: E712
                                       .group_by(ScmRepository.connection_id)).all())
            return {"connections": [{**public_connection(r), "repos": counts.get(r.id, 0),
                                     "repos_in_scope": scoped.get(r.id, 0)} for r in rows],
                    "providers": {"github": ["github_app", "token"], "gitlab": ["token"], "bitbucket": ["token"]},
                    "default_api": H.DEFAULT_API}
    return _ok(await _run("list connections", team_id, work))


@router.post(BASE + "/connections", dependencies=WRITE, status_code=201, openapi_extra=perm("repos.manage"),
             summary="Connect a GitHub org / App installation, GitLab group or Bitbucket workspace")
async def create_connection(team_id: TeamId, body: ConnectionCreate, Authorization: AuthHeader = None):
    engine, user = await authorize(team_id, Authorization)
    return _ok(await _run("create connection", team_id, _create_connection, engine, team_id, user.id, body), 201)


@router.get(BASE + "/connections/{connection_id}", dependencies=READ, openapi_extra=perm("repos.read"),
            summary="One connection, with its sync status")
async def get_connection(team_id: TeamId, connection_id: ObjectId, Authorization: AuthHeader = None):
    engine, _user = await authorize(team_id, Authorization)

    def work():
        with Session(engine) as session:
            return {"connection": public_connection(_connection(session, team_id, connection_id))}
    return _ok(await _run("get connection", team_id, work))


def _update_connection(engine, team_id: int, user_id: int, connection_id: int, body: ConnectionUpdate) -> dict:
    with Session(engine) as session:
        require_admin(session, user_id, team_id, "repository connections")
        row = _connection(session, team_id, connection_id)
        check_version(row, body.expected_version)
        changed = []
        current = decrypt_secrets(row.secret_encrypted)
        new_creds = _clean_secrets(row.auth_kind, body.secrets)
        where_changed = False
        if body.api_base is not None:
            try:
                api_base = H.check_api_base(row.provider, body.api_base)
            except ValueError as exc:
                raise HTTPException(status_code=400, detail=f"API URL: {exc}") from None
            if api_base != row.api_base:
                row.api_base, where_changed = api_base, True
                changed.append("api_base")
        if body.scope_name is not None and body.scope_name.strip() != row.scope_name:
            row.scope_name, where_changed = body.scope_name.strip(), True
            changed.append("scope_name")
        if body.config is not None:
            new_config = body.config.model_dump(mode="json")
            if new_config != (row.config or {}):
                where_changed = where_changed or any((row.config or {}).get(k) != new_config.get(k)
                                                     for k in ("app_id", "installation_id"))
                row.config = new_config
                changed.append("config")
        # a credential can never be pointed somewhere else by someone who cannot see it: re-enter it
        if where_changed and set(new_creds) != set(_SECRET_NAMES[row.auth_kind]):
            raise HTTPException(status_code=400, detail="Secrets: re-enter the credential when the API URL, scope or "
                                                        "App changes")
        if new_creds:
            current.update(new_creds)
            row.secret_encrypted, row.secret_fields = encrypt_secrets(current), sorted(current)
            changed.append("secrets")
        _check_shape(row.provider, row.auth_kind, row.scope_kind, row.scope_name,
                     ConnectionConfig.model_validate(row.config or {}))
        if body.name is not None and body.name != row.name:
            clash = session.exec(select(ScmConnection.id).where(ScmConnection.team_id == team_id,
                                                                ScmConnection.name_lower == body.name.lower(),
                                                                ScmConnection.id != row.id)).first()
            if clash is not None:
                raise HTTPException(status_code=409, detail="A connection with this name already exists")
            row.name, row.name_lower = body.name, body.name.lower()
            changed.append("name")
        if body.enabled is not None and body.enabled != row.enabled:
            row.enabled = body.enabled
            changed.append("enabled")
        if body.sync_interval_min is not None and body.sync_interval_min != row.sync_interval_min:
            row.sync_interval_min = body.sync_interval_min
            changed.append("sync_interval_min")
        if changed:
            bump_version(session, row)
            row.updated_by_user_id, row.last_updated = user_id, utcnow()
            session.add(row)
            audit(session, team_id=team_id, actor_type="user", actor_id=user_id, action="scm_connection_updated",
                  object_type="scm_connection", object_id=row.id, changed_fields=changed)
        session.commit()
        session.refresh(row)
        return {"connection": public_connection(row)}


@router.patch(BASE + "/connections/{connection_id}", dependencies=WRITE, openapi_extra=perm("repos.manage"),
              summary="Rename, disable, re-key or re-point a connection")
async def update_connection(team_id: TeamId, connection_id: ObjectId, body: ConnectionUpdate,
                            Authorization: AuthHeader = None):
    engine, user = await authorize(team_id, Authorization)
    return _ok(await _run("update connection", team_id, _update_connection, engine, team_id, user.id, connection_id,
                          body))


def _delete_connection(engine, team_id: int, user_id: int, connection_id: int) -> dict:
    now = utcnow()
    with Session(engine) as session:
        require_admin(session, user_id, team_id, "repository connections")
        row = _connection(session, team_id, connection_id)
        repo_ids = list(session.exec(select(ScmRepository.id).where(ScmRepository.connection_id == row.id)).all())
        queued = list(session.exec(select(ScmScanRequest.id).where(ScmScanRequest.team_id == team_id,
                                                                   ScmScanRequest.repo_id.in_(repo_ids),  # type: ignore[union-attr]
                                                                   ScmScanRequest.status == "queued")).all()) \
            if repo_ids else []
        refunded = Q._refund_requests(session, team_id, queued, "cancelled", "The connection was deleted", now,
                                      from_status=("queued",))
        for repo_id in repo_ids:
            R.forget_repo(session, repo_id, now)
        audit(session, team_id=team_id, actor_type="user", actor_id=user_id, action="scm_connection_deleted",
              object_type="scm_connection", object_id=row.id, changed_fields=["deleted"])
        session.delete(row)
        session.commit()
    return {"deleted": connection_id, "repositories": len(repo_ids), "refunded": pricing.as_credits(refunded)}


@router.delete(BASE + "/connections/{connection_id}", dependencies=WRITE, openapi_extra=perm("repos.manage"),
               summary="Delete a connection and its inventory (queued scans are cancelled and refunded)")
async def delete_connection(team_id: TeamId, connection_id: ObjectId, Authorization: AuthHeader = None):
    engine, user = await authorize(team_id, Authorization)
    return _ok(await _run("delete connection", team_id, _delete_connection, engine, team_id, user.id, connection_id))


def _test_connection(engine, team_id: int, user_id: int, connection_id: int) -> dict:
    with Session(engine) as session:
        require_admin(session, user_id, team_id, "repository connections")
        row = _connection(session, team_id, connection_id)
        ok, message = True, ""
        provider = None
        try:
            provider = provider_for_connection(row, max_wait_s=10)
            message = provider.test()
        except ScmError as err:
            ok, message = False, str(err)
        finally:
            if provider is not None:
                provider.close()
        row.last_test_status, row.last_test_at, row.last_test_message = ("ok" if ok else "failed"), utcnow(), message[:250]
        session.add(row)
        session.commit()
        return {"ok": ok, "message": message[:250]}


@router.post(BASE + "/connections/{connection_id}/test", dependencies=WRITE, openapi_extra=perm("repos.manage"),
             summary="Check that the credential can read the organisation, group or workspace")
async def test_connection(team_id: TeamId, connection_id: ObjectId, Authorization: AuthHeader = None):
    engine, user = await authorize(team_id, Authorization)
    return _ok(await _run("test connection", team_id, _test_connection, engine, team_id, user.id, connection_id))


def _request_sync(engine, team_id: int, user_id: int, connection_id: int) -> dict:
    with Session(engine) as session:
        require_admin(session, user_id, team_id, "repository connections")
        row = _connection(session, team_id, connection_id)
        if not row.enabled:
            raise HTTPException(status_code=400, detail="The connection is disabled")
        busy = row.sync_lease_until is not None and row.sync_lease_until > utcnow()
        row.sync_requested_at = utcnow()
        if not busy:
            row.sync_status = "queued"
        session.add(row)
        session.commit()
        return {"status": "running" if busy else "queued", "connection": public_connection(row)}


def _background_sync(engine, connection_id: int) -> None:
    try:
        INV.sync_connection(engine, connection_id)
    except Exception as exc:  # the scheduler retries; never leave a traceback in the request log
        log("sync FAILED", connection=connection_id, error=type(exc).__name__)


@router.post(BASE + "/connections/{connection_id}/sync", dependencies=WRITE, status_code=202,
             openapi_extra=perm("repos.manage"), summary="Discover the connection's repositories now")
async def sync_connection(team_id: TeamId, connection_id: ObjectId, background: BackgroundTasks,
                          Authorization: AuthHeader = None):
    engine, user = await authorize(team_id, Authorization)
    out = await _run("sync", team_id, _request_sync, engine, team_id, user.id, connection_id)
    if out["status"] == "queued":
        background.add_task(_background_sync, engine, connection_id)
    return _ok(out, 202)


def _rotate_secret(engine, team_id: int, user_id: int, connection_id: int) -> dict:
    secret = pysecrets.token_urlsafe(32)
    with Session(engine) as session:
        require_admin(session, user_id, team_id, "repository connections")
        row = _connection(session, team_id, connection_id)
        row.webhook_secret_encrypted = encrypt_secrets({"webhook_secret": secret})
        bump_version(session, row)
        audit(session, team_id=team_id, actor_type="user", actor_id=user_id, action="scm_webhook_secret_rotated",
              object_type="scm_connection", object_id=row.id, changed_fields=["webhook_secret"])
        session.add(row)
        session.commit()
        return {"webhook": {"path": f"/scm/webhooks/{row.provider}/{row.webhook_uid}", "secret": secret}}


@router.post(BASE + "/connections/{connection_id}/webhook-secret", dependencies=WRITE,
             openapi_extra=perm("repos.manage"), summary="Generate a new webhook secret (shown once)")
async def rotate_webhook_secret(team_id: TeamId, connection_id: ObjectId, Authorization: AuthHeader = None):
    engine, user = await authorize(team_id, Authorization)
    return _ok(await _run("rotate webhook secret", team_id, _rotate_secret, engine, team_id, user.id, connection_id))


class FiltersBody(_Body):
    filters: F.RepoFilters = Field(default_factory=F.RepoFilters)
    products: list[Literal["sast", "iac", "sbom_sca", "cbom", "ai_bom"]] = Field(default_factory=list, max_length=5)
    expected_version: int | None = None


def _preview(engine, team_id: int, connection_id: int, body: FiltersBody) -> dict:
    with Session(engine) as session:
        row = _connection(session, team_id, connection_id)
        repos = session.exec(select(ScmRepository).where(ScmRepository.connection_id == row.id,
                                                         ScmRepository.removed_at == None)  # noqa: E711
                             .order_by(ScmRepository.full_name)).all()
        reasons: Counter = Counter()
        matched: list[ScmRepository] = []
        excluded: list[dict[str, Any]] = []
        for repo in repos:
            ok, why = F.in_scope(INV.filter_input(repo), body.filters, repo.manual_state)
            reasons[why] += 1
            if ok:
                matched.append(repo)
            elif len(excluded) < 10:
                excluded.append({"full_name": repo.full_name, "reason": why})
        per_product = {}
        total_c = 0
        for product in body.products:
            cents = sum(pricing.price_c(product, r.size_kb) for r in matched
                        if product != "sast" or Q.sast_language(r.language))
            per_product[product] = pricing.as_credits(cents)
            total_c += cents
        return {"discovered": len(repos), "in_scope": len(matched), "reasons": dict(reasons),
                "sample_in": [r.full_name for r in matched[:10]], "sample_out": excluded,
                "estimate": {"per_product": per_product, "credits": pricing.as_credits(total_c),
                             "formula": pricing.FORMULA},
                "sync": {"status": row.sync_status, "last_at": iso_z(row.last_sync_at)}}


@router.post(BASE + "/connections/{connection_id}/preview", dependencies=READ, openapi_extra=perm("repos.read"),
             summary="How many discovered repositories these filters keep, and what one scan of them would cost")
async def preview_filters(team_id: TeamId, connection_id: ObjectId, body: FiltersBody, Authorization: AuthHeader = None):
    engine, _user = await authorize(team_id, Authorization)
    return _ok(await _run("preview", team_id, _preview, engine, team_id, connection_id, body))


def _import(engine, team_id: int, user_id: int, connection_id: int, body: FiltersBody) -> dict:
    with Session(engine) as session:
        require_admin(session, user_id, team_id, "repository connections")
        row = _connection(session, team_id, connection_id)
        check_version(row, body.expected_version)
        changed = INV.apply_filters(session, row.id, body.filters)
        bump_version(session, row)
        row.updated_by_user_id, row.last_updated = user_id, utcnow()
        session.add(row)
        audit(session, team_id=team_id, actor_type="user", actor_id=user_id, action="scm_filters_applied",
              object_type="scm_connection", object_id=row.id, changed_fields=["filters"])
        session.commit()
        in_scope = session.exec(select(func.count()).select_from(ScmRepository).where(
            ScmRepository.connection_id == row.id, ScmRepository.in_scope == True)).one()  # noqa: E712
        session.refresh(row)
        return {"changed": changed, "in_scope": int(in_scope), "connection": public_connection(row)}


@router.put(BASE + "/connections/{connection_id}/filters", dependencies=WRITE,
            openapi_extra=perm("repos.manage"), summary="Import: save the filters and apply them")
async def apply_filters(team_id: TeamId, connection_id: ObjectId, body: FiltersBody, Authorization: AuthHeader = None):
    engine, user = await authorize(team_id, Authorization)
    return _ok(await _run("import", team_id, _import, engine, team_id, user.id, connection_id, body))


# ============================================================================ repositories
def _repo_query(team_id: int, *, connection_id: int | None, q: str | None, scope: str, language: str | None,
                reason: str | None, policy_pinned: int | None, scanned: str | None):
    query = select(ScmRepository).where(ScmRepository.team_id == team_id)
    if connection_id:
        query = query.where(ScmRepository.connection_id == connection_id)
    if scope == "in":
        query = query.where(ScmRepository.in_scope == True)  # noqa: E712
    elif scope == "out":
        query = query.where(ScmRepository.in_scope == False, ScmRepository.removed_at == None)  # noqa: E711,E712
    elif scope == "removed":
        query = query.where(ScmRepository.removed_at != None)  # noqa: E711
    else:
        query = query.where(ScmRepository.removed_at == None)  # noqa: E711
    if q:
        query = query.where(func.lower(ScmRepository.full_name).contains(q.strip().lower()[:100]))
    if language:
        query = query.where(func.lower(ScmRepository.language) == language.strip().lower()[:64])
    if reason:
        query = query.where(ScmRepository.scope_reason == reason[:64])
    if policy_pinned:
        query = query.where(ScmRepository.policy_id == policy_pinned)
    if scanned == "never":
        query = query.where(ScmRepository.last_scan_at == None)  # noqa: E711
    elif scanned == "yes":
        query = query.where(ScmRepository.last_scan_at != None)  # noqa: E711
    return query


def _list_repos(engine, team_id: int, params: dict[str, Any]) -> dict:
    page, size = params.pop("page"), params.pop("page_size")
    with Session(engine) as session:
        query = _repo_query(team_id, **params)
        total = session.exec(select(func.count()).select_from(query.subquery())).one()
        rows = session.exec(query.order_by(ScmRepository.full_name).offset((page - 1) * size).limit(size)).all()
        policies = P.team_policies(session, team_id)
        names = dict(session.exec(select(ScmConnection.id, ScmConnection.name)
                                  .where(ScmConnection.team_id == team_id)).all())
        items = []
        for r in rows:
            winner, why = P.winning_policy(INV.filter_input(r), policies, r.policy_id) if r.in_scope else (None, "none")
            items.append(public_repo(r, winner, why, names.get(r.connection_id)))
        base = select(ScmRepository).where(ScmRepository.team_id == team_id, ScmRepository.removed_at == None)  # noqa: E711
        if params.get("connection_id"):
            base = base.where(ScmRepository.connection_id == params["connection_id"])
        sub = base.subquery()
        languages = session.exec(select(sub.c.language, func.count()).group_by(sub.c.language)).all()
        reasons = session.exec(select(sub.c.scope_reason, func.count()).group_by(sub.c.scope_reason)).all()
        scoped = session.exec(select(func.count()).select_from(sub).where(sub.c.in_scope == True)).one()  # noqa: E712
        return {"items": items, "total": int(total), "page": page, "page_size": size,
                "facets": {"languages": {str(k or ""): int(v) for k, v in languages},
                           "reasons": {str(k or ""): int(v) for k, v in reasons}, "in_scope": int(scoped)}}


@router.get(BASE + "/repositories", dependencies=READ, openapi_extra=perm("repos.read"),
            summary="The repository inventory, filtered and paged, with facets")
async def list_repositories(team_id: TeamId, Authorization: AuthHeader = None,
                            connection_id: int | None = Query(default=None, ge=1),
                            q: str | None = Query(default=None, max_length=100),
                            scope: Literal["in", "out", "all", "removed"] = "all",
                            language: str | None = Query(default=None, max_length=64),
                            reason: str | None = Query(default=None, max_length=64),
                            policy_id: int | None = Query(default=None, ge=1),
                            scanned: Literal["never", "yes"] | None = None,
                            page: int = Query(default=1, ge=1, le=100000),
                            page_size: int = Query(default=50, ge=1, le=200)):
    engine, _user = await authorize(team_id, Authorization)
    params = {"connection_id": connection_id, "q": q, "scope": scope, "language": language, "reason": reason,
              "policy_pinned": policy_id, "scanned": scanned, "page": page, "page_size": page_size}
    return _ok(await _run("list repositories", team_id, _list_repos, engine, team_id, params))


class BulkBody(_Body):
    repo_ids: list[int] = Field(min_length=1, max_length=10000)
    action: Literal["include", "exclude", "reset", "pin_policy", "unpin_policy"]
    policy_id: int | None = Field(default=None, ge=1)


def _bulk(engine, team_id: int, user_id: int, body: BulkBody) -> dict:
    with Session(engine) as session:
        require_admin(session, user_id, team_id, "the repository inventory")
        if body.action in ("include", "exclude", "reset"):
            changed = INV.set_manual_state(session, team_id=team_id, repo_ids=body.repo_ids,
                                           state=None if body.action == "reset" else body.action)
        else:
            if body.action == "pin_policy":
                if body.policy_id is None:
                    raise HTTPException(status_code=400, detail="Policy: choose the policy to pin")
                _policy(session, team_id, body.policy_id)
            rows = session.exec(select(ScmRepository).where(ScmRepository.team_id == team_id,
                                                            ScmRepository.id.in_(body.repo_ids))).all()  # type: ignore[union-attr]
            for row in rows:
                row.policy_id = body.policy_id if body.action == "pin_policy" else None
                session.add(row)
            changed = len(rows)
        audit(session, team_id=team_id, actor_type="user", actor_id=user_id, action=f"scm_repos_{body.action}",
              object_type="scm_repository", object_id=None, changed_fields=["manual_state" if body.action in
                                                                            ("include", "exclude", "reset")
                                                                            else "policy_id"])
        session.commit()
        return {"changed": changed}


@router.post(BASE + "/repositories/bulk", dependencies=WRITE, openapi_extra=perm("repos.manage"),
             summary="Include, exclude or reset repositories, or pin them to a policy")
async def bulk_repositories(team_id: TeamId, body: BulkBody, Authorization: AuthHeader = None):
    engine, user = await authorize(team_id, Authorization)
    return _ok(await _run("bulk", team_id, _bulk, engine, team_id, user.id, body))


# ============================================================================ policies
class PolicyBody(_Body):
    name: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$")
    position: int = Field(default=100, ge=0, le=100000)
    enabled: bool = True
    selector: F.RepoFilters = Field(default_factory=F.RepoFilters)
    products: list[Literal["sast", "iac", "sbom_sca", "cbom", "ai_bom"]] = Field(min_length=1, max_length=5)
    branch: str = Field(default="", max_length=255, pattern=r"^[^\s~^:?*\[\\]*$")
    on_push: bool = False
    schedule: P.ScheduleSpec = Field(default_factory=P.ScheduleSpec)
    options: dict[str, Any] = Field(default_factory=dict)
    expected_version: int | None = None


_OPTION_KEYS = {"iac_modes", "environment", "cbom_scan_binaries", "cbom_include_vendored", "cbom_scan_history"}


def _clean_options(options: dict[str, Any]) -> dict[str, Any]:
    unknown = set(options) - _OPTION_KEYS
    if unknown:
        raise HTTPException(status_code=400, detail=f"Options: unknown option {sorted(unknown)[0][:32]}")
    out: dict[str, Any] = {}
    if "iac_modes" in options:
        modes = options["iac_modes"]
        if not isinstance(modes, list) or not all(m in Q.DEFAULT_IAC_MODES for m in modes):
            raise HTTPException(status_code=400, detail=f"Options: IaC modes are {', '.join(Q.DEFAULT_IAC_MODES)}")
        out["iac_modes"] = list(dict.fromkeys(modes))
    if "environment" in options:
        if options["environment"] not in ("production", "staging", "development"):
            raise HTTPException(status_code=400, detail="Options: environment is production, staging or development")
        out["environment"] = options["environment"]
    for key in ("cbom_scan_binaries", "cbom_include_vendored", "cbom_scan_history"):
        if key in options:
            out[key] = bool(options[key])
    return out


def _matched_counts(session: Session, team_id: int) -> Counter:
    policies = P.team_policies(session, team_id)
    counts: Counter = Counter()
    for repo in session.exec(select(ScmRepository).where(ScmRepository.team_id == team_id,
                                                         ScmRepository.in_scope == True)).all():  # noqa: E712
        winner, _why = P.winning_policy(INV.filter_input(repo), policies, repo.policy_id)
        if winner is not None:
            counts[winner.id] += 1
    return counts


def _list_policies(engine, team_id: int) -> dict:
    with Session(engine) as session:
        rows = session.exec(select(ScmScanPolicy).where(ScmScanPolicy.team_id == team_id)
                            .order_by(ScmScanPolicy.position, ScmScanPolicy.id)).all()
        counts = _matched_counts(session, team_id)
        return {"policies": [public_policy(r, counts.get(r.id, 0)) for r in rows], "products": list(pricing.PRODUCTS),
                "iac_modes": Q.DEFAULT_IAC_MODES}


@router.get(BASE + "/policies", dependencies=READ, openapi_extra=perm("repos.read"),
            summary="Scan policies in evaluation order, with how many repositories each one takes")
async def list_policies(team_id: TeamId, Authorization: AuthHeader = None):
    engine, _user = await authorize(team_id, Authorization)
    return _ok(await _run("list policies", team_id, _list_policies, engine, team_id))


def _save_policy(engine, team_id: int, user_id: int, policy_id: int | None, body: PolicyBody) -> dict:
    options = _clean_options(body.options)
    now = utcnow()
    with Session(engine) as session:
        require_admin(session, user_id, team_id, "scan policies")
        clash = session.exec(select(ScmScanPolicy.id).where(ScmScanPolicy.team_id == team_id,
                                                            ScmScanPolicy.name_lower == body.name.lower(),
                                                            ScmScanPolicy.id != (policy_id or 0))).first()
        if clash is not None:
            raise HTTPException(status_code=409, detail="A policy with this name already exists")
        if policy_id is None:
            row = ScmScanPolicy(team_id=team_id, owner_user_id=user_id, name=body.name, name_lower=body.name.lower(),
                                created_at=now)
        else:
            row = _policy(session, team_id, policy_id)
            check_version(row, body.expected_version)
            bump_version(session, row)
        schedule = body.schedule.model_dump(mode="json")
        if schedule != (row.schedule or {}) or row.next_run_at is None:
            row.next_run_at = P.next_run(body.schedule, now)
        row.name, row.name_lower, row.position, row.enabled = body.name, body.name.lower(), body.position, body.enabled
        row.selector, row.products = body.selector.model_dump(mode="json"), list(dict.fromkeys(body.products))
        row.branch, row.on_push, row.schedule, row.options = body.branch, body.on_push, schedule, options
        row.updated_by_user_id, row.last_updated = user_id, now
        session.add(row)
        session.flush()
        audit(session, team_id=team_id, actor_type="user", actor_id=user_id,
              action="scm_policy_created" if policy_id is None else "scm_policy_updated", object_type="scm_policy",
              object_id=row.id, changed_fields=["selector", "products", "branch", "on_push", "schedule", "options"])
        session.commit()
        session.refresh(row)
        return {"policy": public_policy(row, _matched_counts(session, team_id).get(row.id, 0))}


@router.post(BASE + "/policies", dependencies=WRITE, status_code=201, openapi_extra=perm("repos.manage"),
             summary="Create a scan policy for a group of repositories")
async def create_policy(team_id: TeamId, body: PolicyBody, Authorization: AuthHeader = None):
    engine, user = await authorize(team_id, Authorization)
    return _ok(await _run("create policy", team_id, _save_policy, engine, team_id, user.id, None, body), 201)


@router.put(BASE + "/policies/{policy_id}", dependencies=WRITE, openapi_extra=perm("repos.manage"),
            summary="Change a scan policy")
async def update_policy(team_id: TeamId, policy_id: ObjectId, body: PolicyBody, Authorization: AuthHeader = None):
    engine, user = await authorize(team_id, Authorization)
    return _ok(await _run("update policy", team_id, _save_policy, engine, team_id, user.id, policy_id, body))


def _delete_policy(engine, team_id: int, user_id: int, policy_id: int) -> dict:
    with Session(engine) as session:
        require_admin(session, user_id, team_id, "scan policies")
        row = _policy(session, team_id, policy_id)
        for repo in session.exec(select(ScmRepository).where(ScmRepository.team_id == team_id,
                                                             ScmRepository.policy_id == policy_id)).all():
            repo.policy_id = None
            session.add(repo)
        audit(session, team_id=team_id, actor_type="user", actor_id=user_id, action="scm_policy_deleted",
              object_type="scm_policy", object_id=row.id, changed_fields=["deleted"])
        session.delete(row)
        session.commit()
    return {"deleted": policy_id}


@router.delete(BASE + "/policies/{policy_id}", dependencies=WRITE, openapi_extra=perm("repos.manage"),
               summary="Delete a scan policy (pinned repositories fall back to the selectors)")
async def delete_policy(team_id: TeamId, policy_id: ObjectId, Authorization: AuthHeader = None):
    engine, user = await authorize(team_id, Authorization)
    return _ok(await _run("delete policy", team_id, _delete_policy, engine, team_id, user.id, policy_id))


class PolicyPreviewBody(_Body):
    selector: F.RepoFilters = Field(default_factory=F.RepoFilters)
    products: list[Literal["sast", "iac", "sbom_sca", "cbom", "ai_bom"]] = Field(default_factory=list, max_length=5)
    position: int = Field(default=100, ge=0, le=100000)
    policy_id: int | None = Field(default=None, ge=1)


def _policy_preview(engine, team_id: int, body: PolicyPreviewBody) -> dict:
    """Which in-scope repositories an (unsaved) policy would take, given the other policies, and one run's price."""
    with Session(engine) as session:
        others = [p for p in P.team_policies(session, team_id) if p.id != body.policy_id]
        draft = P.PolicyView(id=body.policy_id or 10**9, position=body.position, enabled=True,
                             selector=body.selector.model_dump(mode="json"), products=list(body.products), name="draft")
        repos = session.exec(select(ScmRepository).where(ScmRepository.team_id == team_id,
                                                         ScmRepository.in_scope == True)).all()  # noqa: E712
        taken, lost_to = [], Counter()
        for repo in repos:
            winner, _why = P.winning_policy(INV.filter_input(repo), [*others, draft], repo.policy_id)
            if winner is draft:
                taken.append(repo)
            elif winner is not None and F.evaluate(INV.filter_input(repo), body.selector)[0]:
                lost_to[winner.name] += 1
        cents = sum(pricing.price_c(p, r.size_kb) for r in taken for p in body.products
                    if p != "sast" or Q.sast_language(r.language))
        return {"repos": len(taken), "sample": [r.full_name for r in taken[:10]], "taken_by_other_policies": dict(lost_to),
                "credits_per_run": pricing.as_credits(cents), "formula": pricing.FORMULA}


@router.post(BASE + "/policies/preview", dependencies=READ, openapi_extra=perm("repos.read"),
             summary="Which repositories a policy would take, and what one run of it costs")
async def preview_policy(team_id: TeamId, body: PolicyPreviewBody, Authorization: AuthHeader = None):
    engine, _user = await authorize(team_id, Authorization)
    return _ok(await _run("policy preview", team_id, _policy_preview, engine, team_id, body))


# ============================================================================ runs and the queue
class RunBody(_Body):
    repo_ids: list[int] | None = Field(default=None, max_length=10000)
    policy_id: int | None = Field(default=None, ge=1)
    products: list[Literal["sast", "iac", "sbom_sca", "cbom", "ai_bom"]] | None = Field(default=None, max_length=5)
    branch: str | None = Field(default=None, max_length=255, pattern=r"^[^\s~^:?*\[\\]*$")
    expected_credits: float | None = Field(default=None, ge=0)
    client_request_id: str | None = Field(default=None, max_length=64, pattern=r"^[A-Za-z0-9._:-]+$")


def _plan_kwargs(body: RunBody) -> dict[str, Any]:
    if (body.repo_ids is None) == (body.policy_id is None):
        raise HTTPException(status_code=400, detail="Choose repositories or a policy (one of the two)")
    return {"repo_ids": body.repo_ids, "policy_id": body.policy_id, "products": body.products or None,
            "branch": body.branch or None}


def _estimate(engine, team_id: int, body: RunBody) -> dict:
    kw = _plan_kwargs(body)
    with Session(engine) as session:
        return _estimate_body(Q.estimate(session, team_id, **kw))


@router.post(BASE + "/runs/estimate", dependencies=READ, openapi_extra=perm("repos.read"),
             summary="What a bulk run would scan and cost, before anything is charged")
async def estimate_run(team_id: TeamId, body: RunBody, Authorization: AuthHeader = None):
    engine, _user = await authorize(team_id, Authorization)
    return _ok(await _run("estimate", team_id, _estimate, engine, team_id, body))


def _create_run(engine, team_id: int, user_id: int, body: RunBody) -> JSONResponse:
    kw = _plan_kwargs(body)
    if body.expected_credits is None or not body.client_request_id:
        raise HTTPException(status_code=400, detail="Estimate first: a run needs the price you saw (expected_credits) "
                                                    "and a client_request_id")
    with Session(engine) as session:
        require_admin(session, user_id, team_id, "bulk scans (they spend the team's credits)")
    try:
        run = Q.create_run(engine, team_id, user_id, trigger="manual", expected_credits=body.expected_credits,
                           client_request_id=body.client_request_id, now=utcnow(), **kw)
    except Q.EstimateChanged as exc:
        return JSONResponse({"detail": f"The price changed to {exc.estimate['credits']:g} credits (repositories or "
                                       "the queue changed since the estimate). Nothing was charged.",
                             "code": "estimate_changed", "estimate": _estimate_body(exc.estimate)},
                            status_code=409, headers=PRIVATE)
    except Q.InsufficientCredits as exc:
        raise HTTPException(status_code=400, detail=f"The run costs {exc.estimate['credits']:g} credits and the team "
                                                    f"has {exc.estimate['balance']:g}. Nothing was charged.") from None
    except Q.NothingToScan:
        raise HTTPException(status_code=400, detail="Nothing to scan: every chosen scan is already queued or skipped") from None
    with Session(engine) as session:
        audit(session, team_id=team_id, actor_type="user", actor_id=user_id, action="scm_run_started",
              object_type="scm_run", object_id=run["run_id"], changed_fields=["credits", "scans"])
        session.commit()
    return JSONResponse({"run": run}, status_code=201, headers=PRIVATE)


@router.post(BASE + "/runs", dependencies=WRITE, status_code=201, openapi_extra=perm("repos.manage"),
             summary="Start a bulk run at the estimated price (charged once, as a whole)")
async def create_run(team_id: TeamId, body: RunBody, Authorization: AuthHeader = None):
    engine, user = await authorize(team_id, Authorization)
    return await _run("create run", team_id, _create_run, engine, team_id, user.id, body)


def _request_counts(session: Session, run_ids: list[int]) -> dict[int, dict[str, int]]:
    out: dict[int, dict[str, int]] = {}
    if not run_ids:
        return out
    for run_id, status, n in session.exec(select(ScmScanRequest.run_id, ScmScanRequest.status, func.count())
                                          .where(ScmScanRequest.run_id.in_(run_ids))  # type: ignore[union-attr]
                                          .group_by(ScmScanRequest.run_id, ScmScanRequest.status)).all():
        out.setdefault(run_id, {})[status] = int(n)
    return out


def _list_runs(engine, team_id: int, limit: int) -> dict:
    with Session(engine) as session:
        runs = session.exec(select(ScmScanRun).where(ScmScanRun.team_id == team_id)
                            .order_by(ScmScanRun.id.desc()).limit(limit)).all()  # type: ignore[union-attr]
        counts = _request_counts(session, [r.id for r in runs])
        return {"runs": [public_run(r, counts.get(r.id)) for r in runs], "queue": Q.queue_stats(session, team_id)}


@router.get(BASE + "/runs", dependencies=READ, openapi_extra=perm("repos.read"), summary="Recent runs and the queue")
async def list_runs(team_id: TeamId, Authorization: AuthHeader = None, limit: int = Query(default=25, ge=1, le=200)):
    engine, _user = await authorize(team_id, Authorization)
    return _ok(await _run("list runs", team_id, _list_runs, engine, team_id, limit))


def _get_run(engine, team_id: int, run_id: int, page: int, size: int, status: str | None) -> dict:
    with Session(engine) as session:
        run = session.exec(select(ScmScanRun).where(ScmScanRun.id == run_id, ScmScanRun.team_id == team_id)).first()
        if run is None:
            raise HTTPException(status_code=404, detail="Run not found")
        query = select(ScmScanRequest, ScmRepository.full_name).join(
            ScmRepository, ScmRepository.id == ScmScanRequest.repo_id).where(ScmScanRequest.run_id == run_id)
        if status:
            query = query.where(ScmScanRequest.status == status)
        rows = session.exec(query.order_by(ScmScanRequest.id).offset((page - 1) * size).limit(size)).all()
        return {"run": public_run(run, _request_counts(session, [run.id]).get(run.id)),
                "requests": [{"id": r.id, "repo_id": r.repo_id, "repo": name, "product": r.product, "branch": r.branch,
                              "status": r.status, "priority": r.priority, "scan_id": r.scan_id,
                              "credits": pricing.as_credits(r.credits_c), "refunded": r.refunded, "error": r.error,
                              "enqueued_at": iso_z(r.enqueued_at), "dispatched_at": iso_z(r.dispatched_at),
                              "finished_at": iso_z(r.finished_at)} for r, name in rows],
                "page": page, "page_size": size}


@router.get(BASE + "/runs/{run_id}", dependencies=READ, openapi_extra=perm("repos.read"),
            summary="One run and its scans")
async def get_run(team_id: TeamId, run_id: ObjectId, Authorization: AuthHeader = None,
                  page: int = Query(default=1, ge=1, le=100000), page_size: int = Query(default=50, ge=1, le=200),
                  status: Literal["queued", "dispatching", "dispatched", "done", "failed", "skipped", "cancelled"] | None = None):
    engine, _user = await authorize(team_id, Authorization)
    return _ok(await _run("get run", team_id, _get_run, engine, team_id, run_id, page, page_size, status))


def _cancel(engine, team_id: int, user_id: int, run_id: int) -> dict:
    with Session(engine) as session:
        require_admin(session, user_id, team_id, "bulk scans")
    refunded = Q.cancel_run(engine, team_id, run_id, utcnow())
    with Session(engine) as session:
        audit(session, team_id=team_id, actor_type="user", actor_id=user_id, action="scm_run_cancelled",
              object_type="scm_run", object_id=run_id, changed_fields=["status"])
        session.commit()
    return {"refunded": refunded}


@router.post(BASE + "/runs/{run_id}/cancel", dependencies=WRITE, openapi_extra=perm("repos.manage"),
             summary="Cancel the scans of a run that have not started (refunded)")
async def cancel_run(team_id: TeamId, run_id: ObjectId, Authorization: AuthHeader = None):
    engine, user = await authorize(team_id, Authorization)
    return _ok(await _run("cancel run", team_id, _cancel, engine, team_id, user.id, run_id))


# ============================================================================ roll-up
def _list_findings(engine, team_id: int, product: str | None, severity: str | None, q: str | None, min_repos: int,
                   include_resolved: bool, page: int, size: int) -> dict:
    with Session(engine) as session:
        query = select(ScmFinding).where(ScmFinding.team_id == team_id, ScmFinding.repo_count >= min_repos)
        if not include_resolved:
            query = query.where(ScmFinding.resolved_at == None)  # noqa: E711
        if product:
            query = query.where(ScmFinding.product == product)
        if severity:
            query = query.where(ScmFinding.severity == severity)
        if q:
            query = query.where(func.lower(ScmFinding.title).contains(q.strip().lower()[:100]))
        total = session.exec(select(func.count()).select_from(query.subquery())).one()
        rows = session.exec(query.order_by(ScmFinding.repo_count.desc(), ScmFinding.id)  # type: ignore[union-attr]
                            .offset((page - 1) * size).limit(size)).all()
        return {"items": [{"id": f.id, "product": f.product, "title": f.title, "severity": f.severity,
                           "repo_count": f.repo_count, "occurrence_count": f.occurrence_count,
                           "key_fields": f.key_fields or {}, "first_seen_at": iso_z(f.first_seen_at),
                           "last_seen_at": iso_z(f.last_seen_at), "resolved_at": iso_z(f.resolved_at)} for f in rows],
                "total": int(total), "page": page, "page_size": size}


@router.get(BASE + "/findings", dependencies=READ, openapi_extra=perm("repos.read"),
            summary="Findings de-duplicated across repositories, most widespread first")
async def list_findings(team_id: TeamId, Authorization: AuthHeader = None,
                        product: Literal["sast", "iac", "sbom_sca", "cbom", "ai_bom"] | None = None,
                        severity: Literal["critical", "high", "medium", "low", "info"] | None = None,
                        q: str | None = Query(default=None, max_length=100),
                        min_repos: int = Query(default=1, ge=0, le=100000), include_resolved: bool = False,
                        page: int = Query(default=1, ge=1, le=100000), page_size: int = Query(default=50, ge=1, le=200)):
    engine, _user = await authorize(team_id, Authorization)
    return _ok(await _run("list findings", team_id, _list_findings, engine, team_id, product, severity, q, min_repos,
                          include_resolved, page, page_size))


def _get_finding(engine, team_id: int, finding_id: int) -> dict:
    with Session(engine) as session:
        f = session.exec(select(ScmFinding).where(ScmFinding.id == finding_id, ScmFinding.team_id == team_id)).first()
        if f is None:
            raise HTTPException(status_code=404, detail="Finding not found")
        rows = session.exec(select(ScmFindingOccurrence, ScmRepository.full_name, ScmRepository.web_url)
                            .join(ScmRepository, ScmRepository.id == ScmFindingOccurrence.repo_id)
                            .where(ScmFindingOccurrence.finding_id == f.id)
                            .order_by(ScmRepository.full_name).limit(1000)).all()
        return {"finding": {"id": f.id, "product": f.product, "title": f.title, "severity": f.severity,
                            "repo_count": f.repo_count, "occurrence_count": f.occurrence_count,
                            "key_fields": f.key_fields or {}, "resolved_at": iso_z(f.resolved_at)},
                "repositories": [{"repo_id": o.repo_id, "repo": name, "web_url": url, "scan_id": o.scan_id,
                                  "count": o.count, "locations": o.locations or [], "last_seen_at": iso_z(o.last_seen_at)}
                                 for o, name, url in rows]}


@router.get(BASE + "/findings/{finding_id}", dependencies=READ, openapi_extra=perm("repos.read"),
            summary="One roll-up finding and every repository it is in")
async def get_finding(team_id: TeamId, finding_id: ObjectId, Authorization: AuthHeader = None):
    engine, _user = await authorize(team_id, Authorization)
    return _ok(await _run("get finding", team_id, _get_finding, engine, team_id, finding_id))


def _rollup(engine, team_id: int) -> dict:
    with Session(engine) as session:
        per_product = {}
        for product, n, occ in session.exec(
                select(ScmFinding.product, func.count(), func.sum(ScmFinding.occurrence_count))
                .where(ScmFinding.team_id == team_id).group_by(ScmFinding.product)).all():
            per_product[product] = {"findings_total": int(n), "occurrences": int(occ or 0)}
        for product, n in session.exec(select(ScmFinding.product, func.count()).where(
                ScmFinding.team_id == team_id, ScmFinding.resolved_at == None)  # noqa: E711
                .group_by(ScmFinding.product)).all():
            per_product.setdefault(product, {})["findings_open"] = int(n)
        for product, n in session.exec(select(ScmFindingOccurrence.product,
                                              func.count(func.distinct(ScmFindingOccurrence.repo_id)))
                                       .where(ScmFindingOccurrence.team_id == team_id)
                                       .group_by(ScmFindingOccurrence.product)).all():
            per_product.setdefault(product, {})["repos_affected"] = int(n)
        for slot in per_product.values():
            open_n = slot.setdefault("findings_open", 0)
            slot.setdefault("repos_affected", 0)
            slot["dedup_ratio"] = round(slot.get("occurrences", 0) / open_n, 2) if open_n else None
        repos = session.exec(select(func.count()).select_from(ScmRepository).where(
            ScmRepository.team_id == team_id, ScmRepository.in_scope == True)).one()  # noqa: E712
        scanned = session.exec(select(func.count()).select_from(ScmRepository).where(
            ScmRepository.team_id == team_id, ScmRepository.in_scope == True,  # noqa: E712
            ScmRepository.last_scan_at != None)).one()  # noqa: E711
        top = session.exec(select(ScmFinding).where(ScmFinding.team_id == team_id, ScmFinding.resolved_at == None)  # noqa: E711
                           .order_by(ScmFinding.repo_count.desc(), ScmFinding.id).limit(10)).all()  # type: ignore[union-attr]
        sev = dict(session.exec(select(ScmFinding.severity, func.count()).where(
            ScmFinding.team_id == team_id, ScmFinding.resolved_at == None).group_by(ScmFinding.severity)).all())  # noqa: E711
        return {"products": per_product, "repos_in_scope": int(repos), "repos_scanned": int(scanned),
                "by_severity": {k: int(v) for k, v in sev.items()},
                "top": [{"id": f.id, "product": f.product, "title": f.title, "severity": f.severity,
                         "repo_count": f.repo_count} for f in top]}


@router.get(BASE + "/rollup", dependencies=READ, openapi_extra=perm("repos.read"),
            summary="Roll-up per product across every repository")
async def rollup_view(team_id: TeamId, Authorization: AuthHeader = None):
    engine, _user = await authorize(team_id, Authorization)
    return _ok(await _run("rollup", team_id, _rollup, engine, team_id))


# ============================================================================ webhooks (public, signed)
def _webhook(provider: str, uid: str, body: bytes, headers: Any) -> JSONResponse:
    engine = get_db()
    with Session(engine) as session:
        row = session.exec(select(ScmConnection).where(ScmConnection.webhook_uid == uid,
                                                       ScmConnection.provider == provider)).first()
        secret = (decrypt_secrets(row.webhook_secret_encrypted).get("webhook_secret") if row is not None else None)
        connection_id = row.id if row is not None else None
    if row is None or not secret or not W.verify(provider, secret, body, headers):
        log("webhook REFUSED", provider=provider, reason="unknown hook" if row is None else "bad signature")
        return JSONResponse({"detail": "Signature verification failed"}, status_code=401, headers=PRIVATE)
    try:
        import json

        payload = json.loads(body or b"{}")
        if not isinstance(payload, dict):
            raise ValueError
    except (ValueError, UnicodeDecodeError):
        return JSONResponse({"detail": "Body is not a JSON object"}, status_code=400, headers=PRIVATE)
    event = (headers.get("x-github-event") or headers.get("x-event-key") or headers.get("x-gitlab-event") or "")[:64]
    out = W.handle(engine, connection_id, provider, event, payload, utcnow())
    return JSONResponse(out, status_code=202, headers=PRIVATE)


# Public: no account; the credential is the connection's webhook secret (HMAC or token, constant-time). No
# x-zs-permission marker (that names a team permission); F4's public(...) policy is added once F4 is on dev.
@router.post("/scm/webhooks/{provider}/{webhook_uid}", dependencies=[Depends(webhook_limiter)],
             summary="Inbound GitHub / GitLab / Bitbucket webhook (signed)")
async def receive_webhook(provider: Literal["github", "gitlab", "bitbucket"], request: Request,
                          webhook_uid: Annotated[str, Path(max_length=64)]):
    uid = webhook_uid
    if not uid or len(uid) != 32 or not all(c in "0123456789abcdef" for c in uid):
        return JSONResponse({"detail": "Signature verification failed"}, status_code=401, headers=PRIVATE)
    body = await read_capped_body(request, W.MAX_BODY)
    try:
        return await run_in_threadpool(_webhook, provider, uid, body, request.headers)
    except Exception as exc:
        raise server_error("scm webhook", exc) from None


__all__ = ["router"]
