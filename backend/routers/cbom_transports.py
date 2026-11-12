"""F1.3 transport routes (contract section 3), included through the fleet aggregator (``cbom_fleet.py``).

``/{team_id}/cbom/sources/fleet/transports``: a team's AWX/AAP, Salt and AWS SSM transports, the per-release
artifacts the customer installs, and a validate action.  Conventions of the fleet routers: ``CbomRoute`` behind the
``CBOM_FLEET_TRANSPORTS`` flag (off -> 404), the rate limiter then ``ctx: Member`` (authentication), a permission per
route (``x-zs-permission``; writes are team-admin only today, a 400 inside the team), another team's row is a 404, a
stale form a 409, secrets write-only (``secrets_set``), an audit row on every write.
"""
from __future__ import annotations

import re
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Path
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator
from sqlalchemy import func
from sqlmodel import Session, select

from backend.utilities.cbom_sources.common import audit, log, utcnow
from backend.utilities.cbom_sources.crypto import decrypt_secrets, encrypt_secrets
from backend.utilities.cbom_sources.fleet.http import FLEET, Member, permission
from backend.utilities.cbom_sources.http import (PRIVATE, ObjectId, TeamId, bump_version, check_version, format_errors,
                                                 read_limiter, require_admin, server_error, write_limiter)
from backend.utilities.cbom_sources.kinds import AWS_REGION_RE, _AWS_ROLE_RE, check_pem_certificates, \
    validate_secret_value
from backend.utilities.cbom_sources.settings import get_or_create_settings
from backend.utilities.cbom_sources.transports import artifacts as A
from backend.utilities.cbom_sources.transports import flags as TF
from backend.utilities.cbom_sources.transports.models import TRANSPORT_KINDS, CbomTransport
from backend.utilities.cbom_sources.transports.registry import active_release, key_fingerprint, sources_using

router = APIRouter(tags=["cbom-fleet"], route_class=TF.route_class())
READ = [Depends(read_limiter)]
WRITE = [Depends(write_limiter)]
BASE = FLEET + "/transports"
MAX_TRANSPORTS = 100
_HOST_RE = re.compile(r"^[A-Za-z0-9.-]{1,253}(:\d{1,5})?$")


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


def _https(v: str) -> str:
    v = (v or "").strip().rstrip("/")
    m = re.fullmatch(r"https://([^/\s?#@]+)(/[A-Za-z0-9._~/-]*)?", v)
    if not m or not _HOST_RE.match(m.group(1)):
        raise ValueError("must be an https:// URL of the control plane (no user, query or fragment)")
    return v


class AwxConfig(_Strict):
    base_url: str = Field(max_length=512)
    job_template_id: int = Field(ge=1, le=2_147_483_647)
    verify_tls: bool = True
    ca_pem: str | None = Field(default=None, max_length=64 * 1024)
    timeout_s: int = Field(default=30, ge=5, le=300)
    max_hosts_per_launch: int = Field(default=200, ge=1, le=200)

    @field_validator("base_url")
    @classmethod
    def _url(cls, v: str) -> str:
        return _https(v)

    @field_validator("ca_pem")
    @classmethod
    def _ca(cls, v: str | None) -> str | None:
        return check_pem_certificates(v)


class SaltConfig(_Strict):
    base_url: str = Field(max_length=512)
    eauth: str = Field(default="pam", pattern=r"^[a-z_]{2,32}$")
    client: Literal["local", "local_async", "ssh"] = "local_async"
    mode: Literal["state", "cmd"] = "cmd"
    batch_size: int = Field(default=50, ge=1, le=500)
    timeout_s: int = Field(default=300, ge=10, le=3600)
    verify_tls: bool = True
    ca_pem: str | None = Field(default=None, max_length=64 * 1024)

    @field_validator("base_url")
    @classmethod
    def _url(cls, v: str) -> str:
        return _https(v)

    @field_validator("ca_pem")
    @classmethod
    def _ca(cls, v: str | None) -> str | None:
        return check_pem_certificates(v)


class SsmConfig(_Strict):
    role_arn: str = Field(max_length=2048)
    regions: list[str] = Field(min_length=1, max_length=16)
    document_name: str = Field(pattern=r"^devsecshield-[A-Za-z0-9_.-]{1,115}$")
    output_s3_bucket: str | None = Field(default=None, pattern=r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$")
    output_s3_prefix: str | None = Field(default=None, pattern=r"^[A-Za-z0-9!_.*'()/-]{0,200}$")
    max_concurrency: str = Field(default="10%", pattern=r"^([1-9][0-9]{0,3}|[1-9][0-9]?%|100%)$")
    max_errors: str = Field(default="100%", pattern=r"^([0-9]{1,4}|[0-9]{1,2}%|100%)$")

    @field_validator("role_arn")
    @classmethod
    def _role(cls, v: str) -> str:
        if not _AWS_ROLE_RE.match(v):
            raise ValueError("must be an IAM role ARN (arn:aws:iam::<account>:role/<name>)")
        return v

    @field_validator("regions")
    @classmethod
    def _regions(cls, v: list[str]) -> list[str]:
        out = sorted({r.strip() for r in v})
        if not all(AWS_REGION_RE.match(r) for r in out):
            raise ValueError("each region must look like ap-south-1")
        return out


MODELS: dict[str, type[_Strict]] = {"awx": AwxConfig, "salt": SaltConfig, "ssm": SsmConfig}
SECRETS = {"awx": {"token"}, "salt": {"username", "password"}, "ssm": set()}


class TransportCreate(_Strict):
    kind: Literal["awx", "salt", "ssm"]
    name: str = Field(min_length=1, max_length=64, pattern=r"^[^\x00-\x1f\x7f]+$")
    enabled: bool = True
    config: dict[str, Any]
    secrets: dict[str, str] = Field(default_factory=dict)


class TransportUpdate(_Strict):
    expected_version: int | None = None
    name: str | None = Field(default=None, min_length=1, max_length=64, pattern=r"^[^\x00-\x1f\x7f]+$")
    enabled: bool | None = None
    config: dict[str, Any] | None = None
    secrets: dict[str, str] = Field(default_factory=dict)


# ----------------------------------------------------------------------------- helpers
async def _run(what: str, team_id: int, fn, *args) -> Any:
    try:
        return await run_in_threadpool(fn, *args)
    except HTTPException:
        raise
    except Exception as exc:
        raise server_error(f"cbom transports {what}", exc, team=team_id) from None


def _ok(payload: Any, status_code: int = 200) -> JSONResponse:
    return JSONResponse(payload, status_code=status_code, headers=PRIVATE)


def _config(kind: str, raw: dict[str, Any]) -> dict[str, Any]:
    try:
        return MODELS[kind].model_validate(raw).model_dump(mode="json")
    except ValidationError as exc:
        raise HTTPException(status_code=400, detail=format_errors(exc.errors())) from None


def _secrets(kind: str, current: dict[str, str], provided: dict[str, str], *, reset: bool) -> dict[str, str]:
    allowed = SECRETS[kind]
    out = {} if reset else {k: v for k, v in current.items() if k in allowed}
    for name, value in provided.items():
        if name not in allowed:
            raise HTTPException(status_code=400, detail=f"secrets.{name}: not used by a {kind} transport")
        if value == "":
            continue
        try:
            out[name] = validate_secret_value(name, value)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=f"secrets.{exc}") from None
    missing = sorted(allowed - set(out))
    if missing:
        raise HTTPException(status_code=400, detail=f"secrets.{missing[0]}: required for a {kind} transport")
    return out


def public(row: CbomTransport, used_by: list[tuple[int, str]] | None = None) -> dict[str, Any]:
    return {"id": row.id, "kind": row.kind, "name": row.name, "enabled": row.enabled, "config": row.config or {},
            "secrets_set": sorted(row.secret_fields or []), "row_version": row.row_version,
            "last_validated_at": row.last_validated_at.strftime("%Y-%m-%dT%H:%M:%SZ") if row.last_validated_at else None,
            "last_validation_status": row.last_validation_status, "last_validation_summary": row.last_validation_summary,
            "used_by": [{"id": i, "name": n} for i, n in (used_by or [])]}


def _owned(session: Session, team_id: int, transport_id: int) -> CbomTransport:
    row = session.get(CbomTransport, transport_id)
    if row is None or row.team_id != team_id or row.deleted_at is not None:
        raise HTTPException(status_code=404, detail="Transport not found")
    return row


# ----------------------------------------------------------------------------- routes
def _list(engine, team_id: int) -> dict:
    with Session(engine) as session:
        rows = session.exec(select(CbomTransport).where(CbomTransport.team_id == team_id,
                                                        CbomTransport.deleted_at.is_(None))
                            .order_by(CbomTransport.id)).all()
        release = active_release(session)
        return {"transports": [public(r, sources_using(session, team_id, r.id)) for r in rows],
                "release": {"version": release.version, "fingerprint": release.key_fingerprint,
                            "sha256": {"amd64": release.sha256_amd64, "arm64": release.sha256_arm64},
                            "verified_at": release.verified_at.strftime("%Y-%m-%dT%H:%M:%SZ")
                            if release.verified_at else None} if release else None,
                "release_key_fingerprint": key_fingerprint()}


@router.get(BASE, dependencies=READ, openapi_extra=permission("cbom.fleet.read"),
            summary="Transports of the team, and the active zs-collect release")
async def list_transports(team_id: TeamId, ctx: Member):
    engine, _user = ctx
    return _ok(await _run("list", team_id, _list, engine, team_id))


def _create(engine, team_id: int, user_id: int, body: TransportCreate) -> dict:
    now = utcnow()
    config = _config(body.kind, body.config)
    secrets_ = _secrets(body.kind, {}, body.secrets, reset=True)
    with Session(engine) as session:
        require_admin(session, user_id, team_id, "transports")
        total = session.exec(select(func.count()).select_from(CbomTransport).where(
            CbomTransport.team_id == team_id, CbomTransport.deleted_at.is_(None))).one()
        if total >= MAX_TRANSPORTS:
            raise HTTPException(status_code=400, detail=f"A team can have at most {MAX_TRANSPORTS} transports")
        clash = session.exec(select(CbomTransport.id).where(
            CbomTransport.team_id == team_id, CbomTransport.name_lower == body.name.lower(),
            CbomTransport.deleted_at.is_(None))).first()
        if clash is not None:
            raise HTTPException(status_code=409, detail=f"A transport named {body.name} already exists")
        row = CbomTransport(team_id=team_id, kind=body.kind, name=body.name, name_lower=body.name.lower(),
                            enabled=body.enabled, config=config, secret_encrypted=encrypt_secrets(secrets_),
                            secret_fields=sorted(secrets_), owner_user_id=user_id, updated_by_user_id=user_id,
                            created_at=now, last_updated=now)
        session.add(row)
        session.flush()
        audit(session, team_id=team_id, actor_type="user", actor_id=user_id, action="transport.create",
              object_type="transport", object_id=row.id,
              changed_fields=["kind", "name", "config"] + [f"secrets.{k}" for k in secrets_])
        session.commit()
        session.refresh(row)
        log("transport created", team=team_id, transport=row.id, kind=row.kind, by=user_id)
        return {"transport": public(row)}


@router.post(BASE, dependencies=WRITE, openapi_extra=permission("cbom.transports.write"),
             summary="Add a transport (AWX/AAP, Salt or AWS SSM); secrets are write-only")
async def create_transport(team_id: TeamId, ctx: Member, body: TransportCreate):
    engine, user = ctx
    return _ok(await _run("create", team_id, _create, engine, team_id, user.id, body), 201)


def _update(engine, team_id: int, user_id: int, transport_id: int, body: TransportUpdate) -> dict:
    now = utcnow()
    with Session(engine) as session:
        require_admin(session, user_id, team_id, "transports")
        row = _owned(session, team_id, transport_id)
        check_version(row, body.expected_version)
        changed: list[str] = []
        config_changed = False
        if body.name is not None and body.name != row.name:
            clash = session.exec(select(CbomTransport.id).where(
                CbomTransport.team_id == team_id, CbomTransport.name_lower == body.name.lower(),
                CbomTransport.id != row.id, CbomTransport.deleted_at.is_(None))).first()
            if clash is not None:
                raise HTTPException(status_code=409, detail=f"A transport named {body.name} already exists")
            row.name, row.name_lower = body.name, body.name.lower()
            changed.append("name")
        if body.enabled is not None and body.enabled != row.enabled:
            row.enabled = body.enabled
            changed.append("enabled")
        current = decrypt_secrets(row.secret_encrypted)
        if body.config is not None:
            config = _config(row.kind, body.config)
            if config != (row.config or {}):
                # where the secret goes changed: it must be entered again (as for sources' where-fields)
                moved = config.get("base_url") != (row.config or {}).get("base_url") \
                    or config.get("role_arn") != (row.config or {}).get("role_arn")
                if moved and SECRETS[row.kind] and not body.secrets:
                    raise HTTPException(status_code=400, detail="secrets: re-enter them; stored credentials are "
                                                                "cleared when the control plane URL changes")
                if moved:
                    current = {}
                row.config = config
                config_changed = True
                changed.append("config")
        if body.secrets or config_changed:
            new = _secrets(row.kind, current, body.secrets, reset=False)
            if new != current or body.secrets:
                row.secret_encrypted, row.secret_fields = encrypt_secrets(new), sorted(new)
                changed += [f"secrets.{k}" for k in body.secrets]
        if not changed:
            return {"transport": public(row, sources_using(session, team_id, row.id))}
        row.updated_by_user_id, row.last_updated = user_id, now
        if config_changed:
            row.last_validation_status, row.last_validation_summary = "never", None
        bump_version(session, row)
        audit(session, team_id=team_id, actor_type="user", actor_id=user_id, action="transport.update",
              object_type="transport", object_id=row.id, changed_fields=changed)
        session.commit()
        session.refresh(row)
        return {"transport": public(row, sources_using(session, team_id, row.id))}


@router.patch(BASE + "/{transport_id}", dependencies=WRITE, openapi_extra=permission("cbom.transports.write"),
              summary="Change a transport (expected_version: 409 when it changed meanwhile)")
async def update_transport(team_id: TeamId, transport_id: ObjectId, ctx: Member, body: TransportUpdate):
    engine, user = ctx
    return _ok(await _run("update", team_id, _update, engine, team_id, user.id, transport_id, body))


def _delete(engine, team_id: int, user_id: int, transport_id: int) -> dict:
    now = utcnow()
    with Session(engine) as session:
        require_admin(session, user_id, team_id, "transports")
        row = _owned(session, team_id, transport_id)
        used = sources_using(session, team_id, row.id)
        if used:
            names = ", ".join(n for _i, n in used[:5]) + (f" and {len(used) - 5} more" if len(used) > 5 else "")
            raise HTTPException(status_code=409, detail=f"Sources still use this transport: {names}")
        row.deleted_at, row.enabled, row.secret_encrypted, row.secret_fields = now, False, None, []
        row.updated_by_user_id, row.last_updated = user_id, now
        bump_version(session, row)
        audit(session, team_id=team_id, actor_type="user", actor_id=user_id, action="transport.delete",
              object_type="transport", object_id=row.id, changed_fields=["deleted_at", "secrets"])
        session.commit()
        return {"deleted": transport_id}


@router.delete(BASE + "/{transport_id}", dependencies=WRITE, openapi_extra=permission("cbom.transports.write"),
               summary="Delete a transport (refused while a source uses it); its secrets are erased")
async def delete_transport(team_id: TeamId, transport_id: ObjectId, ctx: Member):
    engine, user = ctx
    return _ok(await _run("delete", team_id, _delete, engine, team_id, user.id, transport_id))


def _validate(engine, team_id: int, user_id: int, transport_id: int) -> dict:
    now = utcnow()
    with Session(engine) as session:
        require_admin(session, user_id, team_id, "transports")
        row = _owned(session, team_id, transport_id)
        if row.kind != "ssm":
            raise HTTPException(status_code=400, detail="Test a source that uses this transport: its control plane is "
                                                        "reached from a scan node inside your network")
        external_id = get_or_create_settings(session, team_id).aws_external_id
        config = dict(row.config or {})
    status, summary = _check_ssm(team_id, config, external_id)
    with Session(engine) as session:
        row = _owned(session, team_id, transport_id)
        row.last_validated_at, row.last_validation_status, row.last_validation_summary = now, status, summary[:512]
        audit(session, team_id=team_id, actor_type="user", actor_id=user_id, action="transport.validate",
              object_type="transport", object_id=row.id, changed_fields=["last_validation_status"])
        session.commit()
        session.refresh(row)
        return {"transport": public(row), "status": status, "summary": summary}


def _check_ssm(team_id: int, config: dict, external_id: str) -> tuple[str, str]:
    from backend.utilities.cbom_sources.transports.base import TransportError
    from backend.utilities.cbom_sources.transports.ssm import SsmTransport, role_client_factory

    try:
        factory = role_client_factory(team_id, config["role_arn"], external_id)
        transport = SsmTransport(factory)
        for region in config.get("regions") or []:
            transport._document(region, config)
            transport._online(region, [])
    except TransportError as exc:
        return "failed", exc.detail
    except Exception as exc:
        name = exc.__class__.__name__
        if name == "NoZeroShieldCredentials":
            return "failed", "ZeroShield's AWS principal is not configured in this deployment"
        code = str(((getattr(exc, "response", None) or {}).get("Error") or {}).get("Code") or name)
        return "failed", f"The run-command role could not be used: {code}"
    return "passed", (f"Role assumed with the external id; document {config['document_name']} found in "
                      f"{', '.join(config.get('regions') or [])}")


@router.post(BASE + "/{transport_id}/validate", dependencies=WRITE, openapi_extra=permission("cbom.transports.write"),
             summary="Check an SSM transport now (role, external id, document); AWX/Salt: test a source instead")
async def validate_transport(team_id: TeamId, transport_id: ObjectId, ctx: Member):
    engine, user = ctx
    return _ok(await _run("validate", team_id, _validate, engine, team_id, user.id, transport_id))


ArtifactName = Path(pattern=r"^[a-z0-9-]{1,40}$")


def _artifact(engine, team_id: int, name: str) -> tuple[str, Any]:
    with Session(engine) as session:
        external_id = get_or_create_settings(session, team_id).aws_external_id
        session.commit()  # a team's settings row may have been created just now
        release = active_release(session)
        try:
            return A.render(name, release, external_id)
        except KeyError:
            raise HTTPException(status_code=404, detail="No such artifact") from None
        except LookupError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from None


@router.get(BASE + "/artifacts/{name}", dependencies=READ, openapi_extra=permission("cbom.fleet.read"),
            summary="What to install on your side: ssm-document, ssm-role-cfn, salt-state, ansible-collection, "
                    "zs-collect-manifest, zs-collect-pubkey")
async def get_artifact(team_id: TeamId, ctx: Member, name: str = ArtifactName):
    engine, _user = ctx
    media, body = await _run("artifact", team_id, _artifact, engine, team_id, name)
    if media == "application/json":
        return _ok(body)
    return PlainTextResponse(body, media_type=media, headers=PRIVATE)


__all__ = ["router", "TRANSPORT_KINDS"]
