"""SSH certificate authority (F1.4): ``/{team_id}/cbom/sources/fleet/ssh-ca``.

CBOM Sources conventions: members of the team read, admins write (``cbom.sshca.admin``; a member gets a 400, never a
403), another team's CA or certificate is a 404, a stale ``expected_version`` a 409, every write an audit row.  While
``CBOM_SSH_CA`` is off every route here is a 404.  Private keys, Vault tokens and certificates are never returned or
logged; ``public_key`` and ``fingerprint`` are public by nature (they go into every server's ``TrustedUserCAKeys``).

Distribution: ``trusted-keys`` (TrustedUserCAKeys: next, active and recently retired keys), ``revoked`` (an OpenSSH
KRL for RevokedKeys; ``?format=keys`` gives the revoked CA keys as text) and ``templates/{sshd-config|principals}``.
"""
from __future__ import annotations

import re
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import func
from sqlmodel import Session, select

from backend.new_models import CbomCollectionSource
from backend.utilities.cbom_sources.common import NAME_RE, iso_z, utcnow
from backend.utilities.cbom_sources.fleet.http import Member, permission
from backend.utilities.cbom_sources.http import (
    PRIVATE,
    ObjectId,
    TeamId,
    check_version,
    read_limiter,
    require_admin,
    server_error,
    write_limiter,
)
from backend.utilities.cbom_sources.sshca import flags
from backend.utilities.cbom_sources.sshca import keywrap as KW
from backend.utilities.cbom_sources.sshca import registry as R
from backend.utilities.cbom_sources.sshca.models import CbomSshCa, CbomSshCertIssued

router = APIRouter(tags=["cbom-ssh-ca"], route_class=flags.route_class())
BASE = "/{team_id}/cbom/sources/fleet/ssh-ca"
READ = [Depends(read_limiter)]
WRITE = [Depends(write_limiter)]
PERM_READ = permission("cbom.fleet.read")
PERM_ADMIN = permission("cbom.sshca.admin")
TEXT = {**PRIVATE, "Content-Type": "text/plain; charset=utf-8"}
_GROUP = re.compile(r"^[a-z0-9][a-z0-9._-]{0,47}$")


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class CaCreate(_Strict):
    name: str = Field(min_length=1, max_length=64)
    provider: Literal["builtin", "vault"] = "builtin"
    key_alg: Literal["ed25519", "ecdsa-p256"] = "ed25519"
    key_wrap: Literal["fernet", "aws_kms"] | None = None
    kms_key_ref: str | None = Field(default=None, max_length=2048)
    vault_config: dict[str, Any] | None = None
    secrets: dict[str, str] | None = None
    default_ttl_s: int | None = None

    @field_validator("name")
    @classmethod
    def _name(cls, v: str) -> str:
        if not NAME_RE.match(v):
            raise ValueError("letters, digits, spaces and . _ - (64 at most)")
        return v


class CaRotate(_Strict):
    secrets: dict[str, str] | None = None
    expected_version: int | None = None


class CaPromote(_Strict):
    expected_version: int | None = None


class Revoke(_Strict):
    reason: str = Field(min_length=1, max_length=512)
    expected_version: int | None = None


async def _run(what: str, team_id: int, fn, *args):
    try:
        return await run_in_threadpool(fn, *args)
    except HTTPException:
        raise
    except Exception as exc:
        raise server_error(f"cbom ssh ca {what}", exc, team=team_id) from None


def _json(data: Any, status: int = 200) -> JSONResponse:
    return JSONResponse(data, status_code=status, headers=PRIVATE)


def _issued_counts(session: Session, team_id: int) -> dict[int, int]:
    rows = session.exec(select(CbomSshCertIssued.ca_id, func.count()).where(CbomSshCertIssued.team_id == team_id)
                        .group_by(CbomSshCertIssued.ca_id)).all()
    return {int(ca_id): int(n) for ca_id, n in rows}


# ----------------------------------------------------------------------------- reads (static paths first)
def _list(engine, team_id: int) -> dict:
    now = utcnow()
    with Session(engine) as session:
        rows = session.exec(select(CbomSshCa).where(CbomSshCa.team_id == team_id).order_by(CbomSshCa.id)).all()
        counts = _issued_counts(session, team_id)
        wrap, _ref = KW.default_wrap()
        return {"server_time": iso_z(now), "cas": [R.public_ca(r, now, counts.get(int(r.id or 0), 0)) for r in rows],
                "kms_keys": KW.allowed_kms_keys(), "default_key_wrap": wrap}


@router.get(BASE, dependencies=READ, openapi_extra=PERM_READ, summary="SSH CA keys of this team (never a private key)")
async def list_cas(team_id: TeamId, ctx: Member):
    engine, _user = ctx
    return _json(await _run("list", team_id, _list, engine, team_id))


def _trusted(engine, team_id: int) -> str:
    with Session(engine) as session:
        return R.trusted_keys_text(session, team_id, utcnow())


@router.get(BASE + "/trusted-keys", dependencies=READ, openapi_extra=PERM_READ,
            summary="Public keys for sshd TrustedUserCAKeys (next, active and recently retired)")
async def trusted_keys(team_id: TeamId, ctx: Member):
    engine, _user = ctx
    return Response(await _run("trusted keys", team_id, _trusted, engine, team_id), headers=TEXT)


def _revoked(engine, team_id: int, fmt: str) -> bytes | str:
    with Session(engine) as session:
        if fmt == "keys":
            return R.revoked_keys_text(session, team_id, utcnow())
        return R.krl_bytes(session, team_id, utcnow())


@router.get(BASE + "/revoked", dependencies=READ, openapi_extra=PERM_READ,
            summary="OpenSSH KRL for sshd RevokedKeys (format=keys: revoked CA keys as text)")
async def revoked(team_id: TeamId, ctx: Member, format: Literal["krl", "keys"] = Query(default="krl")):
    engine, _user = ctx
    body = await _run("revoked", team_id, _revoked, engine, team_id, format)
    if format == "keys":
        return Response(body, headers=TEXT)
    return Response(body, headers={**PRIVATE, "Content-Type": "application/octet-stream",
                                   "Content-Disposition": f'attachment; filename="zs-team{team_id}-revoked.krl"'})


def _certificates(engine, team_id: int, ca_id: int | None, node_id: int | None, job_id: int | None,
                  before_id: int | None, limit: int) -> dict:
    now = utcnow()
    with Session(engine) as session:
        query = select(CbomSshCertIssued).where(CbomSshCertIssued.team_id == team_id)
        for column, value in ((CbomSshCertIssued.ca_id, ca_id), (CbomSshCertIssued.node_id, node_id),
                              (CbomSshCertIssued.job_id, job_id)):
            if value is not None:
                query = query.where(column == value)
        if before_id is not None:
            query = query.where(CbomSshCertIssued.id < before_id)  # type: ignore[operator]
        rows = session.exec(query.order_by(CbomSshCertIssued.id.desc()).limit(limit + 1)).all()  # type: ignore[union-attr]
        more = len(rows) > limit
        rows = rows[:limit]
        return {"server_time": iso_z(now), "certificates": [R.public_cert(r, now) for r in rows],
                "next_before_id": rows[-1].id if more and rows else None}


@router.get(BASE + "/certificates", dependencies=READ, openapi_extra=PERM_READ,
            summary="Issued-certificate audit, newest first")
async def certificates(team_id: TeamId, ctx: Member, ca_id: int | None = Query(default=None, ge=1, le=2_147_483_647),
                       node_id: int | None = Query(default=None, ge=1, le=2_147_483_647),
                       job_id: int | None = Query(default=None, ge=1, le=2_147_483_647),
                       before_id: int | None = Query(default=None, ge=1, le=2_147_483_647),
                       limit: int = Query(default=100, ge=1, le=500)):
    engine, _user = ctx
    return _json(await _run("certificates", team_id, _certificates, engine, team_id, ca_id, node_id, job_id,
                            before_id, limit))


SSHD_TEMPLATE = """# ZeroShield CBOM: scan sessions with short-lived SSH certificates (team {team_id}).
# Save as /etc/ssh/sshd_config.d/50-zs-cbom-ca.conf (or append to sshd_config), check with `sshd -t`, reload sshd.
# The CA is trusted for the zs-cbom login only, and only for the principals listed in its principals file.
#
#   install -d -m 0755 /etc/ssh/zs-cbom /etc/ssh/zs-cbom/principals
#   # TrustedUserCAKeys: CBOM Sources > Fleet > SSH CA > Download trusted keys (refresh after rotate/promote/revoke)
#   install -m 0644 trusted_user_ca_keys /etc/ssh/zs-cbom/trusted_user_ca_keys
#   # RevokedKeys: Download revocation list (KRL). sshd refuses EVERY key for this user if the file is missing,
#   # so install it before reloading, and refresh it on a schedule (cron) after revocations.
#   install -m 0644 revoked.krl /etc/ssh/zs-cbom/revoked.krl
#   # AuthorizedPrincipalsFile: the principals of this server group (Download principals file), one per line
#   install -m 0644 zs-cbom.principals /etc/ssh/zs-cbom/principals/zs-cbom
#
# Certificates carry no extensions (no PTY, forwarding or agent) and a source-address restriction to the scan node.
# OpenSSH 9.8+ (PerSourcePenalties): refused logins from the scan node's address delay its next connections; fix the
# cause (principals file, trusted keys) rather than exempting the node.
Match User zs-cbom
    TrustedUserCAKeys /etc/ssh/zs-cbom/trusted_user_ca_keys
    RevokedKeys /etc/ssh/zs-cbom/revoked.krl
    AuthorizedPrincipalsFile /etc/ssh/zs-cbom/principals/%u
"""


def _principals_template(engine, team_id: int, group: str | None) -> str:
    with Session(engine) as session:
        used: list[str] = []
        for cfg in session.exec(select(CbomCollectionSource.config).where(
                CbomCollectionSource.team_id == team_id, CbomCollectionSource.kind == "linux_servers")).all():
            if isinstance(cfg, dict) and cfg.get("credential_type") == "ssh_ca":
                used += [str(p) for p in cfg.get("ssh_principals") or []]
    principals = [f"zs-{team_id}-{group}"] if group else sorted(set(used))
    lines = ["# /etc/ssh/zs-cbom/principals/zs-cbom: the certificate principals this server accepts for zs-cbom",
             f"# (team {team_id}). Keep only the principal(s) of the server group this server belongs to."]
    if not principals:
        lines.append(f"# No source uses an SSH CA yet; principals look like zs-{team_id}-<group>, e.g.")
        principals = [f"zs-{team_id}-prod"]
    return "\n".join(lines + principals) + "\n"


@router.get(BASE + "/templates/{name}", dependencies=READ, openapi_extra=PERM_READ,
            summary="sshd configuration snippet or principals file for the servers")
async def template(team_id: TeamId, name: Literal["sshd-config", "principals"], ctx: Member,
                   group: str | None = Query(default=None, max_length=48)):
    engine, _user = ctx
    if group is not None and not _GROUP.match(group):
        raise HTTPException(status_code=400, detail="group: lowercase letters, digits and . _ -")
    if name == "sshd-config":
        return Response(SSHD_TEMPLATE.format(team_id=team_id), headers=TEXT)
    return Response(await _run("template", team_id, _principals_template, engine, team_id, group), headers=TEXT)


def _revoke_cert(engine, team_id: int, user_id: int, cert_id: int, body: Revoke) -> dict:
    now = utcnow()
    with Session(engine) as session:
        require_admin(session, user_id, team_id, "SSH CA certificates")
        row = R.revoke_cert(session, team_id, cert_id, user_id, body.reason, now)
        session.commit()
        session.refresh(row)
        return {"certificate": R.public_cert(row, now)}


@router.post(BASE + "/certificates/{cert_id}/revoke", dependencies=WRITE, openapi_extra=PERM_ADMIN,
             summary="Revoke one issued certificate (listed in the KRL)")
async def revoke_certificate(team_id: TeamId, cert_id: ObjectId, ctx: Member, body: Revoke):
    engine, user = ctx
    return _json(await _run("revoke certificate", team_id, _revoke_cert, engine, team_id, user.id, cert_id, body))


# ----------------------------------------------------------------------------- CA writes
def _create(engine, team_id: int, user_id: int, body: CaCreate) -> dict:
    now = utcnow()
    with Session(engine) as session:
        require_admin(session, user_id, team_id, "SSH CAs")
        row = R.create_ca(session, team_id, user_id, body, now)
        session.commit()
        session.refresh(row)
        return {"ca": R.public_ca(row, now, 0)}


@router.post(BASE, dependencies=WRITE, openapi_extra=PERM_ADMIN, summary="Create an SSH CA (builtin key or Vault)")
async def create_ca(team_id: TeamId, ctx: Member, body: CaCreate):
    engine, user = ctx
    return _json(await _run("create", team_id, _create, engine, team_id, user.id, body), 201)


def _get(engine, team_id: int, ca_id: int) -> dict:
    now = utcnow()
    with Session(engine) as session:
        row = R.get_ca(session, team_id, ca_id)
        return {"ca": R.public_ca(row, now, _issued_counts(session, team_id).get(ca_id, 0))}


@router.get(BASE + "/{ca_id}", dependencies=READ, openapi_extra=PERM_READ, summary="One SSH CA")
async def get_ca(team_id: TeamId, ca_id: ObjectId, ctx: Member):
    engine, _user = ctx
    return _json(await _run("get", team_id, _get, engine, team_id, ca_id))


def _lifecycle(engine, team_id: int, user_id: int, ca_id: int, action: str, body: Any) -> dict:
    now = utcnow()
    with Session(engine) as session:
        require_admin(session, user_id, team_id, "SSH CAs")
        row = R.get_ca(session, team_id, ca_id)
        check_version(row, getattr(body, "expected_version", None))
        if action == "rotate":
            row = R.rotate(session, row, user_id, now, body.secrets)
        elif action == "promote":
            row = R.promote(session, row, user_id, now)
        else:
            row = R.revoke(session, row, user_id, body.reason, now)
        session.commit()
        session.refresh(row)
        return {"ca": R.public_ca(row, now)}


@router.post(BASE + "/{ca_id}/rotate", dependencies=WRITE, openapi_extra=PERM_ADMIN,
             summary="Start a rotation: a new CA key, trusted at once, signing after promote")
async def rotate_ca(team_id: TeamId, ca_id: ObjectId, ctx: Member, body: CaRotate | None = None):
    engine, user = ctx
    return _json(await _run("rotate", team_id, _lifecycle, engine, team_id, user.id, ca_id, "rotate",
                            body or CaRotate()), 201)


@router.post(BASE + "/{ca_id}/promote", dependencies=WRITE, openapi_extra=PERM_ADMIN,
             summary="Make the rotated CA active (the old one is retired, trusted for the overlap)")
async def promote_ca(team_id: TeamId, ca_id: ObjectId, ctx: Member, body: CaPromote | None = None):
    engine, user = ctx
    return _json(await _run("promote", team_id, _lifecycle, engine, team_id, user.id, ca_id, "promote",
                            body or CaPromote()))


@router.post(BASE + "/{ca_id}/revoke", dependencies=WRITE, openapi_extra=PERM_ADMIN,
             summary="Revoke a CA key: it signs nothing more and goes into the KRL")
async def revoke_ca(team_id: TeamId, ca_id: ObjectId, ctx: Member, body: Revoke):
    engine, user = ctx
    return _json(await _run("revoke", team_id, _lifecycle, engine, team_id, user.id, ca_id, "revoke", body))
