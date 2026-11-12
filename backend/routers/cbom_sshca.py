"""SSH certificate authority (F1.4): ``/{team_id}/cbom/sources/fleet/ssh-ca``.

CBOM Sources conventions: members of the team read, admins write (``cbom.sshca.admin``; a member gets a 400, never a
403), another team's CA or certificate is a 404, a stale ``expected_version`` a 409, every write an audit row.  While
``CBOM_SSH_CA`` is off every route here is a 404.  Private keys, Vault tokens and certificates are never returned or
logged; ``public_key`` and ``fingerprint`` are public by nature (they go into every server's ``TrustedUserCAKeys``).

Distribution: ``trusted-keys`` (TrustedUserCAKeys: next, active and recently retired keys), ``revoked`` (an OpenSSH
KRL for RevokedKeys; ``?format=keys`` gives the revoked CA keys as text) and ``templates/{sshd-config|principals|
trust-fetch}`` for people.  Servers fetch the same files with a trust token (``trust-tokens`` here; the machine routes
are ``cbom_sshca_trust.py``), so no user session is needed to keep them current.
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
from backend.utilities.cbom_sources.sshca import sources as SRC
from backend.utilities.cbom_sources.sshca import trust as T
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
    kms_key: str | None = Field(default=None, max_length=2048)  # a label from kms_keys (or, for operators, the ARN)
    kms_key_ref: str | None = Field(default=None, max_length=2048)  # the older name of kms_key
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
    vault_config: dict[str, Any] | None = None  # Vault: mount / role / issuer_ref of the next key
    expected_version: int | None = None


class CaPromote(_Strict):
    expected_version: int | None = None
    force: bool = False  # promote before the minimum age (every server already has the new trusted keys)


class TokenCreate(_Strict):
    name: str = Field(min_length=1, max_length=64)

    @field_validator("name")
    @classmethod
    def _name(cls, v: str) -> str:
        if not NAME_RE.match(v):
            raise ValueError("letters, digits, spaces and . _ - (64 at most)")
        return v


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


def _issued_count(session: Session, team_id: int, ca_id: int) -> int:
    """Certificates of one CA still in the audit (13 months), counted on demand for one CA (``uq_…_ca_serial``
    serves ``ca_id``); the list does not count, so its cost does not grow with the audit."""
    return int(session.exec(select(func.count()).select_from(CbomSshCertIssued).where(
        CbomSshCertIssued.ca_id == ca_id, CbomSshCertIssued.team_id == team_id)).one())


# ----------------------------------------------------------------------------- reads (static paths first)
def _list(engine, team_id: int) -> dict:
    now = utcnow()
    with Session(engine) as session:
        rows = session.exec(select(CbomSshCa).where(CbomSshCa.team_id == team_id).order_by(CbomSshCa.id)).all()
        wrap, _ref = KW.default_wrap()
        need, total = SRC.needing_admin_save(session, team_id)
        return {"server_time": iso_z(now),
                "cas": [R.public_ca(r, now, None, T.readiness(session, r, now)) for r in rows],
                "kms_keys": KW.kms_choices(), "default_key_wrap": wrap,
                "trust_generation": T.generations(session, team_id)[0],
                "attention": {"sources_needing_admin_save": need, "sources_needing_admin_save_total": total}}


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
# The three files below are kept current by the trust-fetch script (CBOM Sources > Fleet > SSH CA > Servers:
# "Fetch script"), run as root from a systemd timer every few minutes with a trust token of this team. It asks
# ZeroShield only for what changed (ETag), writes each file atomically, never installs an empty or unreadable
# revocation list (it keeps the old file instead), then checks `sshd -t` and reloads sshd. Rotation, promotion and
# revocation reach the server on its next run. Salt, Ansible and SSM installers: GitHub issue #{installer_issue}.
#
#   /etc/ssh/zs-cbom/trusted_user_ca_keys   TrustedUserCAKeys (next, active and recently retired CA keys)
#   /etc/ssh/zs-cbom/revoked.krl            RevokedKeys (OpenSSH KRL); sshd refuses EVERY key for zs-cbom while it is
#                                            missing, so run the script once before reloading sshd
#   /etc/ssh/zs-cbom/principals/zs-cbom     AuthorizedPrincipalsFile: zs-{team_id}-<group> for this server's group(s)
#
# Certificates carry no extensions (no PTY, forwarding or agent) and a source-address restriction to the scan node;
# the Match block also closes them for any other key of this account.
# OpenSSH 9.8+ (PerSourcePenalties): refused logins from the scan node's address delay its next connections; fix the
# cause (principals file, trusted keys) rather than exempting the node.
Match User zs-cbom
    TrustedUserCAKeys /etc/ssh/zs-cbom/trusted_user_ca_keys
    RevokedKeys /etc/ssh/zs-cbom/revoked.krl
    AuthorizedPrincipalsFile /etc/ssh/zs-cbom/principals/%u
    PermitTTY no
    AllowTcpForwarding no
    AllowAgentForwarding no
    AllowStreamLocalForwarding no
    X11Forwarding no
    PermitTunnel no
    PermitUserRC no
"""
INSTALLER_ISSUE = 83  # F1.3 track: Salt state, Ansible role and SSM document that install these files

TRUST_FETCH_TEMPLATE = r"""#!/bin/sh
# ZeroShield CBOM: keep this server's SSH CA trust current (team {team_id}). Run as root from a timer, e.g. every 5
# minutes with a random delay (systemd: OnUnitActiveSec=5min, RandomizedDelaySec=120). POSIX sh + curl + ssh-keygen.
#   ZS_TRUST_TOKEN  a trust token of this team (CBOM Sources > Fleet > SSH CA > Trust tokens); keep it in a 0600 file
#   ZS_URL          ZeroShield's API address (the one the scan nodes use, e.g. https://api.<your ZeroShield domain>)
#   ZS_GROUPS       this server's group(s), space separated (principals zs-{team_id}-<group>)
#   ZS_DIR          default /etc/ssh/zs-cbom;  ZS_RELOAD  default "systemctl reload ssh || systemctl reload sshd"
# It never installs an empty or unreadable file: on any failure it keeps the old one and exits non-zero.
set -u
umask 022
: "${{ZS_TRUST_TOKEN:?set ZS_TRUST_TOKEN}}"
URL="${{ZS_URL:?set ZS_URL to ZeroShield's API address}}"
DIR="${{ZS_DIR:-/etc/ssh/zs-cbom}}"
GROUPS_Q=""
for g in ${{ZS_GROUPS:-}}; do GROUPS_Q="${{GROUPS_Q}}${{GROUPS_Q:+&}}group=${{g}}"; done
NAME="$(hostname -f 2>/dev/null || hostname)"
mkdir -p "$DIR/principals" "$DIR/.etag" || exit 1
changed=0
fail=0

# fetch <path> <file> <check>: conditional GET (If-None-Match), atomic replace after <check> accepted the new file
fetch() {{
  path="$1"; dest="$2"; check="$3"; tag="$DIR/.etag/$(basename "$dest")"
  tmp="$(mktemp "$dest.new.XXXXXX")" || return 1
  hdr="$(mktemp "$dest.hdr.XXXXXX")" || {{ rm -f "$tmp"; return 1; }}
  set -- -sS --fail --max-time 30 -D "$hdr" -o "$tmp" -H "X-ZS-Trust-Token: $ZS_TRUST_TOKEN" -H "X-ZS-Fetcher: $NAME"
  if [ -s "$dest" ] && [ -s "$tag" ]; then set -- "$@" -H "If-None-Match: $(cat "$tag")"; fi
  code="$(curl "$@" -w '%{{http_code}}' "$URL/cbom/ssh-ca-trust$path")"  # with --fail: 4xx/5xx exit non-zero
  [ -n "$code" ] || code=000
  if [ "$code" = 304 ]; then rm -f "$tmp" "$hdr"; return 0; fi
  if [ "$code" != 200 ] || [ ! -s "$tmp" ] || ! $check "$tmp"; then
    echo "zs-trust-fetch: $path: HTTP $code or an unusable file; keeping $dest" >&2
    rm -f "$tmp" "$hdr"; return 1
  fi
  chmod 0644 "$tmp" && mv -f "$tmp" "$dest" || {{ rm -f "$tmp" "$hdr"; return 1; }}
  sed -n 's/^[Ee][Tt][Aa][Gg]: *//p' "$hdr" | tr -d '\r' > "$tag"
  rm -f "$hdr"; changed=1
}}
keys_ok() {{ grep -Eq '^(ssh-|ecdsa-|sk-)' "$1" || ! grep -qv '^#' "$1"; }}  # keys, or only comments (no CA)
krl_ok() {{ ssh-keygen -Q -l -f "$1" >/dev/null 2>&1; }}
text_ok() {{ head -c 1 "$1" >/dev/null; }}

fetch /trusted-keys "$DIR/trusted_user_ca_keys" keys_ok || fail=1
fetch /revoked "$DIR/revoked.krl" krl_ok || fail=1
fetch "/principals${{GROUPS_Q:+?}}$GROUPS_Q" "$DIR/principals/zs-cbom" text_ok || fail=1
if [ "$changed" = 1 ]; then
  if sshd -t; then
    sh -c "${{ZS_RELOAD:-systemctl reload ssh || systemctl reload sshd}}" || fail=1
  else
    echo "zs-trust-fetch: sshd -t failed; sshd was not reloaded" >&2; fail=1
  fi
fi
exit "$fail"
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
            summary="sshd configuration snippet, principals file or trust-fetch script for the servers")
async def template(team_id: TeamId, name: Literal["sshd-config", "principals", "trust-fetch"], ctx: Member,
                   group: str | None = Query(default=None, max_length=48)):
    engine, _user = ctx
    if group is not None and not _GROUP.match(group):
        raise HTTPException(status_code=400, detail="group: lowercase letters, digits and . _ -")
    if name == "sshd-config":
        return Response(SSHD_TEMPLATE.format(team_id=team_id, installer_issue=INSTALLER_ISSUE), headers=TEXT)
    if name == "trust-fetch":  # no request data in the script (the API address is the server's ZS_URL)
        return Response(TRUST_FETCH_TEMPLATE.format(team_id=int(team_id)), headers=TEXT)
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


# ----------------------------------------------------------------------------- trust tokens (servers' read access)
def _tokens(engine, team_id: int) -> dict:
    now = utcnow()
    with Session(engine) as session:
        return {"server_time": iso_z(now), "tokens": T.list_tokens(session, team_id, now),
                "trust_generation": T.generations(session, team_id)[0]}


@router.get(BASE + "/trust-tokens", dependencies=READ, openapi_extra=PERM_READ,
            summary="Trust tokens servers use to fetch the trust bundle (never the token itself)")
async def list_trust_tokens(team_id: TeamId, ctx: Member):
    engine, _user = ctx
    return _json(await _run("trust tokens", team_id, _tokens, engine, team_id))


def _create_token(engine, team_id: int, user_id: int, body: TokenCreate) -> dict:
    now = utcnow()
    with Session(engine) as session:
        require_admin(session, user_id, team_id, "SSH CA trust tokens")
        row, secret = T.create_token(session, team_id, user_id, body.name, now)
        session.commit()
        session.refresh(row)
        return {"trust_token": T.public_token(row), "token": secret}


@router.post(BASE + "/trust-tokens", dependencies=WRITE, openapi_extra=PERM_ADMIN,
             summary="Create a read-only trust token for the servers (shown once)")
async def create_trust_token(team_id: TeamId, ctx: Member, body: TokenCreate):
    engine, user = ctx
    return _json(await _run("create trust token", team_id, _create_token, engine, team_id, user.id, body), 201)


def _revoke_token(engine, team_id: int, user_id: int, token_id: int) -> dict:
    now = utcnow()
    with Session(engine) as session:
        require_admin(session, user_id, team_id, "SSH CA trust tokens")
        row = T.revoke_token(session, team_id, token_id, user_id, now)
        session.commit()
        session.refresh(row)
        return {"trust_token": T.public_token(row)}


@router.post(BASE + "/trust-tokens/{token_id}/revoke", dependencies=WRITE, openapi_extra=PERM_ADMIN,
             summary="Revoke a trust token (its servers get 401 from then on)")
async def revoke_trust_token(team_id: TeamId, token_id: ObjectId, ctx: Member):
    engine, user = ctx
    return _json(await _run("revoke trust token", team_id, _revoke_token, engine, team_id, user.id, token_id))


# ----------------------------------------------------------------------------- CA writes
def _create(engine, team_id: int, user_id: int, body: CaCreate) -> dict:
    now = utcnow()
    with Session(engine) as session:
        require_admin(session, user_id, team_id, "SSH CAs")
        if body.kms_key and body.kms_key_ref and body.kms_key != body.kms_key_ref:
            raise HTTPException(status_code=400, detail="kms_key: give kms_key or kms_key_ref, not both")
        body = body.model_copy(update={"kms_key_ref": body.kms_key or body.kms_key_ref})
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
        return {"ca": R.public_ca(row, now, _issued_count(session, team_id, ca_id), T.readiness(session, row, now))}


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
            row = R.rotate(session, row, user_id, now, body.secrets, body.vault_config)
        elif action == "promote":
            row = R.promote(session, row, user_id, now, force=body.force)
        else:
            row = R.revoke(session, row, user_id, body.reason, now)
        session.commit()
        session.refresh(row)
        return {"ca": R.public_ca(row, now, None, T.readiness(session, row, now))}


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
