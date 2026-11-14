"""CA lineages, rotation, revocation and what a browser may see of a CA.

A lineage is a root CA and every CA rotated from it (``lineage_id`` = the root's id).  Sources and credentials name a
lineage (any CA id of it); the lineage's ``active`` CA signs.  Rotation: ``rotate`` adds a ``next`` CA (trusted at
once, signs nothing), the customer distributes ``trusted-keys``, ``promote`` makes it ``active`` and the old one
``retired``.  A retired CA stays in ``trusted-keys`` for ``OVERLAP`` (the longest certificate it could still have
live), then drops out.  ``revoke`` takes a CA (or one certificate) out for good: it goes into the KRL.

Every change of what servers must trust moves the team's trust generation (``trust.bump``), which the machine read
path serves with the files; ``promote`` waits until the ``next`` key is at least ``CBOM_SSHCA_PROMOTE_MIN_AGE_S`` old
(900 s) unless forced, and shows how many fetchers already have it.  Key wrap: a new key (create or rotate) gets the
deployment's wrap: AWS KMS whenever ``CBOM_SSHCA_KMS_KEY_ARNS`` is set (``fernet`` is then refused), the row's own KMS
key on rotation only while the allow-list still has it.
"""
from __future__ import annotations

import datetime as _dt
from typing import Any

from fastapi import HTTPException
from sqlalchemy import update
from sqlmodel import Session, select

from backend.utilities.cbom_sources.common import audit, iso_z, log
from backend.utilities.cbom_sources.crypto import encrypt_secrets
from backend.utilities.cbom_sources.sshca import certs as C
from backend.utilities.cbom_sources.sshca import flags
from backend.utilities.cbom_sources.sshca import keywrap as KW
from backend.utilities.cbom_sources.sshca import trust as T
from backend.utilities.cbom_sources.sshca import vault as V
from backend.utilities.cbom_sources.sshca.ca import from_db_serial
from backend.utilities.cbom_sources.sshca.models import (
    DEFAULT_TTL_S,
    MAX_TTL_S,
    MIN_TTL_S,
    CbomSshCa,
    CbomSshCertIssued,
)

OVERLAP = _dt.timedelta(seconds=MAX_TTL_S + 300)
MAX_CAS_PER_TEAM = 50


def lineage_of(row: CbomSshCa) -> int:
    return int(row.lineage_id or row.id or 0)


def get_ca(session: Session, team_id: int, ca_id: int) -> CbomSshCa:
    row = session.get(CbomSshCa, ca_id)
    if row is None or row.team_id != team_id:
        raise HTTPException(status_code=404, detail="SSH CA not found")
    return row


def lineage_rows(session: Session, team_id: int, lineage_id: int) -> list[CbomSshCa]:
    return list(session.exec(select(CbomSshCa).where(CbomSshCa.team_id == team_id, CbomSshCa.lineage_id == lineage_id)
                             .order_by(CbomSshCa.id)).all())  # type: ignore[arg-type]


def signing_ca(session: Session, team_id: int, ca_ref: int | None) -> CbomSshCa | None:
    """The active, unrevoked CA of the lineage ``ca_ref`` belongs to (in this team), or None."""
    if not ca_ref:
        return None
    row = session.get(CbomSshCa, ca_ref)
    if row is None or row.team_id != team_id:
        return None
    return session.exec(select(CbomSshCa).where(
        CbomSshCa.team_id == team_id, CbomSshCa.lineage_id == lineage_of(row), CbomSshCa.state == "active",
        CbomSshCa.revoked_at.is_(None))).first()  # type: ignore[union-attr]


def usable_ca(session: Session, team_id: int, ca_id: int) -> bool:
    """F1.2's seam (``PolicyEngine``): a policy may use this CA lineage now."""
    return flags.enabled() and signing_ca(session, team_id, ca_id) is not None


def trusted(row: CbomSshCa, now: _dt.datetime) -> bool:
    return T.trusted(row, now, OVERLAP)


def trusted_keys_text(session: Session, team_id: int, now: _dt.datetime) -> str:
    return T.trusted_keys_text(session, team_id, now, OVERLAP)


def wrap_warning(row: CbomSshCa) -> str | None:
    if row.provider == "builtin" and row.key_wrap == "fernet" and row.state in ("next", "active") \
            and KW.kms_configured():
        return ("This CA key is wrapped by the deployment key, but this deployment wraps SSH CA keys with AWS KMS: "
                "rotate the CA to move it onto KMS")
    return None


def public_ca(row: CbomSshCa, now: _dt.datetime, issued: int | None = None,
              readiness: dict[str, Any] | None = None) -> dict[str, Any]:
    vault_cfg = dict(row.vault_config or {})
    if vault_cfg.get("ca_pem"):
        vault_cfg["ca_pem_set"] = True
        vault_cfg.pop("ca_pem", None)
    return {
        "id": row.id, "name": row.name, "provider": row.provider, "key_alg": row.key_alg,
        "public_key": row.public_key, "fingerprint": row.fingerprint, "key_wrap": row.key_wrap,
        "kms_key": KW.kms_label(row.kms_key_ref), "wrap_warning": wrap_warning(row),
        "vault_config": vault_cfg if row.provider == "vault" else None,
        "secrets_set": sorted(row.secret_fields or []), "state": row.state, "trusted": trusted(row, now),
        "default_ttl_s": row.default_ttl_s, "rotated_from_id": row.rotated_from_id, "lineage_id": lineage_of(row),
        "retired_at": iso_z(row.retired_at), "revoked_at": iso_z(row.revoked_at), "revoked_reason": row.revoked_reason,
        "trust_generation": row.trust_generation, "readiness": readiness,
        "issued_count": issued, "row_version": row.row_version, "created_at": iso_z(row.created_at),
        "last_updated": iso_z(row.last_updated),
    }


def public_cert(row: CbomSshCertIssued, now: _dt.datetime) -> dict[str, Any]:
    status = "revoked" if row.revoked_at else ("valid" if row.valid_before > now else "expired")
    return {
        "id": row.id, "ca_id": row.ca_id, "serial": from_db_serial(int(row.serial)), "key_id": row.key_id,
        "principals": row.principals or [], "source_addresses": row.source_addresses or [],
        "valid_after": iso_z(row.valid_after), "valid_before": iso_z(row.valid_before), "status": status,
        "cert_public_key_sha256": row.cert_public_key_sha256, "node_id": row.node_id, "job_id": row.job_id,
        "source_id": row.source_id, "via": row.via, "issued_at": iso_z(row.issued_at),
        "revoked_at": iso_z(row.revoked_at), "revoked_reason": row.revoked_reason,
    }


# ----------------------------------------------------------------------------- lifecycle
def _check_ttl(value: int | None) -> int:
    ttl = DEFAULT_TTL_S if value is None else int(value)
    if ttl < MIN_TTL_S or ttl > MAX_TTL_S:
        raise HTTPException(status_code=400, detail=f"default_ttl_s: between {MIN_TTL_S} and {MAX_TTL_S} seconds")
    return ttl


def _new_key_material(team_id: int, provider: str, key_alg: str, key_wrap: str | None, kms_key_ref: str | None,
                      vault_config: dict | None, secrets: dict | None) -> dict[str, Any]:
    """Columns of a new CA key: a builtin key generated and wrapped, or a Vault mount's public key."""
    if provider == "builtin":
        if vault_config or secrets:
            raise HTTPException(status_code=400, detail="vault_config: only for provider vault")
        wrap_default, ref_default = KW.default_wrap()
        key_wrap = key_wrap or wrap_default
        if key_wrap == "aws_kms":
            arn = KW.resolve_kms_key(kms_key_ref) if kms_key_ref else ref_default
            if not arn:
                raise HTTPException(status_code=400, detail=f"kms_key: choose one of the KMS keys this deployment "
                                                            f"allows ({KW.KMS_ENV})")
            kms_key_ref = arn
        elif key_wrap == "fernet":
            if KW.kms_configured():  # contract section 9: KMS whenever it is configured; no opt-out (sec M2)
                raise HTTPException(status_code=400, detail="key_wrap: this deployment wraps SSH CA keys with AWS KMS; "
                                                            "the deployment key cannot be chosen")
            kms_key_ref = None
        else:
            raise HTTPException(status_code=400, detail="key_wrap: fernet or aws_kms")
        try:
            private = C.generate_ca_key(key_alg)
        except C.CertError as exc:
            raise HTTPException(status_code=400, detail=f"key_alg: {exc}") from None
        public = C.public_line(private)
        fp = C.fingerprint(public)
        try:
            wrapped = KW.wrap(C.private_to_openssh(private), team_id=team_id, ca_fingerprint=fp, key_wrap=key_wrap,
                              kms_key_ref=kms_key_ref)
        except KW.WrapError as exc:
            raise HTTPException(status_code=400, detail=f"key_wrap: {exc}") from None
        return {"key_alg": key_alg, "public_key": public, "fingerprint": fp, "private_key_encrypted": wrapped,
                "key_wrap": key_wrap, "kms_key_ref": kms_key_ref, "vault_config": {}, "secret_encrypted": None,
                "secret_fields": []}
    if provider == "vault":
        if key_wrap or kms_key_ref:
            raise HTTPException(status_code=400, detail="key_wrap: the key stays in Vault for provider vault")
        try:
            cfg = V.check_config(vault_config)
            checked = V.check_secrets(secrets)
            public = C.public_line_of(V.public_key(cfg))  # the issuer's key when issuer_ref is set
            C.load_subject_key(public)  # a plain Ed25519 / ECDSA / RSA >= 3072 key, never a certificate
        except V.VaultError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from None
        except C.CertError:
            raise HTTPException(status_code=400, detail="Vault returned a CA public key that cannot be used") from None
        alg = "ed25519" if public.startswith("ssh-ed25519 ") else ("ecdsa-p256" if public.startswith("ecdsa-") else "rsa")
        return {"key_alg": alg, "public_key": public, "fingerprint": C.fingerprint(public),
                "private_key_encrypted": None, "key_wrap": None, "kms_key_ref": None, "vault_config": cfg,
                "secret_encrypted": encrypt_secrets(checked), "secret_fields": sorted(checked)}
    raise HTTPException(status_code=400, detail="provider: builtin or vault")


def create_ca(session: Session, team_id: int, user_id: int, body: Any, now: _dt.datetime) -> CbomSshCa:
    count = len(session.exec(select(CbomSshCa.id).where(CbomSshCa.team_id == team_id)).all())
    if count >= MAX_CAS_PER_TEAM:
        raise HTTPException(status_code=400, detail=f"A team can have at most {MAX_CAS_PER_TEAM} SSH CA keys")
    material = _new_key_material(team_id, body.provider, body.key_alg, body.key_wrap, body.kms_key_ref,
                                 body.vault_config, body.secrets)
    row = CbomSshCa(team_id=team_id, owner_user_id=user_id, updated_by_user_id=user_id, name=body.name,
                    provider=body.provider, state="active", default_ttl_s=_check_ttl(body.default_ttl_s),
                    created_at=now, last_updated=now, **material)
    session.add(row)
    session.flush()
    row.lineage_id = row.id
    row.trust_generation = T.bump(session, team_id, now)
    session.add(row)
    audit(session, team_id=team_id, actor_type="user", actor_id=user_id, action="sshca.create", object_type="ssh_ca",
          object_id=row.id, changed_fields=["name", "provider", "key_alg", "key_wrap", "default_ttl_s"]
          + [f"secrets.{k}" for k in material["secret_fields"]])
    log("ssh ca created", team=team_id, ca=row.id, provider=row.provider, alg=row.key_alg, wrap=row.key_wrap,
        by=user_id)
    return row


VAULT_ROTATE_KEYS = ("mount", "role", "issuer_ref")


def _rotation_wrap(row: CbomSshCa) -> tuple[str | None, str | None]:
    """The wrap of the next key: the deployment's (``KW.default_wrap``), except that a KMS-wrapped CA keeps its KMS
    key while the allow-list still has it.  A fernet CA moves onto KMS once KMS is configured; a CA whose KMS key left
    the allow-list moves onto the default key (the old key still unwraps the old row)."""
    if row.key_wrap == "aws_kms" and row.kms_key_ref in KW.allowed_kms_keys():
        return "aws_kms", row.kms_key_ref
    return KW.default_wrap()


def rotate(session: Session, row: CbomSshCa, user_id: int, now: _dt.datetime, secrets: dict | None = None,
           vault_overrides: dict | None = None) -> CbomSshCa:
    """A ``next`` CA in the same lineage (same provider and TTL).  One pending rotation at a time."""
    lineage = lineage_of(row)
    rows = lineage_rows(session, row.team_id, lineage)
    if any(r.state == "next" for r in rows):
        raise HTTPException(status_code=409, detail="This CA already has a rotation waiting; promote or revoke it first")
    if row.state != "active":
        raise HTTPException(status_code=400, detail="Rotate the lineage's active CA")
    if row.provider == "vault":
        # the next key lives in another issuer (issuer_ref) or mount, with a role that signs with it; the active row
        # keeps signing through its own mount and role until promote (no gap)
        from backend.utilities.cbom_sources.crypto import decrypt_secrets

        overrides = dict(vault_overrides or {})
        if set(overrides) - set(VAULT_ROTATE_KEYS):
            raise HTTPException(status_code=400, detail="vault_config: only mount, role and issuer_ref can change "
                                                        "on rotation")
        cfg = {**dict(row.vault_config or {}), **{k: v for k, v in overrides.items() if v is not None}}
        material = _new_key_material(row.team_id, "vault", row.key_alg, None, None, cfg,
                                     secrets or decrypt_secrets(row.secret_encrypted))
        if material["fingerprint"] == row.fingerprint:
            raise HTTPException(status_code=400, detail="Vault returns the same CA key as the active one: point the "
                                                        "rotation at the issuer (issuer_ref) or mount that holds the "
                                                        "new key, with a role that signs with it")
    else:
        if vault_overrides:
            raise HTTPException(status_code=400, detail="vault_config: only for provider vault")
        wrap, ref = _rotation_wrap(row)
        material = _new_key_material(row.team_id, "builtin", row.key_alg, wrap, ref, None, None)
    new = CbomSshCa(team_id=row.team_id, owner_user_id=user_id, updated_by_user_id=user_id, name=row.name[:56] + "-next",
                    provider=row.provider, state="next", default_ttl_s=row.default_ttl_s, rotated_from_id=row.id,
                    lineage_id=lineage, created_at=now, last_updated=now, **material)
    session.add(new)
    session.flush()
    new.trust_generation = T.bump(session, row.team_id, now)
    session.add(new)
    audit(session, team_id=row.team_id, actor_type="user", actor_id=user_id, action="sshca.rotate",
          object_type="ssh_ca", object_id=new.id, changed_fields=["rotated_from_id"])
    log("ssh ca rotation started", team=row.team_id, ca=new.id, rotated_from=row.id, by=user_id)
    return new


def _bump(session: Session, row: CbomSshCa, values: dict[str, Any], *, expect_state: str | None = None) -> bool:
    cond = [CbomSshCa.id == row.id, CbomSshCa.row_version == row.row_version]
    if expect_state:
        cond.append(CbomSshCa.state == expect_state)
    changed = session.exec(update(CbomSshCa).where(*cond)  # type: ignore[call-overload]
                           .values(row_version=row.row_version + 1, **values)
                           .execution_options(synchronize_session=False)).rowcount
    session.expire(row)
    return changed == 1


def promote(session: Session, row: CbomSshCa, user_id: int, now: _dt.datetime, force: bool = False) -> CbomSshCa:
    if row.state != "next" or row.revoked_at is not None:
        raise HTTPException(status_code=400, detail="Only a CA waiting in rotation (state next) can be promoted")
    ready = T.readiness(session, row, now) or {}
    if not force and ready.get("age_s", 0) < ready.get("min_age_s", 0):
        fetchers = (f"{ready['fetchers_ready']} of {ready['fetchers_total']} servers that fetch the trust bundle "
                    "have it" if ready.get("fetchers_total") else "no server fetches the trust bundle with a trust token")
        raise HTTPException(status_code=400, detail=(
            f"This CA key was added {ready['age_s'] // 60} min ago and servers may not trust it yet ({fetchers}). "
            f"Promote it after {ready['promote_after']}, or promote with force once every server has the new "
            "trusted keys"))
    for other in lineage_rows(session, row.team_id, lineage_of(row)):
        if other.id != row.id and other.state == "active":
            if not _bump(session, other, {"state": "retired", "retired_at": now, "last_updated": now,
                                          "updated_by_user_id": user_id}, expect_state="active"):
                raise HTTPException(status_code=409, detail="This was changed elsewhere. Reload to see the latest version.")
            KW.forget(other.id)
    if not _bump(session, row, {"state": "active", "last_updated": now, "updated_by_user_id": user_id},
                 expect_state="next"):
        raise HTTPException(status_code=409, detail="This was changed elsewhere. Reload to see the latest version.")
    T.bump(session, row.team_id, now)
    audit(session, team_id=row.team_id, actor_type="user", actor_id=user_id, action="sshca.promote",
          object_type="ssh_ca", object_id=row.id, changed_fields=["state"] + (["force"] if force else []))
    log("ssh ca promoted", team=row.team_id, ca=row.id, by=user_id, forced=int(force),
        fetchers_ready=ready.get("fetchers_ready"), fetchers_total=ready.get("fetchers_total"))
    return row


def revoke(session: Session, row: CbomSshCa, user_id: int, reason: str, now: _dt.datetime) -> CbomSshCa:
    if row.revoked_at is not None:
        raise HTTPException(status_code=400, detail="This CA is already revoked")
    if not _bump(session, row, {"state": "revoked", "revoked_at": now, "revoked_reason": reason[:512],
                                "last_updated": now, "updated_by_user_id": user_id}):
        raise HTTPException(status_code=409, detail="This was changed elsewhere. Reload to see the latest version.")
    KW.forget(row.id)
    T.bump(session, row.team_id, now, revocation=True)
    audit(session, team_id=row.team_id, actor_type="user", actor_id=user_id, action="sshca.revoke",
          object_type="ssh_ca", object_id=row.id, changed_fields=["state", "revoked_reason"])
    log("ssh ca revoked", team=row.team_id, ca=row.id, by=user_id)
    return row


def revoke_cert(session: Session, team_id: int, cert_id: int, user_id: int, reason: str,
                now: _dt.datetime) -> CbomSshCertIssued:
    row = session.get(CbomSshCertIssued, cert_id)
    if row is None or row.team_id != team_id:
        raise HTTPException(status_code=404, detail="Certificate not found")
    if row.revoked_at is not None:
        raise HTTPException(status_code=400, detail="This certificate is already revoked")
    changed = session.exec(update(CbomSshCertIssued)  # type: ignore[call-overload]
                           .where(CbomSshCertIssued.id == row.id, CbomSshCertIssued.revoked_at.is_(None))  # type: ignore[union-attr]
                           .values(revoked_at=now, revoked_reason=reason[:512], last_updated=now,
                                   row_version=CbomSshCertIssued.row_version + 1)
                           .execution_options(synchronize_session=False)).rowcount
    if changed != 1:
        raise HTTPException(status_code=409, detail="This was changed elsewhere. Reload to see the latest version.")
    session.expire(row)
    T.bump(session, team_id, now, revocation=True)
    audit(session, team_id=team_id, actor_type="user", actor_id=user_id, action="sshca.cert.revoke",
          object_type="ssh_cert", object_id=row.id, changed_fields=["revoked_at", "revoked_reason"])
    log("ssh certificate revoked", team=team_id, cert=row.id, ca=row.ca_id, by=user_id)
    return row


# ----------------------------------------------------------------------------- revocation list
def krl_bytes(session: Session, team_id: int, now: _dt.datetime | None = None) -> bytes:
    """The team's KRL (``trust.krl_bytes``: cached per revocation generation)."""
    return T.krl_bytes(session, team_id)[0]


def revoked_keys_text(session: Session, team_id: int, now: _dt.datetime) -> str:
    rows = session.exec(select(CbomSshCa).where(CbomSshCa.team_id == team_id, CbomSshCa.revoked_at.is_not(None))  # type: ignore[union-attr]
                        .order_by(CbomSshCa.id)).all()
    lines = [f"# ZeroShield revoked SSH CA keys (team {team_id}), generated {iso_z(now)}. Revoked certificates are only "
             "in the KRL (GET .../ssh-ca/revoked)."]
    lines += [f"{row.public_key.strip()} zs-ca-{row.id}-revoked" for row in rows]
    return "\n".join(lines) + "\n"
