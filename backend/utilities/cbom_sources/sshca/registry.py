"""CA lineages, rotation, revocation and what a browser may see of a CA.

A lineage is a root CA and every CA rotated from it (``lineage_id`` = the root's id).  Sources and credentials name a
lineage (any CA id of it); the lineage's ``active`` CA signs.  Rotation: ``rotate`` adds a ``next`` CA (trusted at
once, signs nothing), the customer distributes ``trusted-keys``, ``promote`` makes it ``active`` and the old one
``retired``.  A retired CA stays in ``trusted-keys`` for ``OVERLAP`` (the longest certificate it could still have
live), then drops out.  ``revoke`` takes a CA (or one certificate) out for good: it goes into the KRL.
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
    if row.revoked_at is not None or row.state == "revoked":
        return False
    if row.state in ("next", "active"):
        return True
    return row.state == "retired" and row.retired_at is not None and now - row.retired_at < OVERLAP


def trusted_keys_text(session: Session, team_id: int, now: _dt.datetime) -> str:
    rows = session.exec(select(CbomSshCa).where(CbomSshCa.team_id == team_id).order_by(CbomSshCa.id)).all()
    lines = [f"# ZeroShield SSH CA keys for TrustedUserCAKeys (team {team_id}), generated {iso_z(now)}",
             "# Refresh this file after every rotate / promote / revoke; revoked keys also go in RevokedKeys (the KRL)."]
    for row in rows:
        if trusted(row, now):
            lines.append(f"{row.public_key.strip()} zs-ca-{row.id}-{row.state}")
    return "\n".join(lines) + "\n"


def public_ca(row: CbomSshCa, now: _dt.datetime, issued: int | None = None) -> dict[str, Any]:
    vault_cfg = dict(row.vault_config or {})
    if vault_cfg.get("ca_pem"):
        vault_cfg["ca_pem_set"] = True
        vault_cfg.pop("ca_pem", None)
    return {
        "id": row.id, "name": row.name, "provider": row.provider, "key_alg": row.key_alg,
        "public_key": row.public_key, "fingerprint": row.fingerprint, "key_wrap": row.key_wrap,
        "kms_key_ref": row.kms_key_ref, "vault_config": vault_cfg if row.provider == "vault" else None,
        "secrets_set": sorted(row.secret_fields or []), "state": row.state, "trusted": trusted(row, now),
        "default_ttl_s": row.default_ttl_s, "rotated_from_id": row.rotated_from_id, "lineage_id": lineage_of(row),
        "retired_at": iso_z(row.retired_at), "revoked_at": iso_z(row.revoked_at), "revoked_reason": row.revoked_reason,
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
            kms_key_ref = kms_key_ref or ref_default
            if not kms_key_ref or kms_key_ref not in KW.allowed_kms_keys():
                raise HTTPException(status_code=400, detail=f"kms_key_ref: choose one of the KMS keys this deployment "
                                                            f"allows ({KW.KMS_ENV})")
        elif key_wrap == "fernet":
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
            public = C.public_line_of(V.public_key(cfg))
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
    session.add(row)
    audit(session, team_id=team_id, actor_type="user", actor_id=user_id, action="sshca.create", object_type="ssh_ca",
          object_id=row.id, changed_fields=["name", "provider", "key_alg", "key_wrap", "default_ttl_s"]
          + [f"secrets.{k}" for k in material["secret_fields"]])
    log("ssh ca created", team=team_id, ca=row.id, provider=row.provider, alg=row.key_alg, wrap=row.key_wrap,
        by=user_id)
    return row


def rotate(session: Session, row: CbomSshCa, user_id: int, now: _dt.datetime, secrets: dict | None = None) -> CbomSshCa:
    """A ``next`` CA in the same lineage (same provider, wrap and TTL).  One pending rotation at a time."""
    lineage = lineage_of(row)
    rows = lineage_rows(session, row.team_id, lineage)
    if any(r.state == "next" for r in rows):
        raise HTTPException(status_code=409, detail="This CA already has a rotation waiting; promote or revoke it first")
    if row.state != "active":
        raise HTTPException(status_code=400, detail="Rotate the lineage's active CA")
    if row.provider == "vault":
        # Vault rotates its own key; a new row records the new public key once the mount has it
        from backend.utilities.cbom_sources.crypto import decrypt_secrets

        material = _new_key_material(row.team_id, "vault", row.key_alg, None, None, row.vault_config,
                                     secrets or decrypt_secrets(row.secret_encrypted))
        if material["fingerprint"] == row.fingerprint:
            raise HTTPException(status_code=400, detail="Vault still returns the same CA key; rotate the key in Vault "
                                                        "first (POST <mount>/config/ca), then rotate here")
    else:
        material = _new_key_material(row.team_id, "builtin", row.key_alg, row.key_wrap, row.kms_key_ref, None, None)
    new = CbomSshCa(team_id=row.team_id, owner_user_id=user_id, updated_by_user_id=user_id, name=row.name[:56] + "-next",
                    provider=row.provider, state="next", default_ttl_s=row.default_ttl_s, rotated_from_id=row.id,
                    lineage_id=lineage, created_at=now, last_updated=now, **material)
    session.add(new)
    session.flush()
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


def promote(session: Session, row: CbomSshCa, user_id: int, now: _dt.datetime) -> CbomSshCa:
    if row.state != "next" or row.revoked_at is not None:
        raise HTTPException(status_code=400, detail="Only a CA waiting in rotation (state next) can be promoted")
    for other in lineage_rows(session, row.team_id, lineage_of(row)):
        if other.id != row.id and other.state == "active":
            if not _bump(session, other, {"state": "retired", "retired_at": now, "last_updated": now,
                                          "updated_by_user_id": user_id}, expect_state="active"):
                raise HTTPException(status_code=409, detail="This was changed elsewhere. Reload to see the latest version.")
            KW.forget(other.id)
    if not _bump(session, row, {"state": "active", "last_updated": now, "updated_by_user_id": user_id},
                 expect_state="next"):
        raise HTTPException(status_code=409, detail="This was changed elsewhere. Reload to see the latest version.")
    audit(session, team_id=row.team_id, actor_type="user", actor_id=user_id, action="sshca.promote",
          object_type="ssh_ca", object_id=row.id, changed_fields=["state"])
    log("ssh ca promoted", team=row.team_id, ca=row.id, by=user_id)
    return row


def revoke(session: Session, row: CbomSshCa, user_id: int, reason: str, now: _dt.datetime) -> CbomSshCa:
    if row.revoked_at is not None:
        raise HTTPException(status_code=400, detail="This CA is already revoked")
    if not _bump(session, row, {"state": "revoked", "revoked_at": now, "revoked_reason": reason[:512],
                                "last_updated": now, "updated_by_user_id": user_id}):
        raise HTTPException(status_code=409, detail="This was changed elsewhere. Reload to see the latest version.")
    KW.forget(row.id)
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
    audit(session, team_id=team_id, actor_type="user", actor_id=user_id, action="sshca.cert.revoke",
          object_type="ssh_cert", object_id=row.id, changed_fields=["revoked_at", "revoked_reason"])
    log("ssh certificate revoked", team=team_id, cert=row.id, ca=row.ca_id, by=user_id)
    return row


# ----------------------------------------------------------------------------- revocation list
KRL_KEEP_EXPIRED = _dt.timedelta(hours=1)  # a revoked certificate stays listed this long after it expired (clock skew)


def krl_bytes(session: Session, team_id: int, now: _dt.datetime) -> bytes:
    """The team's KRL: every revoked CA key, and the serials of revoked certificates still (nearly) valid."""
    from backend.utilities.cbom_sources.sshca import krl

    cas = {row.id: row for row in session.exec(select(CbomSshCa).where(CbomSshCa.team_id == team_id)).all()}
    revoked_cas = [C.public_blob(row.public_key) for row in cas.values() if row.revoked_at is not None]
    certs = session.exec(select(CbomSshCertIssued).where(
        CbomSshCertIssued.team_id == team_id, CbomSshCertIssued.revoked_at.is_not(None),  # type: ignore[union-attr]
        CbomSshCertIssued.valid_before > now - KRL_KEEP_EXPIRED)).all()
    serials: dict[bytes, list[int]] = {}
    for cert in certs:
        ca = cas.get(cert.ca_id)
        if ca is not None:
            serials.setdefault(C.public_blob(ca.public_key), []).append(from_db_serial(int(cert.serial)))
    stamp = int(now.replace(tzinfo=_dt.timezone.utc).timestamp())
    return krl.build(revoked_ca_blobs=revoked_cas, revoked_serials=serials, krl_version=stamp, generated=stamp,
                     comment=f"ZeroShield SSH CA revocations, team {team_id}")


def revoked_keys_text(session: Session, team_id: int, now: _dt.datetime) -> str:
    rows = session.exec(select(CbomSshCa).where(CbomSshCa.team_id == team_id, CbomSshCa.revoked_at.is_not(None))  # type: ignore[union-attr]
                        .order_by(CbomSshCa.id)).all()
    lines = [f"# ZeroShield revoked SSH CA keys (team {team_id}), generated {iso_z(now)}. Revoked certificates are only "
             "in the KRL (GET .../ssh-ca/revoked)."]
    lines += [f"{row.public_key.strip()} zs-ca-{row.id}-revoked" for row in rows]
    return "\n".join(lines) + "\n"
