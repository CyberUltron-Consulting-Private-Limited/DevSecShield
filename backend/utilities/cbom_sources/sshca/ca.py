"""``CertificateAuthority`` (F1 contract, section 3): the builtin CA (a key ZeroShield holds, wrapped at rest) and the
HashiCorp Vault SSH engine.  ``issue`` signs, checks, and adds the ``cbomsshcertissued`` audit row to the caller's
transaction; it never commits and never logs key or certificate material.
"""
from __future__ import annotations

import datetime as _dt
from dataclasses import dataclass
from typing import Protocol, Sequence

from sqlalchemy import update
from sqlmodel import Session

from backend.utilities.cbom_sources.common import utcnow
from backend.utilities.cbom_sources.crypto import decrypt_secrets
from backend.utilities.cbom_sources.sshca import certs as C
from backend.utilities.cbom_sources.sshca import keywrap as KW
from backend.utilities.cbom_sources.sshca import vault as V
from backend.utilities.cbom_sources.sshca.models import MAX_TTL_S, MIN_TTL_S, CbomSshCa, CbomSshCertIssued

SKEW = _dt.timedelta(seconds=60)  # valid_after = now - 60 s: a target whose clock is a little behind still accepts it
VAULT_TTL_SLACK_S = 5


class IssueError(Exception):
    """Why a certificate was not issued; ``str(err)`` is safe to show to the customer and to the node."""


@dataclass(frozen=True)
class IssuedCert:
    certificate: str
    serial: int
    key_id: str
    principals: tuple[str, ...]
    valid_after: _dt.datetime
    valid_before: _dt.datetime
    record_id: int | None = None


class CertificateAuthority(Protocol):
    def issue(self, principal: str | Sequence[str], ttl: _dt.timedelta, *, public_key: str, key_id: str,
              source_addresses: Sequence[str] = (), node_id: int | None = None,
              job_id: int | None = None) -> IssuedCert: ...

    def public_keys(self) -> list[str]: ...


def clamp_ttl(ttl: _dt.timedelta | int | float) -> int:
    seconds = int(ttl.total_seconds()) if isinstance(ttl, _dt.timedelta) else int(ttl)
    return max(MIN_TTL_S, min(MAX_TTL_S, seconds))


# Postgres BIGINT is signed; Vault serials are random unsigned 64-bit numbers.  Stored two's-complement, shown unsigned.
def to_db_serial(serial: int) -> int:
    return serial - 2 ** 64 if serial >= 2 ** 63 else serial


def from_db_serial(value: int) -> int:
    return value + 2 ** 64 if value < 0 else value


class _Base:
    def __init__(self, session: Session, row: CbomSshCa):
        self.session = session
        self.row = row

    def public_keys(self) -> list[str]:
        return [self.row.public_key]

    def _common(self, principal: str | Sequence[str], ttl: _dt.timedelta | int, public_key: str,
                source_addresses: Sequence[str]) -> tuple[tuple[str, ...], int, tuple[str, ...], bytes]:
        row = self.row
        if row.state != "active" or row.revoked_at is not None:
            raise IssueError(f"SSH CA {row.name} is {row.state}; only the active CA of a lineage signs")
        principals = (principal,) if isinstance(principal, str) else tuple(principal)
        try:
            principals = C.check_principals(principals, row.team_id)
            addresses = C.source_address_list(source_addresses)
            subject_blob = C.public_blob(public_key)
            C.load_subject_key(public_key)
        except C.CertError as exc:
            raise IssueError(str(exc)) from None
        return principals, clamp_ttl(ttl), addresses, subject_blob

    def _record(self, *, serial: int, key_id: str, principals: tuple[str, ...], addresses: tuple[str, ...],
                valid_after: _dt.datetime, valid_before: _dt.datetime, subject_blob: bytes, node_id: int | None,
                job_id: int | None, source_id: int | None, via: str, now: _dt.datetime) -> CbomSshCertIssued:
        record = CbomSshCertIssued(
            team_id=self.row.team_id, ca_id=int(self.row.id or 0), serial=to_db_serial(serial), key_id=key_id[:255],
            principals=list(principals), source_addresses=list(addresses), valid_after=valid_after,
            valid_before=valid_before, cert_public_key_sha256=C.blob_sha256_hex(subject_blob), node_id=node_id,
            job_id=job_id, source_id=source_id, via=via, issued_at=now, created_at=now, last_updated=now)
        self.session.add(record)
        self.session.flush()
        return record


class BuiltinCA(_Base):
    """Signs with the CA key ZeroShield holds (unwrapped through KMS or the deployment key, cached 10 minutes)."""

    def _next_serial(self) -> int:
        # one guarded UPDATE: two workers never sign the same serial, and a CA revoked or retired a moment ago signs
        # nothing more
        value = self.session.exec(  # type: ignore[call-overload]
            update(CbomSshCa)
            .where(CbomSshCa.id == self.row.id, CbomSshCa.state == "active",
                   CbomSshCa.revoked_at.is_(None))  # type: ignore[union-attr]
            .values(serial_next=CbomSshCa.serial_next + 1)
            .returning(CbomSshCa.serial_next)
            .execution_options(synchronize_session=False)
        ).scalar_one_or_none()
        if value is None:
            raise IssueError(f"SSH CA {self.row.name} is no longer active")
        return int(value) - 1

    def issue(self, principal, ttl, *, public_key, key_id, source_addresses=(), node_id=None, job_id=None,
              source_id: int | None = None, via: str = "claim", now: _dt.datetime | None = None) -> IssuedCert:
        principals, ttl_s, addresses, subject_blob = self._common(principal, ttl, public_key, source_addresses)
        row = self.row
        try:
            ca_key = KW.cached_private_key(int(row.id or 0), row.team_id, row.fingerprint, row.private_key_encrypted or "")
        except KW.WrapError as exc:
            raise IssueError(f"SSH CA {row.name}: {exc}") from None
        now = now or utcnow()
        valid_after, valid_before = now - SKEW, now + _dt.timedelta(seconds=ttl_s)
        serial = self._next_serial()
        key_id = key_id.replace("{serial}", str(serial))
        try:
            certificate = C.sign_user_cert(ca_key, public_key, serial=serial, key_id=key_id, principals=principals,
                                           valid_after=valid_after, valid_before=valid_before,
                                           source_addresses=addresses)
        except C.CertError as exc:
            raise IssueError(str(exc)) from None
        record = self._record(serial=serial, key_id=key_id, principals=principals, addresses=addresses,
                              valid_after=valid_after, valid_before=valid_before, subject_blob=subject_blob,
                              node_id=node_id, job_id=job_id, source_id=source_id, via=via, now=now)
        return IssuedCert(certificate, serial, key_id, principals, valid_after, valid_before, record.id)


class VaultCA(_Base):
    """Signs through the customer's Vault SSH engine; the returned certificate is checked before it is recorded."""

    def issue(self, principal, ttl, *, public_key, key_id, source_addresses=(), node_id=None, job_id=None,
              source_id: int | None = None, via: str = "claim", now: _dt.datetime | None = None) -> IssuedCert:
        principals, ttl_s, addresses, subject_blob = self._common(principal, ttl, public_key, source_addresses)
        row = self.row
        key_id = key_id.replace(":{serial}", "").replace("{serial}", "")
        try:
            cfg = V.check_config(row.vault_config)
            text = V.sign(cfg, decrypt_secrets(row.secret_encrypted), public_key_line=public_key,
                          principals=list(principals), ttl_s=ttl_s, key_id=key_id, source_addresses=list(addresses))
        except V.VaultError as exc:
            raise IssueError(f"SSH CA {row.name} (Vault): {exc}") from None
        now = now or utcnow()
        facts = self.check_returned(text, principals=principals, addresses=addresses, subject_blob=subject_blob,
                                    ttl_s=ttl_s, now=now)
        valid_after = _dt.datetime.fromtimestamp(facts.valid_after, _dt.timezone.utc).replace(tzinfo=None)
        valid_before = _dt.datetime.fromtimestamp(facts.valid_before, _dt.timezone.utc).replace(tzinfo=None)
        record = self._record(serial=facts.serial, key_id=facts.key_id, principals=principals, addresses=addresses,
                              valid_after=valid_after, valid_before=valid_before, subject_blob=subject_blob,
                              node_id=node_id, job_id=job_id, source_id=source_id, via=via, now=now)
        return IssuedCert(text, facts.serial, facts.key_id, principals, valid_after, valid_before, record.id)

    def check_returned(self, text: str, *, principals: tuple[str, ...], addresses: tuple[str, ...],
                       subject_blob: bytes, ttl_s: int, now: _dt.datetime) -> C.CertFacts:
        """Vault's answer is not trusted blindly: same CA key, a user certificate for our node key, exactly our
        principals, inside the requested validity, our source-address, and no extensions."""
        name = self.row.name
        try:
            facts = C.read_cert(text)
        except C.CertError as exc:
            raise IssueError(f"SSH CA {name} (Vault) returned an invalid certificate: {exc}") from None
        epoch = int(now.replace(tzinfo=_dt.timezone.utc).timestamp())
        problems = []
        if facts.signature_key_blob != C.public_blob(self.row.public_key):
            problems.append("it is signed by another CA key than the one registered")
        if facts.cert_type != "user":
            problems.append("it is not a user certificate")
        if facts.public_key_blob != subject_blob:
            problems.append("it certifies another key than the scan node's")
        if set(facts.principals) != set(principals):
            problems.append("its principals differ from the ones requested")
        if facts.valid_before > epoch + ttl_s + VAULT_TTL_SLACK_S or facts.valid_before <= epoch:
            problems.append("its validity is not the one requested")
        if addresses and facts.critical_options.get("source-address") != ",".join(addresses):
            problems.append("it has no source-address restriction (allow source-address in the role's "
                            "allowed_critical_options)")
        if set(facts.critical_options) - {"source-address"}:
            problems.append("it carries critical options that were not requested")
        if facts.extensions:
            problems.append("it carries extensions (set default_extensions to {} on the role)")
        if problems:
            raise IssueError(f"SSH CA {name} (Vault) returned a certificate that was refused: {'; '.join(problems)}")
        return facts


def ca_for(session: Session, team_id: int, ca_id: int) -> CertificateAuthority:
    """The CA object for a CA row of this team (``IssueError`` when it is missing or another team's)."""
    row = session.get(CbomSshCa, ca_id)
    if row is None or row.team_id != team_id:
        raise IssueError("SSH CA not found in this team")
    return VaultCA(session, row) if row.provider == "vault" else BuiltinCA(session, row)
