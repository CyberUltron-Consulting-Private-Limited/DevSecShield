"""``CertificateAuthority`` (F1 contract, section 3): the builtin CA (a key ZeroShield holds, wrapped at rest) and the
HashiCorp Vault SSH engine.  ``issue`` signs, checks, and adds the ``cbomsshcertissued`` audit row to the caller's
transaction; it never commits and never logs key or certificate material.
"""
from __future__ import annotations

import datetime as _dt
from dataclasses import dataclass
from typing import Callable, Protocol, Sequence

from sqlalchemy import select, update
from sqlmodel import Session

from backend.utilities.cbom_sources.common import utcnow
from backend.utilities.cbom_sources.crypto import decrypt_secrets
from backend.utilities.cbom_sources.sshca import certs as C
from backend.utilities.cbom_sources.sshca import keywrap as KW
from backend.utilities.cbom_sources.sshca import vault as V
from backend.utilities.cbom_sources.sshca.models import (
    MAX_TTL_S,
    MIN_TTL_S,
    SERIAL_SEQUENCE,
    CbomSshCa,
    CbomSshCertIssued,
)

MAX_SKEW_S = 60
VAULT_TTL_SLACK_S = 5  # Vault stamps the validity with its own clock


def skew_s(ttl_s: int) -> int:
    """How far ``valid_after`` is back-dated, so a server whose clock is a little behind still accepts a certificate:
    60 s, or a fifth of a shorter TTL.  It comes OUT of the TTL: ``valid_before - valid_after`` is exactly the TTL
    (a 5-minute certificate is valid for 5 minutes in all, whatever the clocks say)."""
    return min(MAX_SKEW_S, int(ttl_s) // 5)


def usable_s(ttl_s: int) -> int:
    """Seconds a certificate is good for after it is issued (by the server's clock): the TTL less the back-dating."""
    return int(ttl_s) - skew_s(ttl_s)


class IssueError(Exception):
    """Why a certificate was not issued; ``str(err)`` is safe to show to the customer and to the node.

    ``code``: a short reason code (audit row and log line).  ``status``: what the node route answers: 400 (refused),
    409 (the job must stop; the message starts "Stop this job:"), 503 (``transient``: AWS KMS did not answer, ask
    again later; the claim leaves the certificate to the route)."""

    def __init__(self, message: str, code: str = "refused", *, status: int = 400) -> None:
        super().__init__(message)
        self.code = code
        self.status = status

    @property
    def transient(self) -> bool:
        return self.status == 503

    @classmethod
    def from_wrap(cls, ca_name: str, exc: KW.WrapError) -> "IssueError":
        return cls(f"SSH CA {ca_name}: {exc}", exc.code, status=503 if exc.transient else 400)


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
    """``release``: called just before a network call (AWS KMS unwrapping a key this worker has not cached, or Vault
    signing) to end the caller's read transaction, so no pooled connection waits idle in a transaction while KMS or
    Vault answers (architecture re-review 5874161772).  After the call the CA row is share-locked again
    (``_lock_active``), so a revoke committed meanwhile still stops the mint.  None (the claim, which signs only with
    a key already in memory): nothing is released."""

    def __init__(self, session: Session, row: CbomSshCa, *, release: Callable[[], None] | None = None):
        self.session = session
        self.row = row
        self.release = release

    def _release_reads(self) -> None:
        if self.release is not None:
            self.release()

    def public_keys(self) -> list[str]:
        return [self.row.public_key]

    def _common(self, principal: str | Sequence[str], ttl: _dt.timedelta | int, public_key: str,
                source_addresses: Sequence[str]) -> tuple[tuple[str, ...], int, tuple[str, ...], bytes]:
        row = self.row
        if row.state != "active" or row.revoked_at is not None:
            KW.forget(row.id)  # another worker revoked or retired it: its key leaves this worker's memory too
            raise IssueError(f"SSH CA {row.name} is {row.state}; only the active CA of a lineage signs", "ca_not_active")
        principals = (principal,) if isinstance(principal, str) else tuple(principal)
        try:
            principals = C.check_principals(principals, row.team_id)
            addresses = C.source_address_list(source_addresses)
            subject_blob = C.public_blob(public_key)
            C.load_subject_key(public_key)
        except C.CertError as exc:
            raise IssueError(str(exc), "certificate_fields") from None
        return principals, clamp_ttl(ttl), addresses, subject_blob

    def _lock_active(self) -> None:
        """``SELECT … FOR SHARE`` on the CA row: it is still active and stays so until the caller commits.  Mints take
        share locks, which never block each other; a revoke or promote (an UPDATE) waits for the mints in flight, so
        nothing is signed by a CA after its revocation committed."""
        found = self.session.exec(  # type: ignore[call-overload]
            select(CbomSshCa.id).where(CbomSshCa.id == self.row.id, CbomSshCa.state == "active",
                                       CbomSshCa.revoked_at.is_(None))  # type: ignore[union-attr]
            .with_for_update(read=True)).first()
        if found is None:
            KW.forget(self.row.id)
            raise IssueError(f"SSH CA {self.row.name} is no longer active", "ca_not_active")

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
        """PostgreSQL: the CA row is share-locked (still active) and the serial comes from the deployment-wide
        SEQUENCE ``cbomsshca_serial_seq`` (``nextval`` never waits and is never rolled back, so serials are unique per
        CA; ``uq_cbomsshcertissued_ca_serial`` still guards).  No row lock is held across the caller's transaction, so
        the mints of one CA do not queue behind each other (contract §3, amended 2026-11-12).  SQLite (unit tests,
        one writer at a time): the guarded ``UPDATE serial_next``."""
        self._lock_active()
        if self.session.get_bind().dialect.name == "postgresql":
            return int(self.session.exec(select(SERIAL_SEQUENCE.next_value())).one()[0])  # type: ignore[call-overload]
        value = self.session.exec(  # type: ignore[call-overload]
            update(CbomSshCa)
            .where(CbomSshCa.id == self.row.id, CbomSshCa.state == "active",
                   CbomSshCa.revoked_at.is_(None))  # type: ignore[union-attr]
            .values(serial_next=CbomSshCa.serial_next + 1)
            .returning(CbomSshCa.serial_next)
            .execution_options(synchronize_session=False)
        ).scalar_one_or_none()
        if value is None:
            raise IssueError(f"SSH CA {self.row.name} is no longer active", "ca_not_active")
        return int(value) - 1

    def issue(self, principal, ttl, *, public_key, key_id, source_addresses=(), node_id=None, job_id=None,
              source_id: int | None = None, via: str = "claim", now: _dt.datetime | None = None) -> IssuedCert:
        principals, ttl_s, addresses, subject_blob = self._common(principal, ttl, public_key, source_addresses)
        row = self.row
        ca_id, team_id, name, fingerprint = int(row.id or 0), row.team_id, row.name, row.fingerprint
        blob = row.private_key_encrypted or ""
        if row.key_wrap == "aws_kms" and not KW.is_cached(ca_id, fingerprint):
            self._release_reads()  # KMS may take seconds (or fail after its timeouts): hold no transaction meanwhile
        try:
            ca_key = KW.cached_private_key(ca_id, team_id, fingerprint, blob)
        except KW.WrapError as exc:
            raise IssueError.from_wrap(name, exc) from None
        now = now or utcnow()
        valid_after = now - _dt.timedelta(seconds=skew_s(ttl_s))
        valid_before = valid_after + _dt.timedelta(seconds=ttl_s)  # the whole window is the TTL
        serial = self._next_serial()
        key_id = key_id.replace("{serial}", str(serial))
        try:
            certificate = C.sign_user_cert(ca_key, public_key, serial=serial, key_id=key_id, principals=principals,
                                           valid_after=valid_after, valid_before=valid_before,
                                           source_addresses=addresses)
        except C.CertError as exc:
            raise IssueError(str(exc), "certificate_fields") from None
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
        name = row.name
        key_id = key_id.replace(":{serial}", "").replace("{serial}", "")
        try:
            cfg = V.check_config(row.vault_config)
            secret = decrypt_secrets(row.secret_encrypted)
            self._release_reads()  # Vault answers over the network: hold no transaction meanwhile
            # Vault back-dates by its role's not_before_duration (default 30 s): ask for the TTL less our skew, so
            # its whole window stays inside the TTL (checked below)
            text = V.sign(cfg, secret, public_key_line=public_key, principals=list(principals),
                          ttl_s=usable_s(ttl_s), key_id=key_id, source_addresses=list(addresses))
        except V.VaultError as exc:
            raise IssueError(f"SSH CA {name} (Vault): {exc}", "vault_error") from None
        now = now or utcnow()
        facts = self.check_returned(text, principals=principals, addresses=addresses, subject_blob=subject_blob,
                                    ttl_s=ttl_s, now=now)
        self._lock_active()  # still the lineage's active CA now that Vault answered (a revoke waits for this mint)
        valid_after = _dt.datetime.fromtimestamp(facts.valid_after, _dt.timezone.utc).replace(tzinfo=None)
        valid_before = _dt.datetime.fromtimestamp(facts.valid_before, _dt.timezone.utc).replace(tzinfo=None)
        record = self._record(serial=facts.serial, key_id=facts.key_id, principals=principals, addresses=addresses,
                              valid_after=valid_after, valid_before=valid_before, subject_blob=subject_blob,
                              node_id=node_id, job_id=job_id, source_id=source_id, via=via, now=now)
        return IssuedCert(text, facts.serial, facts.key_id, principals, valid_after, valid_before, record.id)

    def check_returned(self, text: str, *, principals: tuple[str, ...], addresses: tuple[str, ...],
                       subject_blob: bytes, ttl_s: int, now: _dt.datetime) -> C.CertFacts:
        """Vault's answer is not trusted blindly: same CA key, a user certificate for our node key, exactly our
        principals, inside the requested validity (whole window at most the TTL), our source-address, and no
        extensions."""
        name = self.row.name
        try:
            facts = C.read_cert(text)
        except C.CertError as exc:
            raise IssueError(f"SSH CA {name} (Vault) returned an invalid certificate: {exc}", "vault_refused") from None
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
        if (facts.valid_before > epoch + usable_s(ttl_s) + VAULT_TTL_SLACK_S or facts.valid_before <= epoch
                or facts.valid_before - facts.valid_after > ttl_s):
            problems.append("its validity is not the one requested (the whole window must fit in the TTL; keep the "
                            f"role's not_before_duration at {skew_s(ttl_s)} s or less)")
        if addresses and facts.critical_options.get("source-address") != ",".join(addresses):
            problems.append("it has no source-address restriction (allow source-address in the role's "
                            "allowed_critical_options)")
        if set(facts.critical_options) - {"source-address"}:
            problems.append("it carries critical options that were not requested")
        if facts.extensions:
            problems.append("it carries extensions (set default_extensions to {} on the role)")
        if problems:
            raise IssueError(f"SSH CA {name} (Vault) returned a certificate that was refused: {'; '.join(problems)}",
                             "vault_refused")
        return facts


PROVIDERS: dict[str, type[_Base]] = {"builtin": BuiltinCA, "vault": VaultCA}


def authority_for(session: Session, row: CbomSshCa, *, release: Callable[[], None] | None = None) -> BuiltinCA | VaultCA:
    """The signer for a CA row; a provider this code does not know (e.g. a future customer-held CA, #61) is refused,
    never signed as builtin by accident.  ``release``: see ``_Base``."""
    cls = PROVIDERS.get(row.provider or "")
    if cls is None:
        raise IssueError(f"SSH CA {row.name}: provider {str(row.provider)[:32]!r} cannot sign here", "unknown_provider")
    return cls(session, row, release=release)  # type: ignore[return-value]


def ca_for(session: Session, team_id: int, ca_id: int) -> CertificateAuthority:
    """The CA object for a CA row of this team (``IssueError`` when it is missing or another team's)."""
    row = session.get(CbomSshCa, ca_id)
    if row is None or row.team_id != team_id:
        raise IssueError("SSH CA not found in this team", "ca_not_found")
    return authority_for(session, row)
