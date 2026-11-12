"""Tables of the SSH certificate authority (F1 contract, section 2; migration ``r6f14sshca001``).

Rules shared with the other CBOM tables (``backend/new_models.py``): every row carries ``team_id`` and every query
filters on it; times are naive UTC; ``row_version`` is bumped on every write.  Private keys are stored only wrapped
(``keywrap``), Vault credentials only as ``secret_encrypted`` (Fernet JSON, ``crypto.encrypt_secrets``); neither is
ever serialised to a browser or written to a log.

``cbomsshcertissued.ca_id`` is a plain int, not a foreign key: the certificate audit is kept 13 months (contract,
open question 8; ``retention.py``) whatever happens to the CA row.

Serials of builtin CAs come from the PostgreSQL SEQUENCE ``cbomsshca_serial_seq`` (contract §3, amended 2026-11-12);
``serial_next`` is used only where there are no sequences (SQLite in unit tests).

The trust bundle servers fetch (``trust.py``, routes ``/cbom/ssh-ca-trust/*``): ``cbomsshcatrust`` (one row per team:
the trust and revocation generations), ``cbomsshcatrusttoken`` (revocable read-only distribution tokens, SHA-256
only) and ``cbomsshcatrustfetch`` (which generation each fetcher last received, for promote readiness).

Alembic sees these tables because ``prod_database_migrations/migrations/env.py`` imports this module
(``test_alembic_env_imports_every_table_model``).
"""
from __future__ import annotations

import datetime

from sqlalchemy import BigInteger, Index, Sequence, Text, UniqueConstraint, column
from sqlmodel import JSON, Column, DateTime, Field, SQLModel

from backend.new_models import CbomScanNode, _cbom_utcnow

PROVIDERS = ("builtin", "vault")
KEY_ALGS = ("ed25519", "ecdsa-p256")
KEY_WRAPS = ("fernet", "aws_kms")
STATES = ("next", "active", "retired", "revoked")
MIN_TTL_S = 60
MAX_TTL_S = 3600
DEFAULT_TTL_S = 300

# serials of builtin CAs (PostgreSQL); created by create_all and by migration r6f14sshca002
SERIAL_SEQUENCE = Sequence("cbomsshca_serial_seq", start=1, metadata=SQLModel.metadata)
# the key-reuse check (issue.py): equality lookups on the node's public key; hash, because the column holds up to
# 8 KB and a btree entry is limited to about 2.7 KB
Index("ix_cbomscannode_ssh_public_key", CbomScanNode.__table__.c.ssh_public_key, postgresql_using="hash")  # type: ignore[attr-defined]


class CbomSshCa(SQLModel, table=True):
    """One CA key.  A lineage is the root CA and every CA rotated from it (``lineage_id`` = the root's id); sources
    and credentials point at a lineage, and its ``active`` row signs."""
    __tablename__ = "cbomsshca"
    id: int | None = Field(default=None, primary_key=True)
    team_id: int = Field(foreign_key="team.id", index=True, ondelete="CASCADE")
    owner_user_id: int
    updated_by_user_id: int | None = Field(default=None)
    name: str = Field(max_length=64)
    provider: str = Field(default="builtin", max_length=16)  # builtin | vault
    key_alg: str = Field(default="ed25519", max_length=16)  # ed25519 | ecdsa-p256 (vault: what its key is)
    public_key: str = Field(sa_type=Text)  # the CA's OpenSSH public key line (TrustedUserCAKeys)
    fingerprint: str = Field(max_length=64)  # SHA256:<base64> of the public key blob
    private_key_encrypted: str | None = Field(default=None, sa_type=Text)  # builtin only; wrapped (keywrap)
    key_wrap: str | None = Field(default=None, max_length=16)  # fernet | aws_kms (builtin only)
    kms_key_ref: str | None = Field(default=None, max_length=2048)  # the KMS key ARN (aws_kms only)
    vault_config: dict | None = Field(default_factory=dict, sa_column=Column(JSON))  # addr, mount, role, namespace, ca_pem
    secret_encrypted: str | None = Field(default=None, sa_type=Text)  # vault token or AppRole (Fernet JSON)
    secret_fields: list | None = Field(default_factory=list, sa_column=Column(JSON))
    state: str = Field(default="active", max_length=16)  # next | active | retired | revoked
    default_ttl_s: int = Field(default=DEFAULT_TTL_S)
    serial_next: int = Field(default=1, sa_type=BigInteger)  # SQLite only (PostgreSQL: cbomsshca_serial_seq)
    rotated_from_id: int | None = Field(default=None)
    trust_generation: int | None = Field(default=None, sa_type=BigInteger)  # the team's trust generation that added it
    lineage_id: int | None = Field(default=None, index=True)  # root CA id; None on the root itself until flushed
    retired_at: datetime.datetime | None = Field(default=None, sa_type=DateTime)
    revoked_at: datetime.datetime | None = Field(default=None, sa_type=DateTime)
    revoked_reason: str | None = Field(default=None, max_length=512)
    row_version: int = Field(default=1)
    created_at: datetime.datetime | None = Field(default_factory=_cbom_utcnow, sa_type=DateTime)
    last_updated: datetime.datetime | None = Field(default_factory=_cbom_utcnow, sa_type=DateTime)


class CbomSshCertIssued(SQLModel, table=True):
    """One row per certificate the CA issued, written in the same transaction as the signature (the audit log)."""
    __tablename__ = "cbomsshcertissued"
    __table_args__ = (
        UniqueConstraint("ca_id", "serial", name="uq_cbomsshcertissued_ca_serial"),  # also serves ca_id lookups
        Index("ix_cbomsshcertissued_team_issued", "team_id", "issued_at"),  # retention (per team)
        Index("ix_cbomsshcertissued_team_job", "team_id", "job_id"),  # the job's newest certificate
        Index("ix_cbomsshcertissued_team_id_id", "team_id", "id"),  # the audit list, newest first
        Index("ix_cbomsshcertissued_team_node_id", "team_id", "node_id", "id"),  # ?node_id=
        Index("ix_cbomsshcertissued_team_ca_id", "team_id", "ca_id", "id"),  # ?ca_id=
        Index("ix_cbomsshcertissued_revoked", "team_id", "valid_before",  # the KRL
              postgresql_where=column("revoked_at").isnot(None), sqlite_where=column("revoked_at").isnot(None)),
    )
    id: int | None = Field(default=None, primary_key=True)
    team_id: int = Field(foreign_key="team.id", ondelete="CASCADE")
    ca_id: int
    serial: int = Field(sa_type=BigInteger)
    key_id: str = Field(max_length=255)
    principals: list | None = Field(default_factory=list, sa_column=Column(JSON))
    source_addresses: list | None = Field(default_factory=list, sa_column=Column(JSON))
    valid_after: datetime.datetime = Field(sa_type=DateTime)
    valid_before: datetime.datetime = Field(sa_type=DateTime)
    cert_public_key_sha256: str = Field(max_length=64)  # hex SHA-256 of the certified (node) public key blob
    node_id: int | None = Field(default=None)
    job_id: int | None = Field(default=None)
    source_id: int | None = Field(default=None)
    via: str = Field(default="claim", max_length=16)  # claim | refresh
    issued_at: datetime.datetime = Field(default_factory=_cbom_utcnow, sa_type=DateTime)
    revoked_at: datetime.datetime | None = Field(default=None, sa_type=DateTime)
    revoked_reason: str | None = Field(default=None, max_length=512)
    row_version: int = Field(default=1)
    created_at: datetime.datetime | None = Field(default_factory=_cbom_utcnow, sa_type=DateTime)
    last_updated: datetime.datetime | None = Field(default_factory=_cbom_utcnow, sa_type=DateTime)


class CbomSshCaTrust(SQLModel, table=True):
    """One row per team: ``trust_generation`` moves on every change of what servers must trust (CA created, rotated,
    promoted or revoked; certificate revoked), ``revocation_generation`` on every revocation (the KRL's version)."""
    __tablename__ = "cbomsshcatrust"
    id: int | None = Field(default=None, primary_key=True)
    team_id: int = Field(foreign_key="team.id", unique=True, index=True, ondelete="CASCADE")
    trust_generation: int = Field(default=0, sa_type=BigInteger)
    revocation_generation: int = Field(default=0, sa_type=BigInteger)
    trust_changed_at: datetime.datetime | None = Field(default=None, sa_type=DateTime)
    revocation_changed_at: datetime.datetime | None = Field(default=None, sa_type=DateTime)
    row_version: int = Field(default=1)
    created_at: datetime.datetime | None = Field(default_factory=_cbom_utcnow, sa_type=DateTime)
    last_updated: datetime.datetime | None = Field(default_factory=_cbom_utcnow, sa_type=DateTime)


class CbomSshCaTrustToken(SQLModel, table=True):
    """A read-only distribution token for the trust bundle (``zst_…``): shown once, stored as SHA-256, revocable.  It
    reads public keys, the KRL and principals of its team, nothing else."""
    __tablename__ = "cbomsshcatrusttoken"
    id: int | None = Field(default=None, primary_key=True)
    team_id: int = Field(foreign_key="team.id", index=True, ondelete="CASCADE")
    name: str = Field(max_length=64)
    token_hash: str = Field(max_length=64, unique=True, index=True)
    prefix: str = Field(max_length=12)
    created_by_user_id: int
    last_used_at: datetime.datetime | None = Field(default=None, sa_type=DateTime)
    revoked_at: datetime.datetime | None = Field(default=None, sa_type=DateTime)
    revoked_by_user_id: int | None = Field(default=None)
    row_version: int = Field(default=1)
    created_at: datetime.datetime | None = Field(default_factory=_cbom_utcnow, sa_type=DateTime)
    last_updated: datetime.datetime | None = Field(default_factory=_cbom_utcnow, sa_type=DateTime)


class CbomSshCaTrustFetch(SQLModel, table=True):
    """What one fetcher (a server, or the configuration-management host that installs the files) last received."""
    __tablename__ = "cbomsshcatrustfetch"
    __table_args__ = (
        UniqueConstraint("token_id", "fetcher", name="uq_cbomsshcatrustfetch_token_fetcher"),
        Index("ix_cbomsshcatrustfetch_team_seen", "team_id", "last_fetch_at"),
    )
    id: int | None = Field(default=None, primary_key=True)
    team_id: int = Field(foreign_key="team.id", ondelete="CASCADE")
    token_id: int
    fetcher: str = Field(max_length=128)
    trust_generation: int | None = Field(default=None, sa_type=BigInteger)
    revocation_generation: int | None = Field(default=None, sa_type=BigInteger)
    first_fetch_at: datetime.datetime = Field(default_factory=_cbom_utcnow, sa_type=DateTime)
    last_fetch_at: datetime.datetime = Field(default_factory=_cbom_utcnow, sa_type=DateTime)
    last_ip: str | None = Field(default=None, max_length=64)
    row_version: int = Field(default=1)
    created_at: datetime.datetime | None = Field(default_factory=_cbom_utcnow, sa_type=DateTime)
    last_updated: datetime.datetime | None = Field(default_factory=_cbom_utcnow, sa_type=DateTime)
