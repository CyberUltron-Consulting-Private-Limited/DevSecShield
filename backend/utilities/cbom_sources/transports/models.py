"""F1.3 tables (contract section 2): a team's transports, and the deployment's verified zs-collect releases.

* ``cbomtransport``: one customer control plane (AWX/AAP job template, salt-api, an AWS SSM run-command role) that
  fleet sources of kind ``awx_hosts`` / ``salt_hosts`` / ``ssm_hosts`` collect through.  Secrets (AWX token, salt-api
  login) only as ``secret_encrypted`` (Fernet, ``crypto.encrypt_secrets``), never returned; soft-deleted.
* ``cbomzscollectrelease``: a zs-collect release whose manifest signature was verified against the release key when
  it was imported.  ``team_id`` NULL is deployment-wide (this one table has no team foreign key); one is active.
No foreign keys to other parts' tables (contract section 2).
"""
from __future__ import annotations

import datetime
from typing import Dict

from sqlalchemy import JSON, Column, Text, UniqueConstraint
from sqlmodel import Field, SQLModel

from backend.new_models import _cbom_utcnow

TRANSPORT_KINDS = ("awx", "salt", "ssm")


class CbomTransport(SQLModel, table=True):
    __tablename__ = "cbomtransport"
    id: int | None = Field(default=None, primary_key=True)
    team_id: int = Field(foreign_key="team.id", index=True, ondelete="CASCADE")
    kind: str = Field(max_length=16)
    name: str = Field(max_length=64)
    name_lower: str = Field(max_length=64)
    enabled: bool = Field(default=True)
    config: Dict | None = Field(default_factory=dict, sa_column=Column(JSON))
    secret_encrypted: str | None = Field(default=None, sa_type=Text)
    secret_fields: list | None = Field(default_factory=list, sa_column=Column(JSON))
    last_validated_at: datetime.datetime | None = Field(default=None)
    last_validation_status: str = Field(default="never", max_length=16)
    last_validation_summary: str | None = Field(default=None, max_length=512)
    owner_user_id: int
    updated_by_user_id: int | None = Field(default=None)
    row_version: int = Field(default=1)
    created_at: datetime.datetime | None = Field(default_factory=_cbom_utcnow)
    last_updated: datetime.datetime | None = Field(default_factory=_cbom_utcnow)
    deleted_at: datetime.datetime | None = Field(default=None)


class CbomZsCollectRelease(SQLModel, table=True):
    __tablename__ = "cbomzscollectrelease"
    __table_args__ = (UniqueConstraint("version", name="uq_cbomzscollectrelease_version"),)
    id: int | None = Field(default=None, primary_key=True)
    team_id: int | None = Field(default=None, index=True)  # NULL: deployment-wide (no foreign key, by design)
    version: str = Field(max_length=40)
    manifest: Dict | None = Field(default_factory=dict, sa_column=Column(JSON))
    manifest_raw: str = Field(sa_type=Text)  # the exact signed bytes (canonical JSON), for re-verification
    manifest_sig: str = Field(max_length=200)
    sha256_amd64: str | None = Field(default=None, max_length=64)
    sha256_arm64: str | None = Field(default=None, max_length=64)
    key_fingerprint: str = Field(max_length=80)
    verified_at: datetime.datetime | None = Field(default=None)
    active: bool = Field(default=False, index=True)
    row_version: int = Field(default=1)
    created_at: datetime.datetime | None = Field(default_factory=_cbom_utcnow)
    last_updated: datetime.datetime | None = Field(default_factory=_cbom_utcnow)
