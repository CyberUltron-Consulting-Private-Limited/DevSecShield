"""Tables of F1.2 (contract section 2): inventory sources and targets, fleet policies, typed credentials.

Common rules (``backend/new_models.py`` CBOM block): every row has ``team_id`` (FK ``team.id`` ON DELETE CASCADE),
times are naive UTC, ``row_version`` makes a stale form a 409, secrets only as ``secret_encrypted`` +
``secret_fields`` (never returned).  References to another part's rows (transports, SSH CAs) and to collection
sources are plain ints validated in code, so the parts' migrations apply in any order.  Deletes are soft
(``deleted_at``): a decision that points at a deleted row says so instead of failing.
"""
from __future__ import annotations

import datetime
from typing import Dict

from sqlalchemy import Index, Text, UniqueConstraint
from sqlmodel import JSON, Column, DateTime, Field, SQLModel

from backend.new_models import _cbom_utcnow

TARGET_KINDS = ("linux_host", "windows_host", "database", "k8s_cluster", "load_balancer", "certificate", "kms_key",
                "secret", "other")
INVENTORY_KINDS = ("aws", "csv", "json", "api")
CREDENTIAL_TYPES = ("node_key", "password", "ssh_cert", "vault", "ssh_ca")


class CbomInventorySource(SQLModel, table=True):
    """Where targets come from: an AWS account read through its validated role, a CSV/JSON import, or the API."""
    __tablename__ = "cbominventorysource"
    id: int | None = Field(default=None, primary_key=True)
    team_id: int = Field(foreign_key="team.id", index=True, ondelete="CASCADE")
    owner_user_id: int | None = Field(default=None)
    updated_by_user_id: int | None = Field(default=None)
    kind: str = Field(max_length=8)  # aws | csv | json | api
    name: str = Field(max_length=64)
    config: Dict | None = Field(default_factory=dict, sa_column=Column(JSON))
    sync_every_min: int = Field(default=60)
    enabled: bool = Field(default=True)
    last_sync_at: datetime.datetime | None = Field(default=None, sa_type=DateTime)
    last_sync_status: str = Field(default="never", max_length=16)  # never | queued | running | ok | partial | failed
    last_sync_summary: Dict | None = Field(default_factory=dict, sa_column=Column(JSON))
    coverage: Dict | None = Field(default_factory=dict, sa_column=Column(JSON))
    lease_until: datetime.datetime | None = Field(default=None, sa_type=DateTime)
    deleted_at: datetime.datetime | None = Field(default=None, sa_type=DateTime)
    row_version: int = Field(default=1)
    created_at: datetime.datetime | None = Field(default_factory=_cbom_utcnow, sa_type=DateTime)
    last_updated: datetime.datetime | None = Field(default_factory=_cbom_utcnow, sa_type=DateTime)


class CbomInventoryTarget(SQLModel, table=True):
    """One discovered or imported host, database, cluster, load balancer, certificate, key or secret.

    ``external_id`` is unique per team (AWS: the resource ARN); ``fingerprint`` is the SHA-256 of the normalised
    target, so a re-import that changes nothing writes nothing but ``last_seen_at``.  ``inventory_source_id`` is its
    one owner (the first source that listed it, until a person deletes it or its owner stops listing it).

    ``decision`` is the policy engine's Decision, kept current by imports, syncs and the team's evaluation
    (``fleet/evaluate.py``); ``decision_action`` / ``decision_policy_id`` repeat its two fields that lists filter and
    count on, indexed.  ``deleted_at``: a person removed it from the inventory (never collected, unlike a target a
    sync merely missed); ``pending_since``: its managed-source change waits for a busy source.
    ``managed_source_id`` is the managed collection source (sticky batch) it is assigned to."""
    __tablename__ = "cbominventorytarget"
    __table_args__ = (
        UniqueConstraint("team_id", "external_id", name="uq_cbominventorytarget_team_external"),
        Index("ix_cbominventorytarget_team_id_id", "team_id", "id"),
        Index("ix_cbominventorytarget_team_source", "team_id", "inventory_source_id"),
        Index("ix_cbominventorytarget_team_kind", "team_id", "kind"),
        Index("ix_cbominventorytarget_team_managed", "team_id", "managed_source_id"),
        Index("ix_cbominventorytarget_team_action", "team_id", "decision_action"),
        Index("ix_cbominventorytarget_team_policy", "team_id", "decision_policy_id"),
    )
    id: int | None = Field(default=None, primary_key=True)
    team_id: int = Field(foreign_key="team.id", ondelete="CASCADE")
    inventory_source_id: int
    external_id: str = Field(max_length=255)
    kind: str = Field(max_length=24)
    address: str | None = Field(default=None, max_length=253)
    addresses: list | None = Field(default_factory=list, sa_column=Column(JSON))
    hostname: str | None = Field(default=None, max_length=253)
    tags: Dict | None = Field(default_factory=dict, sa_column=Column(JSON))
    account_id: str | None = Field(default=None, max_length=32)
    region: str | None = Field(default=None, max_length=32)
    platform: str | None = Field(default=None, max_length=64)
    handles: Dict | None = Field(default_factory=dict, sa_column=Column(JSON))
    attributes: Dict | None = Field(default_factory=dict, sa_column=Column(JSON))
    fingerprint: str = Field(max_length=64)
    first_seen_at: datetime.datetime | None = Field(default_factory=_cbom_utcnow, sa_type=DateTime)
    last_seen_at: datetime.datetime | None = Field(default_factory=_cbom_utcnow, sa_type=DateTime)
    missing_since: datetime.datetime | None = Field(default=None, sa_type=DateTime)
    decision: Dict | None = Field(default_factory=dict, sa_column=Column(JSON))
    decision_action: str | None = Field(default=None, max_length=16)
    decision_policy_id: int | None = Field(default=None)
    deleted_at: datetime.datetime | None = Field(default=None, sa_type=DateTime)
    pending_since: datetime.datetime | None = Field(default=None, sa_type=DateTime)
    managed_source_id: int | None = Field(default=None)
    row_version: int = Field(default=1)
    created_at: datetime.datetime | None = Field(default_factory=_cbom_utcnow, sa_type=DateTime)
    last_updated: datetime.datetime | None = Field(default_factory=_cbom_utcnow, sa_type=DateTime)


class CbomFleetPolicy(SQLModel, table=True):
    """A tag/kind selector and what to do with the targets it matches (collect how and when, or never scan)."""
    __tablename__ = "cbomfleetpolicy"
    id: int | None = Field(default=None, primary_key=True)
    team_id: int = Field(foreign_key="team.id", index=True, ondelete="CASCADE")
    name: str = Field(max_length=64)
    enabled: bool = Field(default=True)
    priority: int = Field(default=100)
    selector: Dict | None = Field(default_factory=dict, sa_column=Column(JSON))
    action: Dict | None = Field(default_factory=dict, sa_column=Column(JSON))
    owner_user_id: int | None = Field(default=None)
    updated_by_user_id: int | None = Field(default=None)
    deleted_at: datetime.datetime | None = Field(default=None, sa_type=DateTime)
    row_version: int = Field(default=1)
    created_at: datetime.datetime | None = Field(default_factory=_cbom_utcnow, sa_type=DateTime)
    last_updated: datetime.datetime | None = Field(default_factory=_cbom_utcnow, sa_type=DateTime)


class CbomCredential(SQLModel, table=True):
    """A typed login policies hand to managed sources: the same non-secret fields a Linux servers source has, and its
    secrets encrypted (write-only)."""
    __tablename__ = "cbomcredential"
    id: int | None = Field(default=None, primary_key=True)
    team_id: int = Field(foreign_key="team.id", index=True, ondelete="CASCADE")
    name: str = Field(max_length=64)
    credential_type: str = Field(max_length=16)
    config: Dict | None = Field(default_factory=dict, sa_column=Column(JSON))
    secret_encrypted: str | None = Field(default=None, sa_type=Text)
    secret_fields: list | None = Field(default_factory=list, sa_column=Column(JSON))
    owner_user_id: int | None = Field(default=None)
    updated_by_user_id: int | None = Field(default=None)
    deleted_at: datetime.datetime | None = Field(default=None, sa_type=DateTime)
    row_version: int = Field(default=1)
    created_at: datetime.datetime | None = Field(default_factory=_cbom_utcnow, sa_type=DateTime)
    last_updated: datetime.datetime | None = Field(default_factory=_cbom_utcnow, sa_type=DateTime)


class CbomFleetTeamState(SQLModel, table=True):
    """One row per team: what the last evaluation of its targets saw and found, and the work requested of the fleet
    worker.  ``inputs_digest`` hashes everything a decision depends on besides the target (policies, credentials, scan
    nodes, the never-scan list, the day for the 7-day rule): when it differs from the current inputs, the stored
    decisions and ``counts`` (policy id -> [matched, won]) are stale.  ``eval_requested_at`` /
    ``reconcile_requested_at`` are set by writes and cleared by the worker when the run that saw them ends (a later
    request survives the run)."""
    __tablename__ = "cbomfleetteamstate"
    id: int | None = Field(default=None, primary_key=True)
    team_id: int = Field(foreign_key="team.id", ondelete="CASCADE", unique=True)
    inputs_digest: str | None = Field(default=None, max_length=64)
    evaluated_at: datetime.datetime | None = Field(default=None, sa_type=DateTime)
    counts: Dict | None = Field(default_factory=dict, sa_column=Column(JSON))
    eval_requested_at: datetime.datetime | None = Field(default=None, sa_type=DateTime)
    reconcile_requested_at: datetime.datetime | None = Field(default=None, sa_type=DateTime)
    lease_until: datetime.datetime | None = Field(default=None, sa_type=DateTime)
    last_reconcile: Dict | None = Field(default_factory=dict, sa_column=Column(JSON))
    row_version: int = Field(default=1)
    created_at: datetime.datetime | None = Field(default_factory=_cbom_utcnow, sa_type=DateTime)
    last_updated: datetime.datetime | None = Field(default_factory=_cbom_utcnow, sa_type=DateTime)


FLEET_MODELS = (CbomInventoryTarget, CbomInventorySource, CbomFleetPolicy, CbomCredential, CbomFleetTeamState)
