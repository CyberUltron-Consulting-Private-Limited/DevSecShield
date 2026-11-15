"""Tables of code repositories at scale (F3), in their own module (registered on ``SQLModel.metadata`` by the import
block at the end of ``backend/new_models.py``, so alembic and every importer of new_models see them).

Org-level SCM connections, the repository inventory they discover, scan policies per repository group, runs, the
bounded fair queue of repository scans and the cross-repository roll-up of their findings. Rules (as for the CBOM
Sources models): every row carries ``team_id`` (``ON DELETE CASCADE``, so a deleted team takes its rows with it),
times are naive UTC, user and scan references are plain ints, secrets live only in ``*_encrypted`` columns (Fernet)
and are never serialised, ``row_version`` guards edits of what people edit.
"""
from __future__ import annotations

import datetime
from typing import Dict

from sqlalchemy import Index, Text, UniqueConstraint
from sqlmodel import JSON, Column, DateTime, Field, SQLModel


def _utcnow() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)


class ScmConnection(SQLModel, table=True):
    """A GitHub organisation / user / App installation, a GitLab group or a Bitbucket workspace, with its credential."""
    __tablename__ = "scmconnection"
    __table_args__ = (UniqueConstraint("team_id", "name_lower", name="uq_scmconnection_team_name"),)
    id: int | None = Field(default=None, primary_key=True)
    team_id: int = Field(foreign_key="team.id", index=True, ondelete="CASCADE")
    owner_user_id: int
    updated_by_user_id: int | None = Field(default=None)
    provider: str = Field(max_length=16)  # github | gitlab | bitbucket
    auth_kind: str = Field(max_length=16)  # github_app | token
    name: str = Field(max_length=64)
    name_lower: str = Field(max_length=64)
    api_base: str = Field(max_length=255)
    scope_kind: str = Field(max_length=16)  # installation | org | user | group | workspace
    scope_name: str = Field(default="", max_length=255)
    config: Dict | None = Field(default_factory=dict, sa_column=Column(JSON))  # app_id, installation_id, subgroups
    filters: Dict | None = Field(default_factory=dict, sa_column=Column(JSON))  # import filters (scm/filters.py)
    secret_encrypted: str | None = Field(default=None, sa_type=Text)
    secret_fields: list | None = Field(default_factory=list, sa_column=Column(JSON))
    webhook_uid: str = Field(max_length=32, unique=True, index=True)  # public route key, not a secret
    webhook_secret_encrypted: str | None = Field(default=None, sa_type=Text)
    enabled: bool = Field(default=True)
    sync_interval_min: int = Field(default=360)
    sync_status: str = Field(default="never", max_length=16)  # never | queued | running | ok | partial | failed
    sync_lease_until: datetime.datetime | None = Field(default=None, sa_type=DateTime)
    sync_requested_at: datetime.datetime | None = Field(default=None, sa_type=DateTime)
    last_sync_at: datetime.datetime | None = Field(default=None, sa_type=DateTime)
    next_sync_at: datetime.datetime | None = Field(default=None, sa_type=DateTime, index=True)
    last_sync_summary: Dict | None = Field(default_factory=dict, sa_column=Column(JSON))
    last_sync_error: str | None = Field(default=None, max_length=512)
    last_test_status: str = Field(default="never", max_length=16)
    last_test_at: datetime.datetime | None = Field(default=None, sa_type=DateTime)
    last_test_message: str | None = Field(default=None, max_length=255)
    row_version: int = Field(default=1)
    created_at: datetime.datetime | None = Field(default_factory=_utcnow, sa_type=DateTime)
    last_updated: datetime.datetime | None = Field(default_factory=_utcnow, sa_type=DateTime)


class ScmRepository(SQLModel, table=True):
    """One repository a connection discovered. Keyed on the provider's stable id, so a rename updates the row."""
    __tablename__ = "scmrepository"
    __table_args__ = (UniqueConstraint("connection_id", "external_id", name="uq_scmrepository_connection_external"),)
    id: int | None = Field(default=None, primary_key=True)
    team_id: int = Field(foreign_key="team.id", index=True, ondelete="CASCADE")
    connection_id: int = Field(foreign_key="scmconnection.id", index=True, ondelete="CASCADE")
    external_id: str = Field(max_length=64)
    full_name: str = Field(max_length=255, index=True)
    name: str = Field(max_length=255)
    owner: str = Field(default="", max_length=255)
    web_url: str = Field(default="", max_length=512)
    clone_url: str = Field(default="", max_length=512)
    default_branch: str = Field(default="main", max_length=255)
    visibility: str = Field(default="private", max_length=16)
    archived: bool = Field(default=False)
    fork: bool = Field(default=False)
    language: str | None = Field(default=None, max_length=64)
    topics: list | None = Field(default_factory=list, sa_column=Column(JSON))
    size_kb: int = Field(default=0)
    pushed_at: datetime.datetime | None = Field(default=None, sa_type=DateTime)
    in_scope: bool = Field(default=False, index=True)
    scope_reason: str = Field(default="", max_length=64)
    manual_state: str | None = Field(default=None, max_length=8)  # include | exclude (wins over the filters)
    policy_id: int | None = Field(default=None)  # pinned policy (wins over policy selectors)
    first_seen_at: datetime.datetime | None = Field(default_factory=_utcnow, sa_type=DateTime)
    last_seen_at: datetime.datetime | None = Field(default_factory=_utcnow, sa_type=DateTime)
    removed_at: datetime.datetime | None = Field(default=None, sa_type=DateTime)
    last_scan_at: datetime.datetime | None = Field(default=None, sa_type=DateTime)
    last_scan_summary: Dict | None = Field(default_factory=dict, sa_column=Column(JSON))  # per product
    row_version: int = Field(default=1)
    created_at: datetime.datetime | None = Field(default_factory=_utcnow, sa_type=DateTime)
    last_updated: datetime.datetime | None = Field(default_factory=_utcnow, sa_type=DateTime)


class ScmScanPolicy(SQLModel, table=True):
    """Which products scan a group of repositories, on which branch, on a schedule and/or on every push."""
    __tablename__ = "scmscanpolicy"
    __table_args__ = (UniqueConstraint("team_id", "name_lower", name="uq_scmscanpolicy_team_name"),)
    id: int | None = Field(default=None, primary_key=True)
    team_id: int = Field(foreign_key="team.id", index=True, ondelete="CASCADE")
    owner_user_id: int  # scans it starts are this member's
    updated_by_user_id: int | None = Field(default=None)
    name: str = Field(max_length=64)
    name_lower: str = Field(max_length=64)
    position: int = Field(default=100)  # evaluation order: (position, id); the first matching policy wins
    enabled: bool = Field(default=True)
    selector: Dict | None = Field(default_factory=dict, sa_column=Column(JSON))  # filters grammar
    products: list | None = Field(default_factory=list, sa_column=Column(JSON))
    branch: str = Field(default="", max_length=255)  # empty: each repository's default branch
    on_push: bool = Field(default=False)
    schedule: Dict | None = Field(default_factory=dict, sa_column=Column(JSON))
    options: Dict | None = Field(default_factory=dict, sa_column=Column(JSON))
    next_run_at: datetime.datetime | None = Field(default=None, sa_type=DateTime, index=True)
    last_fired_at: datetime.datetime | None = Field(default=None, sa_type=DateTime)
    last_run_id: int | None = Field(default=None)
    last_status: str | None = Field(default=None, max_length=16)  # queued | skipped
    last_message: str | None = Field(default=None, max_length=512)
    row_version: int = Field(default=1)
    created_at: datetime.datetime | None = Field(default_factory=_utcnow, sa_type=DateTime)
    last_updated: datetime.datetime | None = Field(default_factory=_utcnow, sa_type=DateTime)


class ScmScanRun(SQLModel, table=True):
    """One bulk run (manual, scheduled or a push): charged once, as a whole, when it is created."""
    __tablename__ = "scmscanrun"
    __table_args__ = (UniqueConstraint("team_id", "client_request_id", name="uq_scmscanrun_team_request"),)
    id: int | None = Field(default=None, primary_key=True)
    team_id: int = Field(foreign_key="team.id", index=True, ondelete="CASCADE")
    owner_user_id: int
    trigger: str = Field(max_length=16)  # manual | schedule | push
    policy_id: int | None = Field(default=None, index=True)
    client_request_id: str = Field(max_length=64)
    status: str = Field(default="queued", max_length=16)  # queued | running | done | cancelled
    totals: Dict | None = Field(default_factory=dict, sa_column=Column(JSON))
    credits_c: int = Field(default=0)  # charged, in hundredths of a credit
    refunded_c: int = Field(default=0)
    created_at: datetime.datetime | None = Field(default_factory=_utcnow, sa_type=DateTime)
    last_updated: datetime.datetime | None = Field(default_factory=_utcnow, sa_type=DateTime)
    finished_at: datetime.datetime | None = Field(default=None, sa_type=DateTime)


class ScmScanRequest(SQLModel, table=True):
    """The queue: one repository x product scan to run. ``dedupe_key`` makes enqueueing idempotent (webhook
    redeliveries, a slot fired twice); the dispatcher claims rows with a compare-and-set."""
    __tablename__ = "scmscanrequest"
    __table_args__ = (UniqueConstraint("team_id", "dedupe_key", name="uq_scmscanrequest_team_dedupe"),)
    id: int | None = Field(default=None, primary_key=True)
    team_id: int = Field(foreign_key="team.id", index=True, ondelete="CASCADE")
    run_id: int | None = Field(default=None, foreign_key="scmscanrun.id", index=True, ondelete="CASCADE")
    repo_id: int = Field(foreign_key="scmrepository.id", index=True, ondelete="CASCADE")
    owner_user_id: int
    product: str = Field(max_length=16)
    branch: str = Field(max_length=255)
    trigger: str = Field(max_length=16)
    priority: int = Field(default=2)  # 0 push, 1 manual, 2 schedule
    status: str = Field(default="queued", max_length=16, index=True)
    dedupe_key: str = Field(max_length=64)
    commit_sha: str | None = Field(default=None, max_length=64)
    credits_c: int = Field(default=0)
    refunded: bool = Field(default=False)
    scan_id: int | None = Field(default=None, index=True)
    task_id: str | None = Field(default=None, max_length=64)
    attempts: int = Field(default=0)
    error: str | None = Field(default=None, max_length=255)
    enqueued_at: datetime.datetime | None = Field(default_factory=_utcnow, sa_type=DateTime)
    dispatched_at: datetime.datetime | None = Field(default=None, sa_type=DateTime)
    finished_at: datetime.datetime | None = Field(default=None, sa_type=DateTime)


# the dispatcher's query: queued requests of a team in (priority, id) order
Index("ix_scmscanrequest_queue", ScmScanRequest.status, ScmScanRequest.team_id, ScmScanRequest.priority,
      ScmScanRequest.id)


class ScmFinding(SQLModel, table=True):
    """One issue across every repository it appears in (location-free fingerprint per product)."""
    __tablename__ = "scmfinding"
    __table_args__ = (UniqueConstraint("team_id", "product", "fingerprint", name="uq_scmfinding_team_product_fp"),)
    id: int | None = Field(default=None, primary_key=True)
    team_id: int = Field(foreign_key="team.id", index=True, ondelete="CASCADE")
    product: str = Field(max_length=16)
    fingerprint: str = Field(max_length=64)
    title: str = Field(max_length=255)
    severity: str = Field(default="low", max_length=16)
    key_fields: Dict | None = Field(default_factory=dict, sa_column=Column(JSON))
    repo_count: int = Field(default=0)
    occurrence_count: int = Field(default=0)
    first_seen_at: datetime.datetime | None = Field(default_factory=_utcnow, sa_type=DateTime)
    last_seen_at: datetime.datetime | None = Field(default_factory=_utcnow, sa_type=DateTime)
    resolved_at: datetime.datetime | None = Field(default=None, sa_type=DateTime)


class ScmFindingOccurrence(SQLModel, table=True):
    """Where one roll-up finding appears: one row per repository, from that repository's latest scan."""
    __tablename__ = "scmfindingoccurrence"
    __table_args__ = (UniqueConstraint("finding_id", "repo_id", name="uq_scmfindingoccurrence_finding_repo"),)
    id: int | None = Field(default=None, primary_key=True)
    team_id: int = Field(foreign_key="team.id", index=True, ondelete="CASCADE")
    finding_id: int = Field(foreign_key="scmfinding.id", index=True, ondelete="CASCADE")
    repo_id: int = Field(foreign_key="scmrepository.id", index=True, ondelete="CASCADE")
    product: str = Field(max_length=16)
    scan_id: int | None = Field(default=None)
    count: int = Field(default=1)
    locations: list | None = Field(default_factory=list, sa_column=Column(JSON))
    last_seen_at: datetime.datetime | None = Field(default_factory=_utcnow, sa_type=DateTime)


__all__ = ["ScmConnection", "ScmFinding", "ScmFindingOccurrence", "ScmRepository", "ScmScanPolicy", "ScmScanRequest",
           "ScmScanRun"]
