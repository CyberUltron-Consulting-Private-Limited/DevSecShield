"""Tables of the F4 access-management track (RBAC audit log; SSO and SCIM follow in their own PRs).

Kept out of ``new_models.py`` so parallel tracks do not edit the same lines; ``new_models`` imports this module at
its end, so ``SQLModel.metadata`` (alembic, ``create_all`` in tests) sees these tables with the others.
Rules as in new_models' CBOM block: times are naive UTC, user and team references are plain ints (no foreign key,
nothing here ever blocks deleting a team or an account).
"""
import datetime
from typing import Dict

from sqlmodel import JSON, Column, DateTime, Field, SQLModel

__all__ = ["AuditEvent"]


def _utcnow() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)


class AuditEvent(SQLModel, table=True):
    """Append-only: who did what, to which object, from which address, when (backend/utilities/rbac/audit.py).

    Rows are never updated or deleted: the ORM refuses it, and on PostgreSQL triggers refuse UPDATE, DELETE and
    TRUNCATE (migration r6f4rbac001).  ``hash`` chains every row to the one before it (SHA-256 over ``prev_hash``
    and the row), so a row changed or removed behind the application's back shows up in GET /admin/audit/verify.
    ``team_id`` and the actor are plain ints: the trail outlives the team and the account.  ``details`` holds
    names and old -> new roles, never a secret."""
    __tablename__ = "auditevent"
    id: int | None = Field(default=None, primary_key=True)
    at: datetime.datetime = Field(default_factory=_utcnow, sa_type=DateTime, index=True)  # naive UTC
    team_id: int | None = Field(default=None, index=True)
    actor_user_id: int | None = Field(default=None, index=True)
    actor_email: str | None = Field(default=None, max_length=254)
    actor_type: str = Field(default="user", max_length=16)  # user | superuser | scim | sso | system | anonymous
    action: str = Field(max_length=64, index=True)  # a permission name, or a domain event such as team.members.role
    object_type: str | None = Field(default=None, max_length=32)
    object_id: str | None = Field(default=None, max_length=128)
    outcome: str = Field(default="success", max_length=16)  # success | denied
    ip: str | None = Field(default=None, max_length=64)
    user_agent: str | None = Field(default=None, max_length=200)
    details: Dict | None = Field(default_factory=dict, sa_column=Column(JSON))
    prev_hash: str = Field(default="", max_length=64)
    hash: str = Field(max_length=64)
