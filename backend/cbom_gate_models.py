"""SOW S1 / S2 tables: the CBOM CI/CD gate policy of a team (or of one CI/CD integration), and the "Raise test ticket"
clicks of the Jira and ServiceNow integrations.

Kept out of ``new_models.py`` so parallel tracks do not edit the same lines; ``new_models`` imports this module at its
end (as it does ``branding_models``), so ``SQLModel.metadata`` (alembic, ``create_all`` in tests) sees the tables.
Times are naive UTC. User ids are plain ints (deleting an account never blocks).

* ``cbomgatepolicy``: one row per (team, scope). ``scope`` is ``team`` (the team's policy) or ``integration:<id>`` (an
  override for one CBOM CI/CD integration, ``integration_id`` set, removed with the integration). ``policy`` holds the
  normal form of ``utilities/cicd/gate_policy.validate_policy``. No row: the default policy applies.
* ``integrationtestticket``: one row per click (``click_id``, a UUID the browser makes per click), unique per team and
  kind, so a repeated or retried request returns the ticket of that click instead of raising a second one. The row
  keeps the ticket's key and link (acceptance evidence: "a test ticket raised successfully"), never a credential.
"""
import datetime

from sqlalchemy import JSON, UniqueConstraint
from sqlmodel import Column, DateTime, Field, SQLModel

__all__ = ["CbomGatePolicy", "IntegrationTestTicket"]


class CbomGatePolicy(SQLModel, table=True):
    __tablename__ = "cbomgatepolicy"
    __table_args__ = (UniqueConstraint("team_id", "scope", name="uq_cbomgatepolicy_team_scope"),)
    id: int | None = Field(default=None, primary_key=True)
    team_id: int = Field(foreign_key="team.id", index=True, ondelete="CASCADE")
    scope: str = Field(max_length=40)  # "team" | "integration:<id>"
    integration_id: int | None = Field(default=None, foreign_key="cicdintegration.id", ondelete="CASCADE")
    policy: dict = Field(default_factory=dict, sa_column=Column(JSON, nullable=False))
    row_version: int = Field(default=1)
    created_at: datetime.datetime = Field(sa_type=DateTime)
    updated_at: datetime.datetime = Field(sa_type=DateTime)
    updated_by_user_id: int | None = Field(default=None)


class IntegrationTestTicket(SQLModel, table=True):
    __tablename__ = "integrationtestticket"
    __table_args__ = (UniqueConstraint("team_id", "kind", "click_id", name="uq_integrationtestticket_click"),)
    id: int | None = Field(default=None, primary_key=True)
    team_id: int = Field(foreign_key="team.id", index=True, ondelete="CASCADE")
    kind: str = Field(max_length=16)  # "jira" | "servicenow"
    click_id: str = Field(max_length=36)
    status: str = Field(max_length=16)  # "pending" | "created" | "failed" | "uncertain"
    ticket_key: str | None = Field(default=None, max_length=64)
    ticket_url: str | None = Field(default=None, max_length=500)
    message: str | None = Field(default=None, max_length=255)
    created_at: datetime.datetime = Field(sa_type=DateTime)
    updated_at: datetime.datetime = Field(sa_type=DateTime)
    user_id: int | None = Field(default=None)
