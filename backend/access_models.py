"""Tables of the F4 access-management track (RBAC audit log; SSO and SCIM follow in their own PRs).

Kept out of ``new_models.py`` so parallel tracks do not edit the same lines; ``new_models`` imports this module at
its end, so ``SQLModel.metadata`` (alembic, ``create_all`` in tests) sees these tables with the others.
Rules as in new_models' CBOM block: times are naive UTC, user and team references are plain ints (no foreign key,
nothing here ever blocks deleting a team or an account).
"""
import datetime
from typing import Dict

from sqlalchemy import Index as _SaIndex
from sqlalchemy import CheckConstraint, Text, UniqueConstraint
from sqlmodel import JSON, Column, DateTime, Field, SQLModel

__all__ = ["AuditEvent", "TeamSsoConfig", "TeamSsoDomain", "SsoLoginState", "SsoAssertionSeen", "SsoHandoff"]


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


# ========================================= SSO (F4 PR 2) =========================================
SSO_PROTOCOLS = ("oidc", "saml")


class TeamSsoConfig(SQLModel, table=True):
    """One team's identity provider (OIDC or SAML).  Owners change it (team.sso.manage).  The OIDC client secret
    lives only in ``oidc_secret_encrypted`` (Fernet, cbom_sources.crypto) and is never returned."""
    __tablename__ = "teamssoconfig"
    __table_args__ = (CheckConstraint("protocol IN ('oidc', 'saml')", name="ck_teamssoconfig_protocol"),
                      CheckConstraint("default_role IN ('viewer', 'member')", name="ck_teamssoconfig_default_role"))
    id: int | None = Field(default=None, primary_key=True)
    team_id: int = Field(index=True, unique=True)
    protocol: str = Field(default="oidc", max_length=8)  # oidc | saml
    enabled: bool = Field(default=False)
    enforced: bool = Field(default=False)  # password sign-in refused for the verified domains (owners: break-glass)
    jit: bool = Field(default=True)  # create the account / membership on first sign-in
    default_role: str = Field(default="member", max_length=16)  # viewer | member
    oidc_issuer: str | None = Field(default=None, max_length=512)
    oidc_client_id: str | None = Field(default=None, max_length=256)
    oidc_secret_encrypted: str | None = Field(default=None, sa_type=Text)
    oidc_scopes: str = Field(default="openid email profile", max_length=256)
    saml_idp_entity_id: str | None = Field(default=None, max_length=512)
    saml_idp_sso_url: str | None = Field(default=None, max_length=1024)
    saml_idp_certs: list | None = Field(default_factory=list, sa_column=Column(JSON))  # PEM strings
    updated_by_user_id: int | None = Field(default=None)
    row_version: int = Field(default=1)
    created_at: datetime.datetime = Field(default_factory=_utcnow, sa_type=DateTime)
    last_updated: datetime.datetime = Field(default_factory=_utcnow, sa_type=DateTime)


class TeamSsoDomain(SQLModel, table=True):
    """An email domain a team claims for SSO.  Verified by a DNS TXT record (or by a superuser, audited); a
    domain is verified for at most one team (partial unique index ``uq_teamssodomain_verified``)."""
    __tablename__ = "teamssodomain"
    __table_args__ = (UniqueConstraint("team_id", "domain", name="uq_teamssodomain_team_domain"),)
    id: int | None = Field(default=None, primary_key=True)
    team_id: int = Field(index=True)
    domain: str = Field(max_length=253, index=True)
    verification_token: str = Field(max_length=64)
    verified_at: datetime.datetime | None = Field(default=None, sa_type=DateTime)
    verified_by_user_id: int | None = Field(default=None)
    verify_method: str | None = Field(default=None, max_length=16)  # dns | superuser
    created_at: datetime.datetime = Field(default_factory=_utcnow, sa_type=DateTime)


_SaIndex("uq_teamssodomain_verified", TeamSsoDomain.domain, unique=True,
         sqlite_where=TeamSsoDomain.verified_at.isnot(None), postgresql_where=TeamSsoDomain.verified_at.isnot(None))


class SsoLoginState(SQLModel, table=True):
    """One browser's sign-in round trip (10 minutes, single use).  ``id`` is the OIDC ``state`` / SAML RelayState;
    the browser also holds a random cookie whose SHA-256 is ``binding_hash`` (login CSRF), and the SPA a random
    value whose SHA-256 is ``client_nonce_hash`` (it must show it to exchange the result for tokens)."""
    __tablename__ = "ssologinstate"
    id: str = Field(primary_key=True, max_length=64)
    team_id: int = Field(index=True)
    protocol: str = Field(max_length=8)
    binding_hash: str = Field(max_length=64)
    client_nonce_hash: str = Field(max_length=64)
    nonce: str | None = Field(default=None, max_length=128)  # OIDC
    pkce_verifier: str | None = Field(default=None, max_length=128)  # OIDC
    saml_request_id: str | None = Field(default=None, max_length=64)  # SAML
    redirect_path: str = Field(default="/home", max_length=512)
    created_at: datetime.datetime = Field(default_factory=_utcnow, sa_type=DateTime)
    expires_at: datetime.datetime = Field(sa_type=DateTime, index=True)
    used_at: datetime.datetime | None = Field(default=None, sa_type=DateTime)


class SsoAssertionSeen(SQLModel, table=True):
    """SAML assertion ids already used (replay protection), kept until the assertion expires."""
    __tablename__ = "ssoassertionseen"
    key: str = Field(primary_key=True, max_length=64)  # SHA-256 of team id, IdP entity id and assertion ID
    team_id: int = Field(index=True)
    expires_at: datetime.datetime = Field(sa_type=DateTime, index=True)


class SsoHandoff(SQLModel, table=True):
    """The result of a successful SSO sign-in, waiting (60 s, once) for the SPA that started it to exchange it for
    tokens.  Only the code's SHA-256 is stored; tokens never travel in a URL."""
    __tablename__ = "ssohandoff"
    code_hash: str = Field(primary_key=True, max_length=64)
    user_id: int
    team_id: int
    client_nonce_hash: str = Field(max_length=64)
    redirect_path: str = Field(default="/home", max_length=512)
    protocol: str = Field(max_length=8)
    expires_at: datetime.datetime = Field(sa_type=DateTime, index=True)
    used_at: datetime.datetime | None = Field(default=None, sa_type=DateTime)
