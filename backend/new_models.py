import datetime
import uuid
from typing import Dict, Literal
from sqlmodel import JSON, Column, DateTime, Field, SQLModel, String, Relationship
from sqlalchemy import BigInteger, CheckConstraint, Integer, Text, UniqueConstraint
from sqlalchemy.types import TypeDecorator as _SaTypeDecorator
from sqlalchemy import BigInteger as _SaBigInteger, Index as _SaIndex, func as _sa_func, text as _sa_text
scan_types = Literal["sast", "llm", "mcp" , "iac" , "leakage" , "sbom_sca" , "agent_discovery", "dast", "cbom", "ai_bom"]



class VerificationCode(SQLModel,table=True):
    id : int | None = Field(default=None,primary_key=True)
    # one live code per (lower-cased) email: sending a new code replaces the old one
    email : str = Field(index=True, unique=True)
    code : str
    created_at : datetime.datetime | None= Field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc), sa_type=DateTime)
    expires_at : datetime.datetime | None= Field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=10), sa_type=DateTime)
    # wrong codes entered for this email since the code was sent; the code is deleted at the limit
    attempts : int = Field(default=0, sa_column_kwargs={"server_default": "0"})

    class Config:
        arbitrary_types_allowed = True


class AuthCounter(SQLModel,table=True):
    """Fixed-window counters that must hold across workers and replicas (e.g. codes sent per email)."""
    key : str = Field(primary_key=True, max_length=400)
    window_start : datetime.datetime = Field(sa_type=DateTime)
    hits : int = Field(default=0)



TEAM_ROLES = ("owner", "admin", "member", "viewer")  # the order and rules: backend/utilities/rbac/permissions.py


# every user is a member of the "default-team" by default when a user is created ⭐
class TeamMembership(SQLModel,table=True): # many-to-many relationship between team and user
    __table_args__ = (CheckConstraint("role IN ('owner', 'admin', 'member', 'viewer')", name="ck_teammembership_role"),)
    team_id : int | None = Field(default=None,foreign_key="team.id",primary_key=True)
    user_id : int | None = Field(default=None,foreign_key="user.id",primary_key=True)
    # owner > admin > member > viewer (F4 RBAC); what each may do: backend/utilities/rbac/permissions.py
    role : Literal["owner", "admin", "member", "viewer"] = Field(default="member",sa_type=String)

    team : "Team" = Relationship(back_populates="team_memberships")
    user : "User" = Relationship(back_populates="team_memberships")



class Team(SQLModel,table=True):
    id : int | None = Field(default=None,primary_key=True)
    name : str = Field(default="New Team")
    description : str | None = Field(default=None)
    created_at : datetime.datetime | None= Field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc), sa_type=DateTime)
    credit_balance : float = Field(default=0)
    integration_settings : Dict | None = Field(default_factory=dict,sa_column=Column(JSON)) 
    settings : Dict | None = Field(default_factory=dict,sa_column=Column(JSON))

    # many-to-many relationship between team and user
    team_memberships : list[TeamMembership] = Relationship(back_populates="team")

    # guardrails integrations that this team owns 
    guardrails_integrations : list["GuardrailsIntegration"] = Relationship(back_populates="team")

    # cicd integrations that this team owns 
    cicd_integrations : list["CicdIntegration"] = Relationship(back_populates="team")

    # scans that this team owns 
    scans : list["Scan"] = Relationship(back_populates="team")

    dast_profiles : list["DastScanProfile"] = Relationship(back_populates="team")

class User(SQLModel,table=True):
    id : int | None = Field(default=None,primary_key=True)
    email : str = Field(index=True)  # ix_user_email: every access check finds the token's account by its email (F4)
    password : str
    first_name : str | None
    last_name : str | None
    profile_photo : str | None
    session_active : bool | None = Field(default=False)
    last_active : datetime.datetime | None = Field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc), sa_type=DateTime)
    is_superuser : bool | None = Field(default=False)
    default_team_id : int | None = Field(default=None,foreign_key="team.id")
    # tokens carry the version they were issued at ("ver"); bumping it revokes every older token
    token_version : int = Field(default=0, sa_column_kwargs={"server_default": "0"})
    # set for accounts whose password somebody else chose and mailed (the old team-invitation flow): sign-in
    # then asks for a new password before any token is issued (routers/auth.py)
    must_change_password : bool = Field(default=False, sa_column_kwargs={"server_default": "false"})

    # many-to-many relationship between user and team
    team_memberships : list[TeamMembership] = Relationship(back_populates="user")

    # guardrails integrations that this user owns 
    guardrails_integrations : list["GuardrailsIntegration"] = Relationship(back_populates="owner_user")

    # cicd integrations that this user owns 
    cicd_integrations : list["CicdIntegration"] = Relationship(back_populates="owner_user")

    # scans that this user owns 
    scans : list["Scan"] = Relationship(back_populates="owner_user")

    dast_profiles : list["DastScanProfile"] = Relationship(back_populates="owner_user")



# sign-in and invitation lookups compare lower(email) (auth_utils.user_by_email): an expression index (F4, r6f4rbac001)
_SaIndex("ix_user_email_lower", _sa_func.lower(User.__table__.c.email))

class TeamInvitation(SQLModel, table=True):
    """An offer to join a team, mailed as a link to /invite/<token>; nobody joins until the invitee accepts.

    The token is stored only as its SHA-256 (``token_hash``) and works once: accepting, declining, revoking or
    resending clears or replaces it.  One row per (team, address): inviting the address again reuses it.
    Times are naive UTC.  The inviter is a plain int so deleting that user is never blocked."""
    __table_args__ = (UniqueConstraint("team_id", "email", name="uq_teaminvitation_team_email"),
                      CheckConstraint("role IN ('admin', 'member', 'viewer')", name="ck_teaminvitation_role"))
    id : int | None = Field(default=None, primary_key=True)
    team_id : int = Field(foreign_key="team.id", index=True, ondelete="CASCADE")
    email : str = Field(max_length=254)  # lower-cased, as on sign-up
    token_hash : str | None = Field(default=None, max_length=64, unique=True, index=True)
    status : str = Field(default="pending", max_length=16)  # pending | accepted | declined | revoked
    # the role the invitee joins with (admin invites member / viewer; an owner may also invite an admin)
    role : str = Field(default="member", max_length=16, sa_column_kwargs={"server_default": "member"})
    invited_by_user_id : int | None = Field(default=None)
    created_at : datetime.datetime = Field(sa_type=DateTime)
    expires_at : datetime.datetime = Field(sa_type=DateTime)
    responded_at : datetime.datetime | None = Field(default=None, sa_type=DateTime)


# only the user who created the scan can run the scan or update the scan  or send messages to the scan 
class Scan(SQLModel,table=True):
    id : int | None = Field(default=None,primary_key=True)
    team_id : int = Field(foreign_key="team.id")
    owner_user_id : int = Field(foreign_key="user.id") 
    credit_consumed : float | None = Field(default=None)  # the estimate (what the scan will cost)
    credit_charged : float | None = Field(default=None)  # what /start actually took (refunds give back exactly this)
    # what the estimate measured: {"digest": sha256 of the input, "formula": version, "minimum": credits}
    credit_estimate : Dict | None = Field(default=None, sa_column=Column(JSON))
    scan_type : Literal["sast" , "llm" , "mcp" , "iac" , "leakage" , "sbom_sca" , "agent_discovery" , "dast" , "cbom" , "ai_bom"] = Field(default="sast",sa_type=String , index=True)
    title : str = Field(default="New Scan")
    task_id : str | None = Field(default=None)
    scan_metadata : Dict | None = Field(default_factory=dict,sa_column=Column(JSON))
    scan_status : Literal["pending" , "started" , "retry" , "failure" , "success" , "cancelled" , "NOT_STARTED"] = Field(default="NOT_STARTED",sa_type=String)
    created_at : datetime.datetime | None= Field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc), sa_type=DateTime)
    last_updated : datetime.datetime | None= Field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc), sa_type=DateTime)
    scan_data : Dict | None = Field(default_factory=dict,sa_column=Column(JSON))
    info : Dict | None = Field(default=None,sa_column=Column(JSON))

    integration_settings : Dict | None = Field(default_factory=dict,sa_column=Column(JSON))  # integration settings 

    # owner user relationship
    owner_user : "User" = Relationship(back_populates="scans")

    # team relationship
    team : "Team" = Relationship(back_populates="scans")

    class Config:
        arbitrary_types_allowed = True


class CreditLedgerEntry(SQLModel, table=True):
    """One movement of a team's credits and why (#33, #52): written by backend/utilities/team/credit_ledger.py, in the
    same statement (PostgreSQL) or transaction as the balance change it records.

    Integer milli-credits: ``delta_mc`` is negative when credits are taken from the team and positive when they are
    given back; ``balance_after_mc`` is the team's balance right after it (NULL for an insert-only line settled later).
    ``movement_key`` is unique: a movement can never be written twice. ``ref_type`` + ``ref_id`` name what it belongs
    to (``scan`` / scan id, a CBOM run...); ``scan_id`` is set for scan lines. No foreign keys: a line outlives a deleted
    scan or team. ``detail`` holds numbers and digests, never an input, a URL or a secret. The table refuses UPDATE,
    DELETE and TRUNCATE by a trigger (migration r6t2ledger001); that is not a control against the database role itself.
    Written today: reinitialize charges and refunds, cancel refunds, failure refunds; the other paths are #52."""
    __tablename__ = "creditledger"
    __table_args__ = (UniqueConstraint("movement_key", name="uq_creditledger_movement_key"),)
    id: int | None = Field(default=None, sa_column=Column(
        BigInteger().with_variant(Integer(), "sqlite"), primary_key=True, autoincrement=True))  # never pruned: int8
    movement_key: str = Field(max_length=96)
    team_id: int
    ref_type: str = Field(max_length=32)
    ref_id: str = Field(max_length=64)
    scan_id: int | None = Field(default=None)
    user_id: int | None = Field(default=None)  # who caused it
    delta_mc: int = Field(sa_type=BigInteger)
    balance_after_mc: int | None = Field(default=None, sa_type=BigInteger)
    reason: str = Field(max_length=48)
    detail: Dict | None = Field(default=None, sa_column=Column(JSON))
    created_at: datetime.datetime = Field(
        default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None), sa_type=DateTime)

    @property
    def delta(self) -> float:
        """The movement in credits."""
        return self.delta_mc / 1000

    @property
    def balance_after(self) -> float | None:
        return None if self.balance_after_mc is None else self.balance_after_mc / 1000


# reconciliation and statements read (team_id, id) ranges without touching the heap; scan and per-run lookups
_SaIndex("ix_creditledger_team_id_id", CreditLedgerEntry.team_id, CreditLedgerEntry.id,
         postgresql_include=["delta_mc", "created_at"])
_SaIndex("ix_creditledger_scan_id", CreditLedgerEntry.scan_id,
         postgresql_where=CreditLedgerEntry.scan_id.isnot(None), sqlite_where=CreditLedgerEntry.scan_id.isnot(None))
_SaIndex("ix_creditledger_ref", CreditLedgerEntry.ref_type, CreditLedgerEntry.ref_id,
         postgresql_where=CreditLedgerEntry.ref_type != "scan", sqlite_where=CreditLedgerEntry.ref_type != "scan")


class DastScanProfile(SQLModel, table=True):
    """Saved DAST target + encrypted login for scheduled and Jenkins runs."""
    __tablename__ = "dastscanprofile"
    id: int | None = Field(default=None, primary_key=True)
    team_id: int = Field(foreign_key="team.id", index=True)
    owner_user_id: int = Field(foreign_key="user.id")
    title: str = Field(default="DAST Profile")
    enabled: bool = Field(default=True)
    target_url: str
    allowed_hosts: list | None = Field(default_factory=list, sa_column=Column(JSON))
    auth_encrypted: Dict | None = Field(default_factory=dict, sa_column=Column(JSON))
    scan_speed: str = Field(default="medium")
    max_urls: int = Field(default=100)
    additional_urls_to_scan: list | None = Field(default=None, sa_column=Column(JSON))
    exclude_url_patterns: list | None = Field(default=None, sa_column=Column(JSON))
    include_url_patterns: list | None = Field(default=None, sa_column=Column(JSON))
    schedule_kind: str = Field(default="off")
    schedule_time: str | None = Field(default=None)
    schedule_weekday: int | None = Field(default=None)
    schedule_config: Dict | None = Field(default_factory=dict, sa_column=Column(JSON))
    next_run_at: datetime.datetime | None = Field(default=None, sa_type=DateTime, index=True)
    inflight_scan_id: int | None = Field(default=None)
    last_scan_id: int | None = Field(default=None)
    last_run_at: datetime.datetime | None = Field(default=None, sa_type=DateTime)
    consent_ok: bool = Field(default=False)
    created_at: datetime.datetime | None = Field(
        default_factory=lambda: datetime.datetime.now(datetime.timezone.utc),
        sa_type=DateTime,
    )
    last_updated: datetime.datetime | None = Field(
        default_factory=lambda: datetime.datetime.now(datetime.timezone.utc),
        sa_type=DateTime,
    )

    owner_user: "User" = Relationship(back_populates="dast_profiles")
    team: "Team" = Relationship(back_populates="dast_profiles")

    class Config:
        arbitrary_types_allowed = True


# ========================================= Guardrails Integration (DEPRECATED) =========================================
# DEPRECATED: Guardrails product UI removed from user-facing frontend. Model retained for legacy APIs/workers.
"""
threshold should not be 0 or it will fail the scan ( add validation for this )
"""
default_settings = {
    "anonymize": None,
    "toxicity": None,
    "tokenlimit": None,
    "promptinjection": None,
    "regex": None,
    "code": None,
    "secrets": None
}

class GuardrailsIntegration(SQLModel,table=True):
    """DEPRECATED: Retained for legacy Guardrails APIs/workers; not exposed in product UI."""
    id : int | None = Field(default=None,primary_key=True)
    team_id : int = Field(foreign_key="team.id")
    owner_user_id : int = Field(foreign_key="user.id")
    api_key : str
    title : str = Field(default="New Guardrails Integration")
    created_at : datetime.datetime | None= Field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc), sa_type=DateTime)
    last_updated : datetime.datetime | None= Field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc), sa_type=DateTime)
    settings : Dict | None = Field(default=default_settings,sa_column=Column(JSON))  # scanner settings 
    integration_settings : Dict | None = Field(default_factory=dict,sa_column=Column(JSON))  # integration settings 
    
    # owner user relationship
    owner_user : "User" = Relationship(back_populates="guardrails_integrations")

    # team relationship
    team : "Team" = Relationship(back_populates="guardrails_integrations")

    
    
    
    class Config:
        arbitrary_types_allowed = True


# ========================================= CI/CD Integration =========================================

class CicdIntegration(SQLModel,table=True):
    id : int | None = Field(default=None,primary_key=True)
    team_id : int = Field(foreign_key="team.id")
    owner_user_id : int = Field(foreign_key="user.id")
    api_key : str
    title : str = Field(default="New CI/CD Integration")
    created_at : datetime.datetime | None= Field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc), sa_type=DateTime)
    last_updated : datetime.datetime | None= Field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc), sa_type=DateTime)
    scan_type : scan_types | None= Field(default=None,sa_type=String)
    results : Dict | None = Field(default_factory=dict,sa_column=Column(JSON))
    integration_settings : Dict | None = Field(default_factory=dict,sa_column=Column(JSON))  # integration settings
    
    scan_settings : Dict | None = Field(default_factory=dict,sa_column=Column(JSON))  # scan settings
    
    # owner user relationship
    owner_user : "User" = Relationship(back_populates="cicd_integrations")

    # team relationship
    team : "Team" = Relationship(back_populates="cicd_integrations")
    
    class Config:
        arbitrary_types_allowed = True

# ========================================= CBOM collection sources =========================================
# Scan nodes, servers, clusters, databases, cloud accounts, network scope and evidence for the CBOM
# scanner beyond code.  Rules that every model below follows:
#   * every row carries team_id and every query filters on it;
#   * times are naive UTC (``_cbom_utcnow``) and are serialised with a trailing "Z";
#   * user and scan references are plain ints (no foreign key) so team, user and scan deletes are never
#     blocked; foreign keys only link these tables to each other and to ``team``;
#   * secrets live only in ``CbomCollectionSource.secret_encrypted`` (Fernet, see
#     ``backend/utilities/cbom_sources/crypto.py``) and are never serialised to a browser;
#   * ``row_version`` is bumped on every write so a stale form gets a 409 instead of a silent overwrite.
# No Relationship attributes are declared on Team/User on purpose (no implicit cascades).


class CbomFactsJSON(_SaTypeDecorator):
    """A collected asset's facts as the rules read them: a JSON object.  A stored value that is no object (a list, a
    number or a string, written before facts were validated as an object, or by hand) is read as ``{}``, unread, so
    every view and the classifier get the one shape they read instead of an HTTP 500.  The column, its SQL type and
    what is written are unchanged (JSON); only what a read returns is."""

    impl = JSON
    cache_ok = True

    def process_result_value(self, value, dialect):
        return value if value is None or isinstance(value, dict) else {}


CONTENT_DIGEST_COLUMNS = ("asset_type", "cdx_type", "target", "location", "algorithm", "key_size", "protocol",
                          "quantum_vulnerable", "impact", "finding", "finding_codes", "facts")
_JSON_COLUMNS = ("finding_codes", "facts")


def content_digest(values: dict) -> str | None:
    """#352: SHA-256 of the columns the estate hooks read (agility's carry: type, place, algorithm, key size, protocol,
    verdict, codes, facts; the register's grade inputs add the target and the quantum flag), serialised the way the
    JSON columns store them (``json.dumps``, the dialects' default serializer), so equal digests mean equal stored
    values, JSON text included. None when a value cannot be serialised (the row is then compared column by column)."""
    import hashlib as _hashlib
    import json as _json

    # a JSON column left out of an INSERT is SQL NULL, a None in it is JSON null: different stored values
    doc = [values.get(c) if c in values or c not in _JSON_COLUMNS else {"$absent": True}
           for c in CONTENT_DIGEST_COLUMNS]
    try:
        text = _json.dumps(doc)
    except (TypeError, ValueError):
        return None
    return _hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()


def _content_digest_default(context) -> str | None:
    params = context.get_current_parameters() if context is not None else {}
    return content_digest(params)


def _cbom_utcnow() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)


class CbomScanNode(SQLModel, table=True):
    """A customer-run collector that reaches servers, clusters and networks from inside a segment."""
    __tablename__ = "cbomscannode"
    id: int | None = Field(default=None, primary_key=True)
    team_id: int = Field(foreign_key="team.id", index=True)
    owner_user_id: int
    updated_by_user_id: int | None = Field(default=None)
    name: str = Field(max_length=64)
    segment: str = Field(default="", max_length=64)
    timezone: str = Field(default="UTC", max_length=64)
    deployment: str = Field(default="docker", max_length=16)
    proxy_url: str | None = Field(default=None, max_length=512)
    proxy_ca_pem: str | None = Field(default=None, sa_type=Text)
    proxy_tls_inspect: bool = Field(default=False)
    # #199: the proxy's user name when it needs a login (never the password: that stays on the node's host, in the
    # file ZS_PROXY_AUTH_FILE names, created by the install command)
    proxy_user: str | None = Field(default=None, max_length=128)
    registration_token_hash: str | None = Field(default=None, max_length=64, index=True)
    registration_issued_at: datetime.datetime | None = Field(default=None, sa_type=DateTime)
    registration_expires_at: datetime.datetime | None = Field(default=None, sa_type=DateTime)
    enrolled_at: datetime.datetime | None = Field(default=None, sa_type=DateTime)
    node_token_hash: str | None = Field(default=None, max_length=64, unique=True, index=True)
    hostname: str | None = Field(default=None, max_length=255)
    node_version: str | None = Field(default=None, max_length=32)
    source_ips: list | None = Field(default_factory=list, sa_column=Column(JSON))
    ssh_public_key: str | None = Field(default=None, sa_type=Text)
    capabilities: Dict | None = Field(default_factory=dict, sa_column=Column(JSON))
    clock_skew_s: int | None = Field(default=None)
    last_heartbeat_at: datetime.datetime | None = Field(default=None, sa_type=DateTime)
    last_claim_at: datetime.datetime | None = Field(default=None, sa_type=DateTime)
    last_seen_ip: str | None = Field(default=None, max_length=64)
    last_node_error: str | None = Field(default=None, max_length=512)
    # Ed25519 request-signing key the node generated for this enrollment (raw 32 bytes, base64). Set: every request
    # from the node must be signed with it ("required"). None: a node enrolled before signing existed ("legacy").
    signing_public_key: str | None = Field(default=None, max_length=64)
    # SHA-256 of the client certificate the proxy verified at enrollment (mTLS; only when CBOM_MTLS_HEADER_TRUSTED=1).
    client_cert_sha256: str | None = Field(default=None, max_length=64)
    # "agentless" (reaches other systems with stored credentials) or "agent": collects only its own host (ZS_MODE=agent,
    # the Helm DaemonSet); an agent node is only ever given host_agent jobs, and never a credential.
    mode: str = Field(default="agentless", max_length=16, sa_column_kwargs={"server_default": "agentless"})
    # the agent pool token it enrolled with (one node per Kubernetes node of a DaemonSet)
    pool_id: int | None = Field(default=None, foreign_key="cbomnodepool.id", index=True, ondelete="SET NULL")
    # Protocol-2 anti-replay window (node_auth): the highest request sequence accepted and a bitmap of the 63 below
    # it. Checked and advanced by one conditional UPDATE per request instead of a nonce row (F1.1).
    replay_hwm: int = Field(default=0, sa_type=BigInteger, sa_column_kwargs={"server_default": "0"})
    replay_bits: int = Field(default=0, sa_type=BigInteger, sa_column_kwargs={"server_default": "0"})
    row_version: int = Field(default=1)
    created_at: datetime.datetime | None = Field(default_factory=_cbom_utcnow, sa_type=DateTime)
    last_updated: datetime.datetime | None = Field(default_factory=_cbom_utcnow, sa_type=DateTime)


# One name per team, whatever its case (X1 B1, Nov 11): the create route checked for a clash and then inserted, so two
# concurrent requests both passed the check and the team had two nodes with the same name. The database refuses the
# second (routers/cbom_sources.py answers 409); migration rv6p1nodename001 renames older duplicates first.
SCAN_NODE_NAME_INDEX = "uq_cbomscannode_team_lower_name"
_SaIndex(SCAN_NODE_NAME_INDEX, CbomScanNode.team_id, _sa_func.lower(CbomScanNode.name), unique=True)


class CbomNodePool(SQLModel, table=True):
    """An agent pool registration token: many agent-mode nodes (a DaemonSet's pods) enroll with it, each as its own
    node named after its Kubernetes node.  Only the token's SHA-256 is stored; it expires, caps its enrollments and
    can be revoked (revoking stops new enrollments; enrolled nodes keep their own credentials)."""
    __tablename__ = "cbomnodepool"
    id: int | None = Field(default=None, primary_key=True)
    team_id: int = Field(foreign_key="team.id", index=True)
    owner_user_id: int
    name: str = Field(max_length=64)
    segment: str = Field(default="", max_length=64)
    token_hash: str = Field(max_length=64, unique=True, index=True)
    expires_at: datetime.datetime = Field(sa_type=DateTime)
    max_enrollments: int = Field(default=50)
    enrollments: int = Field(default=0)
    revoked_at: datetime.datetime | None = Field(default=None, sa_type=DateTime)
    revoked_by_user_id: int | None = Field(default=None)
    last_enrolled_at: datetime.datetime | None = Field(default=None, sa_type=DateTime)
    created_at: datetime.datetime | None = Field(default_factory=_cbom_utcnow, sa_type=DateTime)


class CbomNodeNonce(SQLModel, table=True):
    """Nonces of signed scan-node requests, kept until their timestamp is outside the accepted clock skew, so a
    captured request cannot be replayed (shared by every worker and replica)."""
    __tablename__ = "cbomnodenonce"
    node_id: int = Field(foreign_key="cbomscannode.id", primary_key=True, ondelete="CASCADE")
    nonce: str = Field(primary_key=True, max_length=64)
    expires_at: datetime.datetime = Field(sa_type=DateTime, index=True)


class CbomDeployment(SQLModel, table=True):
    """One row: this ZeroShield deployment's stable id, stamped on every scan-node response (X-ZS-Deployment) so a
    node can tell a 401 from its own server apart from one sent by a wrong server or a proxy."""
    __tablename__ = "cbomdeployment"
    id: int = Field(default=1, primary_key=True)
    deployment_id: str = Field(max_length=36)
    created_at: datetime.datetime | None = Field(default_factory=_cbom_utcnow, sa_type=DateTime)


class CbomCollectionSource(SQLModel, table=True):
    """One configured source: a server group, cluster, database, cloud account, CA/IdP or network range."""
    __tablename__ = "cbomcollectionsource"
    __table_args__ = (UniqueConstraint("team_id", "kind", "name_lower", name="uq_cbomcollectionsource_team_kind_name"),)
    id: int | None = Field(default=None, primary_key=True)
    team_id: int = Field(foreign_key="team.id", index=True)
    owner_user_id: int
    updated_by_user_id: int | None = Field(default=None)
    kind: str = Field(max_length=32, index=True)
    name: str = Field(max_length=64)
    name_lower: str = Field(max_length=64)
    node_id: int | None = Field(default=None, foreign_key="cbomscannode.id", index=True)
    # F1.1: no node_id and a segment = any agentless scan node of the team whose ``segment`` is this one runs its jobs
    node_segment: str | None = Field(default=None, max_length=64)
    enabled: bool = Field(default=True)
    config: Dict | None = Field(default_factory=dict, sa_column=Column(JSON))
    secret_encrypted: str | None = Field(default=None, sa_type=Text)
    secret_fields: list | None = Field(default_factory=list, sa_column=Column(JSON))
    last_test_status: str = Field(default="never", max_length=16)
    last_test_at: datetime.datetime | None = Field(default=None, sa_type=DateTime)
    last_test_summary: str | None = Field(default=None, max_length=512)
    last_test_job_id: int | None = Field(default=None)
    last_test_result: Dict | None = Field(default_factory=dict, sa_column=Column(JSON))
    row_version: int = Field(default=1)
    created_at: datetime.datetime | None = Field(default_factory=_cbom_utcnow, sa_type=DateTime)
    last_updated: datetime.datetime | None = Field(default_factory=_cbom_utcnow, sa_type=DateTime)
    # stable identity that survives deletion: snapshotted on every collect job, so diffs, drift events and remediation
    # assignments keep pointing at "the same source" after a rename, and a re-created source is a new one
    source_uid: str | None = Field(default_factory=lambda: uuid.uuid4().hex, max_length=32, index=True)
    # F1.2 fleet: the policy whose materializer manages this source (None: made by hand), the typed credential it uses,
    # and its sticky batch key (policy, transport, credential, node or segment, kind); plain ints, no foreign keys
    managed_by_policy_id: int | None = Field(default=None, index=True)
    credential_id: int | None = Field(default=None)
    batch_key: str | None = Field(default=None, max_length=64)


class CbomCollectionRun(SQLModel, table=True):
    """A user-started collection over the configured sources; credits are charged per queued job."""
    __tablename__ = "cbomcollectionrun"
    __table_args__ = (UniqueConstraint("team_id", "client_request_id", name="uq_cbomcollectionrun_team_request"),)
    id: int | None = Field(default=None, primary_key=True)
    team_id: int = Field(foreign_key="team.id", index=True)
    owner_user_id: int
    scan_id: int | None = Field(default=None, index=True)
    client_request_id: str = Field(max_length=64)
    status: str = Field(default="queued", max_length=16)
    include: Dict | None = Field(default_factory=dict, sa_column=Column(JSON))
    breakdown: Dict | None = Field(default_factory=dict, sa_column=Column(JSON))
    credits_charged_c: int = Field(default=0)
    credits_refunded_c: int = Field(default=0)
    # what judged this run, recorded when it was created (the export names them; serial = uuid5(run id + KB version))
    kb_version: str | None = Field(default=None, max_length=32)
    classifier_version: str | None = Field(default=None, max_length=32)
    engine_version: str | None = Field(default=None, max_length=32)
    # CB-19 PR-2: the grade model and the grade inputs (team Mosca X/Y/Z, evidence levels and Q0 gaps) at Start; run
    # views grade with these (the record), never with the team's later edits (null on runs from before cb19grade001)
    grade_model_version: str | None = Field(default=None, max_length=32)
    grade_inputs: Dict | None = Field(default=None, sa_column=Column(JSON, nullable=True))
    soc_ack_by: int | None = Field(default=None)
    soc_ack_at: datetime.datetime | None = Field(default=None, sa_type=DateTime)
    cancelled_by: int | None = Field(default=None)
    cancelled_at: datetime.datetime | None = Field(default=None, sa_type=DateTime)
    created_at: datetime.datetime | None = Field(default_factory=_cbom_utcnow, sa_type=DateTime)
    last_updated: datetime.datetime | None = Field(default_factory=_cbom_utcnow, sa_type=DateTime)
    finished_at: datetime.datetime | None = Field(default=None, sa_type=DateTime)
    schedule_id: int | None = Field(default=None, index=True)  # set when a schedule started the run
    # what started the run (S4): "scheduled" (a schedule: schedule_id) or "manual" (a member's Start); rsched1trig001
    trigger: str = Field(default="manual", max_length=16, sa_column_kwargs={"server_default": "manual"})
    drift_at: datetime.datetime | None = Field(default=None, sa_type=DateTime)  # drift events recorded (once)
    # S4: the run's drift document (drift_report.run_drift: counts, readiness, top items against its baseline), stored
    # once after its drift is recorded (drift.store_pending_summaries), so report.pdf and drift.json neither recompute
    # the comparison per download nor change afterwards; keyed by its baseline id (recomputed if the baseline
    # differs). SQL NULL until stored (none_as_null: "IS NULL" finds it). rsched1trig001
    drift_summary: dict | None = Field(default=None, sa_column=Column(JSON(none_as_null=True), nullable=True))


class CbomCollectionJob(SQLModel, table=True):
    """A unit of work for one scan node: test a connection, collect a source, or run a discovery sweep."""
    __tablename__ = "cbomcollectionjob"
    # CB-14: at most one open collection per source; a Start that races another for the same source gets 409
    # (runs.queue_run) and is charged nothing (migration cb14credit001)
    __table_args__ = (_SaIndex("uq_cbomcollectionjob_open_collect", "source_id", unique=True,
                               postgresql_where=_sa_text("kind = 'collect' AND status IN ('pending', 'claimed')"),
                               sqlite_where=_sa_text("kind = 'collect' AND status IN ('pending', 'claimed')")),
                      # staging QA2 Q1-02 (#497 review M3, migration q102hist001): each source's collection history
                      # (``collections_view.collection_history``) from the index, not a scan of every job's params
                      _SaIndex("ix_cbomcollectionjob_team_source_hist", "team_id", "source_id", "created_at",
                               postgresql_include=["status", "finished_at"],
                               postgresql_where=_sa_text("kind = 'collect' AND run_id IS NOT NULL"),
                               sqlite_where=_sa_text("kind = 'collect' AND run_id IS NOT NULL")))
    id: int | None = Field(default=None, primary_key=True)
    team_id: int = Field(foreign_key="team.id", index=True)
    run_id: int | None = Field(default=None, foreign_key="cbomcollectionrun.id", index=True)
    source_id: int | None = Field(default=None, foreign_key="cbomcollectionsource.id", index=True)
    node_id: int | None = Field(default=None, foreign_key="cbomscannode.id", index=True)
    # F1.1: set = a segment job: while pending (node_id NULL) any agentless node of the team in this segment may claim
    # it (SKIP LOCKED); the claim sets node_id to the claimer, and a lease that expires clears it again
    node_segment: str | None = Field(default=None, max_length=64)
    kind: str = Field(max_length=16)
    status: str = Field(default="pending", max_length=16, index=True)
    params: Dict | None = Field(default_factory=dict, sa_column=Column(JSON))
    source_version: int | None = Field(default=None)
    weight_c: int = Field(default=0)
    refunded: bool = Field(default=False)
    # centi-credits given back (CB-14): weight_c for a failed / cancelled / nothing-read job, the runtime-skip share of
    # it for a partly read one; its ledger row is cbomcreditentry "job:<id>:refund" (billing.py).  F1.1: while
    # ``refund_due`` and not yet ``refunded`` it is the amount owed, which ``jobs.settle_refunds`` moves
    refunded_c: int = Field(default=0, sa_column_kwargs={"server_default": "0"})
    # F1.1 (DA C2): a job end only marks its credits as owed back here; ``jobs.settle_refunds`` moves the money in one
    # pass per run (right after the job end commits, the reaper pass, run end, user cancel) and sets ``refunded`` once
    refund_due: bool = Field(default=False, sa_column_kwargs={"server_default": "false"})
    attempts: int = Field(default=0)
    lease_id: str | None = Field(default=None, max_length=32)
    lease_expires_at: datetime.datetime | None = Field(default=None, sa_type=DateTime)
    created_by_user_id: int | None = Field(default=None)
    created_at: datetime.datetime | None = Field(default_factory=_cbom_utcnow, sa_type=DateTime)
    claimed_at: datetime.datetime | None = Field(default=None, sa_type=DateTime)
    finished_at: datetime.datetime | None = Field(default=None, sa_type=DateTime)
    result: Dict | None = Field(default_factory=dict, sa_column=Column(JSON))
    error: str | None = Field(default=None, max_length=1024)
    # ok | partial | failed, computed by the server from the node's target counts and the stored assets
    outcome: str | None = Field(default=None, max_length=16)
    asset_count: int = Field(default=0)  # assets stored for the current attempt (guarded counter, capped)
    first_claimed_at: datetime.datetime | None = Field(default=None, sa_type=DateTime)
    cancel_requested_at: datetime.datetime | None = Field(default=None, sa_type=DateTime)
    cancel_reason: str | None = Field(default=None, max_length=255)
    # F1 cloud pool: a ``slice`` job (one AWS account x region) points at the source's ``collect`` job it belongs to.
    # Slices have no run (run_id NULL) and no credits: their assets are stored under the parent job, which stays the
    # one job per source that runs, drift, posture and credits know about (``cbom_sources.slices``).
    parent_job_id: int | None = Field(default=None, foreign_key="cbomcollectionjob.id", index=True, ondelete="CASCADE")


class CbomHostKeyReset(SQLModel, table=True):
    """#150: a team admin's decision about a host key a scan node remembered under trust on first use.

    ``accept``: the node replaces its pin for ``target``:``port`` with exactly ``fingerprint`` (the key the admin
    reviewed on a ``host_key_changed`` result), and any other key still fails.  ``forget``: the node drops its pins
    for that address, and the next connection pins on first use again.  The node that reported the change applies it
    on its next job for the source and acknowledges it in that job's result (``applied``).  This row is the record of
    who decided what and when; plain ints (no foreign keys), so it outlives the source, node and job it names."""
    __tablename__ = "cbomhostkeyreset"
    id: int | None = Field(default=None, primary_key=True)
    team_id: int = Field(foreign_key="team.id", index=True)
    source_id: int = Field(index=True)
    node_id: int
    job_id: int  # the job whose result showed the changed key (the evidence the admin reviewed)
    target: str = Field(max_length=255)
    port: int = Field(default=22)
    action: str = Field(max_length=8)  # accept | forget
    fingerprint: str | None = Field(default=None, max_length=64)  # accept: the key the node may now trust
    pinned_fingerprint: str | None = Field(default=None, max_length=64)  # the key it remembered until then
    status: str = Field(default="pending", max_length=12)  # pending | applied | superseded
    requested_by_user_id: int
    requested_at: datetime.datetime | None = Field(default_factory=_cbom_utcnow, sa_type=DateTime)
    applied_at: datetime.datetime | None = Field(default=None, sa_type=DateTime)
    applied_job_id: int | None = Field(default=None)


# Hot-path indexes (F1.1, migration r6f11node001). The partial ones cover only open jobs, so they stay small however
# much history a team keeps: a claim reads (node, oldest pending), a heartbeat reads the node's claimed jobs, the reaper
# reads expired leases and stale pending jobs, and a run's status is decided from (run, status) without loading its jobs.
_PENDING = _sa_text("status = 'pending'")
_CLAIMED = _sa_text("status = 'claimed'")
_SaIndex("ix_cbomcollectionjob_run_status", CbomCollectionJob.run_id, CbomCollectionJob.status)
_SaIndex("ix_cbomcollectionjob_node_pending", CbomCollectionJob.node_id, CbomCollectionJob.id,
         postgresql_where=_PENDING, sqlite_where=_PENDING)
_SaIndex("ix_cbomcollectionjob_node_claimed", CbomCollectionJob.node_id,
         postgresql_where=_CLAIMED, sqlite_where=_CLAIMED)
_SaIndex("ix_cbomcollectionjob_claimed_lease", CbomCollectionJob.lease_expires_at,
         postgresql_where=_CLAIMED, sqlite_where=_CLAIMED)
_SaIndex("ix_cbomcollectionjob_pending_created", CbomCollectionJob.created_at,
         postgresql_where=_PENDING, sqlite_where=_PENDING)
_SaIndex("ix_cbomcollectionjob_team_status_segment", CbomCollectionJob.team_id, CbomCollectionJob.status,
         CbomCollectionJob.node_segment, CbomCollectionJob.id)
# claims a node made after a claim ticket was issued (dispatch: a ticket's used claims, counted only when one is sent)
_SaIndex("ix_cbomcollectionjob_node_claimed_at", CbomCollectionJob.node_id, CbomCollectionJob.claimed_at)
_REFUND_DUE = _sa_text("refund_due AND NOT refunded")
_SaIndex("ix_cbomcollectionjob_refund_due", CbomCollectionJob.run_id,
         postgresql_where=_REFUND_DUE, sqlite_where=_REFUND_DUE)


class CbomCollectedAsset(SQLModel, table=True):
    """One cryptographic asset a collection job found.  Facts come from the node; impact is ours."""
    __tablename__ = "cbomcollectedasset"
    __table_args__ = (UniqueConstraint("job_id", "attempt", "asset_key", name="uq_cbomcollectedasset_job_attempt_key"),
                      # CB-19 PR-3: the run asset list's grade filter and facet (migration cb19grade002)
                      _SaIndex("ix_cbomcollectedasset_run_qgrade", "run_id", "q_grade"))
    id: int | None = Field(default=None, primary_key=True)
    team_id: int = Field(foreign_key="team.id", index=True)
    run_id: int | None = Field(default=None, foreign_key="cbomcollectionrun.id", index=True)
    job_id: int = Field(foreign_key="cbomcollectionjob.id", index=True)
    source_id: int | None = Field(default=None, foreign_key="cbomcollectionsource.id", index=True)
    attempt: int = Field(default=1)
    asset_key: str = Field(max_length=64)
    asset_type: str = Field(max_length=32, index=True)
    cdx_type: str = Field(max_length=32)
    target: str | None = Field(default=None, max_length=255)
    location: str = Field(max_length=512)
    name: str | None = Field(default=None, max_length=255)
    algorithm: str | None = Field(default=None, max_length=64)
    key_size: int | None = Field(default=None)
    protocol: str | None = Field(default=None, max_length=32)
    quantum_vulnerable: bool | None = Field(default=None)
    impact: str | None = Field(default=None, max_length=16, index=True)
    finding_codes: list | None = Field(default_factory=list, sa_column=Column(JSON))
    finding: str | None = Field(default=None, max_length=512)
    facts: Dict | None = Field(default_factory=dict, sa_column=Column(CbomFactsJSON))
    created_at: datetime.datetime | None = Field(default_factory=_cbom_utcnow, sa_type=DateTime)
    # CB-19 PR-3: the record grade stored at ingest (qgrade.ingest_grades), NULL when it was not stored (a row from
    # before cb19grade002, a run without a grade-input snapshot, or a run started under another grade model);
    # q_grade NULL with a q_reason is "no grade" (not_applicable, not_an_item)
    q_grade: str | None = Field(default=None, max_length=2)
    q_reason: str | None = Field(default=None, max_length=32)
    # #352: a digest of what the estate hooks read from the row (``content_digest``), computed on every insert (a
    # Python column default, so the ingest's bulk INSERT, the ORM and the tests all set it). Equal digests mean equal
    # stored values; a changed or NULL digest (a row from before cb352digest001) is compared column by column.
    content_digest: str | None = Field(default=None, max_length=64, sa_column_kwargs={"default": _content_digest_default})


class CbomCollectionSettings(SQLModel, table=True):
    """Team-wide settings: AWS external ID, certificate domains, network scope and safety, SOC contacts."""
    __tablename__ = "cbomcollectionsettings"
    id: int | None = Field(default=None, primary_key=True)
    team_id: int = Field(foreign_key="team.id", unique=True, index=True)
    aws_external_id: str = Field(max_length=40)
    cert_domains: list | None = Field(default_factory=list, sa_column=Column(JSON))
    network_exclusions: list | None = Field(default_factory=list, sa_column=Column(JSON))
    sni_hostnames: list | None = Field(default_factory=list, sa_column=Column(JSON))
    ports: list | None = Field(default_factory=list, sa_column=Column(JSON))
    zeek_span: bool = Field(default=False)
    scan_window: list | None = Field(default_factory=list, sa_column=Column(JSON))
    window_timezone: str = Field(default="Asia/Kolkata", max_length=64)
    rate_conn_per_s: int = Field(default=20)
    rate_parallel_per_server: int = Field(default=2)
    rate_handshakes_per_endpoint: int = Field(default=128)  # CB-12: full suite enumeration
    soc_email: str | None = Field(default=None, max_length=254)
    emergency_contact: str | None = Field(default=None, max_length=64)
    stop_all_network: bool = Field(default=False)
    # Refuse scan nodes that do not sign their requests (enrolled before signing existed, or an old node version).
    require_signed_nodes: bool = Field(default=False)
    risk_model: Dict | None = Field(default_factory=dict, sa_column=Column(JSON))
    # CB-38 PR-4: Jira project (key such as "SEC", or a numeric project id) and issue type for CBOM Sources tickets;
    # the credentials stay in the team's integration settings (the code lane's)
    jira_project_key: str | None = Field(default=None, max_length=32)
    jira_issue_type: str | None = Field(default=None, max_length=64)
    stop_all_changed_by: int | None = Field(default=None)
    stop_all_changed_at: datetime.datetime | None = Field(default=None, sa_type=DateTime)
    updated_by_user_id: int | None = Field(default=None)
    row_version: int = Field(default=1)
    created_at: datetime.datetime | None = Field(default_factory=_cbom_utcnow, sa_type=DateTime)
    last_updated: datetime.datetime | None = Field(default_factory=_cbom_utcnow, sa_type=DateTime)


class CbomEvidenceArea(SQLModel, table=True):
    """An area that cannot be scanned (key hierarchy, HSM firmware, ...) answered by its owner."""
    __tablename__ = "cbomevidencearea"
    __table_args__ = (UniqueConstraint("team_id", "area_key", name="uq_cbomevidencearea_team_area"),)
    id: int | None = Field(default=None, primary_key=True)
    team_id: int = Field(foreign_key="team.id", index=True)
    area_key: str = Field(max_length=32)
    owner: str | None = Field(default=None, max_length=128)
    confidence: str = Field(default="E0", max_length=2)
    confidence_set_by: int | None = Field(default=None)
    answers: Dict | None = Field(default_factory=dict, sa_column=Column(JSON))
    evidence_title: str | None = Field(default=None, max_length=200)
    evidence_url: str | None = Field(default=None, max_length=1000)
    evidence_date: str | None = Field(default=None, max_length=10)
    due_date: str | None = Field(default=None, max_length=10)
    updated_by_user_id: int | None = Field(default=None)
    row_version: int = Field(default=1)
    created_at: datetime.datetime | None = Field(default_factory=_cbom_utcnow, sa_type=DateTime)
    last_updated: datetime.datetime | None = Field(default_factory=_cbom_utcnow, sa_type=DateTime)


class CbomEvidenceVendor(SQLModel, table=True):
    """A third party asked to answer a questionnaire through a single-use link (no login)."""
    __tablename__ = "cbomevidencevendor"
    id: int | None = Field(default=None, primary_key=True)
    team_id: int = Field(foreign_key="team.id", index=True)
    name: str = Field(max_length=128)
    contact_email: str | None = Field(default=None, max_length=254)
    area_key: str = Field(default="third_party_vendors", max_length=32)
    link_token_hash: str | None = Field(default=None, max_length=64, unique=True, index=True)
    link_created_at: datetime.datetime | None = Field(default=None, sa_type=DateTime)
    link_expires_at: datetime.datetime | None = Field(default=None, sa_type=DateTime)
    answered_at: datetime.datetime | None = Field(default=None, sa_type=DateTime)
    answers: Dict | None = Field(default_factory=dict, sa_column=Column(JSON))
    confidence: str = Field(default="E0", max_length=2)
    evidence_url: str | None = Field(default=None, max_length=1000)
    created_by_user_id: int | None = Field(default=None)
    row_version: int = Field(default=1)
    created_at: datetime.datetime | None = Field(default_factory=_cbom_utcnow, sa_type=DateTime)
    last_updated: datetime.datetime | None = Field(default_factory=_cbom_utcnow, sa_type=DateTime)


class CbomCollectionAuditEvent(SQLModel, table=True):
    """Who changed what in CBOM Sources and when; field names only, never values.

    One documented exception: action ``deliverable_issued`` (object ``deliverable``, id = the SOW deliverable number)
    records an issue of the Board report (D14) for its trend, with ``name=value`` items of the figures the PDF itself
    prints (Document ID, as-of day, grade, score, counts), never a setting's value or a secret
    (``dashboard.cbom_board_issues``). It moves to a dedicated ``cbom_deliverable_issue`` table (team, number,
    document_id unique) with the next migration (PR #485 review 2 m1).

    A second one: action ``register_model_regrade`` (actor ``system``, object ``risk_register``) records how many
    register rows a re-grade under a new grade model moved, as ``moved=N`` and ``model_version=...``, so D12 marks that
    week "grade model changed" (``risk_register._record_model_regrade``, PR #496 review 6057476173 M2)."""
    __tablename__ = "cbomcollectionauditevent"
    id: int | None = Field(default=None, primary_key=True)
    team_id: int = Field(foreign_key="team.id", index=True)
    at: datetime.datetime | None = Field(default_factory=_cbom_utcnow, sa_type=DateTime)
    actor_type: str = Field(max_length=8)
    actor_id: int | None = Field(default=None)
    action: str = Field(max_length=48)
    object_type: str = Field(max_length=24)
    object_id: int | None = Field(default=None)
    changed_fields: list | None = Field(default_factory=list, sa_column=Column(JSON))


class CbomCollectionSchedule(SQLModel, table=True):
    """A recurring collection run: daily / weekly / monthly at a wall-clock time in the team's window time zone."""
    __tablename__ = "cbomcollectionschedule"
    id: int | None = Field(default=None, primary_key=True)
    team_id: int = Field(foreign_key="team.id", index=True)
    owner_user_id: int  # the runs it starts are this member's (credits, audit "system" on their behalf)
    updated_by_user_id: int | None = Field(default=None)
    name: str = Field(max_length=64)
    enabled: bool = Field(default=True)
    frequency: str = Field(default="weekly", max_length=8)  # daily | weekly | monthly
    time_of_day: str = Field(default="02:00", max_length=5)  # HH:MM in the team's window_timezone
    weekday: int | None = Field(default=None)  # weekly: 0 = Monday
    monthday: int | None = Field(default=None)  # monthly: 1-28
    include: Dict | None = Field(default_factory=dict, sa_column=Column(JSON))
    source_ids: list | None = Field(default_factory=list, sa_column=Column(JSON))  # empty: every source in the groups
    min_criticality: str | None = Field(default=None, max_length=8)  # only sources at or above this criticality
    soc_ack_by: int | None = Field(default=None)  # network ranges need the SOC acknowledgement, kept with the schedule
    soc_ack_at: datetime.datetime | None = Field(default=None, sa_type=DateTime)
    next_run_at: datetime.datetime | None = Field(default=None, sa_type=DateTime, index=True)  # naive UTC
    last_slot: str | None = Field(default=None, max_length=32)  # local wall time of the last slot fired
    last_fired_at: datetime.datetime | None = Field(default=None, sa_type=DateTime)
    last_run_id: int | None = Field(default=None)
    last_status: str | None = Field(default=None, max_length=16)  # queued | skipped
    last_message: str | None = Field(default=None, max_length=512)
    row_version: int = Field(default=1)
    created_at: datetime.datetime | None = Field(default_factory=_cbom_utcnow, sa_type=DateTime)
    last_updated: datetime.datetime | None = Field(default_factory=_cbom_utcnow, sa_type=DateTime)
    policy_id: int | None = Field(default=None, index=True)  # F1.2: the fleet policy that manages this schedule


class CbomDriftEvent(SQLModel, table=True):
    """What changed between two complete collections of the same source (or two code scans of the same repository
    and branch): finding opened / resolved, asset new / removed, certificate renewed / expiring, schedule skipped.
    ``dedupe_key`` makes recording idempotent; ``forwarded_at`` is for the integrations that forward events."""
    __tablename__ = "cbomdriftevent"
    __table_args__ = (UniqueConstraint("team_id", "dedupe_key", name="uq_cbomdriftevent_team_key"),)
    id: int | None = Field(default=None, primary_key=True)
    team_id: int = Field(foreign_key="team.id", index=True)
    at: datetime.datetime | None = Field(default_factory=_cbom_utcnow, sa_type=DateTime, index=True)
    scope: str = Field(default="node", max_length=8)  # node | code
    kind: str = Field(max_length=24)
    run_id: int | None = Field(default=None, index=True)
    baseline_run_id: int | None = Field(default=None)
    scan_id: int | None = Field(default=None, index=True)
    baseline_scan_id: int | None = Field(default=None)
    source_ref: str = Field(default="", max_length=255)  # source uid (node) or repository@branch key (code)
    source_name: str | None = Field(default=None, max_length=255)
    asset_key: str | None = Field(default=None, max_length=64, index=True)  # stable identity (identity.stable_key)
    asset_label: str | None = Field(default=None, max_length=255)
    code: str | None = Field(default=None, max_length=48)
    severity: str | None = Field(default=None, max_length=16)
    detail: Dict | None = Field(default_factory=dict, sa_column=Column(JSON))
    dedupe_key: str = Field(max_length=64)
    forwarded_at: datetime.datetime | None = Field(default=None, sa_type=DateTime)


class CbomRemediationAssignment(SQLModel, table=True):
    """Wave, owner, target date and status of one asset, keyed by its STABLE identity (not a row id), so the plan
    survives every later run or scan of the same source."""
    __tablename__ = "cbomremediationassignment"
    __table_args__ = (UniqueConstraint("team_id", "asset_key", name="uq_cbomremediation_team_asset"),)
    id: int | None = Field(default=None, primary_key=True)
    team_id: int = Field(foreign_key="team.id", index=True)
    asset_key: str = Field(max_length=64)
    scope: str = Field(default="node", max_length=8)  # node | code
    source_ref: str = Field(default="", max_length=255)
    label: str | None = Field(default=None, max_length=255)
    wave: int | None = Field(default=None)  # 1-4; None = the suggested wave applies
    owner: str | None = Field(default=None, max_length=128)
    target_date: str | None = Field(default=None, max_length=10)  # YYYY-MM-DD
    status: str = Field(default="open", max_length=16)  # open | in_progress | done | accepted_risk
    note: str | None = Field(default=None, max_length=500)
    # CB-38 PR-4: the Jira issue of this asset (one per stable key, across runs) and when the status last became done
    ticket_key: str | None = Field(default=None, max_length=64)
    ticket_url: str | None = Field(default=None, max_length=512)
    # the claim of the request creating the issue (taken and committed before the Jira call; run_tickets)
    ticket_state: str | None = Field(default=None, max_length=16)  # claimed | created
    ticket_claim: str | None = Field(default=None, max_length=32)
    ticket_claimed_at: datetime.datetime | None = Field(default=None, sa_type=DateTime)
    done_at: datetime.datetime | None = Field(default=None, sa_type=DateTime)
    updated_by_user_id: int | None = Field(default=None)
    row_version: int = Field(default=1)
    created_at: datetime.datetime | None = Field(default_factory=_cbom_utcnow, sa_type=DateTime)
    last_updated: datetime.datetime | None = Field(default_factory=_cbom_utcnow, sa_type=DateTime)


class CbomQ0Gap(SQLModel, table=True):
    """One opening of a Q0 item of the team's quantum risk register (CB-23 PR-A): an evidence area or vendor at E0,
    an unread scope, an asset whose class is unknown, a missing Mosca input. Open while ``closed_at`` is NULL; at most
    one open row per (team, kind, key) (partial unique index); closing writes the cause and the grade it closed to,
    and a later reopening is a new row with a new ``opened_at`` (so a new ``q0_closed`` dedupe key)."""
    __tablename__ = "cbomq0gap"
    __table_args__ = (
        _SaIndex("uq_cbomq0gap_open_item", "team_id", "item_kind", "item_key", unique=True,
                 postgresql_where=_sa_text("closed_at IS NULL"), sqlite_where=_sa_text("closed_at IS NULL")),
        _SaIndex("ix_cbomq0gap_team_closed_opened", "team_id", "closed_at", "opened_at"),
    )
    id: int | None = Field(default=None, primary_key=True)
    team_id: int = Field(foreign_key="team.id")
    item_kind: str = Field(max_length=16)  # evidence | scope | asset | inputs
    item_key: str = Field(max_length=128)
    reason: str = Field(max_length=32)  # the Q0 reason code (qgrade.REASONS); evidence: evidence_e0 + detail.sub_reason
    detail: Dict | None = Field(default_factory=dict, sa_column=Column(JSON))
    opened_at: datetime.datetime = Field(default_factory=_cbom_utcnow, sa_type=DateTime)
    as_of: str | None = Field(default=None, max_length=10)  # the day the server last judged it (YYYY-MM-DD)
    last_seen_at: datetime.datetime | None = Field(default=None, sa_type=DateTime)
    closed_at: datetime.datetime | None = Field(default=None, sa_type=DateTime)
    close_cause: str | None = Field(default=None, max_length=16)  # evidence|removed|observation|inputs|model_change
    closed_grade: str | None = Field(default=None, max_length=2)  # Q1..Q4 when known, else NULL (no grade)
    run_id: int | None = Field(default=None)  # the run that last saw it (scope / asset / inputs items)


class CbomRiskRegister(SQLModel, table=True):
    """The team's quantum risk register (CB-23 PR-B): one row per estate asset key (CB-20/CB-21) with its CURRENT
    grade (the team's inputs now, the current grade model) and what a CISO filters on. Written by the estate hook
    only for keys whose graded content, inputs or model changed (``grade_digest``), and by the background re-grade
    after an inputs or model change. ``q_rank``: Q1 1 .. Q4 4, Q0 5, no grade 6 (the list's keyset order)."""
    __tablename__ = "cbomriskregister"
    __table_args__ = (UniqueConstraint("team_id", "item_key", name="uq_cbomriskregister_team_key"),
                      _SaIndex("ix_cbomriskregister_team_rank_key", "team_id", "q_rank", "item_key"),
                      _SaIndex("ix_cbomriskregister_team_reason", "team_id", "q_reason"),
                      # CB-32 (1.5M rows): a filtered list walks its filter's index in list order; the summary is one
                      # index-only GROUP BY
                      _SaIndex("ix_cbomriskregister_team_source_rank", "team_id", "source_ref", "q_rank", "item_key"),
                      _SaIndex("ix_cbomriskregister_team_app_rank", "team_id", "application", "q_rank", "item_key"),
                      _SaIndex("ix_cbomriskregister_team_reason_rank", "team_id", "q_reason", "q_rank", "item_key"),
                      _SaIndex("ix_cbomriskregister_team_unpresent_rank", "team_id", "presence", "q_rank", "item_key",
                               postgresql_where=_sa_text("presence <> 'present'"),
                               sqlite_where=_sa_text("presence <> 'present'")),
                      _SaIndex("ix_cbomriskregister_team_summary", "team_id", "q_grade", "q_reason", "family",
                               "presence"),
                      _SaIndex("ix_cbomriskregister_team_model_inputs", "team_id", "model_version", "inputs_digest"),
                      _SaIndex("ix_cbomriskregister_team_live", "team_id",
                               postgresql_where=_sa_text("presence <> 'removed'"),
                               sqlite_where=_sa_text("presence <> 'removed'")),
                      _SaIndex("ix_cbomriskregister_team_family_source_grade", "team_id", "family", "source_ref",
                               "q_grade"))
    id: int | None = Field(default=None, primary_key=True)
    team_id: int = Field(foreign_key="team.id")
    item_key: str = Field(max_length=64)  # the estate asset key
    item_kind: str = Field(default="asset", max_length=16)
    q_grade: str | None = Field(default=None, max_length=2)  # Q0..Q4, NULL = no grade
    q_rank: int = Field(default=6)
    q_reason: str = Field(max_length=32)
    label: str | None = Field(default=None, max_length=255)
    asset_type: str | None = Field(default=None, max_length=32)
    family: str | None = Field(default=None, max_length=32)
    source_ref: str | None = Field(default=None, max_length=255)  # the observation the grade comes from
    source_name: str | None = Field(default=None, max_length=255)
    application: str | None = Field(default=None, max_length=128)
    exposure: str | None = Field(default=None, max_length=16)
    presence: str = Field(default="present", max_length=16)
    sources: int = Field(default=1)  # observations (sources) of the key
    last_run_id: int | None = Field(default=None)
    last_observed_at: datetime.datetime | None = Field(default=None, sa_type=DateTime)
    model_version: str = Field(max_length=32)
    inputs_digest: str = Field(max_length=16)
    grade_digest: str = Field(max_length=16)
    updated_at: datetime.datetime | None = Field(default=None, sa_type=DateTime)


# ========================================= estate store (CB-20) =========================================
# CB-32 partial-index predicates (the queries in estate / agility_store / agility_rollup repeat them verbatim, so the
# planner matches them)
_AGILITY_LIVE = "presence <> 'removed' AND fix_class IS NOT NULL"
_NOT_CORRELATED_LIVE = "key_kind = 'not_correlated' AND presence <> 'removed'"
_RECHECK = "presence <> 'removed' AND fix_recheck_on IS NOT NULL"
_UNREAD_MOVED = ("presence = 'not_read' AND (fix_job_id <> seen_job_id OR fix_attempt <> seen_attempt)")
class CbomEstateSource(SQLModel, table=True):
    """Per team and source (``source_ref`` = the source uid): the newest collect job the estate store has written.
    A PRESENT observation of the source was read in this job (its row: ``(latest_job_id, latest_attempt,
    observation.row_key)``), so present observations are not rewritten every run (CB-20 scale budget)."""
    __tablename__ = "cbomestatesource"
    __table_args__ = (UniqueConstraint("team_id", "source_ref", name="uq_cbomestatesource_team_source"),)
    id: int | None = Field(default=None, primary_key=True)
    team_id: int = Field(foreign_key="team.id")
    source_ref: str = Field(max_length=255)
    source_id: int | None = Field(default=None)
    source_name: str | None = Field(default=None, max_length=255)
    source_kind: str | None = Field(default=None, max_length=32)
    latest_job_id: int = Field()
    latest_attempt: int = Field(default=1)
    latest_run_id: int | None = Field(default=None)
    latest_at: datetime.datetime | None = Field(default=None, sa_type=DateTime)
    latest_status: str = Field(max_length=16)  # the job's status: success | failed | cancelled ...
    latest_comparable: bool = Field(default=False)  # drift.job_comparable: a complete collection
    updated_at: datetime.datetime | None = Field(default=None, sa_type=DateTime)
    # #352: the latest job each estate hook has brought this source's present observations up to (written by the
    # hook, never by the store). Agility: every present observation's stored class holds for this job, so a re-read
    # rewrites only the observations whose row changed. Register: the grades of the source's present observations
    # were computed from this job's rows. NULL: not known (a new source, a hook that never ran).
    fix_through_job_id: int | None = Field(default=None)
    fix_through_attempt: int | None = Field(default=None)
    register_through_job_id: int | None = Field(default=None)
    register_through_attempt: int | None = Field(default=None)


class CbomAgilityBaseline(SQLModel, table=True):
    """CB-25: the team's crypto-agility baseline written once per run (``agility_store``, an estate hook): what
    ``GET /{team}/cbom/agility`` said when the run's estate write finished."""
    __tablename__ = "cbomagilitybaseline"
    __table_args__ = (UniqueConstraint("team_id", "run_id", name="uq_cbomagilitybaseline_team_run"),)
    id: int | None = Field(default=None, primary_key=True)
    team_id: int = Field(foreign_key="team.id")
    run_id: int = Field()
    scope: str = Field(default="enterprise", max_length=16)
    agility_version: str = Field(max_length=32)
    assets: int = Field(default=0)
    self_fixable_pct: float | None = Field(default=None)
    counts: Dict | None = Field(default_factory=dict, sa_column=Column(JSON))
    counts_excl_pq: Dict | None = Field(default_factory=dict, sa_column=Column(JSON))
    unknown_reasons: Dict | None = Field(default_factory=dict, sa_column=Column(JSON))
    systems: list | None = Field(default_factory=list, sa_column=Column(JSON))  # at most 2,000, largest first
    systems_truncated: bool = Field(default=False)
    created_at: datetime.datetime | None = Field(default=None, sa_type=DateTime)


class CbomEstateLink(SQLModel, table=True):
    """Engine step 3 (correlate): an estate asset linked to a component of a code or SBOM scan that uses it
    (``estate_links``): a library the store holds that an SBOM scan or a CBOM code scan lists, or a certificate a
    code scan holds (CB-21 certificate link keys). Rebuilt when the team's scans or estate change (fingerprint in
    ``CbomEstateLinkState``), never per request."""
    __tablename__ = "cbomestatelink"
    __table_args__ = (_SaIndex("ix_cbomestatelink_team_key", "team_id", "asset_key"),)
    id: int | None = Field(default=None, primary_key=True)
    team_id: int = Field(foreign_key="team.id")
    asset_key: str = Field(max_length=64)
    kind: str = Field(max_length=8)  # sbom | code
    scan_id: int = Field()
    scan_title: str | None = Field(default=None, max_length=255)
    component: str = Field(max_length=255)
    purl: str | None = Field(default=None, max_length=512)
    match: str = Field(max_length=16)  # purl | name_version | name | cert_key


class CbomEstateLinkState(SQLModel, table=True):
    """Per team: the inputs the stored links were built from (a digest of the latest scans and the estate)."""
    __tablename__ = "cbomestatelinkstate"
    __table_args__ = (UniqueConstraint("team_id", name="uq_cbomestatelinkstate_team"),)
    id: int | None = Field(default=None, primary_key=True)
    team_id: int = Field(foreign_key="team.id")
    fingerprint: str = Field(max_length=64)
    links: int = Field(default=0)
    refreshed_at: datetime.datetime | None = Field(default=None, sa_type=DateTime)


class CbomAgilityGroup(SQLModel, table=True):
    """CB-32 summary: the live classed estate assets of a team per (system, fix class, class without PQ codes,
    unknown reasons), the agility roll-up's GROUP BY kept current by database triggers on ``cbomestateasset`` in the
    writing transaction (``estate_summary``). NULL parts are stored as ''. ``system_label``/``system_kind``: the
    latest written."""
    __tablename__ = "cbomagilitygroup"
    __table_args__ = (UniqueConstraint("team_id", "system_key", "fix_class", "fix_class_excl_pq", "fix_reasons",
                                       name="uq_cbomagilitygroup_team_group"),)
    id: int | None = Field(default=None, primary_key=True)
    team_id: int = Field(foreign_key="team.id")
    system_key: str = Field(default="", max_length=300)
    fix_class: str = Field(max_length=16)
    fix_class_excl_pq: str = Field(default="", max_length=16)
    fix_reasons: str = Field(default="", max_length=200)
    n: int = Field(default=0)
    system_label: str | None = Field(default=None, max_length=255)
    system_kind: str | None = Field(default=None, max_length=16)


class CbomRegisterSummary(SQLModel, table=True):
    """CB-32 summary: the team's risk register rows per (grade, reason, family, presence), the register summary's
    GROUP BY kept current by triggers on ``cbomriskregister`` (``estate_summary``). NULL grade / family stored as ''."""
    __tablename__ = "cbomregistersummary"
    __table_args__ = (UniqueConstraint("team_id", "q_grade", "q_reason", "family", "presence",
                                       name="uq_cbomregistersummary_team_group"),)
    id: int | None = Field(default=None, primary_key=True)
    team_id: int = Field(foreign_key="team.id")
    q_grade: str = Field(default="", max_length=2)
    q_reason: str = Field(max_length=32)
    family: str = Field(default="", max_length=32)
    presence: str = Field(max_length=16)
    n: int = Field(default=0)


class CbomEstateCount(SQLModel, table=True):
    """CB-32 summary: team counters kept by triggers (``estate_summary.COUNTS``): live assets, live not-correlated
    assets, live observations."""
    __tablename__ = "cbomestatecount"
    __table_args__ = (UniqueConstraint("team_id", "kind", name="uq_cbomestatecount_team_kind"),)
    id: int | None = Field(default=None, primary_key=True)
    team_id: int = Field(foreign_key="team.id")
    kind: str = Field(max_length=32)
    n: int = Field(default=0)


def _install_estate_summary(target, connection, **kw):
    """Every create_all (tests, local) installs the summary triggers too (CB-32; migrations do it themselves)."""
    from backend.utilities.cbom_sources import estate_summary_ddl

    estate_summary_ddl.install(connection, only_if_tables=True)


class CbomEstateTeam(SQLModel, table=True):
    """Per team: whether the estate store missed a run's write (it failed and was rolled back to its savepoint while
    drift committed). ``stale`` stays set until ``estate.backfill`` has replayed the team's runs."""
    __tablename__ = "cbomestateteam"
    __table_args__ = (UniqueConstraint("team_id", name="uq_cbomestateteam_team"),)
    id: int | None = Field(default=None, primary_key=True)
    team_id: int = Field(foreign_key="team.id")
    stale: bool = Field(default=False)
    stale_run_id: int | None = Field(default=None)  # the first run whose write was missed
    stale_reason: str | None = Field(default=None, max_length=300)
    stale_at: datetime.datetime | None = Field(default=None, sa_type=DateTime)
    repaired_at: datetime.datetime | None = Field(default=None, sa_type=DateTime)
    updated_at: datetime.datetime | None = Field(default=None, sa_type=DateTime)
    stale_marks: int = Field(default=0, sa_column_kwargs={"server_default": "0"})  # missed writes so far (CB-32): a repair clears only what it saw


class CbomEstateAsset(SQLModel, table=True):
    """One asset of a team's estate, keyed by its cross-source asset key (CB-21; ``obs:<observation key>`` when the
    asset has no cross-source identity or its correlation is missing). Written by ``estate.record_run`` inside the
    drift compare-and-set, only when something about it changed; never graded here (CB-19/CB-23 read its latest
    stored row through ``estate.latest_rows``)."""
    __tablename__ = "cbomestateasset"
    __table_args__ = (UniqueConstraint("team_id", "asset_key", name="uq_cbomestateasset_team_key"),
                      _SaIndex("ix_cbomestateasset_team_type_key", "team_id", "asset_type", "asset_key"),
                      _SaIndex("ix_cbomestateasset_team_presence_key", "team_id", "presence", "asset_key"),
                      _SaIndex("ix_cbomestateasset_team_updated", "team_id", "updated_run_id"),
                      # CB-32: the agility roll-up is one index-only GROUP BY over the live classed assets; its pages
                      # walk a class index in key order; heal finds stale versions and counts not-correlated ones
                      _SaIndex("ix_cbomestateasset_agility_groups", "team_id", "system_key", "fix_class",
                               "fix_class_excl_pq", "fix_reasons", postgresql_include=["system_label", "system_kind"],
                               postgresql_where=_sa_text(_AGILITY_LIVE), sqlite_where=_sa_text(_AGILITY_LIVE)),
                      _SaIndex("ix_cbomestateasset_agility_class", "team_id", "fix_class", "asset_key",
                               postgresql_where=_sa_text(_AGILITY_LIVE), sqlite_where=_sa_text(_AGILITY_LIVE)),
                      _SaIndex("ix_cbomestateasset_agility_class_excl", "team_id", "fix_class_excl_pq", "asset_key",
                               postgresql_where=_sa_text(_AGILITY_LIVE), sqlite_where=_sa_text(_AGILITY_LIVE)),
                      _SaIndex("ix_cbomestateasset_team_fix_version", "team_id", "fix_version",
                               postgresql_where=_sa_text("presence <> 'removed'"),
                               sqlite_where=_sa_text("presence <> 'removed'")),
                      _SaIndex("ix_cbomestateasset_team_live", "team_id", postgresql_where=_sa_text("presence <> 'removed'"),
                               sqlite_where=_sa_text("presence <> 'removed'")),
                      _SaIndex("ix_cbomestateasset_team_not_correlated", "team_id",
                               postgresql_where=_sa_text(_NOT_CORRELATED_LIVE),
                               sqlite_where=_sa_text(_NOT_CORRELATED_LIVE)))
    id: int | None = Field(default=None, primary_key=True)
    team_id: int = Field(foreign_key="team.id")
    asset_key: str = Field(max_length=64)
    key_kind: str = Field(max_length=16)  # cross | source | not_correlated
    key_basis: str | None = Field(default=None, max_length=16)  # certificate | endpoint | cloud (cross keys)
    asset_type: str = Field(max_length=32)
    label: str | None = Field(default=None, max_length=255)
    presence: str = Field(default="present", max_length=16)  # present | not_read | removed
    presence_reason: str | None = Field(default=None, max_length=300)
    first_seen_run_id: int | None = Field(default=None)
    first_seen_at: datetime.datetime | None = Field(default=None, sa_type=DateTime)
    updated_run_id: int = Field(default=0)  # the run whose write last changed the row
    updated_at: datetime.datetime | None = Field(default=None, sa_type=DateTime)
    # CB-25 crypto-agility (``agility_store``): the asset's fix class, hardest across its observations; its system is
    # its latest observation's. Roll-ups are a GROUP BY on (team_id, system_key, fix_class). NULL = not computed yet.
    fix_class: str | None = Field(default=None, max_length=16)
    fix_class_excl_pq: str | None = Field(default=None, max_length=16)
    fix_floor: str | None = Field(default=None, max_length=16)
    fix_reasons: str | None = Field(default=None, max_length=200)  # unknown reasons, comma-joined, sorted
    fix_codes: str | None = Field(default=None, max_length=300)  # the codes that decided the class, comma-joined
    fix_version: str | None = Field(default=None, max_length=32)  # agility.version() it was computed with
    fix_at: datetime.datetime | None = Field(default=None, sa_type=DateTime)  # its latest observation's time
    system_key: str | None = Field(default=None, max_length=300)
    system_label: str | None = Field(default=None, max_length=255)
    system_kind: str | None = Field(default=None, max_length=16)
    fix_observations: int | None = Field(default=None)


class CbomEstateObservation(SQLModel, table=True):
    """One estate asset as one source last read it. ``seen_*``: the job that last read it, for an observation that
    is not present any more (a present one was read in the source's latest job, ``CbomEstateSource``)."""
    __tablename__ = "cbomestateobservation"
    __table_args__ = (UniqueConstraint("team_id", "asset_key", "source_ref", name="uq_cbomestateobs_team_key_source"),
                      # CB-32: a source's observations in key order (present_keys, the source filter of the estate
                      # list); the live count; heal's stale probes (version, recheck day, pointer moved)
                      _SaIndex("ix_cbomestateobs_team_source_key", "team_id", "source_ref", "asset_key"),
                      _SaIndex("ix_cbomestateobs_team_live", "team_id", postgresql_where=_sa_text("presence <> 'removed'"),
                               sqlite_where=_sa_text("presence <> 'removed'")),
                      _SaIndex("ix_cbomestateobs_team_fix_version", "team_id", "fix_version",
                               postgresql_where=_sa_text("presence <> 'removed'"),
                               sqlite_where=_sa_text("presence <> 'removed'")),
                      _SaIndex("ix_cbomestateobs_team_recheck", "team_id", "fix_recheck_on",
                               postgresql_where=_sa_text(_RECHECK), sqlite_where=_sa_text(_RECHECK)),
                      _SaIndex("ix_cbomestateobs_present_fix", "team_id", "source_ref", "fix_job_id", "fix_attempt",
                               postgresql_where=_sa_text("presence = 'present'"),
                               sqlite_where=_sa_text("presence = 'present'")),
                      _SaIndex("ix_cbomestateobs_unread_fix_moved", "team_id", postgresql_where=_sa_text(_UNREAD_MOVED),
                               sqlite_where=_sa_text(_UNREAD_MOVED)))
    id: int | None = Field(default=None, primary_key=True)
    team_id: int = Field(foreign_key="team.id")
    asset_key: str = Field(max_length=64)
    source_ref: str = Field(max_length=255)
    observation_key: str = Field(max_length=40)  # identity.stable_key: what drift compares within the source
    row_key: str = Field(max_length=64)  # cbomcollectedasset.asset_key of the observed row (unique per job attempt)
    asset_type: str = Field(max_length=32)
    target: str | None = Field(default=None, max_length=255)
    location: str | None = Field(default=None, max_length=512)
    occurrences: int = Field(default=1)  # rows of the job with this asset key (one certificate in many chains)
    presence: str = Field(default="present", max_length=16)  # present | not_read | removed
    presence_reason: str | None = Field(default=None, max_length=300)
    seen_job_id: int = Field()
    seen_attempt: int = Field(default=1)
    seen_run_id: int | None = Field(default=None)
    seen_at: datetime.datetime | None = Field(default=None, sa_type=DateTime)
    first_seen_run_id: int | None = Field(default=None)
    state_run_id: int = Field(default=0)  # the run whose write last changed the row
    updated_at: datetime.datetime | None = Field(default=None, sa_type=DateTime)
    # CB-25 crypto-agility of this observation's latest row (``agility_store``), with the job it was computed from
    fix_class: str | None = Field(default=None, max_length=16)
    fix_class_excl_pq: str | None = Field(default=None, max_length=16)
    fix_floor: str | None = Field(default=None, max_length=16)
    fix_reasons: str | None = Field(default=None, max_length=200)
    fix_codes: str | None = Field(default=None, max_length=300)
    fix_version: str | None = Field(default=None, max_length=32)
    fix_job_id: int | None = Field(default=None)
    fix_attempt: int | None = Field(default=None)
    fix_recheck_on: datetime.date | None = Field(default=None)  # a date-based rule may change the class from then
    fix_at: datetime.datetime | None = Field(default=None, sa_type=DateTime)
    system_key: str | None = Field(default=None, max_length=300)
    system_label: str | None = Field(default=None, max_length=255)
    system_kind: str | None = Field(default=None, max_length=16)
    cert_cnb_key: str | None = Field(default=None, max_length=46)  # what a code-scan certificate matches (CN+dates)
    cert_cn_key: str | None = Field(default=None, max_length=46)  # CN + notAfter, only when no notBefore was read


# ========================================= integrations (WP11) =========================================
class TeamIntegration(SQLModel, table=True):
    """One outbound integration of a team: ServiceNow, syslog (SIEM), Splunk HEC, signed webhook or OSCAL push.
    Secrets live only in ``secret_encrypted`` (Fernet over a JSON object) and are never serialised to a browser.
    ``lease_until`` lets one dispatcher at a time deliver this integration's queue (in order);
    ``failures`` / ``next_attempt_at`` are its back-off after a failed delivery."""
    __tablename__ = "teamintegration"
    __table_args__ = (UniqueConstraint("team_id", "kind", name="uq_teamintegration_team_kind"),)
    id: int | None = Field(default=None, primary_key=True)
    team_id: int = Field(foreign_key="team.id", index=True)
    kind: str = Field(max_length=16)
    enabled: bool = Field(default=False)
    config: Dict | None = Field(default_factory=dict, sa_column=Column(JSON))
    secret_encrypted: str | None = Field(default=None, sa_type=Text)
    secret_fields: list | None = Field(default_factory=list, sa_column=Column(JSON))
    last_test_status: str = Field(default="never", max_length=16)  # never | ok | failed
    last_test_at: datetime.datetime | None = Field(default=None, sa_type=DateTime)
    last_test_message: str | None = Field(default=None, max_length=255)
    lease_until: datetime.datetime | None = Field(default=None, sa_type=DateTime)
    failures: int = Field(default=0)
    next_attempt_at: datetime.datetime | None = Field(default=None, sa_type=DateTime)
    last_delivery_at: datetime.datetime | None = Field(default=None, sa_type=DateTime)
    last_error: str | None = Field(default=None, max_length=255)
    updated_by_user_id: int | None = Field(default=None)
    row_version: int = Field(default=1)
    created_at: datetime.datetime | None = Field(default_factory=_cbom_utcnow, sa_type=DateTime)
    last_updated: datetime.datetime | None = Field(default_factory=_cbom_utcnow, sa_type=DateTime)


class IntegrationDelivery(SQLModel, table=True):
    """One event queued for one integration (at least once: ``event_uid`` is the same on every retry and for every
    destination, so a receiver can drop duplicates). pending -> delivered, or dead (dead-letter list, retryable)."""
    __tablename__ = "integrationdelivery"
    __table_args__ = (UniqueConstraint("integration_id", "event_uid", name="uq_integrationdelivery_event"),)
    id: int | None = Field(default=None, primary_key=True)
    team_id: int = Field(foreign_key="team.id", index=True)
    integration_id: int = Field(foreign_key="teamintegration.id", index=True, ondelete="CASCADE")
    kind: str = Field(max_length=16)  # the integration's kind (denormalised for the log)
    event_uid: str = Field(max_length=36)
    event_type: str = Field(max_length=32)  # finding.opened, scan.finished, ...
    payload: Dict | None = Field(default_factory=dict, sa_column=Column(JSON))
    status: str = Field(default="pending", max_length=16, index=True)  # pending | delivered | dead
    attempts: int = Field(default=0)
    last_attempt_at: datetime.datetime | None = Field(default=None, sa_type=DateTime)
    delivered_at: datetime.datetime | None = Field(default=None, sa_type=DateTime)
    last_result: str | None = Field(default=None, max_length=255)  # status code and a short reason, never a body
    external_ref: str | None = Field(default=None, max_length=64)  # e.g. the ServiceNow record number
    created_at: datetime.datetime | None = Field(default_factory=_cbom_utcnow, sa_type=DateTime, index=True)


class CbomOpsCounter(SQLModel, table=True):
    """CB-31 (GAP-MATRIX X1): platform-wide operational counters, served as Prometheus counters by the admin-only
    ``GET /cbom/ops/metrics`` (``ops_metrics``). Each is incremented in the transaction of the event it counts (a
    lease the reaper expired, assets the ingest refused), so every API and worker process adds to the same number
    and a rolled-back event counts nothing. Monotonic: never reset, never pruned."""
    __tablename__ = "cbomopscounter"
    name: str = Field(primary_key=True, max_length=64)
    value: int = Field(default=0, sa_column=Column(_SaBigInteger, nullable=False, server_default="0"))
    updated_at: datetime.datetime | None = Field(default=None, sa_type=DateTime)


# CB-32: the estate summary triggers follow every SQLModel.metadata.create_all
from sqlalchemy import event as _sa_event

_sa_event.listen(SQLModel.metadata, "after_create", _install_estate_summary)


# ========================================= F3: code repositories at scale =========================================
# The F3 tables live in their own module; importing it here registers them on SQLModel.metadata for alembic and
# for everything that imports new_models (it imports nothing from this file, so the import cannot cycle).
from backend.utilities.scm.models import *  # noqa: E402,F401,F403

# ========================================= F4 access management: its tables live in backend/access_models.py
from backend.access_models import *  # noqa: E402,F401,F403  (registers them on SQLModel.metadata with the rest)

# ========================================= PDF reports: the team's report logo lives in backend/branding_models.py
from backend.branding_models import *  # noqa: E402,F401,F403  (registers it on SQLModel.metadata with the rest)

# ========================================= SOW S1 / S2: CBOM gate policy and test tickets live in backend/cbom_gate_models.py
from backend.cbom_gate_models import *  # noqa: E402,F401,F403  (registers them on SQLModel.metadata with the rest)
