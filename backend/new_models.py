import datetime
import uuid
from typing import Dict, Literal
from sqlmodel import JSON, Column, DateTime, Field, SQLModel, String, Relationship
from sqlalchemy import Text, UniqueConstraint
from sqlalchemy import Index as _SaIndex, func as _sa_func
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



# every user is a member of the "default-team" by default when a user is created ⭐
class TeamMembership(SQLModel,table=True): # many-to-many relationship between team and user
    team_id : int | None = Field(default=None,foreign_key="team.id",primary_key=True)
    user_id : int | None = Field(default=None,foreign_key="user.id",primary_key=True)
    role : Literal["admin" , "member"] = Field(default="member",sa_type=String)

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
    email : str
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


class TeamInvitation(SQLModel, table=True):
    """An offer to join a team, mailed as a link to /invite/<token>; nobody joins until the invitee accepts.

    The token is stored only as its SHA-256 (``token_hash``) and works once: accepting, declining, revoking or
    resending clears or replaces it.  One row per (team, address): inviting the address again reuses it.
    Times are naive UTC.  The inviter is a plain int so deleting that user is never blocked."""
    __table_args__ = (UniqueConstraint("team_id", "email", name="uq_teaminvitation_team_email"),)
    id : int | None = Field(default=None, primary_key=True)
    team_id : int = Field(foreign_key="team.id", index=True, ondelete="CASCADE")
    email : str = Field(max_length=254)  # lower-cased, as on sign-up
    token_hash : str | None = Field(default=None, max_length=64, unique=True, index=True)
    status : str = Field(default="pending", max_length=16)  # pending | accepted | declined | revoked
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
    soc_ack_by: int | None = Field(default=None)
    soc_ack_at: datetime.datetime | None = Field(default=None, sa_type=DateTime)
    cancelled_by: int | None = Field(default=None)
    cancelled_at: datetime.datetime | None = Field(default=None, sa_type=DateTime)
    created_at: datetime.datetime | None = Field(default_factory=_cbom_utcnow, sa_type=DateTime)
    last_updated: datetime.datetime | None = Field(default_factory=_cbom_utcnow, sa_type=DateTime)
    finished_at: datetime.datetime | None = Field(default=None, sa_type=DateTime)
    schedule_id: int | None = Field(default=None, index=True)  # set when a schedule started the run
    drift_at: datetime.datetime | None = Field(default=None, sa_type=DateTime)  # drift events recorded (once)


class CbomCollectionJob(SQLModel, table=True):
    """A unit of work for one scan node: test a connection, collect a source, or run a discovery sweep."""
    __tablename__ = "cbomcollectionjob"
    id: int | None = Field(default=None, primary_key=True)
    team_id: int = Field(foreign_key="team.id", index=True)
    run_id: int | None = Field(default=None, foreign_key="cbomcollectionrun.id", index=True)
    source_id: int | None = Field(default=None, foreign_key="cbomcollectionsource.id", index=True)
    node_id: int | None = Field(default=None, foreign_key="cbomscannode.id", index=True)
    kind: str = Field(max_length=16)
    status: str = Field(default="pending", max_length=16, index=True)
    params: Dict | None = Field(default_factory=dict, sa_column=Column(JSON))
    source_version: int | None = Field(default=None)
    weight_c: int = Field(default=0)
    refunded: bool = Field(default=False)
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


class CbomCollectedAsset(SQLModel, table=True):
    """One cryptographic asset a collection job found.  Facts come from the node; impact is ours."""
    __tablename__ = "cbomcollectedasset"
    __table_args__ = (UniqueConstraint("job_id", "attempt", "asset_key", name="uq_cbomcollectedasset_job_attempt_key"),)
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
    facts: Dict | None = Field(default_factory=dict, sa_column=Column(JSON))
    created_at: datetime.datetime | None = Field(default_factory=_cbom_utcnow, sa_type=DateTime)


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
    confidence: str = Field(default="Q0", max_length=2)
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
    confidence: str = Field(default="Q0", max_length=2)
    evidence_url: str | None = Field(default=None, max_length=1000)
    created_by_user_id: int | None = Field(default=None)
    row_version: int = Field(default=1)
    created_at: datetime.datetime | None = Field(default_factory=_cbom_utcnow, sa_type=DateTime)
    last_updated: datetime.datetime | None = Field(default_factory=_cbom_utcnow, sa_type=DateTime)


class CbomCollectionAuditEvent(SQLModel, table=True):
    """Who changed what in CBOM Sources and when; field names only, never values."""
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
    updated_by_user_id: int | None = Field(default=None)
    row_version: int = Field(default=1)
    created_at: datetime.datetime | None = Field(default_factory=_cbom_utcnow, sa_type=DateTime)
    last_updated: datetime.datetime | None = Field(default_factory=_cbom_utcnow, sa_type=DateTime)


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
