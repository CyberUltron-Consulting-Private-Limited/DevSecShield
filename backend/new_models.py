import datetime
from typing import Dict, Literal
from sqlmodel import JSON, Column, DateTime, Field, SQLModel, String, Relationship
from sqlalchemy import Text, UniqueConstraint
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

    # many-to-many relationship between user and team
    team_memberships : list[TeamMembership] = Relationship(back_populates="user")

    # guardrails integrations that this user owns 
    guardrails_integrations : list["GuardrailsIntegration"] = Relationship(back_populates="owner_user")

    # cicd integrations that this user owns 
    cicd_integrations : list["CicdIntegration"] = Relationship(back_populates="owner_user")

    # scans that this user owns 
    scans : list["Scan"] = Relationship(back_populates="owner_user")

    dast_profiles : list["DastScanProfile"] = Relationship(back_populates="owner_user")
    

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
    scan_status : Literal["pending" , "started" , "retry" , "failure" , "success" , "NOT_STARTED"] = Field(default="NOT_STARTED",sa_type=String)
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
    row_version: int = Field(default=1)
    created_at: datetime.datetime | None = Field(default_factory=_cbom_utcnow, sa_type=DateTime)
    last_updated: datetime.datetime | None = Field(default_factory=_cbom_utcnow, sa_type=DateTime)


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
    rate_handshakes_per_endpoint: int = Field(default=12)
    soc_email: str | None = Field(default=None, max_length=254)
    emergency_contact: str | None = Field(default=None, max_length=64)
    stop_all_network: bool = Field(default=False)
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
