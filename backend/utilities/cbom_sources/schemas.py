"""Request bodies for the CBOM Sources API (Pydantic v2).  Per-kind source config lives in kinds.py."""
from __future__ import annotations

import re
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from backend.utilities.cbom_sources.common import NAME_RE
from backend.utilities.cbom_sources.kinds import KIND_NAMES, check_http_url, check_pem_certificates, check_timezone, check_window_grid

_EMAIL_RE = re.compile(r"^[^@\s'\"<>]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,}$")
_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


class _Body(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


def _name(value: str) -> str:
    if not NAME_RE.match(value):
        raise ValueError("use 1-64 letters, digits, spaces, dots, dashes or underscores, starting with a letter or digit")
    return value


# ----------------------------------------------------------------------------- nodes
class NodeCreate(_Body):
    name: str = Field(max_length=64)
    segment: str = Field(default="", max_length=64)
    timezone: str = Field(default="Asia/Kolkata", max_length=64)
    deployment: Literal["docker", "ova", "ami", "helm"] = "docker"
    proxy_url: str | None = Field(default=None, max_length=512)
    proxy_ca_pem: str | None = Field(default=None, max_length=64 * 1024)
    proxy_tls_inspect: bool = False

    _n = field_validator("name")(classmethod(lambda cls, v: _name(v)))

    @field_validator("segment")
    @classmethod
    def _seg(cls, v: str) -> str:
        if v and not NAME_RE.match(v):
            raise ValueError("use letters, digits, spaces, dots, dashes or underscores")
        return v

    @field_validator("timezone")
    @classmethod
    def _tz(cls, v: str) -> str:
        return check_timezone(v)

    @field_validator("proxy_url")
    @classmethod
    def _proxy(cls, v: str | None) -> str | None:
        return check_http_url(v)

    @field_validator("proxy_ca_pem")
    @classmethod
    def _ca(cls, v: str | None) -> str | None:
        return check_pem_certificates(v)


class NodeUpdate(_Body):
    name: str | None = Field(default=None, max_length=64)
    segment: str | None = Field(default=None, max_length=64)
    timezone: str | None = Field(default=None, max_length=64)
    deployment: Literal["docker", "ova", "ami", "helm"] | None = None
    proxy_url: str | None = Field(default=None, max_length=512)
    proxy_ca_pem: str | None = Field(default=None, max_length=64 * 1024)
    proxy_tls_inspect: bool | None = None
    expected_version: int | None = None

    @field_validator("name")
    @classmethod
    def _n(cls, v: str | None) -> str | None:
        return _name(v) if v is not None else None

    @field_validator("segment")
    @classmethod
    def _seg(cls, v: str | None) -> str | None:
        if v and not NAME_RE.match(v):
            raise ValueError("use letters, digits, spaces, dots, dashes or underscores")
        return v

    @field_validator("timezone")
    @classmethod
    def _tz(cls, v: str | None) -> str | None:
        return check_timezone(v) if v is not None else None

    @field_validator("proxy_url")
    @classmethod
    def _proxy(cls, v: str | None) -> str | None:
        return check_http_url(v)

    @field_validator("proxy_ca_pem")
    @classmethod
    def _ca(cls, v: str | None) -> str | None:
        return check_pem_certificates(v)


# ----------------------------------------------------------------------------- sources
class SourceCreate(_Body):
    kind: str
    name: str = Field(max_length=64)
    node_id: int | None = Field(default=None, ge=1)
    enabled: bool = True
    config: dict[str, Any] = Field(default_factory=dict)
    secrets: dict[str, str] = Field(default_factory=dict)
    test_after_save: bool = False

    _n = field_validator("name")(classmethod(lambda cls, v: _name(v)))

    @field_validator("kind")
    @classmethod
    def _kind(cls, v: str) -> str:
        if v not in KIND_NAMES:
            raise ValueError("unknown source kind")
        return v


class SourceUpdate(_Body):
    kind: str | None = None
    name: str | None = Field(default=None, max_length=64)
    node_id: int | None = Field(default=None, ge=1)
    clear_node: bool = False
    enabled: bool | None = None
    config: dict[str, Any] | None = None
    secrets: dict[str, str] = Field(default_factory=dict)
    clear_secrets: list[str] = Field(default_factory=list, max_length=10)
    expected_version: int | None = None
    test_after_save: bool = False

    @field_validator("name")
    @classmethod
    def _n(cls, v: str | None) -> str | None:
        return _name(v) if v is not None else None


# ----------------------------------------------------------------------------- settings
class ExclusionItem(_Body):
    cidr: str = Field(max_length=64)
    reason: str = Field(default="", max_length=120)


class PortItem(_Body):
    port: int = Field(ge=1, le=65535)
    protocol: Literal["tls", "starttls-ldap", "starttls-smtp", "starttls-imap", "starttls-postgres",
                      "starttls-mysql", "tds", "ssh", "rdp", "ike",
                      "opcua", "modbus", "modbus-tls"] = "tls"
    label: str = Field(default="", max_length=40)


class RiskModel(_Body):
    """Mosca inputs, in years. All three are needed for a verdict; null clears one."""
    data_shelf_life_years: int | None = Field(default=None, ge=0, le=100, strict=True)
    migration_years: int | None = Field(default=None, ge=0, le=100, strict=True)
    threat_years: int | None = Field(default=None, ge=0, le=100, strict=True)


class SettingsUpdate(_Body):
    cert_domains: list[str] | None = Field(default=None, max_length=200)
    network_exclusions: list[ExclusionItem] | None = Field(default=None, max_length=500)
    sni_hostnames: list[str] | None = Field(default=None, max_length=10_000)
    ports: list[PortItem] | None = Field(default=None, max_length=64)
    zeek_span: bool | None = None
    scan_window: list[list[bool]] | None = None
    window_timezone: str | None = Field(default=None, max_length=64)
    rate_conn_per_s: int | None = Field(default=None, ge=1, le=500)
    rate_parallel_per_server: int | None = Field(default=None, ge=1, le=32)
    rate_handshakes_per_endpoint: int | None = Field(default=None, ge=1, le=200)
    soc_email: str | None = Field(default=None, max_length=254)
    emergency_contact: str | None = Field(default=None, max_length=64)
    risk_model: RiskModel | None = None
    require_signed_nodes: bool | None = None
    expected_version: int | None = None

    @field_validator("scan_window")
    @classmethod
    def _grid(cls, v: list[list[bool]] | None) -> list[list[bool]] | None:
        if v is None:
            return None
        return check_window_grid(v, allow_empty=False)

    @field_validator("window_timezone")
    @classmethod
    def _tz(cls, v: str | None) -> str | None:
        return check_timezone(v) if v is not None else None

    @field_validator("soc_email")
    @classmethod
    def _email(cls, v: str | None) -> str | None:
        if v and not _EMAIL_RE.match(v):
            raise ValueError("enter a valid email address")
        return v or None

    @field_validator("emergency_contact")
    @classmethod
    def _phone(cls, v: str | None) -> str | None:
        if v and not re.match(r"^[0-9+()\- ]{3,64}$", v):
            raise ValueError("enter a phone number (digits, spaces, + - ( ))")
        return v or None


class StopAll(_Body):
    on: bool


# ----------------------------------------------------------------------------- runs
INCLUDE_KEYS = ("servers", "kubernetes", "databases", "cloud", "network")


class Include(_Body):
    servers: bool = False
    kubernetes: bool = False
    databases: bool = False
    cloud: bool = False
    network: bool = False


class EstimateBody(_Body):
    include: Include = Field(default_factory=lambda: Include(servers=True, kubernetes=True, databases=True, cloud=True, network=True))
    source_ids: list[int] | None = Field(default=None, max_length=500)


class RunCreate(_Body):
    include: Include
    source_ids: list[int] | None = Field(default=None, max_length=500)
    scan_id: int | None = Field(default=None, ge=1)
    client_request_id: str = Field(min_length=8, max_length=64)
    expected_credits: float | None = Field(default=None, ge=0)
    soc_ack: bool = False

    @field_validator("client_request_id")
    @classmethod
    def _rid(cls, v: str) -> str:
        if not re.match(r"^[A-Za-z0-9_-]{8,64}$", v):
            raise ValueError("client_request_id must be 8-64 letters, digits, - or _")
        return v


# ----------------------------------------------------------------------------- evidence
class AreaUpdate(_Body):
    owner: str | None = Field(default=None, max_length=128)
    confidence: Literal["Q0", "Q1", "Q2", "Q3"] | None = None
    answers: dict[str, str] | None = None
    evidence_title: str | None = Field(default=None, max_length=200)
    evidence_url: str | None = Field(default=None, max_length=1000)
    evidence_date: str | None = Field(default=None, max_length=10)
    due_date: str | None = Field(default=None, max_length=10)
    expected_version: int | None = None

    @field_validator("evidence_url")
    @classmethod
    def _url(cls, v: str | None) -> str | None:
        return check_http_url(v)

    @field_validator("evidence_date", "due_date")
    @classmethod
    def _date(cls, v: str | None) -> str | None:
        if v is None or v == "":
            return None
        if not _DATE_RE.match(v):
            raise ValueError("use a date like 2026-11-07")
        import datetime as _dt

        _dt.date.fromisoformat(v)
        return v


class VendorCreate(_Body):
    name: str = Field(min_length=1, max_length=128)
    contact_email: str | None = Field(default=None, max_length=254)

    @field_validator("contact_email")
    @classmethod
    def _email(cls, v: str | None) -> str | None:
        if v and not _EMAIL_RE.match(v):
            raise ValueError("enter a valid email address")
        return v or None


class VendorUpdate(VendorCreate):
    name: str | None = Field(default=None, min_length=1, max_length=128)
    confidence: Literal["Q0", "Q1", "Q2", "Q3"] | None = None
    expected_version: int | None = None


class VendorAnswer(_Body):
    answers: dict[str, str] = Field(default_factory=dict)
    evidence_url: str | None = Field(default=None, max_length=1000)

    @field_validator("evidence_url")
    @classmethod
    def _url(cls, v: str | None) -> str | None:
        return check_http_url(v)


# ----------------------------------------------------------------------------- node API
class EnrollBody(_Body):
    registration_token: str = Field(min_length=10, max_length=128)
    hostname: str | None = Field(default=None, max_length=255)
    version: str | None = Field(default=None, max_length=32)
    source_ips: list[str] = Field(default_factory=list, max_length=32)
    ssh_public_key: str | None = Field(default=None, max_length=8192)
    capabilities: dict[str, Any] = Field(default_factory=dict)
    clock: str | None = Field(default=None, max_length=40)
    # base64 of the raw 32-byte Ed25519 key the node signs its requests with (absent: an older, unsigned node)
    signing_public_key: str | None = Field(default=None, max_length=64)
    # ZS_MODE=agent: the node collects only its own host (a pool token always enrolls agent nodes); node_name is the
    # Kubernetes node name a DaemonSet pod enrolls under (WP8b)
    mode: Literal["agent", "agentless"] | None = None
    node_name: str | None = Field(default=None, max_length=253)
    # a pod enrolling again with an agent pool token after a 401: the node id it had (a reset node is taken back)
    node_id: int | None = Field(default=None, ge=1, le=2_147_483_647)

    @field_validator("signing_public_key")
    @classmethod
    def _signing_key(cls, v: str | None) -> str | None:
        if v is None:
            return None
        from backend.utilities.cbom_sources.node_auth import load_public_key

        load_public_key(v)  # ValueError -> 400
        return v


class PoolCreate(_Body):
    """An agent pool registration token (WP8b): many agent-mode nodes enroll with it, each as its own node."""
    name: str = Field(max_length=64)
    segment: str = Field(default="", max_length=64)
    expires_in_hours: int = Field(default=24 * 7, ge=1, le=24 * 90)
    max_enrollments: int = Field(default=50, ge=1, le=1_000_000)  # capped by CBOM_MAX_POOL_ENROLLMENTS at create

    _n = field_validator("name")(classmethod(lambda cls, v: _name(v)))

    @field_validator("segment")
    @classmethod
    def _seg(cls, v: str) -> str:
        if v and not NAME_RE.match(v):
            raise ValueError("use letters, digits, spaces, dots, dashes or underscores")
        return v


class RunningJob(_Body):
    job_id: int = Field(ge=1, le=2_147_483_647)
    lease_id: str = Field(min_length=8, max_length=32)


class HeartbeatBody(_Body):
    # None: an older node that does not report its jobs (every claimed job is renewed).
    running: list[RunningJob] | None = Field(default=None, max_length=64)
    hostname: str | None = Field(default=None, max_length=255)
    version: str | None = Field(default=None, max_length=32)
    source_ips: list[str] = Field(default_factory=list, max_length=32)
    capabilities: dict[str, Any] = Field(default_factory=dict)
    clock: str | None = Field(default=None, max_length=40)
    last_error: str | None = Field(default=None, max_length=2000)


class ClaimBody(_Body):
    # the mode the node runs in now (older nodes send no body): a node reporting agent mode is never given a secret
    mode: Literal["agent", "agentless"] | None = None


class ResultBody(_Body):
    lease_id: str = Field(min_length=8, max_length=32)
    status: Literal["success", "failure", "cancelled"]
    result: dict[str, Any] = Field(default_factory=dict)
    error: str | None = Field(default=None, max_length=4000)

    @model_validator(mode="after")
    def _check(self) -> "ResultBody":
        if self.status == "failure" and not self.error:
            self.error = "The scan node reported a failure"
        return self


class AssetIn(BaseModel):
    """One asset from a node.  Unknown keys are ignored; the server classifies, the node only reports facts."""
    model_config = ConfigDict(extra="ignore")
    type: str = Field(max_length=32)
    target: str | None = Field(default=None, max_length=255)
    location: str = Field(min_length=1, max_length=512)
    name: str | None = Field(default=None, max_length=255)
    algorithm: str | None = Field(default=None, max_length=64)
    key_size: int | None = Field(default=None, ge=0, le=1_000_000)
    protocol: str | None = Field(default=None, max_length=32)
    facts: dict[str, Any] = Field(default_factory=dict)

    @field_validator("facts")
    @classmethod
    def _facts_size(cls, v: dict[str, Any]) -> dict[str, Any]:
        import json

        if len(json.dumps(v, default=str)) > 16 * 1024:
            raise ValueError("facts larger than 16 KB")
        return v


class JobProgress(_Body):
    """A network range while it runs: addresses swept (or skipped) so far, of the addresses in scope."""
    done: int = Field(ge=0, le=16_777_216)
    total: int = Field(ge=0, le=16_777_216)


class AssetsBody(_Body):
    lease_id: str = Field(min_length=8, max_length=32)
    batch_id: str | None = Field(default=None, max_length=64)
    assets: list[dict[str, Any]] = Field(default_factory=list, max_length=500)
    # sent by nodes from round 5 on, for network ranges only (older nodes send none: nothing is shown)
    progress: JobProgress | None = None
