"""Per-kind configuration, secret rules and grouping for CBOM collection sources.

Each kind has a Pydantic model for its non-secret ``config``, a function that says which secret
fields the chosen credential type needs, and the list of "where it is used" fields: changing any of
those clears stored secrets unless they are re-entered, so a password can never be redirected to a
new host by someone who cannot see it.
"""
from __future__ import annotations

import re
import zoneinfo
from dataclasses import dataclass
from typing import Any, Callable, Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_serializer, model_validator

from backend.utilities.cbom_sources import targets as T

MAX_SECRET_BYTES = 256 * 1024
MAX_PEM_BYTES = 64 * 1024

GROUPS = ("servers", "kubernetes", "databases", "cloud", "identity", "network")

VaultProvider = Literal["hashicorp", "cyberark", "aws_secrets_manager", "azure_key_vault"]
_HOST_RE = re.compile(r"^[A-Za-z0-9._:-]{1,253}$")
_LOGIN_RE = re.compile(r"^[A-Za-z0-9._@$\\-]{1,64}$")
_UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_AWS_ROLE_RE = re.compile(r"^arn:aws(-cn|-us-gov)?:iam::(\d{12}):role/[A-Za-z0-9+=,.@_/-]{1,512}$")
AWS_REGION_RE = re.compile(r"^[a-z]{2}(-gov|-iso[a-z]?)?-[a-z]+-\d$")


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


Criticality = Literal["low", "medium", "high", "critical"]


Exposure = Literal["internet", "internal", "unknown"]
DataClassification = Literal["public", "internal", "confidential", "restricted"]


def _metadata_text(value: str | None) -> str | None:
    if value is None:
        return None
    text = "".join(ch for ch in value if ch >= " " and ch != "\x7f").strip()
    return text or None


class _Source(_Strict):
    """Fields every source has: METADATA about the source, never about how to reach it.

    * business_criticality scales the risk score of what the source finds;
    * exposure overrides the internet exposure derived from the collected facts (risk x 1.5 when internet-facing);
    * owner, application, data_classification and data_lifetime_years say who answers for the source, which
      application it serves and how sensitive / long-lived its data is (remediation owners, roadmap, Mosca X);
    * environment (production, staging, ... as the CMDB names it) comes from a CMDB import or the form.

    Every field declared here is metadata (``METADATA_FIELDS``): editing it never cancels a job or resets the
    connection test, a source form that does not send it keeps the stored value (send null to clear), and a run
    snapshots it on its jobs when it is created.
    """
    business_criticality: Criticality | None = None
    exposure: Exposure | None = None
    owner: str | None = Field(default=None, max_length=128)
    application: str | None = Field(default=None, max_length=128)
    data_classification: DataClassification | None = None
    data_lifetime_years: int | None = Field(default=None, ge=0, le=100)
    environment: str | None = Field(default=None, max_length=32)

    @field_validator("owner", "application", "environment")
    @classmethod
    def _plain_text(cls, v: str | None) -> str | None:
        return _metadata_text(v)


class VaultRef(_Strict):
    provider: VaultProvider
    path: str = Field(min_length=1, max_length=512)


def check_pem_certificates(value: str | None) -> str | None:
    if value is None or value.strip() == "":
        return None
    text = value.replace("\r\n", "\n").replace("\r", "\n").strip() + "\n"
    if len(text.encode()) > MAX_PEM_BYTES:
        raise ValueError("certificate is larger than 64 KB")
    if "PRIVATE KEY" in text:
        raise ValueError("paste the CA certificate, not a private key")
    from cryptography import x509

    try:
        certs = x509.load_pem_x509_certificates(text.encode())
    except Exception as exc:  # cryptography raises ValueError for bad PEM
        raise ValueError("not a PEM certificate (expected -----BEGIN CERTIFICATE-----)") from exc
    if not certs:
        raise ValueError("no certificate found")
    return text


def check_window_grid(grid: list[list[bool]] | None, *, allow_empty: bool = True) -> list[list[bool]] | None:
    if grid is None or grid == []:
        if allow_empty:
            return None
        raise ValueError("scan window is required")
    if len(grid) != 7 or any(not isinstance(row, list) or len(row) != 24 for row in grid):
        raise ValueError("scan window must be 7 days x 24 hours")
    clean = [[bool(cell) for cell in row] for row in grid]
    if not any(any(row) for row in clean):
        raise ValueError("scan window has no allowed hours; allow at least one hour")
    return clean


def check_timezone(value: str) -> str:
    try:
        zoneinfo.ZoneInfo(value)
    except Exception as exc:
        raise ValueError(f"unknown time zone {value!r}") from exc
    return value


def check_http_url(value: str | None, *, https_only: bool = False) -> str | None:
    if value is None or value.strip() == "":
        return None
    text = value.strip()
    if any(ch in text for ch in " '\"`<>\\"):
        raise ValueError("URL contains characters that are not allowed")
    parts = urlsplit(text)
    allowed = ("https",) if https_only else ("http", "https")
    if parts.scheme not in allowed or not parts.hostname:
        raise ValueError("URL must start with " + (" or ".join(f"{s}://" for s in allowed)))
    if parts.username or parts.password:
        raise ValueError("URL must not contain a user name or password")
    try:
        parts.port  # noqa: B018 - raises on a bad port
    except ValueError as exc:
        raise ValueError("URL has an invalid port") from exc
    return text


def check_host(value: str) -> str:
    text = value.strip()
    if not _HOST_RE.match(text):
        raise ValueError("enter a host name or IP address")
    return text


def check_login(value: str | None) -> str | None:
    if value is None or value == "":
        return None
    if not _LOGIN_RE.match(value):
        raise ValueError("login may use letters, digits and . _ @ $ \\ - (64 at most)")
    return value


# ----------------------------------------------------------------------------- servers
class ServersConfig(_Source):
    targets: list[str] = Field(default_factory=list, max_length=T.MAX_LINES + 50)
    exclusions: list[str] = Field(default_factory=list, max_length=2000)
    port: int = Field(default=22, ge=1, le=65535)
    login_user: str = Field(default="zs-cbom", max_length=64)
    host_key_policy: Literal["tofu", "pinned"] = "tofu"
    known_hosts: str | None = Field(default=None, max_length=MAX_SECRET_BYTES)
    credential_type: Literal["node_key", "ssh_cert", "vault", "password", "ssh_ca"] = "node_key"
    vault: VaultRef | None = None
    tier: Literal[1, 2] = 1
    parallel: int = Field(default=8, ge=1, le=64)
    timeout_s: int = Field(default=300, ge=10, le=3600)
    window: Literal["network", "any", "custom"] = "network"
    custom_window: list[list[bool]] | None = None
    # credential_type "ssh_ca" (F1.4): the node's own key, certified per job by this team's SSH CA lineage for these
    # principals (zs-<team>-<group>), bound to these source addresses (else the node's reported addresses).  Omitted
    # from the dump for every other credential type, so existing sources keep their connection version.
    ssh_ca_id: int | None = Field(default=None, ge=1, le=2_147_483_647)
    ssh_principals: list[str] = Field(default_factory=list, max_length=16)
    ssh_source_addresses: list[str] = Field(default_factory=list, max_length=32)

    @field_validator("login_user")
    @classmethod
    def _login(cls, v: str) -> str:
        # An empty login falls back to the kind's own default (zs-cbom on Linux, svc-zscbom on Windows/AD).
        return check_login(v) or cls.model_fields["login_user"].default

    @model_serializer(mode="wrap")
    def _dump(self, handler):
        data = handler(self)
        if isinstance(data, dict) and self.credential_type != "ssh_ca":
            for name in ("ssh_ca_id", "ssh_principals", "ssh_source_addresses"):
                data.pop(name, None)
        return data

    @model_validator(mode="after")
    def _check(self) -> "ServersConfig":
        parsed = T.parse_targets(self.targets)
        self.targets = parsed.normalized
        self.exclusions = T.parse_exclusions(self.exclusions).normalized
        if self.credential_type == "ssh_ca":
            from backend.utilities.cbom_sources.sshca import certs as _ca_certs
            from backend.utilities.cbom_sources.sshca import flags as _ca_flags

            if not _ca_flags.enabled():
                raise ValueError(f"credential_type: {_ca_flags.OFF_MESSAGE}")
            if self.ssh_ca_id is None:
                raise ValueError("ssh_ca_id: choose the SSH CA that signs the scan node's certificates")
            principals = [p.strip() for p in self.ssh_principals if p.strip()]
            if not principals or any(not _ca_certs.principal_shape_ok(p) for p in principals):
                raise ValueError("ssh_principals: one or more principals like zs-<team id>-<group> (lowercase "
                                 "letters, digits and . _ -), as listed in the servers' principals file")
            self.ssh_principals = list(dict.fromkeys(principals))
            try:
                self.ssh_source_addresses = list(_ca_certs.source_address_list(self.ssh_source_addresses))
            except ValueError as exc:
                raise ValueError(f"ssh_source_addresses: {exc}") from None
        else:
            self.ssh_ca_id, self.ssh_principals, self.ssh_source_addresses = None, [], []
        if self.credential_type == "vault" and self.vault is None:
            raise ValueError("vault: choose a vault and enter the secret path")
        if self.credential_type != "vault":
            self.vault = None
        if self.host_key_policy == "pinned" and not (self.known_hosts or "").strip():
            raise ValueError("known_hosts: paste the known_hosts lines to pin, or choose trust on first use")
        if self.window == "custom":
            self.custom_window = check_window_grid(self.custom_window, allow_empty=False)
        else:
            self.custom_window = None
        return self


class WindowsServersConfig(ServersConfig):
    port: int = Field(default=5986, ge=1, le=65535)
    login_user: str = Field(default="svc-zscbom", max_length=64)
    credential_type: Literal["vault", "password"] = "password"
    host_key_policy: Literal["tofu", "pinned"] = "tofu"
    # CA that issued the servers' WinRM HTTPS certificates when it is not publicly trusted (an internal CA)
    ca_pem: str | None = Field(default=None, max_length=MAX_PEM_BYTES)

    @field_validator("ca_pem")
    @classmethod
    def _ca(cls, v: str | None) -> str | None:
        return check_pem_certificates(v)


class ActiveDirectoryConfig(WindowsServersConfig):
    port: int = Field(default=636, ge=1, le=65535)


def credential_target_problem(kind: str, cfg: Any, secrets: dict[str, str]) -> str | None:
    """A password is sent only to a server whose identity the node can check first (product decision, 2026-10-31):
    SSH passwords need pinned host keys, WinRM needs HTTPS, and MySQL and Redis (whose logins a fake server could
    read) need TLS with the server's CA.  PostgreSQL without a CA is limited to SCRAM by the node, which never
    reveals the password.  Checked on the new configuration at save; the scan node enforces the same at run time,
    including for vault credentials whose type is only known then."""
    if kind == "linux_servers" and cfg.credential_type == "password" and cfg.host_key_policy != "pinned":
        return ("host_key_policy: password logins need pinned host keys, so the password only goes to the real "
                "servers; paste their known_hosts lines, or use the node key")
    if kind == "appliance" and cfg.vendor in APPLIANCE_SSH_VENDORS and cfg.credential_type == "password" \
            and cfg.host_key_policy != "pinned":
        return ("host_key_policy: appliance passwords need the pinned host key (known_hosts), so the password only "
                "goes to the real device")
    if kind == "windows_servers" and cfg.port == 5985:
        return "port: WinRM over HTTP (5985) would send the login to a server that is not verified; use HTTPS (5986)"
    if kind == "database" and cfg.engine in ("mysql", "redis", "mssql"):
        uses_password = cfg.credential_type == "vault" or bool(secrets.get("password"))
        if uses_password and not (cfg.require_tls and cfg.ca_pem):
            # SQL Server's login packet only obfuscates the password (MS-TDS 2.2.6.4)
            name = {"mysql": "MySQL", "redis": "Redis", "mssql": "SQL Server"}[cfg.engine]
            return (f"ca_pem: {name} logins need TLS and the CA certificate that signed the server's certificate, so "
                    "the password only goes to the real server")
    return None


def _server_secrets(cfg: ServersConfig) -> set[str]:
    if cfg.credential_type == "password":
        return {"password"}
    if cfg.credential_type == "ssh_cert":
        return {"ssh_certificate", "private_key"}
    # node_key, vault, and ssh_ca (nothing stored: the certificate is minted per claim for the node's own key)
    return set()


# ----------------------------------------------------------------------------- kubernetes
class KubernetesConfig(_Source):
    api_url: str = Field(max_length=512)
    ca_pem: str | None = Field(default=None, max_length=MAX_PEM_BYTES)
    credential_type: Literal["kubeconfig", "vault"] = "kubeconfig"
    vault: VaultRef | None = None
    context: str | None = Field(default=None, max_length=128)
    tier: Literal[1, 2] = 1
    managed: bool = False
    cloud_source_id: int | None = None

    @field_validator("api_url")
    @classmethod
    def _url(cls, v: str) -> str:
        return check_http_url(v, https_only=True) or ""

    @field_validator("ca_pem")
    @classmethod
    def _ca(cls, v: str | None) -> str | None:
        return check_pem_certificates(v)

    @model_validator(mode="after")
    def _check(self) -> "KubernetesConfig":
        if self.credential_type == "vault" and self.vault is None:
            raise ValueError("vault: choose a vault and enter the secret path")
        if self.credential_type != "vault":
            self.vault = None
        if not self.managed:
            self.cloud_source_id = None
        return self


def check_kubeconfig(text: str) -> dict[str, Any]:
    """Accept a kubeconfig that only carries static credentials; return a summary (no secrets)."""
    if len(text.encode()) > MAX_SECRET_BYTES:
        raise ValueError("kubeconfig is larger than 256 KB")
    import yaml

    try:
        data = yaml.safe_load(text)
    except Exception as exc:
        raise ValueError("kubeconfig is not valid YAML") from exc
    if not isinstance(data, dict) or not isinstance(data.get("clusters"), list) or not data.get("users"):
        raise ValueError("kubeconfig needs clusters, users and contexts")
    for user in data.get("users") or []:
        detail = (user or {}).get("user") or {}
        if "exec" in detail or "auth-provider" in detail:
            raise ValueError("kubeconfig uses an exec or auth-provider plugin; use a static token or client certificate")
        for key in ("client-certificate", "client-key", "tokenFile"):
            if key in detail:
                raise ValueError(f"kubeconfig points at a file ({key}); embed the data instead")
    for cluster in data.get("clusters") or []:
        if "certificate-authority" in ((cluster or {}).get("cluster") or {}):
            raise ValueError("kubeconfig points at a CA file; embed certificate-authority-data instead")
    contexts = [c.get("name") for c in data.get("contexts") or [] if isinstance(c, dict)]
    return {"contexts": [c for c in contexts if c], "current_context": data.get("current-context")}


# ----------------------------------------------------------------------------- databases
DB_DEFAULT_PORTS = {"postgres": 5432, "mysql": 3306, "mssql": 1433, "oracle": 1521, "mongodb": 27017, "redis": 6379}


class DatabaseConfig(_Source):
    engine: Literal["postgres", "mysql", "mssql", "oracle", "mongodb", "redis"]
    host: str = Field(max_length=253)
    port: int | None = Field(default=None, ge=1, le=65535)
    login: str | None = Field(default=None, max_length=64)
    credential_type: Literal["password", "vault"] = "password"
    vault: VaultRef | None = None
    require_tls: bool = True
    ca_pem: str | None = Field(default=None, max_length=MAX_PEM_BYTES)
    database_name: str | None = Field(default=None, max_length=128)

    @field_validator("host")
    @classmethod
    def _host(cls, v: str) -> str:
        return check_host(v)

    @field_validator("login")
    @classmethod
    def _login(cls, v: str | None) -> str | None:
        return check_login(v)

    @field_validator("ca_pem")
    @classmethod
    def _ca(cls, v: str | None) -> str | None:
        return check_pem_certificates(v)

    @model_validator(mode="after")
    def _check(self) -> "DatabaseConfig":
        if self.port is None:
            self.port = DB_DEFAULT_PORTS[self.engine]
        if self.login is None and self.engine not in ("mongodb", "redis"):
            raise ValueError("login: enter the read-only database login")
        if self.engine == "oracle" and not self.database_name:
            raise ValueError("database_name: enter the Oracle service name (for example ORCLPDB1)")
        if self.credential_type == "vault" and self.vault is None:
            raise ValueError("vault: choose a vault and enter the secret path")
        if self.credential_type != "vault":
            self.vault = None
        return self


def _db_secrets(cfg: DatabaseConfig) -> set[str]:
    if cfg.credential_type == "password" and cfg.engine not in ("redis",) and cfg.login:
        return {"password"}
    if cfg.credential_type == "password" and cfg.engine == "redis":
        return set()  # Redis may run without AUTH; a password is optional
    return set()


# ----------------------------------------------------------------------------- cloud
class AwsAccountConfig(_Source):
    scope: Literal["account", "organization"] = "account"
    role_arn: str = Field(max_length=600)
    regions: list[str] = Field(default_factory=lambda: ["ap-south-1"], min_length=1, max_length=32)
    # Opt-ins, off by default; each needs the matching CloudFormation parameter (validation checks the role matches).
    decrypt_lambda_cmk: bool = False  # Lambda environments under a customer-managed KMS key (decrypt only via Lambda)
    read_glue: bool = False  # glue:GetConnections, always called with HidePassword=True

    @field_validator("role_arn")
    @classmethod
    def _arn(cls, v: str) -> str:
        if not _AWS_ROLE_RE.match(v):
            raise ValueError("enter an IAM role ARN like arn:aws:iam::111122223333:role/ZeroShieldCBOMReader")
        return v

    @field_validator("regions")
    @classmethod
    def _regions(cls, v: list[str]) -> list[str]:
        out: list[str] = []
        for region in v:
            text = region.strip().lower()
            if not AWS_REGION_RE.match(text):
                raise ValueError(f"{region!r} is not an AWS region code")
            if text not in out:
                out.append(text)
        return out


def aws_account_id(role_arn: str) -> str | None:
    match = _AWS_ROLE_RE.match(role_arn or "")
    return match.group(2) if match else None


class AzureConfig(_Source):
    tenant_id: str
    client_id: str
    subscription_ids: list[str] = Field(default_factory=list, max_length=200)
    # client_secret, or a certificate (PEM with its unencrypted private key) for a signed client assertion
    credential_type: Literal["client_secret", "certificate"] = "client_secret"

    @field_validator("tenant_id", "client_id")
    @classmethod
    def _uuid(cls, v: str) -> str:
        if not _UUID_RE.match(v):
            raise ValueError("enter a GUID like 00000000-0000-0000-0000-000000000000")
        return v.lower()

    @field_validator("subscription_ids")
    @classmethod
    def _subs(cls, v: list[str]) -> list[str]:
        for item in v:
            if not _UUID_RE.match(item):
                raise ValueError(f"{item!r} is not a subscription GUID")
        return [i.lower() for i in v]


class GcpConfig(_Source):
    organization_id: str | None = Field(default=None, max_length=32)
    project_ids: list[str] = Field(default_factory=list, max_length=200)
    service_account_email: str = Field(max_length=254)

    @field_validator("service_account_email")
    @classmethod
    def _sa(cls, v: str) -> str:
        if not re.match(r"^[a-z0-9-]+@[a-z0-9-]+\.iam\.gserviceaccount\.com$", v):
            raise ValueError("enter a service account like zs-cbom@project.iam.gserviceaccount.com")
        return v

    @model_validator(mode="after")
    def _check(self) -> "GcpConfig":
        for project in self.project_ids:
            if not re.match(r"^[a-z][a-z0-9-]{4,28}[a-z0-9]$", project):
                raise ValueError(f"{project!r} is not a project id")
        if self.organization_id and not self.organization_id.isdigit():
            raise ValueError("organization id is numeric")
        if not self.organization_id and not self.project_ids:
            raise ValueError("enter an organization id or at least one project id")
        return self


# ----------------------------------------------------------------------------- identity
CA_NODE_PROVIDERS = ("adcs", "vault", "ejbca")  # collected by a scan node inside the customer network


class CaConnectorConfig(_Source):
    provider: Literal["adcs", "aws_private_ca", "vault", "venafi", "keyfactor", "digicert", "ejbca", "sectigo", "other"]
    api_url: str | None = Field(default=None, max_length=512)
    login: str | None = Field(default=None, max_length=64)
    aws_source_id: int | None = None
    # AD CS: the CA server reached over WinRM HTTPS (like a Windows server source)
    host: str | None = Field(default=None, max_length=253)
    port: int | None = Field(default=None, ge=1, le=65535)
    # CA that issued the CA server's / Vault's / EJBCA's own TLS certificate when it is not publicly trusted
    ca_pem: str | None = Field(default=None, max_length=MAX_PEM_BYTES)

    @field_validator("host")
    @classmethod
    def _host(cls, v: str | None) -> str | None:
        return check_host(v) if v else None

    @field_validator("ca_pem")
    @classmethod
    def _ca(cls, v: str | None) -> str | None:
        return check_pem_certificates(v)

    @field_validator("api_url")
    @classmethod
    def _url(cls, v: str | None) -> str | None:
        return check_http_url(v, https_only=True)

    @field_validator("login")
    @classmethod
    def _login(cls, v: str | None) -> str | None:
        return check_login(v)

    @model_validator(mode="after")
    def _check(self) -> "CaConnectorConfig":
        if self.provider in ("vault", "venafi", "keyfactor", "digicert", "ejbca", "sectigo", "other") and not self.api_url:
            raise ValueError("api_url: enter the HTTPS API address")
        if self.provider == "adcs" and not self.login:
            raise ValueError("login: enter the read-only Windows account used to read AD CS")
        if self.provider == "adcs" and not self.host:
            raise ValueError("host: enter the name of the certificate authority server (reached over WinRM HTTPS)")
        if self.provider == "adcs":
            self.port = self.port or 5986
            if self.port == 5985:
                raise ValueError("port: WinRM over HTTP (5985) would send the login to a server that is not verified; "
                                 "use HTTPS (5986)")
        else:
            self.host = self.port = None
        if self.provider == "aws_private_ca" and self.aws_source_id is None:
            raise ValueError("aws_source_id: pick the AWS account that holds the private CA")
        return self


def _ca_secrets(cfg: CaConnectorConfig) -> set[str]:
    if cfg.provider == "adcs":
        return {"password"}
    if cfg.provider == "aws_private_ca":
        return set()
    if cfg.provider == "vault":
        return {"token"}  # a read-only Vault token (policy template on the source's Privilege section)
    if cfg.provider == "ejbca":
        return {"client_cert", "client_key"}  # the EJBCA REST API authenticates clients by certificate
    return {"api_key"}


def _ca_on_node(cfg: Any) -> bool:
    return getattr(cfg, "provider", None) in CA_NODE_PROVIDERS


# ----------------------------------------------------------------------------- keys
KeyManagerProvider = Literal["pkcs11", "kmip"]
_MODULE_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")


class KeyManagerConfig(_Source):
    """An HSM or token through PKCS#11, or a KMIP server.  For PKCS#11 the source names a module; the library path is
    mapped to that name in the scan node's own environment (ZS_PKCS11_MODULES), never sent by the server."""
    provider: KeyManagerProvider
    module: str | None = Field(default=None, max_length=64)
    token_label: str | None = Field(default=None, max_length=32)
    credential_type: Literal["password", "vault"] = "password"
    vault: VaultRef | None = None
    host: str | None = Field(default=None, max_length=253)
    port: int | None = Field(default=None, ge=1, le=65535)
    ca_pem: str | None = Field(default=None, max_length=MAX_PEM_BYTES)

    @field_validator("host")
    @classmethod
    def _host(cls, v: str | None) -> str | None:
        return check_host(v) if v else None

    @field_validator("ca_pem")
    @classmethod
    def _ca(cls, v: str | None) -> str | None:
        return check_pem_certificates(v)

    @model_validator(mode="after")
    def _check(self) -> "KeyManagerConfig":
        if self.provider == "pkcs11":
            if not self.module or not _MODULE_RE.match(self.module):
                raise ValueError("module: enter the module name the scan node lists in ZS_PKCS11_MODULES "
                                 "(letters, digits, . _ -)")
            self.token_label = (self.token_label or "").strip() or None
            if self.token_label and any(ord(ch) < 32 for ch in self.token_label):
                raise ValueError("token_label: control characters are not allowed")
            self.host = self.port = self.ca_pem = None
            if self.credential_type == "vault" and self.vault is None:
                raise ValueError("vault: choose a vault and enter the secret path of the PIN")
            if self.credential_type != "vault":
                self.vault = None
        else:
            if not self.host:
                raise ValueError("host: enter the KMIP server's host name or IP address")
            self.port = self.port or 5696
            self.module = self.token_label = None
            self.credential_type, self.vault = "password", None
        return self


def _key_manager_secrets(cfg: KeyManagerConfig) -> set[str]:
    if cfg.provider == "kmip":
        return {"client_cert", "client_key"}  # KMIP servers authenticate clients by TLS certificate
    return set()  # the PIN is optional: a token without a stored PIN shows its public objects only


class IdpConfig(_Source):
    provider: Literal["entra_id", "okta", "keycloak", "adfs", "saml_metadata", "oidc_discovery"]
    tenant_id: str | None = None
    client_id: str | None = Field(default=None, max_length=128)
    base_url: str | None = Field(default=None, max_length=512)
    realm: str | None = Field(default=None, max_length=128)
    metadata_url: str | None = Field(default=None, max_length=1000)

    @field_validator("base_url")
    @classmethod
    def _base(cls, v: str | None) -> str | None:
        return check_http_url(v, https_only=True)

    @field_validator("realm")
    @classmethod
    def _realm(cls, v: str | None) -> str | None:
        if v is None or v == "":
            return None
        if not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", v):
            raise ValueError("realm may use letters, digits, dots, dashes and underscores")
        return v

    @field_validator("metadata_url")
    @classmethod
    def _meta(cls, v: str | None) -> str | None:
        return check_http_url(v, https_only=True)

    @model_validator(mode="after")
    def _check(self) -> "IdpConfig":
        p = self.provider
        if p == "entra_id":
            if not (self.tenant_id and _UUID_RE.match(self.tenant_id)) or not self.client_id:
                raise ValueError("Entra ID needs the tenant id (GUID) and the application (client) id")
        elif p == "okta":
            if not self.base_url:
                raise ValueError("base_url: enter your Okta domain, e.g. https://example.okta.com")
        elif p == "keycloak":
            if not self.base_url or not self.realm or not self.client_id:
                raise ValueError("Keycloak needs the base URL, realm and client id")
        elif p in ("saml_metadata", "oidc_discovery"):
            if not self.metadata_url:
                raise ValueError("metadata_url: enter the public metadata URL")
        return self


def _idp_secrets(cfg: IdpConfig) -> set[str]:
    if cfg.provider in ("entra_id", "keycloak"):
        return {"client_secret"}
    if cfg.provider == "okta":
        return {"api_token"}
    return set()


# ----------------------------------------------------------------------------- network
class NetworkRangeConfig(_Source):
    cidr: str = Field(max_length=64)
    mode: Literal["full", "fragile"] = "full"

    @field_validator("cidr")
    @classmethod
    def _cidr(cls, v: str) -> str:
        kind, _value, canonical = T.parse_line(v.strip())
        if kind != "net":
            raise ValueError("enter a CIDR range such as 10.20.0.0/16")
        return canonical


# ----------------------------------------------------------------------------- appliances
# Read-only configuration pull (scan_node/zs_scan_node/collectors/appliance.py): SSH show commands or vendor API GETs.
APPLIANCE_SSH_VENDORS = ("cisco_ios", "cisco_asa", "fortios")
APPLIANCE_API_VENDORS = ("panos", "f5_bigip")


class ApplianceConfig(_Source):
    vendor: Literal["cisco_ios", "cisco_asa", "fortios", "panos", "f5_bigip"]
    targets: list[str] = Field(default_factory=list, min_length=1, max_length=256)
    port: int | None = Field(default=None, ge=1, le=65535)
    login_user: str = Field(default="zs-cbom", max_length=64)
    credential_type: Literal["password", "vault"] = "password"
    vault: VaultRef | None = None
    host_key_policy: Literal["pinned", "tofu"] = "pinned"
    known_hosts: str | None = Field(default=None, max_length=MAX_SECRET_BYTES)
    ca_pem: str | None = Field(default=None, max_length=MAX_PEM_BYTES)

    @field_validator("login_user")
    @classmethod
    def _login(cls, v: str) -> str:
        return check_login(v) or "zs-cbom"

    @field_validator("ca_pem")
    @classmethod
    def _ca(cls, v: str | None) -> str | None:
        return check_pem_certificates(v)

    @model_validator(mode="after")
    def _check(self) -> "ApplianceConfig":
        self.targets = T.parse_targets(self.targets).normalized
        if not self.targets:
            raise ValueError("targets: enter the appliance address")
        if self.port is None:
            self.port = 22 if self.vendor in APPLIANCE_SSH_VENDORS else 443
        if self.credential_type == "vault" and self.vault is None:
            raise ValueError("vault: choose a vault and enter the secret path")
        if self.credential_type != "vault":
            self.vault = None
        if self.vendor in APPLIANCE_API_VENDORS:
            self.known_hosts, self.host_key_policy = None, "pinned"
        elif self.host_key_policy == "pinned" and not (self.known_hosts or "").strip():
            raise ValueError("known_hosts: paste the appliance's known_hosts line (ssh-keyscan) so the password only "
                             "goes to the real device")
        return self


def _appliance_secrets(cfg: ApplianceConfig) -> set[str]:
    if cfg.credential_type != "password":
        return set()
    return {"api_key"} if cfg.vendor == "panos" else {"password"}


# ----------------------------------------------------------------------------- agent mode and container images (WP8b)
class HostAgentConfig(_Source):
    """The host an agent-mode node runs on (created when the node enrolls; one per agent node).  Nothing to
    configure: the node reads its own host from read-only mounts and is never given a credential."""


# Same grammar as the node's parser (zs_scan_node/collectors/container_images.py parse_ref): optional registry host
# (with a dot or a port, or localhost), a lower-case repository path, then :tag or @sha256:digest.
_IMAGE_RE = re.compile(
    r"^(?:(?:[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+(?::\d{1,5})?|localhost(?::\d{1,5})?|[A-Za-z0-9-]+:\d{1,5})/)?"
    r"[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*(?:/[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*)*"
    r"(?::[A-Za-z0-9_][A-Za-z0-9_.-]{0,127})?(?:@sha256:[0-9a-f]{64})?$")
MAX_IMAGES = 50


class ContainerImagesConfig(_Source):
    """Images the node pulls from a registry (Distribution API v2, HTTPS only) to inventory their crypto packages.
    Credentials are anonymous or a vault reference resolved on the node; ZeroShield never stores a registry password."""
    images: list[str] = Field(min_length=1, max_length=MAX_IMAGES)
    credential_type: Literal["anonymous", "vault"] = "anonymous"
    vault: VaultRef | None = None
    ca_pem: str | None = Field(default=None, max_length=MAX_PEM_BYTES)
    max_image_mb: int = Field(default=2048, ge=1, le=8192)

    @field_validator("images")
    @classmethod
    def _images(cls, v: list[str]) -> list[str]:
        out: list[str] = []
        for raw in v:
            ref = str(raw).strip()
            if not ref or len(ref) > 512 or not _IMAGE_RE.match(ref):
                raise ValueError(f"images: {ref[:80]!r} is not an image reference (registry/repository:tag or @sha256:...)")
            if ref not in out:
                out.append(ref)
        return out

    @field_validator("ca_pem")
    @classmethod
    def _ca(cls, v: str | None) -> str | None:
        return check_pem_certificates(v)

    @model_validator(mode="after")
    def _check(self) -> "ContainerImagesConfig":
        if self.credential_type == "vault" and self.vault is None:
            raise ValueError("vault: choose a vault and enter the secret path")
        if self.credential_type != "vault":
            self.vault = None
        return self


# ----------------------------------------------------------------------------- registry
@dataclass(frozen=True)
class KindSpec:
    kind: str
    group: str
    label: str
    model: type[BaseModel]
    secret_fields: Callable[[Any], set[str]]
    optional_secrets: frozenset[str]
    needs_node: Callable[[Any], bool]
    collectable: Callable[[Any], bool]
    where_fields: tuple[str, ...]
    node_less: bool = False  # collected by the ZeroShield cloud worker, not by a scan node


def _always(_cfg: Any) -> bool:
    return True


def _never(_cfg: Any) -> bool:
    return False


# Engines the scan node can read today.
COLLECTABLE_DB_ENGINES = frozenset({"postgres", "mysql", "redis", "mongodb", "mssql", "oracle"})


def _db_collectable(cfg: Any) -> bool:
    return getattr(cfg, "engine", None) in COLLECTABLE_DB_ENGINES


# Changing any of these clears the stored secret, so it must be re-entered: where it goes, and how the node checks
# that it is talking to the right server before sending it (host keys, CA, TLS), must not change behind its back.
_SERVER_WHERE = ("targets", "port", "login_user", "host_key_policy", "known_hosts", "vault", "ca_pem")

KINDS: dict[str, KindSpec] = {
    "linux_servers": KindSpec("linux_servers", "servers", "Linux servers", ServersConfig, _server_secrets,
                              frozenset(), _always, _always, _SERVER_WHERE),
    "windows_servers": KindSpec("windows_servers", "servers", "Windows servers", WindowsServersConfig, _server_secrets,
                                frozenset(), _always, _always, _SERVER_WHERE),
    "active_directory": KindSpec("active_directory", "servers", "Active Directory", ActiveDirectoryConfig, _server_secrets,
                                 frozenset(), _always, _never, _SERVER_WHERE),
    "kubernetes": KindSpec("kubernetes", "kubernetes", "Kubernetes cluster", KubernetesConfig,
                           lambda c: {"kubeconfig"} if c.credential_type == "kubeconfig" else set(),
                           frozenset(), _always, _always, ("api_url", "context", "ca_pem", "vault")),
    "database": KindSpec("database", "databases", "Database", DatabaseConfig, _db_secrets,
                         frozenset({"password"}), _always, _db_collectable,
                         ("host", "port", "login", "engine", "require_tls", "ca_pem", "vault")),
    "aws_account": KindSpec("aws_account", "cloud", "AWS account", AwsAccountConfig, lambda c: set(),
                            frozenset(), _never, _always, ("role_arn",), node_less=True),
    # Collected by the cloud worker over HTTPS (Key Vault / Cloud KMS, CA Service, Secret Manager metadata).
    "azure_subscription": KindSpec("azure_subscription", "cloud", "Azure", AzureConfig,
                                   lambda c: {"client_certificate"} if c.credential_type == "certificate" else {"client_secret"},
                                   frozenset(), _never, _always, ("tenant_id", "client_id"), node_less=True),
    "gcp_project": KindSpec("gcp_project", "cloud", "Google Cloud", GcpConfig, lambda c: {"service_account_key"},
                            frozenset(), _never, _always, ("service_account_email",), node_less=True),
    "ca_connector": KindSpec("ca_connector", "identity", "Certificate authority", CaConnectorConfig, _ca_secrets,
                             frozenset(), _ca_on_node, _ca_on_node,
                             ("api_url", "login", "provider", "host", "port", "ca_pem")),
    # Signing keys are read from public metadata, so the IdP secret is optional (kept for API reads later).
    "idp": KindSpec("idp", "identity", "Identity provider", IdpConfig, lambda c: set(),
                    frozenset({"client_secret", "api_token"}), _never, _always, ("base_url", "tenant_id", "client_id", "provider", "metadata_url", "realm"),
                    node_less=True),
    "network_range": KindSpec("network_range", "network", "Network range", NetworkRangeConfig, lambda c: set(),
                              frozenset(), _always, _always, ("cidr",)),
    "key_manager": KindSpec("key_manager", "databases", "HSM or key manager", KeyManagerConfig, _key_manager_secrets,
                            frozenset({"pin"}), _always, _always,
                            ("provider", "module", "token_label", "host", "port", "ca_pem", "vault")),
}
KINDS["appliance"] = KindSpec("appliance", "network", "Network appliance", ApplianceConfig, _appliance_secrets,
                              frozenset(), _always, _always,
                              ("targets", "port", "login_user", "vendor", "host_key_policy", "known_hosts", "ca_pem",
                               "vault"))
# Agent mode: created for each agent-mode node; collected by that node only, never with a credential.
KINDS["host_agent"] = KindSpec("host_agent", "servers", "Host agent", HostAgentConfig, lambda c: set(), frozenset(),
                               _always, _always, ())
KINDS["container_images"] = KindSpec("container_images", "kubernetes", "Container images", ContainerImagesConfig,
                                     lambda c: set(), frozenset(), _always, _always,
                                     ("images", "credential_type", "vault", "ca_pem"))

from backend.utilities.cbom_sources.kinds_fleet import FLEET_KINDS  # noqa: E402  (F1.3: awx/salt/ssm hosts)
KINDS.update(FLEET_KINDS)
KIND_NAMES = tuple(KINDS)
# Config fields that describe the source rather than how it is reached (declared on ``_Source``).
METADATA_FIELDS: tuple[str, ...] = tuple(_Source.model_fields)


def validate_secret_value(field: str, value: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field}: must be text")
    if len(value.encode("utf-8")) > MAX_SECRET_BYTES:
        raise ValueError(f"{field}: larger than 256 KB")
    if "\x00" in value:
        raise ValueError(f"{field}: contains a NUL byte; upload a text file")
    if field == "kubeconfig":
        check_kubeconfig(value)
    if field == "client_certificate":
        check_client_certificate(value)
        return value.replace("\r\n", "\n")
    if field == "service_account_key":
        check_service_account_key(value)
    if field in ("private_key", "ssh_certificate"):
        return value.replace("\r\n", "\n")
    if field in ("client_cert", "client_key"):
        value = value.replace("\r\n", "\n")
        if field == "client_cert" and "-----BEGIN CERTIFICATE-----" not in value:
            raise ValueError(f"{field}: paste the PEM client certificate (-----BEGIN CERTIFICATE-----)")
        if field == "client_key" and ("PRIVATE KEY-----" not in value or "ENCRYPTED PRIVATE KEY" in value):
            raise ValueError(f"{field}: paste the unencrypted PEM private key of the client certificate")
        return value
    return value


def check_client_certificate(text: str) -> None:
    """An Azure app certificate: one PEM certificate plus its unencrypted private key (RSA, as Entra ID requires)."""
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    data = text.replace("\r\n", "\n").encode()
    try:
        certs = x509.load_pem_x509_certificates(data)
    except Exception:
        certs = []
    if not certs:
        raise ValueError("client_certificate: paste the PEM certificate and its private key")
    try:
        key = serialization.load_pem_private_key(data, password=None)
    except TypeError:
        raise ValueError("client_certificate: the private key is encrypted; paste it without a passphrase") from None
    except Exception:
        raise ValueError("client_certificate: no PEM private key found next to the certificate") from None
    if not isinstance(key, rsa.RSAPrivateKey):
        raise ValueError("client_certificate: Entra ID client certificates must use an RSA key")
    if key.public_key().public_numbers() != certs[0].public_key().public_numbers():  # type: ignore[union-attr]
        raise ValueError("client_certificate: the private key does not belong to the first certificate")


def check_service_account_key(text: str) -> None:
    """A Google service account JSON key: type, client_email and an unencrypted RSA private key."""
    import json

    try:
        data = json.loads(text)
    except ValueError:
        raise ValueError("service_account_key: not valid JSON; upload the .json key file") from None
    if not isinstance(data, dict) or data.get("type") != "service_account":
        raise ValueError("service_account_key: not a service account key (type must be service_account)")
    if not isinstance(data.get("client_email"), str) or not isinstance(data.get("private_key"), str):
        raise ValueError("service_account_key: the key file has no client_email or private_key")
    from cryptography.hazmat.primitives import serialization

    try:
        serialization.load_pem_private_key(data["private_key"].encode(), password=None)
    except Exception:
        raise ValueError("service_account_key: private_key is not a readable PEM key") from None
