"""Authored text of D2 "Discovery Methodology and Evidence Plan" (SOW ZS-SOW-CHOLA-CBOM-2026-01 v2.3, Table 7).

The document says how assets are discovered, classified and evidenced, so its words follow the SOW sections they
answer: Section 2 (three collection methods, data protection), Table 4 (sources per layer L1 to L4), 3.2 (ingest,
normalise, grade, score, Q0 Unknown), C6 (scan windows, OT-safe windows), 7.2 (exclusions) and Table 7 (D1 to D14).

Every row describes the product's own behaviour and names the code it describes ("Product text:" comments); the
contract tests in ``test_cbom_deliverable_methodology.py`` pin ``COLLECTORS`` to ``cbom_sources.kinds.KINDS``,
``Q0_REASONS`` to ``cbom_sources.qgrade.REASONS``, ``FIX_CLASSES`` to ``cbom_sources.agility.CLASSES`` and
``EVIDENCE_LEVELS`` to ``cbom_sources.evidence``, so a new collector, grade reason or fix class cannot ship without
its D2 row.  This module imports nothing from the product: the renderer stays a pure function of the view.

``method_limits(view)`` replaces the constant ``cbom_deliverable_text.METHOD_LIMITS`` for D2: a limit is printed only
when the edition's own run coverage leaves it true (no "not probed" sentence when endpoints were probed).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

SOW_ID = "D2"  # the SOW Table 7 identifier printed in the Document ID

# ---------------------------------------------------------------------------------------------
# Collection methods (SOW Section 2)
# ---------------------------------------------------------------------------------------------
AGENTLESS = "Agentless"
AGENT = "Agent"
API = "Read-only API"
METHODS = (AGENTLESS, AGENT, API)

# Product text: scan_node/README.md ("What it runs", "Kubernetes (Helm) and agent mode"), cbom_sources/kinds.py
# (node_less kinds run in the cloud worker), routers/cbom_node.py + cbom_sources/node_auth.py (signed requests).
METHOD_ROWS = (
    (
        AGENTLESS,
        "A ZeroShield scan node runs inside the customer network (container, VM image or Helm chart; uid 10001, "
        "read-only root file system, no capabilities). It reaches each system with a read-only account the "
        "customer creates and probes network endpoints with protocol handshakes. Repositories and archives are "
        "scanned by the hosted service from a read-only clone or an upload; nothing is installed on a target.",
        "Servers over SSH and WinRM-HTTPS, Kubernetes API, databases, network ranges, appliances, container "
        "registries; code repositories and archives.",
        "The node only opens connections: to targets inside the customer's scan window and never-scan list, and "
        "outbound HTTPS to ZeroShield. Every node request is signed (Ed25519).",
    ),
    (
        AGENT,
        "The same scan node in agent mode (ZS_MODE=agent; the Helm DaemonSet, or a VM with / mounted read-only). "
        "It reads only the host it runs on, is never given a credential or any other kind of job, and listens on "
        "no port.",
        "Host agent: OS release, crypto packages, crypto policy and FIPS flag, sshd_config, SSH host keys, key and "
        "certificate files, crypto libraries mapped by running processes.",
        "Outbound HTTPS to ZeroShield only, every request signed (Ed25519). Host files are read through a "
        "descriptor-checked walk; /proc, /sys and /dev of the host are not walked.",
    ),
    (
        API,
        "List-and-describe calls to cloud and key services with a read-only role, service principal, service "
        "account or client certificate the customer grants (the setup templates print the exact read-only "
        "permissions). Cloud accounts and identity providers are read by the ZeroShield cloud worker; HSM and CA "
        "management APIs inside the network are read by the scan node.",
        "AWS, Azure, Google Cloud and Oracle Cloud keys, certificates, secret metadata and TLS settings; HSMs "
        "(PKCS#11, KMIP); certificate authorities; identity providers (Entra ID, Okta, Keycloak, AD FS).",
        "HTTPS (TLS) or the HSM's own protocol; describe and list calls only, never a decrypt, sign, export or "
        "secret-value read.",
    ),
)
METHOD_COLUMNS = ("Method", "How it works", "Sources", "Connections and safeguards")


@dataclass(frozen=True)
class CollectorSpec:
    """One CBOM Sources collector (``cbom_sources.kinds.KINDS`` key), as D2 describes it."""

    kind: str
    label: str
    layer: str  # "L1" .. "L4"
    method: str  # AGENTLESS | AGENT | API
    transport: str
    reads: str
    never: str
    in_sow: bool = True  # False: SOW 7.2 excludes it (described, but outside this engagement)


# Product text: scan_node/README.md per collector; kinds.py groups and node_less flags; SOW 7.2 for in_sow.
COLLECTORS = (
    CollectorSpec("container_images", "Container images", "L1", AGENTLESS, "Registry API (OCI / Distribution v2), HTTPS",
                  "Image manifests and layers streamed once and checked against their digests; crypto packages "
                  "with versions (up to 50 images per source).",
                  "Nothing is written to disk; credentials go only to the registry's own origin."),
    CollectorSpec("linux_servers", "Linux servers", "L2", AGENTLESS, "SSH, fixed read-only command list",
                  "Keystores (JKS, PKCS#12, PEM) as public material, SSH host keys, OpenSSL and Java security "
                  "settings, crypto packages, crypto libraries loaded by processes (Tier 2).",
                  "Private keys: only public parts are printed (openssl pkey -pubout, ssh-keygen -l)."),
    CollectorSpec("windows_servers", "Windows servers", "L2", AGENTLESS, "WinRM over HTTPS (5986), read-only PowerShell",
                  "Certificate stores, SCHANNEL protocol keys, TLS cipher-suite order, BitLocker, RDP security "
                  "layer, key provider class (software, TPM, smart card, HSM).",
                  "No key is opened or exported."),
    CollectorSpec("active_directory", "Active Directory", "L2", AGENTLESS, "LDAPS (636 or 3269)",
                  "Recorded in scope; the current scan node has no directory collector, so domain controllers are "
                  "assessed through the TLS probe of their LDAPS ports (network ranges) and AD CS through the CA "
                  "connector.", "No directory object, password hash or secret attribute is read."),
    CollectorSpec("host_agent", "Host agent", "L2", AGENT, "Outbound HTTPS only (agent mode)",
                  "The agent's own host: OS release, crypto packages, crypto policy, FIPS flag, sshd_config, SSH "
                  "host keys, key and certificate files.", "Never given a credential; reads world-readable files "
                  "unless the customer grants more."),
    CollectorSpec("kubernetes", "Kubernetes clusters", "L2", AGENTLESS, "Kubernetes API (HTTPS), token or client "
                  "certificate", "Ingress TLS, cert-manager certificates, Istio and Linkerd mTLS policy, CA "
                  "bundles; TLS secrets' certificates (Tier 2).", "tls.key is dropped; keys pasted into ConfigMaps "
                  "are recorded by type and size only."),
    CollectorSpec("database", "Databases", "L2", AGENTLESS, "Database protocol over TLS (TLS checked before the "
                  "password is sent)", "TLS versions and certificates, TDE and encrypted tablespaces, key and "
                  "certificate metadata, password hash types.", "Fixed queries only; no table data, no password "
                  "hash."),
    CollectorSpec("key_manager", "HSMs and key managers", "L3", API, "PKCS#11 read-only session; KMIP 1.0-2.0 "
                  "over TLS with a client certificate", "Token information; per object class, key type, size or "
                  "curve, label, usage flags and dates.", "A key's value attribute is never requested; KMIP Get "
                  "and Export are never sent."),
    CollectorSpec("ca_connector", "Certificate authorities", "L3", API, "CA REST APIs (HashiCorp Vault, EJBCA, "
                  "Venafi, Keyfactor, DigiCert, Sectigo, AWS Private CA) or WinRM-HTTPS (AD CS)",
                  "CA hierarchy and certificates, signing profiles and templates, issued certificates, CRL and URL "
                  "configuration, Vault transit key settings.", "Never Vault export or backup; no CA private key."),
    CollectorSpec("aws_account", "AWS accounts", "L3", API, "AWS APIs through an assumed read-only role (external ID)",
                  "KMS keys, ACM and AWS Private CA certificates, Secrets Manager metadata, TLS and encryption "
                  "settings of load balancers, CloudFront, API Gateway, RDS and S3.",
                  "No decrypt, sign or GetSecretValue call."),
    CollectorSpec("azure_subscription", "Azure subscriptions", "L3", API, "Azure Resource Manager and Key Vault APIs, "
                  "reader roles", "Key Vault keys and certificates, secret metadata, TLS and encryption settings.",
                  "Secret values are never read."),
    CollectorSpec("gcp_project", "Google Cloud projects", "L3", API, "Google Cloud APIs, viewer roles",
                  "Cloud KMS keys, CA Service, Certificate Manager, Secret Manager metadata.",
                  "secretmanager.versions.access is not granted."),
    CollectorSpec("oci_tenancy", "Oracle Cloud tenancies", "L3", API, "OCI APIs with signed requests",
                  "Vault keys, certificates, secret metadata, load balancer TLS, Object Storage encryption.",
                  "Secret contents are never read."),
    CollectorSpec("idp", "Identity providers", "L3", API, "Public sign-in metadata (OIDC discovery, SAML metadata) "
                  "over HTTPS", "Token-signing keys and certificates of Entra ID, Okta, Keycloak and AD FS.",
                  "No user or sign-in data."),
    CollectorSpec("network_range", "Network ranges and endpoints", "L4", AGENTLESS, "TLS, STARTTLS, SSH, IKE and OPC "
                  "UA handshakes from the scan node", "Protocol versions, cipher suites, key exchange, certificate "
                  "chains and key sizes, SSH host keys and algorithms, IKE proposals, OPC UA endpoint security; "
                  "Modbus: whether the port accepts connections.", "No login, no application data; no Modbus request "
                  "is sent."),
    CollectorSpec("appliance", "Network appliances", "L4", AGENTLESS, "SSH show commands (Cisco IOS, Cisco ASA, "
                  "FortiOS); read-only API GETs (PAN-OS, F5 BIG-IP)", "SSH, management TLS, IKE and IPsec "
                  "settings and key sizes from the running configuration.", "Pre-shared keys and passwords never "
                  "leave the node."),
    CollectorSpec("ct_logs", "Certificate Transparency", "L3", API, "Public CT search providers", "Certificates "
                  "logged for the team's domains.", "Public data only.", in_sow=False),
    CollectorSpec("awx_hosts", "Hosts through AWX/AAP", "L2", AGENTLESS, "AWX inventory", "Host list for server "
                  "collection.", "Read-only inventory.", in_sow=False),
    CollectorSpec("salt_hosts", "Hosts through Salt", "L2", AGENTLESS, "Salt API", "Host list for server collection.",
                  "Read-only.", in_sow=False),
    CollectorSpec("ssm_hosts", "Hosts through AWS SSM", "L2", AGENTLESS, "AWS Systems Manager", "Host list for server "
                  "collection.", "Read-only.", in_sow=False),
)
COLLECTOR_BY_KIND = {spec.kind: spec for spec in COLLECTORS}
OUT_OF_SOW_NOTE = (
    "Certificate Transparency monitoring and collection through AWX, Salt or AWS SSM are excluded by SOW 7.2; the "
    "platform has these collectors, but they are not part of this engagement."
)

# ---------------------------------------------------------------------------------------------
# SOW Table 4: every source type per layer, matched to what the team configured
# ---------------------------------------------------------------------------------------------
LAYERS = (
    ("L1", "Code, pipelines and images"),
    ("L2", "Servers, Kubernetes and databases"),
    ("L3", "Cloud keys, HSMs, PKI and identity"),
    ("L4", "Network, TLS and appliances"),
)


@dataclass(frozen=True)
class SowSourceType:
    """One source type of SOW Table 4 and how D2 tells whether the team configured it.

    ``code``: matched by the team's code scans (``view.sources``) of these kinds; ``kinds``: CBOM Sources kinds; each
    ``variants`` entry is ``kind:value`` against the source's provider / engine / vendor; ``ports``: the team's probe
    port protocols (prefix match) that must be present as well, for network-range types."""

    layer: str
    label: str
    method: str
    code: tuple[str, ...] = ()
    kinds: tuple[str, ...] = ()
    variants: tuple[str, ...] = ()
    ports: tuple[str, ...] = ()


_CODE = ("repo", "zip", "file", "scan")  # cbom_team_rollup SOURCE_* (and a legacy scan source)
# Product text: SOW Table 4, one row per source type it lists, in its order.
SOW_SOURCE_TYPES = (
    SowSourceType("L1", "Git repositories (GitHub, GitLab, Bitbucket) or uploaded archives", AGENTLESS, code=_CODE),
    SowSourceType("L1", "Infrastructure code (Terraform, CloudFormation, Dockerfile, docker-compose)", AGENTLESS,
                  code=_CODE),
    SowSourceType("L1", "Server and database configuration files", AGENTLESS, code=_CODE),
    SowSourceType("L1", "Container images (up to 50 per source)", AGENTLESS, kinds=("container_images",)),
    SowSourceType("L1", "Compiled binaries and firmware", AGENTLESS, code=_CODE),
    SowSourceType("L2", "Linux servers (SSH)", AGENTLESS, kinds=("linux_servers",)),
    SowSourceType("L2", "Windows servers (WinRM over HTTPS)", AGENTLESS, kinds=("windows_servers",)),
    SowSourceType("L2", "Host agent", AGENT, kinds=("host_agent",)),
    SowSourceType("L2", "Kubernetes clusters", AGENTLESS, kinds=("kubernetes",)),
    SowSourceType("L2", "Active Directory (LDAPS)", AGENTLESS, kinds=("active_directory",)),
    SowSourceType("L2", "PostgreSQL", AGENTLESS, variants=("database:postgres",)),
    SowSourceType("L2", "MySQL", AGENTLESS, variants=("database:mysql",)),
    SowSourceType("L2", "SQL Server", AGENTLESS, variants=("database:mssql",)),
    SowSourceType("L2", "Oracle", AGENTLESS, variants=("database:oracle",)),
    SowSourceType("L2", "MongoDB", AGENTLESS, variants=("database:mongodb",)),
    SowSourceType("L2", "Redis", AGENTLESS, variants=("database:redis",)),
    SowSourceType("L3", "AWS (KMS, ACM, AWS Private CA, Secrets Manager; load balancer, CloudFront, API Gateway, "
                  "RDS and S3 settings)", API, kinds=("aws_account",)),
    SowSourceType("L3", "Azure Key Vault and Azure TLS and encryption settings", API, kinds=("azure_subscription",)),
    SowSourceType("L3", "Google Cloud KMS, CA Service and Secret Manager", API, kinds=("gcp_project",)),
    SowSourceType("L3", "Oracle Cloud Vault, certificates, secrets, load balancer TLS, Object Storage encryption",
                  API, kinds=("oci_tenancy",)),
    SowSourceType("L3", "HashiCorp Vault", API, variants=("ca_connector:vault",)),
    SowSourceType("L3", "HSMs (PKCS#11)", API, variants=("key_manager:pkcs11",)),
    SowSourceType("L3", "HSMs and key managers (KMIP)", API, variants=("key_manager:kmip",)),
    SowSourceType("L3", "AD CS", API, variants=("ca_connector:adcs",)),
    SowSourceType("L3", "AWS Private CA (connector)", API, variants=("ca_connector:aws_private_ca",)),
    SowSourceType("L3", "EJBCA", API, variants=("ca_connector:ejbca",)),
    SowSourceType("L3", "Venafi", API, variants=("ca_connector:venafi",)),
    SowSourceType("L3", "Keyfactor", API, variants=("ca_connector:keyfactor",)),
    SowSourceType("L3", "DigiCert", API, variants=("ca_connector:digicert",)),
    SowSourceType("L3", "Sectigo", API, variants=("ca_connector:sectigo",)),
    SowSourceType("L3", "Entra ID", API, variants=("idp:entra_id",)),
    SowSourceType("L3", "Okta", API, variants=("idp:okta",)),
    SowSourceType("L3", "Keycloak", API, variants=("idp:keycloak",)),
    SowSourceType("L3", "AD FS", API, variants=("idp:adfs",)),
    SowSourceType("L4", "Network ranges and web or API endpoints (TLS)", AGENTLESS, kinds=("network_range",),
                  ports=("tls",)),
    SowSourceType("L4", "SSH services", AGENTLESS, kinds=("network_range",), ports=("ssh",)),
    SowSourceType("L4", "IKE / VPN services", AGENTLESS, kinds=("network_range",), ports=("ike",)),
    SowSourceType("L4", "STARTTLS mail services", AGENTLESS, kinds=("network_range",),
                  ports=("starttls-smtp", "starttls-imap", "starttls-pop3")),
    SowSourceType("L4", "OPC UA OT endpoints", AGENTLESS, kinds=("network_range",), ports=("opcua",)),
    SowSourceType("L4", "Modbus OT endpoints (port check only)", AGENTLESS, kinds=("network_range",),
                  ports=("modbus",)),
    SowSourceType("L4", "Cisco IOS (SSH)", AGENTLESS, variants=("appliance:cisco_ios",)),
    SowSourceType("L4", "Cisco ASA (SSH)", AGENTLESS, variants=("appliance:cisco_asa",)),
    SowSourceType("L4", "FortiOS (SSH)", AGENTLESS, variants=("appliance:fortios",)),
    SowSourceType("L4", "Palo Alto PAN-OS (API)", AGENTLESS, variants=("appliance:panos",)),
    SowSourceType("L4", "F5 BIG-IP (API)", AGENTLESS, variants=("appliance:f5_bigip",)),
)
CONFIGURED = "Configured"
NOT_CONFIGURED = "Not configured"
NOT_LOADED = "Not loaded"
SOW_TABLE_COLUMNS = ("Layer", "SOW Table 4 source type", "Method", "Status", "Sources", "Collected")
SOW_TABLE_NOTE = (
    "Status is read from the team's configured CBOM Sources and code scans when this edition was generated. "
    "'Collected' counts the sources of that type whose latest complete collection is in this edition. A type that "
    "is not configured is not assessed; it is added to the Scope Baseline (D1) by change control."
)


# ---------------------------------------------------------------------------------------------
# Classification (SOW 3.2)
# ---------------------------------------------------------------------------------------------
# Product text: CycloneDX 1.6 cryptoProperties.assetType values the CBOM export writes (cbom_sources/inventory.py).
ASSET_TYPE_ROWS = (
    ("algorithm", "A cipher, hash, signature, key-agreement or MAC algorithm with mode, key size or curve, OID and "
     "NIST quantum security level where known."),
    ("certificate", "An X.509 certificate: subject, issuer, validity, signature and public-key algorithm, chain."),
    ("related-crypto-material", "A key, key pair, secret or token: type, size or curve, state, usage, rotation "
     "and custody (software, TPM, HSM, cloud KMS) without its value."),
    ("protocol", "TLS, SSH or IKE/IPsec as negotiated or configured: versions, cipher suites, key exchange."),
)
# Product text: cbom_sources/posture.py pqc classes; qgrade.py grade scale; SOW 3.2 step 4.
GRADING_TEXT = (
    "Each item is classed against the NIST post-quantum standards FIPS 203, FIPS 204 and FIPS 205, the NSA CNSA 2.0 "
    "algorithm suite and dates, and NIST SP 800-131A transitions: quantum-vulnerable (broken by Shor: RSA, "
    "finite-field and elliptic-curve Diffie-Hellman and signatures), Grover-weakened (128-bit symmetric keys), "
    "deprecated or disallowed today (SP 800-131A: MD5, SHA-1 signatures, DES, 3DES, RSA below 2048 bits), hybrid "
    "(classical plus a FIPS 203 key exchange) or quantum-safe. Certificates are also flagged by expiry. The rules "
    "are deterministic and versioned (knowledge-base and classifier versions are recorded on every run)."
)
Q_GRADE_ROWS = (
    ("Q1 Critical", "Quantum-vulnerable and X + Y > Z (Mosca), reachable from the internet or a trust anchor."),
    ("Q2 High", "Quantum-vulnerable and X + Y > Z, internal or exposure unknown."),
    ("Q3 Medium", "Quantum-vulnerable within Z, Grover-weakened, or post-quantum on E1 evidence only."),
    ("Q4 Low", "Hybrid or quantum-safe, observed by a collector, found in code or attested at E2/E3."),
    ("Q0 Unknown", "Cannot be graded; always carries one of the reasons below and is never counted as safe."),
)
Q0_POLICY = (
    "Q0 Unknown policy: an item that cannot be assessed is graded Q0 with a reason, never left out and never "
    "counted as safe. Q0 items are listed in the Quantum Risk Register (D12) with their reason and are closed only "
    "by new evidence, a complete re-collection, the inputs being set, or the source being removed; each closure is "
    "recorded with its cause and the grade it closed to (D12 'gaps closed by week')."
)
# Product text: cbom_sources/qgrade.py REASONS (grade Q0 only), pinned by a contract test.
Q0_REASONS = (
    ("coverage_gap", "A check, target or address range was not read."),
    ("source_not_read", "The run did not read the source (skipped by the planner, or its collect job did not "
                        "succeed or has not finished)."),
    ("source_truncated", "The collect job was cut at the asset limit, or stored fewer assets than it read."),
    ("excluded_by_choice", "Left out by the team's choice (never-scan list, a disabled source, an option off)."),
    ("evidence_e0", "Evidence at E0 (no answer, rated unknown, expired, vendor no response)."),
    ("unknown_verdict", "The product could not tell the asset's PQC class."),
    ("not_correlated", "Correlation required and absent (reserved)."),
    ("mosca_missing", "Quantum-vulnerable, and the team's Mosca X, Y or Z is not set."),
)
# Product text: cbom_sources/posture.py (risk score) and the Mosca inputs of the team settings (risk_model).
RISK_SCORING_TEXT = (
    "Risk score: impact weight x business criticality x internet exposure, per asset (posture). Data lifetime "
    "enters through Mosca's inequality: X (how long the data must stay secret), Y (migration time) and Z (years "
    "until a cryptographically relevant quantum computer); X + Y > Z marks harvest-now-decrypt-later exposure and "
    "raises the grade. Criticality, exposure, owner, data classification and data lifetime come from the source "
    "metadata the customer supplies (C5); where it is missing the item says so instead of assuming."
)
# Product text: cbom_sources/agility.py CLASSES (fx-1), pinned by a contract test; SOW 3.2 step 5.
FIX_CLASSES = (
    ("configurable", "Configuration", "Fixed by a setting (protocol floor, cipher order, key policy)."),
    ("code-fixed", "Code", "Fixed by a code or dependency change in the customer's software."),
    ("vendor-fixed", "Vendor", "Needs a vendor release (appliance, SaaS, packaged product)."),
    ("hardware-fixed", "Hardware", "Needs new hardware (HSM, smart card, TPM, OT device)."),
)

# ---------------------------------------------------------------------------------------------
# Evidence model (SOW 3.2 step 1, Section 2)
# ---------------------------------------------------------------------------------------------
EVIDENCE_CHAIN = (
    ("1. Signed collection", "Every scan-node request carries an Ed25519 signature over method, path, timestamp, "
     "nonce and the body's SHA-256, made with a key generated at enrolment; the server checks it on the raw bytes "
     "before parsing, refuses clock skew and replays (per-node sequence window) and, with 'require signed nodes', "
     "refuses unsigned nodes."),
    ("2. Job provenance", "Each collection is a job of a run: source, scan node, attempts, outcome, duration, "
     "asset count and coverage rows (what was and was not read, with the reason)."),
    ("3. Fingerprint and de-duplication", "Each asset gets a stable key (identity of the thing itself, e.g. a "
     "certificate's SHA-256 or a key's public-key hash, plus where it was seen); the same item seen again or by "
     "two collectors is one asset with several observations."),
    ("4. Normalised record", "Every item is written to the CycloneDX 1.6 CBOM as an algorithm, certificate, "
     "related crypto material or protocol, with its location, the collector's evidence and the knowledge-base, "
     "classifier and engine versions that judged it."),
    ("5. Signed deliverables", "The run's CycloneDX JSON is signed over its exact bytes; the evidence pack zips the "
     "CBOM (JSON and XML), VEX, OSCAL, the signature, the PDF report and a drift file with a SHA-256 manifest. A "
     "recipient verifies a file offline against the published key or online with the verify endpoint (D11)."),
)
# Product text: per collector, what the job result and asset rows store (scan_node collectors, cbom_sources jobs).
EVIDENCE_BY_METHOD = (
    (AGENTLESS, "Target address and port, the command or handshake that produced the fact, parsed fields (no raw "
                "secret), certificate fingerprints, coverage rows with reason, node id and node version."),
    (AGENT, "Host name, file path or package name, parsed fields, file and certificate fingerprints, coverage rows "
            "for files it could not read."),
    (API, "Cloud account / tenant and region, resource ARN or id, the describe call's metadata fields, key and "
          "certificate identifiers, coverage rows for denied or throttled calls."),
)
# Product text: cbom_sources/evidence.py levels E0..E3 and the 365-day expiry.
EVIDENCE_LEVELS = (
    ("E3", "Observed by a collector or proven by a document the assessor verified."),
    ("E2", "Attested with a dated document (policy, vendor letter, configuration export)."),
    ("E1", "Attested by a named person without a document."),
    ("E0", "No answer, rated unknown, expired (older than 365 days) or vendor no response: the item stays Q0."),
)

# ---------------------------------------------------------------------------------------------
# Data protection (SOW Section 2, 7.1, 7.2)
# ---------------------------------------------------------------------------------------------
DATA_PROTECTION = (
    "Metadata only: private keys, key material and secret values are never read or exported. Collectors print "
    "public parts only (certificates, public keys, fingerprints); PKCS#11 value attributes, KMIP Get/Export, Vault "
    "export, cloud decrypt and secret-value reads are never requested.",
    "Read-only: every collector account is read-only (sudoers lines, PowerShell, database grants and cloud roles "
    "are generated as read-only templates); ZeroShield needs no administrative or write access.",
    "Encrypted in transit: scan nodes reach ZeroShield over HTTPS (TLS), every node request is signed (Ed25519) "
    "and replay-protected; database passwords are sent only after TLS is verified.",
    "Least privilege: each source uses its own service account with only the read permissions its collector "
    "needs; agent-mode nodes never receive credentials.",
    "Credentials at rest: source secrets are write-only in the UI and API and stored encrypted; a vault reference "
    "keeps the secret in the customer's vault.",
    "Role-based access and audit: platform access is per team and role (RBAC); creating, editing or running a "
    "source, a schedule or an export is written to the audit log with the user and the time.",
    "No stored data is read (SOW 7.2): data-at-rest findings come from declared encryption settings only.",
)

# ---------------------------------------------------------------------------------------------
# Scan windows and OT safety (SOW C6, 7.1, 7.2)
# ---------------------------------------------------------------------------------------------
SCAN_WINDOW_TEXT = (
    "Network and server collection runs only inside the team's scan window (a 7 x 24 hour grid in the team's time "
    "zone; a server group may use its own window). Jobs wait for the next open hour, a running job stops when the "
    "window closes, and the stop-all switch halts every network job at once. Network ranges need the SOC "
    "acknowledgement before a run, honour the never-scan list (addresses, ranges and host names, fail-closed), and "
    "are rate-limited (connections per second, parallel connections per server, handshakes per endpoint)."
)
OT_SAFETY_TEXT = (
    "OT endpoints: an address with an OT port open is scanned in fragile mode. OPC UA is read with the Discovery "
    "service only (GetEndpoints on an unsecured channel; no session, nothing read or written in the address "
    "space). Modbus/TCP: only whether the port accepts connections is recorded; no Modbus request is sent (SOW 7.2). "
    "Modbus/TCP Security (802) is TLS and goes through the TLS probe. OT ranges are agreed with the customer as "
    "OT-safe windows (C6)."
)
SCHEDULE_TEXT = (
    "Re-scans (S4): schedules start runs daily, weekly or monthly at a wall-clock time in the team's time zone, "
    "exactly once per slot. Each run records the schedule that started it ('scheduled') or none ('manual'), and its "
    "report and evidence pack carry the drift against the previous comparable run."
)

# ---------------------------------------------------------------------------------------------
# Evidence plan per deliverable (SOW Table 7)
# ---------------------------------------------------------------------------------------------
EVIDENCE_PLAN_COLUMNS = ("SOW", "Deliverable", "Produced from", "Evidence that supports it")
# Product text: utilities/pdf/cbom_deliverables.py registry, routers/cbom_run_deliverables.py, routers/certin.py.
EVIDENCE_PLAN = (
    ("D1", "Scope Baseline and Asset Population Register", "Team CBOM deliverable #1 (PDF)",
     "Configured sources and every completed scan and collection, with asset counts per source; sign-off block."),
    ("D2", "Discovery Methodology and Evidence Plan", "This document (PDF)",
     "Live configured-source status, collector specifications, run coverage of this edition, Appendix A."),
    ("D3", "CBOM Code Scan Reports", "Code-scan CBOM report per repository (PDF)",
     "Scan id, commit and branch, each finding with file and line, CycloneDX 1.6 export."),
    ("D4", "SBOM", "SBOM scan: CycloneDX JSON, VEX, evidence pack, PDF",
     "Signed evidence pack with SHA-256 manifest; NTIA / CERT-In SBOM field checks."),
    ("D5", "AIBOM", "AIBOM scan: CycloneDX 1.6 ML-BOM, SPDX 3.0, SARIF, VEX, evidence pack, PDF",
     "Signed evidence pack; the AIBOM checks of SOW 3.4 (CERT-In AIBOM, RBI FREE-AI, SEBI CSCRF, NIST AI RMF, "
     "Annex IV)."),
    ("D6", "Infrastructure and Cloud Encryption Posture", "Team CBOM deliverable #5 (PDF)",
     "Declared settings from infrastructure code and L3 read-only API collections, per resource."),
    ("D7", "Network, TLS and Crypto Protocol Assessment", "Team CBOM deliverable #6 (PDF)",
     "Probed endpoints with negotiated protocol and cipher, from L4 handshakes; declared listeners from code."),
    ("D8", "Certificate Estate Register", "Team CBOM deliverable #7 (PDF) and its CSV",
     "Every unique certificate (SHA-256) with validity, algorithm, chain and where it was seen."),
    ("D9", "Data-at-Rest Encryption Assessment", "Team CBOM deliverable #9 (PDF)",
     "Declared encryption of stores, backups and disks (settings only; stored data is not read)."),
    ("D10", "Third-Party Cryptographic Assurance and Attestation Register", "Team CBOM deliverable #10 (PDF)",
     "Third-party components and the attestation ledger with evidence level E0 to E3 and dates."),
    ("D11", "Cryptographic Bill of Materials (CBOM)", "Run CBOM: CycloneDX 1.6 JSON (signed) and XML, VEX, "
     "evidence pack", "Signature over the exact bytes, SHA-256 manifest, drift file against the previous run."),
    ("D12", "Quantum Risk Register", "Team CBOM deliverable #2 (PDF, CSV)",
     "Every asset with its Q-grade and reason, each open Q0 gap, gaps closed by week with their cause."),
    ("D13", "PQC Migration Roadmap", "Team CBOM deliverable #15 (PDF)",
     "Quantum-vulnerable assets with the NIST post-quantum target, wave, date and owner (owner-confirmed)."),
    ("D14", "Board / IT Strategy Committee Report", "Team CBOM deliverable #16 (PDF)",
     "Posture, readiness and regulatory exposure, each figure traceable to D11 and D12."),
)

# ---------------------------------------------------------------------------------------------
# Limits of the method: printed only when the edition's run coverage leaves them true
# ---------------------------------------------------------------------------------------------
_CLOUD_KINDS = frozenset({"aws_account", "azure_subscription", "gcp_project", "oci_tenancy"})
_KEY_KINDS = _CLOUD_KINDS | {"key_manager", "ca_connector"}
_HOST_KINDS = frozenset({"linux_servers", "windows_servers", "host_agent", "kubernetes", "database",
                         "active_directory"})

LIMIT_STATIC_ONLY = (
    "Static analysis only: no CBOM Sources collection is in this edition, so source code, configuration and "
    "certificate or key files are inspected and running systems are not."
)
LIMIT_NO_PROBES = "No live-network discovery in this edition: no TLS, SSH or IKE endpoint was probed."
LIMIT_NO_KEY_SERVICES = (
    "No key service was collected in this edition: cloud KMS, HSM and CA settings are known only from declared "
    "configuration."
)
LIMIT_NO_HOSTS = "No server, cluster or database was collected in this edition: running systems are not inspected."
LIMIT_CUSTODY = (
    "HSM firmware, key custodianship and key escrow are not inspected; HSM coverage is PKCS#11 and KMIP metadata "
    "(SOW 7.2)."
)
LIMIT_STORED_DATA = (
    "Stored data is never read: data-at-rest encryption is assessed from declared settings only (D9, SOW 7.2)."
)
LIMIT_SAAS = (
    "Third-party and SaaS services are visible only through the libraries, configuration and endpoints the "
    "collectors reach, and through vendor attestation (D10)."
)
LIMIT_TEMPLATES = (
    "Pulumi, Ansible and Helm templates are not evaluated, Kustomize is not applied and Terraform state is not read; "
    "values set outside the scanned files stay unresolved and are reported as Unknown (Q0)."
)
LIMIT_LANGUAGES = (
    "Outside Python, Java and Go, algorithm detection in code relies on literal patterns and can miss indirect usage."
)
LIMIT_MODBUS = "Modbus endpoints: only whether the port accepts connections is recorded (no Modbus request)."
LIMIT_FONT = "Names with characters outside the Latin alphabet are printed with '?' because of the PDF font."


def _attr(item: Any, name: str, default: Any = None) -> Any:
    return item.get(name, default) if isinstance(item, dict) else getattr(item, name, default)


def coverage(view: Any) -> dict[str, Any]:
    """What this edition's collections actually did: kinds collected, endpoints probed, collections in scope."""
    found = tuple(getattr(view, "collections", ()) or ())
    kinds = {str(_attr(c, "source_kind", "") or "") for c in found}
    probed = sum(int(_attr(c, "endpoints_probed", 0) or 0) for c in found)
    return {"collections": len(found), "kinds": kinds - {""}, "endpoints_probed": probed}


def method_limits(view: Any) -> tuple[str, ...]:
    """The limits that hold for ``view``: a sentence that denies something is printed only when this edition's
    run coverage did not do it (the constant ``METHOD_LIMITS`` said "no live-network discovery" even when 212
    endpoints had been probed)."""
    cov = coverage(view)
    out: list[str] = []
    if not cov["collections"]:
        out.append(LIMIT_STATIC_ONLY)
    if not cov["endpoints_probed"]:
        out.append(LIMIT_NO_PROBES)
    if cov["collections"] and not cov["kinds"] & _HOST_KINDS:
        out.append(LIMIT_NO_HOSTS)
    if not cov["kinds"] & _KEY_KINDS:
        out.append(LIMIT_NO_KEY_SERVICES)
    out += [LIMIT_CUSTODY, LIMIT_STORED_DATA, LIMIT_SAAS, LIMIT_TEMPLATES, LIMIT_LANGUAGES, LIMIT_MODBUS, LIMIT_FONT]
    return tuple(out)


def method_scope_sentence(view: Any) -> str:
    """The disclaimer box's method sentence for D2: short (the box clamps at 600 characters), and true for the run
    coverage of this edition; the full coverage is in the body."""
    cov = coverage(view)
    if not cov["collections"]:
        return ("Method: static analysis of repositories and uploaded artefacts in this edition; the collection methods "
                "of SOW Section 2 are described in section 2 and apply once sources are collected.")
    probed = cov["endpoints_probed"]
    noun = "collection" if cov["collections"] == 1 else "collections"
    probes = (f"{probed} endpoint{'' if probed == 1 else 's'} probed" if probed else "no endpoint probed")
    return (f"Method: code scanning plus {cov['collections']} CBOM Sources {noun} (agentless, agent and read-only "
            f"API; {probes}). Section 2 lists every source type and section 12 the limits of this edition.")


__all__ = [
    "AGENT", "AGENTLESS", "API", "ASSET_TYPE_ROWS", "COLLECTORS", "COLLECTOR_BY_KIND", "CONFIGURED",
    "DATA_PROTECTION", "EVIDENCE_BY_METHOD", "EVIDENCE_CHAIN", "EVIDENCE_LEVELS", "EVIDENCE_PLAN",
    "EVIDENCE_PLAN_COLUMNS", "FIX_CLASSES", "GRADING_TEXT", "LAYERS", "METHODS", "METHOD_COLUMNS", "METHOD_ROWS",
    "NOT_CONFIGURED", "NOT_LOADED", "OT_SAFETY_TEXT", "OUT_OF_SOW_NOTE", "Q0_POLICY", "Q0_REASONS", "Q_GRADE_ROWS",
    "RISK_SCORING_TEXT", "SCAN_WINDOW_TEXT", "SCHEDULE_TEXT", "SOW_ID", "SOW_SOURCE_TYPES", "SOW_TABLE_COLUMNS",
    "SOW_TABLE_NOTE", "CollectorSpec", "SowSourceType", "coverage", "method_limits", "method_scope_sentence",
]

# ---------------------------------------------------------------------------------------------
# Manual checklist, made true for the edition (cbom_deliverable_text.MANUAL_DISCOVERY_ITEMS is shared with D1)
# ---------------------------------------------------------------------------------------------
MANUAL_LIVE_TLS = "Live TLS endpoints"
MANUAL_KEY_CUSTODY = "HSM and KMS key custody"
# Product text: key_manager / ca_connector / cloud collectors read key METADATA; custody is SOW 7.2-excluded.
MANUAL_KEY_CUSTODY_COLLECTED = (
    "Key metadata is collected (section 3). Custodianship, ceremonies and escrow are not inspected (SOW 7.2): record "
    "them as evidence areas (E0 to E3)."
)


def probed_note(probed: int) -> str:
    noun = "endpoint was" if probed == 1 else "endpoints were"
    return (f"Live TLS endpoints are not a manual item in this edition: {probed} {noun} probed by CBOM Sources "
            "collections (Appendix A).")


def key_kinds_collected(view: Any) -> bool:
    return bool(coverage(view)["kinds"] & _KEY_KINDS)
