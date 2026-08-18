from enum import Enum


class MCPResourceCategory(str, Enum):
    WEB = "web"                         # HTTP, APIs, browsing, crawling
    FILE_SYSTEM = "file_system"         # read/write/list local or remote files
    CODE_EXECUTION = "code_execution"   # run code, scripts, shells, notebooks
    DATABASE = "database"               # SQL / NoSQL databases
    SEARCH = "search"                   # full-text or indexed search engines
    VECTOR_STORE = "vector_store"       # embedding / vector databases
    DOCUMENT_STORE = "document_store"   # blob / object / document storage
    CACHE = "cache"                     # in-memory or key-value stores

    AI_MODEL = "ai_model"               # LLMs, ML inference endpoints
    EMBEDDING = "embedding"             # embedding generation services

    AUTH = "auth"                       # auth, users, tokens, identity
    SECRETS = "secrets"                 # secret managers / vaults

    VERSION_CONTROL = "version_control" # git and similar systems
    PACKAGE_REGISTRY = "package_registry"  # artifact / package repositories

    CONTAINER = "container"             # container runtimes / images
    CLOUD = "cloud"                     # cloud control planes / infra APIs

    MESSAGE_QUEUE = "message_queue"     # queues / pub-sub
    EVENT_STREAM = "event_stream"       # streaming systems

    SCHEDULER = "scheduler"             # cron, job schedulers, workflow runners
    OBSERVABILITY = "observability"     # logs, metrics, traces

    CONFIG = "config"                   # configuration / feature flags / params


class LicenseCategory(Enum):
    """
    Risk level splitup :

    Low risk ---> permissive , public_domain , not_declared

    Medium risk ---> weak_copyleft , creative_commons , commercial

    High risk ---> strong_copyleft , network_copyleft , source_available

    """
    PERMISSIVE = "permissive"
    WEAK_COPYLEFT = "weak_copyleft"
    STRONG_COPYLEFT = "strong_copyleft"
    NETWORK_COPYLEFT = "network_copyleft"
    SOURCE_AVAILABLE = "source_available"
    COMMERCIAL = "commercial"
    PUBLIC_DOMAIN = "public_domain"
    CREATIVE_COMMONS = "creative_commons"
    NOT_DECLARED = "not_declared"

class DependencyType(Enum):
    DIRECT = "direct"
    TRANSITIVE = "transitive"

class Reachability(Enum):
    REACHABLE = "reachable"
    POTENTIALLY_REACHABLE = "potentially_reachable"
    NOT_REACHABLE = "not_reachable"
    NOT_ASSESSED = "not_assessed"


class IACVulnerabilityCategory(Enum):
    NETWORK_SECURITY = "Network Security"
    DATA_PROTECTION = "Data Protection"
    ACCESS_CONTROL = "Access Control"
    LOGGING_AND_MONITORING = "Logging and Monitoring"
    SECRET_MANAGEMENT = "Secret Management"
    AUDIT_AND_COMPLIANCE = "Audit and Compliance"

class OWASPTop10(Enum):
    BROKEN_ACCESS_CONTROL = "A01:2021 - Broken Access Control"
    CRYPTOGRAPHIC_FAILURES = "A02:2021 - Cryptographic Failures"
    INJECTION = "A03:2021 - Injection"
    INSECURE_DESIGN = "A04:2021 - Insecure Design"
    SECURITY_MISCONFIGURATION = "A05:2021 - Security Misconfiguration"
    VULNERABLE_AND_OUTDATED_COMPONENTS = "A06:2021 - Vulnerable and Outdated Components"
    IDENTIFICATION_AND_AUTHENTICATION_FAILURES = "A07:2021 - Identification and Authentication Failures"
    SOFTWARE_AND_DATA_INTEGRITY_FAILURES = "A08:2021 - Software and Data Integrity Failures"
    SECURITY_LOGGING_AND_MONITORING_FAILURES = "A09:2021 - Security Logging and Monitoring Failures"
    SERVER_SIDE_REQUEST_FORGERY = "A10:2021 - Server-Side Request Forgery (SSRF)"


class OWASPTop10LLM(Enum):
    PROMPT_INJECTION = "LLM01:2025 - Prompt Injection"
    INSECURE_OUTPUT_HANDLING = "LLM02:2025 - Insecure Output Handling"
    TRAINING_DATA_POISONING = "LLM03:2025 - Training Data Poisoning"
    MODEL_DENIAL_OF_SERVICE = "LLM04:2025 - Model Denial of Service"
    SUPPLY_CHAIN_VULNERABILITIES = "LLM05:2025 - Supply Chain Vulnerabilities"
    SENSITIVE_INFORMATION_DISCLOSURE = "LLM06:2025 - Sensitive Information Disclosure"
    INSECURE_PLUGIN_DESIGN = "LLM07:2025 - Insecure Plugin Design"
    EXCESSIVE_AGENCY = "LLM08:2025 - Excessive Agency"
    OVERRELIANCE = "LLM09:2025 - Overreliance"
    MODEL_THEFT = "LLM10:2025 - Model Theft"

class MitreAtlasTactic(Enum):
    RECONNAISSANCE = "reconnaissance"
    RESOURCE_DEVELOPMENT = "resource_development"
    INITIAL_ACCESS = "initial_access"

    ML_MODEL_ACCESS = "ml_model_access"

    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DEFENSE_EVASION = "defense_evasion"
    CREDENTIAL_ACCESS = "credential_access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral_movement"

    COLLECTION = "collection"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"

class ComplianceControls(Enum):
    # === ISO 27001 ===
    ISO27001_A5_INFORMATION_SECURITY_POLICIES = "ISO 27001 - A.5 Information Security Policies"
    ISO27001_A6_ORGANIZATION_OF_INFORMATION_SECURITY = "ISO 27001 - A.6 Organization of Information Security"
    ISO27001_A7_HUMAN_RESOURCE_SECURITY = "ISO 27001 - A.7 Human Resource Security"
    ISO27001_A8_ASSET_MANAGEMENT = "ISO 27001 - A.8 Asset Management"
    ISO27001_A9_ACCESS_CONTROL = "ISO 27001 - A.9 Access Control"
    ISO27001_A10_CRYPTOGRAPHY = "ISO 27001 - A.10 Cryptography"
    ISO27001_A11_PHYSICAL_SECURITY = "ISO 27001 - A.11 Physical and Environmental Security"
    ISO27001_A12_OPERATIONS_SECURITY = "ISO 27001 - A.12 Operations Security"
    ISO27001_A13_COMMUNICATIONS_SECURITY = "ISO 27001 - A.13 Communications Security"
    ISO27001_A14_SYSTEM_ACQUISITION = "ISO 27001 - A.14 System Acquisition, Development, and Maintenance"
    ISO27001_A15_SUPPLIER_RELATIONSHIPS = "ISO 27001 - A.15 Supplier Relationships"
    ISO27001_A16_INCIDENT_MANAGEMENT = "ISO 27001 - A.16 Incident Management"
    ISO27001_A17_BUSINESS_CONTINUITY = "ISO 27001 - A.17 Business Continuity"
    ISO27001_A18_COMPLIANCE = "ISO 27001 - A.18 Compliance"

    # === ISO 27002 ===
    ISO27002_5_1 = "ISO 27002 - 5.1 Management direction for information security"
    ISO27002_6_1 = "ISO 27002 - 6.1 Internal organization"
    ISO27002_7_1 = "ISO 27002 - 7.1 Prior to employment"
    ISO27002_9_2 = "ISO 27002 - 9.2 User access management"
    ISO27002_12_1 = "ISO 27002 - 12.1 Operational procedures and responsibilities"

    # === ISO 42001 ===
    ISO42001_1 = "ISO 42001 - AI Risk Management"
    ISO42001_2 = "ISO 42001 - Data Governance and Transparency"
    ISO42001_3 = "ISO 42001 - Model Lifecycle Management"

    # === NIST 800-53 ===
    NIST80053_AC = "NIST 800-53 - Access Control"
    NIST80053_AU = "NIST 800-53 - Audit and Accountability"
    NIST80053_AT = "NIST 800-53 - Awareness and Training"
    NIST80053_CM = "NIST 800-53 - Configuration Management"
    NIST80053_CP = "NIST 800-53 - Contingency Planning"
    NIST80053_IA = "NIST 800-53 - Identification and Authentication"
    NIST80053_IR = "NIST 800-53 - Incident Response"
    NIST80053_MA = "NIST 800-53 - Maintenance"
    NIST80053_MP = "NIST 800-53 - Media Protection"
    NIST80053_PE = "NIST 800-53 - Physical and Environmental Protection"
    NIST80053_PL = "NIST 800-53 - Planning"
    NIST80053_PS = "NIST 800-53 - Personnel Security"
    NIST80053_RA = "NIST 800-53 - Risk Assessment"
    NIST80053_SA = "NIST 800-53 - System and Services Acquisition"
    NIST80053_SC = "NIST 800-53 - System and Communications Protection"
    NIST80053_SI = "NIST 800-53 - System and Information Integrity"

    # === NIST CSF ===
    NIST_CSF_IDENTIFY = "NIST CSF - Identify"
    NIST_CSF_PROTECT = "NIST CSF - Protect"
    NIST_CSF_DETECT = "NIST CSF - Detect"
    NIST_CSF_RESPOND = "NIST CSF - Respond"
    NIST_CSF_RECOVER = "NIST CSF - Recover"

    # === MITRE ATT&CK ===
    MITRE_INITIAL_ACCESS = "MITRE ATT&CK - Initial Access"
    MITRE_EXECUTION = "MITRE ATT&CK - Execution"
    MITRE_PERSISTENCE = "MITRE ATT&CK - Persistence"
    MITRE_PRIVILEGE_ESCALATION = "MITRE ATT&CK - Privilege Escalation"
    MITRE_DEFENSE_EVASION = "MITRE ATT&CK - Defense Evasion"
    MITRE_CREDENTIAL_ACCESS = "MITRE ATT&CK - Credential Access"
    MITRE_DISCOVERY = "MITRE ATT&CK - Discovery"
    MITRE_LATERAL_MOVEMENT = "MITRE ATT&CK - Lateral Movement"
    MITRE_COLLECTION = "MITRE ATT&CK - Collection"
    MITRE_EXFILTRATION = "MITRE ATT&CK - Exfiltration"
    MITRE_COMMAND_AND_CONTROL = "MITRE ATT&CK - Command and Control"

    # === CMMC ===
    CMMC_LEVEL_1 = "CMMC - Level 1 (Basic Cyber Hygiene)"
    CMMC_LEVEL_2 = "CMMC - Level 2 (Intermediate Cyber Hygiene)"
    CMMC_LEVEL_3 = "CMMC - Level 3 (Good Cyber Hygiene)"
    CMMC_LEVEL_4 = "CMMC - Level 4 (Proactive)"
    CMMC_LEVEL_5 = "CMMC - Level 5 (Advanced/Progressive)"

    # === GDPR ===
    GDPR_LAWFULNESS = "GDPR - Lawfulness, fairness, and transparency"
    GDPR_PURPOSE_LIMITATION = "GDPR - Purpose limitation"
    GDPR_DATA_MINIMIZATION = "GDPR - Data minimization"
    GDPR_ACCURACY = "GDPR - Accuracy"
    GDPR_STORAGE_LIMITATION = "GDPR - Storage limitation"
    GDPR_INTEGRITY_CONFIDENTIALITY = "GDPR - Integrity and confidentiality"
    GDPR_ACCOUNTABILITY = "GDPR - Accountability"

    # === NIS Directive ===
    NIS_SECURITY_REQUIREMENTS = "NIS - Security Requirements for Network and Information Systems"
    NIS_INCIDENT_REPORTING = "NIS - Incident Reporting Obligations"
    NIS_SUPERVISION_ENFORCEMENT = "NIS - Supervision and Enforcement Measures"

    # === DORA ===
    DORA_ICT_RISK_MANAGEMENT = "DORA - ICT Risk Management Framework"
    DORA_INCIDENT_HANDLING = "DORA - ICT Incident Handling"
    DORA_DIGITAL_OPERATIONAL_RESILIENCE = "DORA - Digital Operational Resilience Testing"
    DORA_INFORMATION_SHARING = "DORA - Information Sharing"

    # === SOC 2 ===
    SOC2_SECURITY = "SOC 2 - Security"
    SOC2_AVAILABILITY = "SOC 2 - Availability"
    SOC2_PROCESSING_INTEGRITY = "SOC 2 - Processing Integrity"
    SOC2_CONFIDENTIALITY = "SOC 2 - Confidentiality"
    SOC2_PRIVACY = "SOC 2 - Privacy"

    # === HIPAA ===
    HIPAA_PRIVACY_RULE = "HIPAA - Privacy Rule"
    HIPAA_SECURITY_RULE = "HIPAA - Security Rule"
    HIPAA_BREACH_NOTIFICATION_RULE = "HIPAA - Breach Notification Rule"
    HIPAA_ENFORCEMENT_RULE = "HIPAA - Enforcement Rule"

    # === RBI CSF ===
    RBI_CSF_GOVERNANCE = "RBI CSF - Governance"
    RBI_CSF_IDENTIFICATION = "RBI CSF - Risk Identification"
    RBI_CSF_PROTECTION = "RBI CSF - Risk Protection"
    RBI_CSF_DETECTION = "RBI CSF - Threat Detection"
    RBI_CSF_RESPONSE = "RBI CSF - Response and Recovery"

    # === SEBI CSCRF ===
    SEBI_CSCRF_GOVERNANCE = "SEBI CSCRF - Governance and Oversight"
    SEBI_CSCRF_TECH_CONTROLS = "SEBI CSCRF - Technology and Security Controls"
    SEBI_CSCRF_CONTINUITY = "SEBI CSCRF - Business Continuity Management"
    SEBI_CSCRF_AUDIT = "SEBI CSCRF - Audit and Compliance"

    # === PCI DSS ===
    PCI_DSS_REQ_1 = "PCI DSS - Install and maintain a firewall configuration"
    PCI_DSS_REQ_2 = "PCI DSS - Do not use vendor-supplied defaults"
    PCI_DSS_REQ_3 = "PCI DSS - Protect stored cardholder data"
    PCI_DSS_REQ_4 = "PCI DSS - Encrypt transmission of cardholder data"
    PCI_DSS_REQ_5 = "PCI DSS - Use and regularly update anti-virus software"
    PCI_DSS_REQ_6 = "PCI DSS - Develop and maintain secure systems"
    PCI_DSS_REQ_7 = "PCI DSS - Restrict access to cardholder data"
    PCI_DSS_REQ_8 = "PCI DSS - Identify and authenticate access"
    PCI_DSS_REQ_9 = "PCI DSS - Restrict physical access"
    PCI_DSS_REQ_10 = "PCI DSS - Track and monitor all access"
    PCI_DSS_REQ_11 = "PCI DSS - Regularly test security systems"
    PCI_DSS_REQ_12 = "PCI DSS - Maintain an information security policy"

    # === DPDP Act (India) ===
    DPDP_CONSENT = "DPDP Act India - Consent Management"
    DPDP_DATA_MINIMIZATION = "DPDP Act India - Data Minimization"
    DPDP_RETENTION = "DPDP Act India - Retention Limitation"
    DPDP_SECURITY_SAFEGUARDS = "DPDP Act India - Security Safeguards"
    DPDP_GRIEVANCE = "DPDP Act India - Grievance Redressal"

    # === Mitra Framework ===
    MITRA_MONITORING = "Mitra Framework - Continuous Monitoring"
    MITRA_RESPONSE = "Mitra Framework - Automated Response"
    MITRA_MITIGATION = "Mitra Framework - Adaptive Mitigation"
    MITRA_REPORTING = "Mitra Framework - Security Analytics & Reporting"

class Impact(Enum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


# ========================================= CBOM Enums =========================================

class CryptoAssetType(str, Enum):
    HASH = "hash"
    SYMMETRIC_CIPHER = "symmetric_cipher"
    ASYMMETRIC_CIPHER = "asymmetric_cipher"
    MAC = "mac"
    KEY_DERIVATION = "key_derivation"
    SIGNATURE = "signature"
    PROTOCOL = "protocol"
    CERTIFICATE = "certificate"
    KEY = "key"
    SECRET = "secret"
    RANDOM_NUMBER_GENERATOR = "random_number_generator"

class CryptoStrength(str, Enum):
    WEAK = "weak"               # MD5, SHA1, DES, RC4, RSA<1024
    MODERATE = "moderate"       # 3DES, RSA-1024, SHA-224
    STRONG = "strong"           # AES-128+, SHA-256+, RSA-2048+ (but quantum-vulnerable)
    QUANTUM_SAFE = "quantum_safe"  # CRYSTALS-Kyber, Dilithium, SPHINCS+, etc.


# ===== AI-BOM Enums =====

class AIComponentType(str, Enum):
    LOCAL_MODEL_FILE = "local_model_file"
    EXTERNAL_PROVIDER = "external_provider"
    HUGGINGFACE_MODEL = "huggingface_model"
    ML_FRAMEWORK = "ml_framework"
    AI_FRAMEWORK = "ai_framework"
    DATASET = "dataset"
    PROMPT_ASSET = "prompt_asset"
    EMBEDDING_MODEL = "embedding_model"

class AIRiskCategory(str, Enum):
    UNTRUSTED_MODEL_DESERIALIZATION = "untrusted_model_deserialization"
    UNPINNED_MODEL_VERSION = "unpinned_model_version"
    DEPRECATED_EOL_MODEL = "deprecated_eol_model"
    MISSING_MODEL_CARD_LINEAGE = "missing_model_card_lineage"
    LICENSE_COMPLIANCE_GAP = "license_compliance_gap"
    DATA_PRIVACY_TRAINING_CONFIG = "data_privacy_training_config"
    MODEL_THEFT_EXPOSURE = "model_theft_exposure"

class ModelProvider(str, Enum):
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    BEDROCK = "bedrock"
    VERTEX = "vertex"
    COHERE = "cohere"
    MISTRAL = "mistral"
    HUGGINGFACE = "huggingface"
    AZURE = "azure"
    OLLAMA = "ollama"
    PYPI = "pypi"
    CREDENTIAL = "credential"
    LOCAL = "local"
    # Legacy payloads only — emitters/resolvers must never return this.
    UNKNOWN = "unknown"
