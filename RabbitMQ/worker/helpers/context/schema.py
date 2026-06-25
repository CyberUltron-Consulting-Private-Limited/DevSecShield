from pydantic import BaseModel, Field
from helpers.context.enums import * 


class IndividualLogicalComponent(BaseModel):
    title: str = Field(..., description="The title of the logical component")
    description: str = Field(..., description="The description of the logical component")
    dependencies: list[str] = Field(..., description="A List of Dependencies of the logical component")
    business_logic: str = Field(..., description="A Detailed summary of the business logic of the logical component")

class LogicalComponents(BaseModel):
    logical_components : list[IndividualLogicalComponent] = Field(..., description="A List of Logical Components of the Codebase")


class BaseVulnerability(BaseModel):
    title : str = Field(description="The title of the vulnerability")
    description : str = Field(description="The description of the vulnerability")
    impact : Impact = Field(description="The impact of the vulnerability")
    owasp_top_10 : list[OWASPTop10] = Field(description="A list of OWASP top 10 vulnerabilities that this vulnerability is related to")
    compliance_controls : list[ComplianceControls] = Field(description="A list of compliance controls that this vulnerability is related to")
    suggested_fix : str = Field(description="The suggested fix for the vulnerability")

class CodebaseVulnerability(BaseVulnerability):
    location : str = Field(description="The location of the vulnerability in the codebase i.e. its file path ")
    snippet : str = Field(description="The snippet of code that contains the vulnerability")

class IACVulnerability(CodebaseVulnerability):
    category : IACVulnerabilityCategory = Field(description="The category of the IAC vulnerability")
    resource : str = Field(description="The name of the resource that is vulnerable ( get this from the code snippet )")


class DependencyVulnerability(BaseVulnerability):
    dependency : str = Field(description="The name of the dependency / package ( with version ) that is vulnerable")
    reachability : Reachability = Field(description="The reachability of the vulnerability")
    dependency_type : DependencyType = Field(description="The type of the dependency / package ,whether it is a direct or transitive dependency")
    license_type : LicenseCategory = Field(description="The license type of the dependency / package , whether it is permissive, weak_copyleft, strong_copyleft, network_copyleft, source_available, commercial, public_domain, creative_commons, unknown . You are allowed to guess the license type based on your knowledge of the dependency / package")



class FallbackCVEEnum(Enum):
    cve_2025_55182 = "Pre-authentication remote code execution in React Server Components due to unsafe deserialization."  # CVE-2025-55182 description from NVD. :contentReference[oaicite:2]{index=2}
    cve_2025_14847 = "Critical MongoDB vulnerability allowing unauthenticated heap memory extraction (MongoBleed)."  # Based on analysis. :contentReference[oaicite:3]{index=3}
    cve_2025_59230 = "Windows Remote Access Connection Manager race condition, enabling privilege escalation and code execution."  # Critical Windows flaw. :contentReference[oaicite:4]{index=4}
    cve_2025_61882 = "Oracle E-Business Suite vulnerability remotely exploitable without authentication, may lead to code execution."  # Oracle - RCE. :contentReference[oaicite:5]{index=5}
    cve_2025_61492 = "Command injection in terminal-controller-mcp allowing arbitrary command execution via crafted input."  # Recent critical injection. :contentReference[oaicite:6]{index=6}
    cve_2025_59719 = "Fortinet products critical remote administrative access via crafted SAML messages."  # Two Fortinet CVEs actively exploited. :contentReference[oaicite:7]{index=7}
    cve_2025_59718 = "Fortinet remote admin access vulnerability allowing attackers to bypass SSO protections."  # Twin Fortinet issue. :contentReference[oaicite:8]{index=8}
    cve_2025_13630 = "Critical type confusion flaw in Google Chrome V8 JavaScript engine."  # Chrome critical patch. :contentReference[oaicite:9]{index=9}
    cve_2025_15471 = "Remote OS command injection in TRENDnet TEW-713RE affecting network control interface."  # Recent NVD report. :contentReference[oaicite:10]{index=10}
    cve_2025_15001 = "Vulnerability catalog entry (details pending), monitored for critical impact."  # Placeholder as latest critical tracking entry. :contentReference[oaicite:11]{index=11}
    cve_2025_55204 = "Recently disclosed CVE pending classification in KEV, potential critical impact."  # Current CVE tracking. :contentReference[oaicite:12]{index=12}
    cve_2025_66398 = "Critical CVE-2025-66398 pending Known Exploited Vulnerability (KEV) catalog review."  # Recent entry. :contentReference[oaicite:13]{index=13}
    cve_2025_37164 = "Newly reported critical CVE with detailed analysis pending publication."  # Tracked new CVE. :contentReference[oaicite:14]{index=14}
    cve_2025_55183 = "New highly severe vulnerability under recent critical CVE lists."  # Reported critical. :contentReference[oaicite:15]{index=15}
    cve_2025_14733 = "Recently published critical CVE with details available on monitoring services."  # Tracking critical. :contentReference[oaicite:16]{index=16}
    cve_2025_43529 = "Recently tracked critical vulnerability (details from Red Hot Cyber)."  # Tracked critical. :contentReference[oaicite:17]{index=17}
    cve_2025_62215 = "Critical race condition vulnerability allowing local elevation of privileges."  # Tracked as critical. :contentReference[oaicite:18]{index=18}
    cve_2025_42880 = "Recently published critical CVE entry (details aggregated)."  # New critical entry. :contentReference[oaicite:19]{index=19}
    cve_2025_49704 = "Critical Microsoft SharePoint remote code execution vulnerability."  # SharePoint critical. :contentReference[oaicite:20]{index=20}
    cve_2025_49706 = "Critical SharePoint spoofing vulnerability enabling unauthenticated access."  # SharePoint critical. :contentReference[oaicite:21]{index=21}



class LLMVulnerabilityPredictions(BaseModel):
    prompt_injection_score : int = Field(description="A score indicating the likelihood of prompt injection vulnerability , score ranges from 0 to 10")
    jailbreak_score : int = Field(description="A score indicating the likelihood of jailbreak vulnerability , score ranges from 0 to 10")
    bias_score : int = Field(description="A score indicating the likelihood of bias vulnerability , score ranges from 0 to 10")
    hallucination_score : int = Field(description="A score indicating the likelihood of hallucination vulnerability , score ranges from 0 to 10")



class LLMBenchmarkingVulnerability(BaseModel):
    title : str = Field(description="The title of the vulnerability")
    description : str = Field(description="The description of the vulnerability")
    impact : Impact = Field(description="The impact of the vulnerability")
    vulnerability_predictions : LLMVulnerabilityPredictions = Field(description="The predictions of the vulnerability")
    owasp_top_10_llm : list[OWASPTop10LLM] = Field(description="A list of OWASP top 10 vulnerabilities that this vulnerability is related to")
    mitre_atlas_tactic : MitreAtlasTactic = Field(description="The MITRE ATLAS tactic that this vulnerability is related to")
    compliance_controls : list[ComplianceControls] = Field(description="A list of compliance controls that this vulnerability is related to")
    suggested_fix : str = Field(description="The suggested fix for the vulnerability")


class LLMModelVulnerability(BaseModel):
    jailbreak_resistance_score : int = Field(description="A score indicating the likelihood of jailbreak resistance vulnerability , score ranges from 0 to 10")
    injection_resistance_score : int = Field(description="A score indicating the likelihood of injection resistance vulnerability , score ranges from 0 to 10")
    hallucination_resistance_score : int = Field(description="A score indicating the likelihood of hallucination resistance vulnerability , score ranges from 0 to 10")
    bias_resistance_score : int = Field(description="A score indicating the likelihood of bias resistance vulnerability , score ranges from 0 to 10")
    content_safety_score : int = Field(description="A score indicating the likelihood of content safety vulnerability , score ranges from 0 to 10")
    data_privacy_score : int = Field(description="A score indicating the likelihood of data privacy vulnerability , score ranges from 0 to 10")

class MCPVulnerability(BaseModel):
    title : str = Field(description="The title of the vulnerability for the tool/resource")
    description : str = Field(description="The description of the vulnerability for the tool/resource")
    impact : Impact = Field(description="The impact of the vulnerability")
    owasp_top_10 : list[OWASPTop10] = Field(description="A list of OWASP top 10 vulnerabilities that this vulnerability is related to")
    owasp_top_10_llm : list[OWASPTop10LLM] = Field(description="A list of OWASP top 10 vulnerabilities that this vulnerability is related to")
    compliance_controls : list[ComplianceControls] = Field(description="A list of compliance controls that this vulnerability is related to")
    suggested_fix : str = Field(description="The suggested fix for the vulnerability")

class MCPResourceResponse(BaseModel):
    resource_category : MCPResourceCategory = Field(description="The category of the resource")
    resource_risk_level : Impact = Field(description="The risk level of the resource")


# ========================================= CBOM Schemas =========================================

class CryptographicAssetVulnerability(BaseVulnerability):
    algorithm_name : str = Field(description="The name of the cryptographic algorithm or asset, e.g. AES-256-GCM, RSA-2048, MD5, TLS 1.2")
    algorithm_type : CryptoAssetType = Field(description="The type of the cryptographic asset")
    crypto_strength : CryptoStrength = Field(description="The strength classification of the cryptographic asset")
    key_size : int | None = Field(default=None, description="The key size in bits, if applicable")
    quantum_safe : bool = Field(description="Whether the cryptographic asset is quantum-safe (post-quantum cryptography)")
    location : str = Field(description="The file path where the cryptographic usage was detected")
    snippet : str = Field(description="The code or configuration snippet containing the cryptographic usage")


# ========================================= AI-BOM Schemas =========================================

class AIComponentVulnerability(BaseVulnerability):
    # AI-BOM findings are LLM-application risks; the web-app OWASP Top 10 is
    # rarely relevant and is not guided by the AI-BOM prompt (only
    # owasp_top_10_llm is). Override the required BaseVulnerability field with a
    # default so structured-output validation does not force the model to
    # hallucinate web-OWASP entries. This override is scoped to the AI-BOM model
    # only and does not relax the requirement on other BaseVulnerability
    # subclasses (sast/iac/sbom_sca/cbom).
    owasp_top_10 : list[OWASPTop10] = Field(default_factory=list, description="A list of OWASP top 10 (web) vulnerabilities that this component is related to; usually empty for AI/ML components — prefer owasp_top_10_llm")
    component_name : str = Field(description="The name of the AI/ML component, e.g. gpt-4o, claude-3-5-sonnet, model.pkl, bert-base-uncased")
    component_type : AIComponentType = Field(description="The type of the AI/ML component, e.g. local_model_file, external_provider, huggingface_model, ml_framework")
    framework : str | None = Field(default=None, description="The framework or library the component is used through, e.g. langchain, transformers, pytorch, openai-sdk")
    version : str | None = Field(default=None, description="The version of the AI/ML component or model, if applicable")
    source : ModelProvider = Field(description="The provider or source of the AI/ML component, e.g. openai, anthropic, huggingface, local")
    license : str | None = Field(default=None, description="The license of the AI/ML component or model, if applicable")
    location : str = Field(description="The file path where the AI/ML component usage was detected")
    snippet : str = Field(description="The code or configuration snippet containing the AI/ML component usage")
    risk_category : AIRiskCategory = Field(description="The AI-specific risk category classification for this component")
    owasp_top_10_llm : list[OWASPTop10LLM] = Field(default_factory=list, description="A list of OWASP Top 10 for LLM Applications vulnerabilities that this component is related to")





