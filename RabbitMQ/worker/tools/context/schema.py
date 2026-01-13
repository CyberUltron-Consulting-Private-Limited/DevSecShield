from pydantic import BaseModel, Field
from enums import * 




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


