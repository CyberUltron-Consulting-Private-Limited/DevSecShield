import json
from enum import Enum
from typing import Any, Dict

from rich.console import Console

from helpers.context.schema import (
    BaseVulnerability,
    CodebaseVulnerability,
    ComplianceControls,
    DependencyVulnerability,
    FallbackCVEEnum,
    Impact,
    MCPVulnerability,
    OWASPTop10,
    OWASPTop10LLM,
    IACVulnerabilityCategory,
    Reachability,
    LicenseCategory,
    DependencyType,
    MitreAtlasTactic,
    CryptographicAssetVulnerability,
)
from helpers.context.enums import CryptoAssetType, CryptoStrength, AIComponentType, AIRiskCategory, ModelProvider
console = Console()

def parse_vuln(data: type[BaseVulnerability] | type[CodebaseVulnerability] | type[DependencyVulnerability] | type[MCPVulnerability]) -> dict:
    try:
        # initial dictionary dump 
        dumped = data.model_dump()


        # convert owasp top 10 enums to proper format { enum_name : enum_value }
        if "owasp_top_10" in dumped:
            console.print(f"⚠️ Owasp top 10 found in dumped,parsing it...",style="bold yellow")
            owasp_top_10_list : list[type[OWASPTop10]] = dumped["owasp_top_10"]
            temp_owasp_top_10 = {}
            for owasp in owasp_top_10_list:
                temp_owasp_top_10[owasp.name] = owasp.value
            dumped["owasp_top_10"] = temp_owasp_top_10
            console.print(f"✅ Owasp top 10 parsed successfully",style="bold green")


        # convert compliance controls enums to proper format { enum_name : enum_value }
        if "compliance_controls" in dumped:
            console.print(f"⚠️ Compliance controls found in dumped,parsing it...",style="bold yellow")
            compliance_controls_list : list[type[ComplianceControls]] = dumped["compliance_controls"]
            temp_compliance_controls = {}
            for compliance_control in compliance_controls_list:
                temp_compliance_controls[compliance_control.name] = compliance_control.value
            dumped["compliance_controls"] = temp_compliance_controls
            console.print(f"✅ Compliance controls parsed successfully",style="bold green")
        
        if "cves" in dumped:
            console.print(f"⚠️ CVE's found in dumped,parsing it...",style="bold yellow")
            cves_list : list[type[FallbackCVEEnum]] = dumped["cves"]
            temp_cves = {}
            for cve in cves_list:
                temp_cves[cve.name] = cve.value
            dumped["cves"] = temp_cves
            console.print(f"✅ CVE's parsed successfully",style="bold green")
        
        if "impact" in dumped:
            console.print(f"⚠️ Impact found in dumped,parsing it...",style="bold yellow")
            impact : type[Impact] = dumped["impact"]
            dumped["impact"] = impact.value
            console.print(f"✅ Impact parsed successfully",style="bold green")
        
        if "category" in dumped:
            console.print(f"⚠️ Category found in dumped,parsing it...",style="bold yellow")
            category : type[IACVulnerabilityCategory] = dumped["category"]
            dumped["category"] = category.value
            console.print(f"✅ Category parsed successfully",style="bold green")
        
        if "owasp_top_10_llm" in dumped:
            console.print(f"⚠️ Owasp top 10 LLM found in dumped,parsing it...",style="bold yellow")
            owasp_top_10_llm_list : list[type[OWASPTop10LLM]] = dumped["owasp_top_10_llm"]
            temp_owasp_top_10_llm = {}
            for owasp_llm in owasp_top_10_llm_list:
                temp_owasp_top_10_llm[owasp_llm.name] = owasp_llm.value
            dumped["owasp_top_10_llm"] = temp_owasp_top_10_llm
            console.print(f"✅ Owasp top 10 LLM parsed successfully",style="bold green")
        
        if "license_type" in dumped:
            console.print(f"⚠️ License type found in dumped,parsing it...",style="bold yellow")
            license_type : type[LicenseCategory] = dumped["license_type"]
            dumped["license_type"] = license_type.value
            console.print(f"✅ License type parsed successfully",style="bold green")
        
        if "dependency_type" in dumped:
            console.print(f"⚠️ Dependency type found in dumped,parsing it...",style="bold yellow")
            dependency_type : type[DependencyType] = dumped["dependency_type"]
            dumped["dependency_type"] = dependency_type.value
            console.print(f"✅ Dependency type parsed successfully",style="bold green")
        
        if "reachability" in dumped:
            console.print(f"⚠️ Reachability found in dumped,parsing it...",style="bold yellow")
            reachability : type[Reachability] = dumped["reachability"]
            dumped["reachability"] = reachability.value
            console.print(f"✅ Reachability parsed successfully",style="bold green")
        
        if "mitre_atlas_tactic" in dumped:
            console.print(f"⚠️ Mitre Atlas Tactic found in dumped,parsing it...",style="bold yellow")
            mitre_atlas_tactic : type[MitreAtlasTactic] = dumped["mitre_atlas_tactic"]
            dumped["mitre_atlas_tactic"] = mitre_atlas_tactic.value
            console.print(f"✅ Mitre Atlas Tactic parsed successfully",style="bold green")
        
        if "algorithm_type" in dumped:
            console.print(f"⚠️ Algorithm type found in dumped,parsing it...",style="bold yellow")
            algorithm_type : type[CryptoAssetType] = dumped["algorithm_type"]
            dumped["algorithm_type"] = algorithm_type.value
            console.print(f"✅ Algorithm type parsed successfully",style="bold green")
        
        if "crypto_strength" in dumped:
            console.print(f"⚠️ Crypto strength found in dumped,parsing it...",style="bold yellow")
            crypto_strength : type[CryptoStrength] = dumped["crypto_strength"]
            dumped["crypto_strength"] = crypto_strength.value
            console.print(f"✅ Crypto strength parsed successfully",style="bold green")

        if "component_type" in dumped:
            console.print(f"⚠️ Component type found in dumped,parsing it...",style="bold yellow")
            component_type : type[AIComponentType] = dumped["component_type"]
            dumped["component_type"] = component_type.value
            console.print(f"✅ Component type parsed successfully",style="bold green")

        if "risk_category" in dumped:
            console.print(f"⚠️ Risk category found in dumped,parsing it...",style="bold yellow")
            risk_category : type[AIRiskCategory] = dumped["risk_category"]
            dumped["risk_category"] = risk_category.value
            console.print(f"✅ Risk category parsed successfully",style="bold green")

        if "source" in dumped and isinstance(dumped["source"], Enum):
            console.print(f"⚠️ Source found in dumped,parsing it...",style="bold yellow")
            source : type[ModelProvider] = dumped["source"]
            dumped["source"] = source.value
            console.print(f"✅ Source parsed successfully",style="bold green")

        console.print(f"✅ Vulnerability parsed successfully",style="bold green")
        return dumped
    
    except Exception as e:
        raise ValueError(f"Error parsing base vulnerability: {e}")
    