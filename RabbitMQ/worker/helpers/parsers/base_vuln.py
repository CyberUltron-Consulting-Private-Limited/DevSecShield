import json
from helpers.context.schema import BaseVulnerability , CodebaseVulnerability , DependencyVulnerability , OWASPTop10 , ComplianceControls , FallbackCVEEnum , Impact
from typing import Any, Dict
from rich.console import Console
console = Console()

def parse_vuln(data: type[BaseVulnerability] | type[CodebaseVulnerability] | type[DependencyVulnerability]) -> dict:
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
        
        console.print(f"✅ Vulnerability parsed successfully",style="bold green")
        return dumped
    
    except Exception as e:
        raise ValueError(f"Error parsing base vulnerability: {e}")
    