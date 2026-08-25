import json
from typing import Any, Dict

from rich.console import Console

from helpers.schema import (
    DASTVulnerability,
    ComplianceControls,
    Impact,
    OWASPTop10,
    DASTConfidence,
    DASTVulnerabilityGroup
)
console = Console(markup=False)



def parse_vuln_list(data_list: list[type[DASTVulnerability]]) -> list[dict]:
    try:
        return [parse_vuln(vuln) for vuln in data_list]
    except Exception as e:
        raise ValueError(f"Error parsing DAST vulnerability list: {e}")

def parse_vuln(vuln: type[DASTVulnerability]) -> dict:
    try:
        # initial dictionary dump 
        dumped = vuln.model_dump()


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
        
        
        if "impact" in dumped:
            console.print(f"⚠️ Impact found in dumped,parsing it...",style="bold yellow")
            impact : type[Impact] = dumped["impact"]
            dumped["impact"] = impact.value
            console.print(f"✅ Impact parsed successfully",style="bold green")
        
        if "category" in dumped:
            console.print(f"⚠️ Category found in dumped,parsing it...",style="bold yellow")
            category : type[DASTVulnerabilityGroup] = dumped["category"]
            dumped["category"] = category.value
            console.print(f"✅ Category parsed successfully",style="bold green")
        
        if "confidence" in dumped:
            console.print(f"⚠️ Confidence found in dumped,parsing it...",style="bold yellow")
            confidence : type[DASTConfidence] = dumped["confidence"]
            dumped["confidence"] = confidence.value
            console.print(f"✅ Confidence parsed successfully",style="bold green")
        
        console.print(f"✅ Vulnerability parsed successfully",style="bold green")
        return dumped
        
      
    
    except Exception as e:
        raise ValueError(f"Error parsing base vulnerability: {e}")
    