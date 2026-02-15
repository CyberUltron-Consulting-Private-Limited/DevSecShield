from backend.new_models import Scan, scan_types
from rich.console import Console
from sqlmodel import Session, select
from fastapi import HTTPException
from backend.get_db import get_db
from collections import defaultdict
from backend.get_db import dev_environment

console = Console()
def generate_scan_dashboard(
    scan_type: scan_types,
    scan_id: int | None = None , 
    scan_object: Scan | None = None,
    scan_results: list[dict] | None = None,
    ) -> dict:
    """
    Generate a dashboard for a scan.
    Args:
        scan_id: The ID of the scan.
        scan_object: The scan object.
    Returns:
        A dictionary containing the dashboard data.
    """
    try:
        # STEP [ 0 ] : =========== Get the Scan Object and get results ===========================
        scan = None 
        if scan_id:
            engine = get_db(dev_environment=dev_environment)
            with Session(engine) as session:
                scan = session.exec(select(Scan).where(Scan.id == scan_id)).first()
                if not scan:
                    raise HTTPException(status_code=404, detail="Scan not found")
        elif scan_object:
            scan = scan_object
        
        
        if scan:
            results = scan.scan_data
        elif scan_results:
            results = scan_results
        else:
            raise ValueError("Either scan_id or scan_object or scan_results must be provided")
        

        # ------------------------------ SAST Dashboard Generation ------------------------------
        if scan_type == "sast":    
            # STEP [ 1 ] : =========== Generate the Dashboard ===========================
            owasp_top_10_metrics = defaultdict(int)
            compliance_controls_metrics = defaultdict(int)
            risk_metrics = {
                "Low": 0,
                "Medium": 0,
                "High": 0,
                "Critical": 0
            }
            cves_per_vulnerability = defaultdict(int)

            # STEP [ 1a ] : -----------------> Calculate Metrics on OWASP Top 10 and compliance controls in findings 
            for item in results:
                for vulnerability in item["vulnerabilities"]:
                    for key,value in vulnerability["owasp_top_10"].items(): 
                        owasp_top_10_metrics[value] += 1
                    for key,value in vulnerability["compliance_controls"].items():
                        compliance_controls_metrics[value] += 1
                    risk_metrics[vulnerability["impact"]] += 1
                    for key,value in vulnerability["cves"].items():
                        cves_per_vulnerability[value] += 1
            

            return {
                "owasp_top_10_metrics": owasp_top_10_metrics,
                "compliance_controls_metrics": compliance_controls_metrics,
                "risk_metrics": risk_metrics,
                "cves_per_vulnerability": cves_per_vulnerability
            }
    
        elif scan_type == "sbom_sca":
            # STEP [ 1 ] : =========== Generate the Dashboard ===========================
            owasp_top_10_metrics = defaultdict(int)
            compliance_controls_metrics = defaultdict(int)
            risk_metrics = {
                "Low": 0,
                "Medium": 0,
                "High": 0,
                "Critical": 0
            }
            cves_per_vulnerability = defaultdict(int)

            # STEP [ 1a ] : -----------------> Calculate Metrics on OWASP Top 10 and compliance controls in findings 
            for vulnerability in results:
                for key,value in vulnerability["owasp_top_10"].items(): 
                    owasp_top_10_metrics[value] += 1
                for key,value in vulnerability["compliance_controls"].items():
                    compliance_controls_metrics[value] += 1
                risk_metrics[vulnerability["impact"]] += 1
                for key,value in vulnerability["cves"].items():
                    cves_per_vulnerability[value] += 1
            

            return {
                "owasp_top_10_metrics": owasp_top_10_metrics,
                "compliance_controls_metrics": compliance_controls_metrics,
                "risk_metrics": risk_metrics,
                "cves_per_vulnerability": cves_per_vulnerability
            }
        
        elif scan_type == "iac" :

            # STEP [ 1 ] : =========== Generate the Dashboard ===========================
            owasp_top_10_metrics = defaultdict(int)
            compliance_controls_metrics = defaultdict(int)
            compliance_standards_metrics = defaultdict(int)
            risk_metrics = {
                "Low": 0,
                "Medium": 0,
                "High": 0,
                "Critical": 0
            }

            # STEP [ 1a ] : -----------------> Calculate Metrics on OWASP Top 10 and compliance controls in findings 
            for vulnerability in results:
                for key,value in vulnerability["owasp_top_10"].items(): 
                    owasp_top_10_metrics[value] += 1
                for key,value in vulnerability["compliance_controls"].items():
                    compliance_controls_metrics[value] += 1
                    compliance_standard = value.split(" - ")[0]
                    compliance_standards_metrics[compliance_standard] += 1 
                    
                risk_metrics[vulnerability["impact"]] += 1
                for key,value in vulnerability["cves"].items():
                    cves_per_vulnerability[value] += 1
            
            
            """
                compliance_controls_metrics will look like this : 
                {
                    "NIST 800-53 - Access Control": 23 , 
                    "ISO 27001 - A.9 Access Control": 45 , 
                    "PCI DSS - 12.3 Data Protection": 12 , 
                }

                compliance_standards_metrics will look like this : 
                {
                    "NIST 800-53": 23 , 
                    "ISO 27001": 45 , 
                    "PCI DSS": 12 , 
                }

                risk_metrics will look like this : 
                {
                    "Low": 23 , 
                    "Medium": 45 , 
                    "High": 12 , 
                    "Critical": 5 , 
                }

                owasp_top_10_metrics will look like this : 
                {
                    "A01:2021 - Broken Access Control": 23 , 
                    "A02:2021 - Cryptographic Failures": 45 , 
                    "A03:2021 - Injection": 12 , 
                }
            """
            
            
            
            
            return {
                "owasp_top_10_metrics": owasp_top_10_metrics,
                "compliance_controls_metrics": compliance_controls_metrics,
                "risk_metrics": risk_metrics,
                "compliance_standards_metrics": compliance_standards_metrics
            }
        
        elif scan_type == "mcp":
            # STEP [ 1 ] : =========== Generate the Dashboard ===========================
            owasp_top_10_metrics = defaultdict(int)
            owasp_top_10_llm_metrics = defaultdict(int)
            compliance_controls_metrics = defaultdict(int)
            risk_metrics = {
                "Low": 0,
                "Medium": 0,
                "High": 0,
                "Critical": 0
            }
            tools_detected:int = 0 
            tools_vulnerability_metrics = defaultdict(int)
            tools_impact_metrics : dict = {}
            tools_compliance_controls_metrics : dict = {}

            # STEP [ 1a ] : -----------------> Calculate Metrics on OWASP Top 10 and compliance controls in findings 
            for tool in results.get("tools", []):
                tools_detected += 1
                tools_vulnerability_metrics[tool["tool_name"]] = len(tool["vulnerabilities"])
                tools_impact_metrics[tool["tool_name"]] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
                tools_compliance_controls_metrics[tool["tool_name"]] = 0 
                for vulnerability in tool["vulnerabilities"]:
                    for key, val in (vulnerability.get("owasp_top_10") or {}).items():
                        owasp_top_10_metrics[val] += 1
                    for key, val in (vulnerability.get("owasp_top_10_llm") or {}).items():
                        owasp_top_10_llm_metrics[val] += 1
                    for key, val in (vulnerability.get("compliance_controls") or {}).items():
                        compliance_controls_metrics[val] += 1
                        tools_compliance_controls_metrics[tool["tool_name"]] += 1
                    risk_metrics[vulnerability["impact"]] += 1
                    impact_key = (vulnerability.get("impact") or "unknown").lower()
                    if impact_key in tools_impact_metrics[tool["tool_name"]]:
                        tools_impact_metrics[tool["tool_name"]][impact_key] += 1

                    """
                    tools_vulnerability_metrics will look like this : 
                    {
                        "tool_name": 23 , 
                        "tool_name2": 45 , 
                        "tool_name3": 12 , 
                    }

                    tools_detected will be integer value of the number of tools detected in the scan

                    tools_impact_metrics will look like this : 
                    {
                        "tool_name": {
                            "critical": 0,
                            "high": 0,
                            "medium": 0,
                            "low": 0
                        }
                    }

                    tools_compliance_controls_metrics will look like this : 
                    {
                        "tool_name": 23 , 
                        "tool_name2": 45 , 
                        "tool_name3": 12 , 
                    }
                    """
            

            return {
                "owasp_top_10_metrics": owasp_top_10_metrics,
                "compliance_controls_metrics": compliance_controls_metrics,
                "risk_metrics": risk_metrics,
                "tools_detected": tools_detected,
                "tools_vulnerability_metrics": tools_vulnerability_metrics,
                "tools_impact_metrics": tools_impact_metrics,
                "tools_compliance_controls_metrics": tools_compliance_controls_metrics
            }

        
        elif scan_type == "llm":
            owasp_top_10_llm_metrics = defaultdict(int)
            compliance_controls_metrics = defaultdict(int)
            risk_metrics = {
                "Low": 0,
                "Medium": 0,
                "High": 0,
                "Critical": 0
            }
            vuln_list = results if isinstance(results, list) else (results.get("vulnerabilities") or [])
            for vulnerability in vuln_list:
                if not isinstance(vulnerability, dict):
                    continue
                owasp_llm = vulnerability.get("owasp_top_10_llm")
                if isinstance(owasp_llm, dict):
                    for key, val in owasp_llm.items():
                        owasp_top_10_llm_metrics[val] += 1
                elif isinstance(owasp_llm, list):
                    for item in owasp_llm:
                        if isinstance(item, dict):
                            for key, val in item.items():
                                owasp_top_10_llm_metrics[val] += 1
                compliance = vulnerability.get("compliance_controls")
                if isinstance(compliance, dict):
                    for key, val in compliance.items():
                        compliance_controls_metrics[val] += 1
                elif isinstance(compliance, list):
                    for item in compliance:
                        if isinstance(item, dict):
                            for key, val in item.items():
                                compliance_controls_metrics[val] += 1
                impact = vulnerability.get("impact")
                if isinstance(impact, str) and impact.strip():
                    impact_key = impact.strip().capitalize()
                    if impact_key in risk_metrics:
                        risk_metrics[impact_key] += 1
            
            console.print(f"OWASP Top 10 LLM Metrics: {owasp_top_10_llm_metrics}",style="bold yellow1")
            console.print(f"Compliance Controls Metrics: {compliance_controls_metrics}",style="bold yellow")
            console.print(f"Risk Metrics: {risk_metrics}",style="bold orange1")
            return {
            "owasp_top_10_llm_metrics": dict(owasp_top_10_llm_metrics),
                "compliance_controls_metrics": dict(compliance_controls_metrics),
                "risk_metrics": risk_metrics,
            }

            

    except Exception as e:
        console.print(f"Error in generate_scan_dashboard: {e}",style="bold red")
        raise e