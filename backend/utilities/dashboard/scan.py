from backend.new_models import Scan, scan_types
from rich.console import Console
from sqlmodel import Session, select
from fastapi import HTTPException
from backend.get_db import get_db
from collections import defaultdict
from backend.get_db import dev_environment
from backend.utilities.db.findings import get_findings_for_scan_id
from backend.utilities.dashboard.remediation_metrics import get_remediation_metrics
from backend.utilities.dashboard.finding_metrics import get_issue_address_metrics, get_issue_status_metrics

risk_score_for_impact = {
    "critical" : 10.0,
    "high" : 7.5,
    "medium" : 5,
    "low" : 2.5,
}

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
        
        
        if scan and "results" in scan.scan_data:
            results = scan.scan_data["results"] 
        elif scan_results:
            results = scan_results
        else:
            raise ValueError("Either scan_id or scan_object or scan_results must be provided")

        if scan : 
            scan_id = scan.id
        elif not scan_id:
            raise ValueError("Either scan_id or scan_object must be provided")
        

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
            risk_scores_per_finding = defaultdict(float)
            policy_violations = defaultdict(int)

            # STEP [ 1a ] : -----------------> Calculate Metrics on OWASP Top 10 and compliance controls in findings 
            for item in results:
                for vulnerability in item["vulnerabilities"]:

                    # calculating owasp metrics 
                    for key,value in vulnerability["owasp_top_10"].items(): 
                        owasp_top_10_metrics[value] += 1

                    # calculating compliance controls metrics 
                    for key,value in vulnerability["compliance_controls"].items():
                        compliance_controls_metrics[value] += 1

                    # calculating risk metrics 
                    risk_metrics[vulnerability["impact"]] += 1

                    # calculating cves per vulnerability 
                    for key,value in vulnerability["cves"].items():
                        cves_per_vulnerability[value] += 1
                    
                    # calculating risk score per finding 
                    risk_score = risk_score_for_impact[vulnerability["impact"].lower()]
                    risk_scores_per_finding[vulnerability["title"]] = risk_score

                    # calculating policy violations 
                    for key,value in vulnerability["compliance_controls"].items():
                        complaince_standard = value.split(" - ")[0]
                        policy_violations[complaince_standard] += 1

                    # calculate remediation metrics 
                    findings = get_findings_for_scan_id(scan_id)
                    remediation_metrics = get_remediation_metrics(findings)


            return {
                "owasp_top_10_metrics": owasp_top_10_metrics,
                "compliance_controls_metrics": compliance_controls_metrics,
                "risk_metrics": risk_metrics,
                "cves_per_vulnerability": cves_per_vulnerability,
                "remediation_metrics": remediation_metrics,
                "policy_violations": policy_violations,
                "risk_scores_per_finding": risk_scores_per_finding,
            }
    



        elif scan_type == "iac" :
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
            policy_violations = defaultdict(int)
            issues_by_category = defaultdict(int)
            issues_by_severity = defaultdict(int)
            sum_of_risk_scores_per_category = defaultdict(float) # needed for average risk score per category
            average_risk_score_per_category = defaultdict(float)
            issue_status_metrics = defaultdict(int)

            # STEP [ 1a ] : -----------------> Calculate Metrics on OWASP Top 10 and compliance controls in findings 
            for vulnerability in results:

                # calculating owasp metrics 
                for key,value in vulnerability["owasp_top_10"].items(): 
                    owasp_top_10_metrics[key] += 1
                
                # calculating compliance controls metrics 
                for key,value in vulnerability["compliance_controls"].items():
                    compliance_controls_metrics[key] += 1
                
                # calculating risk metrics 
                risk_metrics[vulnerability["impact"]] += 1
                
                # calculating cves per vulnerability 
                for key,value in vulnerability["cves"].items():
                    cves_per_vulnerability[key] += 1
                
                # calculating policy violations 
                for key,value in vulnerability["compliance_controls"].items():
                    complaince_standard = value.split(" - ")[0]
                    policy_violations[complaince_standard] += 1
                
                # issues by category 
                issues_by_category[vulnerability["category"]] += 1
                
                # issues by severity 
                issues_by_severity[vulnerability["impact"]] += 1
                
                # issue status count 
                findings = get_findings_for_scan_id(scan_id)
                issue_status_metrics = get_issue_status_metrics(findings)


                # issue address metrics 
                issue_address_metrics = get_issue_address_metrics(findings)

                # average risk score per category 
                risk_score = risk_score_for_impact[vulnerability["impact"].lower()]
                sum_of_risk_scores_per_category[vulnerability["category"]] += risk_score

            for key,value in sum_of_risk_scores_per_category.items():
                average_risk_score_per_category[key] = value / issues_by_category[key]

            return {
                "owasp_top_10_metrics": owasp_top_10_metrics,
                "compliance_controls_metrics": compliance_controls_metrics,
                "risk_metrics": risk_metrics,
                "cves_per_vulnerability": cves_per_vulnerability,
                "issue_status_metrics": issue_status_metrics,
                "issue_address_metrics": issue_address_metrics,
                "issues_by_category": issues_by_category,
                "issues_by_severity": issues_by_severity,
                "average_risk_score_per_category": average_risk_score_per_category,
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
                    for key,_ in vulnerability["owasp_top_10"].items(): 
                        owasp_top_10_metrics[key] += 1
                    for key,_ in vulnerability["owasp_top_10_llm"].items(): 
                        owasp_top_10_llm_metrics[key] += 1
                    for key,_ in vulnerability["compliance_controls"].items():
                        compliance_controls_metrics[key] += 1
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
                    for key in owasp_llm:
                        owasp_top_10_llm_metrics[key] += 1
                elif isinstance(owasp_llm, list):
                    for item in owasp_llm:
                        if isinstance(item, dict):
                            for key in item:
                                owasp_top_10_llm_metrics[key] += 1
                compliance = vulnerability.get("compliance_controls")
                if isinstance(compliance, dict):
                    for key in compliance:
                        compliance_controls_metrics[key] += 1
                elif isinstance(compliance, list):
                    for item in compliance:
                        if isinstance(item, dict):
                            for key in item:
                                compliance_controls_metrics[key] += 1
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