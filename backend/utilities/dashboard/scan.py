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

# All impact severities and default categories for IAC dashboard (always present with 0 if no count)
IAC_SEVERITY_KEYS = ("Critical", "High", "Medium", "Low")
IAC_DEFAULT_CATEGORIES = (
    "Network Security",
    "Access Control",
    "Data Protection",
    "Logging and Monitoring",
    "Secret Management",
    "Audit and Compliance",
)

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
        elif scan_results and "results" in scan_results:
            results = scan_results["results"]
        else:
            raise ValueError("Either scan_id or scan_object or scan_results must be provided")

        if scan : 
            scan_id = scan.id
        elif not scan_id:
            raise ValueError("scan_id must be provided")
        

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
            """
            Need to calculate the following metrics : 
            1. compliance framework violations ( Cards with numbers )
                {
                    "NIST80053": 10,
                    "ISO27001": 20,
                    "ISO27002": 30,
                    "ISO27003": 40,
                    "ISO27004": 50,
                }
            2. issues by finding_status ( Issue status metrics - Pie chart )
                {
                    "not_started": 10,
                    "in_progress": 20,
                    "fixed": 30,
                    "ignored": 40,
                }
            3. risk metrics ( radar chart ) 
                {
                    "critical": 10,
                    "high": 20,
                    "medium": 30,
                    "low": 40,
                }
            4. Security Posture Overview Pie chart : 
                {
                    "Network Security": 10,
                    "Access Control": 10,
                    "Data Protection": 20,
                    "Logging and Monitoring": 30,
                    "Secret Management": 40,
                    "Audit and Compliance": 50,
                }
            5. Issues by risk score ( area - line chart ) : 
                {
                    "finding_title" : risk score ( calculate using risk_score_for_impact )
                    "finding_title" : risk score ( calculate using risk_score_for_impact )
                    "finding_title" : risk score ( calculate using risk_score_for_impact )
                }
            6. Compliance failure trends ( area - line chart ) : 
                {
                    "finding_title" : 10, ( total number of compliance controls violated )
                    "finding_title" : 20, ( total number of compliance controls violated )
                    "finding_title" : 30, ( total number of compliance controls violated )
                }
            """
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

            # STEP [ 1a ] : -----------------> Calculate metrics from scan results (vulnerabilities)
            risk_scores_per_finding: dict[str, float] = {}
            compliance_failure_trends = defaultdict(int)

            _impact_to_key = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low"}
            for vulnerability in results:
                vuln_impact_raw = vulnerability.get("impact") or "Low"
                impact_key = _impact_to_key.get(str(vuln_impact_raw).lower(), "Low")
                vuln_title = vulnerability.get("title") or "Untitled"
                vuln_category = vulnerability.get("category") or "Other"
                owasp = vulnerability.get("owasp_top_10") or {}
                compliance = vulnerability.get("compliance_controls") or {}
                cves = vulnerability.get("cves") or {}

                # OWASP metrics
                if isinstance(owasp, dict):
                    for k, v in owasp.items():
                        owasp_top_10_metrics[k] += 1
                else:
                    for item in (owasp if isinstance(owasp, list) else []):
                        owasp_top_10_metrics[str(item)] += 1

                # Compliance controls metrics
                if isinstance(compliance, dict):
                    for k, v in compliance.items():
                        compliance_controls_metrics[v] += 1
                else:
                    for item in (compliance if isinstance(compliance, list) else []):
                        compliance_controls_metrics[str(item)] += 1

                risk_metrics[impact_key] += 1

                if isinstance(cves, dict):
                    for k, v in cves.items():
                        cves_per_vulnerability[v] += 1
                else:
                    for item in (cves if isinstance(cves, list) else []):
                        cves_per_vulnerability[str(item)] += 1

                # Policy violations: count per framework (e.g. NIST80053, ISO27001)
                if isinstance(compliance, dict):
                    for _k, val in compliance.items():
                        framework = (val.split(" - ")[0]).strip() if isinstance(val, str) else str(val)
                        policy_violations[framework] += 1
                elif isinstance(compliance, list):
                    for item in compliance:
                        framework = (str(item).split(" - ")[0]).strip()
                        policy_violations[framework] += 1

                issues_by_category[vuln_category] += 1
                issues_by_severity[impact_key] += 1

                # 5. Issues by risk score (area/line chart): finding_title -> risk score
                impact_lower = str(vuln_impact_raw).lower()
                risk_score = risk_score_for_impact.get(impact_lower, risk_score_for_impact["low"])
                risk_scores_per_finding[vuln_title] = risk_score
                sum_of_risk_scores_per_category[vuln_category] += risk_score

                # 6. Compliance failure trends: finding_title -> total compliance controls violated
                num_controls = len(compliance) if isinstance(compliance, (dict, list)) else 0
                compliance_failure_trends[vuln_title] += num_controls

            # Ensure all severities and categories are present with 0 when no count
            issues_by_severity_out: dict[str, int] = {s: issues_by_severity.get(s, 0) for s in IAC_SEVERITY_KEYS}
            issues_by_category_out: dict[str, int] = {c: 0 for c in IAC_DEFAULT_CATEGORIES}
            for k, v in issues_by_category.items():
                issues_by_category_out[k] = issues_by_category_out.get(k, 0) + v

            for cat in issues_by_category_out:
                denom = issues_by_category_out[cat]
                average_risk_score_per_category[cat] = (sum_of_risk_scores_per_category[cat] / denom) if denom else 0.0

            # 1. Compliance framework coverage: percentages per framework (for cards)
            total_policy = sum(policy_violations.values())
            compliance_framework_coverage: dict[str, float] = {}
            for framework, count in policy_violations.items():
                compliance_framework_coverage[framework] = round((count / total_policy * 100.0), 1) if total_policy else 0.0

            # 2. Issue status metrics and issue address metrics (from DB findings, once)
            findings = get_findings_for_scan_id(scan_id)
            issue_status_metrics = get_issue_status_metrics(findings)
            issue_address_metrics = get_issue_address_metrics(findings)

            return {
                "owasp_top_10_metrics": dict(owasp_top_10_metrics),
                "compliance_controls_metrics": dict(compliance_controls_metrics),
                "risk_metrics": risk_metrics,
                "cves_per_vulnerability": dict(cves_per_vulnerability),
                "policy_violations": dict(policy_violations),
                "compliance_framework_coverage": compliance_framework_coverage,
                "issue_status_metrics": issue_status_metrics,
                "issue_address_metrics": issue_address_metrics,
                "issues_by_category": issues_by_category_out,
                "issues_by_severity": issues_by_severity_out,
                "average_risk_score_per_category": dict(average_risk_score_per_category),
                "risk_scores_per_finding": risk_scores_per_finding,
                "compliance_failure_trends": dict(compliance_failure_trends),
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