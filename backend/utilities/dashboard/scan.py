from backend.new_models import Scan, scan_types
from rich.console import Console
from sqlmodel import Session, select
from fastapi import HTTPException
from backend.get_db import get_db
from collections import defaultdict
from datetime import datetime, timezone
from backend.utilities.db.findings import get_findings_for_scan_id
from backend.utilities.dashboard.remediation_metrics import get_remediation_metrics
from backend.utilities.dashboard.finding_metrics import get_average_resolution_time, get_issue_address_metrics, get_issue_status_metrics
from backend.utilities.dashboard.garak_probes import GARAK_PROBES_DESCRIPTION

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

# MCP dashboard: all asset categories for category coverage
MCP_CATEGORIES = (
    "web", "file_system", "code_execution", "database", "search", "vector_store",
    "document_store", "cache", "ai_model", "embedding", "auth", "secrets",
    "version_control", "package_registry", "container", "cloud", "message_queue",
    "event_stream", "scheduler", "observability", "config",
)
OWASP_LLM_KEYS = (
    "LLM01:2025 - Prompt Injection",
    "LLM02:2025 - Insecure Output Handling",
    "LLM03:2025 - Training Data Poisoning",
    "LLM04:2025 - Model Denial of Service",
    "LLM05:2025 - Supply Chain Vulnerabilities",
    "LLM06:2025 - Sensitive Information Disclosure",
    "LLM07:2025 - Insecure Plugin Design",
    "LLM08:2025 - Excessive Agency",
    "LLM09:2025 - Overreliance",
    "LLM10:2025 - Model Theft",
)
MITRE_ATLAS_TACTICS = (
    "reconnaissance", "resource_development", "initial_access", "ml_model_access",
    "execution", "persistence", "privilege_escalation", "defense_evasion",
    "credential_access", "discovery", "lateral_movement", "collection",
    "exfiltration", "impact",
)
# SBOM SCA license risk levels
LICENSE_HIGH_RISK = {"strong_copyleft", "network_copyleft", "source_available"}
LICENSE_MEDIUM_RISK = {"weak_copyleft", "creative_commons", "commercial"}
LICENSE_DOCSTRING_KEYS = ("permissive", "public_domain", "weak_copyleft", "creative_commons", "commercial")
# All license categories for distribution (includes high-risk + unknown; all shown with default 0)
LICENSE_ALL_CATEGORIES = (
    "permissive", "public_domain", "weak_copyleft", "creative_commons", "commercial",
    "strong_copyleft", "network_copyleft", "source_available", "unknown",
)

# DAST dashboard: OWASP Top 10 2021 (all 10), 5-category chart, compliance standards, confidence
OWASP_DAST_KEYS = (
    "A01:2021 - Broken Access Control",
    "A02:2021 - Cryptographic Failures",
    "A03:2021 - Injection",
    "A04:2021 - Insecure Design",
    "A05:2021 - Security Misconfiguration",
    "A06:2021 - Vulnerable and Outdated Components",
    "A07:2021 - Identification and Authentication Failures",
    "A08:2021 - Software and Data Integrity Failures",
    "A09:2021 - Security Logging and Monitoring Failures",
    "A10:2021 - Server-Side Request Forgery (SSRF)",
)
DAST_CATEGORIES_FIVE = (
    "injection",
    "xss_and_client_side",
    "authentication",
    "authorization",
    "session_and_state",
)
DAST_COMPLIANCE_STANDARDS = ("PCI DSS", "ISO 27001", "ISO 27002", "ISO 27003", "ISO 27004")
DAST_CONFIDENCE_KEYS = ("high", "medium", "low")

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
            engine = get_db()
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
                for vulnerability in item.get("vulnerabilities", []):

                    # calculating owasp metrics 
                    owasp = vulnerability.get("owasp_top_10") or {}
                    if isinstance(owasp, dict):
                        for key,value in owasp.items(): 
                            owasp_top_10_metrics[value] += 1
                    elif isinstance(owasp, list):
                        for item_val in owasp:
                            owasp_top_10_metrics[str(item_val)] += 1

                    # calculating compliance controls metrics 
                    compliance = vulnerability.get("compliance_controls") or {}
                    if isinstance(compliance, dict):
                        for key,value in compliance.items():
                            compliance_controls_metrics[value] += 1
                    elif isinstance(compliance, list):
                        for item_val in compliance:
                            compliance_controls_metrics[str(item_val)] += 1

                    # calculating risk metrics 
                    impact_raw = vulnerability.get("impact") or "Low"
                    risk_metrics[str(impact_raw)] = risk_metrics.get(str(impact_raw), 0) + 1

                    # calculating cves per vulnerability 
                    cves = vulnerability.get("cves") or {}
                    if isinstance(cves, dict):
                        for key,value in cves.items():
                            cves_per_vulnerability[value] += 1
                    elif isinstance(cves, list):
                        for item_val in cves:
                            cves_per_vulnerability[str(item_val)] += 1
                    
                    # calculating risk score per finding 
                    risk_score = risk_score_for_impact.get(str(impact_raw).lower(), 2.0)
                    risk_scores_per_finding[vulnerability.get("title") or "Untitled"] = risk_score

                    # calculating policy violations 
                    if isinstance(compliance, dict):
                        for key,value in compliance.items():
                            complaince_standard = str(value).split(" - ")[0]
                            policy_violations[complaince_standard] += 1
                    elif isinstance(compliance, list):
                        for item_val in compliance:
                            complaince_standard = str(item_val).split(" - ")[0]
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
            7. Average resolution time ( line chart ) : 
                {
                    "finding_title" : 10.5, ( average resolution time in seconds )
                    "finding_title" : 20.5, ( average resolution time in seconds )
                    "finding_title" : 30.5, ( average resolution time in seconds )
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
            average_resolution_time = get_average_resolution_time(findings)

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
                "average_resolution_time": average_resolution_time,
            }
        



        elif scan_type == "mcp":
            """
            Need to calculate the following metrics :
            1. Card Data :
                - overall risk score ( average risk score )
                - total findings
                - exploitability index ( based on average risk score )
                - attack surface ( total numebr of tools , resources and prompts summed up )
                - mttr ( mean time to remediation )
                - active vulnerabilities ( number of vulnerabilities that are not fixed or ignored )
                - compliance score ( based on number of compliance control violations in each vulnerability)
                - category coverage ( percentage of categories covered by the tools )
                note : all categories are : web, file_system, code_execution, database, search, vector_store, document_store, cache, ai_model, embedding, auth, secrets, version_control, package_registry, container, cloud, message_queue, event_stream, scheduler, observability, config

            2. Severity distribution ( pie chart ) :
                {
                    "critical" : total_critical_issues,
                    "high" : total_high_issues,
                    "medium" : total_medium_issues,
                    "low" : total_low_issues,
                }
            3. Category coverage ( pie chart ) :
                {
                    "web" : total_web_issues,
                    "file_system" : total_file_system_issues,
                    "code_execution" : total_code_execution_issues,
                    "database" : total_database_issues,
                }
            4. Category threat landscape ( bar chart )
                {
                    "web" : { "avg_risk_score" : avg_risk_score_web , "total_issues" : total_issues_web },
                    "file_system" : { "avg_risk_score" : avg_risk_score_file_system , "total_issues" : total_issues_file_system },
                    "code_execution" : { "avg_risk_score" : avg_risk_score_code_execution , "total_issues" : total_issues_code_execution },
                    "database" : { "avg_risk_score" : avg_risk_score_database , "total_issues" : total_issues_database },
                }
            5. Complaince frameworke scores ( pie chart ) :
                {
                    "NIST80053" : 12, ( total number of compliance controls violated )
                    "ISO27001" : 2,
                    "ISO27002" : 3,
                    "ISO27003" : 4,
                    "ISO27004" : 5,
                }
            6. Compliance failure trends ( area - line chart ) :
                {
                    "finding_title" : 10, ( total number of compliance controls violated )
                    "finding_title" : 20, ( total number of compliance controls violated )
                    "finding_title" : 30, ( total number of compliance controls violated )
                }
            7. Asset attack surface ( bar chart ) :
                {
                    "tool_name" : tool_risk_level ( critical , high , medium , low )
                    "tool_name2" : tool_risk_level ( critical , high , medium , low )
                    "resource_name" : resource_risk_level ( critical , high , medium , low )
                    "prompt_name" : prompt_risk_level ( critical , high , medium , low )
                }
            8. Tool impact analysis ( area - line chart ) :
                note : each tool has vulns , each vuln has an impact class ( critical , high , medium , low ) , therefer calculate impact metrics for each tool by summing up the impact classes of all vulns for that tool
                {
                    "tool_name" : { "critical" : total_critical_issues, "high" : total_high_issues, "medium" : total_medium_issues, "low" : total_low_issues }
                }
            9. Asset Compliance violations ( area - line chart ) :
                {
                    "tool_name" : 24 ( totla number of compliance controls violated )
                    "resource_name" : 27 ( totla number of compliance controls violated )
                    "prompt_name" : 30 ( totla number of compliance controls violated )
                }
            10 . OWASP Top 10 llm metrics ( area - line chart ) :
                {
                    "LLM01:2025 - Prompt Injection" : 10, ( total number of prompt injection issues )
                    "LLM02:2025 - Insecure Output Handling" : 20,
                    "LLM03:2025 - Training Data Poisoning" : 30,
                    ...
                    "LLM10:2025 - Model Theft" : 100,
                }
            """
            results = results if isinstance(results, dict) else {}
            tools = results.get("tools") or []
            prompts = results.get("prompts") or []
            resources = results.get("resources") or []

            severity_distribution = {"critical": 0, "high": 0, "medium": 0, "low": 0}
            category_issues = defaultdict(int)
            category_risk_sum = defaultdict(float)
            category_risk_count = defaultdict(int)
            compliance_framework_scores = defaultdict(int)
            compliance_failure_trends = defaultdict(int)
            asset_attack_surface: dict[str, str] = {}
            tool_impact_analysis: dict[str, dict[str, int]] = defaultdict(lambda: {"critical": 0, "high": 0, "medium": 0, "low": 0})
            asset_compliance_violations: dict[str, int] = {}
            owasp_llm_counts = defaultdict(int)

            risk_sum = 0.0
            total_findings_count = 0
            categories_present: set[str] = set()

            def _process_asset_vulns(asset: dict, asset_name_key: str, risk_level_key: str, category_key: str) -> None:
                name = asset.get(asset_name_key) or "unknown"
                risk_level = (asset.get(risk_level_key) or "low").lower().strip()
                category = (asset.get(category_key) or "config").lower().strip().replace(" ", "_")
                vulns = asset.get("vulnerabilities") or []
                categories_present.add(category)
                asset_attack_surface[name] = risk_level
                comp_count = 0
                for v in vulns:
                    imp = (v.get("impact") or "low").lower().strip()
                    if imp in severity_distribution:
                        severity_distribution[imp] += 1
                    rs = risk_score_for_impact.get(imp, risk_score_for_impact["low"])
                    nonlocal risk_sum, total_findings_count
                    risk_sum += rs
                    total_findings_count += 1
                    category_issues[category] += 1
                    category_risk_sum[category] += rs
                    category_risk_count[category] += 1
                    cc = v.get("compliance_controls") or {}
                    n_cc = len(cc) if isinstance(cc, (dict, list)) else 0
                    comp_count += n_cc
                    for _k, val in (cc.items() if isinstance(cc, dict) else []):
                        framework = (str(val).split(" - ")[0]).strip().replace(" ", "") if isinstance(val, str) else str(val)
                        compliance_framework_scores[framework] += 1
                    title = (v.get("title") or "Untitled").strip()
                    compliance_failure_trends[title] += n_cc
                    owasp = v.get("owasp_top_10_llm") or {}
                    if isinstance(owasp, dict):
                        for _k, label in owasp.items():
                            owasp_llm_counts[str(label)] += 1
                asset_compliance_violations[name] = comp_count

            for tool in tools:
                _process_asset_vulns(tool, "tool_name", "tool_risk_level", "tool_category")
                vulns = tool.get("vulnerabilities") or []
                tname = tool.get("tool_name") or "unknown"
                for v in vulns:
                    imp = (v.get("impact") or "low").lower().strip()
                    if imp in tool_impact_analysis[tname]:
                        tool_impact_analysis[tname][imp] += 1
            for prompt in prompts:
                _process_asset_vulns(prompt, "prompt_name", "prompt_risk_level", "prompt_category")
            for resource in resources:
                _process_asset_vulns(resource, "resource_name", "resource_risk_level", "resource_category")

            overall_risk_score = round(risk_sum / total_findings_count, 1) if total_findings_count else 0.0
            exploitability_index = round((overall_risk_score / 10.0) * 100, 1) if overall_risk_score else 0
            attack_surface = len(tools) + len(prompts) + len(resources)
            findings = get_findings_for_scan_id(scan_id)
            remediation = get_remediation_metrics(findings)
            mttr = remediation.get("mean_time_to_remediate", [0, 0, 0])
            active_vulnerabilities = sum(1 for f in findings if f.get("finding_status") not in ("fixed", "ignored"))
            total_compliance_violations = sum(compliance_framework_scores.values())
            compliance_score = max(0, round(100 - min(100, total_compliance_violations), 1))
            category_coverage = round((len(categories_present) / len(MCP_CATEGORIES)) * 100.0, 1) if MCP_CATEGORIES else 0.0

            category_threat_landscape: dict[str, dict[str, float | int]] = {}
            for cat in set(category_issues.keys()):
                n = category_risk_count.get(cat, 0)
                category_threat_landscape[cat] = {
                    "avg_risk_score": round(category_risk_sum[cat] / n, 1) if n else 0.0,
                    "total_issues": category_issues[cat],
                }

            owasp_top_10_llm_metrics = {k: owasp_llm_counts.get(k, 0) for k in OWASP_LLM_KEYS}

            return {
                "card_data": {
                    "overall_risk_score": overall_risk_score,
                    "total_findings": total_findings_count,
                    "exploitability_index": exploitability_index,
                    "attack_surface": attack_surface,
                    "mttr": mttr,
                    "active_vulnerabilities": active_vulnerabilities,
                    "compliance_score": compliance_score,
                    "category_coverage": category_coverage,
                },
                "severity_distribution": severity_distribution,
                "category_coverage": dict(category_issues),
                "category_threat_landscape": category_threat_landscape,
                "compliance_framework_scores": dict(compliance_framework_scores),
                "compliance_failure_trends": dict(compliance_failure_trends),
                "asset_attack_surface": asset_attack_surface,
                "tool_impact_analysis": dict(tool_impact_analysis),
                "asset_compliance_violations": asset_compliance_violations,
                "owasp_top_10_llm_metrics": owasp_top_10_llm_metrics,
            }

        
        elif scan_type == "llm":
            """
            Need to calculate the following metrics :
            1. Card Data :
                - Attacks run ( total number of probes used , get it from the metadata field in scan.scan_data )
                - total vulnerabilities found ( total number of vulnerabilities found )
                - pass rate ( get from the metadata field in scan.scan_data )
                - Risk score ( average risk score of the vulnerabilities based on impact class weighted average )
                - Scan duration ( get from the duration_of_scan field in scan.scan_data )
                - policy violations ( total compliance controls violated + total mitre atlas tactics violated  + total owasp top 10 violations  across all vulnerabilities )

            2. Security Posture ( radar chart ) :
                note : show all categories , default to 0 if no data is available
                {
                    "jailbreak_resistance_score": 10,
                    "injection_resistance_score": 10,
                    "hallucination_resistance_score": 10,
                    "bias_resistance_score": 10,
                    "content_safety_score": 10,
                    "data_privacy_score": 10,
                }
            3. Owasp top 10 LLM metrics ( radar chart ) :
                note : show all categories , default to 0 if no data is available
                {
                    "LLM01:2025 - Prompt Injection" : 10, ( total number of prompt injection issues )
                    "LLM02:2025 - Insecure Output Handling" : 20,
                    ...
                    "LLM10:2025 - Model Theft" : 100,
                }
            4. Mitre Atlas Tactics metrics ( Bar chart ) :
                note : show all categories , default to 0 if no data is available
                {
                    "reconnaissance" : 10, "resource_development" : 20, "initial_access" : 30,
                    "ml_model_access" : 40, "execution" : 50, "persistence" : 60,
                    "privilege_escalation" : 70, "defense_evasion" : 80, "credential_access" : 90,
                    "discovery" : 100, "lateral_movement" : 110, "collection" : 120,
                    "exfiltration" : 130, "impact" : 140,
                }

            5. Vulnerability break down ( pie chart ) ( risk distribution of the vulnerabilities )
                {
                    "critical" : 10, "high" : 20, "medium" : 30, "low" : 40,
                }
            6. Adversarial Attack outcomes ( multiple bar ,bar chart ):
                {
                    "probe_name_1" : { "passed" : 10 , "total" : 100 },
                    "probe_name_2" : { "passed" : 20 , "total" : 100 },
                }

            7. Attack Details ( table ) : ( use garak_probes to get a short description of the probe and display that also )
                {
                    "probe_name" : { "passed" : 10 , "total" : 100 , "hit_rate" : 10.0 , "description" : "short description of the probe" },
                }
            """
            results = results if isinstance(results, dict) else {}
            scan_data = (scan.scan_data or {}) if scan else {}
            metadata = scan_data.get("metadata") or {}
            vulns = results.get("vulnerabilities") or []
            model_vulns = results.get("model_vulnerabilities") or {}

            attacks_run = len(metadata.get("probes_used") or [])
            probes_summary = metadata.get("probes_summary") or {}
            if not attacks_run and probes_summary:
                attacks_run = len(set((p.get("probe") or k for k, p in probes_summary.items() if isinstance(p, dict))))
            total_tests = metadata.get("total_tests") or 0
            total_hits = metadata.get("total_hits") or 0
            pass_rate = round((total_tests - total_hits) / total_tests * 100, 1) if total_tests else 0.0
            duration_of_scan = scan_data.get("duration_of_scan") or 0

            risk_sum = 0.0
            n_vulns = len(vulns)
            for v in vulns:
                imp = (v.get("impact") or "low").lower().strip()
                risk_sum += risk_score_for_impact.get(imp, risk_score_for_impact["low"])
            risk_score = round(risk_sum / n_vulns, 1) if n_vulns else 0.0

            policy_violations = 0
            owasp_llm_counts = defaultdict(int)
            mitre_counts = defaultdict(int)
            vulnerability_breakdown = {"critical": 0, "high": 0, "medium": 0, "low": 0}
            for v in vulns:
                cc = v.get("compliance_controls") or {}
                policy_violations += len(cc) if isinstance(cc, (dict, list)) else 0
                if v.get("mitre_atlas_tactic"):
                    tactic = (v.get("mitre_atlas_tactic") or "").lower().strip()
                    mitre_counts[tactic] += 1
                    policy_violations += 1
                owasp = v.get("owasp_top_10_llm") or {}
                if isinstance(owasp, dict):
                    for _k, label in owasp.items():
                        owasp_llm_counts[str(label)] += 1
                        policy_violations += 1
                imp = (v.get("impact") or "low").lower().strip()
                if imp in vulnerability_breakdown:
                    vulnerability_breakdown[imp] += 1

            security_posture = {
                "jailbreak_resistance_score": float(model_vulns.get("jailbreak_resistance_score") or 0),
                "injection_resistance_score": float(model_vulns.get("injection_resistance_score") or 0),
                "hallucination_resistance_score": float(model_vulns.get("hallucination_resistance_score") or 0),
                "bias_resistance_score": float(model_vulns.get("bias_resistance_score") or 0),
                "content_safety_score": float(model_vulns.get("content_safety_score") or 0),
                "data_privacy_score": float(model_vulns.get("data_privacy_score") or 0),
            }
            # Ensure all OWASP LLM categories are present as keys with default 0 (frontend needs this)
            owasp_top_10_llm_metrics = dict.fromkeys(OWASP_LLM_KEYS, 0)
            for k, v in owasp_llm_counts.items():
                owasp_top_10_llm_metrics[k] = v
            mitre_atlas_metrics = {t: mitre_counts.get(t, 0) for t in MITRE_ATLAS_TACTICS}

            adversarial_attack_outcomes: dict[str, dict[str, int]] = {}
            attack_details: dict[str, dict[str, int | float | str]] = {}
            for probe_key, probe_data in probes_summary.items():
                if not isinstance(probe_data, dict):
                    continue
                probe_name = probe_data.get("probe") or probe_key
                passed = probe_data.get("passed") or 0
                total = probe_data.get("total") or 0
                hit_rate = round(passed / total * 100.0, 1) if total else 0.0
                adversarial_attack_outcomes[probe_name] = {"passed": passed, "total": total}
                attack_details[probe_name] = {
                    "passed": passed,
                    "total": total,
                    "hit_rate": hit_rate,
                    "description": GARAK_PROBES_DESCRIPTION.get(probe_name, ""),
                }

            return {
                "card_data": {
                    "attacks_run": attacks_run,
                    "total_vulnerabilities_found": n_vulns,
                    "pass_rate": pass_rate,
                    "risk_score": risk_score,
                    "scan_duration": duration_of_scan,
                    "policy_violations": policy_violations,
                },
                "security_posture": security_posture,
                "owasp_top_10_llm_metrics": owasp_top_10_llm_metrics,
                "mitre_atlas_metrics": mitre_atlas_metrics,
                "vulnerability_breakdown": vulnerability_breakdown,
                "adversarial_attack_outcomes": adversarial_attack_outcomes,
                "attack_details": attack_details,
            }
        

        elif scan_type == "sbom_sca":
            """
            Need to calculate the following metrics :
            1. Card Data :
                - total vulnerabilities
                - total critical vulnerabilities
                - total policy violations
                - total license risks ( total high and medium risk licenses )
                - total high risk licenses
                note : Risk level splitup for licenses :
                        Low risk ---> permissive , public_domain , unknown
                        Medium risk ---> weak_copyleft , creative_commons , commercial
                        High risk ---> strong_copyleft , network_copyleft , source_available
                - average risk score ( based on weighted average of impact class of all vulnerabilities )
                - total reachable issues

            2. Remediation Actions required : ( Card with a list of progress bars and icons )
                {
                    "total_findings" : total_findings,
                    "total_fixed" : total_fixed,
                    "total_in_progress" : total_in_progress,
                    "total_not_started" : total_not_started,
                    "total_ignored" : total_ignored,
                }
            3. severity distribution : ( radar chart )
                {
                    "critical" : total_critical_issues,
                    "high" : total_high_issues,
                    "medium" : total_medium_issues,
                    "low" : total_low_issues,
                }
            4. Reachability Age ( how long a certail finding remained in not_reachable or potentially_reachable status ) ( Bar chart )
                {
                    "not_reachable" : total_not_reachable_issues,
                    "potentially_reachable" : total_potentially_reachable_issues,
                    "reachable" : total_reachable_issues,
                    "unknown" : total_unknown_issues,
                }
            5. Vulnerability remediation Trends over time : ( area - line chart )
                note : here the date key is the fixed_at or ignored_at dates for the fixed and ignored findings of this scan 
                {
                    "2026-01-01" : { "critical" : 10, "high" : 20, "medium" : 30, "low" : 40 },
                    "2026-01-02" : { "critical" : 15, "high" : 25, "medium" : 35, "low" : 45 },
                }
            6. Licenses Distribution : ( pie chart )
                {
                    "permissive" : total_permissive_licenses,
                    "public_domain" : total_public_domain_licenses,
                    "weak_copyleft" : total_weak_copyleft_licenses,
                    "creative_commons" : total_creative_commons_licenses,
                    "commercial" : total_commercial_licenses,
                }
            7. Top Vulnerabilities by Risk Score : ( Card with a list of components )
                ( sorted by impact in descending order )
                [
                    {
                        "dependency" : dependency_name,
                        "reachability" : reachability,
                        "dependency_type" : dependency_type,
                        "license_type" : license_type,
                        "impact" : impact,
                    },
                ]

            8. Average risk score per reachability level :
                note : calculate average risk score for each reachability level by weighted average of impact class of all vulnerabilities for that reachability level
                {
                    "reachable" : average_risk_score_reachable,
                    "potentially_reachable" : average_risk_score_potentially_reachable,
                    "not_reachable" : average_risk_score_not_reachable,
                    "unknown" : average_risk_score_unknown,
                }
            """
            results_list = results if isinstance(results, list) else []
            severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
            reachability_counts: dict[str, int] = defaultdict(int)
            license_counts: dict[str, int] = defaultdict(int)
            total_policy_violations = 0
            risk_score_weighted_sum = 0.0
            total_reachable = 0
            reachability_risk_sum: dict[str, float] = defaultdict(float)
            reachability_risk_count: dict[str, int] = defaultdict(int)
            impact_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}

            for item in results_list:
                imp = (item.get("impact") or "low").lower().strip()
                if imp in severity_counts:
                    severity_counts[imp] += 1
                reach = (item.get("reachability") or "unknown").lower().strip().replace(" ", "_")
                reachability_counts[reach] += 1
                if reach == "reachable":
                    total_reachable += 1
                lic = (item.get("license_type") or "unknown").lower().strip()
                license_counts[lic] += 1
                cc = item.get("compliance_controls") or {}
                if isinstance(cc, dict):
                    total_policy_violations += len(cc)
                elif isinstance(cc, list):
                    total_policy_violations += len(cc)
                w = risk_score_for_impact.get(imp, risk_score_for_impact["low"])
                risk_score_weighted_sum += w
                reachability_risk_sum[reach] += w
                reachability_risk_count[reach] += 1

            total_vulnerabilities = len(results_list)
            total_critical = severity_counts["critical"]
            average_risk_score = round(risk_score_weighted_sum / total_vulnerabilities, 1) if total_vulnerabilities else 0.0
            total_license_risks = sum(1 for item in results_list if (item.get("license_type") or "").lower().strip() in LICENSE_MEDIUM_RISK | LICENSE_HIGH_RISK)
            total_high_risk_licenses = sum(1 for item in results_list if (item.get("license_type") or "").lower().strip() in LICENSE_HIGH_RISK)

            findings = get_findings_for_scan_id(scan_id)
            status_metrics = get_issue_status_metrics(findings) if findings else {"fixed": 0, "in_progress": 0, "not_started": 0, "ignored": 0}
            remediation_actions_required = {
                "total_findings": len(findings),
                "total_fixed": status_metrics.get("fixed", 0),
                "total_in_progress": status_metrics.get("in_progress", 0),
                "total_not_started": status_metrics.get("not_started", 0),
                "total_ignored": status_metrics.get("ignored", 0),
            }

            reachability_distribution = {
                "not_reachable": reachability_counts.get("not_reachable", 0),
                "potentially_reachable": reachability_counts.get("potentially_reachable", 0),
                "reachable": reachability_counts.get("reachable", 0),
                "unknown": reachability_counts.get("unknown", 0),
            }
            other_reach = sum(v for k, v in reachability_counts.items() if k not in reachability_distribution)
            reachability_distribution["unknown"] = reachability_distribution.get("unknown", 0) + other_reach

            # Vulnerability remediation trends: date key = fixed_at or ignored_at for fixed/ignored findings
            vulnerability_trends_over_time: dict[str, dict[str, int]] = {}
            severity_keys = ("critical", "high", "medium", "low")
            for f in findings or []:
                status = (f.get("finding_status") or "").strip().lower()
                resolved_date: str | None = None
                if status == "fixed" and f.get("fixed_at"):
                    resolved_date = str(f["fixed_at"].date()) if hasattr(f["fixed_at"], "date") else None
                elif status == "ignored" and f.get("ignored_at"):
                    resolved_date = str(f["ignored_at"].date()) if hasattr(f["ignored_at"], "date") else None
                if not resolved_date:
                    continue
                if resolved_date not in vulnerability_trends_over_time:
                    vulnerability_trends_over_time[resolved_date] = {k: 0 for k in severity_keys}
                fd = f.get("finding_data") or {}
                imp = (fd.get("impact") or "low").lower().strip()
                if imp in severity_keys:
                    vulnerability_trends_over_time[resolved_date][imp] += 1
            # Sort by date for consistent chart ordering
            if vulnerability_trends_over_time:
                vulnerability_trends_over_time = dict(sorted(vulnerability_trends_over_time.items()))

            licenses_distribution = {k: license_counts.get(k, 0) for k in LICENSE_ALL_CATEGORIES}

            top_vulnerabilities_by_risk_score = [
                {
                    "dependency": item.get("dependency") or item.get("title") or "—",
                    "reachability": item.get("reachability") or "unknown",
                    "dependency_type": item.get("dependency_type") or "—",
                    "license_type": item.get("license_type") or "unknown",
                    "impact": item.get("impact") or "low",
                }
                for item in results_list
            ]
            top_vulnerabilities_by_risk_score.sort(
                key=lambda x: (impact_order.get((x.get("impact") or "low").lower(), 0),),
                reverse=True,
            )

            average_risk_score_per_reachability: dict[str, float] = {}
            for reach in ("reachable", "potentially_reachable", "not_reachable", "unknown"):
                n = reachability_risk_count.get(reach, 0)
                average_risk_score_per_reachability[reach] = round(reachability_risk_sum[reach] / n, 1) if n else 0.0

            return {
                "card_data": {
                    "total_vulnerabilities": total_vulnerabilities,
                    "total_critical_vulnerabilities": total_critical,
                    "total_policy_violations": total_policy_violations,
                    "total_license_risks": total_license_risks,
                    "total_high_risk_licenses": total_high_risk_licenses,
                    "average_risk_score": average_risk_score,
                    "total_reachable_issues": total_reachable,
                },
                "remediation_actions_required": remediation_actions_required,
                "severity_distribution": severity_counts,
                "reachability_distribution": reachability_distribution,
                "vulnerability_trends_over_time": vulnerability_trends_over_time,
                "licenses_distribution": licenses_distribution,
                "top_vulnerabilities_by_risk_score": top_vulnerabilities_by_risk_score,
                "average_risk_score_per_reachability": average_risk_score_per_reachability,
            }
    
        elif scan_type == "dast":
            """
            Need to calculate the following metrics :
            1. Card Data :
                - total scans
                - total critical issues
                - total high issues
                - total medium issues
                - total low issues
                - average risk score
                - urls scanned
                - coverage percentage
            2. Severity distribution ( pie chart ) :
                {
                    "critical" : total_critical_issues,
                    "high" : total_high_issues,
                    "medium" : total_medium_issues,
                    "low" : total_low_issues,
                }
            3. Compliance status ( Card with a list of progress bars and icons )
                {
                    "PCI DSS" : total_pci_dss_issues,
                    "ISO 27001" : total_iso_27001_issues,
                    "ISO 27002" : total_iso_27002_issues,
                    "ISO 27003" : total_iso_27003_issues,
                    "ISO 27004" : total_iso_27004_issues,
                }
            4. Owasp top 10 issues ( bar chart ) :
                {
                    "A01:2021 - Broken Access Control" : total_broken_access_control_issues,
                    "A02:2021 - Cryptographic Failures" : total_cryptographic_failures_issues,
                    "A03:2021 - Injection" : total_injection_issues,
                    "A04:2021 - Insecure Design" : total_insecure_design_issues,
                    "A05:2021 - Security Misconfiguration" : total_security_misconfiguration_issues,
                }

            5. Vulnerability category issues distribution ( bar chart ) :
                {
                    "injection" : total_injection_issues,
                    "xss_and_client_side" : total_xss_and_client_side_issues,
                    "authentication" : total_authentication_issues,
                    "authorization" : total_authorization_issues,
                    "session_and_state" : total_session_and_state_issues,
                }

            6. Risk scores per category ( area - line chart ) :
                {
                    "injection" : { "critical" : 10, "high" : 20, "medium" : 30, "low" : 40 },
                    "xss_and_client_side" : { "critical" : 10, "high" : 20, "medium" : 30, "low" : 40 },
                    "authentication" : { "critical" : 10, "high" : 20, "medium" : 30, "low" : 40 },
                    "authorization" : { "critical" : 10, "high" : 20, "medium" : 30, "low" : 40 },
                    "session_and_state" : { "critical" : 10, "high" : 20, "medium" : 30, "low" : 40 },
                }

            7. Confidence distribution ( pie chart ) :
                {
                    "high" : 10,
                    "medium" : 20,
                    "low" : 30,
                }

            8. Security Category Assessment ( avg risk score per category ) :
                {
                    "injection" : 10,
                    "xss_and_client_side" : 20,
                    "authentication" : 30,
                    "authorization" : 40,
                    "session_and_state" : 50,
                }
            9 . Compliance risk assessment ( bar chart ) ( average risk score per compliance control ):
                {
                    "PCI DSS" : 10,
                    "ISO 27001" : 20,
                    "ISO 27002" : 30,
                    "ISO 27003" : 40,
                    "ISO 27004" : 50,
                }

            10 . Remediation Metrics ( Card with a list of progress bars and icons ) :
                {
                    "total_findings" : total_findings,
                    "total_fixed" : total_fixed,
                    "total_in_progress" : total_in_progress,
                    "total_not_started" : total_not_started,
                    "total_ignored" : total_ignored,
                }
            """
            # Prefer scan.scan_data["results"] when present (DataSpecs format); else use MongoDB findings
            scan_data = (scan.scan_data or {}) if scan else {}
            results_from_scan_data = scan_data.get("results", [])
            if isinstance(results_from_scan_data, list) and len(results_from_scan_data) > 0:
                # Findings from scan_data have no finding_status; default so remediation/status code does not KeyError
                findings = [
                    {"finding_data": r, "finding_status": "not_started", "fixed_at": None, "ignored_at": None}
                    for r in results_from_scan_data
                ]
            else:
                findings = get_findings_for_scan_id(scan_id)
            metadata = scan_data.get("metadata", {})
            urls_included = metadata.get("urls_included", []) or []
            urls_excluded = metadata.get("urls_excluded", []) or []
            urls_scanned = len(urls_included)
            total_urls = urls_scanned + len(urls_excluded)
            coverage_percentage = round((urls_scanned / total_urls) * 100, 1) if total_urls > 0 else 0.0

            severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
            compliance_status_counts = defaultdict(int)
            owasp_counts = defaultdict(int)
            category_counts = defaultdict(int)
            risk_scores_per_category: dict[str, dict[str, int]] = {c: {"critical": 0, "high": 0, "medium": 0, "low": 0} for c in DAST_CATEGORIES_FIVE}
            confidence_counts = defaultdict(int)
            risk_sum_per_category: dict[str, float] = defaultdict(float)
            risk_count_per_category: dict[str, int] = defaultdict(int)
            compliance_risk_sum: dict[str, float] = defaultdict(float)
            compliance_risk_count: dict[str, int] = defaultdict(int)
            risk_score_total = 0.0
            risk_score_n = 0

            def _dast_extract_standard(val: str) -> str:
                if not val or not isinstance(val, str):
                    return ""
                return (val.split(" - ", 1)[0] or "").strip()

            def _dast_owasp_values(cc):  # dict or list
                if isinstance(cc, dict):
                    return list(cc.values()) if cc else []
                if isinstance(cc, list):
                    return [x.get("value", x) if isinstance(x, dict) else x for x in cc]
                return []

            def _dast_compliance_values(cc):
                """Get string values from compliance_controls (dict or list). Values are 'Standard - control'."""
                if isinstance(cc, dict):
                    return [v for v in (cc.values() if cc else []) if isinstance(v, str)]
                if isinstance(cc, list):
                    out = []
                    for x in cc:
                        if isinstance(x, str):
                            out.append(x)
                        elif isinstance(x, dict):
                            # prefer 'value' or 'control', else first string value
                            s = x.get("value") or x.get("control")
                            if isinstance(s, str):
                                out.append(s)
                            else:
                                for v in x.values():
                                    if isinstance(v, str):
                                        out.append(v)
                                        break
                    return out
                return []

            for finding in findings:
                fd = finding.get("finding_data") or {}
                imp = (fd.get("impact") or "low").lower().strip()
                if imp not in severity_counts:
                    imp = "low"
                severity_counts[imp] = severity_counts.get(imp, 0) + 1
                score = risk_score_for_impact.get(imp, 2.5)
                risk_score_total += score
                risk_score_n += 1

                for std_val in _dast_compliance_values(fd.get("compliance_controls")):
                    std = _dast_extract_standard(std_val or "")
                    if std:
                        compliance_status_counts[std] += 1
                        compliance_risk_sum[std] += score
                        compliance_risk_count[std] += 1

                for owasp_val in _dast_owasp_values(fd.get("owasp_top_10")):
                    s = (owasp_val if isinstance(owasp_val, str) else str(owasp_val)).strip()
                    if s in OWASP_DAST_KEYS:
                        owasp_counts[s] += 1

                cat = (fd.get("category") or "").strip().lower().replace(" ", "_")
                if not cat:
                    cat = "injection"
                if cat in DAST_CATEGORIES_FIVE:
                    category_counts[cat] += 1
                    risk_scores_per_category[cat][imp] = risk_scores_per_category[cat].get(imp, 0) + 1
                    risk_sum_per_category[cat] += score
                    risk_count_per_category[cat] += 1

                conf = (fd.get("confidence") or "low").lower().strip()
                if conf not in DAST_CONFIDENCE_KEYS:
                    conf = "low"
                confidence_counts[conf] += 1

            total_critical = severity_counts.get("critical", 0)
            total_high = severity_counts.get("high", 0)
            total_medium = severity_counts.get("medium", 0)
            total_low = severity_counts.get("low", 0)
            average_risk_score = round(risk_score_total / risk_score_n, 1) if risk_score_n > 0 else 0.0

            # Include fixed PCI/ISO keys plus any standard extracted from data (e.g. NIST CSF, NIST 800-53)
            all_standards = list(DAST_COMPLIANCE_STANDARDS) + [s for s in compliance_status_counts if s not in DAST_COMPLIANCE_STANDARDS]
            compliance_status = {std: compliance_status_counts.get(std, 0) for std in all_standards}
            owasp_top_10_issues = {k: owasp_counts.get(k, 0) for k in OWASP_DAST_KEYS}
            vulnerability_category_issues_distribution = {c: category_counts.get(c, 0) for c in DAST_CATEGORIES_FIVE}
            risk_scores_per_category_out = {c: {s: risk_scores_per_category[c].get(s, 0) for s in ("critical", "high", "medium", "low")} for c in DAST_CATEGORIES_FIVE}
            confidence_distribution = {k: confidence_counts.get(k, 0) for k in DAST_CONFIDENCE_KEYS}
            security_category_assessment = {
                c: round(risk_sum_per_category[c] / risk_count_per_category[c], 1) if risk_count_per_category[c] > 0 else 0.0
                for c in DAST_CATEGORIES_FIVE
            }
            compliance_risk_assessment = {
                std: round(compliance_risk_sum[std] / compliance_risk_count[std], 1) if compliance_risk_count[std] > 0 else 0.0
                for std in all_standards
            }

            status_metrics = get_issue_status_metrics(findings) if findings else {"fixed": 0, "in_progress": 0, "not_started": 0, "ignored": 0}
            remediation_metrics = {
                "total_findings": len(findings),
                "total_fixed": status_metrics.get("fixed", 0),
                "total_in_progress": status_metrics.get("in_progress", 0),
                "total_not_started": status_metrics.get("not_started", 0),
                "total_ignored": status_metrics.get("ignored", 0),
            }

            return {
                "card_data": {
                    "total_critical_issues": total_critical,
                    "total_high_issues": total_high,
                    "total_medium_issues": total_medium,
                    "total_low_issues": total_low,
                    "average_risk_score": average_risk_score,
                    "urls_scanned": urls_scanned,
                    "coverage_percentage": coverage_percentage,
                },
                "severity_distribution": dict(severity_counts),
                "compliance_status": compliance_status,
                "owasp_top_10_issues": owasp_top_10_issues,
                "vulnerability_category_issues_distribution": vulnerability_category_issues_distribution,
                "risk_scores_per_category": risk_scores_per_category_out,
                "confidence_distribution": confidence_distribution,
                "security_category_assessment": security_category_assessment,
                "compliance_risk_assessment": compliance_risk_assessment,
                "remediation_metrics": remediation_metrics,
            }
            
        elif scan_type == "cbom":
            # =========== CBOM Dashboard ===========================
            # CBOM uses the app-wide 0-10 risk scale (consistent across all CBOM surfaces).
            # critical=9, high=7, medium=5, low=2, unknown/missing=0.
            cbom_risk_score_for_impact = {"critical": 9, "high": 7, "medium": 5, "low": 2}
            severity_distribution = {"critical": 0, "high": 0, "medium": 0, "low": 0}
            algorithm_type_distribution = defaultdict(int)
            strength_distribution = {"weak": 0, "moderate": 0, "strong": 0, "quantum_safe": 0}
            quantum_readiness = {"quantum_safe": 0, "quantum_vulnerable": 0, "unknown": 0}
            owasp_top_10_metrics = defaultdict(int)
            compliance_controls_metrics = defaultdict(int)
            top_risks_entries = []

            # 'results' is the LLM-aggregated vulnerability list (a few rows), NOT the
            # crypto asset inventory. The real inventory is the CycloneDX components in
            # scan.scan_data['cbom_json']['components']. Use that count for the asset
            # card, falling back to len(results) only when cbom_json is unavailable.
            cbom_components = []
            if scan and isinstance(scan.scan_data, dict):
                cbom_components = (scan.scan_data.get("cbom_json") or {}).get("components") or []
            total_crypto_vulnerabilities = len(results)
            total_crypto_assets = len(cbom_components) if cbom_components else total_crypto_vulnerabilities
            total_weak = 0
            total_quantum_vulnerable = 0
            total_certificates = 0
            total_keys = 0

            for vulnerability in results:
                # severity distribution
                impact = vulnerability.get("impact") or "Low"
                impact_lower = impact.lower()
                if impact_lower in severity_distribution:
                    severity_distribution[impact_lower] += 1
                
                # algorithm type distribution
                algo_type = vulnerability.get("algorithm_type", "unknown")
                algorithm_type_distribution[algo_type] += 1
                
                # strength distribution
                strength = vulnerability.get("crypto_strength", "unknown")
                if strength in strength_distribution:
                    strength_distribution[strength] += 1
                
                # quantum readiness
                qs = vulnerability.get("quantum_safe")
                if qs is True:
                    quantum_readiness["quantum_safe"] += 1
                elif qs is False:
                    quantum_readiness["quantum_vulnerable"] += 1
                    total_quantum_vulnerable += 1
                else:
                    quantum_readiness["unknown"] += 1
                
                # weak algorithms
                if strength == "weak":
                    total_weak += 1
                
                # certificates and keys
                if algo_type == "certificate":
                    total_certificates += 1
                elif algo_type == "key" or algo_type == "secret":
                    total_keys += 1
                
                # owasp metrics
                for key, value in (vulnerability.get("owasp_top_10") or {}).items():
                    owasp_top_10_metrics[value] += 1

                # compliance controls
                for key, value in (vulnerability.get("compliance_controls") or {}).items():
                    compliance_controls_metrics[value] += 1

                # top risks entries with full vulnerability info
                risk_score = cbom_risk_score_for_impact.get(impact_lower, 0)
                top_risks_entries.append({
                    "algorithm_name": vulnerability.get("algorithm_name", vulnerability.get("title", "Unknown")),
                    "algorithm_type": algo_type,
                    "crypto_strength": strength,
                    "quantum_safe": vulnerability.get("quantum_safe", False),
                    "impact": impact,
                    "risk_score": risk_score,
                })

            # Calculate quantum readiness score.
            # The quantum_readiness distribution is built per-vulnerability (its values
            # sum to len(results) == total_crypto_vulnerabilities), so the score must be
            # divided by that same population, not the (larger) asset inventory count.
            quantum_readiness_denominator = sum(quantum_readiness.values())
            quantum_readiness_score = 0
            if quantum_readiness_denominator > 0:
                quantum_readiness_score = round((quantum_readiness["quantum_safe"] / quantum_readiness_denominator) * 100, 1)

            # Average risk score (0-10 scale, using the standard CBOM impact mapping)
            total_findings = sum(severity_distribution.values())
            if total_findings > 0:
                weighted = (
                    severity_distribution["critical"] * cbom_risk_score_for_impact["critical"]
                    + severity_distribution["high"] * cbom_risk_score_for_impact["high"]
                    + severity_distribution["medium"] * cbom_risk_score_for_impact["medium"]
                    + severity_distribution["low"] * cbom_risk_score_for_impact["low"]
                ) / total_findings
                average_risk_score = min(10.0, max(0.0, weighted))
            else:
                average_risk_score = 0.0

            # Top risks sorted by risk score
            top_risks_list = sorted(top_risks_entries, key=lambda x: x["risk_score"], reverse=True)[:10]

            # Remediation metrics
            findings = get_findings_for_scan_id(scan_id=scan_id)
            remediation_metrics = get_remediation_metrics(findings)
            status_metrics = get_issue_status_metrics(findings)

            remediation_actions_required = {
                "total_findings": len(findings),
                "total_fixed": status_metrics.get("fixed", 0),
                "total_in_progress": status_metrics.get("in_progress", 0),
                "total_not_started": status_metrics.get("not_started", 0),
                "total_ignored": status_metrics.get("ignored", 0),
            }

            return {
                "card_data": {
                    "total_crypto_assets": total_crypto_assets,
                    "total_crypto_vulnerabilities": total_crypto_vulnerabilities,
                    "total_weak_algorithms": total_weak,
                    "total_quantum_vulnerable": total_quantum_vulnerable,
                    "total_certificates": total_certificates,
                    "total_keys": total_keys,
                    "quantum_readiness_score": quantum_readiness_score,
                    "average_risk_score": round(average_risk_score * 10) / 10,
                },
                "severity_distribution": severity_distribution,
                "algorithm_type_distribution": dict(algorithm_type_distribution),
                "strength_distribution": strength_distribution,
                "quantum_readiness": quantum_readiness,
                "owasp_top_10_issues": dict(owasp_top_10_metrics),
                "compliance_controls": dict(compliance_controls_metrics),
                "top_risks": top_risks_list,
                "remediation_actions_required": remediation_actions_required,
                "remediation_metrics": remediation_metrics,
            }

        elif scan_type == "ai_bom":
            # =========== AI-BOM Dashboard ===========================
            model_component_types = {"local_model_file", "huggingface_model", "embedding_model"}

            severity_distribution = {"critical": 0, "high": 0, "medium": 0, "low": 0}
            asset_type_distribution = defaultdict(int)
            provider_distribution = defaultdict(int)
            license_distribution = defaultdict(int)
            risk_category_distribution = defaultdict(int)
            owasp_top_10_llm_issues = defaultdict(int)
            compliance_controls_metrics = defaultdict(int)
            top_risks_entries = []

            total_ai_assets = len(results)
            # Distinct entity sets (count UNIQUE entities, not detection rows).
            # e.g. an OpenAI SDK imported in 4 files is ONE external provider, not 4.
            distinct_external_providers: set = set()
            distinct_models: set = set()
            distinct_datasets: set = set()
            total_high_risk_assets = 0
            total_unlicensed_assets = 0
            assets_with_license_and_card = 0

            for asset in results:
                # severity distribution
                impact = asset.get("impact", "Low")
                impact_lower = (impact or "low").lower()
                if impact_lower in severity_distribution:
                    severity_distribution[impact_lower] += 1

                # asset type distribution (from component_type)
                component_type = (asset.get("component_type") or "unknown").lower()
                asset_type_distribution[component_type] += 1

                # provider distribution (from source)
                provider = asset.get("source") or "unknown"
                provider_distribution[provider] += 1

                # license distribution (from license)
                license_type = asset.get("license") or "unknown"
                license_distribution[license_type] += 1

                # risk category distribution
                risk_category = asset.get("risk_category") or "unknown"
                risk_category_distribution[risk_category] += 1

                # Distinct entity counts.
                # asset_name comes from the worker field 'component_name'; provider
                # from 'source' (ModelProvider value, e.g. openai/anthropic).
                asset_name = asset.get("component_name") or asset.get("title") or "Unknown"
                if component_type in model_component_types:
                    # distinct model by (provider, asset_name). Catalog-only model
                    # references (supported-model registries, not models the app
                    # uses) are already excluded upstream by the aibom adapter's
                    # _inventory(), so this is the verified true count, not the
                    # catalog over-count.
                    distinct_models.add((provider, asset_name))
                if component_type == "external_provider":
                    # distinct provider among external_provider findings
                    distinct_external_providers.add(provider)
                if component_type == "dataset":
                    # distinct dataset by asset_name
                    distinct_datasets.add(asset_name)

                # high-risk assets (Critical / High impact)
                if impact_lower in ("critical", "high"):
                    total_high_risk_assets += 1

                # unlicensed assets = LIBRARIES with a genuinely-unknown license.
                # Excluded: model references (a model with no resolved license is the
                # softer, distinct "model-license-unknown" finding) AND external
                # providers/services (a hosted API — OpenAI, AWS Bedrock, Ollama — is
                # not a licensable software package, so it is never a true "unknown").
                # Counting either inflated this metric beyond genuine library unknowns.
                lic = (asset.get("license") or "").lower().strip()
                if (
                    (not lic or lic == "unknown")
                    and component_type not in model_component_types
                    and component_type != "external_provider"
                ):
                    total_unlicensed_assets += 1

                # governance readiness: assets with both license and model card
                has_license = bool(lic) and lic != "unknown"
                has_card = bool(asset.get("model_card") or asset.get("card"))
                if has_license and has_card:
                    assets_with_license_and_card += 1

                # owasp top 10 llm metrics
                for key, value in (asset.get("owasp_top_10_llm") or {}).items():
                    owasp_top_10_llm_issues[value] += 1

                # compliance controls
                for key, value in (asset.get("compliance_controls") or {}).items():
                    compliance_controls_metrics[value] += 1

                # top risks entries
                top_risks_entries.append({
                    "asset_name": asset.get("component_name", asset.get("title", "Unknown")),
                    "asset_type": component_type,
                    "provider": provider,
                    "license_type": license_type,
                    "impact": impact,
                })

            # Compliance Controls panel: AI-BOM findings carry no per-control
            # data (compliance is framework-level), so aggregate the framework
            # result (ai_bom_compliance) into per-framework FAIL counts — the
            # same evidence the ComplianceCoverage chart uses. Falls back to
            # whatever findings did carry (above) if the framework result is absent.
            _scan_data = scan.scan_data if scan else (scan_results if isinstance(scan_results, dict) else {})
            _ai_bom_compliance = _scan_data.get("ai_bom_compliance") if isinstance(_scan_data, dict) else None
            if isinstance(_ai_bom_compliance, dict):
                for _fw_key, _fw in _ai_bom_compliance.items():
                    if _fw_key == "disclaimer" or not isinstance(_fw, dict):
                        continue
                    _fail = _fw.get("fail") or 0
                    if _fail:
                        _label = _fw.get("title") or _fw_key
                        compliance_controls_metrics[_label] += int(_fail)

            # Materialize distinct entity counts.
            total_models = len(distinct_models)
            total_datasets = len(distinct_datasets)
            total_external_providers = len(distinct_external_providers)

            # Governance readiness score
            governance_readiness_score = 0.0
            if total_ai_assets > 0:
                governance_readiness_score = round((assets_with_license_and_card / total_ai_assets) * 100, 1)

            # Average risk score (normalized 0-10 scale, same as cbom)
            total_findings = sum(severity_distribution.values())
            if total_findings > 0:
                weighted = (severity_distribution["critical"] * 4 + severity_distribution["high"] * 3 + severity_distribution["medium"] * 2 + severity_distribution["low"] * 1) / total_findings
                average_risk_score = min(10.0, max(0.0, (weighted / 4) * 10))
            else:
                average_risk_score = 0.0

            # Top risks sorted by impact severity
            impact_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
            top_risks_list = sorted(
                top_risks_entries,
                key=lambda x: impact_order.get((x.get("impact") or "low").lower(), 0),
                reverse=True,
            )[:10]

            # Remediation metrics
            findings = get_findings_for_scan_id(scan_id=scan_id)
            remediation_metrics = get_remediation_metrics(findings)
            status_metrics = get_issue_status_metrics(findings)

            remediation_actions_required = {
                "total_findings": len(findings),
                "total_fixed": status_metrics.get("fixed", 0),
                "total_in_progress": status_metrics.get("in_progress", 0),
                "total_not_started": status_metrics.get("not_started", 0),
                "total_ignored": status_metrics.get("ignored", 0),
            }

            return {
                "card_data": {
                    "total_ai_assets": total_ai_assets,
                    "total_models": total_models,
                    "total_datasets": total_datasets,
                    "total_external_providers": total_external_providers,
                    "total_high_risk_assets": total_high_risk_assets,
                    "total_unlicensed_assets": total_unlicensed_assets,
                    "governance_readiness_score": governance_readiness_score,
                    "average_risk_score": round(average_risk_score * 10) / 10,
                },
                "severity_distribution": severity_distribution,
                "asset_type_distribution": dict(asset_type_distribution),
                "provider_distribution": dict(provider_distribution),
                "license_distribution": dict(license_distribution),
                "risk_category_distribution": dict(risk_category_distribution),
                "owasp_top_10_llm_issues": dict(owasp_top_10_llm_issues),
                "compliance_controls": dict(compliance_controls_metrics),
                "top_risks": top_risks_list,
                "remediation_actions_required": remediation_actions_required,
                "remediation_metrics": remediation_metrics,
            }

        elif scan_type == "mobile":
            severity_distribution = {"critical": 0, "high": 0, "medium": 0, "low": 0}
            category_distribution = defaultdict(int)
            top_risks_entries = []
            mobile_risk_score_for_impact = {"critical": 9, "high": 7, "medium": 5, "low": 2}

            for vulnerability in results:
                impact = vulnerability.get("impact") or "Low"
                impact_lower = impact.lower()
                if impact_lower in severity_distribution:
                    severity_distribution[impact_lower] += 1
                category = vulnerability.get("category") or "general"
                category_distribution[category] += 1
                risk_score = mobile_risk_score_for_impact.get(impact_lower, 0)
                top_risks_entries.append({
                    "title": vulnerability.get("title", "Unknown"),
                    "category": category,
                    "impact": impact,
                    "risk_score": risk_score,
                })

            total_findings = sum(severity_distribution.values())
            if total_findings > 0:
                weighted = (
                    severity_distribution["critical"] * 4
                    + severity_distribution["high"] * 3
                    + severity_distribution["medium"] * 2
                    + severity_distribution["low"] * 1
                ) / total_findings
                average_risk_score = min(10.0, max(0.0, (weighted / 4) * 10))
            else:
                average_risk_score = 0.0

            impact_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
            top_risks_list = sorted(
                top_risks_entries,
                key=lambda x: impact_order.get((x.get("impact") or "low").lower(), 0),
                reverse=True,
            )[:10]

            findings = get_findings_for_scan_id(scan_id=scan_id)
            remediation_metrics = get_remediation_metrics(findings)
            status_metrics = get_issue_status_metrics(findings)

            mobile_summary = {}
            if scan and isinstance(scan.scan_data, dict):
                mobile_summary = scan.scan_data.get("mobile_summary") or {}

            return {
                "card_data": {
                    "total_findings": total_findings,
                    "total_critical": severity_distribution["critical"],
                    "total_high": severity_distribution["high"],
                    "total_medium": severity_distribution["medium"],
                    "total_low": severity_distribution["low"],
                    "average_risk_score": round(average_risk_score * 10) / 10,
                    "security_score": mobile_summary.get("security_score"),
                    "app_name": mobile_summary.get("app_name"),
                    "package_name": mobile_summary.get("package_name"),
                    "version_name": mobile_summary.get("version_name"),
                    "platform": mobile_summary.get("platform"),
                },
                "severity_distribution": severity_distribution,
                "category_distribution": dict(category_distribution),
                "top_risks": top_risks_list,
                "mobile_summary": mobile_summary,
                "remediation_actions_required": {
                    "total_findings": len(findings),
                    "total_fixed": status_metrics.get("fixed", 0),
                    "total_in_progress": status_metrics.get("in_progress", 0),
                    "total_not_started": status_metrics.get("not_started", 0),
                    "total_ignored": status_metrics.get("ignored", 0),
                },
                "remediation_metrics": remediation_metrics,
            }

    except Exception as e:
        console.print(f"Error in generate_scan_dashboard: {e}",style="bold red")
        raise e