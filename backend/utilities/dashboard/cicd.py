import datetime
from collections import defaultdict

from backend.get_db import dev_environment
from backend.get_db import get_db , get_mongo_client_db
from rich.console import Console

console = Console()

# Risk score mapping (aligned with scan.py)
RISK_SCORE_FOR_IMPACT = {
    "critical": 10.0,
    "high": 7.5,
    "medium": 5.0,
    "low": 2.5,
}


def _normalize_results(data: list[dict] | dict) -> list[dict]:
    """Normalize results: accept either a list of findings or a dict with 'results' key."""
    if isinstance(data, list):
        return data
    if isinstance(data, dict) and "results" in data:
        return data.get("results", [])
    return []


def get_cicd_sast_dashboard_data(results: list[dict] | dict) -> dict:
    """
    Compute SAST dashboard metrics from CI/CD scan results (same structure as scan.py sast, without remediation_metrics).
    Args:
        results: List of logical components with vulnerabilities, or dict with "results" key
    Returns:
        dict with owasp_top_10_metrics, compliance_controls_metrics, risk_metrics,
        cves_per_vulnerability, policy_violations, risk_scores_per_finding
    """
    items = _normalize_results(results)
    owasp_top_10_metrics = defaultdict(int)
    compliance_controls_metrics = defaultdict(int)
    risk_metrics = {"Low": 0, "Medium": 0, "High": 0, "Critical": 0}
    cves_per_vulnerability = defaultdict(int)
    risk_scores_per_finding = defaultdict(float)
    policy_violations = defaultdict(int)

    for item in items:
        for vuln in item.get("vulnerabilities", []):
            # owasp metrics
            for key, value in (vuln.get("owasp_top_10") or {}).items():
                owasp_top_10_metrics[value] += 1
            # compliance controls
            for key, value in (vuln.get("compliance_controls") or {}).items():
                compliance_controls_metrics[value] += 1
            # risk metrics
            impact = (vuln.get("impact") or "").strip()
            if impact in risk_metrics:
                risk_metrics[impact] += 1
            # cves per vulnerability
            for key, value in (vuln.get("cves") or {}).items():
                cves_per_vulnerability[value] += 1
            # risk score per finding
            impact_lower = impact.lower()
            if impact_lower in RISK_SCORE_FOR_IMPACT:
                risk_scores_per_finding[vuln.get("title") or ""] = RISK_SCORE_FOR_IMPACT[impact_lower]
            # policy violations
            for key, value in (vuln.get("compliance_controls") or {}).items():
                if value and " - " in str(value):
                    policy_violations[str(value).split(" - ")[0]] += 1

    return {
        "owasp_top_10_metrics": dict(owasp_top_10_metrics),
        "compliance_controls_metrics": dict(compliance_controls_metrics),
        "risk_metrics": risk_metrics,
        "cves_per_vulnerability": dict(cves_per_vulnerability),
        "policy_violations": dict(policy_violations),
        "risk_scores_per_finding": dict(risk_scores_per_finding),
    }


def get_cicd_vuln_chart_data(results_list: list[tuple[list[dict] | dict, datetime.date]]) -> dict:
    """
    Get the vulnerability chart data for the given results list.
    Args:
        results_list : list[tuple[list[dict],datetime.date]]
    Returns:
        dict
    Example:
    {
        "2026-02-07": {
            "Critical": 10,
            "High": 20,
            "Medium": 30,
            "Low": 40,
        } , 
        "2026-02-08": {
            "Critical": 10,
            "High": 20,
            "Medium": 30,
            "Low": 40,
        } , 
        and so on 
    }
    """
    vulns_over_time_chart_data = {}
    for data, created_at in results_list:
        result = _normalize_results(data)
        if not result:
            continue

        date_key = created_at.isoformat() if hasattr(created_at, "isoformat") else str(created_at)
        if date_key not in vulns_over_time_chart_data:
            vulns_over_time_chart_data[date_key] = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        for finding in result:
            for vuln in finding.get("vulnerabilities", []):
                impact = (vuln.get("impact") or "").strip()
                if impact == "Critical":
                    vulns_over_time_chart_data[date_key]["Critical"] += 1
                elif impact == "High":
                    vulns_over_time_chart_data[date_key]["High"] += 1
                elif impact == "Medium":
                    vulns_over_time_chart_data[date_key]["Medium"] += 1
                elif impact == "Low":
                    vulns_over_time_chart_data[date_key]["Low"] += 1
    return vulns_over_time_chart_data

    # mock_data = {
    #     "2026-02-07": {
    #         "Critical": 10,
    #         "High": 60,
    #         "Medium": 0,
    #         "Low": 0,
    #     } , 
    #     "2026-02-08": {
    #         "Critical": 10,
    #         "High": 20,
    #         "Medium": 20,
    #         "Low": 0,
    #     } , 
    #     "2026-02-09": {
    #         "Critical": 10,
    #         "High": 20,
    #         "Medium": 0,
    #         "Low": 40,
    #     } , 
    #     "2026-02-10": {
    #         "Critical": 0,
    #         "High": 20,
    #         "Medium": 30,
    #         "Low": 40,
    #     } , 
    #     "2026-02-11": {
    #         "Critical": 10,
    #         "High": 20,
    #         "Medium": 30,
    #         "Low": 40,
    #     } , 
    #     "2026-02-12": {
    #         "Critical": 100,
    #         "High": 20,
    #         "Medium": 30,
    #         "Low": 40,
    #     } , 
    #     "2026-02-13": {
    #         "Critical": 10,
    #         "High": 20,
    #         "Medium": 30,
    #         "Low": 40,
    #     } , 
    # }
    # return mock_data


def get_cicd_list_dashboard_data(integration_ids : list[int]) -> dict:
    """
    Get the dashboard data for the given results list.
    Args:
        results_list : list[tuple[list[dict],datetime.date]]
    Returns:
        dict
    """
    try:
        engine = get_db(dev_environment=dev_environment)
        mongo_db = get_mongo_client_db(dev_environment=dev_environment)
        cicd_logs_collection = mongo_db["cicd_logs"]


        results_list = []
        for integration_id in integration_ids:
            cicd_logs = cicd_logs_collection.find({"ci_cd_integration_id": integration_id, "status": {"$in": ["pending", "started" , "success"]}})
            for log in cicd_logs:
                if not log["results"] or log["results"] is None or len(log["results"]) == 0:
                    continue
                results_list.append((log["results"],log["created_at"].date()))
        

        dashboard_data = get_cicd_vuln_chart_data(results_list=results_list)
        return dashboard_data
    except Exception as e:
        console.print(f"Error getting cicd list dashboard data: {str(e)}", style="bold red")
        return {}