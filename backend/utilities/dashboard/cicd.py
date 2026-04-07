import datetime
from collections import defaultdict

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

# Canonical impact keys for risk_metrics (default 0 for each)
RISK_METRICS_KEYS = ("Low", "Medium", "High", "Critical")

# Normalize raw impact string to one of RISK_METRICS_KEYS (or None)
def _normalize_impact(impact: str) -> str | None:
    if not impact or not isinstance(impact, str):
        return None
    key = impact.strip().lower()
    if key == "critical":
        return "Critical"
    if key == "high":
        return "High"
    if key == "medium":
        return "Medium"
    if key == "low":
        return "Low"
    return None


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
    # All keys default to 0
    risk_metrics = {k: 0 for k in RISK_METRICS_KEYS}
    cves_per_vulnerability = defaultdict(int)
    risk_scores_per_finding = defaultdict(float)
    policy_violations = defaultdict(int)

    for item in items:
        for vuln in item.get("vulnerabilities", []):
            # owasp metrics (value as key; default 0 for any new key)
            for key, value in (vuln.get("owasp_top_10") or {}).items():
                if value is not None and str(value).strip():
                    owasp_top_10_metrics[str(value).strip()] += 1
            # compliance controls (default 0)
            for key, value in (vuln.get("compliance_controls") or {}).items():
                if value is not None and str(value).strip():
                    compliance_controls_metrics[str(value).strip()] += 1
            # risk metrics: normalize impact so all keys have default 0
            impact_raw = (vuln.get("impact") or "").strip()
            impact_key = _normalize_impact(impact_raw)
            if impact_key is not None:
                risk_metrics[impact_key] = risk_metrics.get(impact_key, 0) + 1
            # cves per vulnerability (default 0)
            cves = vuln.get("cves")
            if isinstance(cves, dict):
                for key, value in cves.items():
                    if value is not None and str(value).strip():
                        cves_per_vulnerability[str(value).strip()] += 1
            elif isinstance(cves, list):
                for c in cves:
                    if c is not None and str(c).strip():
                        cves_per_vulnerability[str(c).strip()] += 1
            # risk score per finding (default 0)
            impact_lower = (impact_raw or "").lower()
            if impact_lower in RISK_SCORE_FOR_IMPACT:
                risk_scores_per_finding[vuln.get("title") or ""] = RISK_SCORE_FOR_IMPACT[impact_lower]
            # policy violations (default 0)
            for key, value in (vuln.get("compliance_controls") or {}).items():
                if value and " - " in str(value):
                    policy_violations[str(value).split(" - ")[0].strip()] += 1

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
        engine = get_db()
        mongo_db = get_mongo_client_db()
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