from sqlmodel import Session, select
from sqlalchemy.engine import Engine
from backend.new_models import Scan, GuardrailsIntegration, CicdIntegration , User , Team
from sqlalchemy import or_
from datetime import datetime, timedelta, date
from collections import defaultdict
from rich.console import Console
from backend.utilities.db.findings import get_findings_for_scan_id
console = Console()


def _to_date_key(d) -> str | None:
    """Get YYYY-MM-DD from datetime or date. Returns None if not available."""
    if d is None:
        return None
    if hasattr(d, "date") and callable(getattr(d, "date")):
        return d.date().isoformat()
    if hasattr(d, "isoformat") and callable(getattr(d, "isoformat")):
        return d.isoformat()[:10]
    return None

def generate_team_dashboard_data(team_id: int, engine: Engine) -> dict:
    """
    metrics to be added : 
    1. scan status distribution ( radial chart )
        {
            "not_started": int,
            "running": int,
            "completed": int,
            "failed": int
        }
    2. Remediations Status Distribution ( area - line chart ) 
        {
            "2026-01-01": {
                "not_started": int,
                "in_progress": int,
                "fixed": int,
                "ignored": int
            },
            "2026-01-02": {
                "not_started": int,
                "in_progress": int,
                "fixed": int,
                "ignored": int
            },
            ...
        }
    3. Findings Per day ( area - line chart )
    note : number of findings per day ( use created_at field )
        {
            "2026-01-01": int,
            "2026-01-02": int,
            "2026-01-03": int,
            ...
        }
    4. Fixes Per day ( area - line chart )
    note : number of fixed findings per day
        {
            "2026-01-01": int,
            "2026-01-02": int,
            "2026-01-03": int,
            ...
        }
    5. False Positive trends ( area - line chart )
    note : number of ignored findings per day
        {
            "2026-01-01": int,
            "2026-01-02": int,
            "2026-01-03": int,
            ...
        }
    6. Card Data :
        - total findings 
        - total started scans 
        - total completed scans 
        - total not started scans 
        - total fixed findings
        - remediation percentage ( total fixed findings / total findings * 100 )
    """
    
    # STEP [ 1 ] : ==================== Get all the records for this team =================================
    with Session(engine) as session:
        # STEP [ 1.1 ] : ==================== Get all Scan records for this team =================================
        scans = session.exec(select(Scan).where(Scan.team_id == team_id)).all()

        # STEP [ 1.2 ] : ==================== Get all Guardrails Integration records for this team =================================
        guardrails_integrations = session.exec(select(GuardrailsIntegration).where(GuardrailsIntegration.team_id == team_id)).all()

        # STEP [ 1.3 ] : ==================== Get all Cicd Integration records for this team =================================
        cicd_integrations = session.exec(select(CicdIntegration).where(CicdIntegration.team_id == team_id)).all()

        ## STEP [ 1.4 ] : ==================== Get all Scan Findings records for this team =================================
        findings_list = [] # use this to calculate the additonal metrics mentioned above 
        for scan in scans:
            findings = get_findings_for_scan_id(scan.id)
            findings_list.extend(findings)
        console.print(f"{len(findings_list)} findings found")

    # STEP [ 1.5 ] : ==================== Scan status distribution (radial chart) ==========================================
    scan_status_distribution: dict[str, int] = {
        "not_started": 0,
        "running": 0,
        "completed": 0,
        "failed": 0,
    }
    for scan in scans:
        status = (scan.scan_status or "NOT_STARTED").strip().upper()
        if status in ("NOT_STARTED", "PENDING"):
            scan_status_distribution["not_started"] += 1
        elif status in ("STARTED", "RETRY"):
            scan_status_distribution["running"] += 1
        elif status == "SUCCESS":
            scan_status_distribution["completed"] += 1
        elif status == "FAILURE":
            scan_status_distribution["failed"] += 1

    # STEP [ 1.6 ] : ==================== Findings-based metrics (remediations, findings/fixes/FP per day) ==========================================
    findings_per_day: dict[str, int] = defaultdict(int)
    fixes_per_day: dict[str, int] = defaultdict(int)
    false_positive_trends: dict[str, int] = defaultdict(int)
    remediations_status_distribution: dict[str, dict[str, int]] = defaultdict(
        lambda: {"not_started": 0, "in_progress": 0, "fixed": 0, "ignored": 0}
    )

    for finding in findings_list:
        created_at = finding.get("created_at")
        created_key = _to_date_key(created_at)
        status = (finding.get("finding_status") or "not_started").strip().lower().replace(" ", "_")
        fixed_at = finding.get("fixed_at")
        ignored_at = finding.get("ignored_at")
        fixed_key = _to_date_key(fixed_at)
        ignored_key = _to_date_key(ignored_at)

        if created_key:
            findings_per_day[created_key] += 1
            if status not in ("not_started", "in_progress", "fixed", "ignored"):
                status = "not_started"
            remediations_status_distribution[created_key][status] += 1
        if fixed_key:
            fixes_per_day[fixed_key] += 1
            remediations_status_distribution[fixed_key]["fixed"] += 1
        if ignored_key:
            false_positive_trends[ignored_key] += 1
            remediations_status_distribution[ignored_key]["ignored"] += 1

    # Normalize remediations to plain dict with string keys (for JSON)
    remediations_status_distribution = {
        k: dict(v) for k, v in sorted(remediations_status_distribution.items())
    }
    findings_per_day = dict(findings_per_day)
    fixes_per_day = dict(fixes_per_day)
    false_positive_trends = dict(false_positive_trends)

    # STEP [ 1.7 ] : ==================== Card data (totals for summary cards) ==========================================
    total_findings = len(findings_list)
    total_fixed_findings = sum(
        1 for f in findings_list
        if (f.get("finding_status") or "").strip().lower() == "fixed" or f.get("fixed_at") is not None
    )
    remediation_percentage = (
        round((total_fixed_findings / total_findings * 100.0), 1) if total_findings else 0.0
    )
    card_data = {
        "total_findings": total_findings,
        "total_started_scans": scan_status_distribution["running"],
        "total_completed_scans": scan_status_distribution["completed"],
        "total_not_started_scans": scan_status_distribution["not_started"],
        "total_fixed_findings": total_fixed_findings,
        "remediation_percentage": remediation_percentage,
    }

    # STEP [ 2 ] : =============================== calculate scans - created at data ==========================================
    scans_created_at_data = []
    for scan in scans:
        scans_created_at_data.append({
            "date": scan.created_at.date(),
            "count": 1
        })

    # STEP [ 3 ] : =============================== calculate guardrails integrations - created at data ==========================================
    guardrails_integrations_created_at_data = []
    for guardrails_integration in guardrails_integrations:
        guardrails_integrations_created_at_data.append({
            "date": guardrails_integration.created_at.date(),
            "count": 1
        })

    # STEP [ 4 ] : =============================== calculate cicd integrations - created at data ==========================================
    cicd_integrations_created_at_data = []
    for cicd_integration in cicd_integrations:
        cicd_integrations_created_at_data.append({
            "date": cicd_integration.created_at.date(),
            "count": 1
        })
    
    # STEP [ 5 ] : ================================= number of types of scans run in the past month ================================================
    scan_type_count : dict[str,int] = { "sast": 0, "llm": 0, "mcp": 0, "iac": 0, "leakage": 0, "sbom_sca": 0, "agent_discovery": 0, "dast": 0, "cbom": 0, "ai_bom": 0 }
    scans_in_past_month : list[Scan] = []
    for scan in scans:
        if scan.created_at.date() >= datetime.now().date() - timedelta(days=30):
            scans_in_past_month.append(scan)
    for scan in scans_in_past_month:
        scan_type_count[scan.scan_type] += 1
    
    # STEP [ 6 ] : ========================== Detected high and critical vulnerabilities in the past month ================================================
    
    high_and_critical_vuln_in_past_month : dict[str,int] = { "low" : 0 , "medium" : 0 , "high" : 0 , "critical" : 0 }
    for scan in scans_in_past_month:
        if (scan.scan_type == "iac" or scan.scan_type == "sbom_sca") and "results" in scan.scan_data:
            for vulnerability in scan.scan_data["results"]:
                impact : str = vulnerability.get("impact") or "low"
                impact = impact.lower()
                if impact == "high" or impact == "critical":
                    high_and_critical_vuln_in_past_month[impact] += 1
                
        elif scan.scan_type == "sast" and "results" in scan.scan_data:
            for item in scan.scan_data["results"]:
                for vulnerability in item.get("vulnerabilities", []):
                    impact : str = vulnerability.get("impact") or  "low"
                    impact = impact.lower()
                    if impact == "high" or impact == "critical":
                        high_and_critical_vuln_in_past_month[impact] += 1
        
        elif scan.scan_type == "llm" and "results" in scan.scan_data:
            for vulnerability in scan.scan_data["results"]["vulnerabilities"]:
                impact : str = vulnerability.get("impact") or  "low"
                impact = impact.lower()
                if impact == "high" or impact == "critical":
                    high_and_critical_vuln_in_past_month[impact] += 1
        
        elif scan.scan_type == "mcp" and "results" in scan.scan_data : 
            for tool in scan.scan_data["results"]["tools"]:
                if "vulnerabilities" in tool :
                    for vulnerability in tool["vulnerabilities"]:
                        impact : str = vulnerability.get("impact") or  "low"
                        impact = impact.lower()
                        if impact == "high" or impact == "critical":
                            high_and_critical_vuln_in_past_month[impact] += 1
            for resource in scan.scan_data["results"]["resources"]:
                if "vulnerabilities" in resource :
                    for vulnerability in resource["vulnerabilities"]:
                        impact : str = vulnerability.get("impact") or  "low"
                        impact = impact.lower()
                        if impact == "high" or impact == "critical":
                            high_and_critical_vuln_in_past_month[impact] += 1
            for prompt in scan.scan_data["results"]["prompts"]:
                if "vulnerabilities" in prompt :
                    for vulnerability in prompt["vulnerabilities"]:
                        impact : str = vulnerability.get("impact") or  "low"
                        impact = impact.lower()
                        if impact == "high" or impact == "critical":
                            high_and_critical_vuln_in_past_month[impact] += 1
                

    
    # STEP [ 8 ] : ============================= Return the data ================================================
    from backend.utilities.dashboard.rbi_posture import build_team_rbi_posture_from_scans
    from backend.utilities.dashboard.certin_posture import build_team_certin_posture_from_scans

    rbi_csf_rollup = build_team_rbi_posture_from_scans(scans)
    certin_posture = build_team_certin_posture_from_scans(scans)

    return {
        "scans_created_at_data": scans_created_at_data,
        "guardrails_integrations_created_at_data": guardrails_integrations_created_at_data,
        "cicd_integrations_created_at_data": cicd_integrations_created_at_data,
        "scan_type_count": scan_type_count,
        "high_and_critical_vuln_in_past_month": high_and_critical_vuln_in_past_month,
        "scan_status_distribution": scan_status_distribution,
        "remediations_status_distribution": remediations_status_distribution,
        "findings_per_day": findings_per_day,
        "fixes_per_day": fixes_per_day,
        "false_positive_trends": false_positive_trends,
        "card_data": card_data,
        "rbi_csf_rollup": rbi_csf_rollup,
        "certin_posture": certin_posture,
    }


def generate_team_list_dashboard_data(user_id: int, engine: Engine) -> dict:
    """
    Calculate the data for the team list dashboard.
    Arguments :
    - user_id : int
    - engine : Engine
    Returns :
    - dict

    Data : 
    
    1. Team utilization data 
        for every team : 
            - number of sast scans run 
            - number of iac scans run 
            - number of sbom sca scans run 
            - number of guardrails integrations 
            - number of cicd integrations 
    2. Credit balance data 
        for every team : 
            - credit balance 
    
    Data will look like this : 
    {
        "team_utilization_data": {
            f"{team_id}-{team_name}": {
                "sast_scans": int,
                "iac_scans": int,
                "sbom_sca_scans": int,
                "guardrails_integrations": int,
                "cicd_integrations": int
            } , ..........
        },
        "credit_balance_data": {
            f"{team_id}-{team_name}": {
                "credit_balance": int
            } , ..........
        }
    }
    """
    team_utilization_data = {}
    credit_balance_data = {}
    with Session(engine) as session:
        user = session.exec(select(User).where(User.id == user_id)).first()
            
        or_statements = []
        for membership in user.team_memberships:
            or_statements.append(Team.id == membership.team_id)
        team_objects = session.exec(select(Team).where(or_(*or_statements))).all()
        for team_object in team_objects:
            team_utilization_item = {"sast_scans": 0, "iac_scans": 0, "sbom_sca_scans": 0, "guardrails_integrations": 0, "cicd_integrations": 0}
            credit_balance_item = {"credit_balance": team_object.credit_balance}
            scans_in_team = team_object.scans
            for scan in scans_in_team:
                if scan.scan_type == "sast":
                    team_utilization_item["sast_scans"] += 1
                elif scan.scan_type == "iac":
                    team_utilization_item["iac_scans"] += 1
                elif scan.scan_type == "sbom_sca":
                    team_utilization_item["sbom_sca_scans"] += 1
            team_utilization_item["guardrails_integrations"] = len(team_object.guardrails_integrations)
            team_utilization_item["cicd_integrations"] = len(team_object.cicd_integrations)
    

            team_utilization_data[f"{team_object.id}-{team_object.name}"] = team_utilization_item
            credit_balance_data[f"{team_object.id}-{team_object.name}"] = credit_balance_item
    
    return {
        "team_utilization_data": team_utilization_data,
        "credit_balance_data": credit_balance_data
    }
    

            
    
    
    

