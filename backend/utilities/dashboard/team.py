from sqlmodel import Session, select
from sqlalchemy.engine import Engine
from backend.new_models import Scan, GuardrailsIntegration, CicdIntegration , User , Team
from sqlalchemy import or_
from datetime import datetime, timedelta

def generate_team_dashboard_data(team_id: int, engine: Engine) -> dict:
    
    # STEP [ 1 ] : ==================== Get all the records for this team =================================
    with Session(engine) as session:
        # STEP [ 1.1 ] : ==================== Get all Scan records for this team =================================
        scans = session.exec(select(Scan).where(Scan.team_id == team_id)).all()

        # STEP [ 1.2 ] : ==================== Get all Guardrails Integration records for this team =================================
        guardrails_integrations = session.exec(select(GuardrailsIntegration).where(GuardrailsIntegration.team_id == team_id)).all()

        # STEP [ 1.3 ] : ==================== Get all Cicd Integration records for this team =================================
        cicd_integrations = session.exec(select(CicdIntegration).where(CicdIntegration.team_id == team_id)).all()
    

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
    scan_type_count : dict[str,int] = { "sast": 0, "llm": 0, "mcp": 0, "iac": 0, "leakage": 0, "sbom_sca": 0, "agent_discovery": 0, "dast": 0 }
    scans_in_past_month : list[Scan] = []
    for scan in scans:
        if scan.created_at.date() >= datetime.now().date() - timedelta(days=30):
            scans_in_past_month.append(scan)
    for scan in scans_in_past_month:
        scan_type_count[scan.scan_type] += 1
    
    # STEP [ 6 ] : ========================== Detected high and critical vulnerabilities in the past month ================================================
    
    high_and_critical_vuln_in_past_month : dict[str,int] = { "low" : 0 , "medium" : 0 , "high" : 0 , "critical" : 0 }
    for scan in scans_in_past_month:
        if scan.scan_type == "iac" or scan.scan_type == "sbom_sca":
            for vulnerability in scan.scan_data:
                impact : str = vulnerability.get("impact") or "low"
                impact = impact.lower()
                if impact == "high" or impact == "critical":
                    high_and_critical_vuln_in_past_month[impact] += 1
                
        elif scan.scan_type == "sast" :
            for item in scan.scan_data:
                for vulnerability in item.get("vulnerabilities", []):
                    impact : str = vulnerability.get("impact") or  "low"
                    impact = impact.lower()
                    if impact == "high" or impact == "critical":
                        high_and_critical_vuln_in_past_month[impact] += 1
    
    # STEP [ 8 ] : ============================= Return the data ================================================
    return {
        "scans_created_at_data": scans_created_at_data,
        "guardrails_integrations_created_at_data": guardrails_integrations_created_at_data,
        "cicd_integrations_created_at_data": cicd_integrations_created_at_data,
        "scan_type_count": scan_type_count,
        "high_and_critical_vuln_in_past_month": high_and_critical_vuln_in_past_month
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
    

            
    
    
    

