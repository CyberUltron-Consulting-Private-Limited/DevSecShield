from sqlmodel import Session, select
from sqlalchemy.engine import Engine
from backend.new_models import Scan, GuardrailsIntegration, CicdIntegration
import datetime
from datetime import timedelta

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
            for vulnerability in scan.scan_data.get("vulnerabilities", []):
                impact : str = vulnerability.get("impact") | "low"
                impact = impact.lower()
                if impact == "high" or impact == "critical":
                    high_and_critical_vuln_in_past_month[impact] += 1
                
        elif scan.scan_type == "sast" :
            for logical_component in scan.scan_data.get("logical_components", []):
                for vulnerability in logical_component.get("vulnerabilities", []):
                    impact : str = vulnerability.get("impact") | "low"
                    impact = impact.lower()
                    if impact == "high" or impact == "critical":
                        high_and_critical_vuln_in_past_month[impact] += 1
    
    # STEP [ 8 ] : ============================= Return the data ================================================
    # return {
    #     "scans_created_at_data": scans_created_at_data,
    #     "guardrails_integrations_created_at_data": guardrails_integrations_created_at_data,
    #     "cicd_integrations_created_at_data": cicd_integrations_created_at_data,
    #     "scan_type_count": scan_type_count,
    #     "high_and_critical_vuln_in_past_month": high_and_critical_vuln_in_past_month
    # }

    mock_data = {
        "scans_created_at_data": [
            { "date": "2025-01-01", "count": 10 },
            { "date": "2025-01-02", "count": 20 },
            { "date": "2025-01-03", "count": 30 },
        ],
        "guardrails_integrations_created_at_data": [
            { "date": "2025-01-01", "count": 10 },
            { "date": "2025-01-02", "count": 20 },
            { "date": "2025-01-03", "count": 30 },
        ],
        "cicd_integrations_created_at_data": [
            { "date": "2025-01-01", "count": 10 },
            { "date": "2025-01-02", "count": 20 },
            { "date": "2025-01-03", "count": 30 },
        ],
        "scan_type_count": { "sast": 10, "llm": 20, "mcp": 30, "iac": 40, "leakage": 50, "sbom_sca": 60, "agent_discovery": 70, "dast": 80 },
        "high_and_critical_vuln_in_past_month": { "low": 10, "medium": 20, "high": 30, "critical": 40 } 
    }
    return mock_data
    
    

