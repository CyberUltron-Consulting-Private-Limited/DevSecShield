from backend.new_models import Scan, scan_types
from rich.console import Console
from sqlmodel import Session, select
from fastapi import HTTPException
from backend.get_db import get_db
from collections import defaultdict


dev_environment = True

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
                        owasp_top_10_metrics[key] += 1
                    for key,value in vulnerability["compliance_controls"].items():
                        compliance_controls_metrics[key] += 1
                    risk_metrics[vulnerability["impact"]] += 1
                    for key,value in vulnerability["cves"].items():
                        cves_per_vulnerability[key] += 1
            

            return {
                "owasp_top_10_metrics": owasp_top_10_metrics,
                "compliance_controls_metrics": compliance_controls_metrics,
                "risk_metrics": risk_metrics,
                "cves_per_vulnerability": cves_per_vulnerability
            }
    
        elif scan_type == "iac" or scan_type == "sbom_sca":
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
                    owasp_top_10_metrics[key] += 1
                for key,value in vulnerability["compliance_controls"].items():
                    compliance_controls_metrics[key] += 1
                risk_metrics[vulnerability["impact"]] += 1
                for key,value in vulnerability["cves"].items():
                    cves_per_vulnerability[key] += 1
            

            return {
                "owasp_top_10_metrics": owasp_top_10_metrics,
                "compliance_controls_metrics": compliance_controls_metrics,
                "risk_metrics": risk_metrics,
                "cves_per_vulnerability": cves_per_vulnerability
            }

    except Exception as e:
        console.print(f"Error in generate_scan_dashboard: {e}",style="bold red")
        raise e