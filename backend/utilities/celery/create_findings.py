from backend.new_models import scan_types
from rich.console import Console
from backend.mongo_models import ScanFindings
from pymongo.database import Database
from datetime import datetime , timezone
console = Console()


def create_findings_in_mongo_db(
    scan_id: int, 
    scan_results: dict ,
    scan_type: scan_types,
    mongo_db: Database,
    ):  
    pass
    if scan_results == None or scan_results == {}:
        console.print(f"No scan results found for scan id: {scan_id}",style="bold red")
        return 

    
    if scan_type == "sast":
        results = scan_results["results"]
        to_insert = []
        for item in results: 
            logical_component_title = item["logical_component_title"]
            vulnerabilities = item["vulnerabilities"]   
            for vulnerability in vulnerabilities:
                vulnerability["logical_component_title"] = logical_component_title
                scan_finding = ScanFindings(
                    scan_id = scan_id,
                    finding_data = vulnerability,
                    created_at = datetime.now(timezone.utc),
                    finding_status = "not_started",
                    fixed_at = None,
                    ignored_at = None,
                    info = None,
                )
                to_insert.append(scan_finding)
        mongo_db["scan_findings"].insert_many(to_insert)
        
    
    elif scan_type == "iac":
        results = scan_results["results"]
        to_insert = []
        for vulnerability in results:
            scan_finding = ScanFindings(
                scan_id = scan_id,
                finding_data = vulnerability,
                created_at = datetime.now(timezone.utc),
                finding_status = "not_started",
                fixed_at = None,
                ignored_at = None,
                info = None,
            )
            to_insert.append(scan_finding)
        mongo_db["scan_findings"].insert_many(to_insert)

    

    elif scan_type == "sbom_sca":
        pass
    elif scan_type == "mcp":
        pass
    elif scan_type == "llm":
        pass