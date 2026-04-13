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
    try:
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
            if len(to_insert) > 0:
                mongo_db["scan_findings"].insert_many(to_insert)
            
        
        elif scan_type == "iac" or scan_type == "sbom_sca" or scan_type == "dast" :
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
            if len(to_insert) > 0:
                mongo_db["scan_findings"].insert_many(to_insert)


                
        elif scan_type == "mcp":
            results = scan_results["results"]
            to_insert = []
            for tool in results["tools"]:
                for vulnerability in tool["vulnerabilities"]:
                    vulnerability["type"] = "tool"
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
            
            for prompt in results["prompts"]:
                for vulnerability in prompt["vulnerabilities"]:
                    vulnerability["type"] = "prompt"
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
            
            for resource in results["resources"]:
                for vulnerability in resource["vulnerabilities"]:
                    vulnerability["type"] = "resource"
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
            

            if len(to_insert) > 0:
                mongo_db["scan_findings"].insert_many(to_insert)

        elif scan_type == "llm":
            results = scan_results["results"]
            print(results)
            to_insert = []
            for vulnerability in results["vulnerabilities"]:
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
            if len(to_insert) > 0:
                mongo_db["scan_findings"].insert_many(to_insert)
        
        elif scan_type == "cbom":
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
            if len(to_insert) > 0:
                mongo_db["scan_findings"].insert_many(to_insert)

    
    except Exception as e:
        console.print(f"Error in creating findings in mongo db: {e}",style="bold red")
        raise e