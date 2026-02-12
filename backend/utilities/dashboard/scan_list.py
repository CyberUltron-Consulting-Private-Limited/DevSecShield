from backend.new_models import Scan
from datetime import datetime , timezone
from rich.console import Console
from fastapi import HTTPException , status

console = Console()
def generate_dashboard_data_for_scan_list(scans: list[Scan]) -> dict:
    """
    Generate dashboard data for a list of SAST scans.
    Arguments :
    - scans : list[Scan]
    Returns :
    - dict
    """
    try:
        pending_scans , started_scans , success_scans , failure_scans , not_started_scans , scans_created_today , scans_updated_today = 0 , 0 , 0 , 0 , 0 , 0 , 0
        repos_scanned : list[str] = []
        zip_files_scanned : int = 0 
        scans_per_day : dict = {}
        risks_per_day : dict = {} 

        for scan in scans:
            if scan.scan_status == "pending":
                pending_scans += 1
            elif scan.scan_status == "started":
                started_scans += 1
            elif scan.scan_status == "success":
                success_scans += 1
            elif scan.scan_status == "failure":
                failure_scans += 1
            elif scan.scan_status == "NOT_STARTED" or scan.scan_status == "not_started":
                not_started_scans += 1
            if scan.created_at.date() == datetime.now(timezone.utc).date():
                scans_created_today += 1
            if scan.last_updated.date() == datetime.now(timezone.utc).date():
                scans_updated_today += 1
            
            
            if scan.scan_data and scan.scan_data != {} and isinstance(scan.scan_data,list) and scan.scan_status == "success" and "repo_url" in scan.scan_metadata and scan.scan_metadata["repo_url"]:
                repos_scanned.append(scan.scan_metadata["repo_url"])
            if scan.scan_data and scan.scan_data != {} and isinstance(scan.scan_data,list) and scan.scan_status == "success" and "zip_file_used" in scan.scan_metadata and scan.scan_metadata["zip_file_used"]:
                zip_files_scanned += 1

            
            # getting risks per day data 
            """
            Will look like this : 
            {
                "2026-02-12": {
                    "critical": 1,
                    "high": 2,
                    "medium": 3,
                    "low": 4
                }
            }
            """


            if scan.scan_type == "sast" and scan.scan_data and scan.scan_data != {} and isinstance(scan.scan_data,list) and scan.scan_status == "success": 
                temp = { "critical" : 0, "high" : 0, "medium" : 0, "low" : 0 }
                for item in scan.scan_data:
                    for vulnerability in item["vulnerabilities"]:
                        if vulnerability["impact"].lower() == "critical":
                            temp["critical"] += 1
                        elif vulnerability["impact"].lower() == "high":
                            temp["high"] += 1
                        elif vulnerability["impact"].lower() == "medium":
                            temp["medium"] += 1
                        elif vulnerability["impact"].lower() == "low":
                            temp["low"] += 1
                risks_per_day[scan.created_at.date()] = temp
            
            if (scan.scan_type == "sbom_sca" or scan.scan_type == "iac") and scan.scan_data and scan.scan_data != {} and isinstance(scan.scan_data,list) and scan.scan_status == "success": 
                temp = { "critical" : 0, "high" : 0, "medium" : 0, "low" : 0 }
                for item in scan.scan_data:
                    if item["impact"].lower() == "critical":
                        temp["critical"] += 1
                    elif item["impact"].lower() == "high":
                        temp["high"] += 1
                    elif item["impact"].lower() == "medium":
                        temp["medium"] += 1
                    elif item["impact"].lower() == "low":
                        temp["low"] += 1
                risks_per_day[scan.created_at.date()] = temp
        
            
            # getting scans per day data 
            """
            Will look like this : 
            {
                "2026-02-12": 10
            }
            """
            if scan.created_at.date() not in scans_per_day:
                scans_per_day[scan.created_at.date()] = 0
            scans_per_day[scan.created_at.date()] += 1
                
        
        
        
        card_data = {
            "pending_scans": pending_scans,
            "started_scans": started_scans,
            "success_scans": success_scans,
            "failure_scans": failure_scans,
            "not_started_scans": not_started_scans,
            "scans_created_today": scans_created_today,
            "scans_updated_today": scans_updated_today
        }

        return {
            "card_data": card_data,
            "repos_scanned": list(set(repos_scanned)),
            "zip_files_scanned": zip_files_scanned,
            "scans_per_day": scans_per_day,
            "risks_per_day": risks_per_day,
        }
    except Exception as e:
        console.print(f"Error in generating card data for sast list: {e}",style="bold red")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error in generating card data for sast list, please try again later")

