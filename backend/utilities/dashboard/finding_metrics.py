from collections import defaultdict
from backend.mongo_models import ScanFindings
from rich.console import Console

console = Console()
    
def get_issue_status_metrics(findings: list[ScanFindings]) -> dict:
    """
    Data will look like this : 
    {
        "fixed": 10,
        "ignored": 5,
        "in_progress": 3,
        "not_started": 2
    }
    """
    fixed,ignored,in_progress,not_started = 0,0,0,0
    for finding in findings:
        if finding["finding_status"] == "fixed":
            fixed += 1
        elif finding["finding_status"] == "ignored":
            ignored += 1
        elif finding["finding_status"] == "in_progress":
            in_progress += 1
        elif finding["finding_status"] == "not_started":
            not_started += 1
    return {
        "fixed": fixed,
        "ignored": ignored,
        "in_progress": in_progress,
        "not_started": not_started
    }


def get_issue_address_metrics(findings: list[ScanFindings]) -> dict:
    """
    Data will look like this : 
    {
        "finding_title" : [1,23,0]  ,
        "finding_title2" : [3,0,0] ,
        "finding_title3" : [43,0,0] ,
    }
    Calculated in [ days , hours , minutes ]
    """
    
    issue_address_metrics = defaultdict(list)
    for finding in findings:
        if finding["finding_status"] == "fixed":
            time_delta = finding["fixed_at"] - finding["created_at"]
            time_delta_days = time_delta.days
            time_delta_hours = time_delta.seconds // 3600
            time_delta_minutes = time_delta.seconds % 3600 // 60
            issue_address_metrics[finding["finding_data"]["title"]] = [ time_delta_days, time_delta_hours, time_delta_minutes ]
        elif finding["finding_status"] == "ignored":
            time_delta = finding["ignored_at"] - finding["created_at"]
            time_delta_days = time_delta.days
            time_delta_hours = time_delta.seconds // 3600
            time_delta_minutes = time_delta.seconds % 3600 // 60
            issue_address_metrics[finding["finding_data"]["title"]] = [ time_delta_days, time_delta_hours, time_delta_minutes ]
        else:
            issue_address_metrics[finding["finding_data"]["title"]] = [ 0, 0, 0 ]
    

    console.print(f"Issue address metrics : {issue_address_metrics}")
    return issue_address_metrics