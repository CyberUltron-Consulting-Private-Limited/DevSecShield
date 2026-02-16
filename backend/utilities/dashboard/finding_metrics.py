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
    

   
    return issue_address_metrics


def get_mttr_per_day(findings: list[ScanFindings]) -> dict[str, list[int]]:
    """
    Mean time to remediate per day (by fixed_at date).
    Returns: { "2026-01-01": [days, hours, minutes], ... }
    Only includes findings that are fixed or ignored; each date's value is the average MTTR for findings resolved on that day.
    """
    from collections import defaultdict
    from datetime import timedelta

    by_date: dict[str, list[timedelta]] = defaultdict(list)
    for finding in findings:
        if finding["finding_status"] == "fixed" and finding.get("fixed_at"):
            delta = finding["fixed_at"] - finding["created_at"]
            date_key = str(finding["fixed_at"].date())
            by_date[date_key].append(delta)
        elif finding["finding_status"] == "ignored" and finding.get("ignored_at"):
            delta = finding["ignored_at"] - finding["created_at"]
            date_key = str(finding["ignored_at"].date())
            by_date[date_key].append(delta)

    result: dict[str, list[int]] = {}
    for date_key, deltas in by_date.items():
        if not deltas:
            continue
        total = deltas[0]
        for d in deltas[1:]:
            total += d
        avg = total / len(deltas)
        result[date_key] = [
            avg.days,
            avg.seconds // 3600,
            avg.seconds % 3600 // 60,
        ]
    return result