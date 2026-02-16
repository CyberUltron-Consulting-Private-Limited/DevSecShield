from backend.mongo_models import ScanFindings
from datetime import timedelta , datetime , timezone
from rich.console import Console

console = Console()

def get_remediation_metrics(findings: list[ScanFindings]) -> dict:
    """
    Data will look like this : 
    {
        "mean_time_to_remediate": [ days , hours , minutes ], --> Average time taken to remediate an issue 
        "critical_issues_fixed": 0, --> Number of critical issues fixed 
        "remediation_velocity": 0, --> number of issues fixed in the past 7 days 
        "high_priority_backlog": 0, --> Number of issues with high priority ( Critical and High ) that are not fixed yet
    }
    """
    mean_time_to_remediate , critical_issues_fixed , remediation_velocity , high_priority_backlog = 0,0,0,0

    array_of_time_deltas : list[timedelta] = []

    for finding in findings:
        if finding["finding_status"] == "fixed" :
            time_delta = finding["fixed_at"] - finding["created_at"]
            
            # critical issues fixed 
            if finding["finding_data"]["impact"].lower() == "critical":
                critical_issues_fixed += 1
            
            # calculating high priority backlog
            if (finding["finding_data"]["impact"].lower() == "critical" or finding["finding_data"]["impact"].lower() == "high") and finding["finding_status"] not in ["fixed", "ignored"]:
                high_priority_backlog += 1

            # for calculating mean time to remediate 
            if finding["finding_status"] in ["fixed", "ignored"]:
                array_of_time_deltas.append(time_delta)
            

            # calculating remediation velocity
            if finding["finding_status"] in ["fixed","ignored"] and finding["fixed_at"].date() >= (datetime.now(timezone.utc).date() - timedelta(days=7)):
                remediation_velocity += 1
    
        
    # calculating mean time to remediate 
    if len(array_of_time_deltas) > 0:
        sum_of_time_deltas = array_of_time_deltas[0]
        for time_delta in array_of_time_deltas[1:]:
            sum_of_time_deltas += time_delta
        
        mean_time_to_remediate_time_delta : timedelta = sum_of_time_deltas / len(array_of_time_deltas)
        days = mean_time_to_remediate_time_delta.days
        hours = mean_time_to_remediate_time_delta.seconds // 3600
        minutes = mean_time_to_remediate_time_delta.seconds % 3600 // 60
        mean_time_to_remediate = [ days, hours, minutes ]
    else:
        mean_time_to_remediate = [ 0, 0, 0 ]
    

    console.print(f"Mean time to remediate : {mean_time_to_remediate}")

    return {
        "mean_time_to_remediate": mean_time_to_remediate,
        "critical_issues_fixed": critical_issues_fixed,
        "remediation_velocity": remediation_velocity,
        "high_priority_backlog": high_priority_backlog
    }

