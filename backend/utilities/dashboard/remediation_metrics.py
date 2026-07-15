from backend.mongo_models import ScanFindings
from datetime import timedelta, datetime, timezone
from rich.console import Console

console = Console()


def _ensure_utc(dt: datetime | None) -> datetime | None:
    """Normalize datetime to UTC-aware. Handles naive datetimes by assuming UTC."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


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
    seven_days_ago = datetime.now(timezone.utc).date() - timedelta(days=7)

    for finding in findings:
        finding_status = finding.get("finding_status", "not_started")
        finding_data = finding.get("finding_data", {})
        impact = finding_data.get("impact", "").lower() if finding_data.get("impact") else ""
        created_at = _ensure_utc(finding.get("created_at"))

        # High priority backlog: Critical/High findings that are NOT yet fixed or ignored
        if impact in ("critical", "high") and finding_status not in ("fixed", "ignored"):
            high_priority_backlog += 1

        # Metrics for resolved findings (fixed or ignored)
        if finding_status == "fixed":
            fixed_at = _ensure_utc(finding.get("fixed_at"))
            time_delta = (fixed_at - created_at) if (fixed_at and created_at) else None

            # Critical issues fixed
            if impact == "critical":
                critical_issues_fixed += 1

            # MTTR: time from creation to fix
            if time_delta is not None:
                array_of_time_deltas.append(time_delta)

            # Remediation velocity: fixed in the past 7 days
            if fixed_at and fixed_at.date() >= seven_days_ago:
                remediation_velocity += 1

        elif finding_status == "ignored":
            ignored_at = _ensure_utc(finding.get("ignored_at"))
            time_delta = (ignored_at - created_at) if (ignored_at and created_at) else None

            # MTTR: time from creation to ignore (also counts as resolution)
            if time_delta is not None:
                array_of_time_deltas.append(time_delta)

            # Remediation velocity: ignored in the past 7 days
            if ignored_at and ignored_at.date() >= seven_days_ago:
                remediation_velocity += 1

    # calculating mean time to remediate 
    if len(array_of_time_deltas) > 0:
        sum_of_time_deltas = sum(array_of_time_deltas, timedelta())
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

