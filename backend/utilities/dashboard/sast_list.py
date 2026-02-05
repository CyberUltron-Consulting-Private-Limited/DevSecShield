from backend.new_models import Scan
from datetime import datetime , timezone
from rich.console import Console
from fastapi import HTTPException , status

console = Console()
def generate_card_data_for_sast_list(scans: list[Scan]) -> dict:
    """
    Generate card data for a list of SAST scans.
    Arguments :
    - scans : list[Scan]
    Returns :
    - dict
    """
    try:
        pending_scans , started_scans , success_scans , failure_scans , scans_created_today , scans_updated_today = 0 , 0 , 0 , 0 , 0 , 0
        for scan in scans:
            if scan.scan_status == "pending":
                pending_scans += 1
            elif scan.scan_status == "started":
                started_scans += 1
            elif scan.scan_status == "success":
                success_scans += 1
            elif scan.scan_status == "failure":
                failure_scans += 1
            if scan.created_at.date() == datetime.now(timezone.utc).date():
                scans_created_today += 1
            if scan.last_updated.date() == datetime.now(timezone.utc).date():
                scans_updated_today += 1
        return {
            "pending_scans": pending_scans,
            "started_scans": started_scans,
            "success_scans": success_scans,
            "failure_scans": failure_scans,
            "scans_created_today": scans_created_today,
            "scans_updated_today": scans_updated_today
        }
    except Exception as e:
        console.print(f"Error in generating card data for sast list: {e}",style="bold red")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error in generating card data for sast list, please try again later")