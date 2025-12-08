from rich.console import Console
from fastapi import HTTPException, status

console = Console()

def create_export_results(scan_data:dict):
    """
    This function creates the export results for a SAST scan conversation.
    """
    try:
        # STEP [ 1 ] : ======================= Create the export results for the conversation ========================================
        export_results = {
            "scan_data": scan_data
        }
        return export_results
    except Exception as e:
        console.print(f"Error in create_export_results: {e}",style="bold red")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error in creating export results , please try again later")