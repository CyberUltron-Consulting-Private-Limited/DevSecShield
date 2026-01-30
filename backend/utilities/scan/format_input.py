from backend.utilities.db.schemas import StartScanPayload
from backend.new_models import scan_types
from fastapi import UploadFile
from rich.console import Console

console = Console()

def format_input_for_scan(
    scan_type: scan_types,
    start_scan_payload: StartScanPayload,
    uploaded_file: UploadFile | None = None, ):
    """
    Assemble kwargs dict to pass to the celery worker for the scan type specified
    """
    try:
        # TODO 
        pass


    except Exception as e:
        console.print(f"Error in format_input_for_scan: {str(e)}", style="bold red")
        raise e