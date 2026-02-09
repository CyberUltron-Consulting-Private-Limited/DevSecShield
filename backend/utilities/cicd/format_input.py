from backend.new_models import scan_types
from fastapi import UploadFile, HTTPException, status
from backend.utilities.db.s3_utils import upload_file
from io import BytesIO
from rich.console import Console
from backend.utilities.scan.sanitize_path_patterns import sanitize_path_patterns
console = Console()

async def format_cicd_input(
    scan_settings : dict , 
    scan_type : str , 
    uploaded_file: UploadFile | None = None,
) -> dict:
    """
    Format the input for the cicd scan
    """
    try:
        cicd_kwargs = {}

        bytes_io_zip_file_object = BytesIO(await uploaded_file.read())
        s3_upload_response = upload_file(bytes_io_zip_file_object)
        zip_context = {
            "bucket_name": s3_upload_response["bucket"],
            "object_name": s3_upload_response["object_name"],
        }
        cicd_kwargs["zip_dict_context"] = zip_context

        match scan_type:
            case "sast":
                sast_scan_settings : dict | None = scan_settings.get("sast")
                if sast_scan_settings is None:
                    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Sast scan settings not found")
                cicd_kwargs["app_lang"] = sast_scan_settings.get("app_lang")
                cicd_kwargs["exclude_path_arrays"] = sanitize_path_patterns(sast_scan_settings.get("exclude_path_arrays")) if sast_scan_settings.get("exclude_path_arrays") else None
                
                console.print(f"Cicd kwargs assembled successfully: {cicd_kwargs}",style="dim bold yellow")
                return cicd_kwargs

                
    except Exception as e:
        console.print(f"Error in format_cicd_input: {e}",style="bold red")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Error in format_cicd_input: {e}")