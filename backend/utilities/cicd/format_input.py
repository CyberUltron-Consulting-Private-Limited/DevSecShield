from backend.new_models import scan_types
from fastapi import UploadFile, HTTPException, status
from backend.utilities.db.s3_utils import upload_file
from io import BytesIO
from rich.console import Console
from backend.utilities.scan.sanitize_path_patterns import sanitize_path_patterns
console = Console()

# SECURITY: Maximum upload size (50MB)
MAX_UPLOAD_SIZE_BYTES = 50 * 1024 * 1024  # 50MB

# SECURITY: Valid zip magic bytes
ZIP_MAGIC_BYTES = [
    b'PK\x03\x04',  # Standard zip file  
    b'PK\x05\x06',  # Empty zip archive
    b'PK\x07\x08',  # Spanned zip archive
]


async def validate_zip_file(uploaded_file: UploadFile) -> bytes:
    """
    SECURITY: Validate uploaded file is a legitimate zip file.
    
    Checks:
    1. File extension is .zip
    2. File size within limits
    3. Magic bytes indicate ZIP format
    
    Returns file content as bytes if valid.
    Raises HTTPException if invalid.
    """
    # Check 1: Filename extension
    if uploaded_file.filename:
        if not uploaded_file.filename.lower().endswith('.zip'):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid file type. Only .zip files are accepted."
            )
    
    # Read file content
    file_content = await uploaded_file.read()
    
    # Check 2: File size
    if len(file_content) > MAX_UPLOAD_SIZE_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"File too large. Maximum size is {MAX_UPLOAD_SIZE_BYTES // (1024*1024)}MB."
        )
    
    # Check 3: Magic bytes verification
    if len(file_content) < 4:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid zip file: file too small"
        )
    
    file_header = file_content[:4]
    is_valid_zip = any(file_header.startswith(magic[:len(file_header)]) for magic in ZIP_MAGIC_BYTES)
    
    if not is_valid_zip:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid zip file: file does not have valid ZIP signature"
        )
    
    console.print(f"Zip file validated: {uploaded_file.filename}, size={len(file_content)} bytes", style="bold green")
    return file_content


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

        # SECURITY: Validate zip file before processing
        if uploaded_file is None:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No file uploaded")
        
        validated_file_content = await validate_zip_file(uploaded_file)
        bytes_io_zip_file_object = BytesIO(validated_file_content)
        
        s3_upload_response = upload_file(bytes_io_zip_file_object)
        if not s3_upload_response:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to upload file to storage")
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
            case "cbom":
                cbom_scan_settings: dict | None = scan_settings.get("cbom") if scan_settings else None
                cicd_kwargs["scan_binaries"] = cbom_scan_settings.get("scan_binaries", False) if cbom_scan_settings else False
                
                console.print(f"Cicd kwargs assembled successfully: {cicd_kwargs}",style="dim bold yellow")
                return cicd_kwargs

                
    except Exception as e:
        console.print(f"Error in format_cicd_input: {e}",style="bold red")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Error in format_cicd_input: {e}")