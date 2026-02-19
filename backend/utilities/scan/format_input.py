from backend.utilities.db.schemas import StartScanPayload
from backend.new_models import scan_types
from fastapi import UploadFile, HTTPException, status
from backend.utilities.db.s3_utils import upload_file
from io import BytesIO
from rich.console import Console
from backend.utilities.scan.sanitize_path_patterns import sanitize_path_patterns
console = Console()

async def format_input_for_scan(
    scan_type: scan_types,
    start_scan_payload: StartScanPayload,
    uploaded_file: UploadFile | None = None, ):
    """
    Assemble kwargs dict to pass to the celery worker for the scan type specified
    """
    try:
        scan_kwargs = {}
        match scan_type:

            
            case "sast":
                if start_scan_payload.sast.zip_file_used:
                    bytes_io_zip_file_object = BytesIO(await uploaded_file.read())
                    s3_upload_response = upload_file(bytes_io_zip_file_object)
                    zip_context = {
                        "bucket_name": s3_upload_response["bucket"],
                        "object_name": s3_upload_response["object_name"],
                    }
                    scan_kwargs["zip_dict_context"] = zip_context
                elif start_scan_payload.sast.repo_context:
                    scan_kwargs["repo_dict_context"] = start_scan_payload.sast.repo_context.model_dump()
                else:
                    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No zip file or repo context provided")
                scan_kwargs["app_lang"] = start_scan_payload.sast.app_lang

                scan_kwargs["exclude_path_arrays"] = sanitize_path_patterns(start_scan_payload.sast.exclude_path_arrays) if start_scan_payload.sast.exclude_path_arrays else None
                console.print(f"SAST kwargs: {scan_kwargs} assembled successfully", style="dim bright_cyan")
                return scan_kwargs

                

            case "iac":
                if start_scan_payload.iac.zip_file_used:
                    bytes_io_zip_file_object = BytesIO(await uploaded_file.read())
                    s3_upload_response = upload_file(bytes_io_zip_file_object)
                    zip_context = {
                        "bucket_name": s3_upload_response["bucket"],
                        "object_name": s3_upload_response["object_name"],
                    }
                    scan_kwargs["zip_dict_context"] = zip_context
                elif start_scan_payload.iac.repo_context:
                    scan_kwargs["repo_dict_context"] = start_scan_payload.iac.repo_context.model_dump()
                else:
                    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No zip file or repo context provided")
                scan_kwargs["iac_dict_contexts"] = [iac_context.model_dump() for iac_context in start_scan_payload.iac.iac_contexts]
                console.print(f"IAC kwargs: {scan_kwargs} assembled successfully", style="dim bright_cyan")
                return scan_kwargs
                
                


            case "sbom_sca":
                if start_scan_payload.sbom_sca.zip_file_used:
                    bytes_io_zip_file_object = BytesIO(await uploaded_file.read())
                    s3_upload_response = upload_file(bytes_io_zip_file_object, extension=".json")
                    zip_context = {
                        "bucket_name": s3_upload_response["bucket"],
                        "object_name": s3_upload_response["object_name"],
                    }
                    scan_kwargs["zip_dict_context"] = zip_context
                elif start_scan_payload.sbom_sca.repo_context:
                    scan_kwargs["repo_dict_context"] = start_scan_payload.sbom_sca.repo_context.model_dump()
                elif start_scan_payload.sbom_sca.sbom_file_used:
                    bytes_io_sbom_file_object = BytesIO(await uploaded_file.read())
                    s3_upload_response = upload_file(bytes_io_sbom_file_object, extension=".json")
                    file_context = {
                        "bucket_name": s3_upload_response["bucket"],
                        "object_name": s3_upload_response["object_name"],
                    }
                    scan_kwargs["file_dict_context"] = file_context
                else:
                    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No zip file or repo context or sbom file provided")
                
                console.print(f"SBOM kwargs: {scan_kwargs} assembled successfully", style="dim bright_cyan")
                return scan_kwargs

            case "mcp":
                if not start_scan_payload.mcp:
                    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="MCP context is required")
                scan_kwargs["mcp_dict_context"] = start_scan_payload.mcp.model_dump()
                console.print(f"MCP kwargs: {scan_kwargs} assembled successfully", style="dim bright_cyan")
                return scan_kwargs

            case "llm":
                if not start_scan_payload.llm:
                    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="LLM context is required")
                scan_kwargs["llm_benchmark_dict_context"] = start_scan_payload.llm.model_dump()
                console.print(f"LLM kwargs: {scan_kwargs} assembled successfully", style="dim bright_cyan")
                return scan_kwargs
            
            case "dast":
                if not start_scan_payload.dast:
                    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="DAST context is required")
                scan_kwargs["dast_dict_context"] = start_scan_payload.dast.model_dump()
                console.print(f"DAST kwargs: {scan_kwargs} assembled successfully", style="dim bright_cyan")
                return scan_kwargs
            
            case _:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid scan type")
                
    
    except Exception as e:
        console.print(f"Error in format_input_for_scan: {str(e)}", style="bold red")
        raise e