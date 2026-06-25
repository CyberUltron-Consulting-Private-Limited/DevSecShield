import json
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
        # I-7 residual: a syntactically-valid payload that omits the requested scan-type's
        # config (e.g. {"foo":1}, {}, {"ai_bom":null}) passes Pydantic (all fields Optional)
        # but would then dereference None below -> opaque 500. Return a clean 400 instead.
        # Sentinel distinguishes "field absent on the model" (don't guard) from "field is None".
        _typed_payload = getattr(start_scan_payload, scan_type, "__field_absent__")
        if _typed_payload is None:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Payload is missing the '{scan_type}' configuration for this scan type")
        match scan_type:

            
            case "sast":
                if start_scan_payload.sast.zip_file_used:
                    if uploaded_file is None:
                        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="uploaded file is required")
                    uploaded_file_bytes = await uploaded_file.read()
                    if len(uploaded_file_bytes) == 0:
                        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="uploaded file is empty")
                    if len(uploaded_file_bytes) > 50 * 1024 * 1024:
                        raise HTTPException(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail="uploaded file too large (max 50MB)")
                    bytes_io_zip_file_object = BytesIO(uploaded_file_bytes)
                    s3_upload_response = upload_file(bytes_io_zip_file_object)
                    if not s3_upload_response:
                        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to upload file to storage")
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
                    if uploaded_file is None:
                        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="uploaded file is required")
                    uploaded_file_bytes = await uploaded_file.read()
                    if len(uploaded_file_bytes) == 0:
                        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="uploaded file is empty")
                    if len(uploaded_file_bytes) > 50 * 1024 * 1024:
                        raise HTTPException(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail="uploaded file too large (max 50MB)")
                    bytes_io_zip_file_object = BytesIO(uploaded_file_bytes)
                    s3_upload_response = upload_file(bytes_io_zip_file_object)
                    if not s3_upload_response:
                        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to upload file to storage")
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
                    if uploaded_file is None:
                        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="uploaded file is required")
                    uploaded_file_bytes = await uploaded_file.read()
                    if len(uploaded_file_bytes) == 0:
                        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="uploaded file is empty")
                    if len(uploaded_file_bytes) > 50 * 1024 * 1024:
                        raise HTTPException(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail="uploaded file too large (max 50MB)")
                    bytes_io_zip_file_object = BytesIO(uploaded_file_bytes)
                    s3_upload_response = upload_file(bytes_io_zip_file_object, extension=".json")
                    if not s3_upload_response:
                        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to upload file to storage")
                    zip_context = {
                        "bucket_name": s3_upload_response["bucket"],
                        "object_name": s3_upload_response["object_name"],
                    }
                    scan_kwargs["zip_dict_context"] = zip_context
                elif start_scan_payload.sbom_sca.repo_context:
                    scan_kwargs["repo_dict_context"] = start_scan_payload.sbom_sca.repo_context.model_dump()
                elif start_scan_payload.sbom_sca.sbom_file_used:
                    if uploaded_file is None:
                        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="uploaded file is required")
                    uploaded_file_bytes = await uploaded_file.read()
                    if len(uploaded_file_bytes) == 0:
                        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="uploaded file is empty")
                    if len(uploaded_file_bytes) > 50 * 1024 * 1024:
                        raise HTTPException(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail="uploaded file too large (max 50MB)")
                    try:
                        json.loads(uploaded_file_bytes)
                    except Exception:
                        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="uploaded file is not valid JSON")
                    bytes_io_sbom_file_object = BytesIO(uploaded_file_bytes)
                    s3_upload_response = upload_file(bytes_io_sbom_file_object, extension=".json")
                    if not s3_upload_response:
                        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to upload file to storage")
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
            
            case "cbom":
                if start_scan_payload.cbom.zip_file_used:
                    if uploaded_file is None:
                        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="uploaded file is required")
                    uploaded_file_bytes = await uploaded_file.read()
                    if len(uploaded_file_bytes) == 0:
                        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="uploaded file is empty")
                    if len(uploaded_file_bytes) > 50 * 1024 * 1024:
                        raise HTTPException(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail="uploaded file too large (max 50MB)")
                    bytes_io_zip_file_object = BytesIO(uploaded_file_bytes)
                    s3_upload_response = upload_file(bytes_io_zip_file_object)
                    if not s3_upload_response:
                        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to upload file to storage")
                    zip_context = {
                        "bucket_name": s3_upload_response["bucket"],
                        "object_name": s3_upload_response["object_name"],
                    }
                    scan_kwargs["zip_dict_context"] = zip_context
                elif start_scan_payload.cbom.repo_context:
                    scan_kwargs["repo_dict_context"] = start_scan_payload.cbom.repo_context.model_dump()
                elif start_scan_payload.cbom.cbom_file_used:
                    if uploaded_file is None:
                        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="uploaded file is required")
                    uploaded_file_bytes = await uploaded_file.read()
                    if len(uploaded_file_bytes) == 0:
                        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="uploaded file is empty")
                    if len(uploaded_file_bytes) > 50 * 1024 * 1024:
                        raise HTTPException(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail="uploaded file too large (max 50MB)")
                    try:
                        cbom_parsed = json.loads(uploaded_file_bytes)
                    except Exception:
                        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="uploaded file is not valid JSON")
                    if not isinstance(cbom_parsed, dict) or cbom_parsed.get("bomFormat") != "CycloneDX":
                        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="uploaded file is not a valid CycloneDX BOM")
                    bytes_io_cbom_file_object = BytesIO(uploaded_file_bytes)
                    s3_upload_response = upload_file(bytes_io_cbom_file_object, extension=".json")
                    if not s3_upload_response:
                        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to upload file to storage")
                    file_context = {
                        "bucket_name": s3_upload_response["bucket"],
                        "object_name": s3_upload_response["object_name"],
                    }
                    scan_kwargs["file_dict_context"] = file_context
                else:
                    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No zip file or repo context or CBOM file provided")
                scan_kwargs["scan_binaries"] = start_scan_payload.cbom.scan_binaries
                console.print(f"CBOM kwargs: {scan_kwargs} assembled successfully", style="dim bright_cyan")
                return scan_kwargs

            case "ai_bom":
                if start_scan_payload.ai_bom.zip_file_used:
                    if uploaded_file is None:
                        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="uploaded file is required")
                    uploaded_file_bytes = await uploaded_file.read()
                    if len(uploaded_file_bytes) == 0:
                        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="uploaded file is empty")
                    if len(uploaded_file_bytes) > 50 * 1024 * 1024:
                        raise HTTPException(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail="uploaded file too large (max 50MB)")
                    bytes_io_zip_file_object = BytesIO(uploaded_file_bytes)
                    s3_upload_response = upload_file(bytes_io_zip_file_object)
                    if not s3_upload_response:
                        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to upload file to storage")
                    zip_context = {
                        "bucket_name": s3_upload_response["bucket"],
                        "object_name": s3_upload_response["object_name"],
                    }
                    scan_kwargs["zip_dict_context"] = zip_context
                elif start_scan_payload.ai_bom.repo_context:
                    scan_kwargs["repo_dict_context"] = start_scan_payload.ai_bom.repo_context.model_dump()
                elif start_scan_payload.ai_bom.ai_bom_file_used:
                    if uploaded_file is None:
                        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="uploaded file is required")
                    uploaded_file_bytes = await uploaded_file.read()
                    if len(uploaded_file_bytes) == 0:
                        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="uploaded file is empty")
                    if len(uploaded_file_bytes) > 50 * 1024 * 1024:
                        raise HTTPException(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail="uploaded file too large (max 50MB)")
                    try:
                        ai_bom_parsed = json.loads(uploaded_file_bytes)
                    except Exception:
                        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="uploaded file is not valid JSON")
                    if not isinstance(ai_bom_parsed, dict) or ai_bom_parsed.get("bomFormat") != "CycloneDX":
                        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="not a valid CycloneDX BOM")
                    bytes_io_ai_bom_file_object = BytesIO(uploaded_file_bytes)
                    s3_upload_response = upload_file(bytes_io_ai_bom_file_object, extension=".json")
                    if not s3_upload_response:
                        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to upload file to storage")
                    file_context = {
                        "bucket_name": s3_upload_response["bucket"],
                        "object_name": s3_upload_response["object_name"],
                    }
                    scan_kwargs["file_dict_context"] = file_context
                else:
                    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No zip file or repo context or AI-BOM file provided")
                scan_kwargs["scan_binaries"] = start_scan_payload.ai_bom.scan_binaries
                console.print(f"AI-BOM kwargs: {scan_kwargs} assembled successfully", style="dim bright_cyan")
                return scan_kwargs

            case _:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid scan type")
                
    
    except Exception as e:
        console.print(f"Error in format_input_for_scan: {str(e)}", style="bold red")
        raise e