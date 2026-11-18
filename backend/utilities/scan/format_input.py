import asyncio
import json
from backend.utilities.db.schemas import StartScanPayload
from backend.new_models import scan_types
from fastapi import UploadFile, HTTPException, status
from backend.utilities.db.s3_utils import upload_file
from io import BytesIO
from rich.console import Console
from backend.utilities.scan.sanitize_path_patterns import sanitize_path_patterns
from backend.utilities.dast.ssrf import DastSsrfError, assert_manual_dast_allowed
from backend.utilities.scan.target_address import TargetAddressRefused, check_scan_target
from backend.utilities.log_redaction import redact, redact_secrets, safe_repr
import zipfile
console = Console()


async def _require_public_target(url: str | None, what: str) -> None:
    """#53: an MCP server URL / custom model URI the worker will connect to must resolve to public addresses only
    (target_address.py, the CBOM SSRF guard's rule). Resolved off the event loop."""
    try:
        await asyncio.to_thread(check_scan_target, url, what)
    except TargetAddressRefused as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from None


async def require_public_targets(scan_type: scan_types, start_scan_payload: StartScanPayload) -> None:
    """#53: what an MCP scan (server URL) or a custom LLM scan (model URI) will connect to, as a 400. Run here for every
    estimate, start and reinitialize, and by /start before it charges (a stored estimate is charged before dispatch).
    A vendor model's URI is the worker's own template, not customer input."""
    if scan_type == "mcp" and start_scan_payload.mcp:
        await _require_public_target(start_scan_payload.mcp.server_url, "MCP server URL")
    elif scan_type == "llm" and start_scan_payload.llm and start_scan_payload.llm.model_type == "custom":
        await _require_public_target(start_scan_payload.llm.model_uri, "Model URI")


def _require_zip(data: bytes) -> None:
    """A "zip file" upload must be a zip archive. Round 5, L1: a non-zip file uploaded in zip mode was stored and
    handed to the worker, which failed inside the task ("Error in getting directory from zip context: File is not a
    zip file", e.g. cbom_estimation) instead of the customer being told."""
    if not zipfile.is_zipfile(BytesIO(data)):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="uploaded file is not a zip archive; upload a .zip of the code (or choose the "
                                   "option for a single SBOM / CBOM / AI-BOM file)")

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
                    _require_zip(uploaded_file_bytes)
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
                console.print(f"SAST kwargs: {safe_repr(scan_kwargs)} assembled successfully", style="dim bright_cyan",
                              markup=False)
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
                    _require_zip(uploaded_file_bytes)
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
                console.print(f"IAC kwargs: {safe_repr(scan_kwargs)} assembled successfully", style="dim bright_cyan",
                              markup=False)
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
                    _require_zip(uploaded_file_bytes)
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
                
                console.print(f"SBOM kwargs: {safe_repr(scan_kwargs)} assembled successfully", style="dim bright_cyan",
                              markup=False)
                return scan_kwargs

            case "mcp":
                if not start_scan_payload.mcp:
                    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="MCP context is required")
                await require_public_targets(scan_type, start_scan_payload)
                scan_kwargs["mcp_dict_context"] = start_scan_payload.mcp.model_dump()
                console.print(f"MCP kwargs: {safe_repr(scan_kwargs)} assembled successfully", style="dim bright_cyan",
                              markup=False)
                return scan_kwargs

            case "llm":
                if not start_scan_payload.llm:
                    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="LLM context is required")
                await require_public_targets(scan_type, start_scan_payload)
                scan_kwargs["llm_benchmark_dict_context"] = start_scan_payload.llm.model_dump()
                console.print(f"LLM kwargs: {safe_repr(scan_kwargs)} assembled successfully", style="dim bright_cyan",
                              markup=False)
                return scan_kwargs
            
            case "dast":
                if not start_scan_payload.dast:
                    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="DAST context is required")
                # Manual estimate and start: the profile-scan URL rule (utilities/dast/ssrf.py), before any worker
                # crawls a customer-named URL.
                dast = start_scan_payload.dast
                try:
                    assert_manual_dast_allowed(dast.target_url, dast.auth.login_url if dast.auth else None,
                                               dast.additional_urls_to_scan)
                except DastSsrfError as exc:
                    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from None
                scan_kwargs["dast_dict_context"] = start_scan_payload.dast.model_dump()
                console.print(
                    f"DAST kwargs assembled target={redact_secrets(start_scan_payload.dast.target_url)} "
                    f"max_urls={start_scan_payload.dast.max_urls} (auth redacted)",
                    style="dim bright_cyan", markup=False,
                )
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
                    _require_zip(uploaded_file_bytes)
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
                # Sent only when on: a default scan's kwargs stay what an older worker accepts.
                if start_scan_payload.cbom.include_vendored and not start_scan_payload.cbom.cbom_file_used:
                    scan_kwargs["include_vendored"] = True
                # repository scans only: an uploaded archive's own .git is read by the engine when it is complete
                if start_scan_payload.cbom.scan_history and "repo_dict_context" in scan_kwargs:
                    scan_kwargs["scan_history"] = True
                console.print(f"CBOM kwargs: {safe_repr(scan_kwargs)} assembled successfully", style="dim bright_cyan",
                              markup=False)
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
                    _require_zip(uploaded_file_bytes)
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
                console.print(f"AI-BOM kwargs: {safe_repr(scan_kwargs)} assembled successfully", style="dim bright_cyan",
                              markup=False)
                return scan_kwargs

            case _:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid scan type")
                
    
    except Exception as e:
        console.print(f"Error in format_input_for_scan: {redact(str(e))}", style="bold red", markup=False)
        raise e