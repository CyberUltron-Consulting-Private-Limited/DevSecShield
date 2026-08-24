from backend.new_models import scan_types
from backend.utilities.db.schemas import StartScanPayload
from fastapi import HTTPException, status

def get_scan_metadata_for_type(scan_type: scan_types , start_scan_payload: StartScanPayload) -> dict:
    """
    Given a scan type and scan start data, return the scan metadata.
    Arguments :
    - type : scan_types
    - scan_start_data : dict | None
    Returns :
    -  dict ( scan metadata )
    
    """
    match scan_type:
        case "sast":
            return {
                "zip_file_used": start_scan_payload.sast.zip_file_used,
                "repo_url": start_scan_payload.sast.repo_context.repo_url if start_scan_payload.sast.repo_context else None,
                "repo_type": start_scan_payload.sast.repo_context.mode if start_scan_payload.sast.repo_context else None,
                "branch": start_scan_payload.sast.repo_context.branch if start_scan_payload.sast.repo_context else None,
                "app_lang": start_scan_payload.sast.app_lang,
                "exclude_path_arrays": start_scan_payload.sast.exclude_path_arrays,
            }
        case "iac":
            return {
                "zip_file_used": start_scan_payload.iac.zip_file_used,
                "repo_url": start_scan_payload.iac.repo_context.repo_url if start_scan_payload.iac.repo_context else None,
                "repo_type": start_scan_payload.iac.repo_context.mode if start_scan_payload.iac.repo_context else None,
                "branch": start_scan_payload.iac.repo_context.branch if start_scan_payload.iac.repo_context else None,
                "environment": start_scan_payload.iac.environment if start_scan_payload.iac.environment else "development",
                "iac_contexts": [iac_context.model_dump() for iac_context in start_scan_payload.iac.iac_contexts],
            }
        case "sbom_sca":
            return {
                "zip_file_used": start_scan_payload.sbom_sca.zip_file_used,
                "repo_url": start_scan_payload.sbom_sca.repo_context.repo_url if start_scan_payload.sbom_sca.repo_context else None,
                "repo_type": start_scan_payload.sbom_sca.repo_context.mode if start_scan_payload.sbom_sca.repo_context else None,
                "branch": start_scan_payload.sbom_sca.repo_context.branch if start_scan_payload.sbom_sca.repo_context else None,
                "sbom_file_used": start_scan_payload.sbom_sca.sbom_file_used,
            }
        case "mcp":
            return {
                "server_url": start_scan_payload.mcp.server_url,
                "server_mode": start_scan_payload.mcp.server_mode,
                "headers": start_scan_payload.mcp.headers,
                "environment": start_scan_payload.mcp.environment if start_scan_payload.mcp.environment else "development",
            }
        case "llm":
            return {
                "model_type": start_scan_payload.llm.model_type,
                "model_name": start_scan_payload.llm.model_name,
                "generations": start_scan_payload.llm.generations,
                "probes": start_scan_payload.llm.probes,
            }
        case "dast":
            auth = start_scan_payload.dast.auth.model_dump()
            auth.pop("password", None)
            return {
                "target_url": start_scan_payload.dast.target_url,
                "auth": auth,
                "scan_speed": start_scan_payload.dast.scan_speed,
                "max_urls": start_scan_payload.dast.max_urls,
                "additional_urls_to_scan": start_scan_payload.dast.additional_urls_to_scan,
                "exclude_url_patterns": start_scan_payload.dast.exclude_url_patterns,
                "include_url_patterns": start_scan_payload.dast.include_url_patterns,
            }
        case "cbom":
            return {
                "zip_file_used": start_scan_payload.cbom.zip_file_used,
                "repo_url": start_scan_payload.cbom.repo_context.repo_url if start_scan_payload.cbom.repo_context else None,
                "repo_type": start_scan_payload.cbom.repo_context.mode if start_scan_payload.cbom.repo_context else None,
                "branch": start_scan_payload.cbom.repo_context.branch if start_scan_payload.cbom.repo_context else None,
                "cbom_file_used": start_scan_payload.cbom.cbom_file_used,
                "scan_binaries": start_scan_payload.cbom.scan_binaries,
            }
        case "ai_bom":
            return {
                "zip_file_used": start_scan_payload.ai_bom.zip_file_used,
                "repo_url": start_scan_payload.ai_bom.repo_context.repo_url if start_scan_payload.ai_bom.repo_context else None,
                "repo_type": start_scan_payload.ai_bom.repo_context.mode if start_scan_payload.ai_bom.repo_context else None,
                "branch": start_scan_payload.ai_bom.repo_context.branch if start_scan_payload.ai_bom.repo_context else None,
                "ai_bom_file_used": start_scan_payload.ai_bom.ai_bom_file_used,
                "scan_binaries": start_scan_payload.ai_bom.scan_binaries,
            }
        case _:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid scan type")