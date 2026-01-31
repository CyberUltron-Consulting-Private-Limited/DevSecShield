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
                "app_lang": start_scan_payload.sast.app_lang,
                "exclude_path_arrays": start_scan_payload.sast.exclude_path_arrays,
            }
        case "iac":
            return {
                "zip_file_used": start_scan_payload.iac.zip_file_used,
                "repo_url": start_scan_payload.iac.repo_context.repo_url if start_scan_payload.iac.repo_context else None,
                "repo_type": start_scan_payload.iac.repo_context.mode if start_scan_payload.iac.repo_context else None,
                "iac_contexts": [iac_context.model_dump() for iac_context in start_scan_payload.iac.iac_contexts],
            }
        case "sbom_sca":
            return {
                "zip_file_used": start_scan_payload.sbom_sca.zip_file_used,
                "repo_url": start_scan_payload.sbom_sca.repo_context.repo_url if start_scan_payload.sbom_sca.repo_context else None,
                "repo_type": start_scan_payload.sbom_sca.repo_context.mode if start_scan_payload.sbom_sca.repo_context else None,
                "sbom_file_used": start_scan_payload.sbom_sca.sbom_file_used,
            }
        case _:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid scan type")