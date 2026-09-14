import os

from backend.new_models import scan_types
from backend.utilities.pdf.sast_pdf import generate_pdf as generate_pdf_for_sast
from backend.utilities.pdf.iac_pdf import generate_pdf as generate_pdf_for_iac
from backend.utilities.pdf.sbom_sca_pdf import generate_pdf as generate_pdf_for_sbom_sca
from backend.utilities.pdf.mcp_pdf import generate_pdf as generate_pdf_for_mcp
from backend.utilities.pdf.llm_pdf import generate_pdf as generate_pdf_for_llm
from backend.utilities.pdf.dast_pdf import generate_pdf as generate_pdf_for_dast
from backend.utilities.pdf.cbom_pdf import generate_pdf as generate_pdf_for_cbom
from backend.utilities.pdf.ai_bom_pdf import generate_pdf as generate_pdf_for_ai_bom
from backend.utilities.pdf.report_branding import with_scan_duration

_BOM_EXPORT_TYPES = ("ai_bom", "cbom", "sbom_sca")
_BOM_PAYLOAD_KEYS = (
    "results",
    "duration_of_scan",
    "matches",
    "ai_bom_compliance",
    "cbom_compliance",
    "sbom_compliance",
    "rbi_csf_rollup",
    "rbi_compliance",
)
_DAST_METADATA_KEYS = ("urls_included", "urls_excluded")


class UnsupportedPdfExport(Exception):
    """Scan type has no branded PDF renderer (leakage / agent_discovery)."""


def prepare_pdf_export_payload(scan_type: str, scan_data: dict | list | None) -> dict | list:
    """Allowlisted export payload: findings + duration + BOM appendix keys.

    DAST keeps URL counts from metadata. BOM keeps compliance blobs for the
    RBI/CERT-In appendix. Side-channel keys (raw BOM JSON, debug dumps, secrets
    in metadata) are dropped.
    """
    if not isinstance(scan_data, dict):
        return scan_data if scan_data is not None else {}
    if scan_type in _BOM_EXPORT_TYPES:
        return {key: scan_data[key] for key in _BOM_PAYLOAD_KEYS if key in scan_data}
    payload: dict = {"results": scan_data.get("results")}
    worker_duration = scan_data.get("duration_of_scan")
    if worker_duration not in (None, ""):
        payload["duration_of_scan"] = worker_duration
    if scan_type == "dast":
        metadata = scan_data.get("metadata")
        if isinstance(metadata, dict):
            allowed = {key: metadata[key] for key in _DAST_METADATA_KEYS if key in metadata}
            if allowed:
                payload["metadata"] = allowed
    return payload


def _safe_unlink(path: str) -> None:
    try:
        os.unlink(path)
    except OSError:
        pass


def write_scan_pdf(
    type: scan_types,
    scan_data: dict | list,
    output_path: str,
    started_at=None,
    completed_at=None,
):
    """Build a PDF and delete the temp file if the renderer fails."""
    try:
        return generate_pdf_for_type(
            type,
            scan_data,
            output_path,
            started_at=started_at,
            completed_at=completed_at,
        )
    except Exception:
        _safe_unlink(output_path)
        raise


def generate_pdf_for_type(
    type: scan_types,
    scan_data: dict | list,
    output_path: str,
    started_at=None,
    completed_at=None,
):
    """
    This function generates a pdf for a given scan type.

    started_at / completed_at are the scan-row timestamps used as a
    duration fallback when the payload has no duration_of_scan.
    """
    scan_data = with_scan_duration(scan_data, started_at, completed_at)
    match type:
        case "sast":
            return generate_pdf_for_sast(scan_data, output_path)
        case "iac":
            return generate_pdf_for_iac(scan_data, output_path)
        case "sbom_sca":
            return generate_pdf_for_sbom_sca(scan_data, output_path)
        case "mcp":
            return generate_pdf_for_mcp(scan_data, output_path)
        case "llm":
            return generate_pdf_for_llm(scan_data, output_path)
        case "dast":
            return generate_pdf_for_dast(scan_data, output_path)
        case "cbom":
            return generate_pdf_for_cbom(scan_data, output_path)
        case "ai_bom":
            return generate_pdf_for_ai_bom(scan_data, output_path)
        case _:
            # Branded export covers the eight types above; the export route maps this to 400.
            raise UnsupportedPdfExport(
                f"PDF export is not supported for scan type {type!r}"
            )
