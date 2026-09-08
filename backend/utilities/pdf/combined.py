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



def generate_pdf_for_type(
    type: scan_types ,
    scan_data: dict ,
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
