"""Mobile App Security PDF — reuses DAST report layout for findings lists."""

from datetime import datetime
from typing import Any

from backend.utilities.pdf.dast_pdf import generate_pdf as generate_pdf_for_dast


def generate_pdf(scan_data: Any, output_path: str | None = None) -> str:
    if output_path is None:
        output_path = f"mobile_scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"

    if isinstance(scan_data, dict):
        findings = scan_data.get("results") or []
    elif isinstance(scan_data, list):
        findings = scan_data
    else:
        findings = []

    adapted = []
    for f in findings:
        if not isinstance(f, dict):
            continue
        adapted.append({
            "title": f.get("title", "Finding"),
            "url": f.get("location") or f.get("file_path") or f.get("category") or "-",
            "confidence": "high",
            "impact": f.get("impact") or "Low",
            "category": f.get("category") or "mobile",
            "description": f.get("description") or "",
            "suggested_fix": f.get("suggested_fix") or "",
            "owasp_top_10": f.get("owasp_top_10") or {},
            "compliance_controls": f.get("compliance_controls") or {},
        })

    return generate_pdf_for_dast(
        adapted,
        output_path,
        report_title="Mobile App Security Scan Report",
        report_subtitle="Static Mobile Application Security Analysis",
    )
