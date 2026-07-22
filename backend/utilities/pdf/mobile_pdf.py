"""Mobile App Security PDF — reuses DAST report layout for findings lists."""

from datetime import datetime
from typing import Any

from backend.utilities.mobile.sanitize import compliance_controls_for_display, sanitize_mobile_finding
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
        clean = sanitize_mobile_finding(f)
        adapted.append({
            "title": clean.get("title", "Finding"),
            "url": clean.get("location") or clean.get("file_path") or clean.get("category") or "-",
            "confidence": "high",
            "impact": clean.get("impact") or "Low",
            "category": clean.get("category") or "mobile",
            "description": clean.get("description") or "",
            "suggested_fix": clean.get("suggested_fix") or "",
            "owasp_top_10": clean.get("owasp_top_10") or {},
            "compliance_controls": compliance_controls_for_display(clean.get("compliance_controls")),
        })

    return generate_pdf_for_dast(
        adapted,
        output_path,
        report_title="Mobile App Security Scan Report",
        report_subtitle="Static Mobile Application Security Analysis",
    )
