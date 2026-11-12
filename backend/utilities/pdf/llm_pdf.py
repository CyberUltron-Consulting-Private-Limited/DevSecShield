"""
LLM Benchmark Scan Results PDF Generator
Human-readable enterprise report from LLM benchmark scan results.
"""

from __future__ import annotations

import json
import os
from datetime import datetime
from typing import Any, Dict, List, Optional

from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch
from reportlab.platypus import PageBreak, Paragraph, SimpleDocTemplate, Spacer

from backend.utilities.pdf.report_branding import (
    append_executive_summary,
    append_findings_catalog,
    build_finding_section,
    count_label,
    escape_html,
    finding_location,
    format_scan_duration,
    get_report_styles,
    make_cover_callback,
    make_footer_callback,
    mapping_rows,
    severity_color,
    split_scan_payload,
)


def _normalize_vulnerabilities(scan_results: Any) -> List[Dict[str, Any]]:
    """Accept list of vulns or dict with 'vulnerabilities' key."""
    inner, _duration, _raw = split_scan_payload(scan_results)
    if inner is None:
        return []
    if isinstance(inner, list):
        return inner if all(isinstance(x, dict) for x in inner) else []
    if isinstance(inner, dict) and "vulnerabilities" in inner:
        v = inner["vulnerabilities"]
        return v if isinstance(v, list) else []
    return []


def get_severity_color(impact: str):
    return severity_color(impact)


def generate_pdf(scan_results: Any, output_path: Optional[str] = None) -> str:
    """
    Generate a PDF report from LLM benchmark scan results.
    scan_results: list of vulnerability dicts, or dict with "vulnerabilities" key.
    """
    if output_path is None:
        output_path = f"llm_scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"

    vulnerabilities = _normalize_vulnerabilities(scan_results)
    _inner, duration, _raw = split_scan_payload(scan_results)
    total = len(vulnerabilities)

    by_impact: Dict[str, int] = {}
    for v in vulnerabilities:
        imp = count_label(v.get("impact") or "Unknown")
        by_impact[imp] = by_impact.get(imp, 0) + 1

    styles = get_report_styles()
    doc = SimpleDocTemplate(
        output_path,
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=56,
        bottomMargin=52,
    )
    story: List[Any] = []

    overview = [
        ("Scan type", "Large Language Model Security Benchmark"),
        ("Total issues found", str(total)),
        ("Report generated", datetime.now().strftime("%B %d, %Y at %I:%M %p")),
    ]
    append_executive_summary(
        story,
        report_key="llm",
        overview_rows=overview,
        severity_counts=by_impact,
        styles=styles,
        project_name="LLM Findings",
        scan_time=format_scan_duration(duration),
        meta_chips=[
            ("Scan type", "LLM"),
            ("Total issues", str(total)),
            ("Report generated", datetime.now().strftime("%b %d, %Y · %I:%M %p")),
            ("Platform", "zeroshield.ai"),
        ],
    )
    story.append(PageBreak())

    catalog: List[List[Any]] = []
    for idx, vuln in enumerate(vulnerabilities, 1):
        title = (vuln.get("title") or "Untitled finding").strip() or "Untitled finding"
        impact = count_label(vuln.get("impact") or "Unknown")
        catalog.append(
            [
                str(idx),
                impact,
                Paragraph(escape_html(title), styles["table_cell"]),
                Paragraph(escape_html(finding_location(vuln)), styles["mono_cell"]),
            ]
        )
    append_findings_catalog(story, catalog_rows=catalog, styles=styles)
    story.append(PageBreak())

    story.append(Paragraph("Detailed Findings", styles["title"]))
    story.append(
        Paragraph(
            "Each card includes description, OWASP LLM mappings, and remediation.",
            styles["muted"],
        )
    )
    story.append(Spacer(1, 0.1 * inch))

    if total == 0:
        story.append(Paragraph("No vulnerability findings from this LLM benchmark scan.", styles["body"]))
    else:
        for idx, vuln in enumerate(vulnerabilities, 1):
            title = (vuln.get("title") or "Untitled finding").strip() or "Untitled finding"
            impact = count_label(vuln.get("impact") or "Unknown")
            loc = finding_location(vuln)
            standards: List[List[str]] = []
            standards.extend(mapping_rows(vuln.get("owasp_top_10_llm"), label="OWASP Top 10 for LLM"))
            standards.extend(mapping_rows(vuln.get("owasp_top_10"), label="OWASP Top 10"))
            standards.extend(mapping_rows(vuln.get("compliance_controls"), label="Compliance"))
            story.append(
                build_finding_section(
                    index=idx,
                    title=title,
                    severity=impact,
                    detail_rows=[("Severity", impact), ("Where it was found", loc)],
                    description=(vuln.get("description") or "").strip(),
                    evidence="",
                    recommended_fix=(vuln.get("suggested_fix") or "").strip(),
                    standards_rows=standards or None,
                    styles=styles,
                )
            )

    doc.build(
        story,
        onFirstPage=make_cover_callback("llm"),
        onLaterPages=make_footer_callback("llm"),
    )
    return output_path


def create_title_page(canvas_obj, doc) -> None:
    from backend.utilities.pdf.report_branding import draw_enterprise_cover_page

    draw_enterprise_cover_page(canvas_obj, doc, report_key="llm")


def create_header_footer(canvas_obj, doc) -> None:
    from backend.utilities.pdf.report_branding import draw_standard_footer

    draw_standard_footer(canvas_obj, doc, report_key="llm")


if __name__ == "__main__":
    import sys

    test_path = os.path.join(
        os.path.dirname(__file__),
        "..",
        "..",
        "..",
        "RabbitMQ",
        "worker",
        "archive",
        "first_llm_agent_results_testing.json",
    )
    if len(sys.argv) > 1:
        test_path = sys.argv[1]
    out_dir = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "generated_reports"))
    os.makedirs(out_dir, exist_ok=True)
    out = os.path.join(out_dir, "LLM_Enterprise_Report.pdf")
    try:
        with open(test_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        print(generate_pdf(data, out))
    except Exception as e:
        print(
            generate_pdf(
                [
                    {
                        "title": "Prompt injection via unsanitized user input",
                        "impact": "High",
                        "description": "User content is concatenated into the system prompt.",
                        "suggested_fix": "Separate untrusted input from instructions.",
                        "owasp_top_10_llm": {"LLM01:2025": "Prompt Injection"},
                    }
                ],
                out,
            )
        )
        print(f"Fallback sample used: {e}")
