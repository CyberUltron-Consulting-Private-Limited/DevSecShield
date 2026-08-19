"""
IAC Scan Results PDF Generator
Human-readable enterprise report with tabular summary and detailed findings.
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
    get_report_styles,
    make_cover_callback,
    make_footer_callback,
    mapping_rows,
    severity_color,
)


def _normalize_results(scan_results: Any) -> List[Dict[str, Any]]:
    """Accept either a list of findings (agent format) or a dict with 'results' key."""
    if isinstance(scan_results, list):
        return scan_results
    if isinstance(scan_results, dict):
        return scan_results.get("results", [])
    return []


def _is_agent_format(finding: Dict[str, Any]) -> bool:
    """True if finding has title/impact/owasp_top_10 (IAC agent format)."""
    return (
        isinstance(finding, dict)
        and ("title" in finding or "impact" in finding)
        and ("owasp_top_10" in finding or "compliance_controls" in finding)
    )


def get_severity_color(impact_or_severity: str):
    return severity_color(impact_or_severity)


def get_relative_path(file_path: str) -> str:
    """Extract path from repo_xxxxxxx onwards for legacy location.filename."""
    try:
        repo_index = file_path.find("repo_")
        if repo_index != -1:
            return file_path[repo_index:]
        return file_path or ""
    except Exception:
        return file_path or ""


def generate_pdf(scan_results: Any, output_path: Optional[str] = None) -> str:
    """
    Generate a PDF report from IAC scan results.

    Supports IAC agent format: list of findings with title, description, impact,
    owasp_top_10, compliance_controls, suggested_fix, location, snippet, cves.
    Also accepts legacy dict with "results" key.
    """
    if output_path is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = f"iac_scan_report_{timestamp}.pdf"

    results = _normalize_results(scan_results)
    use_agent_format = len(results) > 0 and _is_agent_format(results[0])

    total_findings = len(results)
    by_impact: Dict[str, int] = {}
    unique_locations: set = set()
    by_provider: Dict[str, int] = {}
    by_service: Dict[str, int] = {}

    for result in results:
        if use_agent_format:
            impact = count_label(result.get("impact") or "Unknown")
            by_impact[impact] = by_impact.get(impact, 0) + 1
            loc = result.get("location")
            if isinstance(loc, str) and loc.strip():
                unique_locations.add(loc.strip())
        else:
            severity = count_label(result.get("severity", "UNKNOWN"))
            by_impact[severity] = by_impact.get(severity, 0) + 1
            loc = result.get("location") or {}
            file_path = loc.get("filename", "") if isinstance(loc, dict) else ""
            if file_path:
                unique_locations.add(file_path)
            provider = result.get("rule_provider", "Unknown")
            by_provider[provider] = by_provider.get(provider, 0) + 1
            service = result.get("rule_service", "Unknown")
            by_service[service] = by_service.get(service, 0) + 1

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
        ("Scan type", "Infrastructure as Code (IAC)"),
        ("Total findings", str(total_findings)),
        ("Unique locations", str(len(unique_locations))),
        ("Report generated", datetime.now().strftime("%B %d, %Y at %I:%M %p")),
    ]
    extra_tables = []
    if not use_agent_format and by_provider:
        extra_tables.append(
            (
                "Findings by provider",
                ["Provider", "Count"],
                [[str(p).upper(), str(c)] for p, c in sorted(by_provider.items(), key=lambda x: -x[1])],
                [4.0 * inch, 1.5 * inch],
            )
        )
    if not use_agent_format and by_service:
        extra_tables.append(
            (
                "Findings by service",
                ["Service", "Count"],
                [[str(s).upper(), str(c)] for s, c in sorted(by_service.items(), key=lambda x: -x[1])],
                [4.0 * inch, 1.5 * inch],
            )
        )

    append_executive_summary(
        story,
        report_key="iac",
        overview_rows=overview,
        severity_counts=by_impact,
        styles=styles,
        extra_tables=extra_tables or None,
        project_name="IAC Findings",
        meta_chips=[
            ("Scan type", "IAC"),
            ("Total findings", str(total_findings)),
            ("Locations", str(len(unique_locations))),
            ("Report generated", datetime.now().strftime("%b %d, %Y · %I:%M %p")),
        ],
    )
    story.append(PageBreak())

    catalog: List[List[Any]] = []
    for idx, result in enumerate(results, 1):
        if use_agent_format:
            title = (result.get("title") or "Finding").strip() or "Finding"
            impact = count_label(result.get("impact") or "Unknown")
            location = (result.get("location") or "—").strip() or "—"
        else:
            extra = result.get("rule_description") or result.get("rule_id") or "Finding"
            title = str(extra)
            impact = count_label(result.get("severity", "UNKNOWN"))
            location_obj = result.get("location") or {}
            file_path = get_relative_path(location_obj.get("filename", "Unknown") if isinstance(location_obj, dict) else "Unknown")
            start_line = location_obj.get("start_line", "?") if isinstance(location_obj, dict) else "?"
            location = f"{file_path}:{start_line}"
        catalog.append(
            [
                str(idx),
                impact,
                Paragraph(escape_html(title), styles["table_cell"]),
                Paragraph(escape_html(location), styles["mono_cell"]),
            ]
        )
    append_findings_catalog(story, catalog_rows=catalog, styles=styles)
    story.append(PageBreak())

    story.append(Paragraph("Detailed Findings", styles["title"]))
    story.append(
        Paragraph(
            "Each card includes location, description, evidence, and remediation. Technical values use monospace.",
            styles["muted"],
        )
    )
    story.append(Spacer(1, 0.1 * inch))

    if total_findings == 0:
        story.append(Paragraph("No security findings were identified in this scan.", styles["body"]))
    else:
        for idx, result in enumerate(results, 1):
            if use_agent_format:
                title = (result.get("title") or "Finding").strip() or "Finding"
                impact = count_label(result.get("impact") or "Unknown")
                location_str = (result.get("location") or "").strip() or "—"
                standards: List[List[str]] = []
                standards.extend(mapping_rows(result.get("owasp_top_10"), label="OWASP Top 10"))
                standards.extend(mapping_rows(result.get("compliance_controls"), label="Compliance"))
                standards.extend(mapping_rows(result.get("cves"), label="CVE", limit=10))
                story.append(
                    build_finding_section(
                        index=idx,
                        title=title,
                        severity=impact,
                        detail_rows=[
                            ("Severity", impact),
                            ("Where it was found", location_str[:300]),
                        ],
                        description=(result.get("description") or "").strip(),
                        evidence=(result.get("snippet") or "").strip(),
                        recommended_fix=(result.get("suggested_fix") or "").strip(),
                        standards_rows=standards or None,
                        styles=styles,
                    )
                )
            else:
                rule_id = result.get("rule_id", "Unknown")
                long_id = result.get("long_id", "Unknown")
                rule_description = result.get("rule_description", "No description")
                provider = result.get("rule_provider", "Unknown")
                service = result.get("rule_service", "Unknown")
                severity = count_label(result.get("severity", "UNKNOWN"))
                resource = result.get("resource", "Unknown")
                location = result.get("location") or {}
                file_path = get_relative_path(location.get("filename", "Unknown") if isinstance(location, dict) else "Unknown")
                start_line = location.get("start_line", "?") if isinstance(location, dict) else "?"
                end_line = location.get("end_line", "?") if isinstance(location, dict) else "?"
                standards = []
                for ref in (result.get("links") or [])[:5]:
                    standards.append(["Reference", str(ref)[:120]])
                description = result.get("description") or "No description available"
                impact_text = result.get("impact") or ""
                if impact_text:
                    description = f"{description}\n\nImpact: {impact_text}"
                story.append(
                    build_finding_section(
                        index=idx,
                        title=str(rule_description),
                        severity=severity,
                        detail_rows=[
                            ("Severity", severity),
                            ("Rule / check", str(rule_id)[:140]),
                            ("Long ID", str(long_id)[:140]),
                            ("Provider", str(provider).upper()),
                            ("Service", str(service).upper()),
                            ("Resource", str(resource)),
                            ("File", str(file_path)[:200]),
                            ("Location", f"Lines {start_line}-{end_line}"),
                        ],
                        description=str(description),
                        evidence="",
                        recommended_fix=str(result.get("resolution") or ""),
                        standards_rows=standards or None,
                        styles=styles,
                    )
                )

    doc.build(
        story,
        onFirstPage=make_cover_callback("iac"),
        onLaterPages=make_footer_callback("iac"),
    )
    return output_path


def create_title_page(canvas_obj, doc):
    from backend.utilities.pdf.report_branding import draw_enterprise_cover_page

    draw_enterprise_cover_page(canvas_obj, doc, report_key="iac")


def create_header_footer(canvas_obj, doc):
    from backend.utilities.pdf.report_branding import draw_standard_footer

    draw_standard_footer(canvas_obj, doc, report_key="iac")


if __name__ == "__main__":
    test_file_path = os.path.normpath(
        os.path.join(
            os.path.dirname(__file__),
            "..",
            "..",
            "..",
            "RabbitMQ",
            "worker",
            "iac_results_testing.json",
        )
    )
    out_dir = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "generated_reports"))
    os.makedirs(out_dir, exist_ok=True)
    if os.path.exists(test_file_path):
        with open(test_file_path, "r", encoding="utf-8") as f:
            scan_results = json.load(f)
        print(generate_pdf(scan_results, os.path.join(out_dir, "IAC_Enterprise_Report.pdf")))
    else:
        print(
            generate_pdf(
                [
                    {
                        "title": "Open security group",
                        "impact": "High",
                        "location": "modules/network/sg.tf:12",
                        "description": "Security group allows 0.0.0.0/0 ingress.",
                        "snippet": "cidr_blocks = [\"0.0.0.0/0\"]",
                        "suggested_fix": "Restrict ingress to known CIDRs.",
                        "owasp_top_10": {"A05:2021": "Security Misconfiguration"},
                        "compliance_controls": {},
                    }
                ],
                os.path.join(out_dir, "IAC_Enterprise_Report.pdf"),
            )
        )
