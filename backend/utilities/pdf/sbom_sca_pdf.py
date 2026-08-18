"""
SBOM/SCA Scan Results PDF Generator
Human-readable enterprise report with tabular summary and detailed findings.
"""

from __future__ import annotations

import json
import os
from datetime import datetime
from typing import Any, Dict, List, Optional, Union

from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch
from reportlab.platypus import PageBreak, Paragraph, SimpleDocTemplate, Spacer

from backend.utilities.pdf.report_branding import (
    append_bom_compliance_sections,
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

IMPACT_TO_RISK = {"critical": 9.0, "high": 7.0, "medium": 4.0, "low": 1.0}


def _impact_to_risk(impact: str) -> float:
    if not impact:
        return 2.0
    return IMPACT_TO_RISK.get(impact.strip().lower(), 2.0)


def get_severity_color(severity: str):
    return severity_color(severity)


def _normalize_sbom_results(scan_results: Union[dict, list]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    if isinstance(scan_results, list):
        for item in scan_results:
            if not isinstance(item, dict):
                continue
            out.append(
                {
                    "title": item.get("title") or "Untitled",
                    "description": item.get("description") or "",
                    "impact": item.get("impact") or "Unknown",
                    "owasp_top_10": item.get("owasp_top_10") or {},
                    "compliance_controls": item.get("compliance_controls") or {},
                    "suggested_fix": item.get("suggested_fix") or "",
                    "dependencies": item.get("dependencies") or [],
                    "cves": item.get("cves") or {},
                }
            )
        return out

    matches = (scan_results or {}).get("matches", []) if isinstance(scan_results, dict) else []
    for match in matches:
        vuln = match.get("vulnerability", {}) or {}
        artifact = match.get("artifact", {}) or {}
        fix = vuln.get("fix", {}) or {}
        fix_state = fix.get("state", "unknown")
        fix_versions = fix.get("versions", []) or []
        suggested_fix = f"Fix status: {fix_state}"
        if fix_versions:
            suggested_fix += f". Fixed in: {', '.join(fix_versions[:3])}"
        dependencies = []
        name = artifact.get("name", "")
        version = artifact.get("version", "")
        if name:
            dependencies.append(f"{name}@{version}")
        cves = vuln.get("cves", {}) or {}
        if not isinstance(cves, dict):
            cves = {k: (v if isinstance(v, str) else str(v)) for k, v in (cves or {}).items()} if cves else {}
        out.append(
            {
                "title": vuln.get("id", "Unknown"),
                "description": vuln.get("description", "No description available"),
                "impact": vuln.get("severity", "UNKNOWN"),
                "owasp_top_10": vuln.get("owasp_top_10") or {},
                "compliance_controls": vuln.get("compliance_controls") or {},
                "suggested_fix": suggested_fix,
                "dependencies": dependencies,
                "cves": cves,
            }
        )
    return out


def generate_pdf(scan_results: Union[dict, list], output_path: Optional[str] = None) -> str:
    if output_path is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = f"sbom_sca_scan_report_{timestamp}.pdf"

    vulnerabilities = _normalize_sbom_results(scan_results)
    total = len(vulnerabilities)
    by_severity: Dict[str, int] = {}
    unique_packages: set = set()
    fixable_count = 0
    risk_sum = 0.0

    for v in vulnerabilities:
        impact = count_label(v.get("impact") or "Unknown")
        by_severity[impact] = by_severity.get(impact, 0) + 1
        risk_sum += _impact_to_risk(impact)
        for dep in v.get("dependencies") or []:
            if dep:
                unique_packages.add(dep if isinstance(dep, str) else str(dep))
        suggested = (v.get("suggested_fix") or "").lower()
        if "upgrade" in suggested or "fixed" in suggested or "update" in suggested:
            fixable_count += 1

    avg_risk = risk_sum / total if total else 0.0
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
        ("Scan type", "SBOM / Software Composition Analysis (SCA)"),
        ("Total vulnerabilities", str(total)),
        ("Packages affected", str(len(unique_packages))),
        ("Likely fixable via upgrade/update", str(fixable_count)),
        ("Average risk score (0–10)", f"{avg_risk:.2f}" if avg_risk else "N/A"),
        ("Report generated", datetime.now().strftime("%B %d, %Y at %I:%M %p")),
    ]
    append_executive_summary(
        story,
        report_key="sbom_sca",
        overview_rows=overview,
        severity_counts=by_severity,
        styles=styles,
        project_name="SBOM / SCA Dependencies",
        scan_time="—",
        meta_chips=[
            ("Scan type", "SBOM / SCA"),
            ("Packages affected", str(len(unique_packages))),
            ("Report generated", datetime.now().strftime("%b %d, %Y · %I:%M %p")),
            ("Fixable", str(fixable_count)),
        ],
    )
    story.append(PageBreak())

    catalog: List[List[Any]] = []
    for idx, v in enumerate(vulnerabilities, 1):
        title = v.get("title") or "Untitled"
        impact = (v.get("impact") or "Unknown").strip()
        deps = v.get("dependencies") or []
        location = deps[0] if deps else "—"
        if not isinstance(location, str):
            location = str(location)
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
            "Each card shows affected package(s), description, and remediation. Package and CVE values use monospace.",
            styles["muted"],
        )
    )
    story.append(Spacer(1, 0.1 * inch))

    if total == 0:
        story.append(Paragraph("No vulnerabilities were identified in this scan.", styles["body"]))
    else:
        for idx, v in enumerate(vulnerabilities, 1):
            title = v.get("title") or "Untitled"
            impact = (v.get("impact") or "Unknown").strip()
            dependencies = v.get("dependencies") or []
            deps_str = "; ".join((d if isinstance(d, str) else str(d)) for d in dependencies[:10])
            if len(dependencies) > 10:
                deps_str += f" (+{len(dependencies) - 10} more)"

            detail_rows = [("Severity", impact)]
            if deps_str:
                detail_rows.append(("Affected package(s)", deps_str))
            cves = v.get("cves") or {}
            if isinstance(cves, dict) and cves:
                detail_rows.append(("CVE IDs", ", ".join(list(cves.keys())[:8])))

            standards: List[List[str]] = []
            standards.extend(mapping_rows(v.get("owasp_top_10"), label="OWASP Top 10"))
            standards.extend(mapping_rows(v.get("compliance_controls"), label="Compliance"))
            standards.extend(mapping_rows(cves, label="CVE detail", limit=5))

            story.append(
                build_finding_section(
                    index=idx,
                    title=title,
                    severity=impact,
                    detail_rows=detail_rows,
                    description=v.get("description") or "",
                    evidence="",
                    recommended_fix=v.get("suggested_fix") or "",
                    standards_rows=standards or None,
                    styles=styles,
                )
            )

    append_bom_compliance_sections(story, scan_results, styles)

    doc.build(
        story,
        onFirstPage=make_cover_callback("sbom_sca"),
        onLaterPages=make_footer_callback("sbom_sca"),
    )
    return output_path


def create_title_page(canvas_obj, doc):
    from backend.utilities.pdf.report_branding import draw_enterprise_cover_page

    draw_enterprise_cover_page(canvas_obj, doc, report_key="sbom_sca")


def create_header_footer(canvas_obj, doc):
    from backend.utilities.pdf.report_branding import draw_standard_footer

    draw_standard_footer(canvas_obj, doc, report_key="sbom_sca")


if __name__ == "__main__":
    test_file_path = os.path.normpath(
        os.path.join(
            os.path.dirname(__file__),
            "..",
            "..",
            "..",
            "RabbitMQ",
            "worker",
            "archive",
            "worker_sbom_agent_results_testing.json",
        )
    )
    with open(test_file_path, "r", encoding="utf-8") as f:
        scan_results = json.load(f)
    out_dir = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "generated_reports"))
    os.makedirs(out_dir, exist_ok=True)
    print(generate_pdf(scan_results, os.path.join(out_dir, "SBOM_SCA_Enterprise_Report.pdf")))
