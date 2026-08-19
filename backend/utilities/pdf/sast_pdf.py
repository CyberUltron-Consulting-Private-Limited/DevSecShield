"""
SAST Scan Results PDF Generator
Human-readable enterprise report: cover → summary tables → catalog → detailed findings.
"""

from __future__ import annotations

import json
import os
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

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
)


def get_relative_path(file_path: str) -> str:
    try:
        repo_index = file_path.find("repo_")
        if repo_index != -1:
            return file_path[repo_index:]
        return file_path
    except Exception:
        return file_path


def _is_agent_format(scan_results: Any) -> bool:
    if not isinstance(scan_results, list) or len(scan_results) == 0:
        return False
    first = scan_results[0]
    return (
        isinstance(first, dict)
        and "vulnerabilities" in first
        and isinstance(first.get("vulnerabilities"), list)
    )


def _owasp_compliance_entries(val: Any) -> List[Tuple[Any, Any]]:
    if val is None:
        return []
    if isinstance(val, dict) and not isinstance(val, list):
        return [(k, v) for k, v in val.items() if v is not None and str(v).strip()]
    if isinstance(val, list):
        out: List[Tuple[Any, Any]] = []
        for item in val:
            if isinstance(item, dict) and item:
                for k, v in item.items():
                    if v is not None and str(v).strip():
                        out.append((k, v))
                        break
        return out
    return []


def _standards_rows(vuln: Dict[str, Any]) -> List[List[str]]:
    rows: List[List[str]] = []
    rows.extend(mapping_rows(vuln.get("owasp_top_10"), label="OWASP Top 10"))
    rows.extend(mapping_rows(vuln.get("compliance_controls"), label="Compliance"))
    rows.extend(mapping_rows(vuln.get("cves"), label="CVE", limit=5))
    return rows


def _build_agent_pdf_story(story: List[Any], components: List[Dict[str, Any]]) -> None:
    styles = get_report_styles()
    flat_vulns: List[Tuple[str, Dict[str, Any]]] = []
    for comp in components:
        comp_title = comp.get("logical_component_title") or "Application area"
        for v in comp.get("vulnerabilities") or []:
            flat_vulns.append((comp_title, v))

    total = len(flat_vulns)
    by_impact: Dict[str, int] = {}
    for _, v in flat_vulns:
        imp = count_label(v.get("impact") or "Unknown")
        by_impact[imp] = by_impact.get(imp, 0) + 1

    overview = [
        ("Scan type", "Static Application Security Testing (SAST)"),
        ("Total issues found", str(total)),
        ("Application areas reviewed", str(len(components))),
        ("Report generated", datetime.now().strftime("%B %d, %Y at %I:%M %p")),
    ]
    for imp in ["Critical", "High", "Medium", "Low"]:
        if by_impact.get(imp):
            overview.append((f"{imp} severity issues", str(by_impact[imp])))

    scan_time = "—"
    for comp in components:
        if isinstance(comp, dict) and comp.get("scan_duration"):
            scan_time = str(comp["scan_duration"])
            break

    append_executive_summary(
        story,
        report_key="sast",
        overview_rows=overview,
        severity_counts=by_impact,
        styles=styles,
        project_name=(
            (components[0].get("logical_component_title") or "SAST Findings")
            if components
            else "SAST Findings"
        ),
        scan_time=scan_time,
        meta_chips=[
            ("Project", str(components[0].get("logical_component_title") or "Application") if components else "Application"),
            ("Scan type", "SAST"),
            ("Report generated", datetime.now().strftime("%b %d, %Y · %I:%M %p")),
            ("Platform", "zeroshield.ai"),
        ],
    )
    story.append(PageBreak())

    catalog: List[List[Any]] = []
    for idx, (comp_title, vuln) in enumerate(flat_vulns, 1):
        title = vuln.get("title") or "Untitled issue"
        impact = (vuln.get("impact") or "").strip() or "—"
        location = (vuln.get("location") or comp_title or "—").strip() or "—"
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

    if total == 0:
        story.append(Paragraph("No security findings were identified in this scan.", styles["body"]))
        return

    for idx, (comp_title, vuln) in enumerate(flat_vulns, 1):
        title = vuln.get("title") or "Untitled issue"
        impact = (vuln.get("impact") or "").strip() or "—"
        story.append(
            build_finding_section(
                index=idx,
                title=title,
                severity=impact,
                detail_rows=[
                    ("Severity", impact),
                    ("Where it was found", (vuln.get("location") or "—").strip() or "—"),
                    ("Application area", comp_title),
                ],
                description=(vuln.get("description") or "").strip(),
                evidence=(vuln.get("snippet") or "").strip(),
                recommended_fix=(vuln.get("suggested_fix") or "").strip(),
                standards_rows=_standards_rows(vuln) or None,
                styles=styles,
            )
        )


def _build_semgrep_pdf_story(story: List[Any], scan_results: Dict[str, Any]) -> None:
    styles = get_report_styles()
    version = scan_results.get("version", "Unknown")
    results = scan_results.get("results", []) or []
    all_errors = scan_results.get("errors", []) or []
    scanned_paths = scan_results.get("paths", {}).get("scanned", []) or []
    skipped_paths = scan_results.get("paths", {}).get("skipped", []) or []
    engine_requested = scan_results.get("engine_requested", "Unknown")

    errors = []
    for error in all_errors:
        error_type = error.get("type", "")
        if isinstance(error_type, list) and len(error_type) >= 2 and error_type[0] == "IncompatibleRule":
            continue
        errors.append(error)

    total = len(results)
    by_severity: Dict[str, int] = {}
    unique_files = set()
    for result in results:
        severity = result.get("severity") or result.get("extra", {}).get("severity", "UNKNOWN")
        by_severity[severity] = by_severity.get(severity, 0) + 1
        file_path = result.get("path", "")
        if file_path:
            unique_files.add(get_relative_path(file_path))

    overview = [
        ("Scan type", "Static Application Security Testing (SAST)"),
        ("Total issues found", str(total)),
        ("Files with issues", str(len(unique_files))),
        ("Files scanned", str(len(scanned_paths))),
        ("Files skipped", str(len(skipped_paths))),
        ("Scan engine", str(engine_requested)),
        ("Engine version", str(version)),
        ("Report generated", datetime.now().strftime("%B %d, %Y at %I:%M %p")),
    ]
    append_executive_summary(
        story,
        report_key="sast",
        overview_rows=overview,
        severity_counts=by_severity,
        styles=styles,
    )
    story.append(PageBreak())

    catalog: List[List[Any]] = []
    for idx, result in enumerate(results, 1):
        extra = result.get("extra", {}) or {}
        metadata = extra.get("metadata", {}) or {}
        check_id = result.get("check_id", "Unknown")
        check_name = check_id.split(".")[-1] if "." in check_id else check_id
        display_name = metadata.get("display-name", check_name)
        severity_level = result.get("severity") or extra.get("severity", "UNKNOWN")
        file_path = get_relative_path(result.get("path", "Unknown"))
        start = result.get("start", {}) or {}
        loc = f"{file_path} (line {start.get('line', '?')})"
        catalog.append(
            [
                str(idx),
                str(severity_level),
                Paragraph(escape_html(str(display_name)), styles["table_cell"]),
                Paragraph(escape_html(loc), styles["mono_cell"]),
            ]
        )
    append_findings_catalog(story, catalog_rows=catalog, styles=styles)
    story.append(PageBreak())

    story.append(Paragraph("Detailed Findings", styles["title"]))
    story.append(
        Paragraph(
            "Each card includes location, explanation, code evidence, and related mappings.",
            styles["muted"],
        )
    )
    story.append(Spacer(1, 0.1 * inch))

    if total == 0:
        story.append(Paragraph("No security findings were identified in this scan.", styles["body"]))
    else:
        for idx, result in enumerate(results, 1):
            check_id = result.get("check_id", "Unknown")
            check_name = check_id.split(".")[-1] if "." in check_id else check_id
            file_path = get_relative_path(result.get("path", "Unknown"))
            start = result.get("start", {}) or {}
            extra = result.get("extra", {}) or {}
            message = extra.get("message", "No description available")
            metadata = extra.get("metadata", {}) or {}
            display_name = metadata.get("display-name", check_name)
            snippet = result.get("snippet") or extra.get("lines", "")
            severity_level = result.get("severity") or extra.get("severity", "UNKNOWN")

            detail_rows = [
                ("Severity", str(severity_level)),
                ("Where it was found", f"{file_path}, line {start.get('line', '?')}, column {start.get('col', '?')}"),
                ("Rule / check", str(check_id)[:140]),
            ]
            if metadata.get("likelihood"):
                detail_rows.append(("Likelihood", str(metadata["likelihood"])))
            if metadata.get("impact"):
                detail_rows.append(("Impact", str(metadata["impact"])))
            if metadata.get("confidence"):
                detail_rows.append(("Confidence", str(metadata["confidence"])))

            standards: List[List[str]] = []
            for cwe in (metadata.get("cwe") or [])[:4]:
                standards.append(["CWE", str(cwe)])
            for owasp in (metadata.get("owasp") or [])[:4]:
                standards.append(["OWASP", str(owasp)])
            for ref in (metadata.get("references") or [])[:4]:
                standards.append(["Reference", str(ref)[:120]])

            story.append(
                build_finding_section(
                    index=idx,
                    title=str(display_name),
                    severity=str(severity_level),
                    detail_rows=detail_rows,
                    description=str(message),
                    evidence=str(snippet or ""),
                    recommended_fix="",
                    standards_rows=standards or None,
                    styles=styles,
                )
            )

    if errors:
        story.append(PageBreak())
        story.append(Paragraph("Scan Notes", styles["title"]))
        for error in errors:
            error_type = error.get("type", "Unknown")
            if isinstance(error_type, list):
                error_type = error_type[0] if error_type else "Unknown"
            story.append(
                build_finding_section(
                    index=0,
                    title=str(error_type),
                    severity="ERROR",
                    detail_rows=[
                        ("File", get_relative_path(error.get("path", "Unknown"))),
                    ],
                    description=str(error.get("message", "No message")),
                    styles=styles,
                )
            )


def generate_pdf(scan_results: Any, output_path: Optional[str] = None) -> str:
    if output_path is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = f"sast_scan_report_{timestamp}.pdf"

    doc = SimpleDocTemplate(
        output_path,
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=56,
        bottomMargin=52,
    )
    # Dashboard-first layout (HTML sample style) — no classic title cover page
    story: List[Any] = []

    if _is_agent_format(scan_results):
        _build_agent_pdf_story(story, scan_results)
    else:
        payload = scan_results if isinstance(scan_results, dict) else {}
        _build_semgrep_pdf_story(story, payload)

    doc.build(
        story,
        onFirstPage=make_cover_callback("sast"),
        onLaterPages=make_footer_callback("sast"),
    )
    return output_path


def create_title_page(canvas_obj, doc):
    from backend.utilities.pdf.report_branding import draw_enterprise_cover_page

    draw_enterprise_cover_page(canvas_obj, doc, report_key="sast")


def create_header_footer(canvas_obj, doc):
    from backend.utilities.pdf.report_branding import draw_standard_footer

    draw_standard_footer(canvas_obj, doc, report_key="sast")


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
            "worker_sast_agent_results_testing.json",
        )
    )
    with open(test_file_path, "r", encoding="utf-8") as f:
        scan_results = json.load(f)
    out_dir = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "generated_reports"))
    os.makedirs(out_dir, exist_ok=True)
    print(generate_pdf(scan_results, os.path.join(out_dir, "SAST_Enterprise_Report.pdf")))
