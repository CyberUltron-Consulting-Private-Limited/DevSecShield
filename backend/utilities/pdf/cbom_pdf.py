"""
CBOM (Cryptographic Bill of Materials) Scan Results PDF Generator.
Human-readable enterprise report from CBOM scan results.
"""

from __future__ import annotations

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
    finding_location,
    format_scan_duration,
    get_report_styles,
    make_cover_callback,
    make_footer_callback,
    mapping_rows,
    severity_color,
    split_scan_payload,
)

# Kept for callers that import it; the report itself uses the app-wide scale in cbom_metrics.IMPACT_RISK.
IMPACT_TO_RISK: Dict[str, float] = {
    "critical": 9.0,
    "high": 7.0,
    "medium": 5.0,
    "low": 2.0,
}


def _impact_color(impact: str):
    return severity_color(impact)


def _quantum_label(quantum_safe: Any, strength: Any = None) -> str:
    # The results page's Quantum column rule: an algorithm a quantum computer does not break but that is already
    # broken (MD5, SHA-1, DES, RC4, ECB ...) is "Broken today", never "Quantum-Safe" (the PDF said Quantum-Safe for
    # every weak symmetric finding: lab UI run u2, round 5).
    if quantum_safe is True and str(strength or "").lower() == "weak":
        return "Broken today (classically broken: replace now)"
    if quantum_safe is True:
        return "Quantum-Safe"
    if quantum_safe is False:
        return "Quantum-Vulnerable"
    return "Unknown"


def _normalize_results(scan_results: Union[list, dict]) -> List[dict]:
    """Accept either a list of findings or a dict that contains them."""
    inner, _duration, _raw = split_scan_payload(scan_results)
    if isinstance(inner, list):
        return inner
    if isinstance(inner, dict) and "results" in inner:
        return inner["results"] or []
    return []


def generate_pdf(scan_results: Union[dict, list], output_path: Optional[str] = None) -> str:
    """
    Generate a CBOM scan results PDF.

    Args:
        scan_results: list of CBOM vulnerability dicts produced by the worker agent.
        output_path:  file path for the PDF. Auto-generated when None.
    """
    if output_path is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = f"cbom_scan_report_{timestamp}.pdf"

    from backend.utilities.cbom_sources.cbom_metrics import (
        INFORMATIONAL_LABEL,
        finding_rows,
        finding_severity,
        summarize_code_rows,
    )
    from backend.utilities.cbom_sources.cbom_rows import display_row

    rows = _normalize_results(scan_results)
    # the same numbers as the results page (cbom_metrics): findings only; clean inventory is informational
    summary = summarize_code_rows(rows)
    vulnerabilities = [display_row(v) for v in finding_rows(rows)]
    _inner, duration, raw = split_scan_payload(scan_results)
    total = len(vulnerabilities)

    by_impact: Dict[str, int] = {count_label(s): n for s, n in summary.severity.items() if n}
    by_type: Dict[str, int] = {str(k).strip().lower(): v for k, v in summary.algorithm_types.items()}
    quantum_vulnerable = summary.quantum["quantum_vulnerable"]
    quantum_safe_count = summary.quantum["quantum_safe"]
    avg_risk = summary.average_risk
    readiness = summary.readiness_pct  # one definition for every CBOM surface (cbom_metrics.quantum_readiness_pct)
    readiness_text = "n/a" if readiness is None else f"{readiness:.1f}%"  # as the team deliverables print it
    informational = summary.informational

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

    extra_tables = []
    if by_type:
        extra_tables.append(
            (
                "Algorithm type distribution",
                ["Algorithm type", "Count"],
                [[alg_type.title(), str(cnt)] for alg_type, cnt in sorted(by_type.items(), key=lambda x: -x[1])],
                [4.0 * inch, 1.5 * inch],
            )
        )
    extra_tables.append(
        (
            "Cryptographic posture",
            ["Metric", "Value"],
            [
                ["Cryptographic findings", str(total)],
                [INFORMATIONAL_LABEL + " (no finding)", str(informational)],
                ["Quantum-vulnerable algorithms", str(quantum_vulnerable)],
                ["Quantum-safe algorithms", str(quantum_safe_count)],
                ["Quantum readiness", readiness_text],
                ["Weak algorithms", str(summary.weak)],
                ["Average risk score", f"{avg_risk:.1f} / 10"],
            ],
            [4.0 * inch, 1.5 * inch],
        )
    )

    overview = [
        ("Scan type", "Cryptographic Bill of Materials (CBOM)"),
        ("Total cryptographic findings", str(total)),
        (INFORMATIONAL_LABEL + " (no finding)", str(informational)),
        ("Quantum-vulnerable", str(quantum_vulnerable)),
        ("Quantum-safe", str(quantum_safe_count)),
        ("Average risk score (0–10)", f"{avg_risk:.1f}"),
        ("Report generated", datetime.now().strftime("%B %d, %Y at %I:%M %p")),
    ]
    append_executive_summary(
        story,
        report_key="cbom",
        overview_rows=overview,
        severity_counts=by_impact,
        styles=styles,
        extra_tables=extra_tables,
        project_name="CBOM Findings",
        scan_time=format_scan_duration(duration),
        meta_chips=[
            ("Scan type", "CBOM"),
            ("Total findings", str(total)),
            ("Report generated", datetime.now().strftime("%b %d, %Y · %I:%M %p")),
            ("Quantum-vulnerable", str(quantum_vulnerable)),
        ],
    )
    story.append(PageBreak())

    impact_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    sorted_vulns = sorted(
        vulnerabilities,
        key=lambda v: (
            impact_order.get((v.get("impact") or "low").strip().lower(), 4),
            (v.get("algorithm_name") or "").lower(),
        ),
    )

    catalog: List[List[Any]] = []
    for idx, v in enumerate(sorted_vulns, 1):
        title = v.get("title") or v.get("algorithm_name") or f"Finding #{idx}"
        impact = count_label(finding_severity(v) or "low")  # the severity the counts use
        location = finding_location(v)
        catalog.append(
            [
                str(idx),
                impact,
                Paragraph(escape_html(str(title)), styles["table_cell"]),
                Paragraph(escape_html(location), styles["mono_cell"]),
            ]
        )
    append_findings_catalog(story, catalog_rows=catalog, styles=styles)
    story.append(PageBreak())

    story.append(Paragraph("Detailed Findings", styles["title"]))
    story.append(
        Paragraph(
            "Each card includes algorithm metadata, location, evidence, and remediation.",
            styles["muted"],
        )
    )
    story.append(Spacer(1, 0.1 * inch))

    if informational:
        story.append(Paragraph(
            f"{informational} clean inventory item(s) with no finding are listed in the CycloneDX download, "
            "not here.", styles["muted"]))
    if total == 0:
        story.append(Paragraph("No cryptographic findings were detected.", styles["body"]))
    else:
        for idx, v in enumerate(sorted_vulns, 1):
            title = v.get("title") or v.get("algorithm_name") or f"Finding #{idx}"
            impact = count_label(finding_severity(v) or "low")  # the severity the counts use
            strength = (v.get("crypto_strength") or "unknown").strip()
            alg_name = str(v.get("algorithm_name") or "—")
            alg_type = str(v.get("algorithm_type") or "—")
            key_size = v.get("key_size")
            key_size_text = f"{key_size} bits" if key_size is not None else "—"
            location = finding_location(v)
            standards: List[List[str]] = []
            standards.extend(mapping_rows(v.get("owasp_top_10"), label="OWASP Top 10"))
            standards.extend(mapping_rows(v.get("compliance_controls"), label="Compliance"))
            story.append(
                build_finding_section(
                    index=idx,
                    title=str(title),
                    severity=impact,
                    detail_rows=[
                        ("Severity", impact),
                        ("Algorithm", alg_name),
                        ("Type", alg_type),
                        ("Key size", key_size_text),
                        ("Strength", strength.title()),
                        ("Quantum status", _quantum_label(v.get("quantum_safe"), strength)),
                        ("Where it was found", location),
                        *([("CWE", ", ".join(map(str, v.get("cwe") or [])))] if v.get("cwe") else []),
                        *([("CVE", ", ".join(map(str, v.get("cves") or [])))] if v.get("cves") else []),
                    ],
                    description=str(v.get("description") or ""),
                    evidence=str(v.get("snippet") or ""),
                    recommended_fix=str(v.get("suggested_fix") or ""),
                    standards_rows=standards or None,
                    styles=styles,
                )
            )

    appendix_payload = raw if raw else (scan_results if isinstance(scan_results, dict) else {})
    append_bom_compliance_sections(story, appendix_payload, styles)

    doc.build(
        story,
        onFirstPage=make_cover_callback("cbom"),
        onLaterPages=make_footer_callback("cbom"),
    )
    return output_path


def create_title_page(canvas_obj, doc):
    from backend.utilities.pdf.report_branding import draw_enterprise_cover_page

    draw_enterprise_cover_page(canvas_obj, doc, report_key="cbom")


def create_header_footer(canvas_obj, doc):
    from backend.utilities.pdf.report_branding import draw_standard_footer

    draw_standard_footer(canvas_obj, doc, report_key="cbom")
