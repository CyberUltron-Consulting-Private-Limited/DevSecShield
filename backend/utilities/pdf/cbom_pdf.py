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
    get_report_styles,
    make_cover_callback,
    make_footer_callback,
    mapping_rows,
    severity_color,
)

IMPACT_TO_RISK: Dict[str, float] = {
    "critical": 9.0,
    "high": 7.0,
    "medium": 4.0,
    "low": 1.0,
}


def _impact_color(impact: str):
    return severity_color(impact)


def _quantum_label(quantum_safe: Any) -> str:
    if quantum_safe is True:
        return "Quantum-Safe"
    if quantum_safe is False:
        return "Quantum-Vulnerable"
    return "Unknown"


def _normalize_results(scan_results: Union[list, dict]) -> List[dict]:
    """Accept either a list of findings or a dict that contains them."""
    if isinstance(scan_results, list):
        return scan_results
    if isinstance(scan_results, dict):
        if "results" in scan_results:
            return scan_results["results"] or []
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

    vulnerabilities = _normalize_results(scan_results)
    total = len(vulnerabilities)

    by_impact: Dict[str, int] = {}
    by_strength: Dict[str, int] = {}
    by_type: Dict[str, int] = {}
    quantum_vulnerable = 0
    quantum_safe_count = 0
    risk_sum = 0.0

    for v in vulnerabilities:
        impact_raw = (v.get("impact") or "unknown").strip().lower()
        impact = count_label(impact_raw)
        by_impact[impact] = by_impact.get(impact, 0) + 1
        risk_sum += IMPACT_TO_RISK.get(impact_raw, 2.0)

        strength = (v.get("crypto_strength") or "unknown").strip().lower()
        by_strength[strength] = by_strength.get(strength, 0) + 1

        alg_type = (v.get("algorithm_type") or "unknown").strip().lower()
        by_type[alg_type] = by_type.get(alg_type, 0) + 1

        if v.get("quantum_safe") is False:
            quantum_vulnerable += 1
        elif v.get("quantum_safe") is True:
            quantum_safe_count += 1

    avg_risk = risk_sum / total if total > 0 else 0.0
    quantum_readiness = (quantum_safe_count / total * 100) if total > 0 else 0.0

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
                ["Quantum-vulnerable algorithms", str(quantum_vulnerable)],
                ["Quantum-safe algorithms", str(quantum_safe_count)],
                ["Quantum readiness", f"{quantum_readiness:.1f}%"],
                ["Weak algorithms", str(by_strength.get("weak", 0))],
                ["Average risk score", f"{avg_risk:.1f} / 10"],
            ],
            [4.0 * inch, 1.5 * inch],
        )
    )

    overview = [
        ("Scan type", "Cryptographic Bill of Materials (CBOM)"),
        ("Total cryptographic findings", str(total)),
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
        impact = count_label(v.get("impact") or "Unknown")
        location = str(v.get("location") or "—")
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

    if total == 0:
        story.append(Paragraph("No cryptographic findings were detected.", styles["body"]))
    else:
        for idx, v in enumerate(sorted_vulns, 1):
            title = v.get("title") or v.get("algorithm_name") or f"Finding #{idx}"
            impact = count_label(v.get("impact") or "Unknown")
            strength = (v.get("crypto_strength") or "unknown").strip()
            alg_name = str(v.get("algorithm_name") or "—")
            alg_type = str(v.get("algorithm_type") or "—")
            key_size = v.get("key_size")
            key_size_text = f"{key_size} bits" if key_size is not None else "—"
            location = str(v.get("location") or "—")
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
                        ("Quantum status", _quantum_label(v.get("quantum_safe"))),
                        ("Location", location),
                    ],
                    description=str(v.get("description") or ""),
                    evidence=str(v.get("snippet") or ""),
                    recommended_fix=str(v.get("suggested_fix") or ""),
                    standards_rows=standards or None,
                    styles=styles,
                )
            )

    append_bom_compliance_sections(story, scan_results, styles)

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
