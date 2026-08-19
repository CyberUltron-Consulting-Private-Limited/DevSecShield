"""
AI-BOM (AI Bill of Materials) Scan Results PDF Generator.
Human-readable enterprise report from AI-BOM scan results.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional, Union

from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch
from reportlab.platypus import PageBreak, Paragraph, SimpleDocTemplate, Spacer

from backend.utilities.dashboard.aibom_license import (
    is_unlicensed_library_gap,
    resolve_aibom_license,
)
from backend.utilities.dashboard.aibom_provider import resolve_aibom_provider
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
    "medium": 5.0,
    "low": 2.0,
}


def _impact_color(impact: str):
    return severity_color(impact)


def _asset_name(v: dict) -> str:
    """Tolerate both frontend (asset_name) and stored (component_name) field names."""
    return v.get("asset_name") or v.get("component_name") or ""


def _asset_type(v: dict) -> str:
    """Tolerate both frontend (asset_type) and stored (component_type) field names."""
    return v.get("asset_type") or v.get("component_type") or ""


def _provider(v: dict) -> str:
    """Concrete ModelProvider label (never unknown)."""
    return resolve_aibom_provider(v)


def _license_type(v: dict) -> str:
    """Concrete SPDX / LicenseRef label (never unknown)."""
    return resolve_aibom_license(v)


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
    Generate an AI-BOM scan results PDF.

    Args:
        scan_results: list of AI-BOM asset dicts produced by the worker agent.
        output_path:  file path for the PDF. Auto-generated when None.
    """
    if output_path is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = f"ai_bom_scan_report_{timestamp}.pdf"

    assets = _normalize_results(scan_results)
    total = len(assets)

    by_impact: Dict[str, int] = {}
    by_provider: Dict[str, int] = {}
    by_type: Dict[str, int] = {}
    by_risk_category: Dict[str, int] = {}
    unlicensed = 0
    risk_sum = 0.0

    for v in assets:
        impact_raw = (v.get("impact") or "unknown").strip().lower()
        impact = count_label(impact_raw)
        by_impact[impact] = by_impact.get(impact, 0) + 1
        risk_sum += IMPACT_TO_RISK.get(impact_raw, 2.0)

        provider = _provider(v).strip().lower()
        by_provider[provider] = by_provider.get(provider, 0) + 1

        asset_type = (_asset_type(v) or "unknown").strip().lower()
        by_type[asset_type] = by_type.get(asset_type, 0) + 1

        risk_cat = (v.get("risk_category") or "unknown").strip().lower()
        by_risk_category[risk_cat] = by_risk_category.get(risk_cat, 0) + 1

        lic = _license_type(v)
        if (
            asset_type not in ("local_model_file", "huggingface_model", "embedding_model", "external_provider")
            and is_unlicensed_library_gap(lic)
        ):
            unlicensed += 1

    avg_risk = risk_sum / total if total > 0 else 0.0

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
                "Asset type distribution",
                ["Asset type", "Count"],
                [[asset_type.title(), str(cnt)] for asset_type, cnt in sorted(by_type.items(), key=lambda x: -x[1])],
                [4.0 * inch, 1.5 * inch],
            )
        )

    overview = [
        ("Scan type", "AI Bill of Materials (AI BOM)"),
        ("Total AI assets", str(total)),
        ("Unlicensed assets", str(unlicensed)),
        ("External providers", str(len(by_provider))),
        ("Average risk score (0–10)", f"{avg_risk:.1f}"),
        ("Report generated", datetime.now().strftime("%B %d, %Y at %I:%M %p")),
    ]
    append_executive_summary(
        story,
        report_key="ai_bom",
        overview_rows=overview,
        severity_counts=by_impact,
        styles=styles,
        extra_tables=extra_tables or None,
        project_name="AI BOM Findings",
        meta_chips=[
            ("Scan type", "AI BOM"),
            ("Total assets", str(total)),
            ("Report generated", datetime.now().strftime("%b %d, %Y · %I:%M %p")),
            ("Unlicensed", str(unlicensed)),
        ],
    )
    story.append(PageBreak())

    impact_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    sorted_assets = sorted(
        assets,
        key=lambda v: (
            impact_order.get((v.get("impact") or "low").strip().lower(), 4),
            (_asset_name(v) or "").lower(),
        ),
    )

    catalog: List[List[Any]] = []
    for idx, v in enumerate(sorted_assets, 1):
        title = v.get("title") or _asset_name(v) or f"Finding #{idx}"
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
            "Each card includes asset metadata, location, evidence, and remediation.",
            styles["muted"],
        )
    )
    story.append(Spacer(1, 0.1 * inch))

    if total == 0:
        story.append(Paragraph("No AI assets were detected.", styles["body"]))
    else:
        for idx, v in enumerate(sorted_assets, 1):
            title = v.get("title") or _asset_name(v) or f"Finding #{idx}"
            impact = count_label(v.get("impact") or "Unknown")
            standards: List[List[str]] = []
            standards.extend(mapping_rows(v.get("owasp_top_10"), label="OWASP Top 10"))
            standards.extend(mapping_rows(v.get("owasp_top_10_llm"), label="OWASP Top 10 LLM"))
            standards.extend(mapping_rows(v.get("compliance_controls"), label="Compliance"))
            story.append(
                build_finding_section(
                    index=idx,
                    title=str(title),
                    severity=impact,
                    detail_rows=[
                        ("Severity", impact),
                        ("Asset", _asset_name(v) or "—"),
                        ("Type", _asset_type(v) or "—"),
                        ("Provider", _provider(v) or "—"),
                        ("License", _license_type(v) or "—"),
                        ("Framework", str(v.get("framework") or "—")),
                        ("Version", str(v.get("version") or "—")),
                        ("Risk category", str(v.get("risk_category") or "—")),
                        ("Location", str(v.get("location") or "—")),
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
        onFirstPage=make_cover_callback("ai_bom"),
        onLaterPages=make_footer_callback("ai_bom"),
    )
    return output_path


def create_title_page(canvas_obj, doc):
    from backend.utilities.pdf.report_branding import draw_enterprise_cover_page

    draw_enterprise_cover_page(canvas_obj, doc, report_key="ai_bom")


def create_header_footer(canvas_obj, doc):
    from backend.utilities.pdf.report_branding import draw_standard_footer

    draw_standard_footer(canvas_obj, doc, report_key="ai_bom")
