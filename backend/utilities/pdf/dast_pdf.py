"""
DAST Scan Results PDF Generator
Human-readable enterprise report with tabular summary and detailed findings.
"""

from __future__ import annotations

import json
import os
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch
from reportlab.platypus import PageBreak, Paragraph, SimpleDocTemplate, Spacer

from backend.utilities.pdf.report_context import ReportContext, details_note, join_parts
from backend.utilities.pdf.report_branding import (
    report_generated,
    append_report_masthead,
    append_executive_summary,
    compute_posture_risk_score,
    append_findings_catalog,
    build_finding_section,
    count_label,
    escape_html,
    format_scan_duration,
    get_report_styles,
    make_cover_callback,
    make_footer_callback,
    mapping_rows,
    severity_color,
    split_scan_payload,
)


def _normalize_scan_data(scan_data: Any) -> Tuple[List[Dict[str, Any]], Optional[float], Optional[Dict]]:
    inner, duration, raw = split_scan_payload(scan_data)
    if isinstance(inner, list):
        results = [row for row in inner if isinstance(row, dict)]
    else:
        results = []
    metadata = raw.get("metadata") if isinstance(raw, dict) else None
    if metadata is not None and not isinstance(metadata, dict):
        metadata = None
    return results, duration, metadata


def _format_owasp_compliance_dict(d: Any) -> List[List[str]]:
    if not d or not isinstance(d, dict):
        return []
    return [[str(k), str(v)] for k, v in d.items() if v]


def get_impact_color(impact: str):
    return severity_color(impact)


def generate_pdf(scan_data: Any, output_path: Optional[str] = None, *, ctx: Optional[ReportContext] = None) -> str:
    if output_path is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = f"dast_scan_report_{timestamp}.pdf"

    ctx = ctx or ReportContext()
    results, duration_of_scan, metadata = _normalize_scan_data(scan_data)
    total = len(results)
    # Stored finding rows follow the raw results list (non-dict rows included).
    inner_rows = split_scan_payload(scan_data)[0]
    raw_positions = ([i for i, row in enumerate(inner_rows) if isinstance(row, dict)]
                     if isinstance(inner_rows, list) else list(range(total)))
    shown = ctx.select(results, lambda r: count_label(r.get("impact") or "Unknown"),
                       lambda i, _r: raw_positions[i] if i < len(raw_positions) else None)

    by_impact: Dict[str, int] = {}
    by_confidence: Dict[str, int] = {}
    by_category: Dict[str, int] = {}
    for r in results:
        impact = count_label(r.get("impact") or "Unknown")
        by_impact[impact] = by_impact.get(impact, 0) + 1
        conf = count_label(r.get("confidence") or "Unknown")
        by_confidence[conf] = by_confidence.get(conf, 0) + 1
        cat = (r.get("category") or "Other").strip().replace("_", " ") or "Other"
        by_category[cat] = by_category.get(cat, 0) + 1

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
        ("Scan type", "Dynamic Application Security Testing (DAST)"),
        ("Total issues found", str(total)),
        ("Report generated", report_generated(long=True)),
    ]
    if duration_of_scan is not None:
        overview.append(("Scan duration", format_scan_duration(duration_of_scan)))

    extra_tables = []
    url_rows: List[List[str]] = []
    if metadata and isinstance(metadata, dict):
        urls_in = metadata.get("urls_included")
        urls_ex = metadata.get("urls_excluded")
        if isinstance(urls_in, list):
            overview.append(("URLs included", str(len(urls_in))))
            url_rows.append(["URLs included", str(len(urls_in))])
        if isinstance(urls_ex, list):
            overview.append(("URLs excluded", str(len(urls_ex))))
            url_rows.append(["URLs excluded", str(len(urls_ex))])
    if url_rows:
        extra_tables.append(
            (
                "Scan coverage",
                ["Metric", "Count"],
                url_rows,
                [4.0 * inch, 1.5 * inch],
            )
        )
    conf_rows = [[level, str(by_confidence[level])] for level in ["High", "Medium", "Low", "Unknown"] if by_confidence.get(level)]
    if conf_rows:
        extra_tables.append(
            (
                "Confidence of findings",
                ["Confidence", "Count"],
                conf_rows,
                [2.5 * inch, 1.5 * inch],
            )
        )
    cat_rows = [[cat, str(count)] for cat, count in sorted(by_category.items(), key=lambda x: -x[1])]
    if cat_rows:
        extra_tables.append(
            (
                "Issues by category",
                ["Category", "Count"],
                cat_rows,
                [4.0 * inch, 1.5 * inch],
            )
        )

    duration_label = format_scan_duration(duration_of_scan)
    summary: List[Any] = []
    if not ctx.has("summary"):
        append_report_masthead(summary, report_key="dast", project_name="DAST Findings", styles=styles, ctx=ctx)
    else:
      append_executive_summary(
        summary,
        report_key="dast",
        overview_rows=overview,
        severity_counts=by_impact,
        styles=styles,
        extra_tables=extra_tables,
        project_name="DAST Findings",
        scan_time=duration_label,
        # the one 0-100 score of every product (risk_scale.posture): capped by the worst severity, as the
        # list pages and the AI BOM / CBOM PDFs, not the uncapped compute_risk_score
        risk_score_fn=compute_posture_risk_score,
        meta_chips=[
            ("Scan type", "DAST"),
            ("Total issues", str(total)),
            ("Report generated", report_generated()),
            ("Scan duration", duration_label),
        ],
        ctx=ctx,
      )

    catalog_part: List[Any] = []
    catalog: List[List[Any]] = []
    for idx, r in shown if ctx.has("catalog") else ():
        title = (r.get("title") or "Finding").strip() or "Finding"
        impact = (r.get("impact") or "Unknown").strip() or "Unknown"
        url = (r.get("url") or "—").strip() or "—"
        catalog.append(
            [
                str(idx),
                impact,
                Paragraph(escape_html(title), styles["table_cell"]),
                Paragraph(escape_html(url), styles["mono_cell"]),
            ]
        )
    if ctx.has("catalog"):
        append_findings_catalog(catalog_part, catalog_rows=catalog, styles=styles, ctx=ctx)

    details: List[Any] = []
    if ctx.has("details"):
        details.append(Paragraph("Detailed Findings", styles["title"]))
        details.append(
            Paragraph(
                details_note(ctx, "Each card shows the affected URL, description, and remediation. URLs render in monospace."),
                styles["muted"],
            )
        )
        details.append(Spacer(1, 0.1 * inch))

    if not ctx.has("details"):
        pass
    elif not shown:
        details.append(Paragraph(escape_html(ctx.empty_text("No security findings were identified in this scan.")), styles["body"]))
    else:
        for idx, r in shown:
            title = (r.get("title") or "Finding").strip() or "Finding"
            url = (r.get("url") or "").strip() or "—"
            impact = (r.get("impact") or "Unknown").strip() or "Unknown"
            confidence = (r.get("confidence") or "—").strip() or "—"
            category = (r.get("category") or "—").strip().replace("_", " ") or "—"
            description = (r.get("description") or "No description available").strip()
            suggested_fix = (r.get("suggested_fix") or "").strip()

            standards: List[List[str]] = []
            standards.extend(mapping_rows(r.get("owasp_top_10"), label="OWASP Top 10"))
            standards.extend(mapping_rows(r.get("compliance_controls"), label="Compliance"))

            details.append(
                build_finding_section(
                    index=idx,
                    title=title,
                    severity=impact,
                    detail_rows=[
                        ("Severity", impact),
                        ("Confidence", confidence),
                        ("Category", category),
                        ("Affected URL", url[:300]),
                    ],
                    description=description,
                    evidence="",
                    recommended_fix=suggested_fix,
                    standards_rows=standards or None,
                    styles=styles,
                    ctx=ctx,
                )
            )

    join_parts(story, [summary, catalog_part, details], PageBreak)
    doc.build(
        story,
        onFirstPage=make_cover_callback("dast", ctx),
        onLaterPages=make_footer_callback("dast", ctx),
    )
    return output_path


def create_title_page(canvas_obj, doc) -> None:
    from backend.utilities.pdf.report_branding import draw_enterprise_cover_page

    draw_enterprise_cover_page(canvas_obj, doc, report_key="dast")


def create_header_footer(canvas_obj, doc) -> None:
    from backend.utilities.pdf.report_branding import draw_standard_footer

    draw_standard_footer(canvas_obj, doc, report_key="dast")


if __name__ == "__main__":
    test_path = os.path.normpath(
        os.path.join(os.path.dirname(__file__), "..", "..", "..", "RabbitMQ", "dast_worker", "dast_results_testing.json")
    )
    out_dir = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "generated_reports"))
    os.makedirs(out_dir, exist_ok=True)
    out = os.path.join(out_dir, "DAST_Enterprise_Report.pdf")
    if os.path.exists(test_path):
        with open(test_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        print(generate_pdf(data, out))
    else:
        print(
            generate_pdf(
                [
                    {
                        "title": "Sample XSS",
                        "url": "https://example.com/page",
                        "confidence": "high",
                        "impact": "High",
                        "category": "xss_and_client_side",
                        "description": "Sample description.",
                        "suggested_fix": "Encode output.",
                        "owasp_top_10": {"INJECTION": "A03:2021 - Injection"},
                        "compliance_controls": {},
                    }
                ],
                out,
            )
        )
