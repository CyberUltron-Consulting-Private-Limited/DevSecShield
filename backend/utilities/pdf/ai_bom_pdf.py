"""
AI-BOM (AI Bill of Materials) Scan Results PDF Generator.
Human-readable enterprise report from AI-BOM scan results.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional, Union

from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch
from reportlab.platypus import CondPageBreak, KeepTogether, PageBreak, Paragraph, SimpleDocTemplate, Spacer

from backend.utilities.dashboard.aibom_license import (
    is_unlicensed_library_gap,
    resolve_aibom_license,
)
from backend.utilities.dashboard.aibom_provider import resolve_aibom_provider
from backend.utilities.dashboard.rbi_posture import build_rbi_csf_rollup
from backend.utilities.dashboard.risk_scale import average_risk_of
from backend.utilities.pdf.report_context import ReportContext, details_note, join_parts
from backend.utilities.pdf.report_branding import (
    report_generated,
    append_report_masthead,
    append_bom_compliance_sections,
    append_executive_summary,
    append_findings_catalog,
    build_finding_section,
    compute_posture_risk_score,
    styled_data_table,
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

# The SOW AI BOM checks (CERT-In AIBOM, RBI FREE-AI, SEBI CSCRF, NIST AI RMF, EU AI Act Annex IV), in report
# order, keyed as the engine's compliance report (aibom.compliance) keys them. The healthcare frameworks follow only
# when the scan is in their scope.
SOW_FRAMEWORKS: tuple[tuple[str, str], ...] = (
    ("cert_in_aibom", "CERT-In AIBOM (Technical Guidelines v2.0, Table 10)"),
    ("rbi_free_ai", "RBI FREE-AI Framework (2025)"),
    ("sebi_cscrf_aibom", "SEBI CSCRF"),
    ("nist_rmf", "NIST AI RMF 1.0"),
    ("eu_ai_act_annexIV", "EU AI Act Annex IV"),
)
HEALTHCARE_FRAMEWORKS: tuple[tuple[str, str], ...] = (
    ("fda_524b", "FDA Section 524B"),
    ("hipaa", "HIPAA"),
    ("gmlp", "FDA GMLP"),
)
VERDICT_LABEL = {
    "pass": "Pass",
    "pass_with_evidence": "Pass (attested)",
    "fail": "Fail",
    "not_bom_evidenceable": "Needs evidence",
    "out_of_scope": "Out of scope",
    "na": "Not applicable",
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
    inner, _duration, _raw = split_scan_payload(scan_results)
    if isinstance(inner, list):
        return inner
    if isinstance(inner, dict) and "results" in inner:
        return inner["results"] or []
    return []


def generate_pdf(scan_results: Union[dict, list], output_path: Optional[str] = None, *, ctx: Optional[ReportContext] = None) -> str:
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
    _inner, duration, raw = split_scan_payload(scan_results)
    total = len(assets)

    by_impact: Dict[str, int] = {}
    by_provider: Dict[str, int] = {}
    by_type: Dict[str, int] = {}
    by_risk_category: Dict[str, int] = {}
    unlicensed = 0

    for v in assets:
        impact_raw = (v.get("impact") or "unknown").strip().lower()
        impact = count_label(impact_raw)
        by_impact[impact] = by_impact.get(impact, 0) + 1

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

    # One scale with the dashboard card (risk_scale: Critical 10, High 7.5, Medium 5, Low 2.5).
    avg_risk = average_risk_of(v.get("impact") for v in assets) or 0.0

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

    scope_rows = [
        ("Average risk score (0–10)", f"{avg_risk:.1f}"),
        *_bom_scope_rows(raw if raw else (scan_results if isinstance(scan_results, dict) else {})),
    ]

    overview = [
        ("Scan type", "AI Bill of Materials (AI BOM)"),
        ("Total AI assets", str(total)),
        ("Unlicensed assets", str(unlicensed)),
        ("External providers", str(len(by_provider))),
        ("Average risk score (0–10)", f"{avg_risk:.1f}"),
        ("Report generated", report_generated(long=True)),
    ]
    ctx = ctx or ReportContext()
    impact_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    sorted_assets = sorted(
        assets,
        key=lambda v: (
            impact_order.get((v.get("impact") or "low").strip().lower(), 4),
            (_asset_name(v) or "").lower(),
        ),
    )
    # Stored rows (and statuses) follow the unsorted results list.
    raw_pos = {id(row): i for i, row in enumerate(assets)}
    shown = ctx.select(sorted_assets, lambda v: count_label(v.get("impact") or "Unknown"),
                       lambda _i, v: raw_pos.get(id(v)))

    summary: List[Any] = []
    if not ctx.has("summary"):
        append_report_masthead(summary, report_key="ai_bom", project_name="AI BOM Findings", styles=styles, ctx=ctx)
    else:
      append_executive_summary(
        summary,
        report_key="ai_bom",
        overview_rows=overview,
        severity_counts=by_impact,
        styles=styles,
        extra_tables=extra_tables or None,
        project_name="AI BOM Findings",
        scan_time=format_scan_duration(duration),
        # the grade never claims a worse posture than the worst severity found (same formula as the engine's score)
        risk_score_fn=compute_posture_risk_score,
        meta_chips=[
            ("Scan type", "AI BOM"),
            ("Total assets", str(total)),
            ("Report generated", report_generated()),
            ("Unlicensed", str(unlicensed)),
        ],
        ctx=ctx,
      )

    catalog_part: List[Any] = []
    catalog: List[List[Any]] = []
    for idx, v in shown if ctx.has("catalog") else ():
        title = v.get("title") or _asset_name(v) or f"Finding #{idx}"
        impact = count_label(v.get("impact") or "Unknown")
        location = finding_location(v)
        catalog.append(
            [
                str(idx),
                impact,
                Paragraph(escape_html(str(title)), styles["table_cell"]),
                Paragraph(escape_html(location), styles["mono_cell"]),
            ]
        )
    if ctx.has("catalog"):
        append_findings_catalog(catalog_part, catalog_rows=catalog, styles=styles, ctx=ctx)

    details: List[Any] = []
    if ctx.has("details"):
        details.append(Paragraph("Detailed Findings", styles["title"]))
        details.append(
            Paragraph(
                details_note(ctx, "Each card includes asset metadata, location, evidence, and remediation."),
                styles["muted"],
            )
        )
        details.append(Spacer(1, 0.1 * inch))

    if not ctx.has("details"):
        pass
    elif not shown:
        details.append(Paragraph(escape_html(ctx.empty_text("No AI assets were detected.")), styles["body"]))
    else:
        for idx, v in shown:
            title = v.get("title") or _asset_name(v) or f"Finding #{idx}"
            impact = count_label(v.get("impact") or "Unknown")
            standards: List[List[str]] = []
            standards.extend(mapping_rows(v.get("owasp_top_10"), label="OWASP Top 10"))
            standards.extend(mapping_rows(v.get("owasp_top_10_llm"), label="OWASP Top 10 LLM"))
            standards.extend(mapping_rows(v.get("compliance_controls"), label="Compliance"))
            details.append(
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
                        ("Where it was found", finding_location(v)),
                    ],
                    description=str(v.get("description") or ""),
                    evidence=str(v.get("snippet") or ""),
                    recommended_fix=str(v.get("suggested_fix") or ""),
                    standards_rows=standards or None,
                    styles=styles,
                    ctx=ctx,
                )
            )

    join_parts(story, [summary, catalog_part, details], PageBreak)
    if ctx.has("summary"):
        # what the AI BOM counted and left out, and the average on the dashboard's 0-10 scale; the heading never
        # sits alone at the foot of a page
        story.append(Spacer(1, 0.15 * inch))
        story.append(KeepTogether([
            Paragraph("What this AI BOM counts", styles["heading"]),
            styled_data_table(["Measure", "Value"], [[label, value] for label, value in scope_rows],
                              styles=styles, col_widths=[4.0 * inch, 1.5 * inch]),
        ]))
    if ctx.has("compliance"):
        appendix_payload = raw if raw else (scan_results if isinstance(scan_results, dict) else {})
        if append_aibom_regulatory_checks(story, appendix_payload, styles):
            # every framework and requirement is listed above: only the RBI pillar rollup is new
            append_rbi_pillar_rollup(story, appendix_payload, styles)
        else:  # a stored scan without the engine's compliance report: the older appendix
            append_bom_compliance_sections(story, appendix_payload, styles)

    doc.build(
        story,
        onFirstPage=make_cover_callback("ai_bom", ctx),
        onLaterPages=make_footer_callback("ai_bom", ctx),
    )
    return output_path


def _bom_props(payload: Any) -> Dict[str, str]:
    bom = payload.get("ai_bom_json") if isinstance(payload, dict) else None
    meta = bom.get("metadata") if isinstance(bom, dict) else None
    props = meta.get("properties") if isinstance(meta, dict) else None
    return {str(p.get("name")): str(p.get("value")) for p in props or [] if isinstance(p, dict)}


def _bom_scope_rows(payload: Any) -> List[tuple]:
    """What the AI BOM counted and what it left out (catalog mentions, test-only references, non-AI dependencies)."""
    bom = payload.get("ai_bom_json") if isinstance(payload, dict) else None
    rows: List[tuple] = []
    if isinstance(bom, dict):
        comps = [c for c in bom.get("components") or [] if isinstance(c, dict)]
        kinds = [_model_kind(c) for c in comps if c.get("type") == "machine-learning-model"]
        # the models the compliance checks assess ("all N model(s)"): weight files and catalog / test mentions apart
        rows.append(("Models in use", str(kinds.count("model"))))
        if kinds.count("weights"):
            rows.append(("Model weight files", str(kinds.count("weights"))))
        rows.append(("AI services and endpoints", str(len(bom.get("services") or []))))
    props = _bom_props(payload)
    for key, label in (
        ("aibom:model_mentions_catalog", "Model names only listed in catalogs (not counted)"),
        ("aibom:model_mentions_test", "Model names only in test code (not counted)"),
        ("aibom:dependencies_excluded_non_ai", "Non-AI dependencies (in the SBOM, not here)"),
        ("aibom:dependencies_excluded_dev_tools", "Development and test tools (not counted)"),
    ):
        if props.get(key):
            rows.append((label, props[key]))
    return rows


def _model_kind(comp: dict) -> str:
    """``model`` (a model the application uses), ``weights`` (a weight file) or ``mention`` (a model only named in a
    catalog, a document or a test: kept in the BOM, not counted)."""
    props = {str(p.get("name")): str(p.get("value")) for p in comp.get("properties") or [] if isinstance(p, dict)}
    if props.get("model:weight_file") == "true":
        return "weights"
    if props.get("model:reference_type") in ("catalog", "test"):
        return "mention"
    return "model"


_ID_COL = 1.45 * inch


def _breakable(text: str, style: Any, width: float = _ID_COL - 18) -> str:
    """Escaped text wrapped at its hyphens to fit ``width`` (requirement ids such as T10-ML-Models-and-Algorithms),
    so a line never breaks in the middle of a word. A single part wider than the column is left to the paragraph."""
    from reportlab.pdfbase.pdfmetrics import stringWidth

    parts = [p + "-" for p in text.split("-")]
    parts[-1] = parts[-1][:-1]
    lines: List[str] = []
    line = ""
    for part in parts:
        if line and stringWidth(line + part, style.fontName, style.fontSize) > width:
            lines.append(line)
            line = part
        else:
            line += part
    lines.append(line)
    return "<br/>".join(escape_html(x) for x in lines if x)


def _framework_rows(fw: dict, styles: Dict[str, Any]) -> List[List[Any]]:
    rows: List[List[str]] = []
    for req in fw.get("requirements") or []:
        if not isinstance(req, dict):
            continue
        verdict = str(req.get("verdict") or "")
        evidence = str(req.get("evidence") or "")
        if len(evidence) > 220:
            evidence = evidence[:217] + "..."
        rows.append([
            Paragraph(_breakable(str(req.get("id") or ""), styles["table_cell"]), styles["table_cell"]),
            str(req.get("title") or ""),
            VERDICT_LABEL.get(verdict, verdict or "—"),
            evidence or "—",
        ])
    return rows


def append_aibom_regulatory_checks(story: List[Any], payload: Any, styles: Dict[str, Any]) -> bool:
    """The SOW AI BOM regulatory checks, computed by the engine from the BOM's fields and graph: a summary per
    framework and every requirement with its verdict and evidence. Healthcare frameworks only when in scope.
    True when the section was written."""
    compliance = payload.get("ai_bom_compliance") if isinstance(payload, dict) else None
    if not isinstance(compliance, dict):
        return False
    shown = [(k, label) for k, label in SOW_FRAMEWORKS if isinstance(compliance.get(k), dict)]
    for key, label in HEALTHCARE_FRAMEWORKS:
        fw = compliance.get(key)
        if isinstance(fw, dict) and any(int(fw.get(n) or 0) for n in ("pass", "pass_with_evidence", "fail",
                                                                         "not_bom_evidenceable")):
            shown.append((key, label))
    if not shown:
        return False
    story.append(CondPageBreak(3.5 * inch))  # a new page unless most of one is left (never a blank page)
    story.append(Paragraph("AI BOM regulatory checks", styles["title"]))
    story.append(Paragraph(
        "Each requirement is checked against the fields and relationships recorded in this AI BOM. Pass: the BOM "
        "shows it. Fail: the BOM shows it is missing. Needs evidence: an organisational control the BOM cannot show; "
        "attach an attestation on the results page. Coverage = pass / (pass + fail).", styles["muted"]))
    summary = []
    for key, label in shown:
        fw = compliance[key]
        cov = fw.get("coverage")
        summary.append([
            label,
            str(int(fw.get("pass") or 0) + int(fw.get("pass_with_evidence") or 0)),
            str(fw.get("fail") or 0),
            str(fw.get("not_bom_evidenceable") or 0),
            "n/a" if cov is None else f"{round(float(cov) * 100)}%",
        ])
    story.append(styled_data_table(["Framework", "Pass", "Fail", "Needs evidence", "Coverage"], summary,
                                   styles=styles, col_widths=[3.2 * inch, 0.8 * inch, 0.8 * inch, 1.1 * inch,
                                                              0.9 * inch]))
    for key, label in shown:
        rows = _framework_rows(compliance[key], styles)
        if not rows:
            continue
        story.append(Spacer(1, 0.12 * inch))
        story.append(CondPageBreak(1.3 * inch))  # a framework heading never sits alone at the foot of a page
        story.append(Paragraph(escape_html(label), styles["heading"]))
        story.append(styled_data_table(["Requirement", "Title", "Result", "Evidence"], rows, styles=styles,
                                       col_widths=[_ID_COL, 1.75 * inch, 0.9 * inch, 2.7 * inch]))
    disclaimer = compliance.get("disclaimer")
    if disclaimer:
        story.append(Spacer(1, 0.08 * inch))
        story.append(Paragraph(escape_html(disclaimer), styles["muted"]))
    return True


def append_rbi_pillar_rollup(story: List[Any], payload: Any, styles: Dict[str, Any]) -> None:
    """The RBI cyber-security framework pillars over the AI BOM's checks (the RBI appendix's one table the
    regulatory checks above do not already show)."""
    ai = payload.get("ai_bom_compliance") if isinstance(payload, dict) else None
    rollup = (payload.get("rbi_csf_rollup") if isinstance(payload, dict) else None) or build_rbi_csf_rollup(
        ai_bom_compliance=ai if isinstance(ai, dict) else None, cbom_compliance=None, sbom_compliance=None)
    pillars = rollup.get("rbi_csf_rollup") if isinstance(rollup, dict) else None
    if not isinstance(pillars, dict) or not pillars:
        return
    rows = []
    for name, data in pillars.items():
        if not isinstance(data, dict):
            continue
        cov = data.get("coverage")
        rows.append([str(name).replace("_", " ").capitalize(), str(data.get("pass", 0)), str(data.get("fail", 0)),
                     "n/a" if cov is None else f"{round(float(cov) * 100)}%"])
    if not rows:
        return
    story.append(Spacer(1, 0.15 * inch))
    story.append(KeepTogether([
        Paragraph("RBI cyber-security framework pillars", styles["heading"]),
        styled_data_table(["Pillar", "Pass", "Fail", "Coverage"], rows, styles=styles,
                          col_widths=[3.2 * inch, 0.8 * inch, 0.8 * inch, 0.9 * inch]),
    ]))


def create_title_page(canvas_obj, doc):
    from backend.utilities.pdf.report_branding import draw_enterprise_cover_page

    draw_enterprise_cover_page(canvas_obj, doc, report_key="ai_bom")


def create_header_footer(canvas_obj, doc):
    from backend.utilities.pdf.report_branding import draw_standard_footer

    draw_standard_footer(canvas_obj, doc, report_key="ai_bom")
