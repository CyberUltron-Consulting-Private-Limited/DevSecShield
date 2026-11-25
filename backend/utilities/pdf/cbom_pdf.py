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

from backend.utilities.pdf.cbom_inventory_pdf import append_cbom_inventory
from backend.utilities.pdf.report_context import ReportContext, details_note, join_parts
from backend.utilities.pdf.report_branding import (
    report_generated,
    append_report_masthead,
    append_bom_compliance_sections,
    CBOM_METHOD_NOTE,
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


_NOT_CRYPTO_NOTE = (
    "{n} component(s) of the file are not cryptographic assets (for example libraries or applications) and were not "
    "judged here: a library's known vulnerabilities come from a code scan or the dependency scan."
)  # the results page's sentence (frontend components/cbom/importNotes.ts notCryptoNote)


def scan_notes(raw: Any) -> Optional[tuple[str, str, List[str]]]:
    """The notes the results page shows above the table, as ``(title, summary, lines)``; None when it shows none.

    * an uploaded CBOM file: the import report (``cbom_input``): what was imported, skipped or truncated, the engine's
      notes, then the sentence about non-cryptographic components (shown when the import left something out, as
      the page's ``importReportHasNews``);
    * a code scan: the coverage notes from the CycloneDX ``crypto:coverage:*`` properties (archives, images,
      binaries and firmware it skipped or only counted), as ``cbom_coverage.coverage_report``.
    """
    if not isinstance(raw, dict):
        return None
    from backend.utilities.dashboard.scan_metadata import _cbom_input

    report = _cbom_input(raw.get("cbom_input"))
    if report is not None:
        notes = list(report.get("notes") or [])
        not_crypto = int(report.get("skipped_not_crypto") or 0)
        news = (notes or not_crypto or report.get("skipped_invalid") or report.get("duplicates")
                or report.get("truncated") or not report.get("imported"))
        if not news:
            return None
        parts = [f"{report.get('imported') or 0} of {report.get('crypto_assets') or 0} cryptographic assets imported"]
        if report.get("spec_version"):
            parts.append(f"CycloneDX {report['spec_version']}")
        if not_crypto:
            parts.append(f"{not_crypto} non-crypto components skipped")
        if report.get("skipped_invalid"):
            parts.append(f"{report['skipped_invalid']} unreadable")
        if report.get("duplicates"):
            parts.append(f"{report['duplicates']} duplicates")
        if report.get("truncated"):
            parts.append("truncated")
        if not_crypto:
            notes.append(_NOT_CRYPTO_NOTE.format(n=not_crypto))
        return "About the uploaded CBOM file", " · ".join(parts), notes
    from backend.utilities.dashboard.cbom_coverage import coverage_report

    coverage = coverage_report(raw.get("cbom_json"))
    if not coverage or not coverage.get("notes"):
        return None
    skipped = int(coverage.get("skipped") or 0)
    summary = (
        f"{skipped} kind(s) of input were skipped or only partly read; the CycloneDX file lists the same counts "
        "(crypto:coverage:*)."
        if skipped
        else "Nothing was skipped; these notes say what was read and are also in the CycloneDX file (crypto:coverage:*)."
    )
    return "What this scan covered", summary, [str(n.get("text") or "") for n in coverage["notes"]]


def advisory_text(raw: Any) -> str | None:
    """"OSV snapshot 2026.11.14.1, data as of 2026-11-14" (+ stale / refreshed online), from the run's
    ``advisory_data`` (CB-29); None for scans made before the snapshot existed."""
    data = raw.get("advisory_data") if isinstance(raw, dict) else None
    if not isinstance(data, dict) or not data.get("generated_at"):
        return None
    text = f"OSV snapshot {data.get('snapshot_version') or '?'}, data as of {data['generated_at']}"
    if data.get("stale"):
        text += f" (stale: {data.get('age_days')} days old)"
    online = data.get("online") if isinstance(data.get("online"), dict) else None
    if online:
        text += f"; refreshed online for {online.get('answered', 0)} of {online.get('asked', 0)} package(s)"
    return text


def generate_pdf(scan_results: Union[dict, list], output_path: Optional[str] = None, *, ctx: Optional[ReportContext] = None) -> str:
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
    kept_rows = finding_rows(rows)
    vulnerabilities = [display_row(v) for v in kept_rows]
    # Stored rows (and statuses) are every scan_data row in order; remember each finding's position.
    raw_pos = {id(r): i for i, r in enumerate(rows)}
    pos_of_display = {id(d): raw_pos.get(id(r)) for d, r in zip(vulnerabilities, kept_rows)}
    _inner, duration, raw = split_scan_payload(scan_results)
    total = len(vulnerabilities)

    by_impact: Dict[str, int] = {count_label(s): n for s, n in summary.severity.items() if n}
    by_type: Dict[str, int] = {str(k).strip().lower(): v for k, v in summary.algorithm_types.items()}
    quantum_vulnerable = summary.quantum["quantum_vulnerable"]
    quantum_safe_count = summary.quantum["quantum_safe"]
    broken_today = summary.quantum["broken_today"]  # the results table's "Broken today": not counted as quantum-safe
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
                ["Broken today (classically broken, not quantum-safe)", str(broken_today)],
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
        ("Broken today", str(broken_today)),
        ("Average risk score (0–10)", f"{avg_risk:.1f}"),
        ("Report generated", report_generated(long=True)),
    ]
    advisory = advisory_text(raw)
    if advisory:  # CB-29: which crypto-library advisory data the scan matched, and how old it is
        overview.append(("Library advisory data", advisory))
    ctx = ctx or ReportContext()
    impact_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    sorted_vulns = sorted(
        vulnerabilities,
        key=lambda v: (
            impact_order.get((v.get("impact") or "low").strip().lower(), 4),
            (v.get("algorithm_name") or "").lower(),
        ),
    )
    shown = ctx.select(sorted_vulns, lambda v: count_label(finding_severity(v) or "low"),
                       lambda _i, v: pos_of_display.get(id(v)))

    summary_part: List[Any] = []
    if not ctx.has("summary"):
        append_report_masthead(summary_part, report_key="cbom", project_name="CBOM Findings", styles=styles, ctx=ctx)
    else:
      append_executive_summary(
        summary_part,
        report_key="cbom",
        # the headline is the shared posture: print its method and what a CBOM leaves out (#505 round 4)
        posture_method=True, method_note=CBOM_METHOD_NOTE,
        overview_rows=overview,
        severity_counts=by_impact,
        styles=styles,
        extra_tables=extra_tables,
        project_name="CBOM Findings",
        scan_time=format_scan_duration(duration),
        meta_chips=[
            ("Scan type", "CBOM"),
            ("Total findings", str(total)),
            ("Report generated", report_generated()),
            ("Quantum-vulnerable", str(quantum_vulnerable)),
        ],
        ctx=ctx,
      )
    notes = scan_notes(raw if raw else scan_results)
    if notes and ctx.has("notes"):  # the import / coverage notes the results page shows above the table
        title, summary_line, lines = notes
        summary_part.append(Spacer(1, 0.15 * inch))
        summary_part.append(Paragraph(escape_html(title), styles["heading"]))
        summary_part.append(Paragraph(escape_html(summary_line), styles["muted"]))
        for line in lines:
            summary_part.append(Paragraph("- " + escape_html(line), styles["body"]))

    catalog_part: List[Any] = []
    catalog: List[List[Any]] = []
    for idx, v in shown if ctx.has("catalog") else ():
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
    if ctx.has("catalog"):
        append_findings_catalog(catalog_part, catalog_rows=catalog, styles=styles, ctx=ctx)

    details: List[Any] = []
    if ctx.has("details"):
        details.append(Paragraph("Detailed Findings", styles["title"]))
        details.append(
            Paragraph(
                details_note(ctx, "Each card includes algorithm metadata, location, evidence, and remediation."),
                styles["muted"],
            )
        )
        details.append(Spacer(1, 0.1 * inch))
        if informational:
            payload = raw if raw else (scan_results if isinstance(scan_results, dict) else {})
            bom = payload.get("cbom_json") if isinstance(payload, dict) else None
            where = ("in the cryptographic inventory at the end of this report"
                     if isinstance(bom, dict) and bom.get("components") else "in the CycloneDX download")
            details.append(Paragraph(
                f"{informational} clean inventory item(s) with no finding are listed {where}.", styles["muted"]))

    if not ctx.has("details"):
        pass
    elif not shown:
        details.append(Paragraph(escape_html(ctx.empty_text("No cryptographic findings were detected.")), styles["body"]))
    else:
        for idx, v in shown:
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
            details.append(
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
                    ctx=ctx,
                )
            )

    join_parts(story, [summary_part, catalog_part, details], PageBreak)
    if ctx.has("details"):  # SOW D3: the full inventory, every asset with or without a finding
        append_cbom_inventory(story, raw if raw else (scan_results if isinstance(scan_results, dict) else {}),
                              styles)
    if ctx.has("compliance"):
        appendix_payload = raw if raw else (scan_results if isinstance(scan_results, dict) else {})
        append_bom_compliance_sections(story, appendix_payload, styles)

    doc.build(
        story,
        onFirstPage=make_cover_callback("cbom", ctx),
        onLaterPages=make_footer_callback("cbom", ctx),
    )
    return output_path


def create_title_page(canvas_obj, doc):
    from backend.utilities.pdf.report_branding import draw_enterprise_cover_page

    draw_enterprise_cover_page(canvas_obj, doc, report_key="cbom")


def create_header_footer(canvas_obj, doc):
    from backend.utilities.pdf.report_branding import draw_standard_footer

    draw_standard_footer(canvas_obj, doc, report_key="cbom")
