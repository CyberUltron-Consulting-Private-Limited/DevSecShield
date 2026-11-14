"""PDF report of one CBOM Sources run (CB-38 PR-8), in the code-scan CBOM report's branding (``cbom_pdf``: same
masthead, KPI grid, severity bar, catalog panels, header and footer).

Rule P: every readiness, PQC-class, severity-total and posture number is printed from ``posture.run_posture`` as the
caller passes it, never recounted here. The other sections are listings: the heat-map and certificate calendar from
``heatmap.run_heatmap``, the findings from the run CBOM's components (``run_deliverables.summary``, capped at ``PDF_FINDINGS_CAP`` rows, with the
cap stated), provenance from the run's jobs.
"""
from __future__ import annotations

import datetime as _dt
import io
from typing import Any

from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch
from reportlab.platypus import PageBreak, Paragraph, SimpleDocTemplate

from backend.utilities.pdf.report_branding import (
    append_executive_summary,
    append_findings_catalog,
    count_label,
    escape_html,
    get_report_styles,
    key_value_table,
    make_cover_callback,
    make_footer_callback,
    styled_data_table,
)

PQC_LABEL = {"quantum-vulnerable": "Quantum-vulnerable", "hybrid": "Hybrid (post-quantum key exchange)",
             "quantum-safe": "Quantum-safe", "grover-weakened": "Grover-weakened (128-bit symmetric)",
             "not-applicable": "Not applicable (no public-key algorithm)"}
CERT_ROWS = 40
HEAT_COLUMNS = 5
# The findings catalog's panels cannot split across pages (report_branding.panel_wrap): a run's finding sentences
# (230-380 characters for a certificate, an OpenSSL package or a Windows host) wrap to 5-6 lines, so a cell is cut to
# a bounded length and a panel holds fewer rows than the code lane's 18. The full text is in the CBOM and the VEX.
CATALOG_CHUNK = 8
FINDING_CHARS = 110
LOCATION_CHARS = 80
ERROR_CHARS = 160


def readiness_text(value: Any) -> str:
    """How the report prints ``pqc_readiness_pct`` (as the code-scan CBOM PDF prints its readiness)."""
    return "n/a" if value is None else f"{float(value):.1f}%"


def short(text: Any, limit: int) -> str:
    """``text`` cut to ``limit`` characters, ending with an ellipsis when cut."""
    value = " ".join(str(text if text is not None else "").split())
    return value if len(value) <= limit else value[:limit - 1].rstrip() + "\u2026"


def _p(text: Any, styles: dict, style: str = "table_cell") -> Paragraph:
    return Paragraph(escape_html(str(text if text is not None else "—")), styles[style])


def build_run_pdf(*, run: dict[str, Any], sources: list[dict[str, Any]], posture: dict[str, Any],
                  heatmap: dict[str, Any], head: dict[str, Any], findings: list[dict[str, Any]],
                  vex_states: dict[str, int],
                  provenance: list[dict[str, Any]], at: _dt.datetime, as_of_note: str | None,
                  findings_cap: int, export_cap: int, cbom_sha256: str) -> bytes:
    styles = get_report_styles()
    buf = io.BytesIO()
    pdf = SimpleDocTemplate(buf, pagesize=letter, rightMargin=36, leftMargin=36, topMargin=56, bottomMargin=52,
                            title=f"CBOM Sources run #{run['id']}", author="ZeroShield", invariant=1)
    story: list[Any] = []
    meta = {p.get("name"): p.get("value") for p in (head.get("metadata") or {}).get("properties") or []}
    impacts = {k: int(v or 0) for k, v in (posture.get("impacts") or {}).items()}
    findings_total = sum(impacts.values())
    readiness = readiness_text(posture.get("pqc_readiness_pct"))
    source_names = ", ".join(s["name"] for s in sources) or "—"
    generated = at.strftime("%b %d, %Y · %H:%M UTC")  # the run's time (run_deliverables.stamp), not the request's
    truncated = meta.get("zs:truncated") == "true"
    mosca = posture.get("mosca") or {}

    overview = [
        ("Scan type", "CBOM Sources run (collected from infrastructure)"),
        ("Run", f"#{run['id']} · {run['status']}"),
        ("Sources", source_names),
        ("Assets judged", str(posture.get("assets", 0))),
        ("Findings", str(findings_total)),
        ("PQC readiness", readiness),
        ("Report as of", generated),
    ]
    extra_tables = [(
        "Post-quantum and risk posture",
        ["Metric", "Value"],
        [["PQC readiness", readiness],
         ["Harvest-now-decrypt-later assets", str(posture.get("hndl_assets", 0))],
         *[[PQC_LABEL.get(k, k), str(v)] for k, v in (posture.get("pqc_classes") or {}).items()],
         *[[f"Exposure: {k}", str(v)] for k, v in (posture.get("exposure") or {}).items()],
         ["Mosca (X + Y > Z)", str(mosca.get("verdict") or mosca.get("note") or "—")]],
        [3.2 * inch, 3.9 * inch],
    )]
    append_executive_summary(
        story, report_key="cbom", overview_rows=overview, severity_counts={count_label(k): v for k, v in impacts.items() if v},
        styles=styles, extra_tables=extra_tables, project_name=f"Sources run #{run['id']}",
        scan_time=_duration(run), scan_time_hint="Still collecting" if as_of_note else f"Run {run['status']}",
        meta_chips=[("Run", f"#{run['id']} {run['status']}"), ("PQC readiness", readiness),
                    ("Findings", str(findings_total)), ("Report as of", generated)],
    )
    if as_of_note:
        story.append(_p(as_of_note, styles, "body"))
    story.append(Paragraph("Run identity", styles["heading"]))
    story.append(key_value_table([
        ("Run", f"#{run['id']}"), ("Status", run["status"]), ("Sources", source_names),
        ("Started", run.get("created_at") or "—"), ("Finished", run.get("finished_at") or "not yet"),
        ("Data last changed", run.get("last_updated") or "—"),
        ("CBOM serial", str(head.get("serialNumber") or "")), ("CBOM JSON sha256", cbom_sha256),
        ("Knowledge base", str(meta.get("zs:kb_version") or "")), ("Build", str(meta.get("zs:build") or "")),
        ("Judged on", str(meta.get("zs:judged_on") or "the run's own day")),
    ], styles=styles, mono_labels=["CBOM serial", "CBOM JSON sha256", "Build"]))
    if truncated:
        story.append(_p(f"Export cap: the CBOM and this report hold the first {export_cap:,} assets of this run "
                        f"(the posture numbers above cover every asset).", styles, "body"))
    story.append(PageBreak())

    # algorithm family x source
    story.append(Paragraph("Algorithm family by source", styles["heading"]))
    cols = list(heatmap.get("columns") or [])
    shown_cols, rest = cols[:HEAT_COLUMNS], cols[HEAT_COLUMNS:]
    cells = {(c["row"], c["column"]): c for c in heatmap.get("cells") or []}
    heat_rows = []
    for family in heatmap.get("rows") or []:
        line: list[Any] = [family]
        for col in shown_cols:
            cell = cells.get((family, col))
            line.append(f"{cell['count']} (worst {cell['worst']})" if cell else "—")
        if rest:
            line.append(str(sum(cells[(family, c)]["count"] for c in rest if (family, c) in cells)))
        heat_rows.append(line)
    if heat_rows:
        headers = ["Family", *shown_cols, *(["Other sources"] if rest else [])]
        width = 7.1 * inch / len(headers)
        story.append(styled_data_table(headers, heat_rows, styles=styles, col_widths=[width] * len(headers)))
        if rest:
            story.append(_p(f"{len(rest)} more source(s) are summed under Other sources.", styles, "muted"))
    else:
        story.append(_p("No assets were collected.", styles, "muted"))

    # certificate expiry
    certs = list(heatmap.get("certificates") or [])
    story.append(Paragraph("Certificate expiry", styles["heading"]))
    if certs:
        story.append(styled_data_table(
            ["Expires", "Days left", "Subject", "Where", "Source"],
            [[c["not_after"][:10], str(c["days_left"]), _p(c.get("subject") or c.get("name"), styles),
              _p(c.get("location"), styles, "mono_cell"), _p(c.get("source_name"), styles)] for c in certs[:CERT_ROWS]],
            styles=styles, col_widths=[0.9 * inch, 0.7 * inch, 2.2 * inch, 2.0 * inch, 1.3 * inch]))
        if len(certs) > CERT_ROWS or heatmap.get("certificates_truncated"):
            story.append(_p(f"Showing the {CERT_ROWS} soonest of {len(certs)}"
                            + ("+ (the calendar is capped)" if heatmap.get("certificates_truncated") else "")
                            + " certificates; the CycloneDX JSON lists every one.", styles, "muted"))
    else:
        story.append(_p("No certificate with an expiry date was collected.", styles, "muted"))

    # top risks
    story.append(Paragraph("Top risks", styles["heading"]))
    top = posture.get("top_risks") or []
    if top:
        story.append(styled_data_table(
            ["Score", "Severity", "Asset", "Where", "Exposure"],
            [[str(r.get("score")), count_label(r.get("impact") or "low"), _p(r.get("finding") or r.get("name"), styles),
              _p(r.get("location"), styles, "mono_cell"), _p(f"{r.get('exposure')} · {r.get('criticality')}", styles)]
             for r in top],
            styles=styles, severity_col=1, col_widths=[0.65 * inch, 0.85 * inch, 2.5 * inch, 1.9 * inch, 1.2 * inch]))
        story.append(_p("Score = impact weight x business criticality x internet exposure (posture).", styles, "muted"))
    else:
        story.append(_p("No finding to rank.", styles, "muted"))

    # compliance
    story.append(Paragraph("Compliance clauses the findings touch", styles["heading"]))
    clause_rows = [[fw["framework"], _p(c["id"], styles), _p(c.get("text"), styles), str(c["assets"]),
                    _p(", ".join(c.get("codes") or []), styles, "mono_cell")]
                   for fw in posture.get("compliance") or [] for c in fw.get("clauses") or []]
    if clause_rows:
        story.append(styled_data_table(["Framework", "Clause", "Requirement", "Assets", "Finding codes"], clause_rows,
                                       styles=styles,
                                       col_widths=[0.95 * inch, 0.9 * inch, 2.85 * inch, 0.75 * inch, 1.65 * inch]))
    else:
        story.append(_p("No regulatory clause is touched by this run's findings.", styles, "muted"))

    # VEX summary
    if vex_states:
        story.append(Paragraph("VEX analysis (finding x asset pairs)", styles["heading"]))
        story.append(styled_data_table(["State", "Pairs"], [[k, str(v)] for k, v in sorted(vex_states.items())],
                                       styles=styles, col_widths=[3.2 * inch, 1.2 * inch]))
    story.append(PageBreak())

    # findings
    catalog = [[str(i), count_label(f["impact"]),
                _p(f"{short(f['finding'] or f['name'], FINDING_CHARS)} ({f['type']})", styles),
                _p(short(f["location"], LOCATION_CHARS), styles, "mono_cell")]
               for i, f in enumerate(findings[:findings_cap], 1)]
    if len(findings) > findings_cap:
        story.append(_p(f"Findings cap: this report lists the first {findings_cap:,} of {len(findings):,} findings "
                        "(worst first); the CycloneDX JSON and the VEX list them all.", styles, "body"))
    if catalog:
        story.append(_p(f"Finding text is cut to {FINDING_CHARS} characters and locations to {LOCATION_CHARS}; the "
                        "CycloneDX JSON holds the full sentences.", styles, "muted"))
    append_findings_catalog(story, catalog_rows=catalog, styles=styles, panel_title="Findings",
                            chunk_size=CATALOG_CHUNK)

    # provenance
    story.append(PageBreak())
    story.append(Paragraph("Provenance", styles["heading"]))
    if provenance:
        story.append(styled_data_table(
            ["Source", "Scan node", "Job", "Outcome", "Assets", "Duration"],
            [[_p(p["source"], styles), _p(p.get("node"), styles), f"{p['kind']} · {p['status']}",
              _p(str(p.get("outcome") or "—") + (f": {short(p['error'], ERROR_CHARS)}" if p.get("error") else ""),
                 styles), str(p.get("assets") or 0),
              f"{p['duration_s']} s" if p.get("duration_s") is not None else "—"] for p in provenance],
            styles=styles, col_widths=[1.4 * inch, 1.2 * inch, 1.2 * inch, 1.8 * inch, 0.7 * inch, 0.8 * inch]))
    else:
        story.append(_p("No job ran.", styles, "muted"))
    story.append(_p("Every number on the posture panel comes from the run posture API (the same values the results "
                    "page shows); listings come from the run's CycloneDX export.", styles, "muted"))

    pdf.build(story, onFirstPage=make_cover_callback("cbom"), onLaterPages=make_footer_callback("cbom"))
    return buf.getvalue()


def _duration(run: dict[str, Any]) -> str:
    start, end = run.get("created_at"), run.get("finished_at")
    if not start or not end:
        return "—"
    try:
        a = _dt.datetime.fromisoformat(str(start).rstrip("Z"))
        b = _dt.datetime.fromisoformat(str(end).rstrip("Z"))
    except ValueError:
        return "—"
    seconds = int((b - a).total_seconds())
    return f"{seconds // 60}m {seconds % 60}s" if seconds >= 60 else f"{seconds}s"
