"""PDF report of one CBOM Sources run (CB-38 PR-8), in the code-scan CBOM report's branding (``cbom_pdf``: same
masthead, KPI grid, severity bar, catalog panels, header and footer).

Rule P: every readiness, PQC-class, severity-total and posture number is printed from ``posture.run_posture`` as the
caller passes it, never recounted here. The other sections are listings: the heat-map and certificate calendar from
``heatmap.run_heatmap``, the findings from the run CBOM's components (capped at ``PDF_FINDINGS_CAP`` rows, with the
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
_IMPACT_RANK = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}


def readiness_text(value: Any) -> str:
    """How the report prints ``pqc_readiness_pct`` (as the code-scan CBOM PDF prints its readiness)."""
    return "n/a" if value is None else f"{float(value):.1f}%"


def _p(text: Any, styles: dict, style: str = "table_cell") -> Paragraph:
    return Paragraph(escape_html(str(text if text is not None else "—")), styles[style])


def _props(component: dict[str, Any]) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for prop in component.get("properties") or []:
        out.setdefault(str(prop.get("name")), []).append(str(prop.get("value") or ""))
    return out


def findings_from_cbom(doc: dict[str, Any]) -> list[dict[str, Any]]:
    """The run's findings as the CBOM lists them (components whose ``zs:impact`` is a severity), worst first."""
    rows = []
    for comp in doc.get("components") or []:
        p = _props(comp)
        impact = (p.get("zs:impact") or ["Info"])[0]
        if impact not in _IMPACT_RANK or (p.get("zs:asset_type") or [""])[0] == "coverage":
            continue
        rows.append({"ref": comp.get("bom-ref"), "impact": impact, "name": comp.get("name"),
                     "type": (p.get("zs:asset_type") or [""])[0], "location": (p.get("zs:location") or [""])[0],
                     "source": (p.get("zs:source") or [""])[0], "finding": (p.get("zs:finding") or [""])[0],
                     "codes": p.get("zs:finding_code") or []})
    rows.sort(key=lambda r: (_IMPACT_RANK[r["impact"]], str(r["ref"])))
    return rows


def build_run_pdf(*, run: dict[str, Any], sources: list[dict[str, Any]], posture: dict[str, Any],
                  heatmap: dict[str, Any], doc: dict[str, Any], vex_states: dict[str, int],
                  provenance: list[dict[str, Any]], now: _dt.datetime, as_of_note: str | None,
                  findings_cap: int, export_cap: int, cbom_sha256: str) -> bytes:
    styles = get_report_styles()
    buf = io.BytesIO()
    pdf = SimpleDocTemplate(buf, pagesize=letter, rightMargin=36, leftMargin=36, topMargin=56, bottomMargin=52,
                            title=f"CBOM Sources run #{run['id']}", author="ZeroShield", invariant=1)
    story: list[Any] = []
    meta = {p.get("name"): p.get("value") for p in (doc.get("metadata") or {}).get("properties") or []}
    impacts = {k: int(v or 0) for k, v in (posture.get("impacts") or {}).items()}
    findings_total = sum(impacts.values())
    readiness = readiness_text(posture.get("pqc_readiness_pct"))
    source_names = ", ".join(s["name"] for s in sources) or "—"
    generated = now.strftime("%b %d, %Y · %H:%M UTC")
    truncated = meta.get("zs:truncated") == "true"
    mosca = posture.get("mosca") or {}

    overview = [
        ("Scan type", "CBOM Sources run (collected from infrastructure)"),
        ("Run", f"#{run['id']} · {run['status']}"),
        ("Sources", source_names),
        ("Assets judged", str(posture.get("assets", 0))),
        ("Findings", str(findings_total)),
        ("PQC readiness", readiness),
        ("Report generated", generated),
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
                    ("Findings", str(findings_total)), ("Report generated", generated)],
    )
    if as_of_note:
        story.append(_p(as_of_note, styles, "body"))
    story.append(Paragraph("Run identity", styles["heading"]))
    story.append(key_value_table([
        ("Run", f"#{run['id']}"), ("Status", run["status"]), ("Sources", source_names),
        ("Started", run.get("created_at") or "—"), ("Finished", run.get("finished_at") or "not yet"),
        ("Data last changed", run.get("last_updated") or "—"),
        ("CBOM serial", str(doc.get("serialNumber") or "")), ("CBOM JSON sha256", cbom_sha256),
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
    findings = findings_from_cbom(doc)
    catalog = [[str(i), count_label(f["impact"]), _p(f"{f['finding'] or f['name']} ({f['type']})", styles),
                _p(f["location"], styles, "mono_cell")] for i, f in enumerate(findings[:findings_cap], 1)]
    if len(findings) > findings_cap:
        story.append(_p(f"Findings cap: this report lists the first {findings_cap:,} of {len(findings):,} findings "
                        "(worst first); the CycloneDX JSON and the VEX list them all.", styles, "body"))
    append_findings_catalog(story, catalog_rows=catalog, styles=styles, panel_title="Findings")

    # provenance
    story.append(PageBreak())
    story.append(Paragraph("Provenance", styles["heading"]))
    if provenance:
        story.append(styled_data_table(
            ["Source", "Scan node", "Job", "Outcome", "Assets", "Duration"],
            [[_p(p["source"], styles), _p(p.get("node"), styles), f"{p['kind']} · {p['status']}",
              str(p.get("outcome") or "—"), str(p.get("assets") or 0),
              f"{p['duration_s']} s" if p.get("duration_s") is not None else "—"] for p in provenance],
            styles=styles, col_widths=[1.7 * inch, 1.4 * inch, 1.3 * inch, 0.9 * inch, 0.8 * inch, 1.0 * inch]))
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
