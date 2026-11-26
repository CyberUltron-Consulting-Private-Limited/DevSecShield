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
from reportlab.platypus import CondPageBreak, PageBreak, Paragraph, SimpleDocTemplate, Spacer

from backend.utilities.pdf.report_branding import (
    CBOM_METHOD_NOTE,
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
                  findings_cap: int, export_cap: int, cbom_sha256: str, ctx: Any = None,
                  drift: dict[str, Any] | None = None) -> bytes:
    """``ctx`` (``report_context.ReportContext``): export options and the team logo; omitted, the
    report is today's full report, byte for byte. ``drift``: ``drift_report.run_drift`` for the run (S4); the
    "Changes since the previous comparable run" section is drawn when it is given."""
    from backend.utilities.pdf.report_context import ReportContext, join_parts  # noqa: PLC0415
    from backend.utilities.pdf.report_options import RUN_SECTIONS, severity_bucket  # noqa: PLC0415
    from backend.utilities.pdf.report_branding import append_report_masthead  # noqa: PLC0415

    ctx = ctx or ReportContext()
    ctx.subject = "run"
    if not ctx.available_sections:
        ctx.available_sections = RUN_SECTIONS
    styles = get_report_styles()
    buf = io.BytesIO()
    pdf = SimpleDocTemplate(buf, pagesize=letter, rightMargin=36, leftMargin=36, topMargin=56, bottomMargin=52,
                            title=f"CBOM Sources run #{run['id']}", author="ZeroShield", invariant=1)
    story: list[Any] = []
    summary_part: list[Any] = []
    posture_part: list[Any] = []
    catalog_part: list[Any] = []
    provenance_part: list[Any] = []
    # Findings are filtered before the cap, keeping their worst-first numbers.
    shown = ctx.select(findings, lambda f: count_label(f.get("impact") or "low"))
    ctx.shown = min(ctx.shown, findings_cap)  # what the PDF draws (X-Report-Findings, the scope panel): the cap applies
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
    if not ctx.has("summary"):
        append_report_masthead(summary_part, report_key="cbom", project_name=f"Sources run #{run['id']}",
                               styles=styles, ctx=ctx)
    else:
        append_executive_summary(
            summary_part, report_key="cbom", overview_rows=overview,
            posture_method=True, method_note=CBOM_METHOD_NOTE,
            severity_counts={count_label(k): v for k, v in impacts.items() if v},
            styles=styles, extra_tables=extra_tables, project_name=f"Sources run #{run['id']}",
            scan_time=_duration(run), scan_time_hint="Still collecting" if as_of_note else f"Run {run['status']}",
            meta_chips=[("Run", f"#{run['id']} {run['status']}"), ("PQC readiness", readiness),
                        ("Findings", str(findings_total)), ("Report as of", generated)],
            ctx=ctx,
        )
    story = summary_part
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

    story = posture_part
    if drift is not None:
        append_drift_section(story, drift, styles)
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
    hidden = 0
    if ctx.options.severities is not None:  # a filtered report never names a finding its filter excludes
        kept = [r for r in top if severity_bucket(count_label(r.get("impact") or "low")) in ctx.options.severities]
        hidden, top = len(top) - len(kept), kept
    if top:
        story.append(styled_data_table(
            ["Score", "Severity", "Asset", "Where", "Exposure"],
            [[str(r.get("score")), count_label(r.get("impact") or "low"), _p(r.get("finding") or r.get("name"), styles),
              _p(r.get("location"), styles, "mono_cell"), _p(f"{r.get('exposure')} · {r.get('criticality')}", styles)]
             for r in top],
            styles=styles, severity_col=1, col_widths=[0.65 * inch, 0.85 * inch, 2.5 * inch, 1.9 * inch, 1.2 * inch]))
        story.append(_p("Score = impact weight x business criticality x internet exposure (posture).", styles, "muted"))
        if hidden:
            story.append(_p(f"{hidden} more top risk(s) are outside the selected severities.", styles, "muted"))
    elif hidden:
        story.append(_p(f"No top risk matches the selected severities ({hidden} outside them).", styles, "muted"))
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

    story = catalog_part
    # findings
    catalog = [[str(i), count_label(f["impact"]),
                _p(f"{short(f['finding'] or f['name'], FINDING_CHARS)} ({f['type']})", styles),
                _p(short(f["location"], LOCATION_CHARS), styles, "mono_cell")]
               for i, f in shown[:findings_cap]]
    if len(shown) > findings_cap and ctx.filtered:
        story.append(_p(f"Findings cap: this report lists the first {findings_cap:,} of the {len(shown):,} matching "
                        f"findings (of {len(findings):,}, worst first); the CycloneDX JSON and the VEX list them all.",
                        styles, "body"))
    elif len(findings) > findings_cap and not ctx.filtered:
        story.append(_p(f"Findings cap: this report lists the first {findings_cap:,} of {len(findings):,} findings "
                        "(worst first); the CycloneDX JSON and the VEX list them all.", styles, "body"))
    if catalog:
        story.append(_p(f"Finding text is cut to {FINDING_CHARS} characters and locations to {LOCATION_CHARS}; the "
                        "CycloneDX JSON holds the full sentences.", styles, "muted"))
    append_findings_catalog(story, catalog_rows=catalog, styles=styles, panel_title="Findings",
                            chunk_size=CATALOG_CHUNK, ctx=ctx,
                            empty_text="No security findings were identified in this scan.")

    story = provenance_part
    # provenance
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

    story = []
    join_parts(story, [summary_part,
                       posture_part if ctx.has("posture") else [],
                       catalog_part if ctx.has("catalog") else [],
                       provenance_part if ctx.has("provenance") else []], PageBreak)
    pdf.build(story, onFirstPage=make_cover_callback("cbom", ctx), onLaterPages=make_footer_callback("cbom", ctx))
    return buf.getvalue()


DRIFT_ROWS = 12  # items per drift list in the PDF (drift.json in the evidence pack carries drift_report.TOP)
DRIFT_SOURCES = 15
DRIFT_TABLE_W = 7.1 * inch  # the drift box and its tables share one width (review 6030475121 nit 2)
DRIFT_LABEL_W = 1.55 * inch


def _delta(value: Any) -> str:
    if value is None:
        return "n/a"
    number = float(value)
    return f"{number:+.1f} points" if number else "no change"


def trigger_text(run: dict[str, Any]) -> str:
    """"manual", "scheduled: <name>", or "scheduled (schedule #<id>, since deleted)" (audit D-S4-2, review #486 nit)."""
    if run.get("trigger") != "scheduled":
        return str(run.get("trigger") or "manual")
    if run.get("schedule_name"):
        return f"scheduled: {run['schedule_name']}"
    return f"scheduled (schedule #{run['schedule_id']}, since deleted)" if run.get("schedule_id") else "scheduled"


# staging QA2 Q1-14: one parenthesis said every not-compared source was "collected completely in only one of the two
# runs", also for a source outside the scheduled run's scope and for one collected for the first time
_NOT_COMPARED_WORDS = (("outside_scope", "outside this run's scope"), ("first_collection", "collected only once"),
                       ("outside_baseline_scope", "outside the baseline run's scope"),
                       ("incomplete", "not collected completely in both runs"))


def not_compared_text(counts: dict[str, Any]) -> str:
    """" (2 outside this run's scope, 1 collected only once)"; "" when nothing is uncompared. A diff recorded before
    the reasons were counted keeps the old wording."""
    if not int(counts.get("not_compared_sources", 0) or 0):
        return ""
    parts = [f"{int(counts.get(f'not_compared_{code}', 0) or 0)} {words}" for code, words in _NOT_COMPARED_WORDS
             if int(counts.get(f"not_compared_{code}", 0) or 0)]
    return f" ({', '.join(parts)})" if parts else " (collected completely in only one of the two runs)"


def append_drift_section(story: list[Any], drift: dict[str, Any], styles: dict) -> None:
    """S4: what changed since the previous comparable run, from ``drift_report.run_drift`` (the ``/diff`` numbers)."""
    base = drift.get("baseline")
    story.append(Paragraph(escape_html("Changes since the previous comparable run" if not base
                                       else f"Changes since run #{base['id']}"), styles["heading"]))
    if not base:
        story.append(_p(drift.get("message") or "Nothing to compare yet.", styles, "muted"))
        return
    counts = drift.get("counts") or {}
    ready = drift.get("readiness") or {}
    q0 = drift.get("q0") or {}
    rules = drift.get("rules") or {}
    run = drift.get("run") or {}
    story.append(key_value_table([
        ("Baseline", f"Run #{base['id']} · {base.get('status')} · {trigger_text(base)} · finished "
                     f"{base.get('finished_at') or '—'}"),
        ("This run", f"Run #{run.get('id')} · {trigger_text(run)}"),
        ("Sources compared", f"{counts.get('compared_sources', 0)} compared, {counts.get('not_compared_sources', 0)} "
                             f"not compared{not_compared_text(counts)}"),
        ("Rules", "re-judged with the current rules" if rules.get("reclassified")
         else ("rules changed between the runs" if rules.get("rules_changed") else "same rules")),
        *([("Compared", (f"when the run's drift was recorded, {drift['recorded_at']} (the diff endpoint compares "
                          "with the grade inputs of today)"))] if drift.get("recorded_at") else []),
    ], styles=styles, label_width=DRIFT_LABEL_W, value_width=DRIFT_TABLE_W - DRIFT_LABEL_W))
    story.append(Spacer(1, 6))
    readiness = (f"{readiness_text(ready.get('before'))} → {readiness_text(ready.get('after'))} "
                 f"({_delta(ready.get('delta'))}; {ready.get('scope') or 'compared sources only'})")
    story.append(styled_data_table(
        ["Change", "Count"],
        [["Assets added", str(counts.get("added", 0))], ["Assets removed", str(counts.get("removed", 0))],
         ["Assets changed", str(counts.get("changed", 0))], ["Findings opened (new)", str(counts.get("opened", 0))],
         ["Findings resolved (closed)", str(counts.get("resolved", 0))],
         ["Not read this time (kept at last known state)", str(counts.get("not_read", 0))],
         ["Collector changes (not drift: how a collector reports an asset changed)",
          str(counts.get("collector_changes", 0))],
         ["Q0 Unknown closed (graded Q1-Q4 now)", str(q0.get("closed", 0))],
         ["Q0 Unknown opened", str(q0.get("opened", 0))],
         ["Risk-register Q0 gaps this run closed", str(q0.get("register_closed_total", 0))],
         ["PQC readiness", readiness]],
        styles=styles, col_widths=[3.4 * inch, DRIFT_TABLE_W - 3.4 * inch]))
    story.append(Spacer(1, 4))

    def listing(title: str, key: str, columns: list[str], row) -> None:
        items = list(drift.get(key) or [])
        if not items:
            return
        total = int(counts.get(key, len(items)) or 0)
        story.append(Spacer(1, 8))
        table = styled_data_table(columns, [row(i) for i in items[:DRIFT_ROWS]], styles=styles,
                                  col_widths=[1.1 * inch, 1.9 * inch, 2.6 * inch, DRIFT_TABLE_W - 5.6 * inch])
        # the heading never stands alone at a page foot (#497 review nit); a long table still splits after it
        story.append(CondPageBreak(1.4 * inch))
        story.append(Paragraph(escape_html(f"{title} ({total})"), styles["table_label"]))
        story.append(Spacer(1, 3))
        story.append(table)
        if total > min(len(items), DRIFT_ROWS):
            story.append(_p(f"Showing {min(len(items), DRIFT_ROWS)} of {total}; drift.json in the evidence pack "
                            "and the diff endpoint list more.", styles, "muted"))

    def finding(i: dict[str, Any]) -> list[Any]:
        return [count_label(i.get("impact") or "low"), _p(i.get("code"), styles, "mono_cell"),
                _p(short(i.get("label"), FINDING_CHARS), styles), _p(i.get("source_name"), styles)]

    def asset(i: dict[str, Any]) -> list[Any]:
        return [str(i.get("q_grade") or "—"), _p(i.get("type"), styles),
                _p(short(i.get("label"), FINDING_CHARS), styles), _p(i.get("source_name"), styles)]

    listing("Findings opened", "opened", ["Severity", "Code", "Asset", "Source"], finding)
    listing("Findings resolved", "resolved", ["Severity", "Code", "Asset", "Source"], finding)
    listing("Assets added", "added", ["Q-grade", "Type", "Asset", "Source"], asset)
    listing("Assets removed", "removed", ["Q-grade", "Type", "Asset", "Source"], asset)

    def collector(i: dict[str, Any]) -> list[Any]:
        before = i.get("label_before")
        label = f"{short(before, 60)} → {short(i.get('label'), 60)}" if before else short(i.get("label"), FINDING_CHARS)
        return [_p(i.get("code"), styles, "mono_cell"), _p(i.get("direction"), styles), _p(label, styles),
                _p(i.get("source_name"), styles)]

    listing("Collector changes (not drift)", "collector_changes", ["Code", "Change", "Asset", "Source"], collector)
    skipped = [s for s in drift.get("sources") or [] if s.get("status") != "compared"]
    if skipped:
        story.append(_p("Not compared: " + "; ".join(f"{s.get('name')} ({s.get('reason')})"
                                                      for s in skipped[:DRIFT_SOURCES])
                        + (f"; and {len(skipped) - DRIFT_SOURCES} more" if len(skipped) > DRIFT_SOURCES else "")
                        + ".", styles, "muted"))
    story.append(_p("Same comparison as the run page's Changes and GET .../runs/{id}/diff: only sources collected "
                    "completely in both runs are compared, and what a run could not read is never counted as removed "
                    "or resolved.", styles, "muted"))


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
