"""Quantum Risk Register (#2): landscape PDF (CB-23 PR-C; CB-19 PLAN §3 "CB-23 PR-C").

One of the team-wide CBOM regulatory deliverables. Everything it prints comes from ``TeamCbomView.register``
(``cbom_sources.risk_register.report``, loaded by ``load_team_cbom_view``), which reads the same register rows and
Q0 gap rows as the API (``GET /{team}/cbom/register/summary``, ``…/heatmap``, ``…/register?grade=Q1``,
``…/register/q0``), so the PDF and the Quantum risk tab cannot disagree.

Sections::

    A  Summary                 - KPI cards: assets (distinct estate keys), Q1..Q4, Q0, no grade, still to re-grade
    B  Heat-map                - algorithm family x source, worst known grade per cell with counts (Q0 apart)
    C  Q1 Critical assets      - up to 100 rows (the total is always printed)
    D  Q0 Unknown gaps         - open gaps by reason (evidence, unread scope, assets, inputs), up to 200 rows
    E  Closure trend           - Q0 gaps closed per week (12 weeks) by cause

Rules as the other deliverables: reportlab, the standard library and ``backend.utilities.pdf.*`` only; no network,
no language model, no wall clock (dates come from the view and the register rows); every data string goes through
the common table helpers, which sanitise and escape it.
"""
from __future__ import annotations

from typing import Any

from reportlab.platypus import Flowable, Paragraph, Spacer

from backend.utilities.dashboard.cbom_team_rollup import TeamCbomView
from backend.utilities.pdf.cbom_deliverable_common import (
    Styles,
    build_document,
    dense_table,
    kpi_strip,
    pdf_text,
    section_heading,
    status_chip,
)

NUMBER = 2  # "D02" in the Document ID
REPORT_KEY = "cbom_risk_register"
SLUG = "quantum-risk-register"
TITLE = "Quantum Risk Register"
GRADES = ("Q1", "Q2", "Q3", "Q4")
WORD = {"Q0": "Unknown", "Q1": "Critical", "Q2": "High", "Q3": "Medium", "Q4": "Low"}
TONE = {"Q0": "unknown", "Q1": "critical", "Q2": "high", "Q3": "medium", "Q4": "low"}
NOT_LOADED = "The register could not be loaded for this document; download it again in a few minutes."
EMPTY = ("The register has no assets yet: it fills from the estate store after the team's first CBOM Sources run "
         "(and from the background re-grade for runs recorded before it).")


def grade_text(grade: str | None) -> str:
    return f"{grade} {WORD[grade]}" if grade in WORD else "No grade"


def _chip(grade: str | None) -> Any:
    return status_chip(grade_text(grade), TONE.get(grade or "", "unknown"))


def _note(text: str, styles: Styles) -> Paragraph:
    return Paragraph(pdf_text(text, limit=600), styles["box_text"])


def _summary(reg: dict[str, Any], width: float) -> list[Flowable]:
    s = reg["summary"]
    q = s.get("q_grades") or {}
    cards = [("Assets", str(s.get("total", 0)), "distinct assets across sources")]
    cards += [(grade_text(g), str(q.get(g, 0)), "", TONE[g]) for g in GRADES]
    cards += [("Q0 Unknown", str(q.get("Q0", 0)), "assets the product could not grade", "unknown"),
              ("No grade", str(q.get("none", 0)), "no public-key cryptography"),
              ("Still to re-grade", str(s.get("pending_regrade", 0)), "after an input or model change")]
    return [kpi_strip(cards, width, max_per_row=8)]


# Q0 gap reasons as the Quantum risk tab heads them (frontend components/cbom/grade/model.ts q0ReasonHeading)
_REASON_WORDS = {"evidence_e0": "evidence at E0", "mosca_missing": "Mosca inputs missing",
                 "unknown_verdict": "PQC class unknown", "coverage_gap": "scope not read"}


def heat_cell_text(cell: dict[str, Any]) -> str:
    """A heat-map cell: its worst known grade, else "Q0 only" when it holds Q0 assets, else "No grade"; then its counts
    per grade, Q0 and no grade ("—", as on the Quantum risk tab)."""
    counts = cell.get("counts") or {}
    text = " ".join(f"{g}:{counts[g]}" for g in (*GRADES, "Q0") if counts.get(g))
    if counts.get("none"):
        text = f"{text} —:{counts['none']}".strip()
    if cell.get("worst"):
        label = grade_text(cell["worst"])
    else:
        label = "Q0 only" if int(cell.get("q0") or counts.get("Q0") or 0) > 0 else "No grade"
    return f"{label}\n{text}".strip()


def reason_line(open_by_reason: dict[str, int]) -> str:
    return "Open Q0 gaps by reason: " + ", ".join(
        f"{_REASON_WORDS.get(k, k.replace('_', ' '))} {v}" for k, v in sorted(open_by_reason.items()))


def gap_item(gap: dict[str, Any]) -> str:
    """A Q0 gap's item: the Mosca inputs gap (one item for every asset it leaves ungraded) in words, else its title."""
    if gap.get("item_kind") == "inputs" and gap.get("item_key") == "inputs:mosca":
        n = int((gap.get("detail") or {}).get("count") or 0)
        return (f"Mosca X, Y or Z not set ({n} quantum-vulnerable asset{'' if n == 1 else 's'} left ungraded)"
                if n > 0 else "Mosca X, Y or Z not set")
    return gap.get("title") or ""


def _heatmap(reg: dict[str, Any], styles: Styles, width: float) -> list[Flowable]:
    hm = reg["heatmap"]
    if not hm.get("cells"):
        return [_note("No graded assets to place on the heat-map.", styles)]
    cols = hm["columns"]
    cells = {(c["family"], c["source_ref"]): c for c in hm["cells"]}
    headers = ["Family"] + [c["source_name"] or c["source_ref"] or "source" for c in cols]
    rows = []
    for r in hm["rows"]:
        line: list[Any] = [r["family"] if not r["other"] else r.get("label")]
        for c in cols:
            cell = cells.get((r["family"] if not r["other"] else None, c["source_ref"] if not c["other"] else None))
            if not cell:
                line.append("")
                continue
            line.append(heat_cell_text(cell))
        rows.append(line)
    first = 110.0
    rest = (width - first) / max(1, len(cols))
    return [dense_table(headers, rows, [first] + [rest] * len(cols))]


def _top_q1(reg: dict[str, Any], styles: Styles, width: float) -> list[Flowable]:
    items = reg.get("top_q1") or []
    total = int(reg.get("top_q1_total") or 0)
    if not items:
        return [_note("No asset grades Q1 Critical.", styles)]
    rows = [[_chip(i["q_grade"]), i.get("label") or i["item_key"], i.get("asset_type"), i.get("family"),
             i.get("exposure"), i.get("source_name"), i.get("sources"), i.get("q_reason")] for i in items]
    out: list[Flowable] = [dense_table(
        ["Grade", "Asset", "Type", "Family", "Exposure", "Source", "Sources", "Reason"], rows,
        [62, width - 62 - 80 - 70 - 60 - 110 - 40 - 110, 80, 70, 60, 110, 40, 110])]
    if total > len(items):
        out.append(_note(f"{total - len(items)} further Q1 Critical assets are omitted here; the register list and "
                         "its CSV hold every row.", styles))
    return out


def _q0(reg: dict[str, Any], styles: Styles, width: float) -> list[Flowable]:
    gaps = reg.get("q0_gaps") or []
    open_by_reason = reg["summary"].get("q0_gaps_open") or {}
    total = sum(int(v) for v in open_by_reason.values())
    if not gaps:
        return [_note("No open Q0 gap.", styles)]
    out: list[Flowable] = [_note(reason_line(open_by_reason), styles), Spacer(1, 4)]
    rows = [[g["reason"], g.get("sub_reason"), g["item_kind"], gap_item(g), g.get("source_name"),
             (g.get("opened_at") or "")[:10], f"{g.get('age_days', 0)} d"] for g in gaps]
    out.append(dense_table(["Reason", "Why", "Kind", "Item", "Source", "Opened", "Age"], rows,
                           [90, 100, 55, width - 90 - 100 - 55 - 110 - 70 - 40, 110, 70, 40]))
    if total > len(gaps):
        out.append(_note(f"{total - len(gaps)} further open Q0 gaps are omitted here; the Q0 gap list holds every "
                         "row.", styles))
    return out


def _trend(reg: dict[str, Any], styles: Styles, width: float) -> list[Flowable]:
    weeks = reg["summary"].get("closures_by_week") or []
    if not any(w.get("total") for w in weeks):
        return [_note("No Q0 gap closed in the last 12 weeks.", styles)]
    rows = [[w["week"], w["total"], ", ".join(f"{k} {v}" for k, v in sorted((w.get("by_cause") or {}).items()))]
            for w in weeks]
    return [dense_table(["Week of", "Closed", "By cause"], rows, [90, 60, width - 150])]


def build_body(view: TeamCbomView, styles: Styles, width: float) -> list[Flowable]:
    reg = view.register
    if reg is None:
        return [_note(NOT_LOADED, styles)]
    out: list[Flowable] = []
    out += section_heading("A. Summary", styles)
    out += _summary(reg, width)
    if not (reg.get("summary") or {}).get("total"):
        out += [Spacer(1, 6), _note(EMPTY, styles)]
    out += section_heading("B. Heat-map: algorithm family x source (worst known grade; Q0 counted apart)", styles)
    out += _heatmap(reg, styles, width)
    out += section_heading("C. Q1 Critical assets", styles)
    out += _top_q1(reg, styles, width)
    out += section_heading("D. Q0 Unknown gaps (open)", styles)
    out += _q0(reg, styles, width)
    out += section_heading("E. Q0 gaps closed per week", styles)
    out += _trend(reg, styles, width)
    return out


def build_pdf(view: TeamCbomView, *, ctx: Any = None) -> bytes:
    """Render the Quantum Risk Register of ``view`` as a landscape PDF (bytes)."""
    reg = view.register or {}
    model = (reg.get("summary") or {}).get("model_version")

    def body(styles: Styles, width: float) -> list[Flowable]:
        return build_body(view, styles, width)

    return build_document(ctx=ctx, view=view, number=NUMBER, report_key=REPORT_KEY, title=TITLE, landscape=True, body=body,
                          basis_extra=[f"Grade model: {model}"] if model else None)


__all__ = ["NUMBER", "REPORT_KEY", "SLUG", "TITLE", "build_body", "build_pdf", "grade_text"]
