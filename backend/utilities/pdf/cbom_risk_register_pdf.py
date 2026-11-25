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
    E  Closure trend           - Q0 gaps opened, closed and still open per week (12 weeks), closures by cause
    F  Every asset             - each register row with its grade, class, standards verdicts, fix class, NIST PQ
                                 target and the Mosca inputs used (up to 2,000 rows; the CSV holds every row)

Grades read the team's Mosca X / Y / Z where set, else documented defaults; a grade that used one says "default
assumptions" (``summary.default_assumptions``, the rows' ``grade_inputs``).

Rules as the other deliverables: reportlab, the standard library and ``backend.utilities.pdf.*`` only; no network,
no language model, no wall clock (dates come from the view and the register rows); every data string goes through
the common table helpers, which sanitise and escape it.
"""
from __future__ import annotations

import re
from typing import Any

from reportlab.pdfbase.pdfmetrics import stringWidth
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
NO_GRADE_NOTE = ("No grade: the asset has no public-key cryptography to grade. An algorithm or key NIST disallows today "
                 "is graded: DES, Triple DES, RC4 or MD5 (SP 800-131A); RSA below 2048 bits; DSA at any size (FIPS "
                 "186-5 keeps DSA for verifying existing signatures only); SHA-1 or MD5 signatures. It is Q1 when "
                 "internet-facing, else Q2, or worse when its quantum grade is worse.")
NOT_LOADED = "The register could not be loaded for this document; download it again in a few minutes."
EMPTY = ("The register has no assets yet: it fills from the estate store after the team's first CBOM Sources run "
         "(and from the background re-grade for runs recorded before it).")


def grade_text(grade: str | None) -> str:
    return f"{grade} {WORD[grade]}" if grade in WORD else "No grade"


def _chip(grade: str | None) -> Any:
    return status_chip(grade_text(grade), TONE.get(grade or "", "unknown"))


def _note(text: str, styles: Styles, limit: int = 600) -> Paragraph:
    return Paragraph(pdf_text(text, limit=limit), styles["box_text"])


def _summary(reg: dict[str, Any], width: float) -> list[Flowable]:
    s = reg["summary"]
    q = s.get("q_grades") or {}
    cards = [("Assets", str(s.get("total", 0)), "distinct assets across sources")]
    cards += [(grade_text(g), str(q.get(g, 0)), "", TONE[g]) for g in GRADES]
    cards += [("Q0 Unknown", str(q.get("Q0", 0)), "assets the product could not grade", "unknown"),
              ("No grade", str(q.get("none", 0)),
               "no public-key cryptography (disallowed items are graded)"),
              ("Still to re-grade", str(s.get("pending_regrade", 0)), "after an input or model change")]
    return [kpi_strip(cards, width, max_per_row=8)]


# What X, Y and Z mean and where each default comes from (``qgrade.MOSCA_DEFINITION``, served in the register report:
# the PDF repeats it, never paraphrases it)
def mosca_definition(reg: dict[str, Any] | None) -> str:
    return str((reg or {}).get("mosca_definition") or "")


# Readable labels for the values the register stores as codes (a client document never prints ``not_compliant``)
_STATUS_WORDS = {"not_applicable": "n/a", "not_compliant": "not compliant", "compliant": "compliant",
                 "acceptable": "acceptable", "disallowed": "disallowed", "deprecated": "deprecated",
                 "legacy_use": "legacy use only", "unknown": "unknown", "approved": "approved"}
_CLASS_WORDS = {"quantum-vulnerable": "quantum-vulnerable", "quantum-safe": "quantum-safe", "hybrid": "hybrid",
                "grover-weakened": "Grover-weakened", "unknown": "unknown", "not-applicable": "n/a",
                "deprecated": "SP 800-131A disallowed"}
_STANDARD_SHORT = (("fips_203_204_205", "FIPS"), ("cnsa_2_0", "CNSA"), ("sp800_131a", "800-131A"))


def status_word(value: Any) -> str:
    """A standards status as words (``not_compliant`` -> ``not compliant``; ``approved (FIPS 203 category 3)``
    kept as is)."""
    text = str(value or "").strip()
    if not text:
        return "\u2014"
    return _STATUS_WORDS.get(text, text.replace("_", " "))


def class_word(value: Any) -> str:
    text = str(value or "").strip()
    return _CLASS_WORDS.get(text, text.replace("_", " ")) if text else "\u2014"


def reason_word(code: Any, texts: dict[str, str] | None = None) -> str:
    """A grade reason in words (``qgrade.REASONS``, served as the report's ``reason_text``), never the raw code."""
    text = (texts or {}).get(str(code or ""))
    return text or str(code or "").replace("_", " ")


_PIECE = re.compile(r"[^@./_\-:\s]*[@./_\-:]?|\s+")
_CELL_FONT, _CELL_SIZE, _CELL_PAD = "Helvetica", 7, 3


def breakable(value: Any, width: float) -> str:
    """``value`` with line breaks after ``@ . - / _ :`` where a word is wider than the column (``width`` points), so
    reportlab never cuts it mid-token ("quantum-vulnerabl/e", "ops@chola.exampl/e"). A piece wider than the column on
    its own is left whole. The text is unchanged but for the ``\\n``."""
    usable = max(float(width) - 2 * _CELL_PAD - 1, 10.0)
    out_lines: list[str] = []
    for raw in str(value if value is not None else "").split("\n"):
        words = raw.split(" ")
        rebuilt: list[str] = []
        for word in words:
            if stringWidth(word, _CELL_FONT, _CELL_SIZE) <= usable:
                rebuilt.append(word)
                continue
            lines, line = [], ""
            for piece in (p for p in _PIECE.findall(word) if p):
                if line and stringWidth(line + piece, _CELL_FONT, _CELL_SIZE) > usable:
                    lines.append(line)
                    line = piece
                else:
                    line += piece
            if line:
                lines.append(line)
            rebuilt.append("\n".join(lines))
        out_lines.append(" ".join(rebuilt))
    return "\n".join(out_lines)


def assumptions_text(summary: dict[str, Any]) -> str | None:
    """The "default assumptions" line: how many grades rest on a default Mosca input, which inputs, the defaults."""
    d = summary.get("default_assumptions") or {}
    n = int(d.get("count") or 0)
    if n <= 0:
        return None
    which = ", ".join(f"{k.upper()} ({v})" for k, v in (d.get("inputs") or {}).items())
    return (f"Default assumptions: {n} quantum-vulnerable grade{'' if n == 1 else 's'} used a default Mosca input "
            f"({which}) because the team or the source has not set it. Defaults: {d.get('defaults')}. Set the data "
            "lifetime on each source and the team's migration and quantum-computer years to replace them; the "
            "register re-grades in the background.")


# Q0 gap reasons as the Quantum risk tab heads them (frontend components/cbom/grade/model.ts q0ReasonHeading)
_REASON_WORDS = {"evidence_e0": "evidence at E0", "mosca_missing": "Mosca inputs missing",
                 "deprecated": "disallowed by SP 800-131A",
                 "unknown_verdict": "PQC class unknown", "coverage_gap": "scope not read",
                 "not_correlated": "not correlated across sources", "source_not_read": "source not read",
                 "source_truncated": "source cut at the asset limit", "excluded_by_choice": "left out by choice"}


def gap_reason(code: Any) -> str:
    """A Q0 gap reason in words (never the raw code)."""
    text = str(code or "")
    return _REASON_WORDS.get(text, text.replace("_", " "))


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


def inputs_cell(i: dict[str, Any]) -> str:
    """The Mosca inputs a row's grade read (``risk_register.add_detail``): X with its basis, Y, Z and the marker."""
    if i.get("data_lifetime_years") is None:
        return ""
    if str(i.get("grade_inputs") or "").startswith("not used"):
        return str(i["grade_inputs"])
    head = (f"X {i['data_lifetime_years']} ({i.get('data_lifetime_basis')}), Y {i.get('migration_years')}, "
            f"Z {i.get('crqc_years')}")
    return f"{head}\n{i.get('grade_inputs') or ''}".strip()


def _top_q1(reg: dict[str, Any], styles: Styles, width: float) -> list[Flowable]:
    items = reg.get("top_q1") or []
    total = int(reg.get("top_q1_total") or 0)
    if not items:
        return [_note("No asset grades Q1 Critical.", styles)]
    widths = [62, width - 62 - 72 - 60 - 52 - 96 - 130 - 130, 72, 60, 52, 96, 130, 130]
    rows = [[_chip(i["q_grade"]), breakable(i.get("label") or i["item_key"], widths[1]),
             breakable(i.get("asset_type"), widths[2]), i.get("family"), i.get("exposure"),
             breakable(i.get("source_name"), widths[5]), reason_word(i.get("q_reason"), reg.get("reason_text")),
             inputs_cell(i)] for i in items]
    out: list[Flowable] = [dense_table(
        ["Grade", "Asset", "Type", "Family", "Exposure", "Source", "Reason", "Inputs used"], rows, widths)]
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
    rows = [[gap_reason(g["reason"]), str(g.get("sub_reason") or "").replace("_", " "), g["item_kind"], gap_item(g),
             g.get("source_name"),
             (g.get("opened_at") or "")[:10], f"{g.get('age_days', 0)} d"] for g in gaps]
    out.append(dense_table(["Reason", "Why", "Kind", "Item", "Source", "Opened", "Age"], rows,
                           [90, 100, 55, width - 90 - 100 - 55 - 110 - 70 - 40, 110, 70, 40]))
    if total > len(gaps):
        out.append(_note(f"{total - len(gaps)} further open Q0 gaps are omitted here; the Q0 gap list holds every "
                         "row.", styles))
    return out


def trend_weeks(weeks: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The weeks the trend prints: from the first week with a gap open, opened or closed (weeks before the
    engagement had no gap and would only print zeros); the numbers are the API's, never recomputed."""
    for i, w in enumerate(weeks):
        if w.get("total") or w.get("q0_gaps_opened") or w.get("q0_gaps_open_at_week_end"):
            return weeks[i:]
    return []


def _trend(reg: dict[str, Any], styles: Styles, width: float) -> list[Flowable]:
    weeks = trend_weeks(reg["summary"].get("closures_by_week") or [])
    if not weeks:
        return [_note("No Q0 gap opened or closed in the last 12 weeks.", styles)]
    rows = [[w["week"], w.get("q0_gaps_opened", ""), w["total"], w.get("q0_gaps_open_at_week_end", ""),
             ", ".join([*(f"{k} {v}" for k, v in sorted((w.get("by_cause") or {}).items())),
                        *([f"grade model changed: {w['model_changes']} re-graded, not counted as closed"]
                          if w.get("model_changes") else [])])] for w in weeks]
    return [_note("Quantum gaps opened / closed per week: Q0 (unknown) gaps opened and closed each week (Monday to "
                  "Sunday, UTC) and the Q0 gaps still open at the end of the week, from the gap lifecycle the runs "
                  "recorded. This is the one weekly closure series of this register; it counts Q0 gaps, not drift "
                  "findings. A gap the grade model itself resolved (a new model version re-graded it) is not counted "
                  "as closed; its week is marked \"grade model changed\".", styles), Spacer(1, 3),
            dense_table(["Week of", "Q0 gaps opened", "Q0 gaps closed", "Q0 gaps open at week end",
                         "Closed by cause"], rows, [80, 70, 70, 100, width - 320])]


_ASSET_HEADERS = ["Grade", "Asset", "Type", "PQC class", "Algorithm", "Exposure",
                  "FIPS 203/204/205 / CNSA 2.0 / SP 800-131A", "Fix class", "NIST PQ target", "Inputs used", "Owner"]


def _assets(reg: dict[str, Any], styles: Styles, width: float) -> list[Flowable]:
    items = reg.get("assets") or []
    total = int(reg.get("assets_total") or len(items))
    if not items:
        return [_note("The register has no assets yet.", styles)]
    rows = []
    for i in items:
        algorithm = " ".join(str(x) for x in (i.get("algorithm"), i.get("key_size")) if x not in (None, ""))
        verdicts = "\n".join(f"{short}: {status_word(i.get(k))}" for k, short in _STANDARD_SHORT)
        rows.append([_chip(i["q_grade"]), i.get("label") or i["item_key"], i.get("asset_type"),
                     class_word(i.get("pqc_class")), algorithm, i.get("exposure"), verdicts,
                     str(i.get("fix_class") or "").replace("_", " "), i.get("nist_pq_target"), inputs_cell(i),
                     i.get("owner")])
    fixed = [48, 0, 52, 72, 60, 42, 92, 54, 90, 80, 64]
    fixed[1] = width - sum(fixed)
    rows = [[row[0], *(breakable(cell, w) for cell, w in zip(row[1:], fixed[1:]))] for row in rows]
    out: list[Flowable] = [
        _note("Every register row, worst grade first, with the columns of the register CSV (the CSV is the full "
              "per-asset list).", styles), Spacer(1, 3), dense_table(_ASSET_HEADERS, rows, fixed)]
    if total > len(items):
        out.append(_note(f"{total - len(items)} further assets are omitted here; the register CSV holds every row.",
                         styles))
    return out


REMOVED_INTRO = (
    "Removed from scope: assets that only CBOM Sources sources deleted since their last collection still hold (not "
    "read, \"source deleted\"). They are listed for the record with their last grade; none of them is counted in any "
    "total of this register, the Scope Baseline (D1) or the board report (D14)."
)


def _removed(reg: dict[str, Any], styles: Styles, width: float) -> list[Flowable]:
    """#497 review M2: the register rows of assets only deleted sources read, outside every total (D1's wording)."""
    found = reg.get("removed_from_scope") if isinstance(reg.get("removed_from_scope"), dict) else {}
    total, items = int(found.get("total") or 0), list(found.get("items") or [])
    if not total:
        return []
    rows = [[_chip(i.get("q_grade")), i.get("label") or i["item_key"], i.get("asset_type"), i.get("source_name"),
             str(i.get("last_observed_at") or "")[:10], "No"] for i in items]
    fixed = [48, 0, 90, 150, 80, 60]
    fixed[1] = width - sum(fixed)
    rows = [[row[0], *(breakable(cell, w) for cell, w in zip(row[1:], fixed[1:]))] for row in rows]
    out: list[Flowable] = [*section_heading("G. Removed from scope", styles), _note(REMOVED_INTRO, styles),
                           Spacer(1, 3),
                           dense_table(["Last grade", "Asset", "Type", "Last read by (deleted)", "Last seen",
                                        "Counted"], rows, fixed)]
    if total > len(items):
        out.append(_note(f"{total - len(items)} further removed assets are not listed here.", styles))
    return out


def build_body(view: TeamCbomView, styles: Styles, width: float) -> list[Flowable]:
    reg = view.register
    if reg is None:
        return [_note(NOT_LOADED, styles)]
    out: list[Flowable] = []
    out += section_heading("A. Summary", styles)
    out += _summary(reg, width)
    assumed = assumptions_text(reg.get("summary") or {})
    if assumed:
        out += [Spacer(1, 4), _note(assumed, styles)]
    out += [Spacer(1, 4), _note(mosca_definition(reg), styles, limit=1200),
            Spacer(1, 2), _note(NO_GRADE_NOTE, styles)]
    if not (reg.get("summary") or {}).get("total"):
        out += [Spacer(1, 6), _note(EMPTY, styles)]
    out += section_heading("B. Heat-map: algorithm family x source (worst known grade; Q0 counted apart)", styles)
    out += _heatmap(reg, styles, width)
    out += section_heading("C. Q1 Critical assets", styles)
    out += _top_q1(reg, styles, width)
    out += section_heading("D. Q0 Unknown gaps (open)", styles)
    out += _q0(reg, styles, width)
    out += section_heading("E. Quantum gaps opened / closed per week", styles)
    out += _trend(reg, styles, width)
    out += section_heading("F. Every asset with its grade", styles)
    out += _assets(reg, styles, width)
    out += _removed(reg, styles, width)
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
