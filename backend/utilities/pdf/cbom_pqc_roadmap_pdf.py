"""PQC Migration Roadmap (#15): the team-wide post-quantum migration register (WP3e).

A landscape PDF, rendered in-house with reportlab only, as a pure function of a
``TeamCbomView``.  It lists every CURRENT quantum-vulnerable public-key algorithm occurrence
with the NIST target the engine graded for it, frames them with the public regulatory timeline
(decision D-06) and leaves wave, target date and owner / status to the assessor.

It is RENDER-ONLY.  It never re-grades an asset, never derives a target the engine did not
record, and does not sequence the migration: sequencing is out of scope, the printed order is
scanner impact and not a plan.  Roadmap tables reuse the register scaffolding of
``cbom_deliverable_common`` (``dense_table``, ``kpi_strip``, ``status_chip``), which is built on
the palette, fonts and pills of the existing CBOM PDF.

Sections, numbered in print order (the conditional ones shift the numbering):

* Summary: KPI strip (quantum-vulnerable occurrences, distinct kinds, readiness %, quantum-safe,
  hybrid, not gradeable).
* Regulatory timeline: the authored rows with their public source URLs.
* Target families: family x primitive x occurrences x sources.
* Per-asset roadmap: one table per primitive group (pke, signature, key-agree, kem, other),
  rows sorted by impact, key size, name.  With nothing quantum-vulnerable it is an explicit
  "No quantum-vulnerable assets" section, never an empty table; an empty team gets "Roadmap not
  available" instead, because a missing scan is not a clean result.
* Already quantum-safe and hybrid: counts by NIST quantum security level.
* Previously seen, not in latest scan: only when such assets exist; never counted anywhere else.
* Notes.

Data rules.  Only ``current`` algorithm assets with ``quantum_vulnerable is True`` are roadmap
rows (an asset that left its source's latest scan is "previously seen").  Headline counts come
from the view so every deliverable agrees.  A value the engine did not record prints as a dash;
a missing target on a legacy-format row reads ``LEGACY_TARGET_UNAVAILABLE`` ("not available",
"legacy scan"), and on a current-format row "not recorded".  Every data-derived string goes
through ``pdf_text`` / ``pdf_multiline`` (directly or inside the ``cbom_deliverable_common``
helpers): scanned repositories are untrusted input and reportlab parses mini-HTML.

Hard rules: reportlab, the standard library and the in-package modules only; no network, no
language-model calls, no wall clock (every date comes from the view); Python 3.10 syntax.
"""

from __future__ import annotations

import itertools
import re
from collections import Counter
from collections.abc import Sequence

from reportlab.lib.styles import ParagraphStyle
from reportlab.platypus import CondPageBreak, Flowable, KeepTogether, Paragraph, Spacer

from backend.utilities.dashboard.cbom_team_rollup import (
    ASSET_ALGORITHM,
    IMPACT_LEVELS,
    TIER_A,
    AssetAgg,
    TeamCbomView,
    plan_key,
)
from backend.utilities.pdf import cbom_deliverable_text as authored
from backend.utilities.pdf.cbom_deliverable_common import (
    Styles,
    build_document,
    dense_table,
    fmt_date_utc,
    kpi_strip,
    pdf_text,
    section_heading,
    status_chip,
    tone_for_impact,
)
from backend.utilities.pdf.report_branding import REPORT_META

SLUG = "pqc-migration-roadmap"
NUMBER = 15  # "D15" in the Document ID
REPORT_KEY = "cbom_pqc_roadmap"  # REPORT_META key: its own page header and footer label
TITLE = "PQC Migration Roadmap"
# Plan decision D-04: roadmap rows are capped; the headline counts always stay true.
MAX_ROWS = 2000

_DASH = "\u2014"
_DOT = "\u00b7"
_BULLET = "\u2022"
_NOT_RECORDED = "not recorded"
_OTHER = "other"
_OTHER_LABEL = "Other or unclassified primitive"

# Roadmap columns.  The three manual headers get their " (assessor)" suffix from dense_table.
_ROADMAP_HEADERS = (
    "#",
    "Algorithm",
    "Key/curve",
    "Classical strength (bits)",
    "NIST QSL",
    "Target family",
    "Sized target",
    "Impact",
    "Where found",
    "Seen",
    "Wave",
    "Target date",
    "Owner / status",
)
# Column widths in points.  Every full-width table sums to the 720 pt frame of a landscape letter
# page.  "Where found" fits "github.com/e2e-demo/payments-service" (125 pt at 7 pt) on one line,
# so a typical repository label is not broken in the middle of a word.
_ROADMAP_COLS = (24, 46, 44, 38, 30, 76, 88, 44, 138, 52, 42, 44, 54)
_MANUAL_COLS = (10, 11, 12)  # Wave, Target date, Owner / status: left blank for the assessor
_TIMELINE_HEADERS = ("When", "Milestone", "Status", "Source", "Source URL")
# The URL column fits the longest authored URL (CNSA 2.0, 305 pt at 7 pt) on one line.
_TIMELINE_COLS = (56, 198, 50, 96, 320)
_FAMILY_HEADERS = ("Target family", "Primitive", "Occurrences", "Sources")
_FAMILY_COLS = (330, 150, 120, 120)
_LEVEL_HEADERS = ("NIST quantum security level", "Occurrences", "Of which hybrid")
_LEVEL_COLS = (260, 130, 130)
_PREVIOUS_HEADERS = (
    "Algorithm",
    "Key/curve",
    "Target family",
    "Where found",
    "First seen",
    "Last seen",
    "Scans",
)
_PREVIOUS_COLS = (90, 60, 150, 230, 70, 70, 50)

# Status chips: text is always present; the tone only reinforces it.
_STATUS_TONE = {"final": "low", "draft": "medium", "advisory": "unknown"}

# --- document-specific wording (each line names the code it describes) -----------------------
# Product text: the timeline rows and their sources are authored in cbom_deliverable_text.
_TIMELINE_INTRO = (
    "Public milestones that frame the migration. Each row names its source; the dates are "
    "those published by the source and are not deadlines set by this document."
)
# Product text: aibom/src/aibom/cbom/pqc.py grades quantum-vulnerable public-key algorithms at
# NIST quantum security level 0 and flags hybrid key exchange.
_SAFE_INTRO = (
    "Current algorithm occurrences with no known quantum weakness, by the NIST quantum "
    "security level the engine recorded. Level 0 would mean no security against a quantum "
    "computer. Hybrid means a key exchange that combines a classical and a post-quantum "
    "algorithm."
)
_NO_SAFE_TEXT = "No quantum-safe algorithm occurrences are recorded in the current scans."
_UNGRADED_NOTE = (
    "Algorithm occurrences with no recorded quantum status are left out of the readiness "
    "figure (count: {count})."
)
_PREVIOUS_INTRO = (
    "These quantum-vulnerable algorithms were found in earlier scans of a source but not in "
    "its latest scan. They are excluded from every count and from the roadmap above."
)
# An empty team must never read as a clean result (plan 4.6).
_NO_SCANS_TITLE = "Roadmap not available"
_NO_SCANS_TEXT = (
    "No CBOM scan has completed, so no asset has been assessed and no roadmap rows are "
    "listed. This is not evidence that no quantum-vulnerable assets exist."
)
_OMITTED_TEMPLATE = (
    "{omitted} omitted. This document lists at most {cap} rows; the counts above include every row."
)
# Product text: readiness is pqc_safe / (pqc_safe + pqc_vulnerable) of cbom_team_rollup.
_NOTES = (
    "Readiness = quantum-safe / (quantum-safe + quantum-vulnerable), over current algorithm "
    "occurrences. Occurrences with no recorded quantum status are left out.",
    "Counts are current occurrences, not de-duplicated across sources: the same algorithm in "
    "two sources is counted twice because each source's usage is a separate exposure.",
    "NIST QSL is the NIST quantum security level the engine recorded; 0 means no security "
    "against a quantum computer. The sized target is the post-quantum parameter set the "
    "engine matches to the asset's classical strength; it exists only for scans in the "
    "current format.",
    "A dash (" + _DASH + ") means the value is not recorded: legacy-format scans carry no "
    "classical strength, quantum security level or sized target.",
    "Wave, target date and owner / status are for the assessor to complete. This document "
    "lists assets and the NIST target for each; it does not sequence the migration.",
)
# With the team's remediation plan loaded (``view.remediation``) the last note is replaced by this one: the three
# columns are filled from the plan, and scan-node / cloud assets get their own table.
_PLAN_NOTE = (
    "Wave, target date and owner / status come from the team's remediation plan in DevSecShield. "
    "Where no wave was assigned, the suggested wave is printed with \"(suggested)\": 1 = critical or high "
    "and internet-facing or harvest-now-decrypt-later, 2 = other critical or high, 3 = medium and low, "
    "4 = quantum-vulnerable with no other weakness. Blank cells are for the assessor."
)
_NODE_HEADERS = ("#", "Asset", "Type", "Algorithm / key", "Impact", "Where found", "Collected", "Wave",
                 "Target date", "Owner / status")
_NODE_COLS = (24, 150, 70, 64, 44, 150, 52, 52, 50, 64)

_KEY_BITS_RE = re.compile(r"\s*(\d{1,9})\b")
_DIGITS_RE = re.compile(r"\d+")


# ---------------------------------------------------------------------------------------------
# Small pure helpers
# ---------------------------------------------------------------------------------------------
def _fit(columns: Sequence[float], width: float, *, stretch: bool = True) -> list[float]:
    """Column widths scaled to ``width`` (a narrow table only shrinks, never stretches)."""
    total = float(sum(columns))
    scale = float(width) / total
    if not stretch:
        scale = min(scale, 1.0)
    return [column * scale for column in columns]


def _plural(count: int, noun: str) -> str:
    return f"{count} {noun}" if count == 1 else f"{count} {noun}s"


def _impact_rank(impact: str) -> int:
    return IMPACT_LEVELS.index(impact) if impact in IMPACT_LEVELS else len(IMPACT_LEVELS)


def _key_rank(asset: AssetAgg) -> tuple[int, int]:
    """Numeric key sizes ascending, anything else (curve only, text, huge) last."""
    match = _KEY_BITS_RE.match(asset.key_size or "")
    return (0, int(match.group(1))) if match else (1, 0)


def _row_order(asset: AssetAgg) -> tuple:
    """Total order inside a group: impact, key size, name, then source / path / identity."""
    return (
        _impact_rank(asset.impact),
        _key_rank(asset),
        asset.title.casefold(),
        asset.source_label.casefold(),
        asset.location,
        asset.ident,
    )


def _group_code(asset: AssetAgg) -> str:
    primitive = (asset.primitive or "").strip().casefold()
    return primitive if primitive in authored.PQC_PRIMITIVE_ORDER else _OTHER


_GROUP_ORDER = (*authored.PQC_PRIMITIVE_ORDER, _OTHER)


def _group_label(code: str) -> str:
    return authored.PQC_PRIMITIVE_LABELS.get(code, _OTHER_LABEL)


def _is_algorithm(asset: AssetAgg) -> bool:
    return asset.asset_type == ASSET_ALGORITHM


def _from_sources(asset: AssetAgg) -> bool:
    """A CBOM Sources asset: the collected-infrastructure section lists it with its plan (``node_rows``)."""
    return asset.source_key.startswith("sources:")


def _roadmap_assets(view: TeamCbomView) -> list[AssetAgg]:
    """Current quantum-vulnerable algorithm occurrences of code scans (the roadmap rows)."""
    return [a for a in view.assets if a.current and _is_algorithm(a) and a.quantum_vulnerable and not _from_sources(a)]


def _previous_assets(view: TeamCbomView) -> list[AssetAgg]:
    """Quantum-vulnerable algorithms that left their source's latest scan."""
    found = [a for a in view.assets if not a.current and _is_algorithm(a) and a.quantum_vulnerable]
    return sorted(
        found, key=lambda a: (a.source_label.casefold(), a.title.casefold(), a.location, a.ident)
    )


def _unavailable(asset: AssetAgg) -> str:
    """Why a target is missing: a legacy-format scan never carried it; a current one should."""
    return authored.LEGACY_TARGET_UNAVAILABLE if asset.tier != TIER_A else _NOT_RECORDED


def _family(asset: AssetAgg) -> str:
    return asset.pqc_migration_target or _unavailable(asset)


def _sized(asset: AssetAgg) -> str:
    return asset.pqc_migration_roadmap or _unavailable(asset)


def _number(value: int | None) -> str:
    return _DASH if value is None else str(value)


def _key_curve(asset: AssetAgg) -> str:
    parts: list[str] = []
    key = (asset.key_size or "").strip()
    if key:
        parts.append(f"{key} bits" if _DIGITS_RE.fullmatch(key) else key)
    curve = (asset.curve or "").strip()
    if curve:
        parts.append(curve)
    return "\n".join(parts) if parts else _DASH


def _where(asset: AssetAgg) -> str:
    return f"{asset.source_label}\n{asset.location}" if asset.location else asset.source_label


def _seen(asset: AssetAgg) -> str:
    first, last = fmt_date_utc(asset.first_seen), fmt_date_utc(asset.last_seen)
    span = first if first == last else f"{first} to\n{last}"
    return f"{span}\n{_plural(max(int(asset.scan_count), 0), 'scan')}"


def _plan_cells(plan: dict | None, suggested: int | None) -> list[str]:
    """Wave, target date and owner / status from the team's remediation plan (blank without a plan)."""
    if plan is None:
        return ["", "", ""]
    assigned = plan.get("assigned") or {}
    wave = assigned.get("wave")
    wave_text = str(wave) if wave else (f"{suggested} (suggested)" if suggested else "")
    status = str(assigned.get("status") or "").replace("_", " ")
    owner = " / ".join(x for x in (assigned.get("owner") or "", status if assigned else "") if x)
    return [wave_text, str(assigned.get("target_date") or ""), owner]


def _asset_plan(view: TeamCbomView, asset: AssetAgg) -> dict | None:
    """The asset's remediation plan, precomputed into the view by the loader (``code_plans``)."""
    if view.remediation is None:
        return None
    return (view.remediation.get("code_plans") or {}).get(plan_key(asset)) or {"assigned": {}, "suggested": None}


def _roadmap_row(number: int, asset: AssetAgg, plan: dict | None = None) -> list[object]:
    return [
        str(number),
        asset.title,
        _key_curve(asset),
        _number(asset.security_strength_bits),
        _number(asset.nist_quantum_security_level),
        _family(asset),
        _sized(asset),
        status_chip(asset.impact.upper(), tone_for_impact(asset.impact)),
        _where(asset),
        _seen(asset),
        *_plan_cells(plan, (plan or {}).get("suggested")),
    ]


def _note(text: str, styles: Styles, *, style: str = "muted") -> Paragraph:
    return Paragraph(pdf_text(text, limit=700), styles[style])


def _card(label: str, value: str, hint: str, tone: str = "") -> tuple[str, ...]:
    """A ``kpi_strip`` card; without a tone the card keeps the brand accent."""
    return (label, value, hint, tone) if tone else (label, value, hint)


def _heading(title: str, styles: Styles) -> Paragraph:
    """A section heading to be wrapped in ``KeepTogether`` with the block it introduces.

    Small blocks (KPIs, timeline, families, notes) are kept whole on one page; the long tables
    use ``section_heading`` instead, whose guard lets the table start on the current page.
    """
    return Paragraph(pdf_text(title, limit=160), styles["section_heading"])


# ---------------------------------------------------------------------------------------------
# Sections
# ---------------------------------------------------------------------------------------------
def _summary(
    view: TeamCbomView, rows: list[AssetAgg], styles: Styles, width: float, title: str
) -> list[Flowable]:
    kinds = len({(a.title.casefold(), a.key_size or "", a.curve or "") for a in rows})
    readiness = "n/a" if view.readiness_pct is None else f"{view.readiness_pct:.1f}%"
    cards = [
        _card(
            "Quantum-vulnerable",
            str(view.pqc_vulnerable),
            "current occurrences",
            "high" if view.pqc_vulnerable else "low",
        ),
        _card("Distinct kinds", str(kinds), "algorithm with key size or curve"),
        _card("Quantum readiness", readiness, "quantum-safe / (safe + vulnerable)"),
        _card("Quantum-safe", str(view.pqc_safe), "current occurrences", "low"),
        _card("Hybrid", str(view.pqc_hybrid), "subset of quantum-safe"),
        _card(
            "Not gradeable",
            str(view.pqc_ungraded),
            "no quantum status recorded",
            "unknown" if view.pqc_ungraded else "",
        ),
    ]
    meta = REPORT_META[REPORT_KEY]
    # Heading, purpose line and KPI strip stay together; the reading guidance follows them.
    block = KeepTogether(
        [
            _heading(title, styles),
            _note(meta["intro"], styles, style="body"),
            Spacer(1, 4),
            kpi_strip(cards, width),
        ]
    )
    return [block, Spacer(1, 4), _note(meta["how_to_read"], styles), Spacer(1, 2)]


def _timeline(styles: Styles, width: float, title: str) -> list[Flowable]:
    rows = [
        [
            row.when,
            row.milestone,
            status_chip(row.status.upper(), _STATUS_TONE.get(row.status.casefold(), "unknown")),
            row.source,
            row.url,
        ]
        for row in authored.PQC_TIMELINE_ROWS
    ]
    block = KeepTogether(
        [
            _heading(title, styles),
            _note(_TIMELINE_INTRO, styles),
            dense_table(_TIMELINE_HEADERS, rows, _fit(_TIMELINE_COLS, width)),
            Spacer(1, 3),
            _note(authored.PQC_TIMELINE_FOOTNOTE, styles),
        ]
    )
    return [block, Spacer(1, 4)]


def _families(rows: list[AssetAgg], styles: Styles, width: float, title: str) -> list[Flowable]:
    tally: dict[tuple[int, str, str], tuple[int, set[str]]] = {}
    for asset in rows:
        code = _group_code(asset)
        key = (_GROUP_ORDER.index(code), code, _family(asset))
        count, sources = tally.get(key, (0, set()))
        tally[key] = (count + 1, sources | {asset.source_key})
    table_rows = [
        [family, code, str(count), str(len(sources))]
        for (_index, code, family), (count, sources) in sorted(tally.items())
    ]
    block = KeepTogether(
        [
            _heading(title, styles),
            dense_table(_FAMILY_HEADERS, table_rows, _fit(_FAMILY_COLS, width)),
        ]
    )
    return [block, Spacer(1, 4)]


def _roadmap(
    rows: list[AssetAgg],
    styles: Styles,
    width: float,
    title: str,
    max_rows: int,
    view: TeamCbomView | None = None,
) -> list[Flowable]:
    group_style = ParagraphStyle(
        "PqcGroupHeading", parent=styles["finding_title"], spaceBefore=8, spaceAfter=3
    )
    story: list[Flowable] = [
        *section_heading(title, styles),
        _note(authored.PQC_ROADMAP_ORDER_NOTE, styles),
    ]
    groups: dict[str, list[AssetAgg]] = {code: [] for code in _GROUP_ORDER}
    for asset in sorted(rows, key=_row_order):
        groups[_group_code(asset)].append(asset)
    widths = _fit(_ROADMAP_COLS, width)
    remaining = max_rows
    number = 0
    for code in _GROUP_ORDER:
        group = groups[code]
        shown = group[: max(remaining, 0)]
        if not shown:
            continue
        remaining -= len(shown)
        heading = f"{code} {_DOT} {_group_label(code)} {_DOT} {_plural(len(group), 'occurrence')}"
        table_rows = []
        for asset in shown:
            number += 1
            table_rows.append(_roadmap_row(number, asset, _asset_plan(view, asset) if view else None))
        planned = view is not None and view.remediation is not None
        story += [
            CondPageBreak(90),
            Paragraph(pdf_text(heading, limit=200), group_style),
            dense_table(_ROADMAP_HEADERS, table_rows, widths, manual_cols=() if planned else _MANUAL_COLS),
        ]
    omitted = len(rows) - number
    if omitted > 0:
        notice = _OMITTED_TEMPLATE.format(
            omitted=_plural(omitted, "further row"), cap=max(int(max_rows), 0)
        )
        story += [Spacer(1, 3), _note(notice, styles)]
    return story


def _no_rows(view: TeamCbomView, styles: Styles, title_prefix: str) -> list[Flowable]:
    """The explicit replacement for the roadmap table (never an empty table)."""
    if view.is_empty:
        title, message = _NO_SCANS_TITLE, _NO_SCANS_TEXT
    else:
        title, message = authored.PQC_NO_VULNERABLE_TITLE, authored.PQC_NO_VULNERABLE_TEXT
    block = KeepTogether(
        [_heading(f"{title_prefix} {title}", styles), _note(message, styles, style="body")]
    )
    return [block, Spacer(1, 4)]


def _safe_section(view: TeamCbomView, styles: Styles, width: float, title: str) -> list[Flowable]:
    safe = [
        a for a in view.assets
        if a.current and _is_algorithm(a) and a.quantum_vulnerable is False and not a.broken_today  # not MD5, DES ...
    ]
    parts: list[Flowable] = [_heading(title, styles)]
    if not safe:
        parts.append(_note(_NO_SAFE_TEXT, styles, style="body"))
    else:
        by_level = Counter(a.nist_quantum_security_level for a in safe)
        hybrid = Counter(a.nist_quantum_security_level for a in safe if a.hybrid is True)
        rows = [
            [f"Level {level}", str(by_level[level]), str(hybrid.get(level, 0))]
            for level in sorted(level for level in by_level if level is not None)
        ]
        if None in by_level:
            rows.append(["Not recorded", str(by_level[None]), str(hybrid.get(None, 0))])
        rows.append(["Total quantum-safe", str(len(safe)), str(sum(hybrid.values()))])
        parts += [
            _note(_SAFE_INTRO, styles),
            dense_table(_LEVEL_HEADERS, rows, _fit(_LEVEL_COLS, width, stretch=False)),
        ]
    if view.pqc_ungraded:
        parts += [Spacer(1, 3), _note(_UNGRADED_NOTE.format(count=view.pqc_ungraded), styles)]
    return [KeepTogether(parts), Spacer(1, 4)]


def _previously_seen(
    previous: list[AssetAgg], styles: Styles, width: float, title: str, max_rows: int
) -> list[Flowable]:
    shown = previous[: max(int(max_rows), 0)]
    rows = [
        [
            asset.title,
            _key_curve(asset),
            _family(asset),
            _where(asset),
            fmt_date_utc(asset.first_seen),
            fmt_date_utc(asset.last_seen),
            str(asset.scan_count),
        ]
        for asset in shown
    ]
    story: list[Flowable] = [
        *section_heading(title, styles),
        _note(_PREVIOUS_INTRO, styles),
        dense_table(_PREVIOUS_HEADERS, rows, _fit(_PREVIOUS_COLS, width)),
    ]
    omitted = len(previous) - len(shown)
    if omitted > 0:
        notice = _OMITTED_TEMPLATE.format(
            omitted=_plural(omitted, "further row"), cap=max(int(max_rows), 0)
        )
        story += [Spacer(1, 3), _note(notice, styles)]
    story.append(Spacer(1, 4))
    return story


def _notes_section(styles: Styles, title: str, *, planned: bool = False) -> list[Flowable]:
    notes = (*_NOTES[:-1], _PLAN_NOTE) if planned else _NOTES
    lines = [_note(f"{_BULLET} {line}", styles, style="body") for line in notes]
    return [KeepTogether([_heading(title, styles), *lines])]


def _node_section(view: TeamCbomView, styles: Styles, width: float, title: str, max_rows: int) -> list[Flowable]:
    """Quantum-vulnerable assets of each collection source's latest complete run (scan nodes, cloud worker)."""
    rem = view.remediation or {}
    rows = rem.get("node_rows") or []
    table_rows = []
    for number, item in enumerate(rows[: max(int(max_rows), 0)], start=1):
        key = item.get("algorithm") or ""
        if item.get("key_size"):
            key = f"{key} {item['key_size']}".strip()
        where = "\n".join(x for x in (item.get("source_name") or "", item.get("target") or "",
                                       item.get("location") or "") if x)
        impact = str(item.get("impact") or "Info")
        plan = {"assigned": item.get("assignment") or {}, "suggested": item.get("suggested_wave")}
        table_rows.append([
            str(number), item.get("label") or "", item.get("type") or "", key or _DASH,
            status_chip(impact.upper(), tone_for_impact(impact)), where,
            (item.get("collected_at") or "")[:10], *_plan_cells(plan, plan["suggested"]),
        ])
    story: list[Flowable] = [
        *section_heading(title, styles),
        _note("Quantum-vulnerable assets found by scan nodes and the ZeroShield cloud worker in each source's "
              "latest complete collection (servers, clusters, databases, cloud accounts, identity providers, "
              "network endpoints).", styles),
    ]
    if table_rows:
        story.append(dense_table(_NODE_HEADERS, table_rows, _fit(_NODE_COLS, width)))
    omitted = len(rows) - len(table_rows) + int(rem.get("node_rows_omitted") or 0)
    if omitted > 0:
        story += [Spacer(1, 3), _note(_OMITTED_TEMPLATE.format(omitted=_plural(omitted, "further row"),
                                                               cap=max(int(max_rows), 0)), styles)]
    story.append(Spacer(1, 4))
    return story


# ---------------------------------------------------------------------------------------------
# Public entry points
# ---------------------------------------------------------------------------------------------
def build_body(
    view: TeamCbomView, styles: Styles, width: float, *, max_rows: int = MAX_ROWS
) -> list[Flowable]:
    """The document-specific flowables (everything after the shared front matter)."""
    rows = _roadmap_assets(view)
    previous = _previous_assets(view)
    counter = itertools.count(1)

    def title(name: str) -> str:
        return f"{next(counter)} {name}"

    story: list[Flowable] = []
    story += _summary(view, rows, styles, width, title("Summary"))
    story += _timeline(styles, width, title("Regulatory timeline"))
    if rows:
        story += _families(rows, styles, width, title("Target families"))
        story += _roadmap(rows, styles, width, title("Per-asset roadmap"), max_rows, view)
    else:
        story += _no_rows(view, styles, str(next(counter)))
    if view.remediation is not None and view.remediation.get("node_rows"):
        story += _node_section(view, styles, width, title("Collected infrastructure (scan nodes and cloud)"),
                               max_rows)
    if not view.is_empty:
        story += _safe_section(view, styles, width, title("Already quantum-safe and hybrid"))
    if previous:
        story += _previously_seen(
            previous, styles, width, title(authored.PREVIOUSLY_SEEN_TITLE), max_rows
        )
    story += _notes_section(styles, title("Notes"), planned=view.remediation is not None)
    return story


def build_pdf(view: TeamCbomView, *, max_rows: int = MAX_ROWS) -> bytes:
    """Render the PQC Migration Roadmap of ``view`` as a landscape PDF (bytes)."""

    def body(styles: Styles, width: float) -> list[Flowable]:
        return build_body(view, styles, width, max_rows=max_rows)

    return build_document(
        view=view,
        number=NUMBER,
        report_key=REPORT_KEY,
        title=TITLE,
        landscape=True,
        body=body,
    )


__all__ = [
    "MAX_ROWS",
    "NUMBER",
    "REPORT_KEY",
    "SLUG",
    "TITLE",
    "build_body",
    "build_pdf",
]
