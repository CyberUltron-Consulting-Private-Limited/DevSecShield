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

from typing import Any

import itertools
import re
from collections import Counter
from collections.abc import Sequence

from reportlab.lib.styles import ParagraphStyle
from reportlab.platypus import CondPageBreak, Flowable, KeepTogether, Paragraph, Spacer

import backend.utilities.cbom_sources.pqc_targets as PQT
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
    "Function",
    "NIST PQ target",
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
_ROADMAP_COLS = (22, 46, 42, 36, 28, 52, 118, 42, 112, 50, 54, 60, 58)
_MANUAL_COLS = (10, 11, 12)  # Wave, Target date, Owner / status: left blank for the assessor
_TIMELINE_HEADERS = ("When", "Milestone", "Status", "Source", "Source URL")
# The URL column fits the longest authored URL (CNSA 2.0, 305 pt at 7 pt) on one line.
_TIMELINE_COLS = (56, 198, 50, 96, 320)
_FAMILY_HEADERS = ("Function", "NIST PQ target", "CNSA 2.0", "Reference", "Assets", "Sources")
_FAMILY_COLS = (150, 230, 120, 90, 60, 70)
_WAVE_HEADERS = ("Wave", "What goes in it", "Assets", "Proposed date", "Basis (public milestones)", "Owners")
_WAVE_COLS = (34, 150, 44, 70, 270, 152)
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
    "Current assets (code scans and collected infrastructure) with no known quantum weakness, the "
    "population of the summary card, by the NIST quantum "
    "security level the engine recorded. Level 0 would mean no security against a quantum "
    "computer. Hybrid means a key exchange that combines a classical and a post-quantum "
    "algorithm."
)
_NO_SAFE_TEXT = "No quantum-safe asset is recorded in the current scans and collections."
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
    "against a quantum computer. The NIST PQ target follows the asset's function (key "
    "establishment, TLS / SSH / IKE key exchange, signatures, certificates, CAs, code signing, "
    "symmetric, hashes): the NIST default parameter set first, the CNSA 2.0 one below it, with "
    "the FIPS 203 / 204 / 205 or SP 800-208 reference. One table in the crypto knowledge base "
    "drives it, the same one behind the run pages.",
    "A dash (" + _DASH + ") means the value is not recorded: legacy-format scans carry no "
    "classical strength, quantum security level or sized target.",
    "Wave, target date and owner / status are for the assessor to complete. This document "
    "lists assets and the NIST target for each; it does not sequence the migration.",
)
_UNKNOWN_FUNCTION = "not recorded"
# With the team's remediation plan loaded (``view.remediation``) the last note is replaced by this one: the three
# columns are filled from the plan, and scan-node / cloud assets get their own table.
_PLAN_NOTE = (
    "Wave, target date and owner / status come from the team's remediation plan in DevSecShield. "
    "Where no wave was assigned, the suggested wave is printed with \"(suggested)\": 1 = critical or high "
    "and internet-facing or harvest-now-decrypt-later, 2 = other critical or high, 3 = any other weakness, "
    "4 = quantum-vulnerable with no other weakness. A target date marked \"(proposed)\" is the wave's date from "
    "the public milestones (NIST IR 8547, CNSA 2.0); an owner marked \"(source owner)\" is the owner recorded on the "
    "source. Waves, dates and owners are proposals until ZeroShield confirms them with the asset owners before issue."
)
_WAVE_INTRO = (
    "Each wave with its proposed completion date. The dates come from public milestones (NIST IR 8547, CNSA 2.0), "
    "not from this document; an assigned date in the plan replaces the proposal. ZeroShield confirms waves, dates and "
    "owners with the asset owners before issue."
)
_NODE_HEADERS = ("#", "Asset", "Type", "Algorithm / key", "NIST PQ target", "Impact", "Where found", "Wave",
                 "Target date", "Owner / status")
_NODE_COLS = (22, 100, 52, 72, 124, 42, 142, 44, 64, 58)

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


def _effective_wave(plan: dict | None) -> int | None:
    """The wave a row is planned in: the assigned one, else the suggested one."""
    if plan is None:
        return None
    wave = (plan.get("assigned") or {}).get("wave") or plan.get("suggested")
    return int(wave) if isinstance(wave, int) and not isinstance(wave, bool) else None


def _plan_cells(plan: dict | None, suggested: int | None, owner_hint: str | None = None) -> list[str]:
    """Wave, target date and owner / status from the team's remediation plan (blank without a plan). A date the plan
    does not set is the wave's proposed date (``pqc_targets.wave_milestone``, "(proposed)"); an owner it does not set
    is the source's recorded owner (C5, "(source owner)"), else ``UNASSIGNED_OWNER``."""
    if plan is None:
        return ["", "", ""]
    assigned = plan.get("assigned") or {}
    wave = assigned.get("wave")
    wave_text = str(wave) if wave else (f"{suggested} (suggested)" if suggested else "")
    date = str(assigned.get("target_date") or "")
    if not date:
        milestone = PQT.wave_milestone(wave or suggested)
        date = f"{milestone['date']} (proposed)" if milestone else ""
    status = str(assigned.get("status") or "").replace("_", " ")
    owner = assigned.get("owner") or ""
    if not owner:
        hint = str(owner_hint or "").strip()
        owner = f"{hint} (source owner)" if hint else PQT.UNASSIGNED_OWNER
    owner = " / ".join(x for x in (owner, status if assigned else "") if x)
    return [wave_text, date, owner]


def _code_target(asset: AssetAgg) -> dict | None:
    """The NIST PQ target of a code-scan algorithm row, from its primitive (``pqc_targets``, as the API's
    ``waves.code_items``)."""
    return PQT.asset_target(asset.asset_type, asset.title, None, asset.primitive)


def _function(target: dict | None) -> str:
    return target["usage_label"] if target else _UNKNOWN_FUNCTION


def _short_function(target: dict | None) -> str:
    """The function without its examples ("Key establishment"), for the narrow per-asset column."""
    return _function(target).split(" (")[0]


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
        _short_function(_code_target(asset)),
        PQT.cell_text(_code_target(asset)),
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


def _families(rows: list[AssetAgg], styles: Styles, width: float, title: str,
              node_rows: Sequence[dict] = ()) -> list[Flowable]:
    """NIST PQ targets by function, over the code-scan rows and the collected infrastructure rows."""
    order = list(PQT.table())
    tally: dict[str, tuple[int, set[str]]] = {}
    targets: dict[str, dict | None] = {}
    entries = [(_code_target(a), a.source_key) for a in rows]
    entries += [(PQT.target_for(r.get("pq_usage")), str(r.get("source_name") or "")) for r in node_rows]
    for target, source in entries:
        usage = target["usage"] if target else ""
        targets[usage] = target
        count, sources = tally.get(usage, (0, set()))
        tally[usage] = (count + 1, sources | {source})
    table_rows = []
    for usage in sorted(tally, key=lambda u: (order.index(u) if u in order else len(order), u)):
        target, (count, sources) = targets[usage], tally[usage]
        table_rows.append([
            _function(target), target["target_text"] if target else PQT.cell_text(None),
            target["cnsa_target"] if target else _DASH, target["reference"] if target else _DASH,
            str(count), str(len(sources))])
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
    collected = len((view.remediation or {}).get("node_rows") or []) + int(
        (view.remediation or {}).get("node_rows_omitted") or 0)
    if view.is_empty:
        title, message = _NO_SCANS_TITLE, _NO_SCANS_TEXT
    elif collected:
        # the collected infrastructure has quantum-vulnerable assets (next section): "none found" would contradict it
        title = authored.PQC_NO_VULNERABLE_CODE_TITLE
        message = authored.PQC_NO_VULNERABLE_CODE_TEXT.format(count=_plural(collected, "quantum-vulnerable asset"))
    else:
        title, message = authored.PQC_NO_VULNERABLE_TITLE, authored.PQC_NO_VULNERABLE_TEXT
    block = KeepTogether(
        [_heading(f"{title_prefix} {title}", styles), _note(message, styles, style="body")]
    )
    return [block, Spacer(1, 4)]


def _safe_section(view: TeamCbomView, styles: Styles, width: float, title: str) -> list[Flowable]:
    # the population of the summary card "Quantum-safe" (cbom_team_rollup._headline: every current asset, code scans
    # and collected infrastructure), so the card and this section never disagree (audit A-08)
    safe = [a for a in view.assets if a.current and a.quantum_vulnerable is False and not a.broken_today]
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
        kinds = Counter(a.asset_type for a in safe)
        parts += [
            _note(_SAFE_INTRO, styles),
            dense_table(_LEVEL_HEADERS, rows, _fit(_LEVEL_COLS, width, stretch=False)),
            Spacer(1, 3),
            _note("By asset type: " + ", ".join(f"{k} {n}" for k, n in sorted(kinds.items(), key=lambda kv: (-kv[1], kv[0]))),
                  styles),
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


def _node_key(item: dict) -> str:
    """Algorithm / key of a collected row; a TLS or SSH endpoint leads with its key-exchange group (the part a
    quantum computer breaks), not only the symmetric suite."""
    key = item.get("algorithm") or ""
    if item.get("key_size"):
        key = f"{key} {item['key_size']}".strip()
    group = str(item.get("kex_group") or "").strip()
    if group and item.get("pq_usage") in ("tls_kex", "ssh_kex", "vpn_kex"):
        key = f"{group} (key exchange)" + (f"\n{key}" if key else "")
    return key or _DASH


def _node_section(view: TeamCbomView, styles: Styles, width: float, title: str, max_rows: int) -> list[Flowable]:
    """Quantum-vulnerable assets of each collection source's latest complete run (scan nodes, cloud worker)."""
    rem = view.remediation or {}
    rows = rem.get("node_rows") or []
    table_rows = []
    for number, item in enumerate(rows[: max(int(max_rows), 0)], start=1):
        collected = (item.get("collected_at") or "")[:10]
        where = "\n".join(x for x in (item.get("source_name") or "", item.get("target") or "",
                                       item.get("location") or "", f"collected {collected}" if collected else "") if x)
        impact = str(item.get("impact") or "Info")
        plan = {"assigned": item.get("assignment") or {}, "suggested": item.get("suggested_wave")}
        table_rows.append([
            str(number), item.get("label") or "", item.get("type") or "", _node_key(item),
            PQT.cell_text(PQT.target_for(item.get("pq_usage"))),
            status_chip(impact.upper(), tone_for_impact(impact)), where,
            *_plan_cells(plan, plan["suggested"], item.get("owner_hint")),
        ])
    story: list[Flowable] = [
        *section_heading(title, styles),
        _note("Quantum-vulnerable assets found by scan nodes and the ZeroShield cloud worker in each source's "
              "latest complete collection (servers, clusters, databases, cloud accounts, identity providers, "
              "network endpoints), each with the NIST post-quantum target of its function.", styles),
    ]
    if table_rows:
        story.append(dense_table(_NODE_HEADERS, table_rows, _fit(_NODE_COLS, width)))
    omitted = len(rows) - len(table_rows) + int(rem.get("node_rows_omitted") or 0)
    if omitted > 0:
        story += [Spacer(1, 3), _note(_OMITTED_TEMPLATE.format(omitted=_plural(omitted, "further row"),
                                                               cap=max(int(max_rows), 0)), styles)]
    story.append(Spacer(1, 4))
    return story


def _owner_of(plan: dict, hint: str | None) -> str:
    owner = (plan.get("assigned") or {}).get("owner") or str(hint or "").strip()
    return owner or PQT.UNASSIGNED_OWNER


def _waves(view: TeamCbomView, rows: list[AssetAgg], styles: Styles, width: float, title: str) -> list[Flowable]:
    """Count, proposed date, basis and owners per wave over the code-scan rows and the collected rows."""
    planned: list[tuple[int | None, str]] = []
    for asset in rows:
        plan = _asset_plan(view, asset) or {}
        planned.append((_effective_wave(plan), _owner_of(plan, None)))
    rem = view.remediation or {}
    for item in rem.get("node_rows") or []:
        plan = {"assigned": item.get("assignment") or {}, "suggested": item.get("suggested_wave")}
        planned.append((_effective_wave(plan), _owner_of(plan, item.get("owner_hint"))))
    by_wave: dict[int, Counter] = {}
    for wave, owner in planned:
        if wave is not None:
            by_wave.setdefault(wave, Counter())[owner] += 1
    table_rows = []
    for wave in sorted(by_wave):
        owners = by_wave[wave]
        milestone = PQT.wave_milestone(wave) or {}
        named = [f"{o} ({n})" for o, n in sorted(owners.items(), key=lambda kv: (-kv[1], kv[0]))
                 if o != PQT.UNASSIGNED_OWNER][:3]
        if owners.get(PQT.UNASSIGNED_OWNER):
            named.append(f"{owners[PQT.UNASSIGNED_OWNER]} {PQT.UNASSIGNED_OWNER}")
        table_rows.append([str(wave), PQT.WAVE_LABEL.get(wave, ""), str(sum(owners.values())),
                           milestone.get("date") or _DASH, milestone.get("basis") or "", "\n".join(named)])
    parts: list[Flowable] = [*section_heading(title, styles), _note(_WAVE_INTRO, styles)]
    if table_rows:
        parts.append(dense_table(_WAVE_HEADERS, table_rows, _fit(_WAVE_COLS, width)))
    return [*parts, Spacer(1, 4)]


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
    node_rows = (view.remediation or {}).get("node_rows") or []
    if rows or node_rows:
        story += _families(rows, styles, width, title("NIST post-quantum targets by function"), node_rows)
    if rows:
        story += _roadmap(rows, styles, width, title("Per-asset roadmap"), max_rows, view)
    else:
        story += _no_rows(view, styles, str(next(counter)))
    if view.remediation is not None and node_rows:
        story += _node_section(view, styles, width, title("Collected infrastructure (scan nodes and cloud)"),
                               max_rows)
    if view.remediation is not None and (rows or node_rows):
        story += _waves(view, rows, styles, width, title("Waves: proposed dates and owners"))
    if not view.is_empty:
        story += _safe_section(view, styles, width, title("Already quantum-safe and hybrid"))
    if previous:
        story += _previously_seen(
            previous, styles, width, title(authored.PREVIOUSLY_SEEN_TITLE), max_rows
        )
    story += _notes_section(styles, title("Notes"), planned=view.remediation is not None)
    return story


def build_pdf(view: TeamCbomView, *, max_rows: int = MAX_ROWS, ctx: Any = None) -> bytes:
    """Render the PQC Migration Roadmap of ``view`` as a landscape PDF (bytes)."""

    def body(styles: Styles, width: float) -> list[Flowable]:
        return build_body(view, styles, width, max_rows=max_rows)

    return build_document(ctx=ctx, 
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
