"""Scope Baseline and Asset Population Register (SOW D1): the team-wide PDF renderer.

One portrait PDF that records WHAT was assessed for a team: the sources (repositories, archives,
uploaded CBOM files, CBOM Sources collections) behind its completed CBOM results, the cryptographic
asset population found in them, how every scan was treated, and the parts of the scope the method
did not cover, which are left as blank forms for the assessor.  Sections, in order:

    A. Assessment boundary            manual: boundary items, boundary statement and approver
    B. Sources assessed               live: one row per source with its SOW layer (L1-L4), and the
                                      source metadata (owner, application, data classification,
                                      lifetime, criticality, exposure) from the platform, "to confirm"
                                      where the platform holds none
    C. Asset population               live: by SOW layer, by kind x impact, by source, and the
                                      reconciliation of occurrences, distinct assets and BOM components
    D. Exclusions and data quality    live: every scan accounted for, why some were left out
    E. Outside static / collected     manual: checklist with blank status / owner / evidence; it never
       visibility                     lists what a CBOM Sources collection read (probed endpoints ...)
    F. Sign-off                       manual: blank

Contract (plan 5.2 / 5.4): ``build_pdf(view: TeamCbomView) -> bytes`` is a pure function of the
view.  ``build_body(view, styles, width)`` returns the document-specific flowables and is public
only so tests can inspect the structure (for example that a manual cell is truly empty).

Rules this module keeps (enforced by the T-1 tests and the T-NOLLM guards):

* reportlab and the standard library only, plus ``backend.utilities.pdf.*`` and the aggregator
  module ``backend.utilities.dashboard.cbom_team_rollup``; never a router, never anything that
  could reach a language model or the network.
* No wall clock: every date comes from the view (``generated_at`` / ``as_of`` and the scan
  dates), so the same view gives byte-identical output.
* Every data-derived string (labels, URLs, branches, titles, statuses) reaches a Paragraph only
  through ``pdf_text`` or a ``dense_table`` / ``status_chip`` helper, which sanitise, clamp and
  escape it.  Scanned repositories are untrusted input.
* Repository URLs are sanitised once more at render time, so a credential could not reach the
  page even through a hand-built view.
* Manual cells ("(assessor)") are empty.  Nothing is pre-filled, guessed or marked "N/A".  The
  source metadata table is not a manual form: it prints what the platform holds for each source and
  "to confirm" where it holds nothing (SOW audit A-10).
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from datetime import date, datetime, timezone
from typing import Any

from reportlab.lib.styles import ParagraphStyle
from reportlab.platypus import CondPageBreak, Flowable, KeepTogether, Paragraph, Spacer

from backend.utilities.dashboard.cbom_team_rollup import (
    EXCLUDED_FAILURE,
    EXCLUDED_NO_DATA,
    EXCLUDED_NOT_COMPLETED,
    FIDELITY_FULL,
    IMPACT_LEVELS,
    INFO,
    SOURCE_FILE,
    SOURCE_REPO,
    SOURCE_SCAN,
    SOURCE_ZIP,
    STATUS_FAILURE,
    STATUS_SUCCESS,
    ScanFacts,
    SourceAgg,
    TeamCbomView,
    removed_collections,
    sanitize_repo_url,
)
from backend.utilities.pdf import cbom_deliverable_text as authored
from backend.utilities.pdf import cbom_population as population
from backend.utilities.pdf.cbom_deliverable_common import (
    Styles,
    build_document,
    dense_table,
    fmt_date_utc,
    kpi_strip,
    pdf_text,
    section_heading,
    signoff_block,
    status_chip,
)
from backend.utilities.pdf.report_branding import REPORT_META

REPORT_KEY = "cbom_scope_register"
DELIVERABLE_NUMBER = 1  # SOW D1 (REPORT_META sow_id; the Document ID reads it)
TITLE = REPORT_META[REPORT_KEY]["title"]

# Table caps (plan 4.7): an explicit omission notice is printed whenever a cap bites.
MAX_SOURCE_ROWS = 500
MAX_EXCLUDED_ROWS = 100
_MAX_NAMED_SOURCES = 10  # legacy sources spelled out in the data-quality table

_DASH = "\u2014"
_WRITE_IN_HEIGHT = 16  # points of blank room in a manual cell (row = this + padding)
_STATEMENT_HEIGHT = 36

# ---------------------------------------------------------------------------------------------
# Authored text.  Product wording specific to THIS document (it describes what the register
# does; it makes no standards or regulatory claim).  Shared wording, and every sentence that
# cites a public source, lives in ``cbom_deliverable_text`` (banners, disclaimers, boundary
# items, the outside-visibility checklist, the failed-latest template).
# ---------------------------------------------------------------------------------------------
# Product text: how a source is identified (cbom_team_rollup.source_key_for, plan 4.3).
_SOURCES_INTRO = (
    "Sources assessed: {sources}. Completed scans included: {included}. A source is one "
    "repository branch, one uploaded archive, one uploaded CBOM file or one CBOM Sources source; "
    "its current state is its latest successful scan or collection."
)
_SOURCES_NONE = (
    "No sources have been assessed: no completed CBOM scan exists for this team, so there is "
    "nothing to list."
)
_SOURCES_LIMITS = (
    "Limits: the same repository on two branches is two sources; two uploaded archives with "
    "the same title are one source."
)
_ASSETS_LEGEND = (
    "Layer: the SOW scope layer of the source (L1 code, pipelines and images; L2 servers, Kubernetes "
    "and databases; L3 cloud keys, HSMs, PKI and identity; L4 network, TLS and appliances). Assets: "
    "the asset occurrences in the source's current result."
)
_METADATA_INTRO = (
    "Source metadata held by the platform (the owner, application, data classification, data "
    "lifetime, business criticality and exposure set on each CBOM Sources source). \"to confirm\" "
    "marks a value the platform does not hold; a code repository carries none, so its owner and "
    "application are confirmed with the client."
)
_LEGACY_LEGEND = (
    "Legacy: the scan predates the current CBOM engine (reduced fidelity). Certificate "
    "details, compliance results and post-quantum target sizing may be incomplete; re-scan "
    "the source to restore full detail."
)
# Plan 4.5 failed-latest rule.  A failed attempt uses the authored SOURCE_FAILED_LATEST; the
# two other ways a newest attempt can differ from the scan the figures come from get the same
# shape, so the register never calls a queued or empty scan "failed".
_ATTEMPT_NOT_COMPLETED = (
    "most recent attempt has not completed (scan #{attempt_id}, {attempt_date}); "
    "figures reflect scan #{current_id} of {current_date}"
)
_ATTEMPT_NO_DATA = (
    "most recent attempt completed without usable data (scan #{attempt_id}, {attempt_date}); "
    "figures reflect scan #{current_id} of {current_date}"
)

# Product text: what the counts mean (cbom_team_rollup: assets are never merged across sources).
_POPULATION_BASIS = (
    "Counts describe the current state: the latest successful result of each source. An asset "
    "occurrence is one inventory row of a source's result: the same algorithm or key used in two sources "
    "is one occurrence in each, because each source's use is a separate exposure. A certificate is the "
    "exception: one observed by several sources (or by a code scan and a source) is counted once, from its "
    "latest observation, here and in the {cert_register}. The reconciliation below shows the arithmetic."
)
_COLLECTION_INTRO = (
    "How each CBOM Sources source was collected: the method, the window its latest collection ran in (UTC) and "
    "the credential it used, named by reference only; no secret value is held in or printed by this register."
)
_REMOVED_INTRO = (
    "Removed from scope: CBOM Sources sources deleted since their last collection. Their last collections are listed "
    "for the record only; none of their assets is counted in any total of this register, the board report (D14) or "
    "the posture documents. The quantum risk register (D12) keeps an asset only they read as not read (\"source "
    "deleted\"), with its last grade."
)
_REMOVED_HEADERS = ("#", "Source (deleted)", "Last run", "Last collected (UTC)", "Assets listed", "Counted")
_REMOVED_WIDTHS = (14, 196, 60, 110, 80, 80)
_COLLECTION_HEADERS = ("#", "Source", "Run", "Method", "Collection window (UTC)", "Credential reference")
_COLLECTION_WIDTHS = (14, 96, 32, 118, 96, 184)
_LAYER_INTRO = (
    "Population by SOW scope layer (SOW section 3.1, Table 4). Each source belongs to one layer; "
    "its asset occurrences are counted there by kind."
)
_LIBRARIES_LINE = (
    "Crypto libraries: {unique} unique across sources ({occurrences} source-level "
    "occurrences) in the code scans' library inventory. They are listed in the {assurance_register}. "
    "The Libraries kind above counts library assets: libraries loaded by running processes and "
    "library rows that carry a finding."
)
_EXCLUSIONS_INTRO = (
    "Only successful scans that returned data contribute to this register. The table below "
    "accounts for every CBOM scan of the team; scans of other types and of other teams are "
    "never read."
)
_NO_EXCLUDED = "No scans were excluded."
_EXCLUDED_REASONS = {
    EXCLUDED_FAILURE: "The scan failed, so no data was read.",
    EXCLUDED_NOT_COMPLETED: "The scan had not completed, so no data was read.",
    EXCLUDED_NO_DATA: "The scan completed but its result holds no usable data.",
}
_EXCLUDED_REASON_DEFAULT = "The scan was not included in this register."

_BOUNDARY_INTRO = (
    "The platform records what the scanned sources contain. Which applications, "
    "infrastructure, APIs, cloud accounts and third parties fall inside the assessment "
    "boundary is an assessor decision: complete the shaded cells below. Nothing in them is "
    "pre-filled from scan data."
)
_VISIBILITY_INTRO = (
    "A static scan of repositories and uploaded artefacts cannot see the items below. For each "
    "one, record how it is assessed, who owns it and where the evidence is kept."
)
_COLLECTED_VISIBILITY_INTRO = (
    "The code scans and the CBOM Sources collections in scope did not cover the items below. For "
    "each one, record how it is assessed, who owns it and where the evidence is kept."
)
_SIGNOFF_ROLES = ("Prepared by", "Reviewed by", "Approved by")

_KIND_LABELS = {
    SOURCE_REPO: "Repository",
    SOURCE_ZIP: "Zip upload",
    SOURCE_FILE: "CBOM file upload",
    SOURCE_SCAN: "Scan",
    "sources": "CBOM Sources collection",  # cbom_team_rollup.SOURCE_SOURCES (merge_collections)
}
_OTHER_IMPACT = "Other"

# Column widths in points for a 540 pt frame; ``_scaled`` stretches them to the real width.
_SOURCE_HEADERS = (
    "#",
    "Source",
    "Repository (sanitised)",
    "Scans",
    "First scanned",
    "Last scanned (age)",
    "Last attempt",
    "Fidelity",
    "Layer",
    "Assets",
)
_SOURCE_WIDTHS = (14, 96, 84, 28, 50, 54, 92, 42, 40, 40)  # Layer fits "to confirm" on one line (QA2 Q1-16)
_METADATA_HEADERS = ("#", "Source", "Layer", *(label for _key, label in population.METADATA_COLUMNS))
_METADATA_WIDTHS = (14, 108, 40, 82, 66, 62, 50, 54, 64)  # Layer fits "to confirm" (QA2 Q1-16)
_LAYER_WIDTHS_BASE = (150, 40, 44)
_BASIS_WIDTHS = (440, 100)
_EXCLUDED_HEADERS = ("Scan", "Title", "Source", "Created", "Status", "Reason")
_EXCLUDED_WIDTHS = (34, 100, 150, 52, 66, 138)
_QUALITY_WIDTHS = (230, 310)
_BOUNDARY_WIDTHS = (150, 270, 120)
_STATEMENT_WIDTHS = (300, 160, 80)
_CHECKLIST_WIDTHS = (108, 188, 80, 80, 84)


# ---------------------------------------------------------------------------------------------
# Small total helpers (hand-built views may carry odd values; nothing here may raise)
# ---------------------------------------------------------------------------------------------
def _num(value: object) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) else 0


def _count(counts: Mapping[str, int] | None, key: str) -> int:
    return _num(counts.get(key, 0)) if isinstance(counts, Mapping) else 0


def _scaled(base: Sequence[float], width: float) -> list[float]:
    total = float(sum(base))
    return [part * width / total for part in base]


def _day(moment: object) -> date | None:
    """The UTC calendar day of a datetime (naive values are UTC), or of a date."""
    if isinstance(moment, datetime):
        aware = moment if moment.tzinfo is not None else moment.replace(tzinfo=timezone.utc)
        return aware.astimezone(timezone.utc).date()
    return moment if isinstance(moment, date) else None


def _age_text(as_of: date, moment: object) -> str:
    """``today`` / ``1 day ago`` / ``N days ago``; empty for a missing or future date."""
    day = _day(moment)
    if day is None:
        return ""
    days = (as_of - day).days
    if days < 0:
        return ""
    if days == 0:
        return "today"
    return "1 day ago" if days == 1 else f"{days} days ago"


def _para(text: str, style: ParagraphStyle, *, limit: int = 1500) -> Paragraph:
    return Paragraph(pdf_text(text, limit=limit), style)


def _blank(height: float) -> Spacer:
    """An empty cell with room to write; carries no text at all."""
    return Spacer(1, height)


def _sub(text: str, styles: Styles) -> Paragraph:
    return Paragraph(pdf_text(text, limit=160), styles["box_title"])


def _sub_with_room(text: str, styles: Styles, room: float = 90) -> list[Flowable]:
    """A sub-heading for a table that may be long: it starts a new page rather than being left
    alone at the foot of one (``room`` = heading plus the table header and a couple of rows)."""
    return [CondPageBreak(room), _sub(text, styles)]


def _notice_sources(omitted: int) -> str:
    noun = "source is" if omitted == 1 else "sources are"
    return f"{omitted} further {noun} not listed; the totals still include every source."


def _notice_excluded(omitted: int) -> str:
    noun = "excluded scan is" if omitted == 1 else "excluded scans are"
    return f"{omitted} further {noun} not listed."


def _unique_libraries(view: TeamCbomView) -> int:
    return sum(1 for lib in view.libs if lib.current)


def _unique_certificates(view: TeamCbomView) -> int:
    return sum(1 for cert in view.certs if cert.current)


# ---------------------------------------------------------------------------------------------
# Intro
# ---------------------------------------------------------------------------------------------
def _intro(styles: Styles) -> list[Flowable]:
    meta = REPORT_META[REPORT_KEY]
    return [_para(meta["intro"], styles["body"]), _para(meta["how_to_read"], styles["muted"])]


# ---------------------------------------------------------------------------------------------
# A. Assessment boundary (manual)
# ---------------------------------------------------------------------------------------------
def _section_boundary(styles: Styles, width: float) -> list[Flowable]:
    items = [
        [item, _blank(_WRITE_IN_HEIGHT), _blank(_WRITE_IN_HEIGHT)]
        for item in authored.SCOPE_BOUNDARY_ITEMS
    ]
    boundary = dense_table(
        authored.SCOPE_BOUNDARY_COLUMNS, items, _scaled(_BOUNDARY_WIDTHS, width), manual_cols=(1, 2)
    )
    statement = dense_table(
        ("Boundary statement", "Approver, name and role", "Date"),
        [[_blank(_STATEMENT_HEIGHT) for _ in range(3)]],
        _scaled(_STATEMENT_WIDTHS, width),
        manual_cols=(0, 1, 2),
    )
    return [
        *section_heading("A. Assessment boundary", styles, min_space=180),
        _para(_BOUNDARY_INTRO, styles["muted"]),
        _para(authored.MANUAL_CELL_NOTE, styles["muted"]),
        KeepTogether([_sub("Boundary items", styles), boundary]),
        Spacer(1, 6),
        KeepTogether([_sub(authored.SCOPE_BOUNDARY_STATEMENT, styles), statement]),
    ]


# ---------------------------------------------------------------------------------------------
# B. Sources assessed
# ---------------------------------------------------------------------------------------------
def _sources_attempt_parts(source: SourceAgg) -> tuple[str, str, str]:
    """A CBOM Sources source's latest attempt from its job history (staging QA2 Q1-02): "FAILED run #53
    (auth_failed)", or "NOT COMPLETED run #55 (waiting)"; the figures stay those of its latest successful run."""
    current_id, attempt_id = _num(source.current_scan_id), _num(source.last_attempt_scan_id)
    if attempt_id == current_id:
        return "SUCCESS", "low", f"run #{current_id}"
    status = str(source.last_attempt_status or "").strip().lower()
    reason = f" ({source.last_attempt_reason})" if source.last_attempt_reason else ""
    detail = (f"run #{attempt_id}{reason}, {fmt_date_utc(source.last_attempt_at)}; figures reflect run "
              f"#{current_id} of {fmt_date_utc(source.last_scanned)}")
    if status == STATUS_FAILURE:
        return "FAILED", "critical", detail
    return "NOT COMPLETED", "medium", detail


def _attempt_parts(source: SourceAgg) -> tuple[str, str, str]:
    """``(chip text, chip tone, detail)`` for a source's most recent attempt (plan 4.5)."""
    if source.kind == "sources":  # a CBOM Sources collection belongs to a run
        return _sources_attempt_parts(source)
    current_id, attempt_id = _num(source.current_scan_id), _num(source.last_attempt_scan_id)
    if attempt_id == current_id:
        return "SUCCESS", "low", f"scan #{current_id}"
    status = str(source.last_attempt_status or "").strip().lower()
    attempt_date = fmt_date_utc(source.last_attempt_at)
    current_date = fmt_date_utc(source.last_scanned)
    if status == STATUS_FAILURE:
        detail = authored.SOURCE_FAILED_LATEST.format(
            failed_date=attempt_date,
            failed_scan_id=attempt_id,
            current_scan_id=current_id,
            current_date=current_date,
        )
        return "FAILED", "critical", detail
    template, chip = (
        (_ATTEMPT_NO_DATA, "NO DATA")
        if status == STATUS_SUCCESS
        else (_ATTEMPT_NOT_COMPLETED, "NOT COMPLETED")
    )
    detail = template.format(
        attempt_id=attempt_id,
        attempt_date=attempt_date,
        current_id=current_id,
        current_date=current_date,
    )
    return chip, "medium", detail


def _attempt_cell(source: SourceAgg, styles: Styles) -> list[Flowable]:
    chip, tone, detail = _attempt_parts(source)
    return [
        status_chip(chip, tone),
        Spacer(1, 2),
        Paragraph(pdf_text(detail, limit=400), styles["dense_cell"]),
    ]


def _layer_text(source: SourceAgg, view: TeamCbomView, by_source: Mapping[str, list]) -> str:
    return population.source_layer(source, view, _assets=by_source) or population.LAYER_UNKNOWN


def _source_row(
    index: int, source: SourceAgg, view: TeamCbomView, styles: Styles,
    by_source: Mapping[str, list] | None = None,
) -> list[object]:
    label = source.label or source.key or _DASH
    repo = [sanitize_repo_url(source.repo_url) or _DASH]
    if source.branch:
        repo.append(f"branch: {source.branch}")
    scanned = [fmt_date_utc(source.last_scanned)]
    age = _age_text(view.as_of, source.last_scanned)
    if age:
        scanned.append(age)
    full = source.current_fidelity == FIDELITY_FULL
    by_source = by_source if by_source is not None else population.current_assets_by_source(view)
    return [
        str(index),
        f"{label}\n{_KIND_LABELS.get(source.kind, 'Source')}",
        "\n".join(repo),
        str(_num(source.scan_count)),
        fmt_date_utc(source.first_scanned),
        "\n".join(scanned),
        _attempt_cell(source, styles),
        status_chip("FULL" if full else "LEGACY", "low" if full else "medium"),
        _layer_text(source, view, by_source),
        str(len(by_source.get(source.key, ()))),
    ]


def _metadata_row(index: int, source: SourceAgg, view: TeamCbomView, by_source: Mapping[str, list]) -> list[object]:
    return [str(index), source.label or source.key, _layer_text(source, view, by_source),
            *population.source_metadata(source, view)]


def _section_sources(view: TeamCbomView, styles: Styles, width: float) -> list[Flowable]:
    sources = list(view.sources)
    shown = sources[: max(0, MAX_SOURCE_ROWS)]
    intro = (
        _SOURCES_INTRO.format(sources=len(sources), included=_num(view.included))
        if sources
        else _SOURCES_NONE
    )
    by_source = population.current_assets_by_source(view)
    table = dense_table(
        _SOURCE_HEADERS,
        [_source_row(i, source, view, styles, by_source) for i, source in enumerate(shown, start=1)],
        _scaled(_SOURCE_WIDTHS, width),
    )
    story: list[Flowable] = [
        *section_heading("B. Sources assessed", styles, min_space=160),
        _para(intro, styles["muted"]),
        table,
        Spacer(1, 4),
    ]
    if len(sources) > len(shown):
        story.append(_para(_notice_sources(len(sources) - len(shown)), styles["muted"]))
    notes = [_SOURCES_LIMITS, _ASSETS_LEGEND]
    if any(source.current_fidelity != FIDELITY_FULL for source in sources):
        notes.append(_LEGACY_LEGEND)
    story += [_para(note, styles["dense_muted"]) for note in notes]
    if shown:
        story += [
            Spacer(1, 8),
            *_sub_with_room("Source metadata", styles),
            _para(_METADATA_INTRO, styles["dense_muted"]),
            dense_table(_METADATA_HEADERS,
                        [_metadata_row(i, source, view, by_source) for i, source in enumerate(shown, start=1)],
                        _scaled(_METADATA_WIDTHS, width)),
        ]
    collected = _collection_rows(view)
    if collected:
        story += [
            Spacer(1, 8),
            *_sub_with_room("Collection method, window and credential", styles),
            _para(_COLLECTION_INTRO, styles["dense_muted"]),
            dense_table(_COLLECTION_HEADERS, collected, _scaled(_COLLECTION_WIDTHS, width)),
        ]
    return story + _removed_from_scope(view, styles, width)


def removed_rows(view: TeamCbomView) -> list[list[str]]:
    """One row per deleted source's last collection (``cbom_team_rollup.removed_collections``), outside every total."""
    found = sorted(removed_collections(view), key=lambda c: (str(c.label).casefold(), c.key))
    return [[str(i), c.label or c.key, f"#{_num(c.run_id)}", fmt_date_utc(c.observed_at), str(_num(c.asset_count)),
             "No"] for i, c in enumerate(found[: max(0, MAX_SOURCE_ROWS)], start=1)]


def _removed_from_scope(view: TeamCbomView, styles: Styles, width: float) -> list[Flowable]:
    rows = removed_rows(view)
    if not rows:
        return []
    return [Spacer(1, 8), *_sub_with_room("Removed from scope", styles), _para(_REMOVED_INTRO, styles["dense_muted"]),
            dense_table(_REMOVED_HEADERS, rows, _scaled(_REMOVED_WIDTHS, width))]


# ---------------------------------------------------------------------------------------------
# C. Asset population
# ---------------------------------------------------------------------------------------------
def _impact_bucket(impact: object) -> str:
    known = isinstance(impact, str) and impact in (*IMPACT_LEVELS, INFO)
    return str(impact) if known else _OTHER_IMPACT


def _impact_columns(present: Iterable[str]) -> list[str]:
    """The four severities, then Info (clean inventory, no finding) and Other only when some asset has them."""
    seen = set(present)
    return list(IMPACT_LEVELS) + [extra for extra in (INFO, _OTHER_IMPACT) if extra in seen]


def _population_kpis(view: TeamCbomView) -> list[tuple[str, str, str]]:
    """The headline tiles; the six kind tiles add up to the asset occurrences (review m4)."""
    kinds = population.kind_counts(view)
    return [
        ("Sources", str(len(view.sources)), "with a completed result"),
        ("Asset occurrences", str(_num(view.asset_occurrences)), "current state: the six kinds below"),
        ("Certificates", str(kinds["certificate"]), f"{_unique_certificates(view)} unique"),
        ("Keys and secrets", str(kinds["key"]), "occurrences"),
        ("Protocols and endpoints", str(kinds["protocol"]), "occurrences"),
        ("Algorithms", str(kinds["algorithm"]), "occurrences"),
        ("Libraries", str(kinds["library"]), "occurrences"),
        ("Encryption settings", str(kinds["setting"]), "occurrences"),
    ]


def _when(value: object) -> str:
    text = str(value or "")
    return f"{text[:10]} {text[11:16]}" if len(text) >= 16 else (text or _DASH)


def _collection_rows(view: TeamCbomView) -> list[list[object]]:
    rows = []
    by_key = population.collections_by_key(view)
    sources = [s for s in view.sources if s.key in by_key]
    for index, source in enumerate(sources[: max(0, MAX_SOURCE_ROWS)], start=1):
        found = by_key[source.key]
        info = getattr(found, "info", None) or {}
        window = f"{_when(info.get('started'))} to\n{_when(info.get('finished'))}" if info.get("finished") else _DASH
        rows.append([str(index), source.label or source.key, f"#{found.run_id}",
                     info.get("method") or population.LAYER_UNKNOWN, window,
                     info.get("credential") or population.LAYER_UNKNOWN])
    return rows


def _layer_table(view: TeamCbomView, width: float) -> Flowable:
    """Sources and asset occurrences per SOW layer, by kind, with a total row."""
    rows_in = population.layer_rows(view)
    kinds = list(population.KINDS)
    rows: list[list[object]] = []
    for row in rows_in:
        rows.append([population.layer_label(row["layer"]), str(row["sources"]), str(row["assets"]),
                     *(str(row["kinds"].get(k, 0)) for k in kinds), str(row["findings"])])
    rows.append(["All layers", str(sum(r["sources"] for r in rows_in)), str(sum(r["assets"] for r in rows_in)),
                 *(str(sum(r["kinds"].get(k, 0) for r in rows_in)) for k in kinds),
                 str(sum(r["findings"] for r in rows_in))])
    headers = ["Layer", "Sources", "Assets", *(population.KIND_LABELS[k] for k in kinds), "Findings"]
    numeric = (540.0 - 150.0) / (len(headers) - 1)
    return dense_table(headers, rows, _scaled([150.0, *([numeric] * (len(headers) - 1))], width))


def _by_type_table(view: TeamCbomView, width: float) -> Flowable:
    """Current assets by kind (rows) and impact (columns), with a total row; no "other" kind."""
    cells: Counter[tuple[str, str]] = Counter()
    for asset in view.assets:
        if asset.current:
            cells[(population.asset_kind(asset), _impact_bucket(asset.impact))] += 1
    kinds = list(population.KINDS)
    impacts = _impact_columns(i for _, i in cells)
    rows: list[list[object]] = []
    for kind in kinds:
        counts = [cells.get((kind, impact), 0) for impact in impacts]
        rows.append([population.KIND_LABELS[kind], *(str(n) for n in counts), str(sum(counts))])
    totals = [sum(cells.get((kind, impact), 0) for kind in kinds) for impact in impacts]
    rows.append(["All kinds", *(str(n) for n in totals), str(sum(totals))])
    numeric = (540.0 - 150.0) / (len(impacts) + 1)
    base = [150.0, *([numeric] * (len(impacts) + 1))]
    return dense_table(["Asset kind", *impacts, "Total"], rows, _scaled(base, width))


_KIND_SHORT = {"algorithm": "Algo.", "certificate": "Certs", "key": "Keys", "protocol": "Proto.", "library": "Libs",
               "setting": "Settings"}


def _by_source_table(view: TeamCbomView, shown: Sequence[SourceAgg], width: float) -> Flowable:
    """Current assets per source by kind and impact; the total row covers EVERY source, shown or not."""
    sources = list(view.sources)
    by_source = population.current_assets_by_source(view)
    impacts_of = {s.key: Counter(_impact_bucket(a.impact) for a in by_source.get(s.key, ())) for s in sources}
    has_info = any(c.get(INFO) for c in impacts_of.values())
    extra_impacts = any(c.get(_OTHER_IMPACT) for c in impacts_of.values())
    levels = [*IMPACT_LEVELS, INFO] if has_info else list(IMPACT_LEVELS)
    if extra_impacts:
        levels.append(_OTHER_IMPACT)
    kinds = list(population.KINDS)
    headers = ["#", "Source", "Layer", *(_KIND_SHORT[k] for k in kinds), "Total", *levels]

    def kind_counts(source: SourceAgg) -> list[int]:
        found = Counter(population.asset_kind(a) for a in by_source.get(source.key, ()))
        return [found.get(k, 0) for k in kinds]

    def impact_counts(source: SourceAgg) -> list[int]:
        return [impacts_of[source.key].get(level, 0) for level in levels]

    rows: list[list[object]] = []
    for index, source in enumerate(shown, start=1):
        counts = kind_counts(source)
        rows.append([str(index), source.label or source.key, _layer_text(source, view, by_source),
                     *(str(n) for n in counts), str(sum(counts)), *(str(n) for n in impact_counts(source))])
    if sources:
        kind_totals = [sum(col) for col in zip(*(kind_counts(s) for s in sources), strict=True)]
        impact_totals = [sum(col) for col in zip(*(impact_counts(s) for s in sources), strict=True)]
        rows.append(["", "All sources", "", *(str(n) for n in kind_totals), str(sum(kind_totals)),
                     *(str(n) for n in impact_totals)])
    fixed = [40.0] + [32.0] * len(kinds) + [32.0] + [30.0] * len(levels)  # Layer fits "to confirm" (QA2 Q1-16)
    widths = [14.0, 540.0 - 14.0 - sum(fixed), *fixed]
    return dense_table(headers, rows, _scaled(widths, width))


def _reconciliation_box(view: TeamCbomView, styles: Styles) -> list[Flowable]:
    """The population reconciliation as arithmetic (SOW audit A-09, review M6)."""
    lines = [_sub("Population reconciliation", styles)]
    lines += [_para(step, styles["dense_muted"], limit=900) for step in population.reconciliation_steps(view)]
    return [KeepTogether(lines)]


def _section_population(view: TeamCbomView, styles: Styles, width: float) -> list[Flowable]:
    shown = list(view.sources)[: max(0, MAX_SOURCE_ROWS)]
    occurrences = sum(_num(source.library_count) for source in view.sources)
    basis = _POPULATION_BASIS.format(cert_register=REPORT_META["cbom_cert_register"]["title"])
    libraries = _LIBRARIES_LINE.format(
        unique=_unique_libraries(view),
        occurrences=occurrences,
        assurance_register=REPORT_META["cbom_assurance_register"]["title"],
    )
    story: list[Flowable] = [
        *section_heading("C. Asset population", styles, min_space=200),
        _para(basis, styles["muted"]),
        kpi_strip(_population_kpis(view), width, max_per_row=4),
        Spacer(1, 6),
        *_reconciliation_box(view, styles),
        Spacer(1, 8),
        KeepTogether([_sub("Asset population by SOW layer", styles), _para(_LAYER_INTRO, styles["dense_muted"]),
                      _layer_table(view, width)]),
        Spacer(1, 8),
        KeepTogether([_sub("Assets by kind and impact", styles), _by_type_table(view, width)]),
        Spacer(1, 8),
        *_sub_with_room("Asset population by source", styles),
        _by_source_table(view, shown, width),
        Spacer(1, 4),
    ]
    if len(view.sources) > len(shown):
        omitted = len(view.sources) - len(shown)
        story.append(_para(_notice_sources(omitted), styles["dense_muted"]))
    story.append(_para(libraries, styles["dense_muted"]))
    return story


# ---------------------------------------------------------------------------------------------
# D. Exclusions and data quality
# ---------------------------------------------------------------------------------------------
def _basis_rows(view: TeamCbomView) -> list[list[object]]:
    excluded = view.excluded if isinstance(view.excluded, Mapping) else {}
    return [
        ["CBOM scans of the team", str(_num(view.scans_total))],
        ["Eligible: completed successfully", str(_num(view.eligible))],
        ["Included in this register", str(_num(view.included))],
        ["Excluded: failed", str(_count(excluded, EXCLUDED_FAILURE))],
        [
            "Excluded: not completed (queued, running or retrying)",
            str(_count(excluded, EXCLUDED_NOT_COMPLETED)),
        ],
        ["Excluded: completed without usable data", str(_count(excluded, EXCLUDED_NO_DATA))],
        ["Older scans not folded (history window)", str(_num(view.history_truncated))],
    ]


def _excluded_row(facts: ScanFacts) -> list[object]:
    return [
        f"#{_num(facts.scan_id)}",
        facts.title,
        facts.source_label,
        fmt_date_utc(facts.created_at),
        facts.status,
        _EXCLUDED_REASONS.get(facts.exclusion or "", _EXCLUDED_REASON_DEFAULT),
    ]


def _quality_rows(view: TeamCbomView) -> list[list[object]]:
    legacy = [s.label or s.key for s in view.sources if s.current_fidelity != FIDELITY_FULL]
    if legacy:
        named = "; ".join(legacy[:_MAX_NAMED_SOURCES])
        if len(legacy) > _MAX_NAMED_SOURCES:
            named += f"; and {len(legacy) - _MAX_NAMED_SOURCES} more"
        legacy_result = f"{len(legacy)}: {named}"
    else:
        legacy_result = "0"
    older_only = sum(1 for asset in view.assets if not asset.current)
    weak_identity = sum(1 for cert in view.certs if not cert.identity_strong)
    return [
        ["Sources represented by a legacy-format scan", legacy_result],
        ["Asset occurrences seen only in older scans", str(older_only)],
        ["Certificates identified without X.509 fields", str(weak_identity)],
        ["Input records skipped or corrected", str(len(view.warnings))],
    ]


def _section_exclusions(view: TeamCbomView, styles: Styles, width: float) -> list[Flowable]:
    excluded = [facts for facts in view.scans if facts.exclusion is not None]
    shown = excluded[: max(0, MAX_EXCLUDED_ROWS)]
    story: list[Flowable] = [
        *section_heading("D. Exclusions and data quality", styles, min_space=200),
        _para(_EXCLUSIONS_INTRO, styles["muted"]),
        KeepTogether(
            [
                _sub("How each CBOM scan was treated", styles),
                dense_table(("Measure", "Scans"), _basis_rows(view), _scaled(_BASIS_WIDTHS, width)),
            ]
        ),
        Spacer(1, 8),
    ]
    if shown:
        story += [
            *_sub_with_room("Scans not included", styles),
            dense_table(
                _EXCLUDED_HEADERS,
                [_excluded_row(facts) for facts in shown],
                _scaled(_EXCLUDED_WIDTHS, width),
            ),
        ]
        if len(excluded) > len(shown):
            story += [
                Spacer(1, 2),
                _para(_notice_excluded(len(excluded) - len(shown)), styles["dense_muted"]),
            ]
    else:
        story += [_sub("Scans not included", styles), _para(_NO_EXCLUDED, styles["muted"])]
    story += [
        Spacer(1, 8),
        KeepTogether(
            [
                _sub("Data-quality checks", styles),
                dense_table(
                    ("Check", "Result"), _quality_rows(view), _scaled(_QUALITY_WIDTHS, width)
                ),
            ]
        ),
    ]
    return story


# ---------------------------------------------------------------------------------------------
# E. Outside static visibility (manual) and F. Sign-off (manual)
# ---------------------------------------------------------------------------------------------
def _section_visibility(view: TeamCbomView, styles: Styles, width: float) -> list[Flowable]:
    rows = [
        [item, why, _blank(_WRITE_IN_HEIGHT), _blank(_WRITE_IN_HEIGHT), _blank(_WRITE_IN_HEIGHT)]
        for item, why in authored.manual_discovery_items(view)
    ]
    table = dense_table(
        authored.discovery_columns(view),
        rows,
        _scaled(_CHECKLIST_WIDTHS, width),
        manual_cols=(2, 3, 4),
    )
    collected = bool(authored.collections_in_scope(view))
    return [
        *section_heading(f"E. {authored.visibility_heading(view)}", styles, min_space=160),
        _para(_COLLECTED_VISIBILITY_INTRO if collected else _VISIBILITY_INTRO, styles["muted"]),
        _para(authored.MANUAL_CELL_NOTE, styles["muted"]),
        table,
    ]


def _section_signoff(styles: Styles, width: float) -> list[Flowable]:
    return [
        *section_heading("F. Sign-off", styles, min_space=170),
        signoff_block(_SIGNOFF_ROLES, title=None, width=width),
    ]


# ---------------------------------------------------------------------------------------------
# Public entry points
# ---------------------------------------------------------------------------------------------
def build_body(view: TeamCbomView, styles: Styles, width: float) -> list[Flowable]:
    """The document-specific flowables (everything below the shared front matter)."""
    story: list[Flowable] = []
    story += _intro(styles)
    story += _section_boundary(styles, width)
    story += _section_sources(view, styles, width)
    story += _section_population(view, styles, width)
    story += _section_exclusions(view, styles, width)
    story += _section_visibility(view, styles, width)
    story += _section_signoff(styles, width)
    return story


def build_pdf(view: TeamCbomView, *, ctx: Any = None) -> bytes:
    """Render SOW deliverable D1 for ``view`` and return the PDF bytes (pure, deterministic)."""
    return build_document(ctx=ctx, 
        view=view,
        number=DELIVERABLE_NUMBER,
        report_key=REPORT_KEY,
        title=TITLE,
        landscape=False,
        body=lambda styles, width: build_body(view, styles, width),
    )


__all__ = [
    "DELIVERABLE_NUMBER",
    "MAX_EXCLUDED_ROWS",
    "MAX_SOURCE_ROWS",
    "REPORT_KEY",
    "TITLE",
    "build_body",
    "build_pdf",
]
