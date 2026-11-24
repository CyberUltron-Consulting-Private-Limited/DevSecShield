"""D2 Discovery Methodology and Evidence Plan (team-wide CBOM deliverable; SOW Table 7 "D2").

``build_pdf(view)`` renders one portrait PDF from a ``TeamCbomView``.  The document answers the SOW's "how assets
are discovered, classified and evidenced" in seventeen numbered sections and an appendix:

1.  Purpose and scope             live: sources, scans, assets by type, KPI cards
2.  Collection methods and sources in scope   agentless / agent / read-only API (SOW Section 2); SOW Table 4
                                  source types per layer L1-L4, each "Configured" or "Not configured" for the team
3.  Collectors and what they record           every CBOM Sources collector, pinned to cbom_sources.kinds.KINDS
4.  Automated code discovery (L1) the registered code scanners, pinned to the engine registry
5.  Manual discovery checklist    what no collector in this edition read; status / owner / evidence BLANK
6.  Classification and grading    CycloneDX 1.6 asset types; FIPS 203/204/205, CNSA 2.0, SP 800-131A; Q-grades;
                                  Q0 Unknown policy with reasons (live open counts); risk scoring; fix classes
7.  Evidence model and integrity  signed collection, provenance, fingerprints, signed deliverables; live evidence
                                  presence counts and scan-node signing; evidence levels E0-E3
8.  Data protection               metadata only, read-only, TLS, least privilege, RBAC and audit
9.  Scan windows, OT safety and re-scans      live window, rate limits, schedules, runs by trigger
10. Validation approach           authored: deterministic rules, schema validation, no ML
11. Coverage methodology          authored tri-state semantics + live pooled table (13 frameworks)
12. Confidence classification     authored scheme and its honest limit
13. Evidence plan per deliverable D1 to D14 of SOW Table 7
14. Ownership and responsibilities (RACI)   BLANK
15. Evidence retention and versioning       what is stored per scan; retention period BLANK
16. Limits of the method          only the limits this edition's run coverage leaves true
17. Sign-off                      BLANK
    Appendix A  every code scan AND every CBOM Sources collection the edition considered

Words come from ``cbom_deliverable_text`` (shared with the other deliverables) and ``cbom_methodology_text`` (D2's
own, pinned to the product by contract tests); this module only adds the lead-in sentences that describe the
renderer's own layout.  Figures come from the view and nowhere else: ``view.collections`` (run coverage),
``view.methodology`` (the team's configured collection set-up, ``cbom_sources.methodology_facts``) and
``view.register`` (open Q0 gaps).  The only counting done here is of rows of those (and of ``view.assets`` /
``view.certs`` for the evidence-presence table), never a new aggregate such as a score or a grade.

Manual cells ("Status", "Owner", RACI, retention period, sign-off) are rendered as empty tinted
cells carrying the ``(assessor)`` suffix in their header.  They are never pre-filled.

Hard rules (enforced by ``test_cbom_deliverable_methodology.py``): reportlab and the standard
library only, plus ``backend.utilities.pdf.*`` and the roll-up types; no network, no language
model, no wall clock (every date comes from the view); every data-derived string reaches a
``Paragraph`` through ``pdf_text`` (scanned repositories are untrusted input); Helvetica and
Courier only; Python 3.10 syntax.
"""

from __future__ import annotations

from typing import Any

from collections import Counter
from collections.abc import Sequence

from reportlab.lib.enums import TA_LEFT
from reportlab.lib.styles import ParagraphStyle
from reportlab.platypus import Flowable, KeepTogether, Paragraph, Spacer

from backend.utilities.dashboard.cbom_team_rollup import (
    ASSET_ALGORITHM,
    ASSET_OTHER,
    ASSET_TYPES,
    EXCLUDED_FAILURE,
    EXCLUDED_NO_DATA,
    EXCLUDED_NOT_COMPLETED,
    FIDELITY_FULL,
    HISTORY_WINDOW,
    SOURCE_FILE,
    SOURCE_REPO,
    SOURCE_SCAN,
    SOURCE_ZIP,
    FrameworkPool,
    ScanFacts,
    TeamCbomView,
)
from backend.utilities.pdf import cbom_deliverable_text as authored
from backend.utilities.pdf import cbom_methodology_text as method
from backend.utilities.pdf.cbom_deliverable_common import (
    TEMPLATE_VERSION,
    document_digest_of,
    Styles,
    build_document,
    dense_table,
    document_id,
    fmt_date_utc,
    kpi_strip,
    pdf_text,
    section_heading,
    signoff_block,
)
from backend.utilities.pdf.report_branding import REPORT_META

SLUG = "methodology-evidence-plan"
NUMBER = 2  # SOW D2 (REPORT_META sow_id; the Document ID reads it)
DOCUMENT_CODE = NUMBER
REPORT_KEY = "cbom_methodology"  # REPORT_META key: page header and footer label
TITLE = REPORT_META[REPORT_KEY]["title"]

# Appendix A lists at most this many scans (newest first); the rest get a one-line notice.
MAX_SCAN_ROWS = 500

SECTION_TITLES = (
    "Purpose and scope",
    "Collection methods and sources in scope",
    "Collectors and what they record",
    "Automated code discovery (L1)",
    "Manual discovery checklist",
    "Classification and grading",
    "Evidence model and integrity",
    "Data protection",
    "Scan windows, OT safety and re-scans",
    "Validation approach",
    "Coverage methodology",
    "Confidence classification",
    "Evidence plan per deliverable",
    "Ownership and responsibilities (RACI)",
    "Evidence retention and versioning",
    "Limits of the method",
    "Sign-off",
)
SEC = {title: number for number, title in enumerate(SECTION_TITLES, start=1)}
APPENDIX_TITLE = "Appendix A. Scans and collections considered"
SIGNOFF_ROLES = ("Prepared by", "Reviewed by (CISO)", "Approved by")

# Document-specific lead-in sentences.  Provenance (plan 5.7): none of them is a standards or
# regulatory claim; each describes this document's own tables or the product's behaviour, so
# each carries a "Product text:" comment naming the code it describes.
#
# Product text: plan 4.6 (empty team) - the same stance as the "NO COMPLETED CBOM SCANS" banner.
EMPTY_SCOPE = (
    "No completed CBOM scan is available for this team yet, so this edition reports no live "
    "figures. The method below applies to every scan the team runs."
)
# Product text: the checklist columns are left blank by design (cbom_deliverable_text
# MANUAL_DISCOVERY_ITEMS); nothing in the platform records manual discovery.
MANUAL_INTRO = (
    "These discovery activities cannot be performed by static analysis. Record the status, "
    "owner and evidence reference for each one; the platform leaves them blank."
)
# Product text: ownership is not stored anywhere in the platform.
RACI_INTRO = (
    "Name who is responsible, accountable, consulted and informed for each activity. The "
    "platform does not pre-fill this table."
)
# Product text: the pooled counts and the coverage of backend/utilities/dashboard/
# cbom_team_rollup.py FrameworkPool (aibom compliance engine rule: pass / (pass + fail)).
COVERAGE_FORMULA_NOTE = (
    "Coverage = (Pass + Pass with evidence) / (Pass + Pass with evidence + Fail). Not "
    "evidenceable and out-of-scope requirements are shown as their own counts and are never "
    "counted as passes."
)
# Product text: asset occurrences are per source, certificates are de-duplicated (plan 4.4).
ASSET_TABLE_NOTE = (
    "Occurrences are counted per source and file and are not merged, because each source's "
    "usage is a separate exposure. A certificate found in several places is several "
    "occurrences here but one unique certificate in the card above."
)
# Product text: the three tables of section 2 (methods, SOW Table 4 rows matched to the team's sources).
METHODS_INTRO = (
    "Data is collected in the three ways SOW Section 2 names. The table after it lists every source type of SOW "
    "Table 4 by layer with the method that reads it and whether this team has it configured."
)
# Product text: section 3 table (cbom_methodology_text.COLLECTORS, pinned to cbom_sources.kinds.KINDS).
COLLECTORS_INTRO = (
    "Each CBOM Sources collector, the layer it serves, how it connects, what it records and what it never reads. "
    "'This edition' counts the sources of that kind whose latest complete collection is included (ep. = "
    "endpoints probed)."
)
# Product text: section 6 tables (cbom_methodology_text, pinned to qgrade / agility).
CLASSIFICATION_INTRO = (
    "Every collected or scanned cryptographic item is normalised into a CycloneDX 1.6 cryptographic asset of one of "
    "four types (crypto libraries are CycloneDX library components), then graded and scored as follows."
)
# Product text: section 7 tables.
EVIDENCE_INTRO = (
    "Each figure in the deliverables can be traced from the signed collection request to the signed file the "
    "customer receives:"
)
EVIDENCE_LEVELS_INTRO = (
    "Evidence the customer supplies (policies, vendor letters, attestations) is rated by confidence; documented "
    "evidence expires after 365 days and then counts as E0."
)
# Product text: section 13 table (cbom_methodology_text.EVIDENCE_PLAN).
PLAN_INTRO = (
    "For each deliverable of SOW Table 7: where the platform produces it and the evidence a reviewer can check it "
    "against."
)
# Product text: Appendix A, second table (view.collections: each source's latest complete collection, M1x).
COLLECTION_APPENDIX_INTRO = (
    "Every CBOM Sources collection this edition included: the latest complete collection of each source, with the "
    "run that collected it. Each counts as one completed CBOM result in the Basis box."
)
# Product text: current / history-only scans and exclusions (plan 4.1 and 4.5).
SCAN_APPENDIX_INTRO = (
    "Every CBOM scan of this team that this edition considered, newest first. 'Current for "
    "source' marks the scan that defines a source's present state; 'History only' scans "
    "contribute first-seen and last-seen dates; excluded scans contribute nothing."
)

# ---------------------------------------------------------------------------------------------
# Small private helpers
# ---------------------------------------------------------------------------------------------
_DASH = "\u2014"
_BULLET = "\u2022"
_TEXT_LIMIT = 2000  # authored paragraphs are long; pdf_text's default (300) would cut them
_CELL_LIMIT = 700  # scanner descriptions run to ~290 characters; leave generous headroom
_BLANK_HEIGHT = 18  # write-in cells are at least this tall (points)

ASSET_LIBRARY = "library"  # a CBOM Sources crypto library: a CycloneDX library component in the run CBOM
_ASSET_TYPE_LABELS = {
    "algorithm": "Algorithm",
    "certificate": "Certificate",
    "protocol": "Protocol",
    "related-crypto-material": "Related crypto material",
    ASSET_LIBRARY: "Crypto library (CycloneDX library component)",
    ASSET_OTHER: "Other",
}
_SOURCE_KIND_NOUNS = (
    (SOURCE_REPO, "repository", "repositories"),
    (SOURCE_ZIP, "zip upload", "zip uploads"),
    (SOURCE_FILE, "uploaded CBOM file", "uploaded CBOM files"),
    (SOURCE_SCAN, "other scan", "other scans"),
    ("sources", "collected infrastructure source", "collected infrastructure sources"),  # SOURCE_SOURCES
)
_EXCLUSION_TEXT = {
    EXCLUDED_FAILURE: "Excluded: failed",
    EXCLUDED_NOT_COMPLETED: "Excluded: not completed",
    EXCLUDED_NO_DATA: "Excluded: no data",
}
_EVIDENCE_COLUMNS = ("Evidence recorded", "Present for", "Out of", "Share")
_POOL_COLUMNS = (
    "Framework",
    "Pass",
    "Pass with evidence",
    "Fail",
    "Not evidenceable",
    "Out of scope",
    "Coverage",
    "Sources pooled",
)
_APPENDIX_COLUMNS = (
    "Scan",
    "Title",
    "Source",
    "Created (UTC)",
    "Disposition",
    "Fidelity",
    "Assets",
)


def _count(number: int, singular: str, plural: str | None = None) -> str:
    """``1 scan`` / ``8 scans`` (``plural`` overrides the regular ``+s``)."""
    return f"{number} {singular if number == 1 else (plural or singular + 's')}"


def _join_and(parts: Sequence[str]) -> str:
    """``a``, ``a and b``, ``a, b and c``."""
    if len(parts) <= 1:
        return "".join(parts)
    return ", ".join(parts[:-1]) + " and " + parts[-1]


def _share(part: int, whole: int) -> str:
    return "n/a" if whole <= 0 else f"{100.0 * part / whole:.1f}%"


def _percent(ratio: float | None) -> str:
    return "n/a" if ratio is None else f"{100.0 * ratio:.1f}%"


def _para(text: object, style: ParagraphStyle) -> Paragraph:
    """The only way a sentence becomes a Paragraph: sanitised, clamped and escaped."""
    return Paragraph(pdf_text(text, limit=_TEXT_LIMIT), style)


def _blank() -> Flowable:
    """An empty write-in cell of a sensible height (an empty Paragraph would be ~0 pt tall)."""
    return Spacer(1, _BLANK_HEIGHT)


def _local_styles(styles: Styles) -> dict[str, ParagraphStyle]:
    return {
        "bullet": ParagraphStyle(
            "MethodologyBullet",
            parent=styles["body"],
            alignment=TA_LEFT,
            leftIndent=14,
            bulletIndent=3,
            spaceAfter=2,
        ),
        "strong": ParagraphStyle(
            "MethodologyStrong", parent=styles["dense_cell"], fontName="Helvetica-Bold"
        ),
        "caption": ParagraphStyle(
            "MethodologyCaption", parent=styles["muted"], spaceBefore=3, spaceAfter=4
        ),
    }


def _heading_text(number: int) -> str:
    return f"{number}. {SECTION_TITLES[number - 1]}"


def _section(
    number: int, styles: Styles, content: Sequence[Flowable], *, together: bool
) -> list[Flowable]:
    """Heading plus content.  ``together`` keeps a short section on one page, heading included."""
    heading = _heading_text(number)
    if not together:
        return [*section_heading(heading, styles), *content]
    return [
        KeepTogether([Paragraph(pdf_text(heading, limit=160), styles["section_heading"]), *content])
    ]


# ---------------------------------------------------------------------------------------------
# 1. Purpose and scope (live)
# ---------------------------------------------------------------------------------------------
def _framework_keys(view: TeamCbomView) -> list[str]:
    """The registered frameworks in engine order, then any key the view has that we do not know."""
    known = list(authored.FRAMEWORK_LABELS)
    extra = sorted({pool.framework for pool in view.frameworks} - set(known))
    return [*known, *extra]


def _kpis(view: TeamCbomView) -> list[tuple[str, str, str]]:
    pooled = int(view.compliance_sources_pooled)
    unique_certs = sum(1 for cert in view.certs if cert.current)
    pooled_hint = f"pooled over {_count(pooled, 'source')}" if pooled else "no results pooled"
    return [
        ("Sources", str(len(view.sources)), "assessed in this edition"),
        (
            "Scans included",
            str(int(view.included)),
            f"of {_count(int(view.eligible), 'successful scan')}",
        ),
        ("Crypto assets", str(int(view.asset_occurrences)), "current occurrences"),
        ("Unique certificates", str(unique_certs), "de-duplicated across sources"),
        ("Frameworks", str(len(_framework_keys(view))), pooled_hint),
        ("Requirements", str(len(view.requirements)), "tracked across frameworks"),
    ]


def _beyond_window(older: int, singular_tail: str, plural_tail: str) -> str:
    """``3 older successful scans fall outside the history window of 200 scans and <tail>``."""
    noun = _count(older, "older successful scan")
    if older == 1:
        return (
            f"{noun} falls outside the history window of {HISTORY_WINDOW} scans and {singular_tail}"
        )
    return f"{noun} fall outside the history window of {HISTORY_WINDOW} scans and {plural_tail}"


def _scope_text(view: TeamCbomView) -> str:
    if view.is_empty:
        return EMPTY_SCOPE
    excluded = view.excluded or {}
    included = int(view.included)
    first = (
        f"This edition reflects {_count(included, 'completed scan')} of "
        f"{_count(len(view.sources), 'source')} as of {fmt_date_utc(view.as_of)}: "
        f"{int(view.fidelity_full)} full-fidelity and {int(view.fidelity_reduced)} legacy-format."
    )
    second = (
        f"Of {_count(int(view.scans_total), 'CBOM scan')} recorded for this team, "
        f"{int(view.eligible)} completed successfully and {included} "
        f"{'is' if included == 1 else 'are'} included; "
        f"left out: {int(excluded.get(EXCLUDED_FAILURE, 0) or 0)} failed, "
        f"{int(excluded.get(EXCLUDED_NOT_COMPLETED, 0) or 0)} not completed and "
        f"{int(excluded.get(EXCLUDED_NO_DATA, 0) or 0)} completed without data."
    )
    parts = [first, second]
    older = int(view.history_truncated)
    if older > 0:
        tail = "not read, so first-seen dates may be later than the true first scan."
        parts.append(_beyond_window(older, f"was {tail}", f"were {tail}"))
    return " ".join(parts)


def _asset_type_counts(view: TeamCbomView) -> dict[str, int]:
    """``view.assets_by_type`` with the CBOM Sources rows the rollup types "other" counted under the type the run
    CBOM export writes them as (``methodology.sources_other_types``: algorithm, or a library component); review #486
    minor 9. The total is unchanged."""
    counts = {k: int(v) for k, v in (view.assets_by_type or {}).items()}
    mapped = (_facts(view) or {}).get("sources_other_types")
    if isinstance(mapped, dict):
        algorithm, library = int(mapped.get("algorithm", 0) or 0), int(mapped.get("library", 0) or 0)
        moved = min(algorithm + library, counts.get(ASSET_OTHER, 0))
        if moved == algorithm + library:
            counts[ASSET_OTHER] = counts.get(ASSET_OTHER, 0) - moved
            counts[ASSET_ALGORITHM] = counts.get(ASSET_ALGORITHM, 0) + algorithm
            if library:
                counts[ASSET_LIBRARY] = library
    return counts


def _asset_type_table(view: TeamCbomView, local: dict[str, ParagraphStyle]) -> Flowable:
    counts = _asset_type_counts(view)
    keys = [k for k in ASSET_TYPES if k != ASSET_OTHER]
    keys += [k for k in (ASSET_LIBRARY, ASSET_OTHER) if counts.get(k, 0)]
    keys += sorted(k for k in counts if k not in ASSET_TYPES and k != ASSET_LIBRARY)
    rows: list[list[object]] = [
        [_ASSET_TYPE_LABELS.get(key, key), str(int(counts.get(key, 0)))] for key in keys
    ]
    rows.append(
        [
            Paragraph(pdf_text("Total"), local["strong"]),
            Paragraph(pdf_text(str(int(view.asset_occurrences))), local["strong"]),
        ]
    )
    return dense_table(["Asset type", "Occurrences"], rows, [170, 90])


def _purpose(
    view: TeamCbomView, styles: Styles, width: float, local: dict[str, ParagraphStyle]
) -> list[Flowable]:
    body = styles["body"]
    asset_block = KeepTogether(
        [
            _para("Current asset occurrences by type", styles["table_label"]),
            Spacer(1, 2),
            _asset_type_table(view, local),
            _para(ASSET_TABLE_NOTE, local["caption"]),
        ]
    )
    content: list[Flowable] = [
        _para(authored.METHOD_PURPOSE, body),
        kpi_strip(_kpis(view), width, max_per_row=3),
        Spacer(1, 6),
        _para(_scope_text(view), body),
        asset_block,
    ]
    return _section(SEC["Purpose and scope"], styles, content, together=False)


# ---------------------------------------------------------------------------------------------
# 2. Automated discovery (scanner table pinned to the registry)
# ---------------------------------------------------------------------------------------------
def _automated(styles: Styles) -> list[Flowable]:
    rows = [
        [
            Paragraph(pdf_text(spec.name), styles["dense_mono"]),
            str(spec.order),
            spec.discovers,
            spec.evidence,
        ]
        for spec in authored.CBOM_SCANNERS
    ]
    table = dense_table(
        ["Scanner", "Order", "Discovers", "Evidence recorded"],
        rows,
        [84, 30, 236, 190],
        cell_limit=_CELL_LIMIT,
    )
    content = [
        _para(authored.CBOM_SCANNER_INTRO, styles["body"]),
        table,
        Spacer(1, 4),
        _para(authored.POSTURE_LANES_NOTE, styles["body"]),
    ]
    return _section(SEC["Automated code discovery (L1)"], styles, content, together=False)


# ---------------------------------------------------------------------------------------------
# 2. Collection methods and sources in scope (SOW Section 2 and Table 4, live)
# ---------------------------------------------------------------------------------------------
def _facts(view: TeamCbomView) -> dict[str, Any] | None:
    facts = getattr(view, "methodology", None)
    return facts if isinstance(facts, dict) else None


def _collection_variant(view: TeamCbomView, collection: Any) -> str:
    facts = _facts(view) or {}
    by_uid = (facts.get("sources") or {}).get("variant_by_uid") or {}
    key = str(getattr(collection, "key", "") or "")
    return str(by_uid.get(key.split(":", 1)[-1], "")) if key.startswith("sources:") else ""


def _sow_row_status(view: TeamCbomView, spec: method.SowSourceType) -> tuple[str, int | None, int]:
    """(status, sources of the type, of them collected in this edition) for one SOW Table 4 row."""
    facts = _facts(view)
    if spec.code:
        found = sum(1 for source in view.sources if source.kind in spec.code)
        if spec.option and found:  # read only by scans run with the option (review #486 minor 5)
            available = method.AVAILABLE_WITH_OPTION.format(option=method.OPTION_LABELS.get(spec.option, spec.option))
            code = (facts or {}).get("code")
            if not isinstance(code, dict):
                return available, None, 0
            with_option = int(code.get(spec.option, 0) or 0)
            return (method.CONFIGURED, with_option, with_option) if with_option else (available, 0, 0)
        return (method.CONFIGURED if found else method.NOT_CONFIGURED), found, found
    collections = [c for c in view.collections if c.source_kind in spec.kinds] if spec.kinds else [
        c for c in view.collections if _collection_variant(view, c) in spec.variants]
    if facts is None:
        return method.NOT_LOADED, None, len(collections)
    sources = facts.get("sources") or {}
    by_kind, variants = sources.get("by_kind") or {}, sources.get("variants") or {}
    count = (sum(int((by_kind.get(k) or {}).get("configured", 0)) for k in spec.kinds)
             + sum(int(variants.get(v, 0)) for v in spec.variants))
    if spec.ports and count:
        protocols = set((facts.get("settings") or {}).get("port_protocols") or ())
        if not protocols & set(spec.ports):
            return method.NOT_CONFIGURED + " (port not in the probe list)", count, 0
    return (method.CONFIGURED if count else method.NOT_CONFIGURED), count, len(collections) if count else 0


def _sow_table(view: TeamCbomView) -> Flowable:
    rows = []
    for spec in method.SOW_SOURCE_TYPES:
        status, count, collected = _sow_row_status(view, spec)
        rows.append([spec.layer, spec.label, spec.method, status, _DASH if count is None else str(count),
                     str(collected)])
    return dense_table(list(method.SOW_TABLE_COLUMNS), rows, [30, 214, 66, 96, 54, 60])


def _setup_sentence(view: TeamCbomView) -> str:
    facts = _facts(view)
    if facts is None:
        return "The team's CBOM Sources set-up was not loaded for this edition; the table shows code scans only."
    sources = facts.get("sources") or {}
    nodes = facts.get("nodes") or {}
    kinds = len(sources.get("by_kind") or {})
    return (f"Configured for this team: {_count(int(sources.get('total', 0) or 0), 'CBOM Sources source')} of "
            f"{_count(kinds, 'kind')}, {_count(int(nodes.get('agentless', 0) or 0), 'agentless scan node')} and "
            f"{_count(int(nodes.get('agent', 0) or 0), 'agent-mode node')}; this edition holds "
            f"{_count(len(view.collections), 'complete collection')} and "
            f"{_count(sum(1 for s in view.sources if s.kind in (SOURCE_REPO, SOURCE_ZIP, SOURCE_FILE)), 'code source')}.")


def _methods(view: TeamCbomView, styles: Styles, local: dict[str, ParagraphStyle]) -> list[Flowable]:
    table = dense_table(list(method.METHOD_COLUMNS), [list(row) for row in method.method_rows(view)],
                        [60, 190, 150, 140], cell_limit=_CELL_LIMIT)
    content: list[Flowable] = [
        _para(METHODS_INTRO, styles["body"]),
        table,
        Spacer(1, 6),
        _para(_setup_sentence(view), styles["body"]),
        _para("SOW Table 4 source types and their status for this team", styles["table_label"]),
        Spacer(1, 2),
        _sow_table(view),
        _para(method.SOW_TABLE_NOTE, local["caption"]),
    ]
    return _section(SEC["Collection methods and sources in scope"], styles, content, together=False)


# ---------------------------------------------------------------------------------------------
# 3. Collectors and what they record (pinned to cbom_sources.kinds.KINDS)
# ---------------------------------------------------------------------------------------------
def _collectors(view: TeamCbomView, styles: Styles, local: dict[str, ParagraphStyle]) -> list[Flowable]:
    collected: Counter[str] = Counter(c.source_kind for c in view.collections)
    probed: Counter[str] = Counter()
    for c in view.collections:
        probed[c.source_kind] += int(c.endpoints_probed or 0)
    rows = []
    for spec in method.COLLECTORS:
        label = spec.label if spec.in_sow else f"{spec.label} (outside SOW, 7.2)"
        this = f"{collected[spec.kind]}" + (f" / {probed[spec.kind]} ep." if probed[spec.kind] else "")
        rows.append([f"{spec.layer} {label}", spec.method, spec.transport, spec.reads, spec.never, this])
    table = dense_table(["Collector", "Method", "Connection", "Records", "Never read", "This edition"],
                        rows, [84, 50, 96, 150, 110, 50], cell_limit=_CELL_LIMIT)
    by_method = dense_table(["Method", "Evidence each record carries"],
                            [list(row) for row in method.EVIDENCE_BY_METHOD], [80, 460], cell_limit=_CELL_LIMIT)
    content: list[Flowable] = [
        _para(COLLECTORS_INTRO, styles["body"]),
        table,
        _para(method.OUT_OF_SOW_NOTE, local["caption"]),
        Spacer(1, 4),
        by_method,
        Spacer(1, 4),
    ]
    return _section(SEC["Collectors and what they record"], styles, content, together=False)


# ---------------------------------------------------------------------------------------------
# 5. Manual discovery checklist (blank; only what no collector in this edition read)
# ---------------------------------------------------------------------------------------------
def _manual_items(view: TeamCbomView) -> list[tuple[str, str]]:
    probed = method.network_probed(view)  # a database's or cluster's own TLS port is no live-network discovery
    keys = method.key_kinds_collected(view)
    out: list[tuple[str, str]] = []
    for item, reason in authored.MANUAL_DISCOVERY_ITEMS:
        if item == method.MANUAL_LIVE_TLS and probed:
            continue
        if item == method.MANUAL_KEY_CUSTODY and keys:
            reason = method.MANUAL_KEY_CUSTODY_COLLECTED
        out.append((item, reason))
    return out


def _manual(view: TeamCbomView, styles: Styles, local: dict[str, ParagraphStyle]) -> list[Flowable]:
    rows = [[item, reason, _blank(), _blank(), _blank()] for item, reason in _manual_items(view)]
    table = dense_table(
        list(authored.discovery_columns(view)),
        rows,
        [118, 192, 70, 80, 80],
        manual_cols=(2, 3, 4),
    )
    content: list[Flowable] = [_para(MANUAL_INTRO, styles["body"]), table, Spacer(1, 4)]
    probed = method.network_probed(view)
    if probed:
        content.append(_para(method.probed_note(probed), local["caption"]))
    return _section(SEC["Manual discovery checklist"], styles, content, together=True)


# ---------------------------------------------------------------------------------------------
# 6. Classification and grading (SOW 3.2)
# ---------------------------------------------------------------------------------------------
def _q0_open(view: TeamCbomView) -> dict[str, int] | None:
    register = view.register if isinstance(view.register, dict) else None
    summary = (register or {}).get("summary")
    found = summary.get("q0_gaps_open") if isinstance(summary, dict) else None
    return {str(k): int(v or 0) for k, v in found.items()} if isinstance(found, dict) else None


def _classification(view: TeamCbomView, styles: Styles, local: dict[str, ParagraphStyle]) -> list[Flowable]:
    body = styles["body"]
    types = dense_table(["CycloneDX 1.6 asset type", "What is recorded"],
                        [list(row) for row in method.ASSET_TYPE_ROWS], [120, 420])
    grades = dense_table(["Grade", "Meaning"], [list(row) for row in method.Q_GRADE_ROWS], [80, 460])
    q0_open = _q0_open(view)
    q0_rows = [[code, text, _DASH if q0_open is None else str(q0_open.get(code, 0))]
               for code, text in method.Q0_REASONS]
    q0_table = dense_table(["Q0 reason", "Meaning", "Open now"], q0_rows, [96, 384, 60])
    q0_note = ("Open now: Q0 gaps open in the team's quantum risk register (D12) when this edition was generated."
               if q0_open is not None else "The quantum risk register was not loaded, so open Q0 counts are not shown.")
    fixes = dense_table(["Fix class", "SOW term", "Meaning"], [list(row) for row in method.FIX_CLASSES],
                        [90, 70, 380])
    content: list[Flowable] = [
        _para(CLASSIFICATION_INTRO, body),
        types,
        Spacer(1, 4),
        _para(method.GRADING_TEXT, body),
        grades,
        Spacer(1, 4),
        _para(method.Q0_POLICY, body),
        KeepTogether([q0_table, _para(q0_note, local["caption"])]),
        _para(method.RISK_SCORING_TEXT, body),
        fixes,
        Spacer(1, 4),
    ]
    return _section(SEC["Classification and grading"], styles, content, together=False)


# ---------------------------------------------------------------------------------------------
# 7. Evidence model and integrity (live presence counts)
# ---------------------------------------------------------------------------------------------
def _sources_sentence(view: TeamCbomView) -> str:
    if not view.sources:
        return "No source has been assessed yet."
    kinds = Counter(source.kind for source in view.sources)
    parts = [
        _count(kinds[kind], singular, plural)
        for kind, singular, plural in _SOURCE_KIND_NOUNS
        if kinds.get(kind)
    ]
    unknown = len(view.sources) - sum(kinds.get(kind, 0) for kind, _s, _p in _SOURCE_KIND_NOUNS)
    if unknown:
        parts.append(_count(unknown, "other source"))
    return f"Evidence is drawn from {_count(len(view.sources), 'source')}: {_join_and(parts)}."


def _signing_sentence(view: TeamCbomView) -> str:
    facts = _facts(view)
    if facts is None:
        return "Scan-node signing status was not loaded for this edition."
    nodes = facts.get("nodes") or {}
    settings = facts.get("settings") or {}
    signing, legacy = int(nodes.get("signing", 0) or 0), int(nodes.get("legacy", 0) or 0)
    required = settings.get("require_signed_nodes")
    policy = ("unsigned nodes are refused (require signed nodes: on)" if required
              else "unsigned nodes are not refused (require signed nodes: off)" if required is False
              else "the team has not opened CBOM Sources settings yet")
    return (f"Scan nodes: {signing} enrolled with an Ed25519 request-signing key, {legacy} without (legacy); "
            f"{policy}.")


def _evidence(view: TeamCbomView, styles: Styles) -> list[Flowable]:
    live = [asset for asset in view.assets if asset.current]
    located = sum(1 for asset in live if (asset.location or "").strip())
    certs = [cert for cert in view.certs if cert.current]
    identified = sum(1 for cert in certs if cert.identity_strong)
    algorithms = [asset for asset in live if asset.asset_type == ASSET_ALGORITHM]
    graded = sum(1 for asset in algorithms if asset.quantum_vulnerable is not None)
    pooled, sources = int(view.compliance_sources_pooled), len(view.sources)
    rows = [
        [
            "Location of each asset occurrence (file path, host, endpoint or resource)",
            located,
            len(live),
            _share(located, len(live)),
        ],
        [
            "Certificates identified from parsed X.509 fields",
            identified,
            len(certs),
            _share(identified, len(certs)),
        ],
        [
            "Algorithm occurrences graded for quantum exposure",
            graded,
            len(algorithms),
            _share(graded, len(algorithms)),
        ],
        [
            "Sources whose latest scan carries compliance results",
            pooled,
            sources,
            _share(pooled, sources),
        ],
    ]
    chain = dense_table(["Step", "What is recorded"], [list(row) for row in method.EVIDENCE_CHAIN], [110, 430],
                        cell_limit=_CELL_LIMIT)
    table = dense_table(list(_EVIDENCE_COLUMNS), rows, [286, 80, 80, 94])
    levels = dense_table(["Evidence level", "Meaning"], [list(row) for row in method.EVIDENCE_LEVELS], [90, 450])
    content: list[Flowable] = [
        _para(EVIDENCE_INTRO, styles["body"]),
        chain,
        Spacer(1, 4),
        _para(_signing_sentence(view), styles["body"]),
        _para(authored.METHOD_EVIDENCE_TRACE, styles["body"]),
        _para(_sources_sentence(view), styles["body"]),
        KeepTogether([table, Spacer(1, 4)]),
        _para(EVIDENCE_LEVELS_INTRO, styles["body"]),
        levels,
        Spacer(1, 4),
    ]
    return _section(SEC["Evidence model and integrity"], styles, content, together=False)


# ---------------------------------------------------------------------------------------------
# 8. Data protection (SOW Section 2)
# ---------------------------------------------------------------------------------------------
def _protection(view: TeamCbomView, styles: Styles, local: dict[str, ParagraphStyle]) -> list[Flowable]:
    content: list[Flowable] = [
        Paragraph(pdf_text(line, limit=_TEXT_LIMIT), local["bullet"], bulletText=_BULLET)
        for line in method.data_protection(view)
    ]
    return _section(SEC["Data protection"], styles, content, together=True)


# ---------------------------------------------------------------------------------------------
# 9. Scan windows, OT safety and re-scans (live settings)
# ---------------------------------------------------------------------------------------------
def _window_sentence(view: TeamCbomView) -> str:
    facts = _facts(view)
    if facts is None:
        return "The team's scan window and rate limits were not loaded for this edition."
    st = facts.get("settings") or {}
    sched = facts.get("schedules") or {}
    runs = facts.get("runs") or {}
    hours = st.get("window_hours")
    window = (f"{hours} of 168 hours a week open ({st.get('window_timezone')})" if hours is not None
              else "no window set")
    default = " (product defaults: the team has not saved CBOM Sources settings)" if st.get("settings_default") else ""
    rates = ", ".join(f"{label} {st.get(key)}" for key, label in (
        ("rate_conn_per_s", "connections/s"), ("rate_parallel_per_server", "parallel per server"),
        ("rate_handshakes_per_endpoint", "handshakes per endpoint")) if st.get(key) is not None)
    stop = "on (every network job is halted)" if st.get("stop_all_network") else "off"
    ot = sorted(p for p in st.get("port_protocols") or () if p in ("opcua", "modbus", "modbus-tls"))
    return (f"This team: scan window {window}{default}; rate limits {rates or 'product defaults'}; "
            f"{_count(int(st.get('never_scan_entries', 0) or 0), 'team never-scan entry', 'team never-scan entries')}; "
            f"stop-all switch {stop}; OT probe protocols {', '.join(ot) if ot else 'none configured'}; "
            f"{_count(int(sched.get('enabled', 0) or 0), 'enabled schedule')} of {int(sched.get('total', 0) or 0)}; "
            f"{_count(int(runs.get('total', 0) or 0), 'run')} so far ({int(runs.get('scheduled', 0) or 0)} scheduled, "
            f"{int(runs.get('manual', 0) or 0)} manual).")


def _windows(view: TeamCbomView, styles: Styles) -> list[Flowable]:
    body = styles["body"]
    content = [_para(method.SCAN_WINDOW_TEXT, body), _para(method.OT_SAFETY_TEXT, body),
               _para(method.SCHEDULE_TEXT, body), _para(_window_sentence(view), body)]
    return _section(SEC["Scan windows, OT safety and re-scans"], styles, content, together=True)


# ---------------------------------------------------------------------------------------------
# 13. Evidence plan per deliverable (SOW Table 7)
# ---------------------------------------------------------------------------------------------
def _plan(styles: Styles) -> list[Flowable]:
    table = dense_table(list(method.EVIDENCE_PLAN_COLUMNS), [list(row) for row in method.EVIDENCE_PLAN],
                        [30, 140, 150, 220], cell_limit=_CELL_LIMIT)
    content = [_para(PLAN_INTRO, styles["body"]), table, Spacer(1, 4)]
    return _section(SEC["Evidence plan per deliverable"], styles, content, together=False)


# ---------------------------------------------------------------------------------------------
# 5. Validation approach
# ---------------------------------------------------------------------------------------------
def _validation(styles: Styles) -> list[Flowable]:
    return _section(SEC["Validation approach"], styles, [_para(authored.METHOD_VALIDATION, styles["body"])],
                    together=True)


# ---------------------------------------------------------------------------------------------
# 6. Coverage methodology (tri-state + live pooled table)
# ---------------------------------------------------------------------------------------------
def _pool_note(view: TeamCbomView) -> str:
    pooled = int(view.compliance_sources_pooled)
    legacy = int(view.compliance_legacy_excluded)
    legacy_sources = _count(legacy, "legacy-format source")
    if pooled:
        note = (
            f"Pooled over {pooled} of {_count(len(view.sources), 'source')} whose latest scan "
            "is full-fidelity"
        )
        if not legacy:
            return note + "."
        verb = (
            "is excluded because it carries" if legacy == 1 else "are excluded because they carry"
        )
        return f"{note}; {legacy_sources} {verb} no compliance results."
    note = "No compliance results are pooled: no source has a latest scan that is full-fidelity."
    if legacy:
        note += f" {legacy_sources} {'carries' if legacy == 1 else 'carry'} no compliance results."
    return note


def _pool_row(label: str, pool: FrameworkPool | None) -> list[object]:
    if pool is None:
        return [label, *([_DASH] * 7)]
    return [
        label,
        int(pool.passed),
        int(pool.passed_with_evidence),
        int(pool.failed),
        int(pool.not_bom_evidenceable),
        int(pool.out_of_scope),
        _percent(pool.coverage),
        int(pool.sources_pooled),
    ]


def _pool_table(view: TeamCbomView, local: dict[str, ParagraphStyle]) -> Flowable:
    pools = {pool.framework: pool for pool in view.frameworks}
    rows = [
        _pool_row(authored.framework_label(key), pools.get(key)) for key in _framework_keys(view)
    ]
    live = list(pools.values())
    totals = [
        "All frameworks",
        sum(int(p.passed) for p in live),
        sum(int(p.passed_with_evidence) for p in live),
        sum(int(p.failed) for p in live),
        sum(int(p.not_bom_evidenceable) for p in live),
        sum(int(p.out_of_scope) for p in live),
        _DASH,
        _DASH,
    ]
    rows.append([Paragraph(pdf_text(cell), local["strong"]) for cell in totals])
    return dense_table(list(_POOL_COLUMNS), rows, [160, 42, 62, 40, 66, 54, 56, 60])


def _coverage(
    view: TeamCbomView, styles: Styles, local: dict[str, ParagraphStyle]
) -> list[Flowable]:
    body = styles["body"]
    block: list[Flowable] = [_para(_pool_note(view), local["caption"]), _pool_table(view, local)]
    not_applicable = sum(int(pool.na) for pool in view.frameworks)
    if not_applicable:
        verb = "is" if not_applicable == 1 else "are"
        block.append(
            _para(
                f"{_count(not_applicable, 'requirement')} marked not applicable {verb} "
                "excluded from every column.",
                local["caption"],
            )
        )
    content = [
        _para(authored.METHOD_COVERAGE, body),
        _para(COVERAGE_FORMULA_NOTE, body),
        KeepTogether(block),
        Spacer(1, 4),
    ]
    return _section(SEC["Coverage methodology"], styles, content, together=False)


# ---------------------------------------------------------------------------------------------
# 7. Confidence classification
# ---------------------------------------------------------------------------------------------
def _confidence(styles: Styles) -> list[Flowable]:
    table = dense_table(
        ["Detection class", "Meaning"],
        [[name, meaning] for name, meaning in authored.METHOD_CONFIDENCE_SCHEME],
        [130, 410],
    )
    content = [table, Spacer(1, 4), _para(authored.METHOD_CONFIDENCE_LIMIT, styles["body"])]
    return _section(SEC["Confidence classification"], styles, content, together=True)


# ---------------------------------------------------------------------------------------------
# 8. Ownership and responsibilities (RACI, blank)
# ---------------------------------------------------------------------------------------------
def _raci(styles: Styles) -> list[Flowable]:
    rows = [
        [activity, _blank(), _blank(), _blank(), _blank()] for activity in authored.RACI_ACTIVITIES
    ]
    table = dense_table(
        ["Activity", *authored.RACI_COLUMNS],
        rows,
        [180, 90, 90, 90, 90],
        manual_cols=(1, 2, 3, 4),
    )
    content = [_para(RACI_INTRO, styles["body"]), table, Spacer(1, 4)]
    return _section(SEC["Ownership and responsibilities (RACI)"], styles, content, together=True)


# ---------------------------------------------------------------------------------------------
# 9. Evidence retention and versioning
# ---------------------------------------------------------------------------------------------
def _versioning_text(view: TeamCbomView) -> str:
    return (
        f"Versioning: this edition is Document ID {document_id(view, DOCUMENT_CODE)} with data "
        f"fingerprint {document_digest_of(view, DOCUMENT_CODE) or 'n/a'} and template version {TEMPLATE_VERSION}. "
        "Regenerating it from the same scans and settings gives the same fingerprint; a new successful scan, "
        "an attestation upload or a change to the regulatory profile, source metadata or quantum risk inputs "
        "changes it. The roll-up reads up to "
        f"{HISTORY_WINDOW} of the newest successful scans for first-seen and last-seen history, "
        "plus the latest scan of every source."
    )


def _retention(view: TeamCbomView, styles: Styles) -> list[Flowable]:
    table = dense_table(
        ["Item", "Value"],
        [
            [authored.METHOD_RETENTION_PERIOD_LABEL, _blank()],
            [authored.METHOD_EVIDENCE_STORE_LABEL, _blank()],
        ],
        [200, 340],
        manual_cols=(1,),
    )
    content = [
        _para(authored.METHOD_RETENTION, styles["body"]),
        _para(_versioning_text(view), styles["body"]),
        table,
    ]
    return _section(SEC["Evidence retention and versioning"], styles, content, together=True)


# ---------------------------------------------------------------------------------------------
# 10. Limits of the method
# ---------------------------------------------------------------------------------------------
def _limits(view: TeamCbomView, styles: Styles, local: dict[str, ParagraphStyle]) -> list[Flowable]:
    # method_limits(view): only the limits this edition's run coverage leaves true (never "not probed" after probes)
    content: list[Flowable] = [
        Paragraph(pdf_text(limit, limit=_TEXT_LIMIT), local["bullet"], bulletText=_BULLET)
        for limit in method.method_limits(view)
    ]
    return _section(SEC["Limits of the method"], styles, content, together=False)


# ---------------------------------------------------------------------------------------------
# 11. Sign-off (blank)
# ---------------------------------------------------------------------------------------------
def _signoff(width: float) -> list[Flowable]:
    # signoff_block is already a KeepTogether that carries its own heading.  Never wrap it in
    # another KeepTogether: reportlab reports a nested one as ~16 million points tall, which
    # would push the block onto a page of its own however much room is left.
    return [signoff_block(SIGNOFF_ROLES, title=_heading_text(SEC["Sign-off"]), width=width)]


# ---------------------------------------------------------------------------------------------
# Appendix A. Scans considered
# ---------------------------------------------------------------------------------------------
def _disposition(facts: ScanFacts) -> str:
    if facts.exclusion is not None:
        return _EXCLUSION_TEXT.get(facts.exclusion, "Excluded")
    return "Current for source" if facts.is_current else "History only"


def _scan_row(facts: ScanFacts, labels: dict[str, str]) -> list[object]:
    included = facts.exclusion is None
    fidelity = _DASH if not included else ("Full" if facts.fidelity == FIDELITY_FULL else "Legacy")
    return [
        f"#{facts.scan_id}",
        facts.title,
        labels.get(facts.source_key, facts.source_label),
        fmt_date_utc(facts.created_at),
        _disposition(facts),
        fidelity,
        str(int(facts.asset_count or 0)) if included else _DASH,
    ]


def _appendix(
    view: TeamCbomView, styles: Styles, local: dict[str, ParagraphStyle]
) -> list[Flowable]:
    labels = {source.key: source.label for source in view.sources}
    listed = view.scans[: max(0, int(MAX_SCAN_ROWS))]
    table = dense_table(
        list(_APPENDIX_COLUMNS),
        [_scan_row(facts, labels) for facts in listed],
        [34, 112, 170, 58, 74, 46, 46],
    )
    content: list[Flowable] = [_para(SCAN_APPENDIX_INTRO, styles["body"]), table]
    omitted = len(view.scans) - len(listed)
    if omitted > 0:
        content.append(
            _para(
                f"{_count(omitted, 'further scan')} omitted; the first {len(listed)} of "
                f"{len(view.scans)} are listed.",
                local["caption"],
            )
        )
    older = int(view.history_truncated)
    if older > 0:
        content.append(
            _para(_beyond_window(older, "is not listed.", "are not listed."), local["caption"])
        )
    content += _collection_appendix(view, styles, local)
    return [*section_heading(APPENDIX_TITLE, styles, min_space=200), *content]


_COLLECTION_COLUMNS = ("Run", "Source", "Collector", "Layer / method", "Collected (UTC)", "Assets", "Endpoints")


def _collection_row(collection: Any) -> list[object]:
    spec = method.COLLECTOR_BY_KIND.get(collection.source_kind)
    return [
        f"#{int(collection.run_id)}",
        collection.source_name or collection.label,
        spec.label if spec else (collection.source_kind or "Deleted source"),
        f"{spec.layer} {spec.method}" if spec else _DASH,
        fmt_date_utc(collection.observed_at),
        str(int(collection.asset_count or 0)),
        str(int(collection.endpoints_probed or 0)),
    ]


def _collection_appendix(
    view: TeamCbomView, styles: Styles, local: dict[str, ParagraphStyle]
) -> list[Flowable]:
    found = sorted(view.collections, key=lambda c: (c.observed_at, c.run_id, c.job_id), reverse=True)
    if not found:
        return [_para("No CBOM Sources collection is in this edition.", local["caption"])]
    listed = found[: max(0, int(MAX_SCAN_ROWS))]
    out: list[Flowable] = [
        Spacer(1, 6),
        _para(COLLECTION_APPENDIX_INTRO, styles["body"]),
        dense_table(list(_COLLECTION_COLUMNS), [_collection_row(c) for c in listed],
                    [36, 150, 96, 80, 62, 54, 62]),
    ]
    if len(found) > len(listed):
        out.append(_para(f"{_count(len(found) - len(listed), 'further collection')} omitted; the first "
                         f"{len(listed)} of {len(found)} are listed.", local["caption"]))
    return out


# ---------------------------------------------------------------------------------------------
# Entry points
# ---------------------------------------------------------------------------------------------
def build_body(view: TeamCbomView, styles: Styles, width: float) -> list[Flowable]:
    """The document-specific flowables (everything after the shared front matter)."""
    local = _local_styles(styles)
    story: list[Flowable] = []
    story += _purpose(view, styles, width, local)
    story += _methods(view, styles, local)
    story += _collectors(view, styles, local)
    story += _automated(styles)
    story += _manual(view, styles, local)
    story += _classification(view, styles, local)
    story += _evidence(view, styles)
    story += _protection(view, styles, local)
    story += _windows(view, styles)
    story += _validation(styles)
    story += _coverage(view, styles, local)
    story += _confidence(styles)
    story += _plan(styles)
    story += _raci(styles)
    story += _retention(view, styles)
    story += _limits(view, styles, local)
    story += _signoff(width)
    story += _appendix(view, styles, local)
    return story


def build_pdf(view: TeamCbomView, *, ctx: Any = None) -> bytes:
    """Render SOW deliverable D2 for ``view`` and return the PDF bytes (byte-stable for a view)."""
    return build_document(
        ctx=ctx,
        view=view,
        number=DOCUMENT_CODE,
        report_key=REPORT_KEY,
        title=TITLE,
        landscape=False,
        body=lambda styles, width: build_body(view, styles, width),
        # the method sentence short enough for the box (600 characters) and true for this edition's run coverage
        disclaimer_paragraphs=(authored.CERTIN_DISCLAIMER, authored.RBI_BOM_DISCLAIMER,
                               method.method_scope_sentence(view)),
    )


__all__ = [
    "APPENDIX_TITLE",
    "DOCUMENT_CODE",
    "MAX_SCAN_ROWS",
    "NUMBER",
    "REPORT_KEY",
    "SECTION_TITLES",
    "SIGNOFF_ROLES",
    "SLUG",
    "TITLE",
    "build_body",
    "build_pdf",
]
