"""Board / IT Strategy Committee Regulatory & Executive Report (deliverable #16, portrait) - WP3f.

``build_pdf(view) -> bytes`` renders the team-wide roll-up (``TeamCbomView``) as a short
executive document: the posture grade and headline numbers, the ten most material risks,
quantum readiness, certificate posture, regulatory exposure across the 13 frameworks,
remediation priorities, a post-quantum summary, governance actions and a blank sign-off block,
plus three appendices (grade formula, scans included, disclaimers).  Plan 5.4 / 3.2 / 6.3 (T-16).

Design decisions, in one place:

* **Grade input** (plan D-03): only CURRENT issue assets, i.e. de-duplicated current crypto
  assets with at least one finding code, bucketed by their impact, go into the existing
  ``compute_risk_score``.  Inventory-only assets are excluded, so the grade does not saturate
  on inventory volume.  The formula is printed in Appendix A.
* **NOT ASSESSED** (plan F-06 / R-05): ``compute_risk_score(0, 0, 0, 0)`` is grade A / "Low risk",
  which would be false assurance.  A grade is therefore assigned only when current assets were
  inventoried and their findings can be read.  No completed scan, no inventoried asset, or only
  legacy-format scans without any finding data all give "NOT ASSESSED" with the reason; none of
  them prints a band name.  A genuinely clean inventory (assets, no findings) is grade A.
* **Material risks** are the issue assets, not the whole inventory (a Low inventory-only row
  has no finding to report).  Order: impact rank, then scanner risk score (absent last), then
  name.  Nothing here derives weakness from ``weak`` / ``crypto_strength`` (plan F-04).
* **Regulatory exposure** prints the pooled counts of the view as they are; "Pass" includes
  requirements passed on attached evidence (that is what the coverage definition counts).
* Every data-derived string reaches a ``Paragraph`` through ``pdf_text`` (the one helper
  ``_para``) or through ``dense_table`` / ``kpi_strip`` / ``status_chip``, which sanitise
  themselves; scanned repositories are untrusted input.

Hard rules (enforced by the guards in ``test_cbom_deliverable_board_report.py``): reportlab,
the standard library and the two backend packages ``backend.utilities.pdf`` and
``backend.utilities.dashboard.cbom_team_rollup`` only; no network, no language model, no wall
clock (every date comes from the view); Python 3.10 syntax.
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.styles import ParagraphStyle
from reportlab.platypus import Flowable, Paragraph, Spacer, Table, TableStyle

from backend.utilities.dashboard.cbom_team_rollup import (
    ASSET_ALGORITHM,
    ASSET_CERTIFICATE,
    ASSET_MATERIAL,
    ASSET_OTHER,
    ASSET_PROTOCOL,
    EXPIRED,
    FIDELITY_FULL,
    IMPACT_LEVELS,
    LE_30,
    LE_90,
    SOURCE_SOURCES,
    UNKNOWN,
    VALID,
    AssetAgg,
    TeamCbomView,
    posture_active,
)
from backend.utilities.pdf import cbom_deliverable_text as authored
from backend.utilities.pdf.cbom_collected_compliance import collected_clauses
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
    tone_for_impact,
)
from backend.utilities.pdf.report_branding import (
    KPI_ACCENT_TIME,
    PILL_CRITICAL_BG,
    PILL_CRITICAL_FG,
    PILL_MEDIUM_BG,
    PILL_MEDIUM_FG,
    PILL_UNKNOWN_BD,
    REPORT_META,
    compute_risk_score,
)

DELIVERABLE_NUMBER = 16
REPORT_KEY = "cbom_board_report"
TOP_RISKS = 10  # "Material risks (top 10)"
MAX_SCAN_ROWS = 100  # Appendix B cap; the rest is counted, not listed

# ---------------------------------------------------------------------------------------------
# Section headings (the test pins these strings and their order)
# ---------------------------------------------------------------------------------------------
H_SUMMARY = "1. Executive summary"
H_RISKS = f"2. Material risks (top {TOP_RISKS})"
H_QUANTUM = "3. Quantum readiness"
H_CERTS = "4. Certificate and key-material posture"
H_EXPOSURE = "5. Regulatory exposure"
H_REMEDIATION = "6. Remediation priorities"
H_PQC = "7. Post-quantum roadmap summary"
H_GOVERNANCE = "8. Governance actions and decisions required"
H_SIGNOFF = "9. Sign-off"
H_APP_GRADE = "Appendix A. Grade formula"
H_APP_SCANS = "Appendix B. Scans included"
H_APP_DISCLAIMERS = "Appendix C. Disclaimers and limits"

# ---------------------------------------------------------------------------------------------
# Document-specific text.  Product text: statements about this report's own behaviour.  The
# standards and regulatory wording lives in cbom_deliverable_text.py with its provenance.
# ---------------------------------------------------------------------------------------------
NO_DATA_NOTE = "No data: no completed CBOM scans."
REASON_NO_SCANS = "No completed CBOM scans are available for this team."
REASON_NO_ASSETS = "The completed scans inventoried no cryptographic assets."
REASON_LEGACY_ONLY = "Every latest scan is in legacy format and carries no finding data."
NOT_ASSESSED_EXPLANATION = (
    "No posture grade is assigned: a grade is shown only when current cryptographic assets "
    "have been inventoried and their findings can be read."
)
SIGNOFF_ROLES = ("Prepared by", "CISO review", "Board IT Strategy Committee approval")
GOVERNANCE_LEAD = (
    "Proposed actions follow from the figures in this report. The board or its delegate "
    "records the owner, due date and decision in the cells marked (assessor)."
)
RISKS_ORDER_NOTE = "ordered by impact, then scanner risk score, then name"
READINESS_NOTE = (
    "Readiness = quantum-safe algorithm occurrences / (quantum-safe + quantum-vulnerable "
    "occurrences), counted over the current assets of every source. Quantum-vulnerable "
    "public-key algorithms (RSA, elliptic-curve, Diffie-Hellman, DSA) are the migration scope; "
    "section 7 summarises the target standards and the regulatory timeline."
)
CERT_DATE_NOTE = (
    "Validity is computed as of {as_of} (the report date) from each certificate's notAfter "
    "date, not from the flag raised when the scan ran. Certificates are counted once across "
    "all sources."
)
EXPOSURE_LEGACY_NOTE = (
    "No compliance results are available: {pooled} of {sources} sources pooled "
    "({legacy} legacy excluded). Re-scan the legacy-format sources to include them."
)
EXPOSURE_POOLED = "{pooled} of {sources} sources pooled ({legacy} legacy excluded)."
EXPOSURE_COLLECTED_LEAD = (
    "Collected infrastructure (CBOM Sources): the regulatory clauses that the findings of each "
    "source's latest collection touch, with the number of assets concerned (knowledge-base "
    "mapping, the same as the run's compliance view; a clause listed here is not a verdict)."
)
PQC_COLLECTED_ONLY = (
    "{count} quantum-vulnerable public-key occurrences were found on certificates, endpoints and "
    "keys (the collected infrastructure included), none in the algorithm inventory, so there is "
    "no target family to group them by. The PQC Migration Roadmap lists each with its plan."
)
REMEDIATION_NOTE = (
    "Ordered by the highest impact among the affected assets, then by the number of assets."
)
NO_ISSUES_RISKS = "No current asset carries a finding."
NO_ISSUES_REMEDIATION = "No findings to remediate."
PQC_FAMILIES_LEAD = (
    "Quantum-vulnerable public-key algorithms in the current assets, grouped by the NIST "
    "post-quantum standard they should migrate to."
)
PQC_DETAIL_POINTER = (
    "Per-asset detail, with wave, owner and target-date columns for the assessor, is in the "
    "PQC Migration Roadmap. {order_note}"
)
TARGET_NOT_RECORDED = "Target not recorded (legacy scan)"
SCANS_NOTE = "The Basis box on page 1 counts the scans excluded from this report."
SCANS_OMITTED = "{omitted} further scans omitted from this list."
GRADE_NOT_ASSIGNED = "No grade was assigned. {reason}"
GRADE_WORKED = (
    "Weighted points: {weighted}. Score = min({cap}, {multiplier} x {weighted}) = {score}. "
    "Grade {grade} ({band})."
)

_ASSET_TYPE_LABEL = {
    ASSET_ALGORITHM: "Algorithm",
    ASSET_CERTIFICATE: "Certificate",
    ASSET_PROTOCOL: "Protocol",
    ASSET_MATERIAL: "Key or secret material",
    ASSET_OTHER: "Other",
}
# code scans (aibom) and CBOM Sources collections (cbom_sources.classify) name the same certificate findings differently
_WEAK_CERT_CODES = frozenset({"WEAK_CERTIFICATE_SIGNATURE", "WEAK_CERTIFICATE_KEY", "SIG_MD5", "SIG_SHA1",
                              "RSA_LT_1024", "RSA_LT_2048", "EC_LT_224"})
_SELF_SIGNED_LEAF_CODES = frozenset({"SELF_SIGNED_LEAF", "CERT_SELF_SIGNED"})  # the collected code is leaf-only too
_RANK = {level: index for index, level in enumerate(IMPACT_LEVELS)}
_UNRANKED = len(IMPACT_LEVELS)
# "1 sources" -> "1 source": the authored governance templates are written in the plural
_SINGULAR = re.compile(
    r"\b1 (unique certificate|requirement|quantum-vulnerable asset occurrence|source)s\b"
)
# grade box colours for A and B mirror report_branding.build_kpi_grid
_GRADE_OK_BG = colors.HexColor("#ECFDF5")
_GRADE_OK_FG = colors.HexColor("#047857")


# ---------------------------------------------------------------------------------------------
# Facts: pure functions of the view (unit-testable without rendering)
# ---------------------------------------------------------------------------------------------
@dataclass(frozen=True)
class PostureGrade:
    """The posture grade, or the reason there is none (``assessed`` is False)."""

    assessed: bool
    grade: str  # "A".."F", or ``GRADE_NOT_ASSESSED``
    score: int | None
    band: str | None  # "Critical risk" ... only when assessed
    reason: str | None  # why it is NOT ASSESSED
    critical: int  # issue assets by impact: the grade input
    high: int
    medium: int
    low: int
    weighted_points: int


def _not_assessed_reason(view: TeamCbomView) -> str | None:
    if view.is_empty:
        return REASON_NO_SCANS
    # Posture facts with findings are enough to grade, even with no crypto assets.
    if view.asset_occurrences <= 0 and not posture_active(view):
        return REASON_NO_ASSETS
    if (
        view.compliance_sources_pooled == 0
        and not any(asset.current and asset.finding_codes for asset in view.assets)
        and not posture_active(view)
    ):
        # only legacy rows: they carry no finding codes to grade (they are still counted as findings with their
        # stored impact in issue_by_impact, as on the scan page; the grade is not built from them alone)
        return REASON_LEGACY_ONLY
    return None


def _posture_issue_counts(view: TeamCbomView) -> tuple[int, int, int, int]:
    counts = view.posture.counts.facts_with_findings_by_impact
    return tuple(int(counts.get(level, 0) or 0) for level in IMPACT_LEVELS)


def configuration_posture_line(view: TeamCbomView) -> str | None:
    """Printed only when posture findings enter the grade. ``None`` keeps the old text."""
    if not posture_active(view):
        return None
    resources = sum(_posture_issue_counts(view))
    findings = sum(int(count) for count in view.posture.counts.findings_by_code.values())
    sources = sum(
        1 for row in view.posture.sources if row.state not in ("assessed", "partial")
    )
    return (
        f"Configuration posture findings: {findings} "
        f"({resources} resources, {sources} sources not assessed)"
    )


def posture_grade(view: TeamCbomView) -> PostureGrade:
    """Grade of the current issue assets via ``compute_risk_score``; NOT ASSESSED without data."""
    asset_counts = [int(view.issue_by_impact.get(level, 0) or 0) for level in IMPACT_LEVELS]
    if posture_active(view):
        asset_counts = [
            base + extra
            for base, extra in zip(asset_counts, _posture_issue_counts(view), strict=True)
        ]
    critical, high, medium, low = asset_counts
    weights = authored.GRADE_WEIGHTS
    weighted = sum(
        count * weights[level]
        for level, count in zip(IMPACT_LEVELS, (critical, high, medium, low), strict=True)
    )
    reason = _not_assessed_reason(view)
    if reason is not None:
        return PostureGrade(
            False,
            authored.GRADE_NOT_ASSESSED,
            None,
            None,
            reason,
            critical,
            high,
            medium,
            low,
            weighted,
        )
    score, grade, band = compute_risk_score(critical, high, medium, low)
    return PostureGrade(True, grade, score, band, None, critical, high, medium, low, weighted)


def _risk_key(asset: AssetAgg):
    score = asset.risk_score
    return (
        _RANK.get(asset.impact, _UNRANKED),
        0 if score is not None else 1,  # an absent scanner score sorts after every real one
        -(score or 0.0),
        asset.title.casefold(),
        asset.source_key,
        asset.location,
        asset.ident,
    )


def issue_assets(view: TeamCbomView) -> list[AssetAgg]:
    """Current assets with at least one finding code, most material first."""
    return sorted((a for a in view.assets if a.current and a.finding_codes), key=_risk_key)


def material_risks(view: TeamCbomView, limit: int = TOP_RISKS) -> list[AssetAgg]:
    """The ``limit`` most material issue assets (Critical first)."""
    return issue_assets(view)[: max(0, int(limit))]


@dataclass(frozen=True)
class RemediationRow:
    code: str
    label: str
    assets: int  # current asset occurrences carrying the code
    highest_impact: str  # highest impact among those assets
    action: str


def _remediation_key(row: RemediationRow):
    return (_RANK.get(row.highest_impact, _UNRANKED), -row.assets, row.label.casefold(), row.code)


def remediation_rows(view: TeamCbomView) -> list[RemediationRow]:
    """One row per finding code in the current assets: impact rank, then count, then label."""
    counts: Counter[str] = Counter()
    best: dict[str, str] = {}
    for asset in view.assets:
        if not asset.current:
            continue
        for code in asset.finding_codes:
            counts[code] += 1
            held = best.get(code)
            if held is None or _RANK.get(asset.impact, _UNRANKED) < _RANK.get(held, _UNRANKED):
                best[code] = asset.impact
    rows = [
        RemediationRow(
            code, authored.finding_label(code), count, best[code], authored.finding_action(code)
        )
        for code, count in counts.items()
    ]
    rows.sort(key=_remediation_key)
    return rows


@dataclass(frozen=True)
class FamilyRow:
    family: str
    occurrences: int
    sources: int


def pqc_families(view: TeamCbomView) -> list[FamilyRow]:
    """Current quantum-vulnerable algorithm occurrences grouped by NIST target family."""
    groups: dict[str, list[AssetAgg]] = {}
    for asset in view.assets:
        if asset.current and asset.asset_type == ASSET_ALGORITHM and asset.quantum_vulnerable:
            groups.setdefault(asset.pqc_migration_target or TARGET_NOT_RECORDED, []).append(asset)
    rows = [
        FamilyRow(family, len(items), len({a.source_key for a in items}))
        for family, items in groups.items()
    ]
    rows.sort(key=lambda r: (-r.occurrences, r.family.casefold()))
    return rows


@dataclass(frozen=True)
class CertPosture:
    unique: int
    expired: int
    within_30: int
    within_90: int  # 31 to 90 days
    valid: int  # more than 90 days
    unknown: int
    weak: int  # weak signature hash or undersized key
    self_signed_leaf: int
    material: int  # key and secret material occurrences
    material_flagged: int


def certificate_posture(view: TeamCbomView) -> CertPosture:
    """Counts over the current unique certificates and the current key-material occurrences."""
    certs = [c for c in view.certs if c.current]
    bands = Counter(c.expiry.band for c in certs)
    material = [a for a in view.assets if a.current and a.asset_type == ASSET_MATERIAL]
    return CertPosture(
        unique=len(certs),
        expired=bands[EXPIRED],
        within_30=bands[LE_30],
        within_90=bands[LE_90],
        valid=bands[VALID],
        unknown=bands[UNKNOWN],
        weak=sum(1 for c in certs if _WEAK_CERT_CODES.intersection(c.finding_codes)),
        self_signed_leaf=sum(1 for c in certs if _SELF_SIGNED_LEAF_CODES.intersection(c.finding_codes)),
        material=len(material),
        material_flagged=sum(1 for a in material if a.finding_codes),
    )


@dataclass(frozen=True)
class GovernanceMetrics:
    unique_certs: int
    attestations_outstanding: int  # requirements some current source cannot evidence from the BOM
    quantum_vulnerable: int
    legacy_scans: int  # current sources whose latest scan is in legacy format


def governance_metrics(view: TeamCbomView) -> GovernanceMetrics:
    return GovernanceMetrics(
        unique_certs=sum(1 for c in view.certs if c.current),
        attestations_outstanding=sum(
            1 for r in view.requirements if r.attestable_sources > r.attested_sources
        ),
        quantum_vulnerable=int(view.pqc_vulnerable),
        legacy_scans=int(view.compliance_legacy_excluded),
    )


def _count(number: int, singular: str, plural: str | None = None) -> str:
    return f"{number} {singular if number == 1 else (plural or singular + 's')}"


def governance_rows(view: TeamCbomView) -> list[list[str]]:
    """``[action, live metric, "", "", ""]``: owner, due date and decision stay blank (manual)."""
    metrics = governance_metrics(view)
    fields = {
        "unique_certs": metrics.unique_certs,
        "attestations_outstanding": metrics.attestations_outstanding,
        "quantum_vulnerable": metrics.quantum_vulnerable,
        "legacy_scans": metrics.legacy_scans,
    }
    live = {
        "owners": _count(metrics.unique_certs, "unique certificate"),
        "attestations": f"{_count(metrics.attestations_outstanding, 'requirement')} outstanding",
        "pqc": _count(metrics.quantum_vulnerable, "quantum-vulnerable occurrence"),
        "legacy": f"{_count(metrics.legacy_scans, 'source')} in legacy format",
    }
    rows = []
    for key, template in authored.GOVERNANCE_ACTIONS:
        action = _SINGULAR.sub(r"1 \1", template.format(**fields))
        rows.append([action, live.get(key, ""), "", "", ""])
    return rows


def _percent(ratio: float | None) -> str:
    return "n/a" if ratio is None else f"{ratio * 100:.1f}%"


def exposure_rows(view: TeamCbomView) -> list[list[str]]:
    """One row per pooled framework (engine order): label, coverage, pass, fail, NBE, OOS, n."""
    return [
        [
            authored.framework_label(pool.framework),
            _percent(pool.coverage),
            str(pool.passed + pool.passed_with_evidence),
            str(pool.failed),
            str(pool.not_bom_evidenceable),
            str(pool.out_of_scope),
            str(pool.sources_pooled),
        ]
        for pool in view.frameworks
    ]


def scan_rows(view: TeamCbomView) -> list[list[str]]:
    """Included scans grouped by source (newest first inside a source) for Appendix B."""
    labels = {source.key: source.label for source in view.sources}
    included = [scan for scan in view.scans if scan.exclusion is None]
    included.sort(key=lambda s: (s.created_at, s.scan_id), reverse=True)
    included.sort(key=lambda s: (labels.get(s.source_key, s.source_label).casefold(), s.source_key))
    return [
        [
            f"#{scan.scan_id}",
            labels.get(scan.source_key, scan.source_label),
            fmt_date_utc(scan.created_at),
            "Full" if scan.fidelity == FIDELITY_FULL else "Legacy format",
            "Current" if scan.is_current else "History",
        ]
        for scan in included
    ]


# ---------------------------------------------------------------------------------------------
# Rendering helpers
# ---------------------------------------------------------------------------------------------
def _para(text: object, styles: Styles, style: str = "body", *, limit: int = 1500) -> Paragraph:
    """The one place a Paragraph is made: text is sanitised and escaped by ``pdf_text``."""
    return Paragraph(pdf_text(text, limit=limit), styles[style])


def _gap(points: float = 6) -> Spacer:
    return Spacer(1, points)


def _flat(*extra: tuple) -> TableStyle:
    return TableStyle(
        [
            ("LEFTPADDING", (0, 0), (-1, -1), 0),
            ("RIGHTPADDING", (0, 0), (-1, -1), 0),
            ("TOPPADDING", (0, 0), (-1, -1), 0),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            *extra,
        ]
    )


def _grade_colours(grade: str):
    if grade in ("D", "F"):
        return PILL_CRITICAL_BG, PILL_CRITICAL_FG
    if grade == "C":
        return PILL_MEDIUM_BG, PILL_MEDIUM_FG
    return _GRADE_OK_BG, _GRADE_OK_FG


def _grade_card(posture: PostureGrade, styles: Styles, width: float) -> Table:
    """The risk-grade card: same look as ``build_kpi_grid``'s, with a caption and NOT ASSESSED."""
    inner = width - 3.0 - 18.0  # accent bar, then 10 + 8 points of padding
    score = "n/a" if posture.score is None else str(posture.score)
    hint = posture.reason if not posture.assessed else posture.band
    text_width = inner - 40 if posture.assessed else inner
    text = Table(
        [
            [_para("Risk score", styles, "kpi_label")],
            [_para(score, styles, "kpi_value")],
            [_para(hint, styles, "kpi_hint")],
        ],
        colWidths=[text_width],
    )
    text.setStyle(_flat())
    rows: list[list[Flowable]] = [[_para("Posture grade", styles, "kpi_label")]]
    if posture.assessed:
        background, foreground = _grade_colours(posture.grade)
        letter = ParagraphStyle(
            "BoardGrade",
            fontName="Helvetica-Bold",
            fontSize=16,
            leading=18,
            textColor=foreground,
            alignment=TA_CENTER,
        )
        badge = Table(
            [[Paragraph(pdf_text(posture.grade, limit=2), letter)]],
            colWidths=[28],
            rowHeights=[28],
        )
        badge.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, -1), background),
                    ("BOX", (0, 0), (-1, -1), 0.5, foreground),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("ROUNDEDCORNERS", [6, 6, 6, 6]),
                ]
            )
        )
        row = Table([[badge, text]], colWidths=[32, inner - 32])
        row.setStyle(_flat(("LEFTPADDING", (1, 0), (1, 0), 8)))
        rows.append([row])
    else:
        pill = Table([[status_chip(posture.grade, "unknown")]], colWidths=[88], hAlign="LEFT")
        pill.setStyle(_flat())
        rows += [[pill], [text]]
    pad = Table(rows, colWidths=[inner])
    pad.setStyle(
        _flat(
            ("LEFTPADDING", (0, 0), (-1, -1), 10),
            ("RIGHTPADDING", (0, 0), (-1, -1), 8),
            ("TOPPADDING", (0, 0), (0, 0), 10),
            ("TOPPADDING", (0, 1), (0, -1), 4),
            ("BOTTOMPADDING", (0, -1), (0, -1), 10),
        )
    )
    card = Table([["", pad]], colWidths=[3.0, width - 3.0])
    card.setStyle(
        _flat(
            ("BACKGROUND", (0, 0), (0, 0), KPI_ACCENT_TIME),
            ("BACKGROUND", (1, 0), (1, 0), colors.white),
            ("BOX", (0, 0), (-1, -1), 0.7, PILL_UNKNOWN_BD),
            ("ROUNDEDCORNERS", [8, 8, 8, 8]),
        )
    )
    return card


def _issue_breakdown(view: TeamCbomView) -> tuple[int, str]:
    """``(issue assets, "Critical 1 · High 23 · Medium 5 · Low 0")``; unknown impacts as Other."""
    known = [int(view.issue_by_impact.get(level, 0) or 0) for level in IMPACT_LEVELS]
    total = sum(int(n or 0) for n in view.issue_by_impact.values())
    parts = [f"{level} {n}" for level, n in zip(IMPACT_LEVELS, known, strict=True)]
    if total > sum(known):
        parts.append(f"Other {total - sum(known)}")
    return total, " \u00b7 ".join(parts)


def _worst_tone(view: TeamCbomView) -> str:
    for level in IMPACT_LEVELS:
        if view.issue_by_impact.get(level, 0):
            return level.lower()
    return "low"


def _pct_or_na(view: TeamCbomView) -> str:
    return "n/a" if view.readiness_pct is None else f"{view.readiness_pct:.1f}%"


def _certificate_sentence(certs: CertPosture) -> str:
    if certs.unique == 0:
        return "No certificates were inventoried."
    soon = certs.within_30 + certs.within_90
    if certs.expired == 0 and soon == 0:
        return "No certificate has expired or expires within 90 days."
    return (
        f"{_count(certs.expired, 'certificate')} "
        f"{'has' if certs.expired == 1 else 'have'} expired and {soon} "
        f"{'expires' if soon == 1 else 'expire'} within 90 days."
    )


def _quantum_sentence(view: TeamCbomView) -> str:
    graded = view.pqc_safe + view.pqc_vulnerable + view.pqc_broken_today
    if view.readiness_pct is None:
        return (
            "Quantum readiness cannot be computed because no algorithm occurrence could be graded."
        )
    verb = "uses" if view.pqc_vulnerable == 1 else "use"
    return (
        f"Quantum readiness is {view.readiness_pct:.1f}%: {view.pqc_vulnerable} of {graded} "
        f"gradeable algorithm occurrences {verb} quantum-vulnerable public-key cryptography"
        + (f" and {view.pqc_broken_today} are broken today (MD5, DES and the like)." if view.pqc_broken_today else ".")
    )


def _scope_counts(view: TeamCbomView) -> tuple[int, int, int]:
    """(code sources, code scans, CBOM Sources collections). ``merge_collections`` adds each collection to
    ``view.sources`` and to ``view.included``, so the code part is what is left."""
    collections = len(view.collections or ())
    code_sources = sum(1 for source in view.sources if source.kind != SOURCE_SOURCES)
    return code_sources, max(int(view.included) - collections, 0), collections


def scope_captions(view: TeamCbomView) -> tuple[str, str]:
    """Captions of the "Sources" and "Scans included" summary cards."""
    code_sources, code_scans, collections = _scope_counts(view)
    if not collections:
        return "repositories and uploads assessed", f"of {view.eligible} eligible completed scans"
    return (f"{code_sources} repositories and uploads, {collections} CBOM Sources",
            f"of {view.eligible} eligible: {_count(code_scans, 'code scan')}, "
            f"{_count(collections, 'Sources collection')}")


def scope_sentence(view: TeamCbomView) -> str:
    """The summary's opening clause: what the roll-up covers."""
    code_sources, code_scans, collections = _scope_counts(view)
    if not collections:
        return f"Across {_count(len(view.sources), 'source')} and {_count(view.included, 'completed scan')}"
    return (f"Across {_count(len(view.sources), 'source')} ({code_sources} repositories and uploads, "
            f"{collections} CBOM Sources) and {_count(view.included, 'completed result')} "
            f"({_count(code_scans, 'code scan')}, {_count(collections, 'Sources collection')})")


def _summary_paragraphs(view: TeamCbomView, posture: PostureGrade) -> list[str]:
    if not posture.assessed:
        return [f"{posture.reason} {NOT_ASSESSED_EXPLANATION}"]
    total, breakdown = _issue_breakdown(view)
    findings = breakdown.replace(" \u00b7 ", ", ")
    paragraphs = [
        (
            f"{scope_sentence(view)}, the platform inventoried "
            f"{_count(view.asset_occurrences, 'cryptographic asset occurrence')}. Findings were "
            f"raised on {total} of them: {findings}."
        ),
        (
            f"Posture grade {posture.grade} ({posture.band}, score {posture.score} of "
            f"{authored.GRADE_SCORE_CAP}) is computed from the issue assets only. It is a "
            "platform posture grade, not a regulatory rating."
        ),
        f"{_quantum_sentence(view)} {_certificate_sentence(certificate_posture(view))}",
    ]
    line = configuration_posture_line(view)
    if line is not None:
        paragraphs.append(line)
    return paragraphs


# ---------------------------------------------------------------------------------------------
# Sections
# ---------------------------------------------------------------------------------------------
def _summary_section(view: TeamCbomView, posture: PostureGrade, styles: Styles, w: float):
    total, breakdown = _issue_breakdown(view)
    certs = certificate_posture(view)
    grade_width, gap = 190.0, 6.0
    rest = w - grade_width - gap
    first = Table(
        [
            [
                _grade_card(posture, styles, grade_width),
                "",
                kpi_strip(
                    [
                        (
                            "Crypto assets",
                            str(view.asset_occurrences),
                            "current occurrences across all sources",
                        ),
                        ("Issue assets", str(total), breakdown, _worst_tone(view)),
                    ],
                    rest,
                    max_per_row=2,
                ),
            ]
        ],
        colWidths=[grade_width, gap, rest],
        hAlign="LEFT",
    )
    first.setStyle(_flat())
    detail = (
        f"{view.pqc_vulnerable} of {view.pqc_safe + view.pqc_vulnerable + view.pqc_broken_today} algorithm occurrences "
        "quantum-vulnerable"
        if view.readiness_pct is not None
        else "no algorithm occurrence could be graded"
    )
    sources_caption, scans_caption = scope_captions(view)
    second = kpi_strip(
        [
            ("Sources", str(len(view.sources)), sources_caption),
            ("Scans included", str(view.included), scans_caption),
            ("Unique certificates", str(certs.unique), "de-duplicated across sources"),
            ("Quantum readiness", _pct_or_na(view), detail),
        ],
        w,
        max_per_row=4,
    )
    story: list[Flowable] = [*section_heading(H_SUMMARY, styles), first, _gap(), second, _gap(8)]
    for text in _summary_paragraphs(view, posture):
        story += [_para(text, styles), _gap(4)]
    return story


def _risks_section(view: TeamCbomView, styles: Styles):
    story: list[Flowable] = [*section_heading(H_RISKS, styles)]
    if view.is_empty:
        return [*story, _para(NO_DATA_NOTE, styles, "muted")]
    issues = issue_assets(view)
    if not issues:
        return [*story, _para(NO_ISSUES_RISKS, styles, "muted")]
    rows = []
    for rank, asset in enumerate(issues[:TOP_RISKS], start=1):
        kind = _ASSET_TYPE_LABEL.get(asset.asset_type, _ASSET_TYPE_LABEL[ASSET_OTHER])
        where = f"{asset.source_label}\n{asset.location}" if asset.location else asset.source_label
        rows.append(
            [
                str(rank),
                f"{asset.title}\n{kind}",
                where,
                status_chip(asset.impact, tone_for_impact(asset.impact)),
                "\n".join(authored.finding_label(code) for code in asset.finding_codes),
                fmt_date_utc(asset.first_seen),
            ]
        )
    story.append(
        dense_table(
            ["#", "Asset", "Source / location", "Impact", "Finding", "First seen"],
            rows,
            [18, 112, 134, 60, 150, 66],
        )
    )
    shown = min(len(issues), TOP_RISKS)
    if len(issues) > shown:
        lead = f"Top {shown} of {len(issues)} issue assets"
    elif len(issues) == 1:
        lead = "The only issue asset is listed"
    else:
        lead = f"All {len(issues)} issue assets are listed"
    return [*story, _gap(3), _para(f"{lead}, {RISKS_ORDER_NOTE}.", styles, "muted")]


def _quantum_section(view: TeamCbomView, styles: Styles, w: float):
    story: list[Flowable] = [*section_heading(H_QUANTUM, styles, min_space=180)]
    if view.is_empty:
        return [*story, _para(NO_DATA_NOTE, styles, "muted")]
    strip = kpi_strip(
        [
            ("Readiness", _pct_or_na(view), "share of gradeable algorithm occurrences"),
            ("Quantum-vulnerable", str(view.pqc_vulnerable), "public-key occurrences to migrate"),
            ("Quantum-safe", str(view.pqc_safe), f"of which {view.pqc_hybrid} hybrid"),
            ("Not gradeable", str(view.pqc_ungraded), "excluded from readiness"),
        ],
        w,
        max_per_row=4,
    )
    return [*story, strip, _gap(), _para(READINESS_NOTE, styles, "muted")]


def _certs_section(view: TeamCbomView, styles: Styles):
    story: list[Flowable] = [*section_heading(H_CERTS, styles, min_space=270)]
    if view.is_empty:
        return [*story, _para(NO_DATA_NOTE, styles, "muted")]
    c = certificate_posture(view)
    rows = [
        ["Unique certificates in the estate", str(c.unique)],
        ["Expired", str(c.expired)],
        ["Expiring within 30 days", str(c.within_30)],
        ["Expiring in 31 to 90 days", str(c.within_90)],
        ["Valid for more than 90 days", str(c.valid)],
        ["Validity date not recorded", str(c.unknown)],
        ["Weak signature hash or undersized key", str(c.weak)],
        ["Self-signed leaf certificates", str(c.self_signed_leaf)],
        ["Key and secret material occurrences", str(c.material)],
        ["With a key-misuse finding", str(c.material_flagged)],
    ]
    note = CERT_DATE_NOTE.format(as_of=fmt_date_utc(view.as_of))
    return [
        *story,
        dense_table(["Measure", "Count"], rows, [400, 140]),
        _gap(3),
        _para(note, styles, "muted"),
    ]


def _exposure_section(view: TeamCbomView, styles: Styles):
    story: list[Flowable] = [*section_heading(H_EXPOSURE, styles)]
    if view.is_empty:
        return [*story, _para(NO_DATA_NOTE, styles, "muted")]
    basis = {
        "pooled": view.compliance_sources_pooled,
        "sources": len(view.sources),
        "legacy": view.compliance_legacy_excluded,
    }
    collected = _collected_exposure(view, styles)
    if not view.frameworks:
        if collected:
            return [*story, *collected]
        return [*story, _para(EXPOSURE_LEGACY_NOTE.format(**basis), styles, "muted")]
    headers = [
        "Framework",
        "Coverage",
        "Pass",
        "Fail",
        "Not evidenceable",
        "Out of scope",
        "Sources pooled",
    ]
    table = dense_table(headers, exposure_rows(view), [190, 56, 44, 44, 70, 66, 70])
    return [
        *story,
        _para(EXPOSURE_POOLED.format(**basis), styles),
        _gap(3),
        table,
        _gap(4),
        _para(authored.RBI_MAPPING_NOTE, styles, "muted"),
        _gap(3),
        _para(authored.METHOD_COVERAGE, styles, "muted"),
        *([_gap(6), *collected] if collected else []),
    ]


def _collected_exposure(view: TeamCbomView, styles: Styles) -> list[Flowable]:
    rows = collected_clauses(view)
    if not rows:
        return []
    body = [[f"{r.framework} {r.clause}", str(r.assets), ", ".join(r.codes)] for r in rows]
    return [
        _para(EXPOSURE_COLLECTED_LEAD, styles),
        _gap(3),
        dense_table(["Framework and clause", "Assets", "Finding codes"], body, [300, 50, 190]),
    ]


def _remediation_section(view: TeamCbomView, styles: Styles):
    story: list[Flowable] = [*section_heading(H_REMEDIATION, styles)]
    if view.is_empty:
        return [*story, _para(NO_DATA_NOTE, styles, "muted")]
    rows = remediation_rows(view)
    if not rows:
        return [*story, _para(NO_ISSUES_REMEDIATION, styles, "muted")]
    body = [
        [
            r.label,
            str(r.assets),
            status_chip(r.highest_impact, tone_for_impact(r.highest_impact)),
            r.action,
        ]
        for r in rows
    ]
    return [
        *story,
        dense_table(
            ["Finding", "Assets", "Highest impact", "Recommended action"], body, [170, 40, 62, 268]
        ),
        _gap(3),
        _para(REMEDIATION_NOTE, styles, "muted"),
    ]


def _pqc_section(view: TeamCbomView, styles: Styles):
    story: list[Flowable] = [*section_heading(H_PQC, styles, min_space=330)]
    if view.is_empty:
        story.append(_para(NO_DATA_NOTE, styles, "muted"))
    else:
        families = pqc_families(view)
        if families:
            story += [
                _para(PQC_FAMILIES_LEAD, styles),
                _gap(3),
                dense_table(
                    ["Target family", "Occurrences", "Sources"],
                    [[f.family, str(f.occurrences), str(f.sources)] for f in families],
                    [380, 80, 80],
                ),
            ]
        elif view.pqc_vulnerable:
            story.append(_para(PQC_COLLECTED_ONLY.format(count=view.pqc_vulnerable), styles))
        else:
            story.append(_para(authored.PQC_NO_VULNERABLE_TEXT, styles))
    timeline = [
        [row.when, row.milestone, row.status, row.source] for row in authored.PQC_TIMELINE_ROWS
    ]
    pointer = PQC_DETAIL_POINTER.format(order_note=authored.PQC_ROADMAP_ORDER_NOTE)
    return [
        *story,
        _gap(6),
        dense_table(["When", "Milestone", "Status", "Source"], timeline, [70, 290, 50, 130]),
        _gap(3),
        _para(authored.PQC_TIMELINE_FOOTNOTE, styles, "muted"),
        _gap(2),
        _para(pointer, styles, "muted"),
    ]


def _governance_section(view: TeamCbomView, styles: Styles):
    story: list[Flowable] = [*section_heading(H_GOVERNANCE, styles, min_space=210)]
    if view.is_empty:
        return [*story, _para(NO_DATA_NOTE, styles, "muted")]
    return [
        *story,
        _para(GOVERNANCE_LEAD, styles),
        _gap(3),
        dense_table(
            ["Action", "Live metric", "Owner", "Due", "Decision"],
            governance_rows(view),
            [205, 95, 80, 70, 90],
            manual_cols=(2, 3, 4),
        ),
    ]


def _signoff_section(styles: Styles, width: float):
    return [
        *section_heading(H_SIGNOFF, styles, min_space=210),
        signoff_block(SIGNOFF_ROLES, title=None, width=width),
    ]


def _grade_input_text(view: TeamCbomView) -> str:
    if not posture_active(view):
        return authored.GRADE_INPUT
    return authored.GRADE_INPUT + " plus configuration posture findings by impact."


def _grade_appendix(view: TeamCbomView, posture: PostureGrade, styles: Styles):
    story: list[Flowable] = [
        *section_heading(H_APP_GRADE, styles, min_space=280),
        _para(authored.GRADE_FORMULA, styles),
        _gap(3),
        _para(_grade_input_text(view), styles),
        _gap(6),
    ]
    line = configuration_posture_line(view)
    if line is not None:
        story += [_para(line, styles), _gap(4)]
    if posture.assessed:
        counts = (posture.critical, posture.high, posture.medium, posture.low)
        weights = authored.GRADE_WEIGHTS
        rows = [
            [level, str(n), str(weights[level]), str(n * weights[level])]
            for level, n in zip(IMPACT_LEVELS, counts, strict=True)
        ]
        worked = GRADE_WORKED.format(
            weighted=posture.weighted_points,
            cap=authored.GRADE_SCORE_CAP,
            multiplier=authored.GRADE_SCORE_MULTIPLIER,
            score=posture.score,
            grade=posture.grade,
            band=posture.band,
        )
        story += [
            dense_table(["Impact", "Issue assets", "Weight", "Points"], rows, [150, 130, 130, 130]),
            _gap(4),
            _para(worked, styles),
        ]
    else:
        story.append(_para(GRADE_NOT_ASSIGNED.format(reason=posture.reason), styles))
    return [*story, _gap(4), _para(authored.GRADE_DISCLAIMER, styles, "muted")]


def _scans_appendix(view: TeamCbomView, styles: Styles):
    story: list[Flowable] = [*section_heading(H_APP_SCANS, styles)]
    rows = scan_rows(view)
    if not rows:
        return [*story, _para(NO_DATA_NOTE, styles, "muted")]
    story += [_para(SCANS_NOTE, styles, "muted"), _gap(3)]
    story.append(
        dense_table(
            ["Scan", "Source", "Scanned (UTC)", "Fidelity", "Role"],
            rows[:MAX_SCAN_ROWS],
            [40, 250, 80, 80, 90],
        )
    )
    if len(rows) > MAX_SCAN_ROWS:
        omitted = SCANS_OMITTED.format(omitted=len(rows) - MAX_SCAN_ROWS)
        story += [_gap(3), _para(omitted, styles, "muted")]
    return story


def _disclaimers_appendix(styles: Styles, view: TeamCbomView | None = None):
    story: list[Flowable] = [*section_heading(H_APP_DISCLAIMERS, styles)]
    for paragraph in (*authored.disclaimer_paragraphs(view), authored.GRADE_DISCLAIMER):
        story += [_para(paragraph, styles), _gap(3)]
    story.append(_para(authored.PQC_TIMELINE_FOOTNOTE, styles))
    story.append(_gap(6))
    story.append(_para("Limits of the method", styles, "box_title"))
    for limit in authored.METHOD_LIMITS:
        story += [_gap(2), _para(f"\u2022 {limit}", styles)]
    return story


def _body(view: TeamCbomView, styles: Styles, width: float) -> list[Flowable]:
    posture = posture_grade(view)
    story: list[Flowable] = []
    story += _summary_section(view, posture, styles, width)
    story += _risks_section(view, styles)
    story += _quantum_section(view, styles, width)
    story += _certs_section(view, styles)
    story += _exposure_section(view, styles)
    story += _remediation_section(view, styles)
    story += _pqc_section(view, styles)
    story += _governance_section(view, styles)
    story += _signoff_section(styles, width)
    story += _grade_appendix(view, posture, styles)
    story += _scans_appendix(view, styles)
    story += _disclaimers_appendix(styles, view)
    return story


def build_pdf(view: TeamCbomView) -> bytes:
    """Render the Board / IT Strategy Committee report for ``view`` (portrait, in memory)."""
    return build_document(
        view=view,
        number=DELIVERABLE_NUMBER,
        report_key=REPORT_KEY,
        title=REPORT_META[REPORT_KEY]["title"],
        landscape=False,
        body=lambda styles, width: _body(view, styles, width),
    )


__all__ = [
    "CertPosture",
    "FamilyRow",
    "GovernanceMetrics",
    "PostureGrade",
    "RemediationRow",
    "build_pdf",
    "certificate_posture",
    "exposure_rows",
    "governance_metrics",
    "governance_rows",
    "issue_assets",
    "material_risks",
    "pqc_families",
    "posture_grade",
    "remediation_rows",
    "scan_rows",
]
