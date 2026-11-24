"""Board / IT Strategy Committee Report (SOW D14, portrait) - WP3f.

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
  has no finding to report), each asset once across sources (``population.asset_identity``).  Order: impact rank,
  then scanner risk score (absent last), then name.  Nothing here derives weakness from ``weak`` /
  ``crypto_strength`` (plan F-04).
* **Trend**: the headline figures against the previous issue of this report (``view.previous_issue``, recorded by
  the route), or "first issue" when none is recorded.
* **Post-quantum roadmap summary**: every current quantum-vulnerable asset (algorithms, certificates, keys,
  protocols) grouped by the target its usage calls for, so the total equals section 3 (review M5).
* **Regulatory exposure** prints the pooled counts of the frameworks that bind the team (its regulatory profile:
  jurisdiction, entity type, card data, SEBI, government; ``crypto_kb.applies``) and names the others as not
  applicable; "Pass" includes requirements passed on attached evidence. Each row says on how many of the team's
  sources it is based, and the lead prints the counts the rows use (SOW audit A-11, review M3/M4). The
  collected-infrastructure clauses are the run API's, filtered the same way.
* **Readiness** prints the formula with the very numbers of the view (Rule P): safe / (safe + quantum-vulnerable +
  broken today), the rule of ``cbom_metrics.quantum_readiness_pct`` (SOW audit A-07).
* **Remediation** rows name each finding by the knowledge base's title and fix (SOW audit A-12); the quantum risk
  grades of the register (D12) are summarised in section 3.
* Every data-derived string reaches a ``Paragraph`` through ``pdf_text`` (the one helper
  ``_para``) or through ``dense_table`` / ``kpi_strip`` / ``status_chip``, which sanitise
  themselves; scanned repositories are untrusted input.

Hard rules (enforced by the guards in ``test_cbom_deliverable_board_report.py``): reportlab,
the standard library and the two backend packages ``backend.utilities.pdf`` and
``backend.utilities.dashboard.cbom_team_rollup`` only; no network, no language model, no wall
clock (every date comes from the view); Python 3.10 syntax.
"""

from __future__ import annotations

from typing import Any

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
from backend.utilities.pdf import cbom_kb_text as kb_text
from backend.utilities.pdf import cbom_population as population
from backend.utilities.pdf import cbom_risk_register_pdf as register_pdf
from backend.utilities.pdf.cbom_collected_compliance import collected_clauses
from backend.utilities.pdf.cbom_deliverable_common import (
    Styles,
    build_document,
    dense_table,
    document_id,
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

DELIVERABLE_NUMBER = 14  # SOW D14 (REPORT_META sow_id; the Document ID reads it)
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
READINESS_FORMULA = (
    "Readiness = quantum-safe / (quantum-safe + quantum-vulnerable + broken today) = "
    "{safe} / ({safe} + {vulnerable} + {broken}) = {pct}"
)
READINESS_NOTE = (
    "Counted over the current assets of every source that carry a quantum verdict; assets without one are left "
    "out of both sides. Broken today (MD5, DES and the like) is not ready. Quantum-vulnerable public-key "
    "algorithms (RSA, elliptic-curve, Diffie-Hellman, DSA) are the migration scope; section 7 summarises the "
    "target standards and the regulatory timeline."
)
QGRADE_HEADING = "Quantum risk grades (D12)"
QGRADE_LEAD = (
    "Grades from the quantum risk register (D12): {total} distinct assets. Q1 Critical to Q4 Low rank quantum risk "
    "under the team's Mosca inputs; Q0 Unknown means the platform could not grade the asset, never that it is safe."
)
QGRADE_NOT_LOADED = "The quantum risk register (D12) could not be loaded for this report."
CERT_DATE_NOTE = (
    "Validity is computed as of {as_of} (the report date) from each certificate's notAfter "
    "date, not from the flag raised when the scan ran. Certificates are counted once across "
    "all sources."
)
EXPOSURE_LEGACY_NOTE = (
    "No compliance results are available: {pooled} of {sources} sources pooled "
    "({legacy} legacy excluded). Re-scan the legacy-format sources to include them."
)
EXPOSURE_POOLED = "Rows are based on {pooled} of {sources} sources{legacy}; each row shows its own count."
EXPOSURE_NOT_APPLICABLE = (
    "Not applicable to this team and not shown ({profile}): {frameworks}."
)
EXPOSURE_BASIS = (
    "Each row is computed only over the sources whose results that framework's checks can read, shown in the last "
    "column as N of {sources} sources. A percentage is therefore not a measure of estate-wide compliance: a row "
    "based on one code repository says nothing about the other sources."
)
EXPOSURE_ENTITY = (
    "Regulated entity: {label} (team setting). RBI clauses are cited from {instrument}; RBI directions for other "
    "entity types are not applied."
)
EXPOSURE_ENTITY_NONE = (
    "Regulated entity: {label} (team setting). No RBI cybersecurity direction binds this entity type, so no RBI "
    "clause is cited."
)
EXPOSURE_COLLECTED_LEAD = (
    "Collected infrastructure (CBOM Sources): the regulatory clauses that bind the team and that the findings of "
    "each source's latest collection touch, with the number of assets concerned (knowledge-base mapping, the same "
    "as the run's compliance view; a clause listed here is not a verdict)."
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
    "Every current quantum-vulnerable asset ({total}, as in section 3: algorithms, certificates, keys and "
    "protocols), grouped by the post-quantum target its use calls for: key establishment moves to {kem}, "
    "signatures, certificates and signing keys to {sig} (national security systems under CNSA 2.0: {kem5} and "
    "{sig5}). A code-scan algorithm keeps the target its scan recorded."
)
TREND_HEADING = "Trend against the previous issue"
TREND_LEAD = "Previous issue: {document} (as of {as_of}). Change = this issue minus the previous one."
TREND_FIRST = (
    "First issue: no earlier issue of this report is recorded for the team, so there is no trend yet. The next "
    "issue will compare its figures with this one ({document})."
)
PQC_DETAIL_POINTER = (
    "Per-asset detail, with wave, owner and target-date columns for the assessor, is in the "
    "PQC Migration Roadmap. {order_note}"
)
TARGET_NOT_RECORDED = "Target not recorded (legacy scan)"
SCANS_NOTE = (
    "Every result this report includes: code scans and the latest collection of each CBOM Sources source. The "
    "Basis box on page 1 counts the scans excluded from this report."
)
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
}
_KIND_LABEL = {"algorithm": "Algorithm", "certificate": "Certificate", "key": "Key or secret material",
               "protocol": "Protocol", "library": "Library", "setting": "Encryption setting"}
# code scans (aibom) and CBOM Sources collections (cbom_sources.classify) name the same certificate findings differently
_WEAK_CERT_CODES = frozenset({"WEAK_CERTIFICATE_SIGNATURE", "WEAK_CERTIFICATE_KEY", "SIG_MD5", "SIG_SHA1",
                              "RSA_LT_1024", "RSA_LT_2048", "EC_LT_224"})
_SELF_SIGNED_LEAF_CODES = frozenset({"SELF_SIGNED_LEAF", "CERT_SELF_SIGNED"})  # the collected code is leaf-only too
_RANK = {level: index for index, level in enumerate(IMPACT_LEVELS)}
_UNRANKED = len(IMPACT_LEVELS)
# "1 sources" -> "1 source": the authored governance templates are written in the plural
_SINGULAR = re.compile(
    r"\b1 (unique certificate|requirement|quantum-vulnerable asset occurrence|source|quantum-vulnerable asset)s\b"
)
_TREND_ROWS = (  # (snapshot field, label, lower is better)
    ("grade", "Posture grade", True),
    ("score", "Risk score", True),
    ("issues", "Issue assets", True),
    ("critical", "Critical issue assets", True),
    ("high", "High issue assets", True),
    ("quantum_vulnerable", "Quantum-vulnerable occurrences", True),
    ("readiness", "Quantum readiness (%)", False),
    ("q1", "Q1 Critical (register)", True),
    ("q0", "Q0 Unknown (register)", True),
    ("expired", "Expired certificates", True),
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
        f"({_count(resources, 'resource')}, {_count(sources, 'source')} not assessed)"
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
    """Current assets with at least one finding code, most material first; an asset observed by several sources
    is listed once, by its most material observation (review M7b)."""
    ordered = sorted((a for a in view.assets if a.current and a.finding_codes), key=_risk_key)
    seen: set[tuple[str, ...]] = set()
    out = []
    for asset in ordered:
        key = population.asset_identity(asset)
        if key not in seen:
            seen.add(key)
            out.append(asset)
    return out


def observed_by(view: TeamCbomView, asset: AssetAgg) -> int:
    """How many current sources observed the asset (1 for an asset only its own source holds)."""
    key = population.asset_identity(asset)
    return len({a.source_key for a in view.assets if a.current and population.asset_identity(a) == key})


def material_risks(view: TeamCbomView, limit: int = TOP_RISKS) -> list[AssetAgg]:
    """The ``limit`` most material issue assets (Critical first), each asset once."""
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
    """Every current quantum-vulnerable asset grouped by its migration target (``population.pqc_target_groups``):
    the occurrences add up to ``view.pqc_vulnerable`` (section 3)."""
    return [FamilyRow(group["target"], group["occurrences"], group["sources"])
            for group in population.pqc_target_groups(view)]


def _kinds_text(kinds: Counter) -> str:
    return ", ".join(f"{population.KIND_LABELS[k].lower()} {n}" for k, n in sorted(
        kinds.items(), key=lambda kv: (-kv[1], population.KINDS.index(kv[0]))))


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
    mosca_missing: int = 0  # register assets graded Q0 because the Mosca inputs are not set (D12)


def _register_summary(view: TeamCbomView) -> dict[str, Any] | None:
    register = getattr(view, "register", None)
    summary = register.get("summary") if isinstance(register, dict) else None
    return summary if isinstance(summary, dict) else None


def governance_metrics(view: TeamCbomView) -> GovernanceMetrics:
    summary = _register_summary(view) or {}
    reasons = summary.get("q0_reasons") if isinstance(summary.get("q0_reasons"), dict) else {}
    return GovernanceMetrics(
        unique_certs=sum(1 for c in view.certs if c.current),
        attestations_outstanding=sum(
            1 for r in view.requirements if r.attestable_sources > r.attested_sources
        ),
        quantum_vulnerable=int(view.pqc_vulnerable),
        legacy_scans=int(view.compliance_legacy_excluded),
        mosca_missing=int(reasons.get("mosca_missing", 0) or 0),
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
        "mosca_missing": metrics.mosca_missing,
    }
    live = {
        "owners": _count(metrics.unique_certs, "unique certificate"),
        "attestations": f"{_count(metrics.attestations_outstanding, 'requirement')} outstanding",
        "pqc": _count(metrics.quantum_vulnerable, "quantum-vulnerable occurrence"),
        "legacy": f"{_count(metrics.legacy_scans, 'source')} in legacy format",
        "mosca": f"{_count(metrics.mosca_missing, 'asset')} Q0 for missing inputs",
    }
    counts = {"owners": metrics.unique_certs, "attestations": metrics.attestations_outstanding,
              "legacy": metrics.legacy_scans, "mosca": metrics.mosca_missing}
    rows = []
    for key, template in authored.GOVERNANCE_ACTIONS:
        if key in authored.GOVERNANCE_HIDE_WHEN_ZERO and counts.get(key, 0) <= 0:
            continue  # nothing to decide ("Re-scan the 0 sources ..."): the row is left out
        action = _SINGULAR.sub(r"1 \1", template.format(**fields))
        rows.append([action, live.get(key, ""), "", "", ""])
    return rows


def _percent(ratio: float | None) -> str:
    return "n/a" if ratio is None else f"{ratio * 100:.1f}%"


def binding_frameworks(view: TeamCbomView) -> list:
    """The pooled frameworks that bind the team (its regulatory profile; review M4), engine order."""
    return [pool for pool in view.frameworks if kb_text.framework_binds(pool.framework, view)]


def not_applicable_frameworks(view: TeamCbomView) -> list[str]:
    """Labels of the pooled frameworks that do not bind the team (named, never silently dropped)."""
    return [authored.framework_label(pool.framework) for pool in view.frameworks
            if not kb_text.framework_binds(pool.framework, view)]


def profile_text(view: TeamCbomView) -> str:
    """"NBFC in India, no payment-card data, not SEBI-regulated, not a government entity"."""
    profile = kb_text.view_profile(view)
    flags = set(profile.get("flags") or ())
    return (f"{kb_text.entity_label(profile['entity'])} in India, "
            + ("payment-card data processed" if "processes_card_data" in flags else "no payment-card data") + ", "
            + ("SEBI-regulated" if "sebi_regulated" in flags else "not SEBI-regulated") + ", "
            + ("a government entity" if "government_entity" in flags else "not a government entity"))


def exposure_basis(view: TeamCbomView) -> str:
    """The lead of the framework table: the source counts the rows use (review M3), never a different count."""
    shown = binding_frameworks(view)
    total = len(view.sources)
    counts = sorted({int(pool.sources_pooled) for pool in shown})
    if not counts:
        pooled = "0"
    elif len(counts) == 1:
        pooled = str(counts[0])
    else:
        pooled = f"{counts[0]} to {counts[-1]}"
    legacy = int(view.compliance_legacy_excluded or 0)
    return EXPOSURE_POOLED.format(pooled=pooled, sources=total,
                                  legacy=f" ({legacy} in legacy format excluded)" if legacy else "")


def exposure_rows(view: TeamCbomView) -> list[list[str]]:
    """One row per pooled framework that binds the team (engine order): label, coverage, pass, fail, NBE, OOS, and
    the basis "N of M sources" (M = every source of the report, so a row pooled from one repository says so)."""
    total = len(view.sources)
    return [
        [
            authored.framework_label(pool.framework),
            _percent(pool.coverage),
            str(pool.passed + pool.passed_with_evidence),
            str(pool.failed),
            str(pool.not_bom_evidenceable),
            str(pool.out_of_scope),
            f"{pool.sources_pooled} of {total} source{'' if total == 1 else 's'}",
        ]
        for pool in binding_frameworks(view)
    ]


def readiness_formula(view: TeamCbomView) -> str | None:
    """The readiness formula printed with the view's own numbers (Rule P), None when nothing was graded."""
    if view.readiness_pct is None:
        return None
    return READINESS_FORMULA.format(safe=view.pqc_safe, vulnerable=view.pqc_vulnerable,
                                    broken=view.pqc_broken_today, pct=f"{view.readiness_pct:.1f}%")


def qgrade_rows(view: TeamCbomView) -> list[list[str]] | None:
    """``[grade, assets]`` rows of the quantum risk register (D12), None when it was not loaded."""
    summary = _register_summary(view)
    if summary is None:
        return None
    grades = summary.get("q_grades") if isinstance(summary.get("q_grades"), dict) else {}
    rows = [[register_pdf.grade_text(g), str(int(grades.get(g, 0) or 0))] for g in ("Q1", "Q2", "Q3", "Q4", "Q0")]
    rows.append(["No grade (no public-key cryptography)", str(int(grades.get("none", 0) or 0))])
    return rows


def q0_reason_text(view: TeamCbomView) -> str:
    """"Q0 by reason: Mosca inputs missing 3, PQC class unknown 1" (the register's reasons, most first)."""
    summary = _register_summary(view) or {}
    reasons = summary.get("q0_reasons") if isinstance(summary.get("q0_reasons"), dict) else {}
    parts = sorted(((str(k), int(v or 0)) for k, v in reasons.items() if int(v or 0) > 0), key=lambda kv: (-kv[1], kv[0]))
    if not parts:
        return ""
    words = register_pdf._REASON_WORDS
    def word(key: str) -> str:
        text = words.get(key) or key.replace("_", " ")
        return text[:1].upper() + text[1:]  # "PQC class unknown" keeps its acronym

    return "Q0 by reason: " + ", ".join(f"{word(k)} {n}" for k, n in parts) + "."


def scan_rows(view: TeamCbomView) -> list[list[str]]:
    """Every included result for Appendix B (review M7a): the code scans grouped by source (newest first inside a
    source), then each CBOM Sources source's latest collection (its run)."""
    labels = {source.key: source.label for source in view.sources}
    included = [scan for scan in view.scans if scan.exclusion is None]
    included.sort(key=lambda s: (s.created_at, s.scan_id), reverse=True)
    included.sort(key=lambda s: (labels.get(s.source_key, s.source_label).casefold(), s.source_key))
    rows = [
        [
            f"Scan #{scan.scan_id}",
            labels.get(scan.source_key, scan.source_label),
            fmt_date_utc(scan.created_at),
            "Full" if scan.fidelity == FIDELITY_FULL else "Legacy format",
            "Current" if scan.is_current else "History",
        ]
        for scan in included
    ]
    for found in sorted(view.collections or (), key=lambda c: (c.label.casefold(), c.key)):
        rows.append([f"Run #{found.run_id}", f"{labels.get(found.key, found.label)}\nCBOM Sources collection",
                     fmt_date_utc(found.observed_at), "Full", "Current"])
    return rows


# ---------------------------------------------------------------------------------------------
# Trend against the previous issue (review M7c)
# ---------------------------------------------------------------------------------------------
def issue_snapshot(view: TeamCbomView) -> dict[str, Any]:
    """The headline figures this issue prints, as ``cbom_board_issues`` records them for the next issue."""
    posture = posture_grade(view)
    total, _breakdown = _issue_breakdown(view)
    grades = (_register_summary(view) or {}).get("q_grades") or {}
    return {
        "document_id": document_id(view, DELIVERABLE_NUMBER),
        "as_of": view.as_of.isoformat(),
        "grade": posture.grade if posture.assessed else authored.GRADE_NOT_ASSESSED,
        "score": posture.score,
        "issues": total,
        "critical": posture.critical,
        "high": posture.high,
        "quantum_vulnerable": int(view.pqc_vulnerable),
        "readiness": None if view.readiness_pct is None else round(float(view.readiness_pct), 1),
        "q1": int(grades.get("Q1", 0) or 0) if isinstance(grades, dict) and _register_summary(view) else None,
        "q0": int(grades.get("Q0", 0) or 0) if isinstance(grades, dict) and _register_summary(view) else None,
        "expired": certificate_posture(view).expired,
    }


def _change(name: str, before: Any, now: Any, lower_better: bool) -> str:
    if before is None or now is None:
        return "n/a"
    if name == "grade":
        if before == now:
            return "no change"
        ranks = "ABCDEF"
        if before in ranks and now in ranks:
            return "better" if ranks.index(now) < ranks.index(before) else "worse"
        return "changed"
    delta = round(float(now) - float(before), 1)
    if delta == 0:
        return "no change"
    better = (delta < 0) == lower_better
    number = f"{delta:+.1f}" if name == "readiness" else f"{int(delta):+d}"
    return f"{number} ({'better' if better else 'worse'})"


def trend_rows(view: TeamCbomView) -> list[list[str]] | None:
    """``[measure, previous, now, change]`` against ``view.previous_issue``; None for the first issue."""
    before = getattr(view, "previous_issue", None)
    if not isinstance(before, dict) or not before.get("document_id"):
        return None
    now = issue_snapshot(view)

    def shown(value: Any) -> str:
        return "n/a" if value is None else (f"{value:.1f}" if isinstance(value, float) else str(value))

    return [[label, shown(before.get(name)), shown(now.get(name)), _change(name, before.get(name), now.get(name), low)]
            for name, label, low in _TREND_ROWS]


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
            "Quantum readiness cannot be computed because no asset occurrence could be graded."
        )
    verb = "uses" if view.pqc_vulnerable == 1 else "use"
    return (
        f"Quantum readiness is {view.readiness_pct:.1f}%: {view.pqc_vulnerable} of {graded} "
        f"gradeable asset occurrences (algorithms, keys, certificates and protocols) {verb} quantum-vulnerable "
        "public-key cryptography"
        + (f" and {view.pqc_broken_today} {'is' if view.pqc_broken_today == 1 else 'are'} broken today (MD5, DES and "
           "the like)." if view.pqc_broken_today else ".")
    )


def _scope_counts(view: TeamCbomView) -> tuple[int, int, int]:
    """(code sources, code scans, CBOM Sources collections). ``merge_collections`` adds each collection to
    ``view.sources`` and to ``view.included``, so the code part is what is left."""
    collections = len(view.collections or ())
    code_sources = sum(1 for source in view.sources if source.kind != SOURCE_SOURCES)
    return code_sources, max(int(view.included) - collections, 0), collections


def _repos(number: int) -> str:
    return f"{number} {'repository or upload' if number == 1 else 'repositories and uploads'}"


def scope_captions(view: TeamCbomView) -> tuple[str, str]:
    """Captions of the "Sources" and "Scans included" summary cards."""
    code_sources, code_scans, collections = _scope_counts(view)
    if not collections:
        return "repositories and uploads assessed", f"of {view.eligible} eligible completed scans"
    return (f"{_repos(code_sources)}, {collections} CBOM Sources",
            f"of {view.eligible} eligible: {_count(code_scans, 'code scan')}, "
            f"{_count(collections, 'Sources collection')}")


def scope_sentence(view: TeamCbomView) -> str:
    """The summary's opening clause: what the roll-up covers."""
    code_sources, code_scans, collections = _scope_counts(view)
    if not collections:
        return f"Across {_count(len(view.sources), 'source')} and {_count(view.included, 'completed scan')}"
    return (f"Across {_count(len(view.sources), 'source')} ({_repos(code_sources)}, "
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
    paragraphs.append(population.reconciliation_line(view))
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
        f"{view.pqc_vulnerable} of {view.pqc_safe + view.pqc_vulnerable + view.pqc_broken_today} gradeable asset "
        "occurrences quantum-vulnerable"
        if view.readiness_pct is not None
        else "no asset occurrence could be graded"
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
    return [*story, *_trend_block(view, styles)]


def _trend_block(view: TeamCbomView, styles: Styles) -> list[Flowable]:
    if view.is_empty:
        return []
    story: list[Flowable] = [_gap(2), _para(TREND_HEADING, styles, "box_title")]
    rows = trend_rows(view)
    if rows is None:
        return [*story, _para(TREND_FIRST.format(document=document_id(view, DELIVERABLE_NUMBER)), styles, "muted")]
    before = view.previous_issue or {}
    return [*story, _para(TREND_LEAD.format(document=before.get("document_id"), as_of=before.get("as_of") or "n/a"),
                          styles, "muted"), _gap(3),
            dense_table(["Measure", "Previous issue", "This issue", "Change"], rows, [200, 100, 100, 140])]


def _risks_section(view: TeamCbomView, styles: Styles):
    story: list[Flowable] = [*section_heading(H_RISKS, styles)]
    if view.is_empty:
        return [*story, _para(NO_DATA_NOTE, styles, "muted")]
    issues = issue_assets(view)
    if not issues:
        return [*story, _para(NO_ISSUES_RISKS, styles, "muted")]
    rows = []
    for rank, asset in enumerate(issues[:TOP_RISKS], start=1):
        # what the asset is (a library, an encryption setting ...), never "Other" (SOW audit A-10)
        kind = _ASSET_TYPE_LABEL.get(asset.asset_type) or _KIND_LABEL[population.asset_kind(asset)]
        where = f"{asset.source_label}\n{asset.location}" if asset.location else asset.source_label
        others = observed_by(view, asset) - 1
        if others > 0:
            where += f"\nalso observed by {_count(others, 'other source')}"
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
            ("Readiness", _pct_or_na(view), "share of gradeable asset occurrences"),
            ("Quantum-vulnerable", str(view.pqc_vulnerable), "public-key occurrences to migrate"),
            ("Quantum-safe", str(view.pqc_safe), f"of which {view.pqc_hybrid} hybrid"),
            ("Not gradeable", str(view.pqc_ungraded), "excluded from readiness"),
        ],
        w,
        max_per_row=4,
    )
    story += [strip, _gap()]
    formula = readiness_formula(view)
    if formula is not None:
        story += [_para(formula, styles), _gap(2)]
    story += [_para(READINESS_NOTE, styles, "muted"), _gap(6), _para(QGRADE_HEADING, styles, "box_title")]
    rows = qgrade_rows(view)
    if rows is None:
        return [*story, _para(QGRADE_NOT_LOADED, styles, "muted")]
    total = int((_register_summary(view) or {}).get("total", 0) or 0)
    story += [_para(QGRADE_LEAD.format(total=total), styles), _gap(3),
              dense_table(["Quantum risk grade", "Assets"], rows, [400, 140])]
    reasons = q0_reason_text(view)
    if reasons:
        story += [_gap(3), _para(reasons, styles, "muted")]
    return story


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
    hidden = not_applicable_frameworks(view)
    hidden_note = ([_gap(3), _para(EXPOSURE_NOT_APPLICABLE.format(profile=profile_text(view),
                                                                   frameworks=", ".join(hidden)), styles, "muted")]
                   if hidden else [])
    shown = binding_frameworks(view)
    if not shown:
        if collected:
            return [*story, *collected, *hidden_note]
        if hidden:
            return [*story, *hidden_note]
        return [*story, _para(EXPOSURE_LEGACY_NOTE.format(**basis), styles, "muted")]
    rbi_row = any(pool.framework == "rbi_free_ai_protection" for pool in shown)
    rbi_note = ([_gap(4), _para(authored.rbi_mapping_note(kb_text.view_profile(view)["entity"]), styles, "muted")]
                if rbi_row else [])
    headers = [
        "Framework",
        "Coverage",
        "Pass",
        "Fail",
        "Not evidenceable",
        "Out of scope",
        "Based on",
    ]
    table = dense_table(headers, exposure_rows(view), [190, 56, 44, 44, 70, 66, 70])
    return [
        *story,
        _para(exposure_basis(view), styles),
        _gap(2),
        _para(EXPOSURE_BASIS.format(sources=len(view.sources)), styles, "muted"),
        _gap(3),
        table,
        *rbi_note,
        _gap(3),
        _para(authored.METHOD_COVERAGE, styles, "muted"),
        *hidden_note,
        *([_gap(6), *collected] if collected else []),
    ]


def clause_title(framework: str, clause: str) -> str:
    """"NSA CNSA 2.0 FAQ (April 2024)", never "NSA CNSA 2.0 CNSA 2.0 FAQ ..." (the clause may repeat the framework)."""
    words = framework.split()
    for start in range(len(words)):
        tail = " ".join(words[start:])
        if tail and clause.startswith(tail):
            return " ".join([*words[:start], clause]).strip()
    return f"{framework} {clause}"


def _collected_exposure(view: TeamCbomView, styles: Styles) -> list[Flowable]:
    rows = collected_clauses(view)
    if not rows:
        return []
    # board-readable finding names (the knowledge base's titles), never raw codes (review M7d)
    body = [[clause_title(r.framework, r.clause), str(r.assets),
             "; ".join(dict.fromkeys(authored.finding_label(code) for code in r.codes))
             + (f" (algorithm not recorded for {r.unrecorded}: verify)" if r.unrecorded else "")] for r in rows]
    entity = kb_text.view_profile(view)["entity"]
    found = authored.entity_instrument(entity)
    entity_line = (EXPOSURE_ENTITY.format(label=kb_text.entity_label(entity), instrument=f"{found[0]}, {found[1]}")
                   if found else EXPOSURE_ENTITY_NONE.format(label=kb_text.entity_label(entity)))
    return [
        _para(EXPOSURE_COLLECTED_LEAD, styles),
        _gap(2),
        _para(entity_line, styles, "muted"),
        _gap(3),
        dense_table(["Framework and clause", "Assets", "Findings"], body, [260, 50, 230]),
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
        groups = population.pqc_target_groups(view)
        if groups:
            total = sum(g["occurrences"] for g in groups)
            lead = PQC_FAMILIES_LEAD.format(
                total=total, kem=population.pq_target(population.USAGE_KEM),
                sig=population.pq_target(population.USAGE_SIGNATURE),
                kem5=population.pq_target(population.USAGE_KEM, 5),
                sig5=population.pq_target(population.USAGE_SIGNATURE, 5))
            rows = [[g["target"], population.USAGE_LABELS[g["usage"]], _kinds_text(g["kinds"]),
                     str(g["occurrences"]), str(g["sources"])] for g in groups]
            rows.append(["Total", "", "", str(total), str(len({a.source_key for a in
                                                                population.quantum_vulnerable_assets(view)}))])
            story += [
                _para(lead, styles),
                _gap(3),
                dense_table(["Target", "Use", "What", "Occurrences", "Sources"], rows, [96, 190, 154, 56, 44]),
            ]
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
    return authored.GRADE_INPUT_WITH_POSTURE


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
            ["Result", "Source", "Scanned (UTC)", "Fidelity", "Role"],
            rows[:MAX_SCAN_ROWS],
            [56, 234, 80, 80, 90],
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
    for limit in authored.method_limits(view):
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


def build_pdf(view: TeamCbomView, *, ctx: Any = None) -> bytes:
    """Render the Board / IT Strategy Committee report for ``view`` (portrait, in memory)."""
    return build_document(ctx=ctx,
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
    "binding_frameworks",
    "clause_title",
    "exposure_basis",
    "exposure_rows",
    "governance_metrics",
    "governance_rows",
    "issue_snapshot",
    "issue_assets",
    "material_risks",
    "not_applicable_frameworks",
    "observed_by",
    "pqc_families",
    "posture_grade",
    "remediation_rows",
    "scan_rows",
    "trend_rows",
]
