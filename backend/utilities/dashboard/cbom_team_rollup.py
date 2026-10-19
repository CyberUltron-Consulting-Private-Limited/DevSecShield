"""Team-wide CBOM roll-up: the aggregation core behind the six regulatory PDF deliverables.

STATUS - WP1a interface freeze.  This module holds the *types* and the *function signatures*
(every function body raises ``NotImplementedError``).  WP1b implements the bodies test-first
WITHOUT changing a name, field or signature below; WP2 / WP3a-f / WP4 code against these types
in parallel.  If a downstream package needs a type to change, it asks for a new interface
freeze - it does not edit this file ad hoc.

Spec: ``.agents/tasks/cbom-medium-renderers-plan.md`` section 4 (aggregation), section 5.2
(signatures), section 6.2 + Appendix B (fixture and independent oracle).

Hard rules for this module (enforced by the T-NOLLM guards, plan 6.5):

* Pure standard library at import time.  The one DB-touching function
  (``load_team_cbom_view``) imports ``sqlmodel`` / ``backend.new_models`` INSIDE its body, so
  importing this module never pulls ``boto3`` / ``langchain`` / ``requests`` / ``httpx`` /
  ``pymongo`` / ``celery``.
* No LLM, no network, no subprocess, no clock reads: ``now`` / ``as_of`` are always injected.
* Python 3.10 syntax only (no ``datetime.UTC``, ``StrEnum``, ``tomllib``, ``typing.Self``).
* The view never holds a raw ``scan_data`` blob and never holds raw ``scan_metadata`` (it can
  carry a ``user:token@`` URL); repository URLs are sanitised before they enter any field.

Data model in one paragraph.  ``fold_scans`` receives one ``ScanHead`` per CBOM scan (no blobs)
and streams the blobs of the eligible ones.  ``extract_scan_facts`` turns ONE blob into
``ScanFacts`` whose ``assets`` / ``certs`` / ``libs`` / ``requirements`` / ``frameworks`` are
single-scan observations expressed with the same ``*Agg`` types as the final view
(``scan_count == 1``, ``first_seen == last_seen == created_at``).  The fold merges those
observations per entity identity (plan 4.4), keeps the NEWEST scan's attributes ("latest
wins"), marks entities present in a source's current scan ``current=True`` (plan 4.5), pools
compliance over the current full-fidelity scans and returns a ``TeamCbomView``.  Renderers are
pure functions of that view.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import date, datetime
from typing import Any

# ---------------------------------------------------------------------------------------------
# Plan 5.2 constants (caps are decision D-04)
# ---------------------------------------------------------------------------------------------
HISTORY_WINDOW = 200  # newest eligible scans folded for first/last-seen history
HARD_MAX_SCANS = 1000  # absolute ceiling, even while chasing every source's latest scan
BATCH_SIZE = 20  # blobs loaded per ``load_blobs`` call
NEAR_EXPIRY_DAYS = 90  # mirrors aibom weakness._NEAR_EXPIRY_DAYS (weakness.py:38)

# Per-entity list caps (plan 4.5: "newest 12 (+N more)").  ``scan_count`` / ``*_total`` keep the
# true numbers so a renderer can print "+N more".
MAX_SCAN_IDS = 12
MAX_LOCATIONS = 12

# Digest namespace of ``TeamCbomView.fingerprint``.  Plan 4.8 writes ``sha256(slug + '|' + ...)``
# but ``fold_scans`` (and ``document_id(view, number)``) carry no per-document slug, so the view
# uses this constant; the per-document part of a Document ID is its ``D{nn}`` number.
FINGERPRINT_NAMESPACE = "cbom-team-rollup"

# ---------------------------------------------------------------------------------------------
# Closed vocabularies (plain strings: JSON-friendly and safe on Python 3.10)
# ---------------------------------------------------------------------------------------------
# Scan status after ``str(status).strip().lower()``.  Only STATUS_SUCCESS is eligible (plan 4.1).
STATUS_SUCCESS = "success"
STATUS_FAILURE = "failure"
NOT_COMPLETED_STATUSES = frozenset({"pending", "started", "retry", "not_started"})

# ``ScanFacts.exclusion`` / ``TeamCbomView.excluded`` keys.  ``exclusion is None`` == included.
EXCLUDED_FAILURE = "failure"
EXCLUDED_NOT_COMPLETED = "not_completed"  # pending / started / retry / NOT_STARTED / unknown
# success, but scan_data has neither a list "results" nor a dict "cbom_json"
EXCLUDED_NO_DATA = "no_data"

# ``source_key_for`` third element (plan 4.3)
SOURCE_REPO = "repo"
SOURCE_ZIP = "zip"
SOURCE_FILE = "file"
SOURCE_SCAN = "scan"

# Fidelity (plan 3.1).  ``full`` <=> cbom_distributions is a dict AND cbom_compliance is a
# non-empty dict AND result rows carry ``asset_type``; anything else is ``reduced`` + reasons.
FIDELITY_FULL = "full"
FIDELITY_REDUCED = "reduced"
FIDELITY_NONE = "none"  # excluded scans: no blob was read
FIDELITY_REASONS = ("no_distributions", "no_compliance", "no_asset_type", "no_cbom_json")
# Tier A = full.  Tier B = reduced but ``cbom_json`` and typed rows survive (certificates and
# libraries are recoverable).  Tier C = reduced and (no_asset_type or no_cbom_json), i.e. the
# pre-reconcile worker output.  TIER_NONE = no blob read.
TIER_A = "A"
TIER_B = "B"
TIER_C = "C"
TIER_NONE = "-"

# CycloneDX 1.6 crypto ``assetType`` values (+ a catch-all so no row is ever dropped)
ASSET_ALGORITHM = "algorithm"
ASSET_CERTIFICATE = "certificate"
ASSET_PROTOCOL = "protocol"
ASSET_MATERIAL = "related-crypto-material"
ASSET_OTHER = "other"
ASSET_TYPES = (ASSET_ALGORITHM, ASSET_CERTIFICATE, ASSET_PROTOCOL, ASSET_MATERIAL, ASSET_OTHER)

# ``results[].impact`` buckets, worst first (rank = index).  Anything else sorts last.
IMPACT_LEVELS = ("Critical", "High", "Medium", "Low")

# Certificate validity bands (``classify_expiry``), in display / sort order.
EXPIRED = "EXPIRED"  # days_left < 0
LE_30 = "LE_30"  # 0 <= days_left <= 30
LE_90 = "LE_90"  # 30 < days_left <= NEAR_EXPIRY_DAYS
VALID = "VALID"  # days_left > NEAR_EXPIRY_DAYS
UNKNOWN = "UNKNOWN"  # notAfter missing / unparseable
EXPIRY_BANDS = (EXPIRED, LE_30, LE_90, VALID, UNKNOWN)

# Compliance verdicts (aibom.compliance.base.Verdict) and the roll-up precedence of plan 4.5,
# highest first: fail > not_bom_evidenceable > pass_with_evidence > pass > out_of_scope > na.
VERDICT_PASS = "pass"
VERDICT_PASS_WITH_EVIDENCE = "pass_with_evidence"
VERDICT_FAIL = "fail"
VERDICT_OUT_OF_SCOPE = "out_of_scope"
VERDICT_NOT_BOM_EVIDENCEABLE = "not_bom_evidenceable"
VERDICT_NA = "na"
VERDICT_PRECEDENCE = (
    VERDICT_FAIL,
    VERDICT_NOT_BOM_EVIDENCEABLE,
    VERDICT_PASS_WITH_EVIDENCE,
    VERDICT_PASS,
    VERDICT_OUT_OF_SCOPE,
    VERDICT_NA,
)


# ---------------------------------------------------------------------------------------------
# Input / per-scan types
# ---------------------------------------------------------------------------------------------
@dataclass(frozen=True)
class ScanHead:
    """Pass-1 projection of one ``Scan`` row: every column EXCEPT ``scan_data`` (plan 4.2).

    ``created_at`` / ``last_updated`` are timezone-aware UTC.  Postgres returns naive UTC, so the
    loader attaches ``timezone.utc`` (plan 3.1); ``fold_scans`` / ``extract_scan_facts`` must
    still tolerate a naive value by treating it as UTC.  ``team_id`` and ``scan_type`` are
    carried so the pure fold can re-check tenancy and type even though the SQL already filters
    (defence in depth: a ``load_blobs`` spy must never see a foreign or non-cbom id).
    ``scan_metadata`` is raw and may hold ``user:token@`` URLs - it is never copied out.
    """

    id: int
    team_id: int
    scan_type: str
    title: str
    status: str  # raw DB value: pending|started|retry|failure|success|NOT_STARTED
    created_at: datetime
    last_updated: datetime
    scan_metadata: Mapping[str, Any] | None = None


@dataclass(frozen=True)
class ExpiryBand:
    """Result of ``classify_expiry``: a band from ``EXPIRY_BANDS`` plus the signed day count."""

    band: str
    # (notAfter date - as_of).days; negative when expired; None when the band is UNKNOWN
    days_left: int | None = None


@dataclass
class ScanFacts:
    """What the fold needs from ONE scan; built by ``extract_scan_facts`` (or from a head only).

    ``TeamCbomView.scans`` stores *slim* copies: the heavy payload lists (``assets`` ...
    ``warnings``) are emptied once folded and only the counts remain.  Excluded scans (failure /
    not completed) are built from the head alone - their blob is never read.
    """

    scan_id: int
    title: str
    status: str  # raw DB status
    created_at: datetime  # tz-aware UTC
    last_updated: datetime  # tz-aware UTC
    source_key: str
    source_label: str
    source_kind: str  # SOURCE_*
    # sanitised (no userinfo / .git / trailing slash); None for zip / file sources
    repo_url: str | None = None
    branch: str | None = None
    exclusion: str | None = None  # None => included; else one of EXCLUDED_*
    is_current: bool = False  # newest included scan of its source (plan 4.5)
    tier: str = TIER_NONE  # TIER_*
    fidelity: str = FIDELITY_NONE  # FIDELITY_*
    fidelity_reasons: tuple[str, ...] = ()  # subset of FIDELITY_REASONS, in that order
    asset_count: int = 0  # number of results[] rows
    cert_count: int = 0  # number of certificate components in cbom_json
    lib_count: int = 0  # number of library components in cbom_json
    # --- single-scan observations (emptied in TeamCbomView.scans) ---
    assets: list[AssetAgg] = field(default_factory=list)
    certs: list[CertAgg] = field(default_factory=list)
    libs: list[LibAgg] = field(default_factory=list)
    # per-framework verdict counts of this scan (sources_pooled == 1)
    frameworks: dict[str, FrameworkPool] = field(default_factory=dict)
    # one entry per requirement, a single source in ``verdicts``
    requirements: list[RequirementAgg] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)  # skipped rows, coerced types, ...

    @property
    def included(self) -> bool:
        return self.exclusion is None


# ---------------------------------------------------------------------------------------------
# Aggregates (single-scan observations during extraction, roll-ups in the final view)
# ---------------------------------------------------------------------------------------------
@dataclass
class SourceAgg:
    """One scanned source (repo + branch, zip upload, uploaded CBOM file).  Plan 4.3 / 4.5.

    Only sources with at least one INCLUDED scan appear in ``TeamCbomView.sources``.  The
    "most recent attempt failed ... figures reflect scan #m" note is rendered when
    ``last_attempt_scan_id != current_scan_id`` and ``last_attempt_status`` is not success.
    """

    # e.g. "repo:github.com/e2e-demo/payments-service@main", "zip:cert-lifecycle-lab"
    key: str
    # e.g. "github.com/e2e-demo/payments-service (main)", "Zip upload: cert-lifecycle-lab"
    label: str
    kind: str  # SOURCE_*
    repo_url: str | None  # sanitised
    branch: str | None
    scan_ids: tuple[int, ...]  # included scans, newest first
    scan_count: int
    first_scanned: datetime
    last_scanned: datetime  # created_at of the current scan
    current_scan_id: int
    current_tier: str
    current_fidelity: str
    last_attempt_scan_id: int  # newest scan of this source regardless of status (heads only)
    last_attempt_status: str  # raw DB status of that scan
    last_attempt_at: datetime
    asset_counts: dict[str, int] = field(default_factory=dict)  # current, by ASSET_*
    impact_counts: dict[str, int] = field(default_factory=dict)  # current, by IMPACT_LEVELS
    library_count: int = 0  # current library components


@dataclass
class AssetAgg:
    """One crypto asset occurrence: a ``results[]`` row of one source.

    Identity is ``(source_key, asset_type, ident)``.  Every ``results[]`` row is an AssetAgg -
    including certificate rows (they ALSO feed the global ``CertAgg`` register).  Assets are
    never merged across sources: each source's usage is a distinct exposure (plan 4.4), so
    Appendix B's "68 current asset occurrences" is a plain count.  Attribute values come from
    the newest scan that contains the asset.  Values the row stores as text (``key_size`` is
    "1024") stay text; ``None`` means "not recorded" (legacy tiers).  Derive weakness from
    ``finding_codes`` / ``impact`` - never from the row's ``weak`` or ``crypto_strength`` (they
    ignore certificate findings, plan F-04).
    """

    source_key: str
    source_label: str
    asset_type: str  # ASSET_*
    ident: str  # bom_ref if present else slug(title) + "#" + location
    title: str  # results[].title, e.g. "RSA-1024", "cert.pem", "TLS 1.0"
    location: str  # repo-relative path
    impact: str  # IMPACT_LEVELS member (unknown values kept verbatim, rank last)
    finding_codes: tuple[str, ...] = ()
    bom_ref: str | None = None
    description: str = ""  # raw finding text; renderers must pass it through ``pdf_text``
    primitive: str | None = None
    key_size: str | None = None
    curve: str | None = None
    mode: str | None = None
    protocol_version: str | None = None
    material_kind: str | None = None
    parameter_set: str | None = None
    not_valid_after: str | None = None  # certificate rows only (ISO "YYYY-MM-DDThh:mm:ssZ")
    security_strength_bits: int | None = None
    risk_score: float | None = None  # absent on legacy tiers
    # --- quantum posture (algorithm rows).  quantum_vulnerable None => not gradeable (Tier C) ---
    quantum_vulnerable: bool | None = None
    quantum_safe: bool | None = None  # legacy-compatible tri-state mirror of the above
    hybrid: bool | None = None
    nist_quantum_security_level: int | None = None
    # target family, e.g. "ML-KEM (FIPS 203) / ML-DSA (FIPS 204)"
    pqc_migration_target: str | None = None
    pqc_migration_roadmap: str | None = None  # sized target; None on legacy tiers
    # --- provenance ---
    tier: str = TIER_NONE  # tier of the newest scan containing it
    current: bool = False  # present in its source's current scan
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    scan_count: int = 0
    scan_ids: tuple[int, ...] = ()  # newest MAX_SCAN_IDS
    latest_scan_id: int | None = None


@dataclass
class CertAgg:
    """One UNIQUE certificate across the whole team (``cert_key``): one row, many locations.

    Facts come from the ``crypto:*`` properties of the ``cbom_json`` certificate component (the
    lossy ``results[]`` row lacks issuer / subject / notBefore / public-key algorithm / CA flag),
    joined to the matching ``results[]`` row for ``impact`` / ``finding_codes``.  ``self_signed``
    and ``is_ca`` are tri-state: ``None`` means the property was absent (unknown), NOT false.
    """

    key: str  # cert_identity_key(...)[0]
    identity_strong: bool  # False => fell back to "name:<basename>|<source_key>" (Tier C)
    name: str  # certificate file basename in the newest scan
    file_names: tuple[str, ...] = ()  # every distinct basename seen, newest first
    subject_cn: str | None = None
    issuer_cn: str | None = None
    not_before: str | None = None  # ISO "YYYY-MM-DDThh:mm:ssZ"
    not_after: str | None = None
    public_key_algorithm: str | None = None  # crypto:publicKeyAlgorithm (properties[] only)
    key_size: str | None = None
    curve: str | None = None
    signature_algorithm: str | None = None
    self_signed: bool | None = None
    is_ca: bool | None = None
    # file names of issuer certs via cbom_graph "signed_by" edges (empty on legacy tiers)
    signed_by: tuple[str, ...] = ()
    # band vs ``TeamCbomView.as_of`` (the register's expiry column; plan F-03).  Filled by
    # ``fold_scans`` - ``extract_scan_facts`` has no clock, so a per-scan CertAgg holds UNKNOWN.
    expiry: ExpiryBand = field(default_factory=lambda: ExpiryBand(UNKNOWN, None))
    scan_time_expired: bool | None = None  # results[].expired at scan time (None on legacy tiers)
    impact: str = "Low"
    # WEAK_CERTIFICATE_KEY / WEAK_CERTIFICATE_SIGNATURE / SELF_SIGNED_LEAF / EXPIRED_CERTIFICATE
    finding_codes: tuple[str, ...] = ()
    tier: str = TIER_NONE
    source_keys: tuple[str, ...] = ()  # sources where seen in ANY included scan
    current_source_keys: tuple[str, ...] = ()  # subset where it is in the source's current scan
    # distinct (source_label, path), newest first, at most MAX_LOCATIONS
    locations: tuple[tuple[str, str], ...] = ()
    locations_total: int = 0
    current: bool = False  # in the current scan of >= 1 source
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    scan_count: int = 0  # distinct scans containing it
    scan_ids: tuple[int, ...] = ()  # newest MAX_SCAN_IDS
    latest_scan_id: int | None = None


@dataclass
class LibAgg:
    """One crypto library (``cbom_json`` component ``type: library``); identity ``casefold(name)``.

    The engine records only the name and ``discovery:source`` - no version / licence / vendor -
    so there is no version field (the deliverables render those columns as MANUAL).
    """

    key: str  # name.casefold()
    name: str  # display name from the newest scan, e.g. "pyca/cryptography"
    source_keys: tuple[str, ...] = ()  # sources where seen in ANY included scan
    source_labels: tuple[str, ...] = ()  # parallel to ``source_keys``
    current_source_keys: tuple[str, ...] = ()  # subset where it is in the source's current scan
    discovered_in: tuple[str, ...] = ()  # distinct discovery:source paths, <= MAX_LOCATIONS
    discovered_in_total: int = 0
    current: bool = False
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    scan_count: int = 0
    scan_ids: tuple[int, ...] = ()
    latest_scan_id: int | None = None


@dataclass
class RequirementAgg:
    """One compliance requirement ``(framework, req_id)`` rolled up across sources (plan 4.5).

    Only CURRENT, FULL-fidelity scans contribute.  ``verdicts`` maps source_key -> that source's
    verdict.  ``verdict`` is the roll-up by ``VERDICT_PRECEDENCE``.  A source is "attestable"
    when its verdict is ``not_bom_evidenceable`` or ``pass_with_evidence`` and "attested" when it
    is ``pass_with_evidence`` (the attestation upload route recomputes compliance, so the flipped
    verdict is persisted in the scan's ``cbom_compliance``).  The latest-attestation fields come
    from ``scan_data.attestations[framework][req_id]`` (``filename`` / ``note`` /
    ``uploaded_at``), maximised over ``uploaded_at`` across sources.
    """

    framework: str
    req_id: str
    title: str = ""
    citation: str = ""  # the requirement's "source", e.g. "Table 9 / Algorithms / Name"
    verdict: str = VERDICT_NA
    verdicts: dict[str, str] = field(default_factory=dict)
    attestable_sources: int = 0  # n
    attested_sources: int = 0  # k  ("Attested k/n")
    latest_attestation_file: str | None = None
    latest_attestation_note: str | None = None
    latest_attestation_at: str | None = None  # "YYYY-MM-DDThh:mm:ssZ" as stored


@dataclass
class FrameworkPool:
    """Pooled verdict counts of one framework over the current full-fidelity scans (plan 4.5).

    ``coverage = (passed + passed_with_evidence) / (passed + passed_with_evidence + failed)``
    rounded to 3 dp, ``None`` when the denominator is 0 (engine rule; AGENTS "Coverage% =
    pass/(pass+fail)").  An arithmetic roll-up of existing verdict counts - not a new scoring
    algorithm.  In ``ScanFacts.frameworks`` the same type carries one scan
    (``sources_pooled == 1``).
    """

    framework: str  # key in CBOM_FRAMEWORKS, e.g. "cert_in_cbom"
    passed: int = 0  # blob key "pass"
    passed_with_evidence: int = 0
    failed: int = 0  # blob key "fail"
    out_of_scope: int = 0
    not_bom_evidenceable: int = 0
    na: int = 0
    coverage: float | None = None
    sources_pooled: int = 0
    legacy_excluded: int = 0  # current sources left out because their scan is reduced-fidelity


# ---------------------------------------------------------------------------------------------
# The view
# ---------------------------------------------------------------------------------------------
@dataclass
class TeamCbomView:
    """Everything a deliverable renderer may read.  Built by ``fold_scans``; read-only to them.

    Defaults describe an EMPTY team, so tests can build a minimal view from the four identity
    fields.  Ordering contracts (PDFs are byte-stable for the same data): ``sources`` by
    ``(label.casefold(), key)``; ``assets`` by ``(source_key, asset_type, ident)``; ``certs`` and
    ``libs`` by ``key``; ``frameworks`` in ``CBOM_FRAMEWORKS`` order; ``requirements`` by
    ``(framework, req_id)``; ``scans`` by ``(created_at, id)`` descending.  A renderer needing
    another order sorts explicitly.
    """

    team_id: int
    team_name: str
    generated_at: datetime  # == the injected ``now`` (tz-aware UTC)
    as_of: date  # generated_at's UTC date; every expiry band is computed against it
    # --- basis (printed in every document's Basis box, plan 5.4) -------------------------------
    scans_total: int = 0  # every cbom scan of the team seen in the heads
    eligible: int = 0  # status == success
    included: int = 0  # folded and data-bearing
    # keys EXCLUDED_FAILURE / EXCLUDED_NOT_COMPLETED / EXCLUDED_NO_DATA
    excluded: dict[str, int] = field(
        default_factory=lambda: {
            EXCLUDED_FAILURE: 0,
            EXCLUDED_NOT_COMPLETED: 0,
            EXCLUDED_NO_DATA: 0,
        }
    )
    # older eligible scans NOT folded (first-seen may be later than actual);
    # invariant: eligible == included + excluded[EXCLUDED_NO_DATA] + history_truncated
    history_truncated: int = 0
    fidelity_full: int = 0  # included scans in full fidelity
    fidelity_reduced: int = 0  # included scans in legacy (reduced) fidelity
    window_start: datetime | None = None  # oldest included scan created_at
    window_end: datetime | None = None  # newest included scan created_at
    fingerprint: str = ""  # 12 hex chars - formula in ``fold_scans``
    # --- entities -------------------------------------------------------------------------------
    scans: tuple[ScanFacts, ...] = ()  # slim facts of included + excluded scans (no blobs)
    sources: tuple[SourceAgg, ...] = ()
    assets: tuple[AssetAgg, ...] = ()  # includes ``current=False`` ("previously seen") entries
    certs: tuple[CertAgg, ...] = ()
    libs: tuple[LibAgg, ...] = ()
    frameworks: tuple[FrameworkPool, ...] = ()
    requirements: tuple[RequirementAgg, ...] = ()
    # --- headline counts: CURRENT state only, computed once so all six documents agree ----------
    # current ``assets`` rows (Appendix B: 68); NOT de-duplicated across sources
    asset_occurrences: int = 0
    assets_by_type: dict[str, int] = field(default_factory=dict)  # current, by ASSET_*
    assets_by_impact: dict[str, int] = field(default_factory=dict)  # current, by IMPACT_LEVELS
    # current assets with >= 1 finding code, by impact (D-03 grade input; Appendix B: C1 H23 M5)
    issue_by_impact: dict[str, int] = field(default_factory=dict)
    finding_counts: dict[str, int] = field(default_factory=dict)  # current occurrences per code
    pqc_vulnerable: int = 0  # current algorithm rows with quantum_vulnerable is True
    pqc_safe: int = 0  # current algorithm rows with quantum_vulnerable is False (hybrid included)
    pqc_hybrid: int = 0  # subset of pqc_safe flagged hybrid
    pqc_ungraded: int = 0  # quantum_vulnerable is None (left out of the readiness denominator)
    readiness_pct: float | None = None  # round(100 * safe / (safe + vulnerable), 1); None if 0
    compliance_sources_pooled: int = 0  # current full-fidelity sources (Appendix B: 6)
    compliance_legacy_excluded: int = 0  # current reduced-fidelity sources left out (Appendix B: 1)
    warnings: tuple[str, ...] = ()  # skipped / coerced inputs; capped (renderers may print count)

    @property
    def is_empty(self) -> bool:
        """No data-bearing scan at all => banner "NO COMPLETED CBOM SCANS", never a grade."""
        return self.included == 0

    @property
    def fidelity_summary(self) -> str:
        """``X-Cbom-Fidelity`` header value: ``full`` | ``mixed`` | ``reduced`` | ``none``."""
        if self.included == 0:
            return "none"
        if self.fidelity_reduced == 0:
            return "full"
        if self.fidelity_full == 0:
            return "reduced"
        return "mixed"


# ---------------------------------------------------------------------------------------------
# Function stubs - bodies are WP1b.  Signatures are plan 5.2 verbatim (annotations added).
# ---------------------------------------------------------------------------------------------
def _wp1b(name: str) -> NotImplementedError:
    return NotImplementedError(f"{name}: WP1a interface freeze - implemented by WP1b")


def sanitize_repo_url(url: str | None) -> str | None:
    """Canonical, credential-free repository URL, or ``None`` for empty / unparseable input.

    Drops userinfo (``user:token@``), query and fragment, a trailing ``/`` and a ``.git``
    suffix; lower-cases scheme and host; keeps the path's case.  Total: never raises.
    """
    raise _wp1b("sanitize_repo_url")


def source_key_for(
    meta: Mapping[str, Any] | None, title: str, scan_id: int
) -> tuple[str, str, str]:
    """``(key, label, kind)`` per plan 4.3.  Total: ``meta`` may be ``None`` / hold wrong types.

    ``repo_url`` -> ``repo:{host}{path}@{branch or 'default'}`` (whole key lower-cased, userinfo
    / ``.git`` / trailing ``/`` stripped), label ``{host}{path} ({branch})``; else
    ``zip_file_used`` -> ``zip:{slug(title)}`` / ``Zip upload: {title}``; else ``cbom_file_used``
    -> ``file:{slug(title)}`` / ``Uploaded CBOM: {title}``; else ``scan:{scan_id}`` /
    ``Scan #{scan_id}``.
    """
    raise _wp1b("source_key_for")


def cert_identity_key(
    props: Mapping[str, str], *, fallback_name: str, source_key: str
) -> tuple[str, bool]:
    """``(key, strong)`` for a certificate component's ``crypto:*`` properties (plan 4.4).

    Strong key = ``sha256("\\x1f".join([casefold(strip(subjectCN)), casefold(strip(issuerCN)),
    notBefore, notAfter, casefold(sigAlg), casefold(pubKeyAlg), str(keySize),
    casefold(curve)])).hexdigest()[:16]`` with a missing part as ``""``.  If
    ``crypto:subjectName`` or ``crypto:notValidAfter`` is missing, the key falls back to
    ``"name:" + fallback_name + "|" + source_key`` and ``strong`` is ``False``.
    """
    raise _wp1b("cert_identity_key")


def classify_expiry(not_after_iso: str | None, as_of: date) -> ExpiryBand:
    """Validity band of a certificate as of ``as_of`` (date arithmetic on ``not_after_iso[:10]``).

    ``days_left = (notAfter date - as_of).days``: ``< 0`` -> EXPIRED, ``<= 30`` -> LE_30,
    ``<= NEAR_EXPIRY_DAYS`` -> LE_90, else VALID; a missing / unparseable value -> UNKNOWN with
    ``days_left=None``.  Same "strictly before today" rule as aibom ``cert_expiry_finding``.
    """
    raise _wp1b("classify_expiry")


def extract_scan_facts(head: ScanHead, scan_data: Any) -> ScanFacts:
    """Tier-tolerant, TOTAL extraction of one scan's facts (plan 3.1 / 3.2 / 4.6).  Never raises.

    Reads ``results`` / ``cbom_json`` / ``cbom_distributions`` / ``cbom_compliance`` /
    ``cbom_graph`` / ``attestations`` defensively (``isinstance`` everywhere); a bad row is
    skipped and recorded in ``ScanFacts.warnings``.  A success scan whose ``scan_data`` is not a
    dict, or has neither a list ``results`` nor a dict ``cbom_json``, gets
    ``exclusion=EXCLUDED_NO_DATA``.  A valid but empty scan (``results == []`` with a
    ``cbom_json``) is INCLUDED.  Tier-C rows derive ``asset_type`` from ``algorithm_type``
    (certificate / key -> related-crypto-material / protocol / else algorithm).  Never prints or
    copies ``cbom_compliance["disclaimer"]`` or ``cbom_json.metadata`` (AIBOM text, plan F-05).
    """
    raise _wp1b("extract_scan_facts")


def fold_scans(
    heads: Sequence[ScanHead],
    load_blobs: Callable[[Sequence[int]], Mapping[int, Any]],
    *,
    team_id: int,
    team_name: str,
    now: datetime,
    history_window: int = HISTORY_WINDOW,
    hard_max: int = HARD_MAX_SCANS,
    batch_size: int = BATCH_SIZE,
) -> TeamCbomView:
    """Fold scan heads + streamed blobs into a ``TeamCbomView``.  PURE (no DB, clock or I/O).

    ``load_blobs(ids)`` returns ``{scan_id: scan_data}``; a missing id means ``scan_data=None``
    (-> ``no_data``).  It is called with at most ``batch_size`` ids and ONLY for eligible scans
    of ``team_id`` with ``scan_type == 'cbom'`` and status ``success`` (anything else is never
    loaded).  Selection, source identity, dedupe keys, latest-scan-wins, the failed-latest rule,
    compliance pooling, requirement roll-up, caps and degradation follow plan 4.1-4.6 exactly.

    ``view.fingerprint`` = ``sha256((FINGERPRINT_NAMESPACE + "|" + ",".join(
    f"{scan_id}:{last_updated.isoformat()}" for each INCLUDED scan sorted by scan_id)
    ).encode("utf-8")).hexdigest()[:12]`` (``last_updated`` tz-aware UTC).  The same scan set
    gives the same fingerprint; a re-scan or an attestation upload moves ``last_updated`` and
    therefore the fingerprint.  Every date derives from ``now``.
    """
    raise _wp1b("fold_scans")


def load_team_cbom_view(engine: Any, team_id: int, *, now: datetime | None = None) -> TeamCbomView:
    """Load a team's CBOM scans and fold them.  The ONLY DB-touching function (plan 4.2 / 5.2).

    Pass 1 selects ``Scan`` heads (no ``scan_data``) for ``team_id`` and ``scan_type == 'cbom'``
    ordered by ``(created_at DESC, id DESC)`` and attaches ``timezone.utc`` to naive datetimes;
    pass 2 streams ``scan_data`` for the chosen ids in batches via ``fold_scans``.  Imports
    ``sqlmodel`` / ``backend.new_models`` INSIDE this function.  ``now=None`` means the current
    UTC time - the only clock read this module may make.
    """
    raise _wp1b("load_team_cbom_view")


__all__ = [
    "ASSET_ALGORITHM",
    "ASSET_CERTIFICATE",
    "ASSET_MATERIAL",
    "ASSET_OTHER",
    "ASSET_PROTOCOL",
    "ASSET_TYPES",
    "BATCH_SIZE",
    "EXCLUDED_FAILURE",
    "EXCLUDED_NOT_COMPLETED",
    "EXCLUDED_NO_DATA",
    "EXPIRED",
    "EXPIRY_BANDS",
    "FIDELITY_FULL",
    "FIDELITY_NONE",
    "FIDELITY_REASONS",
    "FIDELITY_REDUCED",
    "FINGERPRINT_NAMESPACE",
    "HARD_MAX_SCANS",
    "HISTORY_WINDOW",
    "IMPACT_LEVELS",
    "LE_30",
    "LE_90",
    "MAX_LOCATIONS",
    "MAX_SCAN_IDS",
    "NEAR_EXPIRY_DAYS",
    "NOT_COMPLETED_STATUSES",
    "SOURCE_FILE",
    "SOURCE_REPO",
    "SOURCE_SCAN",
    "SOURCE_ZIP",
    "STATUS_FAILURE",
    "STATUS_SUCCESS",
    "TIER_A",
    "TIER_B",
    "TIER_C",
    "TIER_NONE",
    "UNKNOWN",
    "VALID",
    "VERDICT_FAIL",
    "VERDICT_NA",
    "VERDICT_NOT_BOM_EVIDENCEABLE",
    "VERDICT_OUT_OF_SCOPE",
    "VERDICT_PASS",
    "VERDICT_PASS_WITH_EVIDENCE",
    "VERDICT_PRECEDENCE",
    "AssetAgg",
    "CertAgg",
    "ExpiryBand",
    "FrameworkPool",
    "LibAgg",
    "RequirementAgg",
    "ScanFacts",
    "ScanHead",
    "SourceAgg",
    "TeamCbomView",
    "cert_identity_key",
    "classify_expiry",
    "extract_scan_facts",
    "fold_scans",
    "load_team_cbom_view",
    "sanitize_repo_url",
    "source_key_for",
]
