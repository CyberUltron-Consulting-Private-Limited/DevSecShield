"""Team-wide CBOM roll-up: the aggregation core behind the six regulatory PDF deliverables.

STATUS - WP1b implemented (test-first; ``backend/tests/test_cbom_team_rollup.py``).  WP10 appends
``ScanFacts.posture`` and ``TeamCbomView.posture`` with empty defaults.  Existing field order,
function signatures, the fingerprint formula, ``HISTORY_WINDOW``, ``HARD_MAX_SCANS`` and
``BATCH_SIZE`` are unchanged.

Conventions the bodies guarantee (renderers may rely on them):

* Count dictionaries (``assets_by_type``, ``assets_by_impact``, ``issue_by_impact``,
  ``finding_counts``, ``SourceAgg.asset_counts`` / ``impact_counts``) are SPARSE: a bucket with a
  zero count is absent, so read them with ``.get(key, 0)``.  Keys come in canonical order
  (``ASSET_TYPES`` / ``IMPACT_LEVELS``, unknown values last, sorted).
* The fold is ORDER-INDEPENDENT: the same set of scans gives an equal view whatever the order of
  ``heads`` or the ``batch_size``.  "Newest" always means the larger ``(created_at, scan_id)``.
* An entity's attributes come from the newest scan containing it; ``first_seen`` / ``last_seen`` /
  ``scan_count`` are over every folded scan.  Two exceptions, both for facts that cannot change
  for the same certificate: ``CertAgg.is_ca`` / ``self_signed`` fall back to the newest KNOWN
  value, and ``CertAgg.signed_by`` is the union of issuer files seen in the current scans (all
  scans when the certificate is not current anywhere).
* ``ScanFacts.warnings`` and ``TeamCbomView.warnings`` never echo scanned text, only indexes and
  framework keys, so they are safe to print.

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

import contextlib
import hashlib
import json
import math
import re
from collections import Counter, deque
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from datetime import date, datetime, timezone
from typing import Any
from urllib.parse import urlsplit

# ---------------------------------------------------------------------------------------------
# Plan 5.2 constants (caps are decision D-04)
# ---------------------------------------------------------------------------------------------
HISTORY_WINDOW = 200  # newest eligible scans folded for first/last-seen history
HARD_MAX_SCANS = 1000  # absolute ceiling, even while chasing every source's latest scan
BATCH_SIZE = 20  # blobs loaded per ``load_blobs`` call
MAX_POSTURE_ACCS = 100_000  # distinct (source, fact) posture rows kept per team
POSTURE_REGISTER_CAP = 2_000  # rows kept per posture register; the excess is ``omitted``
POSTURE_SCHEMA = 1  # highest cbom_posture schema_version this roll-up understands
POSTURE_DIAGNOSTIC_CAP = 50
POSTURE_CLASSIFICATION_CAP = 50
NEAR_EXPIRY_DAYS = 90  # mirrors aibom weakness._NEAR_EXPIRY_DAYS (weakness.py:38)

# Per-entity list caps (plan 4.5: "newest 12 (+N more)").  ``scan_count`` / ``*_total`` keep the
# true numbers so a renderer can print "+N more".
MAX_SCAN_IDS = 12
MAX_LOCATIONS = 12

# Digest namespace of ``TeamCbomView.fingerprint``.  Plan 4.8 writes ``sha256(slug + '|' + ...)``
# but ``fold_scans`` (and ``document_id(view, number)``) carry no per-document slug, so the view
# uses this constant; the per-document part of a Document ID is its ``D{nn}`` number.  The text
# hashed after the namespace also covers the attestation records (addendum A-2): see ``fold_scans``.
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
# A clean inventory row (``cbom_rows.is_finding`` is False: an empty finding-code list, not weak, not
# quantum-vulnerable) has no impact: it is listed under INFO and never counted as an issue, in old scans (stored "Low")
# and new ones (None) alike, as on the scan dashboard and PDF.  A legacy row stored before ``finding_codes`` existed
# is a finding with its stored impact (Low when it has none), counted as an issue exactly as the scan dashboard, the
# scan list and the scan PDF count it (``cbom_metrics.finding_severity``).
INFO = "Info"

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
    # None until a blob is read.  Absent / malformed blocks stay Not_Assessed (never a zero pass).
    posture: PostureScan | None = None

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
    impact: str = INFO  # INFO until a results[] row with a finding says otherwise
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
# Configuration posture (WP10).  Additive: every new field on the frozen types has a default.
# ---------------------------------------------------------------------------------------------
_AT_REST_LAYERS = ("application", "database", "volume", "service", "backup")
_TRANSPORT_KINDS = frozenset({"tls_endpoint", "ssh_service"})
_NO_TRI_KINDS = frozenset({"kms_key", "certificate_policy"})
_PASS_VERDICTS = frozenset({"ENCRYPTED_DECLARED", "ENCRYPTED_PROVIDER_DEFAULT"})
_POSTURE_CODE_SEVERITY = {
    "UNENCRYPTED_AT_REST": "High",
    "UNENCRYPTED_IN_TRANSIT": "High",
    "PLAINTEXT_LISTENER": "Medium",
    "TLS_VERIFICATION_DISABLED": "High",
    "DOWNGRADE_PROTECTION_MISSING": "Medium",
    "KNOWN_TLS_VULNERABILITY": "High",
    "KMS_KEY_ROTATION_DISABLED": "Medium",
    "KMS_KEY_POLICY_PUBLIC": "High",
    "KMS_KEY_DELETION_UNPROTECTED": "Low",
    "AT_REST_ENCRYPTION_WEAK": "Medium",
    "PROVIDER_MANAGED_KEY": "Low",  # the engine's "note": the data is encrypted, the key is the provider's
    "EOL_BASE_IMAGE": "Medium",
}
_TLS_RANK = {
    "sslv3": 0,
    "ssl3": 0,
    "1.0": 1,
    "tls1.0": 1,
    "tlsv1.0": 1,
    "1.1": 2,
    "tls1.1": 2,
    "tlsv1.1": 2,
    "1.2": 3,
    "tls1.2": 3,
    "tlsv1.2": 3,
    "1.3": 4,
    "tls1.3": 4,
    "tlsv1.3": 4,
}
_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_SEVERITY_LEVELS = ("High", "Medium", "Low")


def _zero_severity() -> dict[str, int]:
    return {level: 0 for level in _SEVERITY_LEVELS}


def _zero_impact() -> dict[str, int]:
    return {level: 0 for level in IMPACT_LEVELS}


def _zero_tri() -> dict[str, TriState]:
    return {"at_rest": TriState(), "transport": TriState()}


@dataclass
class TriState:
    """One axis of the configuration tri-state.  ``coverage`` is None when nothing was judged."""

    pass_: int = 0
    fail: int = 0
    not_bom_evidenceable: int = 0
    out_of_scope: int = 0
    coverage: float | None = None


@dataclass
class KmsCounts:
    keys: int = 0
    rotation_enabled: int = 0
    rotation_disabled: int = 0
    rotation_not_applicable: int = 0
    rotation_unknown: int = 0


@dataclass
class PostureCounts:
    """Headline posture counts from current facts of assessed sources.  ``zero()`` is empty."""

    facts: int = 0
    by_kind_provider_verdict: dict[tuple[str, str, str], int] = field(default_factory=dict)
    tri_state: dict[str, TriState] = field(default_factory=_zero_tri)
    findings_by_code: dict[str, int] = field(default_factory=dict)
    findings_by_severity: dict[str, int] = field(default_factory=_zero_severity)
    facts_with_findings_by_impact: dict[str, int] = field(default_factory=_zero_impact)
    kms: KmsCounts = field(default_factory=KmsCounts)
    by_classification: dict[str, int] = field(default_factory=dict)
    declared_resources: dict[tuple[str, str], int] = field(default_factory=dict)
    out_of_scope_resources: int = 0
    disabled_resources: int = 0

    @classmethod
    def zero(cls) -> PostureCounts:
        return cls()


@dataclass
class PostureScan:
    """Posture block of one scan.  Heavy lists are cleared once the fold has merged them."""

    state: str = "absent"  # assessed|partial|absent|malformed|failed|newer_engine
    schema_version: int | None = None
    lanes: tuple[str, ...] = ()
    failed_lanes: tuple[str, ...] = ()
    facts: list[dict[str, Any]] = field(default_factory=list)
    imports: list[dict[str, Any]] = field(default_factory=list)
    diagnostics: list[dict[str, Any]] = field(default_factory=list)
    diagnostic_totals: dict[str, int] = field(default_factory=dict)
    data_tables: list[dict[str, str]] = field(default_factory=list)
    counts: dict[str, Any] = field(default_factory=dict)
    truncated: bool = False
    dropped: dict[str, int] = field(default_factory=dict)


@dataclass
class PostureFactAgg:
    """One fact of one source.  ``fact`` is compact when the fact is not current."""

    source_key: str
    fact_id: str
    current: bool
    first_seen: datetime
    last_seen: datetime
    scan_count: int
    last_scan_id: int
    fact: Mapping[str, Any]
    paired_with: str | None = None
    discrepancy: bool = False


@dataclass
class PostureSourceAgg:
    """One row of the per-source posture status table."""

    key: str
    label: str
    state: str  # assessed|partial|not_assessed|newer_engine|malformed
    reason: str | None
    current_scan_id: int
    last_scanned: datetime
    zero_facts: bool
    truncated: bool
    dropped: int
    lanes: tuple[str, ...]
    failed_lanes: tuple[str, ...]


@dataclass
class PostureView:
    """Team posture.  Exactly one field has a default, and it is the last."""

    state: str  # none|assessed|mixed|not_assessed
    sources: tuple[PostureSourceAgg, ...]
    facts: tuple[PostureFactAgg, ...]
    previously_seen: tuple[PostureFactAgg, ...]
    previously_seen_total: int
    imports: tuple[Mapping[str, Any], ...]
    diagnostic_totals: dict[str, int]
    diagnostics: tuple[Mapping[str, Any], ...]
    data_tables: tuple[Mapping[str, str], ...]
    counts: PostureCounts
    omitted: dict[str, int]
    warnings: tuple[str, ...]
    previously_seen_exact: bool = True

    @classmethod
    def empty(cls) -> PostureView:
        return cls(
            state="none",
            sources=(),
            facts=(),
            previously_seen=(),
            previously_seen_total=0,
            imports=(),
            diagnostic_totals={},
            diagnostics=(),
            data_tables=(),
            counts=PostureCounts.zero(),
            omitted={},
            warnings=(),
        )


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
    # current FINDINGS (cbom_rows.is_finding: impact != INFO), by impact (D-03 grade input; Appendix B: C1 H25 M5 L5)
    issue_by_impact: dict[str, int] = field(default_factory=dict)
    finding_counts: dict[str, int] = field(default_factory=dict)  # current occurrences per code
    # quantum verdicts are cbom_metrics.code_row_quantum_vulnerable (the stored quantum_safe tri-state): the current
    # engine grades algorithms only; a legacy worker row may also grade a certificate or key
    pqc_vulnerable: int = 0  # current assets with quantum_vulnerable is True
    pqc_safe: int = 0  # current assets with quantum_vulnerable is False (hybrid included)
    pqc_hybrid: int = 0  # subset of pqc_safe flagged hybrid
    pqc_ungraded: int = 0  # current ALGORITHM assets without a verdict (left out of the readiness denominator)
    readiness_pct: float | None = None  # round(100 * safe / (safe + vulnerable), 1); None if 0
    compliance_sources_pooled: int = 0  # current full-fidelity sources (Appendix B: 6)
    compliance_legacy_excluded: int = 0  # current reduced-fidelity sources left out (Appendix B: 1)
    warnings: tuple[str, ...] = ()  # skipped / coerced inputs; capped (renderers may print count)
    posture: PostureView = field(default_factory=PostureView.empty)
    # the team's remediation plan (``cbom_sources.waves.roadmap_extras``: assignments by stable key and the
    # quantum-vulnerable assets of each collection source's latest complete run); None = not loaded (hand-made views)
    # Not part of the fold: excluded from equality and repr (a DB-loaded view equals the in-memory fold of its scans).
    remediation: dict[str, Any] | None = field(default=None, compare=False, repr=False)

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
# Private constants and total (never-raising) value coercers
# ---------------------------------------------------------------------------------------------
_UTC = timezone.utc
_EPOCH = datetime(1970, 1, 1, tzinfo=_UTC)
_MAX_WARNINGS = 100

# ``aibom.cbom.compliance.CBOM_FRAMEWORKS`` order.  The backend cannot import ``aibom``, so the
# keys are mirrored here; ``test_cbom_team_rollup`` pins them to the generated registry fixture.
_FRAMEWORK_ORDER = (
    "nist_1800_38b",
    "nist_800_57",
    "omb_m_23_02",
    "eu_cra",
    "eu_dora",
    "pci_dss_4",
    "fips_140_3",
    "bsi_tr_02102",
    "nist_1800_38c",
    "cnsa_2_0",
    "rbi_free_ai_protection",
    "cert_in_cbom",
    "sebi_cscrf_cbom",
)
_FRAMEWORK_RANK = {key: index for index, key in enumerate(_FRAMEWORK_ORDER)}
_VERDICT_RANK = {verdict: index for index, verdict in enumerate(VERDICT_PRECEDENCE)}
_IMPACT_BY_FOLD = {level.casefold(): level for level in IMPACT_LEVELS}
_LEGACY_ASSET_TYPE = {  # pre-reconcile ``algorithm_type`` -> CycloneDX assetType (plan 3.1)
    "certificate": ASSET_CERTIFICATE,
    "key": ASSET_MATERIAL,
    "protocol": ASSET_PROTOCOL,
}
# Current-engine rows that have no CycloneDX crypto ``assetType`` by design: a crypto library with a
# finding (advisory, CVE range, end of life) and a declared configuration fact (posture lanes).  They
# are typed rows, not pre-reconcile output, and they are not algorithms (never in quantum readiness).
_UNTYPED_BY_DESIGN = frozenset({"library", "configuration"})
_REPO_SCHEMES = frozenset({"http", "https", "ssh", "git"})
_DEFAULT_PORTS = {"http": 80, "https": 443, "ssh": 22, "git": 9418}
_SCP_RE = re.compile(r"^[\w.-]+@([\w.-]+):(?!//)(.+)$")  # git@host:org/repo.git
_BARE_URL_RE = re.compile(r"^[A-Za-z0-9.-]+(:\d{1,5})?/.+$")  # host/org/repo (no scheme)
_CONTROL_OR_SPACE_RE = re.compile(r"[\x00-\x20\x7f]")
_SLUG_RE = re.compile(r"[^a-z0-9]+")
_INT_RE = re.compile(r"[+-]?\d+")
_SAFE_KEY_RE = re.compile(r"[A-Za-z0-9_.-]{1,40}")  # a framework key that may appear in a warning


def _utc(moment: Any) -> datetime | None:
    """Timezone-aware UTC copy of a datetime (naive values are taken as UTC), else ``None``."""
    if not isinstance(moment, datetime):
        return None
    if moment.tzinfo is None or moment.utcoffset() is None:
        return moment.replace(tzinfo=_UTC)
    return moment.astimezone(_UTC)


def _text(value: Any) -> str | None:
    """Stripped non-empty text; numbers become text; bools, containers and ``None`` are ``None``."""
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, str):
        return value.strip() or None
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float) and math.isfinite(value):
        return str(int(value)) if value.is_integer() else str(value)
    return None


def _int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value) if math.isfinite(value) and value.is_integer() else None
    if isinstance(value, str) and _INT_RE.fullmatch(value.strip()):
        return int(value.strip())
    return None


def _float(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value) if math.isfinite(value) else None


def _tri(value: Any) -> bool | None:
    """Tri-state: ``True`` / ``False`` for bools and 'true'/'false' text, else unknown."""
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        folded = value.strip().casefold()
        if folded in ("true", "yes", "1"):
            return True
        if folded in ("false", "no", "0"):
            return False
    return None


def _slug(text: str) -> str:
    """Lower-case ASCII slug; titles without ASCII letters get a stable hash instead."""
    slug = _SLUG_RE.sub("-", text.lower()).strip("-")
    if slug:
        return slug
    return "t-" + hashlib.sha256(text.casefold().encode("utf-8", "replace")).hexdigest()[:10]


def _props(component: Mapping[str, Any]) -> dict[str, str]:
    """``properties[]`` of a CycloneDX component as ``{name: text}`` (first occurrence wins)."""
    found: dict[str, str] = {}
    entries = component.get("properties")
    if isinstance(entries, list):
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            name, value = entry.get("name"), entry.get("value")
            if isinstance(name, str) and name not in found and isinstance(value, (str, int, float)):
                found[name] = value if isinstance(value, str) else str(value)
    return found


def _coverage(passed: int, passed_with_evidence: int, failed: int) -> float | None:
    """Engine rule: ``(pass + pass_with_evidence) / (pass + pass_with_evidence + fail)``."""
    denominator = passed + passed_with_evidence + failed
    if denominator <= 0:
        return None
    return round((passed + passed_with_evidence) / denominator, 3)


def _ordered_counts(counter: Mapping[str, int], order: Sequence[str]) -> dict[str, int]:
    """Sparse count dict in canonical key order (known keys first, unknown sorted last)."""
    known = [key for key in order if counter.get(key, 0) > 0]
    unknown = sorted(key for key, count in counter.items() if key not in order and count > 0)
    return {key: counter[key] for key in known + unknown}


# ---------------------------------------------------------------------------------------------
# Functions.  Signatures are plan 5.2 verbatim (annotations added); docstrings are the contract.
# ---------------------------------------------------------------------------------------------

def sanitize_repo_url(url: str | None) -> str | None:
    """Canonical, credential-free repository URL, or ``None`` for empty / unparseable input.

    Drops userinfo (``user:token@``), query and fragment, a trailing ``/`` and a ``.git``
    suffix; lower-cases scheme and host; keeps the path's case.  Total: never raises.
    """
    if not isinstance(url, str):
        return None
    text = url.strip()
    if not text or _CONTROL_OR_SPACE_RE.search(text):
        return None
    if "://" not in text:
        scp = _SCP_RE.match(text)
        if scp:
            text = f"ssh://{scp.group(1)}/{scp.group(2)}"
        elif _BARE_URL_RE.match(text):
            text = "https://" + text
        else:
            return None
    try:
        parts = urlsplit(text)
        port = parts.port
    except ValueError:
        return None
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").lower()  # ``hostname`` already excludes any userinfo
    if scheme not in _REPO_SCHEMES or not host:
        return None
    if ":" in host:  # IPv6 literal
        host = f"[{host}]"
    if port is not None and port != _DEFAULT_PORTS.get(scheme):
        host = f"{host}:{port}"
    path = parts.path.rstrip("/")
    if path.lower().endswith(".git"):
        path = path[: -len(".git")].rstrip("/")
    return f"{scheme}://{host}{path}"


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
    data: Mapping[str, Any] = meta if isinstance(meta, Mapping) else {}
    name = (title if isinstance(title, str) else "" if title is None else str(title)).strip()
    repo = sanitize_repo_url(data.get("repo_url"))
    if repo is not None:
        parts = urlsplit(repo)
        where = parts.netloc + parts.path  # credentials were dropped by ``sanitize_repo_url``
        branch = _text(data.get("branch")) or "default"
        return f"repo:{where}@{branch}".lower(), f"{where} ({branch})", SOURCE_REPO
    if _tri(data.get("zip_file_used")) is True:
        return f"zip:{_slug(name)}", f"Zip upload: {name or '(untitled)'}", SOURCE_ZIP
    if _tri(data.get("cbom_file_used")) is True:
        return f"file:{_slug(name)}", f"Uploaded CBOM: {name or '(untitled)'}", SOURCE_FILE
    return f"scan:{scan_id}", f"Scan #{scan_id}", SOURCE_SCAN


def plan_key(asset: AssetAgg) -> str:
    """Key of an asset in ``TeamCbomView.remediation["code_plans"]`` (renderers look plans up with it)."""
    return f"{asset.source_key}\x1f{asset.asset_type}\x1f{asset.ident}"


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

    def pick(name: str) -> str:
        value = props.get(name) if isinstance(props, Mapping) else None
        if value is None:
            return ""
        return value if isinstance(value, str) else str(value)

    subject, not_after = pick("crypto:subjectName"), pick("crypto:notValidAfter")
    if not subject.strip() or not not_after.strip():
        return f"name:{fallback_name}|{source_key}", False
    parts = [
        subject.strip().casefold(),
        pick("crypto:issuerName").strip().casefold(),
        pick("crypto:notValidBefore"),
        not_after,
        pick("crypto:signatureAlgorithm").casefold(),
        pick("crypto:publicKeyAlgorithm").casefold(),
        pick("crypto:keySize"),
        pick("crypto:curve").casefold(),
    ]
    digest = hashlib.sha256("\x1f".join(parts).encode("utf-8", "replace")).hexdigest()
    return digest[:16], True


def classify_expiry(not_after_iso: str | None, as_of: date) -> ExpiryBand:
    """Validity band of a certificate as of ``as_of`` (date arithmetic on ``not_after_iso[:10]``).

    ``days_left = (notAfter date - as_of).days``: ``< 0`` -> EXPIRED, ``<= 30`` -> LE_30,
    ``<= NEAR_EXPIRY_DAYS`` -> LE_90, else VALID; a missing / unparseable value -> UNKNOWN with
    ``days_left=None``.  Same "strictly before today" rule as aibom ``cert_expiry_finding``.
    """
    today = as_of.date() if isinstance(as_of, datetime) else as_of
    if not isinstance(not_after_iso, str) or not isinstance(today, date):
        return ExpiryBand(UNKNOWN, None)
    try:
        expires = date.fromisoformat(not_after_iso.strip()[:10])
    except ValueError:
        return ExpiryBand(UNKNOWN, None)
    days_left = (expires - today).days
    if days_left < 0:
        return ExpiryBand(EXPIRED, days_left)
    if days_left <= 30:
        return ExpiryBand(LE_30, days_left)
    if days_left <= NEAR_EXPIRY_DAYS:
        return ExpiryBand(LE_90, days_left)
    return ExpiryBand(VALID, days_left)


def _status_exclusion(status: Any) -> str | None:
    """``None`` for a successful scan, else the ``EXCLUDED_*`` bucket of any other status."""
    folded = ("" if status is None else str(status)).strip().casefold()
    if folded == STATUS_SUCCESS:
        return None
    return EXCLUDED_FAILURE if folded == STATUS_FAILURE else EXCLUDED_NOT_COMPLETED


def _head_facts(head: ScanHead) -> ScanFacts:
    """Everything that needs no blob: identity, source, dates and the status-based exclusion."""
    warnings: list[str] = []
    created = _utc(getattr(head, "created_at", None))
    if created is None:
        created = _EPOCH
        warnings.append("created_at is not a datetime (treated as 1970-01-01)")
    updated = _utc(getattr(head, "last_updated", None)) or created
    scan_id = _int(getattr(head, "id", None)) or 0
    raw_meta = getattr(head, "scan_metadata", None)
    meta: Mapping[str, Any] = raw_meta if isinstance(raw_meta, Mapping) else {}
    raw_title = getattr(head, "title", None)
    title = ("" if raw_title is None else str(raw_title)).strip()
    key, label, kind = source_key_for(meta, title, scan_id)
    status = getattr(head, "status", None)
    return ScanFacts(
        scan_id=scan_id,
        title=title,
        status="" if status is None else str(status),
        created_at=created,
        last_updated=updated,
        source_key=key,
        source_label=label,
        source_kind=kind,
        repo_url=sanitize_repo_url(meta.get("repo_url")) if kind == SOURCE_REPO else None,
        branch=_text(meta.get("branch")) if kind == SOURCE_REPO else None,
        exclusion=_status_exclusion(status),
        warnings=warnings,
    )


def _asset_type_of(row: Mapping[str, Any]) -> str:
    declared = _text(row.get("asset_type"))
    if declared is not None:
        folded = declared.casefold()
        return folded if folded in ASSET_TYPES else ASSET_OTHER
    legacy = (_text(row.get("algorithm_type")) or "").casefold()
    if legacy in _UNTYPED_BY_DESIGN:
        return ASSET_OTHER
    return _LEGACY_ASSET_TYPE.get(legacy, ASSET_ALGORITHM)


def _untyped(row: Mapping[str, Any]) -> bool:
    """A row without ``asset_type`` that is not a library / configuration row: pre-reconcile output."""
    if _text(row.get("asset_type")) is not None:
        return False
    return (_text(row.get("algorithm_type")) or "").casefold() not in _UNTYPED_BY_DESIGN


def _codes_of(value: Any) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)):
        return ()
    cleaned = (code.strip() for code in value if isinstance(code, str) and code.strip())
    return tuple(dict.fromkeys(cleaned))


def _asset_from_row(row: Mapping[str, Any], facts: ScanFacts) -> AssetAgg:
    """One ``results[]`` row (any tier) as a single-scan ``AssetAgg`` observation.

    Impact and the quantum verdict come from ``cbom_metrics`` (the rules of the scan page, the scan list and the scan
    PDF): ``finding_severity`` (a finding without a recognised impact is Low; clean inventory is INFO) and
    ``code_row_quantum_vulnerable`` (the row's stored ``quantum_safe`` tri-state; certificates, keys and protocols of
    the current engine keep None, so only rows the engine graded count towards readiness)."""
    # one set of numbers for every CBOM view (pure modules: stdlib plus cbom_rows)
    from backend.utilities.cbom_sources.cbom_metrics import code_row_quantum_vulnerable, finding_severity

    asset_type = _asset_type_of(row)
    title = _text(row.get("title")) or _text(row.get("algorithm_name")) or "(unnamed)"
    location = _text(row.get("location")) or ""
    bom_ref = _text(row.get("bom_ref"))
    quantum_safe = _tri(row.get("quantum_safe"))
    quantum_vulnerable = code_row_quantum_vulnerable(dict(row))
    severity = finding_severity(dict(row))
    primitive = _text(row.get("primitive"))
    if primitive is None and asset_type == ASSET_ALGORITHM:
        primitive = _text(row.get("algorithm_type"))
    return AssetAgg(
        source_key=facts.source_key,
        source_label=facts.source_label,
        asset_type=asset_type,
        ident=bom_ref or f"{_slug(title)}#{location}",
        title=title,
        location=location,
        impact=INFO if severity is None else severity.capitalize(),
        finding_codes=_codes_of(row.get("finding_codes")),
        bom_ref=bom_ref,
        description=_text(row.get("description")) or "",
        primitive=primitive,
        key_size=_text(row.get("key_size")),
        curve=_text(row.get("curve")),
        mode=_text(row.get("mode")),
        protocol_version=_text(row.get("protocol_version")),
        material_kind=_text(row.get("material_kind")),
        parameter_set=_text(row.get("parameter_set")),
        not_valid_after=_text(row.get("not_valid_after")),
        security_strength_bits=_int(row.get("security_strength_bits")),
        risk_score=_float(row.get("risk_score")),
        quantum_vulnerable=quantum_vulnerable,
        quantum_safe=quantum_safe,
        hybrid=_tri(row.get("hybrid")),
        nist_quantum_security_level=_int(row.get("nist_quantum_security_level")),
        pqc_migration_target=_text(row.get("pqc_migration_target")),
        pqc_migration_roadmap=_text(row.get("pqc_migration_roadmap")),
        first_seen=facts.created_at,
        last_seen=facts.created_at,
        scan_count=1,
        scan_ids=(facts.scan_id,),
        latest_scan_id=facts.scan_id,
    )


def _read_rows(
    results: list[Any], facts: ScanFacts, warnings: list[str]
) -> tuple[list[AssetAgg], list[dict[str, Any]], bool]:
    """``(assets, raw rows parallel to assets, any row untyped)``; the first duplicate wins."""
    assets: list[AssetAgg] = []
    rows: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    untyped = False
    for index, row in enumerate(results):
        if not isinstance(row, dict):
            warnings.append(f"results[{index}] is not an object (skipped)")
            continue
        untyped = untyped or _untyped(row)
        asset = _asset_from_row(row, facts)
        identity = (asset.asset_type, asset.ident)
        if identity in seen:
            warnings.append(f"results[{index}] duplicates an earlier asset identity (first kept)")
            continue
        seen.add(identity)
        assets.append(asset)
        rows.append(row)
    return assets, rows, untyped


def _basename(path: str) -> str:
    return path.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1]


# crypto:* property -> CycloneDX certificateProperties key (the two carry the same values)
_CERT_PROPERTY_FALLBACK = (
    ("crypto:subjectName", "subjectName"),
    ("crypto:issuerName", "issuerName"),
    ("crypto:notValidBefore", "notValidBefore"),
    ("crypto:notValidAfter", "notValidAfter"),
)


def _cert_name(comp: Mapping[str, Any], props: Mapping[str, str]) -> str:
    path = _text(props.get("discovery:source"))
    return _text(comp.get("name")) or (_basename(path) if path else "") or "(unnamed certificate)"


def _new_cert(facts: ScanFacts, path: str, **fields: Any) -> CertAgg:
    """A single-scan observation: provenance fields describe this scan only."""
    return CertAgg(
        source_keys=(facts.source_key,),
        locations=((facts.source_label, path),),
        locations_total=1,
        first_seen=facts.created_at,
        last_seen=facts.created_at,
        scan_count=1,
        scan_ids=(facts.scan_id,),
        latest_scan_id=facts.scan_id,
        **fields,
    )


def _cert_from_component(
    comp: Mapping[str, Any],
    props: Mapping[str, str],
    pair: tuple[dict[str, Any], AssetAgg] | None,
    signed_by: tuple[str, ...],
    facts: ScanFacts,
) -> CertAgg:
    """A certificate ``cbom_json`` component joined to its ``results[]`` row (impact, codes)."""
    merged = dict(props)
    crypto = comp.get("cryptoProperties")
    cert_props = crypto.get("certificateProperties") if isinstance(crypto, dict) else None
    if isinstance(cert_props, dict):
        for prop, field_name in _CERT_PROPERTY_FALLBACK:
            replacement = _text(cert_props.get(field_name))
            if not merged.get(prop, "").strip() and replacement is not None:
                merged[prop] = replacement
    name = _cert_name(comp, props)
    path = _text(props.get("discovery:source")) or name
    key, strong = cert_identity_key(merged, fallback_name=name, source_key=facts.source_key)
    row, asset = pair if pair is not None else (None, None)
    self_signed = _tri(props.get("crypto:selfSigned"))
    if self_signed is None and row is not None:
        self_signed = _tri(row.get("self_signed"))
    return _new_cert(
        facts,
        path,
        key=key,
        identity_strong=strong,
        name=name,
        file_names=(name,),
        subject_cn=_text(merged.get("crypto:subjectName")),
        issuer_cn=_text(merged.get("crypto:issuerName")),
        not_before=_text(merged.get("crypto:notValidBefore")),
        not_after=_text(merged.get("crypto:notValidAfter")),
        public_key_algorithm=_text(merged.get("crypto:publicKeyAlgorithm")),
        key_size=_text(merged.get("crypto:keySize")),
        curve=_text(merged.get("crypto:curve")),
        signature_algorithm=_text(merged.get("crypto:signatureAlgorithm")),
        self_signed=self_signed,
        is_ca=_tri(props.get("crypto:isCertificateAuthority")),
        signed_by=signed_by,
        scan_time_expired=_tri(row.get("expired")) if row is not None else None,
        impact=asset.impact if asset is not None else INFO,
        finding_codes=asset.finding_codes if asset is not None else (),
    )


def _cert_from_row(row: Mapping[str, Any], asset: AssetAgg, facts: ScanFacts) -> CertAgg:
    """A certificate seen only as a ``results[]`` row (pre-reconcile scans): weak identity."""
    props = {"crypto:notValidAfter": asset.not_valid_after} if asset.not_valid_after else {}
    key, strong = cert_identity_key(props, fallback_name=asset.title, source_key=facts.source_key)
    return _new_cert(
        facts,
        asset.location or asset.title,
        key=key,
        identity_strong=strong,
        name=asset.title,
        file_names=(asset.title,),
        not_after=asset.not_valid_after,
        key_size=asset.key_size,
        curve=asset.curve,
        self_signed=_tri(row.get("self_signed")),
        scan_time_expired=_tri(row.get("expired")),
        impact=asset.impact,
        finding_codes=asset.finding_codes,
    )


def _read_components(
    bom: Mapping[str, Any],
    assets: list[AssetAgg],
    rows: list[dict[str, Any]],
    graph: Any,
    facts: ScanFacts,
    warnings: list[str],
) -> tuple[list[CertAgg], list[LibAgg]]:
    """Certificates and libraries of ``cbom_json`` (plus certificate rows it does not cover)."""
    components = bom.get("components")
    if components is not None and not isinstance(components, list):
        warnings.append("cbom_json.components is not a list (ignored)")
        components = []
    cert_pairs = [
        (row, asset)
        for row, asset in zip(rows, assets, strict=True)
        if asset.asset_type == ASSET_CERTIFICATE
    ]
    by_ref = {asset.bom_ref: (row, asset) for row, asset in cert_pairs if asset.bom_ref}
    by_place = {(asset.title, asset.location): (row, asset) for row, asset in cert_pairs}
    cert_components: list[tuple[dict[str, Any], dict[str, str]]] = []
    names_by_ref: dict[str, str] = {}
    library_paths: dict[str, tuple[str, list[str]]] = {}
    for index, comp in enumerate(components or []):
        if not isinstance(comp, dict):
            warnings.append(f"cbom_json.components[{index}] is not an object (skipped)")
            continue
        props = _props(comp)
        crypto = comp.get("cryptoProperties")
        declared = (_text(crypto.get("assetType")) if isinstance(crypto, dict) else None) or ""
        declared = declared or props.get("crypto:assetType", "")
        if (_text(comp.get("type")) or "").casefold() == "library" or (
            props.get("crypto:role", "").casefold() == "library"
        ):
            name = _text(comp.get("name"))
            if name is None:
                warnings.append(f"cbom_json.components[{index}] is a library without a name")
                continue
            paths = library_paths.setdefault(name.casefold(), (name, []))[1]
            path = _text(props.get("discovery:source"))
            if path and path not in paths:
                paths.append(path)
        elif declared.casefold() == ASSET_CERTIFICATE:
            cert_components.append((comp, props))
            ref = _text(comp.get("bom-ref"))
            if ref:
                names_by_ref[ref] = _cert_name(comp, props)
    signers: dict[str, list[str]] = {}
    edges = graph.get("edges") if isinstance(graph, dict) else None
    for edge in edges if isinstance(edges, list) else []:
        if not isinstance(edge, dict) or edge.get("rel") != "signed_by":
            continue
        source, target = _text(edge.get("source")), _text(edge.get("target"))
        issuer = names_by_ref.get(target) if target else None
        if source in names_by_ref and issuer is not None:
            chain = signers.setdefault(source or "", [])
            if issuer not in chain:
                chain.append(issuer)
    certs: list[CertAgg] = []
    used: set[int] = set()
    for comp, props in cert_components:
        ref = _text(comp.get("bom-ref"))
        name = _cert_name(comp, props)
        place = (name, _text(props.get("discovery:source")) or name)
        pair = (by_ref.get(ref) if ref else None) or by_place.get(place)
        if pair is not None:
            used.add(id(pair[1]))
        certs.append(
            _cert_from_component(comp, props, pair, tuple(signers.get(ref or "", ())), facts)
        )
    certs.extend(
        _cert_from_row(row, asset, facts) for row, asset in cert_pairs if id(asset) not in used
    )
    libs = [
        LibAgg(
            key=key,
            name=name,
            source_keys=(facts.source_key,),
            source_labels=(facts.source_label,),
            discovered_in=tuple(paths[:MAX_LOCATIONS]),
            discovered_in_total=len(paths),
            first_seen=facts.created_at,
            last_seen=facts.created_at,
            scan_count=1,
            scan_ids=(facts.scan_id,),
            latest_scan_id=facts.scan_id,
        )
        for key, (name, paths) in library_paths.items()
    ]
    return certs, libs


def _read_compliance(
    scan_data: Mapping[str, Any], facts: ScanFacts, warnings: list[str]
) -> tuple[dict[str, FrameworkPool], list[RequirementAgg]]:
    """Per-framework verdict counts and per-requirement rows of ONE scan (never the disclaimer)."""
    compliance = scan_data.get("cbom_compliance")
    if not isinstance(compliance, dict):
        return {}, []
    attestations = scan_data.get("attestations")
    attested: Mapping[str, Any] = attestations if isinstance(attestations, dict) else {}
    frameworks: dict[str, FrameworkPool] = {}
    requirements: list[RequirementAgg] = []
    for raw_key, block in compliance.items():
        if not isinstance(block, dict):  # "disclaimer" and anything else that is not a framework
            continue
        framework = str(raw_key)
        counts = {
            state: _int(block.get(state)) or 0
            for state in ("pass", "pass_with_evidence", "fail", "out_of_scope",
                          "not_bom_evidenceable", "na")  # fmt: skip
        }
        frameworks[framework] = FrameworkPool(
            framework=framework,
            passed=counts["pass"],
            passed_with_evidence=counts["pass_with_evidence"],
            failed=counts["fail"],
            out_of_scope=counts["out_of_scope"],
            not_bom_evidenceable=counts["not_bom_evidenceable"],
            na=counts["na"],
            coverage=_coverage(counts["pass"], counts["pass_with_evidence"], counts["fail"]),
            sources_pooled=1,
        )
        entries = block.get("requirements")
        if entries is None:
            continue
        shown = framework if _SAFE_KEY_RE.fullmatch(framework) else "?"  # never echo odd text
        if not isinstance(entries, list):
            warnings.append(f"cbom_compliance.{shown}.requirements is not a list (ignored)")
            continue
        notes = attested.get(framework)
        notes = notes if isinstance(notes, dict) else {}
        seen: set[str] = set()
        for index, entry in enumerate(entries):
            where = f"cbom_compliance.{shown}.requirements[{index}]"
            if not isinstance(entry, dict):
                warnings.append(f"{where} is not an object (skipped)")
                continue
            req_id = _text(entry.get("id"))
            if req_id is None or req_id in seen:
                warnings.append(f"{where} has no usable id (skipped)")
                continue
            seen.add(req_id)
            verdict = (_text(entry.get("verdict")) or VERDICT_NA).casefold()
            note = notes.get(req_id)
            note = note if isinstance(note, dict) else {}
            requirements.append(
                RequirementAgg(
                    framework=framework,
                    req_id=req_id,
                    title=_text(entry.get("title")) or "",
                    citation=_text(entry.get("source")) or "",
                    verdict=verdict,
                    verdicts={facts.source_key: verdict},
                    attestable_sources=int(
                        verdict in (VERDICT_NOT_BOM_EVIDENCEABLE, VERDICT_PASS_WITH_EVIDENCE)
                    ),
                    attested_sources=int(verdict == VERDICT_PASS_WITH_EVIDENCE),
                    latest_attestation_file=_text(note.get("filename")),
                    latest_attestation_note=_text(note.get("note")),
                    latest_attestation_at=_text(note.get("uploaded_at")),
                )
            )
    return frameworks, requirements


def _fill_from_blob(facts: ScanFacts, scan_data: Any) -> ScanFacts:
    """Read ``scan_data`` into ``facts``; assigns last, so a failure leaves no half state."""
    if facts.exclusion is not None:  # failure / not completed: the blob is never looked at
        return facts
    results = scan_data.get("results") if isinstance(scan_data, dict) else None
    bom = scan_data.get("cbom_json") if isinstance(scan_data, dict) else None
    has_rows, has_bom = isinstance(results, list), isinstance(bom, dict)
    if not has_rows and not has_bom:
        facts.exclusion = EXCLUDED_NO_DATA
        return facts
    warnings: list[str] = []
    if results is not None and not has_rows:
        warnings.append("results is not a list (ignored)")
    raw_rows: list[Any] = results if isinstance(results, list) else []
    raw_bom: dict[str, Any] = bom if isinstance(bom, dict) else {}
    assets, rows, untyped = _read_rows(raw_rows, facts, warnings)
    certs, libs = _read_components(
        raw_bom, assets, rows, scan_data.get("cbom_graph"), facts, warnings
    )
    frameworks, requirements = _read_compliance(scan_data, facts, warnings)
    compliance = scan_data.get("cbom_compliance")
    reasons = tuple(
        reason
        for reason, missing in (
            ("no_distributions", not isinstance(scan_data.get("cbom_distributions"), dict)),
            ("no_compliance", not (isinstance(compliance, dict) and bool(frameworks))),
            ("no_asset_type", untyped),
            ("no_cbom_json", not has_bom),
        )
        if missing
    )
    if not reasons:
        tier = TIER_A
    elif "no_asset_type" in reasons or "no_cbom_json" in reasons:
        tier = TIER_C
    else:
        tier = TIER_B
    for asset in assets:
        asset.tier = tier
    for cert in certs:
        cert.tier = tier
    facts.assets, facts.certs, facts.libs = assets, certs, libs
    facts.frameworks, facts.requirements = frameworks, requirements
    facts.asset_count, facts.cert_count, facts.lib_count = len(assets), len(certs), len(libs)
    facts.tier = tier
    facts.fidelity = FIDELITY_REDUCED if reasons else FIDELITY_FULL
    facts.fidelity_reasons = reasons
    _read_posture(scan_data, facts, warnings)
    facts.warnings.extend(warnings)
    return facts


def _safe_fill(facts: ScanFacts, scan_data: Any) -> ScanFacts:
    try:
        return _fill_from_blob(facts, scan_data)
    except Exception:  # noqa: BLE001 - the contract is "total": never fail a document on one scan
        facts.assets, facts.certs, facts.libs = [], [], []
        facts.frameworks, facts.requirements = {}, []
        facts.asset_count = facts.cert_count = facts.lib_count = 0
        facts.tier, facts.fidelity, facts.fidelity_reasons = TIER_NONE, FIDELITY_NONE, ()
        facts.exclusion = EXCLUDED_NO_DATA
        facts.posture = None
        facts.warnings.append("scan_data could not be read (unexpected structure)")
        return facts


def extract_scan_facts(head: ScanHead, scan_data: Any) -> ScanFacts:
    """Tier-tolerant, TOTAL extraction of one scan's facts (plan 3.1 / 3.2 / 4.6).  Never raises.

    Reads ``results`` / ``cbom_json`` / ``cbom_distributions`` / ``cbom_compliance`` /
    ``cbom_graph`` / ``attestations`` defensively (``isinstance`` everywhere); a bad row is
    skipped and recorded in ``ScanFacts.warnings``.  A success scan whose ``scan_data`` is not a
    dict, or has neither a list ``results`` nor a dict ``cbom_json``, gets
    ``exclusion=EXCLUDED_NO_DATA``.  A valid but empty scan (``results == []`` with a
    ``cbom_json``) is INCLUDED.  Tier-C rows derive ``asset_type`` from ``algorithm_type``
    (certificate / key -> related-crypto-material / protocol / else algorithm).  A current-engine
    library or configuration row has no ``asset_type`` by design: it is typed ``other`` and does not
    make the scan reduced.  Never prints or
    copies ``cbom_compliance["disclaimer"]`` or ``cbom_json.metadata`` (AIBOM text, plan F-05).
    """
    return _safe_fill(_head_facts(head), scan_data)


Rank = tuple[datetime, int]  # (created_at, scan_id): "newer" simply means a larger Rank


class _AssetAcc:
    """Running aggregate of one asset identity; order-independent (newest rank wins)."""

    __slots__ = ("best", "rank", "scan_ids")

    def __init__(self, obs: AssetAgg, rank: Rank) -> None:
        self.best, self.rank = obs, rank
        self.scan_ids: set[int] = {rank[1]}


class _CertAcc:
    __slots__ = ("best", "rank", "scan_ids", "names", "places", "signers", "is_ca", "self_signed")

    def __init__(self, obs: CertAgg, rank: Rank) -> None:
        self.best, self.rank = obs, rank
        self.scan_ids: set[int] = set()
        self.names: dict[str, Rank] = {}  # file basename -> newest rank seen
        self.places: dict[tuple[str, str], Rank] = {}  # (source_key, path) -> newest rank
        self.signers: dict[str, set[int]] = {}  # issuer file -> scans whose graph had the edge
        self.is_ca: tuple[Rank, bool] | None = None  # newest KNOWN value (not newest scan's)
        self.self_signed: tuple[Rank, bool] | None = None


class _LibAcc:
    __slots__ = ("best", "rank", "scan_ids", "paths")

    def __init__(self, obs: LibAgg, rank: Rank) -> None:
        self.best, self.rank = obs, rank
        self.scan_ids: set[int] = set()
        self.paths: dict[str, Rank] = {}


class _SourceAcc:
    """Included scans of one source.  Only the newest keeps its compliance payload."""

    __slots__ = ("ranks", "newest", "newest_rank")

    def __init__(self) -> None:
        self.ranks: list[Rank] = []
        self.newest: ScanFacts | None = None
        self.newest_rank: Rank | None = None


def _bump(table: dict[Any, Rank], key: Any, rank: Rank) -> None:
    current = table.get(key)
    if current is None or rank > current:
        table[key] = rank


def _merge_asset(accs: dict[tuple[str, str, str], _AssetAcc], obs: AssetAgg, rank: Rank) -> None:
    identity = (obs.source_key, obs.asset_type, obs.ident)
    acc = accs.get(identity)
    if acc is None:
        accs[identity] = _AssetAcc(obs, rank)
        return
    acc.scan_ids.add(rank[1])
    if rank > acc.rank:
        acc.best, acc.rank = obs, rank


def _merge_cert(accs: dict[str, _CertAcc], obs: CertAgg, rank: Rank) -> None:
    acc = accs.get(obs.key)
    if acc is None:
        acc = accs[obs.key] = _CertAcc(obs, rank)
    elif rank > acc.rank:
        acc.best, acc.rank = obs, rank
    acc.scan_ids.add(rank[1])
    for name in obs.file_names:
        _bump(acc.names, name, rank)
    for _label, path in obs.locations:
        _bump(acc.places, (obs.source_keys[0], path), rank)
    for signer in obs.signed_by:
        acc.signers.setdefault(signer, set()).add(rank[1])
    if obs.is_ca is not None and (acc.is_ca is None or rank > acc.is_ca[0]):
        acc.is_ca = (rank, obs.is_ca)
    if obs.self_signed is not None and (acc.self_signed is None or rank > acc.self_signed[0]):
        acc.self_signed = (rank, obs.self_signed)


def _merge_lib(accs: dict[str, _LibAcc], obs: LibAgg, rank: Rank) -> None:
    acc = accs.get(obs.key)
    if acc is None:
        acc = accs[obs.key] = _LibAcc(obs, rank)
    elif rank > acc.rank:
        acc.best, acc.rank = obs, rank
    acc.scan_ids.add(rank[1])
    for path in obs.discovered_in:
        _bump(acc.paths, path, rank)


class _Ctx:
    """Lookups the finalisers need once every scan has been folded."""

    def __init__(
        self,
        rank_of: dict[int, Rank],
        source_of: dict[int, str],
        current_ids: set[int],
        label_of: dict[str, str],
        as_of: date,
    ) -> None:
        self.rank_of, self.source_of = rank_of, source_of
        self.current_ids, self.label_of, self.as_of = current_ids, label_of, as_of

    def ordered(self, scan_ids: Iterable[int]) -> list[int]:
        """Scan ids newest first."""
        return sorted(scan_ids, key=lambda scan_id: self.rank_of[scan_id], reverse=True)

    def span(self, scan_ids: Iterable[int]) -> tuple[datetime, datetime]:
        stamps = [self.rank_of[scan_id][0] for scan_id in scan_ids]
        return min(stamps), max(stamps)

    def by_label(self, source_keys: Iterable[str]) -> tuple[str, ...]:
        return tuple(sorted(source_keys, key=lambda key: (self.label_of[key].casefold(), key)))

    @staticmethod
    def newest_first(table: Mapping[Any, Rank]) -> list[Any]:
        """Keys by newest rank first; ties break on the key (stable, deterministic)."""
        items = sorted(table.items(), key=lambda item: item[0])
        items.sort(key=lambda item: item[1], reverse=True)
        return [key for key, _ in items]


def _finish_assets(accs: dict[tuple[str, str, str], _AssetAcc], ctx: _Ctx) -> list[AssetAgg]:
    finished = []
    for acc in accs.values():
        ids = ctx.ordered(acc.scan_ids)
        first, last = ctx.span(acc.scan_ids)
        finished.append(
            replace(
                acc.best,
                source_label=ctx.label_of[acc.best.source_key],
                current=any(scan_id in ctx.current_ids for scan_id in acc.scan_ids),
                first_seen=first,
                last_seen=last,
                scan_count=len(ids),
                scan_ids=tuple(ids[:MAX_SCAN_IDS]),
                latest_scan_id=ids[0],
            )
        )
    finished.sort(key=lambda asset: (asset.source_key, asset.asset_type, asset.ident))
    return finished


def _known(newest: bool | None, fallback: tuple[Rank, bool] | None) -> bool | None:
    """The newest scan's tri-state value, else the newest KNOWN value of an older scan."""
    if newest is not None:
        return newest
    return fallback[1] if fallback is not None else None


def _finish_certs(accs: dict[str, _CertAcc], ctx: _Ctx) -> list[CertAgg]:
    finished = []
    for acc in accs.values():
        best = acc.best
        ids = ctx.ordered(acc.scan_ids)
        first, last = ctx.span(acc.scan_ids)
        sources = {ctx.source_of[scan_id] for scan_id in acc.scan_ids}
        live = {ctx.source_of[i] for i in acc.scan_ids if i in ctx.current_ids}
        places = [(ctx.label_of[key], path) for key, path in ctx.newest_first(acc.places)]
        signer_rank: dict[str, Rank] = {}
        for signer, seen_in in acc.signers.items():
            relevant = [i for i in seen_in if not live or i in ctx.current_ids]
            if relevant:
                signer_rank[signer] = max(ctx.rank_of[i] for i in relevant)
        finished.append(
            replace(
                best,
                file_names=tuple(ctx.newest_first(acc.names)),
                self_signed=_known(best.self_signed, acc.self_signed),
                is_ca=_known(best.is_ca, acc.is_ca),
                signed_by=tuple(ctx.newest_first(signer_rank)),
                expiry=classify_expiry(best.not_after, ctx.as_of),
                source_keys=ctx.by_label(sources),
                current_source_keys=ctx.by_label(live),
                locations=tuple(places[:MAX_LOCATIONS]),
                locations_total=len(places),
                current=bool(live),
                first_seen=first,
                last_seen=last,
                scan_count=len(ids),
                scan_ids=tuple(ids[:MAX_SCAN_IDS]),
                latest_scan_id=ids[0],
            )
        )
    finished.sort(key=lambda cert: cert.key)
    return finished


def _finish_libs(accs: dict[str, _LibAcc], ctx: _Ctx) -> list[LibAgg]:
    finished = []
    for acc in accs.values():
        ids = ctx.ordered(acc.scan_ids)
        first, last = ctx.span(acc.scan_ids)
        sources = ctx.by_label({ctx.source_of[scan_id] for scan_id in acc.scan_ids})
        live = {ctx.source_of[i] for i in acc.scan_ids if i in ctx.current_ids}
        paths = ctx.newest_first(acc.paths)
        finished.append(
            replace(
                acc.best,
                source_keys=sources,
                source_labels=tuple(ctx.label_of[key] for key in sources),
                current_source_keys=tuple(key for key in sources if key in live),
                discovered_in=tuple(paths[:MAX_LOCATIONS]),
                discovered_in_total=len(paths),
                current=bool(live),
                first_seen=first,
                last_seen=last,
                scan_count=len(ids),
                scan_ids=tuple(ids[:MAX_SCAN_IDS]),
                latest_scan_id=ids[0],
            )
        )
    finished.sort(key=lambda lib: lib.key)
    return finished


def _rollup_verdict(verdicts: Iterable[str]) -> str:
    """Highest-precedence verdict (fail > nbe > pwe > pass > out_of_scope > na); unknown last."""
    best, best_rank = VERDICT_NA, len(VERDICT_PRECEDENCE) + 1
    for verdict in verdicts:
        rank = _VERDICT_RANK.get(verdict, len(VERDICT_PRECEDENCE))
        if rank < best_rank:
            best, best_rank = verdict, rank
    return best


def _stamp(text: str | None) -> tuple[datetime, str]:
    """Sort key of an ``uploaded_at`` string: parsed instant first, raw text as tie-break."""
    moment = None
    if text:
        candidate = text.strip()
        if candidate[-1:] in ("Z", "z"):
            candidate = candidate[:-1] + "+00:00"
        try:
            moment = _utc(datetime.fromisoformat(candidate))
        except ValueError:
            moment = None
    return moment or _EPOCH, text or ""


def _keep_latest_attestation(agg: RequirementAgg, one: RequirementAgg) -> None:
    """Keep the attestation with the latest ``uploaded_at`` across sources (first wins a tie)."""
    fields = (one.latest_attestation_file, one.latest_attestation_note, one.latest_attestation_at)
    if all(value is None for value in fields):
        return
    held = (agg.latest_attestation_file, agg.latest_attestation_note, agg.latest_attestation_at)
    if all(value is None for value in held) or _stamp(fields[2]) > _stamp(held[2]):
        agg.latest_attestation_file, agg.latest_attestation_note = fields[0], fields[1]
        agg.latest_attestation_at = fields[2]


def _pool_compliance(
    newest_full: Sequence[ScanFacts], legacy_excluded: int
) -> tuple[tuple[FrameworkPool, ...], tuple[RequirementAgg, ...]]:
    """Pool the current full-fidelity scans (given newest first): sums, then the roll-up."""
    pools: dict[str, FrameworkPool] = {}
    merged: dict[tuple[str, str], RequirementAgg] = {}
    for facts in newest_full:
        for framework, one in facts.frameworks.items():
            pool = pools.setdefault(framework, FrameworkPool(framework=framework))
            pool.passed += one.passed
            pool.passed_with_evidence += one.passed_with_evidence
            pool.failed += one.failed
            pool.out_of_scope += one.out_of_scope
            pool.not_bom_evidenceable += one.not_bom_evidenceable
            pool.na += one.na
            pool.sources_pooled += 1
        for req in facts.requirements:
            agg = merged.setdefault(
                (req.framework, req.req_id), RequirementAgg(req.framework, req.req_id)
            )
            agg.verdicts.update(req.verdicts)
            agg.attestable_sources += req.attestable_sources
            agg.attested_sources += req.attested_sources
            agg.title = agg.title or req.title
            agg.citation = agg.citation or req.citation
            _keep_latest_attestation(agg, req)
    for pool in pools.values():
        pool.coverage = _coverage(pool.passed, pool.passed_with_evidence, pool.failed)
        pool.legacy_excluded = legacy_excluded
    for agg in merged.values():
        agg.verdict = _rollup_verdict(agg.verdicts.values())
    unknown_rank = len(_FRAMEWORK_ORDER)
    frameworks = sorted(
        pools.values(), key=lambda p: (_FRAMEWORK_RANK.get(p.framework, unknown_rank), p.framework)
    )
    requirements = sorted(merged.values(), key=lambda r: (r.framework, r.req_id))
    return tuple(frameworks), tuple(requirements)


def _bounded(value: Any, default: int, minimum: int) -> int:
    number = _int(value)
    return max(minimum, default if number is None else number)


def _attestation_stamps(scan_id: int, scan_data: Any) -> list[tuple[int, str, str, str]]:
    """``(scan_id, framework, req_id, uploaded_at)`` of every attestation record of ONE scan.

    Reads ``scan_data["attestations"][framework][req_id]``, the ``{filename, note, uploaded_at}``
    dict the upload route stores.  TOTAL: anything that is not a dict (or a text key) at one of
    the three levels is skipped, so a malformed entry never counts and never raises.  A dict
    record whose ``uploaded_at`` is missing or unusable still counts, with ``""``, because the
    register prints that record.
    """
    attestations = scan_data.get("attestations") if isinstance(scan_data, dict) else None
    if not isinstance(attestations, dict):
        return []
    stamps: list[tuple[int, str, str, str]] = []
    for framework, records in attestations.items():
        if not (isinstance(framework, str) and isinstance(records, dict)):
            continue
        for req_id, record in records.items():
            if isinstance(req_id, str) and isinstance(record, dict):
                stamps.append((scan_id, framework, req_id, _text(record.get("uploaded_at")) or ""))
    return stamps


def _attestation_suffix(stamps: Sequence[tuple[int, str, str, str]]) -> str:
    """Tail of the fingerprint text: ``""`` without records, so the old formula is untouched.

    Each record is one compact ASCII JSON array, so no value can blur into its neighbour
    whatever characters a framework key, requirement id or timestamp contains.
    """
    if not stamps:
        return ""
    return "|attestations|" + ",".join(
        json.dumps(stamp, separators=(",", ":")) for stamp in sorted(stamps)
    )


class _PostureAcc:
    """One ``(source_key, fact_id)`` while the fold is running."""

    __slots__ = (
        "best_rank",
        "fact",
        "fact_id",
        "first_seen",
        "full",
        "last_scan_id",
        "last_seen",
        "scan_count",
        "source_key",
    )

    def __init__(
        self, source_key: str, fact_id: str, fact: dict[str, Any], rank: Rank, full: bool
    ) -> None:
        self.source_key = source_key
        self.fact_id = fact_id
        self.fact = fact
        self.best_rank = rank
        self.full = full
        self.first_seen = rank[0]
        self.last_seen = rank[0]
        self.scan_count = 1
        self.last_scan_id = rank[1]


class _PostureAccs(dict):
    """Accumulator map plus the 'previously seen count is exact' flag."""

    def __init__(self) -> None:
        super().__init__()
        self.exact = True


def _compact_posture_fact(fact: Mapping[str, Any]) -> dict[str, str]:
    """Identity fields only.  Scanned prose and finding text stay off the appendix row."""
    return {
        "id": str(fact.get("id") or ""),
        "kind": str(fact.get("kind") or ""),
        "native_type": str(fact.get("native_type") or ""),
        "address": str(fact.get("address") or ""),
        "path": str(fact.get("path") or ""),
        "verdict": str(fact.get("verdict") or ""),
    }


def _string_list(value: Any) -> tuple[str, ...] | None:
    """A list of strings, or None when the shape is wrong.  Never reads the element text out."""
    if not isinstance(value, list):
        return None
    if any(not isinstance(item, str) for item in value):
        return None
    return tuple(value)


def _posture_state(block: Mapping[str, Any]) -> tuple[str, str | None]:
    """``(state, warning)``.  The warning is a fixed sentence and never quotes the blob."""
    version = block.get("schema_version")
    if isinstance(version, bool) or not isinstance(version, int):
        return "malformed", "cbom_posture.schema_version is not an integer (skipped)"
    lanes = _string_list(block.get("lanes"))
    failed = _string_list(block.get("failed_lanes"))
    if lanes is None or failed is None:
        return "malformed", "cbom_posture.lanes is not a list of strings (skipped)"
    for key in ("facts", "imports", "diagnostics"):
        if not isinstance(block.get(key), list):
            return "malformed", f"cbom_posture.{key} is not a list (skipped)"
    if version > POSTURE_SCHEMA:
        return "newer_engine", "cbom_posture.schema_version is newer than this renderer (skipped)"
    if not lanes:
        if failed:
            return "failed", None
        return "malformed", "cbom_posture.lanes is empty (skipped)"
    if failed:
        names = ", ".join(sorted(set(failed)))
        return "partial", f"cbom_posture lanes failed: {names}"
    return "assessed", None


def _safe_int(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value


def _data_table_row(item: Any) -> dict[str, str] | None:
    if not isinstance(item, dict):
        return None
    name = item.get("name")
    if not isinstance(name, str) or not name.strip():
        return None
    version = item.get("data_version")
    version_text = version.strip() if isinstance(version, str) else ""
    raw_date = item.get("valid_as_of")
    if not isinstance(raw_date, str) or _DATE_RE.match(raw_date[:10]) is None:
        return None
    return {
        "name": " ".join(name.split())[:128],
        "data_version": version_text[:64],
        "valid_as_of": raw_date[:10],
    }


def _copy_import(item: Any) -> dict[str, Any] | None:
    if not isinstance(item, dict):
        return None
    kept: dict[str, Any] = {}
    for key in (
        "path",
        "tool",
        "variant",
        "tool_version",
        "scan_started",
        "scan_finished",
        "scan_started_iso",
        "scan_finished_iso",
        "status",
    ):
        value = item.get(key)
        if isinstance(value, str):
            kept[key] = " ".join(value.split())[:512]
    endpoints = _safe_int(item.get("endpoints"))
    if endpoints is not None:
        kept["endpoints"] = endpoints
    return kept or None


def _copy_diagnostic(item: Any) -> dict[str, Any] | None:
    if not isinstance(item, dict):
        return None
    code = item.get("code")
    path = item.get("path")
    if not isinstance(code, str) or not isinstance(path, str):
        return None
    line = _safe_int(item.get("line"))
    row: dict[str, Any] = {
        "code": code[:64],
        "path": " ".join(path.split())[:512],
        "line": 0 if line is None else line,
    }
    value = _safe_int(item.get("value"))
    if value is not None:
        row["value"] = value
    return row


def _read_posture(scan_data: Any, facts: ScanFacts, warnings: list[str]) -> None:
    """Attach ``facts.posture``.  A bad block is Not_Assessed and adds one fixed warning."""
    try:
        _read_posture_inner(scan_data, facts, warnings)
    except Exception:  # noqa: BLE001 - one scan must not fail the document
        facts.posture = PostureScan(state="malformed")
        warnings.append("cbom_posture could not be read (skipped)")


def _read_posture_inner(scan_data: Any, facts: ScanFacts, warnings: list[str]) -> None:
    blob = scan_data if isinstance(scan_data, dict) else {}
    if "cbom_posture" not in blob:
        facts.posture = PostureScan(state="absent")
        return
    block = blob.get("cbom_posture")
    if not isinstance(block, dict):
        facts.posture = PostureScan(state="malformed")
        warnings.append("cbom_posture is not an object (skipped)")
        return
    state, warning = _posture_state(block)
    if warning is not None:
        warnings.append(warning)
    if state == "malformed":
        # Lane strings are scanned text. A block that already failed validation must not
        # carry them onto the status row.
        facts.posture = PostureScan(
            state="malformed",
            schema_version=_safe_int(block.get("schema_version")),
        )
        return
    if state in ("newer_engine", "failed"):
        failed = _string_list(block.get("failed_lanes")) or ()
        lanes = _string_list(block.get("lanes")) or ()
        facts.posture = PostureScan(
            state=state,
            schema_version=_safe_int(block.get("schema_version")),
            lanes=tuple(sorted(set(lanes))),
            failed_lanes=tuple(sorted(set(failed))),
        )
        return
    kept: list[dict[str, Any]] = []
    raw_facts = block.get("facts")
    if isinstance(raw_facts, list):
        for index, item in enumerate(raw_facts):
            if not isinstance(item, dict):
                warnings.append(f"cbom_posture.facts[{index}] is not an object (skipped)")
                continue
            fact_id = item.get("id")
            kind = item.get("kind")
            if (
                not isinstance(fact_id, str)
                or fact_id == ""
                or not isinstance(kind, str)
                or kind == ""
            ):
                warnings.append(f"cbom_posture.facts[{index}] has no usable id (skipped)")
                continue
            kept.append(dict(item))
    imports = [
        row
        for item in block.get("imports") or []
        if (row := _copy_import(item)) is not None
    ]
    diagnostics = [
        row
        for item in block.get("diagnostics") or []
        if (row := _copy_diagnostic(item)) is not None
    ]
    tables = [
        row
        for item in block.get("data_tables") or []
        if (row := _data_table_row(item)) is not None
    ]
    totals_raw = block.get("diagnostic_totals")
    totals: dict[str, int] = {}
    if isinstance(totals_raw, dict):
        for key, value in totals_raw.items():
            number = _safe_int(value)
            if isinstance(key, str) and number is not None:
                totals[key] = number
    counts = block.get("counts") if isinstance(block.get("counts"), dict) else {}
    dropped_raw = block.get("dropped")
    dropped: dict[str, int] = {}
    if isinstance(dropped_raw, dict):
        for key, value in dropped_raw.items():
            number = _safe_int(value)
            if isinstance(key, str) and number is not None and number > 0:
                dropped[key] = number
    lanes = _string_list(block.get("lanes")) or ()
    failed = _string_list(block.get("failed_lanes")) or ()
    version = _safe_int(block.get("schema_version"))
    facts.posture = PostureScan(
        state=state,
        schema_version=version,
        lanes=tuple(sorted(set(lanes))),
        failed_lanes=tuple(sorted(set(failed))),
        facts=kept,
        imports=imports,
        diagnostics=diagnostics,
        diagnostic_totals=totals,
        data_tables=tables,
        counts=dict(counts),
        truncated=block.get("truncated") is True,
        dropped=dropped,
    )


def _merge_posture(
    accs: dict[tuple[str, str], _PostureAcc],
    source_acc: _SourceAcc,
    facts: ScanFacts,
    rank: Rank,
) -> None:
    """Latest scan of a source keeps full fact dicts.  Older observations are compact."""
    posture = facts.posture
    if posture is None or posture.state not in ("assessed", "partial"):
        if posture is not None:
            posture.facts = []
        return
    source_key = facts.source_key
    newest = source_acc.newest_rank == rank
    if newest:
        for key, acc in accs.items():
            if key[0] == source_key and acc.full and acc.best_rank < rank:
                acc.fact = _compact_posture_fact(acc.fact)
                acc.full = False
    cap = MAX_POSTURE_ACCS
    for item in posture.facts:
        fact_id = item.get("id")
        if not isinstance(fact_id, str) or fact_id == "":
            continue
        key = (source_key, fact_id)
        current = accs.get(key)
        if current is None:
            if not newest and len(accs) >= cap:
                if isinstance(accs, _PostureAccs):
                    accs.exact = False
                continue
            stored = dict(item) if newest else _compact_posture_fact(item)
            accs[key] = _PostureAcc(source_key, fact_id, stored, rank, newest)
            continue
        current.scan_count += 1
        if rank[0] < current.first_seen:
            current.first_seen = rank[0]
        if rank > current.best_rank:
            current.best_rank = rank
            current.last_seen = rank[0]
            current.last_scan_id = rank[1]
            current.full = newest
            current.fact = dict(item) if newest else _compact_posture_fact(item)
    posture.facts = []
    if facts is not source_acc.newest:
        posture.imports = []
        posture.diagnostics = []
        posture.data_tables = []


def _evidence_only(fact: Mapping[str, Any]) -> bool:
    if fact.get("evidence_only") is True:
        return True
    attrs = fact.get("attrs")
    return isinstance(attrs, dict) and attrs.get("evidence_only") is True


def _layer_map(fact: Mapping[str, Any]) -> dict[str, str]:
    raw = fact.get("layers")
    if not isinstance(raw, dict):
        return {}
    return {str(key): value for key, value in raw.items() if isinstance(value, str)}


def _axis_verdict(fact: Mapping[str, Any], axis: str) -> str | None:
    """Resource verdict for one tri-state axis, or None when the fact is outside that axis."""
    if _evidence_only(fact):
        return None
    native = fact.get("native_type")
    if axis == "transport" and isinstance(native, str) and native.startswith("verification:"):
        return None
    layers = _layer_map(fact)
    kind = fact.get("kind")
    if axis == "at_rest":
        found = [layers[name] for name in _AT_REST_LAYERS if name in layers]
        if not found and "at_rest" in layers:
            found = [layers["at_rest"]]
        if not found:
            if layers or kind in _TRANSPORT_KINDS or kind in _NO_TRI_KINDS:
                return None
            verdict = fact.get("verdict")
            return verdict if isinstance(verdict, str) else None
    else:
        if "transport" in layers:
            return layers["transport"]
        if layers or kind not in _TRANSPORT_KINDS:
            return None
        verdict = fact.get("verdict")
        return verdict if isinstance(verdict, str) else None
    if "ENCRYPTED_DECLARED" in found:
        return "ENCRYPTED_DECLARED"
    if "ENCRYPTED_PROVIDER_DEFAULT" in found:
        return "ENCRYPTED_PROVIDER_DEFAULT"
    if "UNKNOWN" in found:
        return "UNKNOWN"
    return "NOT_ENCRYPTED"


def _tri_bucket(verdict: str) -> str | None:
    if verdict in _PASS_VERDICTS:
        return "pass_"
    if verdict == "NOT_ENCRYPTED":
        return "fail"
    if verdict == "UNKNOWN":
        return "not_bom_evidenceable"
    return None


def _finding_codes(fact: Mapping[str, Any]) -> tuple[str, ...]:
    raw = fact.get("finding_codes")
    if not isinstance(raw, list):
        return ()
    return tuple(dict.fromkeys(code for code in raw if isinstance(code, str) and code))


def _fact_impact(fact: Mapping[str, Any], codes: Sequence[str]) -> str:
    raw = fact.get("impact")
    if isinstance(raw, str):
        mapped = _IMPACT_BY_FOLD.get(raw.casefold())
        if mapped is not None:
            return mapped
    best = "Low"
    rank = {level: index for index, level in enumerate(IMPACT_LEVELS)}
    for code in codes:
        severity = _POSTURE_CODE_SEVERITY.get(code, "Medium")
        if rank[severity] < rank[best]:
            best = severity
    return best


def _rotation_of(fact: Mapping[str, Any]) -> str:
    signals = fact.get("signals") if isinstance(fact.get("signals"), dict) else {}
    attrs = fact.get("attrs") if isinstance(fact.get("attrs"), dict) else {}
    raw = signals.get("rotation", attrs.get("rotation"))
    text = raw.strip().casefold() if isinstance(raw, str) else ""
    if text in ("enabled", "true", "yes"):
        return "enabled"
    if text in ("disabled", "false", "no"):
        return "disabled"
    if text in ("not_applicable", "not applicable", "n/a", "na"):
        return "not_applicable"
    return "unknown"


def _classification_of(fact: Mapping[str, Any]) -> str | None:
    linkage = fact.get("linkage") if isinstance(fact.get("linkage"), dict) else {}
    raw = linkage.get("data_classification")
    if not isinstance(raw, str):
        return None
    cleaned = "".join(ch if ch >= " " and ch != "\x7f" else " " for ch in raw)
    text = " ".join(cleaned.split())[:128]
    return text or None


def _nested_out_of_scope(counts: Mapping[str, Any], axis: str) -> int | None:
    tri = counts.get("tri_state")
    if not isinstance(tri, dict):
        return None
    block = tri.get(axis)
    if not isinstance(block, dict):
        return None
    return _safe_int(block.get("out_of_scope"))


def _declared_from_block(counts: Mapping[str, Any]) -> dict[tuple[str, str], int] | None:
    raw = counts.get("declared_resources")
    if not isinstance(raw, list):
        return None
    found: dict[tuple[str, str], int] = {}
    for item in raw:
        if not isinstance(item, dict):
            continue
        fmt = item.get("format")
        provider = item.get("provider")
        count = _safe_int(item.get("count"))
        if isinstance(fmt, str) and isinstance(provider, str) and count is not None and count > 0:
            key = (fmt[:64], provider[:64])
            found[key] = found.get(key, 0) + count
    return found


def _coverage_fraction(passed: int, failed: int) -> float | None:
    total = passed + failed
    if total == 0:
        return None
    return round(passed / total, 3)


def _posture_counts(
    facts: Sequence[PostureFactAgg], scans: Sequence[ScanFacts]
) -> PostureCounts:
    """Recompute the team tri-state from current facts.  A missing axis is not a pass."""
    counts = PostureCounts.zero()
    counts.facts = len(facts)
    kind_counts: Counter[tuple[str, str, str]] = Counter()
    code_counts: Counter[str] = Counter()
    severity = _zero_severity()
    impact = _zero_impact()
    kms = KmsCounts()
    classes: Counter[str] = Counter()
    declared: Counter[tuple[str, str]] = Counter()
    saw_declared = False
    out_of_scope = 0
    disabled = 0
    axis_out = {"at_rest": 0, "transport": 0}
    saw_axis_out = {"at_rest": False, "transport": False}
    buckets = {
        "at_rest": {"pass_": 0, "fail": 0, "not_bom_evidenceable": 0},
        "transport": {"pass_": 0, "fail": 0, "not_bom_evidenceable": 0},
    }
    for agg in facts:
        fact = agg.fact
        kind = str(fact.get("kind") or "")
        provider = str(fact.get("provider") or "")
        verdict = str(fact.get("verdict") or "")
        kind_counts[(kind, provider, verdict)] += 1
        codes = _finding_codes(fact)
        for code in codes:
            code_counts[code] += 1
            severity[_POSTURE_CODE_SEVERITY.get(code, "Medium")] += 1
        if codes:
            impact[_fact_impact(fact, codes)] += 1
        if kind == "kms_key":
            kms.keys += 1
            slot = _rotation_of(fact)
            setattr(kms, f"rotation_{slot}", getattr(kms, f"rotation_{slot}") + 1)
        label = _classification_of(fact)
        if label is not None:
            classes[label] += 1
        fmt = fact.get("format")
        if isinstance(fmt, str) and fmt:
            declared[(fmt[:64], provider[:64])] += 1
        for axis in ("at_rest", "transport"):
            axis_verdict = _axis_verdict(fact, axis)
            if axis_verdict is None:
                continue
            bucket = _tri_bucket(axis_verdict)
            if bucket is not None:
                buckets[axis][bucket] += 1
    for scan in scans:
        block = scan.posture.counts if scan.posture is not None else {}
        if not isinstance(block, dict):
            continue
        number = _safe_int(block.get("out_of_scope_resources"))
        if number is not None:
            out_of_scope += number
        number = _safe_int(block.get("disabled_resources"))
        if number is not None:
            disabled += number
        from_block = _declared_from_block(block)
        if from_block is not None:
            saw_declared = True
            for key, count in from_block.items():
                declared[key] += count
        for axis in ("at_rest", "transport"):
            extra = _nested_out_of_scope(block, axis)
            if extra is not None:
                saw_axis_out[axis] = True
                axis_out[axis] += extra
    if saw_declared:
        declared = Counter(
            {
                key: count
                for key, count in declared.items()
                if any(
                    key in (_declared_from_block(scan.posture.counts) or {})
                    for scan in scans
                    if scan.posture is not None
                )
            }
        )
    ranked = sorted(classes.items(), key=lambda item: (-item[1], item[0]))
    classified: dict[str, int] = {}
    if len(ranked) <= POSTURE_CLASSIFICATION_CAP:
        classified = dict(ranked)
    else:
        classified = dict(ranked[:POSTURE_CLASSIFICATION_CAP])
        rest = sum(count for _, count in ranked[POSTURE_CLASSIFICATION_CAP:])
        classified["other"] = classified.get("other", 0) + rest
    tri: dict[str, TriState] = {}
    for axis in ("at_rest", "transport"):
        passed = buckets[axis]["pass_"]
        failed = buckets[axis]["fail"]
        scope = axis_out[axis] if saw_axis_out[axis] else (out_of_scope if axis == "at_rest" else 0)
        tri[axis] = TriState(
            pass_=passed,
            fail=failed,
            not_bom_evidenceable=buckets[axis]["not_bom_evidenceable"],
            out_of_scope=scope,
            coverage=_coverage_fraction(passed, failed),
        )
    counts.by_kind_provider_verdict = dict(sorted(kind_counts.items()))
    counts.tri_state = tri
    counts.findings_by_code = dict(sorted(code_counts.items()))
    counts.findings_by_severity = severity
    counts.facts_with_findings_by_impact = impact
    counts.kms = kms
    counts.by_classification = classified
    counts.declared_resources = dict(sorted(declared.items()))
    counts.out_of_scope_resources = out_of_scope
    counts.disabled_resources = disabled
    return counts


def _register_names(fact: Mapping[str, Any]) -> tuple[str, ...]:
    kind = str(fact.get("kind") or "")
    names: list[str] = []
    if kind == "kms_key":
        names.append("kms_keys")
    if kind == "tls_endpoint":
        names.append("tls_endpoints")
    if kind == "ssh_service":
        names.append("ssh")
    if kind in ("secret", "certificate_policy"):
        names.append("secrets")
    if kind == "backup":
        names.append("backups")
    if kind in (
        "object_store",
        "relational_db",
        "document_db",
        "cache",
        "block_volume",
        "disk_encryption",
        "volume",
        "database",
    ):
        names.append("data_stores")
    native = fact.get("native_type")
    verification = isinstance(native, str) and native.startswith("verification:")
    if (
        kind not in _TRANSPORT_KINDS
        and kind not in _NO_TRI_KINDS
        and kind != "secret"
        and not _evidence_only(fact)
        and not verification
    ):
        names.append("resources")
    if _finding_codes(fact):
        names.append("findings")
    if fact.get("verdict") == "UNKNOWN":
        names.append("unknown")
    return tuple(names)


def _omitted_counts(facts: Sequence[PostureFactAgg], previous_total: int) -> dict[str, int]:
    cap = POSTURE_REGISTER_CAP
    tallies: Counter[str] = Counter()
    for agg in facts:
        for name in _register_names(agg.fact):
            tallies[name] += 1
    omitted = {name: count - cap for name, count in sorted(tallies.items()) if count > cap}
    if previous_total > cap:
        omitted["previously_seen"] = previous_total - cap
    return omitted


def _source_posture_row(facts: ScanFacts, live: int) -> PostureSourceAgg:
    posture = facts.posture if facts.posture is not None else PostureScan(state="absent")
    state = posture.state
    reason: str | None
    row_state = state
    if state == "assessed":
        reason = None
    elif state == "partial":
        reason = None
    elif state == "failed":
        row_state = "not_assessed"
        reason = "lanes_failed"
    elif state == "malformed":
        row_state = "malformed"
        reason = "malformed"
    elif state == "newer_engine":
        row_state = "newer_engine"
        reason = "newer_engine"
    elif facts.source_kind == SOURCE_FILE:
        row_state = "not_assessed"
        reason = "uploaded_bom_file"
    else:
        row_state = "not_assessed"
        reason = "rescan_needed"
    totals = posture.diagnostic_totals or {}
    internal = _safe_int(totals.get("internal_error")) or 0
    zero_facts = state == "assessed" and live == 0 and internal == 0
    return PostureSourceAgg(
        key=facts.source_key,
        label=facts.source_label,
        state=row_state,
        reason=reason,
        current_scan_id=facts.scan_id,
        last_scanned=facts.created_at,
        zero_facts=zero_facts,
        truncated=posture.truncated,
        dropped=sum(posture.dropped.values()),
        lanes=posture.lanes,
        failed_lanes=posture.failed_lanes,
    )


def _finish_posture(
    accs: dict[tuple[str, str], _PostureAcc],
    sources: Mapping[str, _SourceAcc],
    attempt: Mapping[str, ScanFacts],
    now: datetime,
) -> PostureView:
    """Current facts are those in the newest assessed scan.  Older-only facts are an appendix."""
    del attempt, now  # failed-latest stays on SourceAgg; the clock belongs to the renderer
    current_facts: list[PostureFactAgg] = []
    previous: list[PostureFactAgg] = []
    rows: list[PostureSourceAgg] = []
    assessed: list[ScanFacts] = []
    for key, acc in sources.items():
        newest = acc.newest
        if newest is None or acc.newest_rank is None:
            continue
        posture = newest.posture if newest.posture is not None else PostureScan(state="absent")
        live = sum(
            1
            for ident, item in accs.items()
            if ident[0] == key and item.best_rank == acc.newest_rank
        )
        if posture.state not in ("assessed", "partial"):
            live = 0
        rows.append(_source_posture_row(newest, live))
        if posture.state in ("assessed", "partial"):
            assessed.append(newest)
    assessed_keys = {facts.source_key for facts in assessed}
    newest_rank = {
        key: acc.newest_rank
        for key, acc in sources.items()
        if acc.newest_rank is not None and key in assessed_keys
    }
    for ident, item in accs.items():
        source_key = ident[0]
        if source_key not in assessed_keys:
            continue
        is_current = item.best_rank == newest_rank.get(source_key)
        payload: Mapping[str, Any] = item.fact if is_current else _compact_posture_fact(item.fact)
        agg = PostureFactAgg(
            source_key=source_key,
            fact_id=item.fact_id,
            current=is_current,
            first_seen=item.first_seen,
            last_seen=item.last_seen,
            scan_count=item.scan_count,
            last_scan_id=item.last_scan_id,
            fact=payload,
        )
        if is_current:
            current_facts.append(agg)
        else:
            previous.append(agg)
    current_facts.sort(
        key=lambda agg: (
            agg.source_key,
            str(agg.fact.get("kind") or ""),
            str(agg.fact.get("path") or ""),
            _safe_int(agg.fact.get("line")) or 0,
            str(agg.fact.get("address") or ""),
            agg.fact_id,
        )
    )
    previous.sort(key=lambda agg: (agg.source_key, agg.fact_id))
    previous.sort(key=lambda agg: agg.last_seen, reverse=True)
    previous_total = len(previous)
    capped = tuple(previous[:POSTURE_REGISTER_CAP])
    rows.sort(key=lambda row: (row.label.casefold(), row.key))
    if not rows:
        state = "none"
    elif all(row.state in ("assessed", "partial") for row in rows):
        state = "assessed"
    elif any(row.state in ("assessed", "partial") for row in rows):
        state = "mixed"
    else:
        state = "not_assessed"
    tables: dict[str, tuple[str, str]] = {}
    diag_totals: Counter[str] = Counter()
    diagnostics: list[dict[str, Any]] = []
    imports: list[dict[str, Any]] = []
    for facts in assessed:
        posture = facts.posture
        if posture is None:
            continue
        for row in posture.data_tables:
            stamp = (row["valid_as_of"], row["data_version"])
            held = tables.get(row["name"])
            if held is None or stamp < held:
                tables[row["name"]] = stamp
        diag_totals.update(posture.diagnostic_totals)
        for item in posture.diagnostics:
            copied = dict(item)
            copied["source_label"] = facts.source_label
            diagnostics.append(copied)
        imports.extend(posture.imports)
    diagnostics.sort(
        key=lambda item: (
            str(item.get("source_label") or "").casefold(),
            str(item.get("path") or ""),
            _safe_int(item.get("line")) or 0,
            str(item.get("code") or ""),
        )
    )
    imports.sort(key=lambda item: (str(item.get("path") or ""), str(item.get("tool") or "")))
    data_tables = tuple(
        {"name": name, "data_version": version, "valid_as_of": day}
        for name, (day, version) in sorted(tables.items())
    )
    exact = accs.exact if isinstance(accs, _PostureAccs) else True
    return PostureView(
        state=state,
        sources=tuple(rows),
        facts=tuple(current_facts),
        previously_seen=capped,
        previously_seen_total=previous_total,
        imports=tuple(imports),
        diagnostic_totals=dict(sorted(diag_totals.items())),
        diagnostics=tuple(diagnostics[:POSTURE_DIAGNOSTIC_CAP]),
        data_tables=data_tables,
        counts=_posture_counts(current_facts, assessed),
        omitted=_omitted_counts(current_facts, previous_total),
        warnings=(),
        previously_seen_exact=exact,
    )


def _tls_rank(label: str) -> int | None:
    token = label.strip().casefold().replace(" ", "").replace("_", "").replace("-", "")
    token = token.removeprefix("tls").removeprefix("v") if token.startswith("tls") else token
    if token in ("sslv3", "ssl3"):
        return 0
    return _TLS_RANK.get(token) or _TLS_RANK.get(label.strip().casefold().replace(" ", ""))


def _lowest_offered(protocols: Any) -> int | None:
    pairs: list[tuple[Any, Any]] = []
    if isinstance(protocols, dict):
        pairs = list(protocols.items())
    elif isinstance(protocols, list):
        for row in protocols:
            if isinstance(row, dict):
                pairs.append((row.get("version") or row.get("protocol"), row.get("status")))
            elif isinstance(row, str):
                pairs.append((row, "offered"))
    ranks = []
    for label, status in pairs:
        if not isinstance(label, str):
            continue
        if isinstance(status, str) and status.casefold() != "offered":
            continue
        rank = _tls_rank(label)
        if rank is not None:
            ranks.append(rank)
    return min(ranks) if ranks else None


def _floor_is_higher(static_net: Mapping[str, Any], imported_net: Mapping[str, Any]) -> bool:
    floor = static_net.get("min")
    if not isinstance(floor, str):
        return False
    floor_rank = _tls_rank(floor)
    offered = _lowest_offered(imported_net.get("protocols"))
    if floor_rank is None or offered is None:
        return False
    return floor_rank > offered


def pair_endpoints(view: PostureView) -> None:
    """Link a static TLS fact to an imported result that names the same host:port string."""
    static: list[PostureFactAgg] = []
    imported: list[PostureFactAgg] = []
    for agg in view.facts:
        if agg.fact.get("kind") != "tls_endpoint":
            continue
        net = agg.fact.get("net")
        if not isinstance(net, dict):
            continue
        endpoints = net.get("endpoints")
        if isinstance(endpoints, list) and any(isinstance(item, str) for item in endpoints):
            static.append(agg)
        elif isinstance(net.get("endpoint"), str) or isinstance(net.get("endpoint_alt"), str):
            imported.append(agg)
    static.sort(key=lambda agg: (agg.source_key, agg.fact_id))
    index: dict[str, list[PostureFactAgg]] = {}
    for agg in static:
        net = agg.fact.get("net")
        if not isinstance(net, dict):
            continue
        for endpoint in net.get("endpoints") or []:
            if isinstance(endpoint, str):
                index.setdefault(endpoint, []).append(agg)
    for agg in imported:
        net = agg.fact.get("net")
        if not isinstance(net, dict):
            continue
        match: PostureFactAgg | None = None
        for key in ("endpoint", "endpoint_alt"):
            endpoint = net.get(key)
            if isinstance(endpoint, str) and endpoint in index:
                match = index[endpoint][0]
                break
        if match is None:
            continue
        agg.paired_with = f"{match.source_key}|{match.fact_id}"
        if match.paired_with is None:
            match.paired_with = f"{agg.source_key}|{agg.fact_id}"
        match_net = match.fact.get("net")
        if isinstance(match_net, dict) and _floor_is_higher(match_net, net):
            agg.discrepancy = True
            match.discrepancy = True


def posture_active(view: TeamCbomView) -> bool:
    """True when an assessed source has a current fact that carries a finding of its own."""
    posture = view.posture
    if posture.state not in ("assessed", "mixed"):
        return False
    return any(_finding_codes(agg.fact) for agg in posture.facts)


def _posture_warnings(scans: Sequence[ScanFacts]) -> tuple[str, ...]:
    lines = [
        f"scan #{facts.scan_id}: {text}"
        for facts in scans
        for text in facts.warnings
        if text.startswith("cbom_posture")
    ]
    if len(lines) > _MAX_WARNINGS:
        omitted = len(lines) - (_MAX_WARNINGS - 1)
        lines = [*lines[: _MAX_WARNINGS - 1], f"{omitted} further warnings omitted"]
    return tuple(lines)


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

    ``view.fingerprint`` = ``sha256(text.encode("utf-8")).hexdigest()[:12]`` with ``text`` =
    ``FINGERPRINT_NAMESPACE + "|" + ",".join(f"{scan_id}:{last_updated.isoformat()}" for each
    INCLUDED scan sorted by scan_id)`` (``last_updated`` tz-aware UTC).  A re-scan is a new scan
    id, so it moves the fingerprint.  An attestation upload (or delete) does NOT: the route
    rewrites ``scan_data`` and leaves ``Scan.last_updated`` alone.  So when at least one
    INCLUDED scan holds an attestation record, ``text`` also gets ``"|attestations|"`` + the
    records ``[scan_id, framework, req_id, uploaded_at]`` of all INCLUDED scans, each as compact
    ASCII JSON, sorted and joined with ``","`` (addendum A-2).  A scan set without attestation
    records keeps the previous text and therefore the previous value.  The same scan set and the
    same records give the same fingerprint whatever the order of ``heads`` or ``batch_size``.
    Every date derives from ``now``.
    """
    # one quantum-readiness definition for every CBOM view (a pure, stdlib-only module)
    from backend.utilities.cbom_sources.cbom_metrics import quantum_readiness_pct

    moment = _utc(now) or _EPOCH
    hard = _bounded(hard_max, HARD_MAX_SCANS, 0)
    batch = _bounded(batch_size, BATCH_SIZE, 1)
    window = min(_bounded(history_window, HISTORY_WINDOW, 0), hard)

    # 1. heads: tenancy + type filter (defence in depth), one ScanFacts each, newest first
    entries: list[tuple[Rank, ScanFacts]] = []
    seen_ids: set[int] = set()
    for head in heads:
        if getattr(head, "team_id", None) != team_id:
            continue
        if str(getattr(head, "scan_type", "")).strip().casefold() != "cbom":
            continue
        facts = _head_facts(head)
        if facts.scan_id in seen_ids:
            continue
        seen_ids.add(facts.scan_id)
        entries.append(((facts.created_at, facts.scan_id), facts))
    entries.sort(key=lambda entry: entry[0], reverse=True)

    excluded = {EXCLUDED_FAILURE: 0, EXCLUDED_NOT_COMPLETED: 0, EXCLUDED_NO_DATA: 0}
    attempt: dict[str, ScanFacts] = {}  # source -> its newest scan of ANY status
    for _rank, facts in entries:
        attempt.setdefault(facts.source_key, facts)
        if facts.exclusion is not None:
            excluded[facts.exclusion] += 1
    eligible = [entry for entry in entries if entry[1].exclusion is None]

    # 2. stream the blobs of eligible scans; merge each into order-independent accumulators
    assets: dict[tuple[str, str, str], _AssetAcc] = {}
    certs: dict[str, _CertAcc] = {}
    libs: dict[str, _LibAcc] = {}
    sources: dict[str, _SourceAcc] = {}
    posture_accs = _PostureAccs()
    rank_of: dict[int, Rank] = {}
    source_of: dict[int, str] = {}
    folded: list[ScanFacts] = []  # data-bearing scans
    loaded: list[ScanFacts] = []  # data-bearing + success-but-empty scans
    stamps: list[tuple[int, str, str, str]] = []  # attestation records of the folded scans

    def fold_into(rank: Rank, facts: ScanFacts) -> None:
        folded.append(facts)
        rank_of[facts.scan_id], source_of[facts.scan_id] = rank, facts.source_key
        acc = sources.setdefault(facts.source_key, _SourceAcc())
        acc.ranks.append(rank)
        if acc.newest is None or acc.newest_rank is None or rank > acc.newest_rank:
            if acc.newest is not None:  # only a source's newest scan keeps its compliance payload
                acc.newest.frameworks, acc.newest.requirements = {}, []
            acc.newest, acc.newest_rank = facts, rank
        else:
            facts.frameworks, facts.requirements = {}, []
        for asset in facts.assets:
            _merge_asset(assets, asset, rank)
        for cert in facts.certs:
            _merge_cert(certs, cert, rank)
        for lib in facts.libs:
            _merge_lib(libs, lib, rank)
        _merge_posture(posture_accs, acc, facts, rank)
        facts.assets, facts.certs, facts.libs = [], [], []

    def load(group: list[tuple[Rank, ScanFacts]]) -> None:
        found = load_blobs([facts.scan_id for _rank, facts in group])
        blobs = found if isinstance(found, Mapping) else {}
        for rank, facts in sorted(group, key=lambda entry: entry[0], reverse=True):
            blob = blobs.get(facts.scan_id)
            _safe_fill(facts, blob)
            loaded.append(facts)
            if facts.exclusion is not None:
                excluded[facts.exclusion] += 1  # success but no usable data
            else:
                fold_into(rank, facts)
                stamps.extend(_attestation_stamps(facts.scan_id, blob))  # before the blob goes

    first_pass = eligible[:window]
    for start in range(0, len(first_pass), batch):
        load(first_pass[start : start + batch])
    # beyond the window, chase ONLY the sources that still lack a data-bearing scan, one scan
    # per source per batch, so no source silently drops out of scope (plan 4.2 step 2)
    satisfied = {facts.source_key for facts in folded}
    queues: dict[str, deque[tuple[Rank, ScanFacts]]] = {}
    for entry in eligible[window:]:
        if entry[1].source_key not in satisfied:
            queues.setdefault(entry[1].source_key, deque()).append(entry)
    while queues and len(loaded) < hard:
        room = min(batch, hard - len(loaded))
        picked = [queues[key].popleft() for key in list(queues)[:room]]
        load(picked)
        for _rank, facts in picked:
            if facts.exclusion is None or not queues.get(facts.source_key):
                queues.pop(facts.source_key, None)

    # 3. finalise entities against the now-known current scan of every source
    current = {key: acc.newest for key, acc in sources.items() if acc.newest is not None}
    current_ids = {facts.scan_id for facts in current.values()}
    label_of = {key: facts.source_label for key, facts in current.items()}
    ctx = _Ctx(rank_of, source_of, current_ids, label_of, moment.date())
    asset_rows = _finish_assets(assets, ctx)
    cert_rows = _finish_certs(certs, ctx)
    lib_rows = _finish_libs(libs, ctx)

    newest_first = sorted(current.values(), key=lambda f: (f.created_at, f.scan_id), reverse=True)
    full = [facts for facts in newest_first if facts.fidelity == FIDELITY_FULL]
    legacy_excluded = len(newest_first) - len(full)
    framework_rows, requirement_rows = _pool_compliance(full, legacy_excluded)

    live = [asset for asset in asset_rows if asset.current]
    types_by_source: dict[str, Counter[str]] = {}
    impacts_by_source: dict[str, Counter[str]] = {}
    for asset in live:
        types_by_source.setdefault(asset.source_key, Counter())[asset.asset_type] += 1
        impacts_by_source.setdefault(asset.source_key, Counter())[asset.impact] += 1
    libs_by_source = Counter(key for lib in lib_rows for key in lib.current_source_keys)
    source_rows = []
    for key, acc in sources.items():
        newest, ranks, last_try = current[key], sorted(acc.ranks, reverse=True), attempt[key]
        source_rows.append(
            SourceAgg(
                key=key,
                label=newest.source_label,
                kind=newest.source_kind,
                repo_url=newest.repo_url,
                branch=newest.branch,
                scan_ids=tuple(rank[1] for rank in ranks),
                scan_count=len(ranks),
                first_scanned=ranks[-1][0],
                last_scanned=newest.created_at,
                current_scan_id=newest.scan_id,
                current_tier=newest.tier,
                current_fidelity=newest.fidelity,
                last_attempt_scan_id=last_try.scan_id,
                last_attempt_status=last_try.status,
                last_attempt_at=last_try.created_at,
                asset_counts=_ordered_counts(types_by_source.get(key, Counter()), ASSET_TYPES),
                impact_counts=_ordered_counts(impacts_by_source.get(key, Counter()), IMPACT_LEVELS),
                library_count=libs_by_source.get(key, 0),
            )
        )
    source_rows.sort(key=lambda source: (source.label.casefold(), source.key))

    # 4. headline counts: CURRENT state only, computed once so every document agrees.  Readiness is
    # cbom_metrics.quantum_readiness_pct over every asset with a verdict (the scan page's rule): the current engine
    # grades algorithms only, a legacy worker row also graded its certificates and keys.
    vulnerable = sum(1 for asset in live if asset.quantum_vulnerable is True)
    safe = sum(1 for asset in live if asset.quantum_vulnerable is False)
    hybrid = sum(1 for a in live if a.quantum_vulnerable is False and a.hybrid is True)
    ungraded_algorithms = sum(1 for a in live if a.asset_type == ASSET_ALGORITHM and a.quantum_vulnerable is None)
    codes = Counter(code for asset in live for code in asset.finding_codes)

    posture_view = _finish_posture(posture_accs, sources, attempt, moment)
    pair_endpoints(posture_view)
    posture_view = replace(posture_view, warnings=_posture_warnings(folded))

    # 5. slim per-scan facts (no payload survives), warnings, fingerprint
    loaded_ids = {facts.scan_id for facts in loaded}
    in_view = [
        facts
        for _rank, facts in entries
        if facts.exclusion in (EXCLUDED_FAILURE, EXCLUDED_NOT_COMPLETED)
        or facts.scan_id in loaded_ids
    ]
    notes = sorted(
        (facts.scan_id, index, text)
        for facts in in_view
        for index, text in enumerate(facts.warnings)
    )
    warning_text = [f"scan #{scan_id}: {text}" for scan_id, _index, text in notes]
    if len(warning_text) > _MAX_WARNINGS:
        omitted = len(warning_text) - (_MAX_WARNINGS - 1)
        warning_text = [*warning_text[: _MAX_WARNINGS - 1], f"{omitted} further warnings omitted"]
    for facts in in_view:
        facts.is_current = facts.scan_id in current_ids
        facts.assets, facts.certs, facts.libs = [], [], []
        facts.frameworks, facts.requirements, facts.warnings = {}, [], []
        if facts.posture is not None:
            facts.posture.facts = []
            facts.posture.imports = []
            facts.posture.diagnostics = []
            facts.posture.data_tables = []
    stamped = ",".join(
        f"{f.scan_id}:{f.last_updated.isoformat()}" for f in sorted(folded, key=lambda f: f.scan_id)
    )
    text = f"{FINGERPRINT_NAMESPACE}|{stamped}{_attestation_suffix(stamps)}"
    digest = hashlib.sha256(text.encode("utf-8", "replace"))
    created = [facts.created_at for facts in folded]

    return TeamCbomView(
        team_id=team_id,
        team_name=team_name if isinstance(team_name, str) else str(team_name),
        generated_at=moment,
        as_of=moment.date(),
        scans_total=len(entries),
        eligible=len(eligible),
        included=len(folded),
        excluded=excluded,
        history_truncated=len(eligible) - len(loaded),
        fidelity_full=sum(1 for facts in folded if facts.fidelity == FIDELITY_FULL),
        fidelity_reduced=sum(1 for facts in folded if facts.fidelity != FIDELITY_FULL),
        window_start=min(created) if created else None,
        window_end=max(created) if created else None,
        fingerprint=digest.hexdigest()[:12],
        scans=tuple(in_view),
        sources=tuple(source_rows),
        assets=tuple(asset_rows),
        certs=tuple(cert_rows),
        libs=tuple(lib_rows),
        frameworks=framework_rows,
        requirements=requirement_rows,
        asset_occurrences=len(live),
        assets_by_type=_ordered_counts(Counter(a.asset_type for a in live), ASSET_TYPES),
        assets_by_impact=_ordered_counts(Counter(a.impact for a in live), IMPACT_LEVELS),
        # a finding is impact != INFO (cbom_rows.is_finding): a legacy row has no finding codes and is still one
        issue_by_impact=_ordered_counts(Counter(a.impact for a in live if a.impact != INFO), IMPACT_LEVELS),
        finding_counts=dict(sorted(codes.items())),
        pqc_vulnerable=vulnerable,
        pqc_safe=safe,
        pqc_hybrid=hybrid,
        pqc_ungraded=ungraded_algorithms,
        readiness_pct=quantum_readiness_pct(vulnerable, safe + vulnerable),
        compliance_sources_pooled=len(full),
        compliance_legacy_excluded=legacy_excluded,
        warnings=tuple(warning_text),
        posture=posture_view,
    )


def load_team_cbom_view(engine: Any, team_id: int, *, now: datetime | None = None) -> TeamCbomView:
    """Load a team's CBOM scans and fold them.  The ONLY DB-touching function (plan 4.2 / 5.2).

    Pass 1 selects ``Scan`` heads (no ``scan_data``) for ``team_id`` and ``scan_type == 'cbom'``
    ordered by ``(created_at DESC, id DESC)`` and attaches ``timezone.utc`` to naive datetimes;
    pass 2 streams ``scan_data`` for the chosen ids in batches via ``fold_scans``.  Imports
    ``sqlmodel`` / ``backend.new_models`` INSIDE this function.  ``now=None`` means the current
    UTC time - the only clock read this module may make.
    """
    from sqlmodel import Session, col, select  # lazy: keeps the import closure stdlib-only

    from backend.new_models import Scan, Team

    moment = datetime.now(_UTC) if now is None else now
    # a caller-owned Session is used as is (and left open); an engine gets a short-lived one
    owner = contextlib.nullcontext(engine) if isinstance(engine, Session) else Session(engine)
    with owner as session:
        team_name = session.exec(select(Team.name).where(Team.id == team_id)).first()
        rows = session.exec(
            select(
                Scan.id, Scan.team_id, Scan.scan_type, Scan.title, Scan.scan_status,
                Scan.created_at, Scan.last_updated, Scan.scan_metadata,
            )  # pass 1: heads only, never the scan_data blob
            .where(Scan.team_id == team_id, Scan.scan_type == "cbom")
            .order_by(col(Scan.created_at).desc(), col(Scan.id).desc())
        ).all()  # fmt: skip
        heads = []
        for scan_id, owner_team, kind, title, status, created, updated, meta in rows:
            made = _utc(created) or _EPOCH  # Postgres / SQLite return naive UTC
            heads.append(
                ScanHead(
                    id=scan_id, team_id=owner_team, scan_type=kind, title=title, status=status,
                    created_at=made, last_updated=_utc(updated) or made, scan_metadata=meta,
                )  # fmt: skip
            )

        def load_blobs(ids: Sequence[int]) -> dict[int, Any]:
            # pass 2: only ids the fold asked for, still scoped to the tenant and scan type
            found = session.exec(
                select(Scan.id, Scan.scan_data).where(
                    col(Scan.id).in_(list(ids)),
                    Scan.team_id == team_id,
                    Scan.scan_type == "cbom",
                )
            ).all()
            return {scan_id: data for scan_id, data in found}

        view = fold_scans(
            heads,
            load_blobs,
            team_id=team_id,
            team_name=team_name or f"Team {team_id}",
            now=moment,
        )
        try:  # remediation waves and scan-node assets for the roadmap; a failure leaves the manual columns blank
            from backend.utilities.cbom_sources.waves import roadmap_extras

            view.remediation = roadmap_extras(session, team_id, view)
        except Exception as exc:  # pragma: no cover - defensive
            view.remediation = None
            view.warnings = (*view.warnings, f"remediation plan not loaded: {type(exc).__name__}")
        return view


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
