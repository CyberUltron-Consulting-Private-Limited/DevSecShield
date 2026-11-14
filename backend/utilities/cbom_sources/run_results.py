"""One CBOM Sources run in the shapes of the code-scan results page (CB-38 PR-2 / PR-5 / PR-7 data).

``GET /{team_id}/cbom/sources/runs/{run_id}/results`` serves this. It gives the unified results page everything the
code-scan page shows (dashboard cards and charts, crypto charts, compliance, top risks) plus the run-only views of the
architecture diagram (orphaned / unmanaged certificates, provenance per job, source and node).

Rule P (CB-38 PLAN 2.5): every readiness, PQC-class, severity-total or posture figure is taken 1:1 from
``posture.run_posture`` (called here, never re-implemented): ``card_data.quantum_readiness_score``,
``total_quantum_vulnerable``, ``severity_distribution``, ``quantum_readiness``, ``strength_distribution.quantum_safe``,
``distributions.pqc`` counts, the NIST level "0" count, ``migration_total`` and the top risks. The code lane's
``node_row`` -> ``summarize_code_rows`` path is NOT used for any of them (on the same run it reads a 128-bit XTS volume
key as weak and "broken today" and gives a lower readiness than the posture; that adapter is the team dashboard's,
OQ-4, and is not changed here).

Strength per asset (``crypto_strength``, ``total_weak_algorithms``, the weak / moderate / strong bars): from posture's
own ``pqc_class`` and the knowledge base, never from ``node_row``:
  * ``weak``: a finding code that names a classically broken or too-small algorithm, by its KB entry (CWE-326 / 327 /
    328 / 757 / 780 / 916: MD5, SHA-1, DES, RC4, RSA < 2048, old TLS / SSH ...); quantum verdict codes (KB category
    ``pqc``) and grover-weakened codes are not weaknesses;
  * ``moderate``: posture class grover-weakened (128-bit symmetric keys: quantum-safe, margin halved);
  * ``strong``: any other asset with a quantum verdict (post-quantum, hybrid, symmetric, or a classical public key that
    is sound today but quantum-vulnerable: the Quantum column says that);
  * ``not-applicable``: no verdict (not counted, as on the code page).
  ``strength_distribution.quantum_safe`` is posture's ready count (quantum-safe + hybrid + grover-weakened), so it
  equals ``quantum_readiness.quantum_safe``; it overlaps the classical-strength bars by design.

Inventory figures that carry no grade (algorithm type, certificate / key counts, OWASP and compliance controls from the
knowledge base, algorithm primitives, weakness codes, certificates, protocols) come from ONE streamed pass over the
run's non-coverage assets (``yield_per``), judged today exactly as every run view judges them (``classify.shown``).
``run_posture`` takes no clock argument and reads ``utcnow()`` itself (posture.py is not edited here), so a compute
that spans 00:00 UTC could judge posture and the inventory pass on adjacent days; ``judged_on`` is this request's day.

Caching (in-process, per worker: single flight holds within one process only; the stored ``cbomrunsummary`` of PLAN
5.2 makes it cross-process later):
  * finished runs: keyed by (run id, ``run.last_updated``, UTC day, KB version) plus an inputs digest (asset count,
    newest asset id, run status, the team risk model, which posture's quantum risk grades read); one computation at
    a time per run;
  * active runs (queued / running): one computation at a time per run as well, reused for ``LIVE_TTL_S`` seconds while
    the digest is unchanged. Above ``LIVE_MAX_ASSETS`` assets (PLAN 5.3) the request never waits: it gets the last
    computed summary (``stale: true``, its ``computed_at``) or ``state: "computing"`` while one background thread per
    run computes the next one;
  * the cache is bounded by the total number of assets its entries summarise (``CBOM_RUN_RESULTS_CACHE_ROWS``, default
    200,000), least recently used out first; a run's lock and counter leave with its entry.
Remediation status is never cached: the stable asset keys are part of the computed result (20 bytes each, one per
distinct finding asset) and the assignments are joined at request time, so a status change shows at once.
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import heapq
import json
import os
import re
import threading
import time
from collections import Counter, OrderedDict
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import func
from sqlmodel import Session, select

from backend.new_models import (
    CbomCollectedAsset,
    CbomCollectionJob,
    CbomCollectionRun,
    CbomCollectionSource,
    CbomRemediationAssignment,
    CbomScanNode,
)
from backend.utilities.build_info import current_request_id, utc_timestamp
from backend.utilities.cbom_sources import algid
from backend.utilities.cbom_sources import collections_view as CV
from backend.utilities.cbom_sources import crypto_kb
from backend.utilities.cbom_sources import identity as ID
from backend.utilities.cbom_sources import posture as POSTURE
from backend.utilities.cbom_sources.cbom_metrics import INFORMATIONAL, average_risk
from backend.utilities.cbom_sources.common import console, iso_z, utcnow

ACTIVE_STATUSES = ("queued", "running")
FRAMEWORKS = ("CERT-In", "RBI", "SEBI CSCRF", "NIST", "CNSA 2.0")
_FRAMEWORK_ALIAS = {"NSA CNSA 2.0": "CNSA 2.0"}
CALENDAR_CAP = 2_000  # certificate calendar rows: the soonest-expiring ones
EMBED_CAP = 200  # other embedded lists (migration rows, key material, orphaned, unmanaged); full lists are paged /assets
YIELD_PER = 2_000
LIVE_TTL_S = 10.0
LIVE_MAX_ASSETS = 5_000
CACHE_ROWS = int(os.environ.get("CBOM_RUN_RESULTS_CACHE_ROWS") or 200_000)
NEAR_EXPIRY_DAYS = 30
LABELS = {"orphaned": "Not presented by any endpoint probed in this run",
          "unmanaged": "No certificate manager seen for it in this run"}
_IMPACTS = ("Critical", "High", "Medium", "Low")
_IMPACT_RANK = {name: i for i, name in enumerate(_IMPACTS)}
_READY = ("quantum-safe", "hybrid", "grover-weakened")
_BROKEN_CWES = frozenset({"CWE-326", "CWE-327", "CWE-328", "CWE-757", "CWE-780", "CWE-916"})
_NOT_WEAKNESS = frozenset({"QUANTUM_VULNERABLE", "NO_PQ_KEX"})  # verdicts, not weaknesses (collections_view._NOT_WEAK)
_WEAK_SIGNATURE = frozenset({"SIG_MD5", "SIG_SHA1", "CERT_SELF_SHA1"})
_WEAK_KEY = frozenset({"RSA_LT_1024", "RSA_LT_2048", "EC_LT_224", "DH_LT_2048"})
_NETWORK_TYPES = CV.NETWORK_TYPES
_KEY_TYPES = frozenset({"private_key", "public_key", "keystore", "ssh_host_key", "ssh_user_key", "kms_key", "cloud_secret",
                        "signing_key", "host_secret"})
_PROTO = re.compile(r"^\s*(TLS|SSL|DTLS)\s*v?\s*(\d)(?:\.(\d))?\s*$", re.IGNORECASE)
_CHAIN = re.compile(r"#chain\[(\d+)\]")
_EXPIRY_BUCKETS = ("expired", "within_30_days", "within_90_days", "within_365_days", "later", "unknown")


# ----------------------------------------------------------------------------- small helpers
def _proto_label(value: Any) -> str | None:
    text = str(value or "").strip()
    if not text:
        return None
    m = _PROTO.match(text)
    if m:
        return f"{m.group(1).upper()} {m.group(2)}.{m.group(3) or '0'}"
    return text[:32]


def _framework(name: str) -> str:
    return _FRAMEWORK_ALIAS.get(name, name)


def _title(code: str) -> str:
    return (crypto_kb.entry("node", code) or {}).get("title") or code


def _managing_system(row: CbomCollectedAsset) -> str | None:
    """The certificate-managing system a certificate asset lives in (PLAN 5.6), or None."""
    location, facts = str(row.location or ""), row.facts or {}
    if row.asset_type == "k8s_certificate":
        return "cert-manager"
    if location.startswith("arn:aws:acm:"):
        return "AWS ACM"
    if location.startswith("arn:aws:acm-pca:"):
        return "AWS Private CA"
    if location.startswith("adcs://"):
        return "AD CS"
    if facts.get("provider") == "azure" and facts.get("vault"):
        return "Azure Key Vault"
    if facts.get("provider") == "gcp" or (location.startswith("projects/") and (
            "/certificateAuthorities/" in location or "/certificates/" in location)):
        return "GCP Certificate Manager"
    return None


def _chain_index(row: CbomCollectedAsset) -> int | None:
    facts = row.facts or {}
    if isinstance(facts.get("chain_index"), int) and not isinstance(facts.get("chain_index"), bool):
        return int(facts["chain_index"])
    m = _CHAIN.search(str(row.location or ""))
    return int(m.group(1)) if m else None


def _is_ca(row: CbomCollectedAsset) -> bool:
    facts = row.facts or {}
    leaf = facts.get("leaf") if isinstance(facts.get("leaf"), dict) else {}
    return bool(facts.get("is_ca") or leaf.get("is_ca")) or row.asset_type == "cloud_ca"


def _cert_identity(row: CbomCollectedAsset) -> str | None:
    facts = row.facts or {}
    leaf = facts.get("leaf") if isinstance(facts.get("leaf"), dict) else {}
    return CV.cert_identity(facts.get("subject") or leaf.get("subject"), facts.get("issuer") or leaf.get("issuer"),
                            facts.get("not_before") or leaf.get("not_before"),
                            facts.get("not_after") or leaf.get("not_after"))


def _cert_ref(row: CbomCollectedAsset, source: str | None, system: str | None) -> dict[str, Any]:
    facts = row.facts or {}
    used_by = facts.get("in_use_by")
    return {"asset_id": row.id, "subject": facts.get("subject"), "issuer": facts.get("issuer"),
            "not_after": facts.get("not_after"), "location": row.location, "target": row.target, "source": source,
            "type": row.asset_type, "managed_by": system,
            "in_use_by": [str(v) for v in used_by[:10]] if isinstance(used_by, list) else []}


def _parse_time(value: Any) -> _dt.datetime | None:
    from backend.utilities.cbom_sources.drift import parse_time

    try:
        return parse_time(value) if value else None
    except Exception:
        return None


def _bounded_push(heap: list, cap: int, key: tuple, item: Any) -> None:
    """Keep the ``cap`` items with the SMALLEST ``key`` (a max-heap on the negated key; keys are numeric tuples)."""
    entry = (tuple(-k for k in key), item)
    if len(heap) < cap:
        heapq.heappush(heap, entry)
    elif entry[0] > heap[0][0]:
        heapq.heapreplace(heap, entry)


def _drain(heap: list) -> list:
    return [item for _key, item in sorted(heap, key=lambda e: e[0], reverse=True)]


class _Memo:
    """Per-pass memo of pure knowledge-base / algid lookups (codes and algorithm texts repeat across thousands of
    assets)."""

    def __init__(self) -> None:
        self.owasp: dict[tuple[str, ...], dict[str, str]] = {}
        self.controls: dict[tuple[str, ...], dict[str, str]] = {}
        self.ident: dict[str, Any] = {}
        self.broken: dict[str, bool] = {}

    def owasp_of(self, codes: tuple[str, ...]) -> dict[str, str]:
        if codes not in self.owasp:
            self.owasp[codes] = crypto_kb.owasp_legacy("node", list(codes))
        return self.owasp[codes]

    def controls_of(self, codes: tuple[str, ...]) -> dict[str, str]:
        if codes not in self.controls:
            self.controls[codes] = crypto_kb.controls_legacy("node", list(codes))
        return self.controls[codes]

    def identity(self, text: Any) -> Any:
        key = str(text or "").strip()
        if not key:
            return None
        if key not in self.ident:
            try:
                self.ident[key] = algid.resolve(key)
            except Exception:
                self.ident[key] = None
        return self.ident[key]

    def is_broken(self, code: str) -> bool:
        """A code that names a classically broken or too-small algorithm (KB category and CWE)."""
        if code not in self.broken:
            e = crypto_kb.entry("node", code) or {}
            self.broken[code] = bool(e) and e.get("category") != "pqc" and e.get("pqc") != "grover-weakened" \
                and bool(_BROKEN_CWES.intersection(e.get("cwe") or []))
        return self.broken[code]


def strength(klass: str, codes: tuple[str, ...] | list[str], memo: _Memo | None = None) -> str:
    """Classical strength of one asset from posture's PQC class and the knowledge base (module docstring)."""
    memo = memo or _Memo()
    if any(memo.is_broken(c) for c in codes):
        return "weak"
    if klass == "grover-weakened":
        return "moderate"
    if klass in ("quantum-safe", "hybrid", "quantum-vulnerable"):
        return "strong"
    return "not-applicable"


def _algorithm_type(row: CbomCollectedAsset) -> str:
    return CV._algorithm_type(row.asset_type, row.cdx_type)


# ----------------------------------------------------------------------------- the pass and its result
@dataclass
class _Acc:
    """What the one streamed pass collects (an empty one gives the all-zero skeleton)."""

    rows: int = 0
    weak: int = 0
    certificates: int = 0
    keys: int = 0
    algorithm_types: Counter = field(default_factory=Counter)
    strengths: Counter = field(default_factory=Counter)
    owasp: Counter = field(default_factory=Counter)
    controls: Counter = field(default_factory=Counter)
    primitives: Counter = field(default_factory=Counter)
    weakness: Counter = field(default_factory=Counter)
    nist_levels: Counter = field(default_factory=Counter)  # levels of ready assets ("0" comes from posture)
    protocols: Counter = field(default_factory=Counter)
    expiry: dict = field(default_factory=lambda: {b: 0 for b in _EXPIRY_BUCKETS})
    calendar: list = field(default_factory=list)  # bounded heap, the soonest CALENDAR_CAP
    cert_total: int = 0
    key_rows: list = field(default_factory=list)
    key_total: int = 0
    migration: list = field(default_factory=list)  # bounded heap, the worst EMBED_CAP
    kb_codes: set = field(default_factory=set)
    finding_keys: dict = field(default_factory=dict)  # 20-byte stable key -> (rows << 2) | impact rank
    per_job: dict = field(default_factory=dict)
    chain_ids: set = field(default_factory=set)
    managed_ids: set = field(default_factory=set)
    managed_secrets: set = field(default_factory=set)
    cert_candidates: list = field(default_factory=list)


@dataclass
class _Computed:
    posture: dict[str, Any]
    dashboard: dict[str, Any]  # without the two remediation blocks (live)
    distributions: dict[str, Any]
    compliance: dict[str, Any]
    certificates: dict[str, Any]  # orphaned / unmanaged lists, totals, basis
    provenance: list[dict[str, Any]]
    finding_keys: dict[bytes, int]
    rows: int
    computed_at: str | None


_EMPTY_POSTURE: dict[str, Any] = {"assets": 0, "pqc_classes": {c: 0 for c in POSTURE.PQC_CLASSES},
                                  "pqc_readiness_pct": None, "impacts": {k: 0 for k in _IMPACTS}, "top_risks": [],
                                  "compliance": []}


def _job_context(session: Session, team_id: int, run_id: int) -> tuple[
        dict[int, CbomCollectionJob], dict[int, CbomCollectionSource], dict[int, CbomScanNode]]:
    jobs = {j.id: j for j in session.exec(select(CbomCollectionJob).where(
        CbomCollectionJob.team_id == team_id, CbomCollectionJob.run_id == run_id)
        .order_by(CbomCollectionJob.id)).all()}  # type: ignore[arg-type]
    sources = {s.id: s for s in session.exec(select(CbomCollectionSource).where(
        CbomCollectionSource.team_id == team_id)).all()}
    nodes = {n.id: n for n in session.exec(select(CbomScanNode).where(CbomScanNode.team_id == team_id)).all()}
    return jobs, sources, nodes  # type: ignore[return-value]


def _source_ref(job: CbomCollectionJob | None, source: CbomCollectionSource | None,
                source_id: int | None) -> tuple[str, str]:
    if job is None:
        return f"source-{source_id}", (source.name if source else "Unknown source")
    return ID.job_source_ref(job, source), ID.job_source_name(job, source)


def _add(acc: _Acc, memo: _Memo, row: CbomCollectedAsset, view: dict[str, Any], source_ref: str, source_name: str,
         now: _dt.datetime) -> None:
    counters = acc.per_job.setdefault(row.job_id, Counter())
    if row.asset_type == "coverage":
        counters["coverage"] += 1
        return
    counters["assets"] += 1
    if row.asset_type in _NETWORK_TYPES:
        counters["endpoints"] += 1
    acc.rows += 1
    facts = row.facts if isinstance(row.facts, dict) else {}
    impact = view["impact"] if view["impact"] in _IMPACT_RANK else None
    codes = tuple(c for c in view["finding_codes"] or [] if isinstance(c, str) and not c.startswith("COVERAGE_"))
    klass = POSTURE.pqc_class(row.asset_type, row.quantum_vulnerable, list(codes), facts)  # posture's own function

    a_type = _algorithm_type(row)
    acc.algorithm_types[a_type] += 1
    level = strength(klass, codes, memo)
    acc.strengths[level] += 1
    if level == "weak":
        acc.weak += 1
    if a_type == "certificate":
        acc.certificates += 1
    elif a_type == "key":
        acc.keys += 1
    if impact:
        for value in memo.owasp_of(codes).values():
            acc.owasp[value] += 1
        for value in memo.controls_of(codes).values():
            acc.controls[value] += 1
        key = bytes.fromhex(ID.stable_key("node", source_ref, ID.node_identity(row)))
        acc.finding_keys[key] = (((acc.finding_keys.get(key, 0) >> 2) + 1) << 2) | _IMPACT_RANK[impact]
        for code in codes:
            if code not in _NOT_WEAKNESS:
                acc.weakness[code] += 1

    texts = [t for t in (row.algorithm, facts.get("key_alg"), facts.get("group"), facts.get("kex"),
                         facts.get("sig_alg")) if t]
    idents = [i for i in (memo.identity(t) for t in texts) if i is not None]
    if texts:
        primitive = next((i.primitive for i in idents if i.primitive), None)
        acc.primitives[primitive or "other"] += 1

    if klass == "quantum-vulnerable":
        broken = [c for c in codes if (crypto_kb.entry("node", c) or {}).get("pqc") == "quantum-broken"]
        acc.kb_codes.update(codes)
        entry = {"name": row.name or row.algorithm or row.location, "primitive": idents[0].primitive if idents else None,
                 "key_size": None if row.key_size is None else str(row.key_size),
                 "curve": facts.get("curve") or facts.get("group"), "nist_quantum_security_level": 0,
                 # KB text is sent once in pqc.kb, keyed by code: migration_code / fix_code point there
                 "migration_target": None, "migration_roadmap": None, "suggested_fix": None,
                 "migration_code": broken[0] if broken else None, "fix_code": codes[0] if codes else None,
                 "impact": impact, "location": row.location, "bom_ref": f"zs-asset-{row.id}", "asset_id": row.id,
                 "description": view["finding"] or "", "finding_codes": list(codes)}
        _bounded_push(acc.migration, EMBED_CAP, (_IMPACT_RANK.get(impact or "", 9), int(row.id or 0)), entry)
    elif klass in _READY:
        level_pq = next((i.nist_category for i in idents if i.nist_category), None)
        if level_pq:
            acc.nist_levels[str(level_pq)] += 1

    offered = facts.get("protocols") if isinstance(facts.get("protocols"), list) else None
    if offered:
        for p in offered:
            label = _proto_label(p)
            if label:
                acc.protocols[label] += 1
    elif row.protocol and row.cdx_type == "protocol":
        label = _proto_label(row.protocol)
        if label:
            acc.protocols[label] += 1

    if ID.is_certificate(row):
        _add_certificate(acc, row, facts, codes, source_name, now)
    elif row.asset_type in _KEY_TYPES or row.cdx_type == "related-crypto-material":
        acc.key_total += 1
        if len(acc.key_rows) < EMBED_CAP:
            acc.key_rows.append({"name": row.name or row.algorithm or row.location, "material_kind": row.asset_type,
                                 "container_format": facts.get("format") or facts.get("container_format"),
                                 "parse_status": facts.get("parse_status"), "location": row.location,
                                 "bom_ref": f"zs-asset-{row.id}", "asset_id": row.id})


def _add_certificate(acc: _Acc, row: CbomCollectedAsset, facts: dict[str, Any], codes: tuple[str, ...],
                     source_name: str, now: _dt.datetime) -> None:
    leaf = facts.get("leaf") if isinstance(facts.get("leaf"), dict) else {}
    raw_after = facts.get("not_after") or leaf.get("not_after")
    when = _parse_time(raw_after)  # ISO and "%b %d %H:%M:%S %Y %Z" alike
    days = None if when is None else (when - now).total_seconds() / 86400
    bucket = ("unknown" if days is None else "expired" if days < 0 else "within_30_days"
              if days <= NEAR_EXPIRY_DAYS else "within_90_days" if days <= 90 else "within_365_days"
              if days <= 365 else "later")
    acc.expiry[bucket] += 1
    acc.cert_total += 1
    item = {"name": row.name or facts.get("subject") or row.location,
            "not_valid_after": (when.replace(microsecond=0).isoformat() + "Z") if when else raw_after,
            "self_signed": bool(facts.get("self_signed")),
            "expired": "CERT_EXPIRED" in codes or bucket == "expired",
            "near_expiry": "CERT_EXPIRES_30D" in codes or bucket == "within_30_days",
            "weak_signature": bool(_WEAK_SIGNATURE.intersection(codes)),
            "weak_key_size": bool(_WEAK_KEY.intersection(codes)),
            "signature_algorithm": facts.get("sig_alg"),
            "key_size": None if row.key_size is None else str(row.key_size),
            "location": row.location, "bom_ref": f"zs-asset-{row.id}", "asset_id": row.id, "target": row.target,
            "days_left": None if days is None else int(days // 1), "expiry_bucket": bucket, "source": source_name}
    # the soonest-expiring CALENDAR_CAP, by parsed days left (unknown dates last)
    _bounded_push(acc.calendar, CALENDAR_CAP, (1 if days is None else 0, days or 0.0, int(row.id or 0)), item)

    ident = _cert_identity(row)
    chain = _chain_index(row)
    system = _managing_system(row)
    if system:
        if ident:
            acc.managed_ids.add(ident)
        if row.asset_type == "k8s_certificate" and facts.get("namespace") and facts.get("secret"):
            acc.managed_secrets.add((str(row.target or ""), f"{facts['namespace']}/secret/{facts['secret']}"))
    if chain is not None and ident:
        acc.chain_ids.add(ident)
    if _is_ca(row) or (chain is not None and chain > 0):
        return  # trust anchors, CA certificates and chain intermediates are never listed (leaf / end-entity only)
    secret = (str(row.target or ""), str(row.location or "")) if row.asset_type == "k8s_tls_secret" else None
    acc.cert_candidates.append((ident, chain is not None, system, secret, facts.get("in_use") is True,
                                _cert_ref(row, source_name, system)))


def _certificates(acc: _Acc) -> dict[str, Any]:
    """Orphaned and unmanaged certificates within this run (PLAN 5.6), leaf / end-entity certificates only.

    * orphaned: a stored certificate (file, keystore, k8s secret, cloud store) whose identity no endpoint certificate
      of this run presents, and that its store does not report in use (ACM ``in_use``). Empty, with basis
      ``no_endpoints_probed``, when the run probed no endpoint (nothing to compare with);
    * unmanaged: a certificate that does not live in a certificate manager and whose identity / Kubernetes secret no
      manager seen in this run holds."""
    endpoints = sum(int(c["endpoints"]) for c in acc.per_job.values())
    orphaned: list[dict[str, Any]] = []
    unmanaged: list[dict[str, Any]] = []
    orphaned_total = unmanaged_total = 0
    for ident, presented, system, secret, in_use, ref in acc.cert_candidates:
        if endpoints and not presented and not in_use and ident and ident not in acc.chain_ids:
            orphaned_total += 1
            if len(orphaned) < EMBED_CAP:
                orphaned.append(ref)
        held = system is not None or (ident is not None and ident in acc.managed_ids) or \
            (secret is not None and secret in acc.managed_secrets)
        if ident and not held:
            unmanaged_total += 1
            if len(unmanaged) < EMBED_CAP:
                unmanaged.append(ref)
    return {"orphaned": orphaned, "unmanaged": unmanaged, "orphaned_total": orphaned_total,
            "unmanaged_total": unmanaged_total, "orphaned_truncated": orphaned_total > len(orphaned),
            "unmanaged_truncated": unmanaged_total > len(unmanaged),
            "basis": "endpoints_probed" if endpoints else "no_endpoints_probed"}


def _assemble(acc: _Acc, posture: dict[str, Any], top_risks: list[dict[str, Any]],
              provenance: list[dict[str, Any]], computed_at: str | None) -> _Computed:
    classes = posture["pqc_classes"]
    impacts = posture["impacts"]
    severity = {k.lower(): int(impacts.get(k, 0)) for k in _IMPACTS}
    findings = sum(severity.values())
    assets = int(posture["assets"])
    readiness = posture["pqc_readiness_pct"]
    vulnerable = int(classes.get("quantum-vulnerable", 0))
    ready = sum(int(classes.get(c, 0)) for c in _READY)
    dashboard = {
        "card_data": {
            "total_crypto_assets": assets,
            "total_crypto_vulnerabilities": findings,
            "total_informational": assets - findings,
            "total_weak_algorithms": acc.weak,
            "total_quantum_vulnerable": vulnerable,
            "total_certificates": acc.certificates,
            "total_keys": acc.keys,
            "quantum_readiness_score": 0 if readiness is None else readiness,
            "quantum_readiness_judged": readiness is not None,
            "average_risk_score": average_risk(severity),
        },
        "severity_distribution": {**severity, INFORMATIONAL: assets - findings},
        "algorithm_type_distribution": dict(sorted(acc.algorithm_types.items())),
        "strength_distribution": {"weak": acc.strengths["weak"], "moderate": acc.strengths["moderate"],
                                  "strong": acc.strengths["strong"], "quantum_safe": ready},
        "quantum_readiness": {"quantum_safe": ready, "quantum_vulnerable": vulnerable,
                              "unknown": int(classes.get("not-applicable", 0))},
        "owasp_top_10_issues": dict(sorted(acc.owasp.items())),
        "compliance_controls": dict(sorted(acc.controls.items())),
        "top_risks": top_risks,
    }
    migration = _drain(acc.migration)
    migration.sort(key=lambda r: (_IMPACT_RANK.get(r["impact"] or "", 9), str(r["name"]), r["asset_id"] or 0))
    kb: dict[str, dict[str, Any]] = {}
    for code in sorted(acc.kb_codes):
        e = crypto_kb.entry("node", code)
        if e:
            kb[code] = {"title": e.get("title"), "fix": crypto_kb.summary_fix("node", [code]),
                        "standards": list(e.get("standards") or []), "pqc": e.get("pqc")}
    levels = dict(acc.nist_levels)
    if vulnerable:
        levels["0"] = vulnerable  # Rule P: the quantum-vulnerable count is posture's
    calendar = _drain(acc.calendar)
    pqc = {"quantum_vulnerable": vulnerable, "quantum_safe": ready, "hybrid": int(classes.get("hybrid", 0)),
           "grover_weakened": int(classes.get("grover-weakened", 0)), "readiness_pct": readiness,
           "nist_level_distribution": dict(sorted(levels.items())),
           "migration": migration, "migration_total": vulnerable, "migration_truncated": vulnerable > len(migration),
           "kb": kb}
    distributions = {
        "algorithms": dict(sorted(acc.primitives.items())),
        "weakness": dict(sorted(acc.weakness.items())),
        "weakness_labels": {code: _title(code) for code in sorted(acc.weakness)},
        "pqc": pqc,
        "certificates": calendar,
        "certificates_total": acc.cert_total,
        "certificates_truncated": acc.cert_total > len(calendar),
        "certificate_expiry": dict(acc.expiry),
        "key_material": sorted(acc.key_rows, key=lambda r: (str(r["material_kind"]), str(r["name"]))),
        "key_material_total": acc.key_total,
        "key_material_truncated": acc.key_total > len(acc.key_rows),
        "protocols": dict(sorted(acc.protocols.items())),
    }
    return _Computed(posture=posture, dashboard=dashboard, distributions=distributions,
                     compliance=_compliance(posture.get("compliance") or []), certificates=_certificates(acc),
                     provenance=provenance, finding_keys=acc.finding_keys, rows=acc.rows, computed_at=computed_at)


def _duration_s(job: CbomCollectionJob) -> float | None:
    start = job.first_claimed_at or job.claimed_at
    if start is None or job.finished_at is None:
        return None
    return round(max((job.finished_at - start).total_seconds(), 0.0), 1)


def _provenance(acc: _Acc, jobs: dict, sources: dict, nodes: dict) -> list[dict[str, Any]]:
    out = []
    for job in jobs.values():
        source = sources.get(job.source_id or 0)
        node = nodes.get(job.node_id or 0)
        counts = acc.per_job.get(job.id, Counter())
        out.append({
            "job_id": job.id, "source_id": job.source_id, "source": ID.job_source_name(job, source),
            "kind": source.kind if source else (job.params or {}).get("source_kind") or job.kind,
            "job_kind": job.kind, "node": node.name if node else None, "node_id": job.node_id,
            "runner": "node" if job.node_id else "cloud",
            "status": job.status, "outcome": job.outcome, "assets": int(counts["assets"]),
            "not_collected": int(counts["coverage"]), "endpoints_probed": int(counts["endpoints"]),
            "duration_s": _duration_s(job), "credits": round((job.weight_c or 0) / 100, 2),
            "refunded": bool(job.refunded), "attempts": job.attempts})
    return out


def _compute(session: Session, run: CbomCollectionRun, team_id: int, risk_model: dict[str, Any] | None,
             now: _dt.datetime) -> _Computed:
    from backend.utilities.cbom_sources.classify import shown

    # Rule P: the one posture function, called as /runs/{id}/posture calls it (it reads its own utcnow())
    posture = POSTURE.run_posture(session, team_id=team_id, run_id=int(run.id or 0), risk_model=risk_model)
    jobs, sources, nodes = _job_context(session, team_id, int(run.id or 0))
    refs: dict[int, tuple[str, str]] = {}
    memo = _Memo()
    acc = _Acc()
    query = (select(CbomCollectedAsset)
             .where(CbomCollectedAsset.team_id == team_id, CbomCollectedAsset.run_id == run.id)
             .order_by(CbomCollectedAsset.id)  # type: ignore[arg-type]
             .execution_options(yield_per=YIELD_PER))
    for row in session.exec(query):
        ref = refs.get(row.job_id)
        if ref is None:
            job = jobs.get(row.job_id)
            ref = refs[row.job_id] = _source_ref(job, sources.get((job.source_id if job else row.source_id) or 0),
                                                 row.source_id)
        view = shown(row, now) if row.asset_type != "coverage" else {}
        _add(acc, memo, row, view, ref[0], ref[1], now)
    top = _dashboard_top_risks(session, team_id, posture.get("top_risks") or [], memo, now)
    return _assemble(acc, posture, top, _provenance(acc, jobs, sources, nodes), iso_z(now))


def _dashboard_top_risks(session: Session, team_id: int, risks: list[dict[str, Any]], memo: _Memo,
                         now: _dt.datetime) -> list[dict[str, Any]]:
    """Posture's top risks (same order, same score) in the dashboard's item shape; strength and the quantum flag by
    the same rules as the strength chart (posture class + KB)."""
    from backend.utilities.cbom_sources.classify import shown

    ids = [r["id"] for r in risks if r.get("id") is not None]
    by_id = {a.id: a for a in session.exec(select(CbomCollectedAsset).where(
        CbomCollectedAsset.team_id == team_id, CbomCollectedAsset.id.in_(ids))).all()} if ids else {}  # type: ignore[union-attr]
    out = []
    for risk in risks:
        row = by_id.get(risk.get("id"))
        item = {"algorithm_name": risk.get("name") or risk.get("location") or "", "algorithm_type": "configuration",
                "crypto_strength": "not-applicable", "quantum_safe": False, "impact": risk.get("impact"),
                "risk_score": risk.get("score"), "asset_id": risk.get("id"), "location": risk.get("location"),
                "exposure": risk.get("exposure"), "hndl": risk.get("hndl"), "source_name": risk.get("source_name"),
                "pqc_class": None}
        if row is not None:
            view = shown(row, now)
            codes = [c for c in view["finding_codes"] or [] if not str(c).startswith("COVERAGE_")]
            klass = POSTURE.pqc_class(row.asset_type, row.quantum_vulnerable, codes, row.facts or {})
            item.update({"algorithm_name": row.algorithm or row.name or item["algorithm_name"],
                         "algorithm_type": _algorithm_type(row), "crypto_strength": strength(klass, codes, memo),
                         "quantum_safe": klass in _READY, "pqc_class": klass})
        out.append(item)
    return out


def _compliance(clauses_by_framework: list[dict[str, Any]]) -> dict[str, Any]:
    """Posture's KB clause mapping grouped as the results page shows it: CERT-In, RBI, SEBI CSCRF, NIST, CNSA 2.0
    (always listed, in that order), then any other framework a newer KB adds."""
    grouped: dict[str, list[dict[str, Any]]] = {name: [] for name in FRAMEWORKS}
    for block in clauses_by_framework:
        name = _framework(str(block.get("framework") or ""))
        for clause in block.get("clauses") or []:
            grouped.setdefault(name, []).append({
                "clause": clause.get("id"), "title": clause.get("text"), "assets": int(clause.get("assets") or 0),
                "codes": list(clause.get("codes") or []), "source": clause.get("source"), "note": clause.get("note")})
    order = list(FRAMEWORKS) + sorted(n for n in grouped if n not in FRAMEWORKS)
    return {"frameworks": [{"framework": name, "clauses": grouped[name]} for name in order],
            "scope": "Knowledge-base clauses this run's findings touch (asset counts per clause)"}


# ----------------------------------------------------------------------------- live remediation join
def _remediation(session: Session, team_id: int, finding_keys: dict[bytes, int]) -> tuple[dict, dict]:
    status: dict[bytes, str] = {}
    keys = [k.hex() for k in finding_keys]
    for start in range(0, len(keys), 500):
        for key, value in session.exec(select(CbomRemediationAssignment.asset_key, CbomRemediationAssignment.status)
                                       .where(CbomRemediationAssignment.team_id == team_id,
                                              CbomRemediationAssignment.asset_key.in_(  # type: ignore[attr-defined]
                                                  keys[start:start + 500]))).all():
            status[bytes.fromhex(key)] = value or "open"
    buckets: Counter[str] = Counter()
    total = critical_fixed = backlog = 0
    for key, packed in finding_keys.items():
        count, impact = packed >> 2, _IMPACTS[packed & 3]
        state = status.get(key, "open")
        buckets[CV.REMEDIATION_BUCKET.get(state, "not_started")] += count
        total += count
        if impact == "Critical" and state == "done":
            critical_fixed += count
        if impact in ("Critical", "High") and state not in ("done", "accepted_risk"):
            backlog += count
    actions = {"total_findings": total, "total_fixed": buckets["fixed"],
               "total_in_progress": buckets["in_progress"], "total_not_started": buckets["not_started"],
               "total_ignored": buckets["ignored"]}
    # time-based metrics need the date an assignment was done (``done_at``, CB-38 PR-4); until then they are zeros
    metrics = {"mean_time_to_remediate": [0, 0, 0], "critical_issues_fixed": critical_fixed,
               "remediation_velocity": 0, "high_priority_backlog": backlog, "metrics_available": False}
    return actions, metrics


# ----------------------------------------------------------------------------- cache
@dataclass
class _Entry:
    key: tuple[Any, ...]
    digest: str
    computed: _Computed
    live: bool  # computed while the run was active
    at: float  # _monotonic() of the computation


_CACHE: "OrderedDict[int, _Entry]" = OrderedDict()
_CACHE_LOCK = threading.Lock()
_RUN_LOCKS: dict[int, threading.Lock] = {}
_BACKGROUND: dict[int, threading.Thread] = {}
COMPUTE_COUNT: Counter[int] = Counter()  # run id -> computations (tests and the bench read it)


def _monotonic() -> float:
    return time.monotonic()


def _run_lock(run_id: int) -> threading.Lock:
    with _CACHE_LOCK:
        lock = _RUN_LOCKS.get(run_id)
        if lock is None:
            lock = _RUN_LOCKS[run_id] = threading.Lock()
        return lock


def _store(run_id: int, entry: _Entry) -> None:
    """Put an entry in and evict least recently used runs while the cached rows exceed CACHE_ROWS (the newest entry
    always stays). A run's lock and counter leave with its entry unless a request holds the lock."""
    with _CACHE_LOCK:
        _CACHE[run_id] = entry
        _CACHE.move_to_end(run_id)
        total = sum(max(e.computed.rows, 1) for e in _CACHE.values())
        while total > CACHE_ROWS and len(_CACHE) > 1:
            old_id, old = _CACHE.popitem(last=False)
            total -= max(old.computed.rows, 1)
            lock = _RUN_LOCKS.get(old_id)
            if lock is not None and not lock.locked():
                _RUN_LOCKS.pop(old_id, None)
            COMPUTE_COUNT.pop(old_id, None)


def _get(run_id: int) -> _Entry | None:
    with _CACHE_LOCK:
        entry = _CACHE.get(run_id)
        if entry is not None:
            _CACHE.move_to_end(run_id)
        return entry


def clear_cache() -> None:
    with _CACHE_LOCK:
        _CACHE.clear()
        _RUN_LOCKS.clear()
        COMPUTE_COUNT.clear()


def wait_background(timeout: float = 30.0) -> None:
    """Join the background computations (tests)."""
    with _CACHE_LOCK:
        threads = list(_BACKGROUND.values())
    for t in threads:
        t.join(timeout)


def _log_summary(**fields: Any) -> None:
    """``cbom run summary run= team= rows= ms= digest= cause=`` (PLAN 5.7), one line per computation."""
    parts = [utc_timestamp(), "cbom run summary"] + [f"{k}={v}" for k, v in fields.items() if v is not None]
    request_id = current_request_id()
    if request_id:
        parts.append(f"request_id={request_id}")
    try:
        console.print(" ".join(parts), markup=False, highlight=False, soft_wrap=True)
    except Exception:  # logging must never fail a request
        pass


def _inputs(session: Session, team_id: int, run: CbomCollectionRun, judged_on: str, kb_version: str,
            risk_model: dict[str, Any] | None) -> tuple[tuple[Any, ...], str, int]:
    count, newest = session.exec(select(func.count(), func.max(CbomCollectedAsset.id)).where(
        CbomCollectedAsset.team_id == team_id, CbomCollectedAsset.run_id == run.id)).one()
    key = (int(run.id or 0), iso_z(run.last_updated), judged_on, kb_version)
    # the team risk model feeds posture's quantum risk grades (CB-19 q_grade in top_risks), so it is an input
    material = {"key": list(key), "assets": int(count or 0), "newest": int(newest or 0), "status": run.status,
                "risk_model": {k: (risk_model or {}).get(k) for k in sorted(risk_model or {})}}
    digest = hashlib.sha256(json.dumps(material, sort_keys=True, default=str).encode()).hexdigest()[:16]
    return key, digest, int(count or 0)


def _timed_compute(session: Session, run: CbomCollectionRun, team_id: int, risk_model: dict[str, Any] | None,
                   now: _dt.datetime, digest: str, cause: str) -> _Computed:
    started = time.perf_counter()
    computed = _compute(session, run, team_id, risk_model, now)
    with _CACHE_LOCK:
        COMPUTE_COUNT[int(run.id or 0)] += 1
    _log_summary(run=run.id, team=team_id, rows=computed.rows, ms=int((time.perf_counter() - started) * 1000),
                 digest=digest, cause=cause)
    return computed


def _background(engine: Any, run_id: int, team_id: int, risk_model: dict[str, Any] | None, key: tuple[Any, ...],
                digest: str, cause: str) -> None:
    try:
        with Session(engine) as session:
            run = session.get(CbomCollectionRun, run_id)
            if run is not None:
                computed = _timed_compute(session, run, team_id, risk_model, utcnow(), digest, cause)
                _store(run_id, _Entry(key=key, digest=digest, computed=computed, live=True, at=_monotonic()))
    except Exception as exc:  # a failed background summary leaves the last one in place; the next request retries
        _log_summary(run=run_id, team=team_id, cause=cause, error=type(exc).__name__)
    finally:
        with _CACHE_LOCK:
            _BACKGROUND.pop(run_id, None)


def _start_background(session: Session, run_id: int, team_id: int, risk_model: dict[str, Any] | None,
                      key: tuple[Any, ...], digest: str, cause: str) -> None:
    with _CACHE_LOCK:
        if run_id in _BACKGROUND:  # one background computation per run
            return
        thread = threading.Thread(target=_background, name=f"cbom-run-summary-{run_id}", daemon=True,
                                  args=(session.get_bind(), run_id, team_id, risk_model, key, digest, cause))
        _BACKGROUND[run_id] = thread
    thread.start()


def _skeleton() -> _Computed:
    return _assemble(_Acc(), _EMPTY_POSTURE, [], [], None)


def run_results(session: Session, run: CbomCollectionRun, *, team_id: int, risk_model: dict[str, Any] | None,
                run_detail: dict[str, Any], now: _dt.datetime | None = None) -> dict[str, Any]:
    now = now or utcnow()
    judged_on = now.date().isoformat()
    kb_version = crypto_kb.version()
    key, digest, count = _inputs(session, team_id, run, judged_on, kb_version, risk_model)
    rid = int(run.id or 0)
    active = run.status in ACTIVE_STATUSES
    state, stale = ("live" if active else "ready"), False
    with _run_lock(rid):  # single flight per run, finished or active; a second request waits, then reads the cache
        entry = _get(rid)
        if not active:
            if entry is not None and not entry.live and entry.key == key and entry.digest == digest:
                computed = entry.computed
            else:
                cause = "first" if entry is None else ("stale_day" if entry.key[2] != judged_on else "inputs")
                computed = _timed_compute(session, run, team_id, risk_model, now, digest, cause)
                _store(rid, _Entry(key=key, digest=digest, computed=computed, live=False, at=_monotonic()))
        elif entry is not None and entry.live and entry.digest == digest and _monotonic() - entry.at < LIVE_TTL_S:
            computed = entry.computed  # an active run's summary, reused while nothing changed for LIVE_TTL_S
        else:
            cause = "reopened" if entry is not None and not entry.live else "live"
            if count > LIVE_MAX_ASSETS:  # PLAN 5.3: a large active run never makes the request wait
                _start_background(session, rid, team_id, risk_model, key, digest, cause)
                if entry is not None:
                    computed, stale = entry.computed, True
                else:
                    computed, state = _skeleton(), "computing"
            else:
                computed = _timed_compute(session, run, team_id, risk_model, now, digest, cause)
                _store(rid, _Entry(key=key, digest=digest, computed=computed, live=True, at=_monotonic()))
    actions, metrics = _remediation(session, team_id, computed.finding_keys)  # never cached
    certs = computed.certificates
    return {
        "run": run_detail,
        "dashboard": {**computed.dashboard, "remediation_actions_required": actions, "remediation_metrics": metrics},
        "distributions": computed.distributions,
        "compliance": computed.compliance,
        "certificates_orphaned": certs["orphaned"],
        "certificates_unmanaged": certs["unmanaged"],
        "certificates_orphaned_total": certs["orphaned_total"],
        "certificates_unmanaged_total": certs["unmanaged_total"],
        "certificates_orphaned_truncated": certs["orphaned_truncated"],
        "certificates_unmanaged_truncated": certs["unmanaged_truncated"],
        "certificates_basis": certs["basis"],
        "certificates_labels": dict(LABELS),
        "certificates_scope": "run",
        "provenance": computed.provenance,
        "top_risks": computed.posture.get("top_risks") or [],
        "kb_version": kb_version,
        "judged_on": judged_on,
        "computed_at": computed.computed_at,
        "inputs_digest": digest,
        "state": state,
        "stale": stale,
    }


__all__ = ["ACTIVE_STATUSES", "CACHE_ROWS", "CALENDAR_CAP", "EMBED_CAP", "FRAMEWORKS", "LABELS", "LIVE_MAX_ASSETS",
           "LIVE_TTL_S", "clear_cache", "run_results", "strength", "wait_background"]
