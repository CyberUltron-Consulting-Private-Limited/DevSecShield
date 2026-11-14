"""One CBOM Sources run in the shapes of the code-scan results page (CB-38 PR-2 / PR-5 / PR-7 data).

``GET /{team_id}/cbom/sources/runs/{run_id}/results`` serves this. It gives the unified results page everything the
code-scan page shows (dashboard cards and charts, crypto charts, compliance, top risks) plus the run-only views of the
architecture diagram (orphaned / unmanaged certificates, provenance per job, source and node).

Rule P (CB-38 PLAN 2.5): every readiness, PQC-class, severity-total or posture figure is taken 1:1 from
``posture.run_posture`` (called here, never re-implemented): ``card_data.quantum_readiness_score``,
``total_quantum_vulnerable``, ``severity_distribution``, ``quantum_readiness``, ``distributions.pqc`` counts and the
top risks. The code lane's ``node_row`` -> ``summarize_code_rows`` path is NOT used for those numbers (on the same
run it reads a 128-bit XTS volume key as "broken today" and gives a lower readiness than the posture).

Inventory figures that carry no grade (algorithm type, strength label, certificate / key counts, OWASP and compliance
controls from the knowledge base, algorithm primitives, weakness codes, certificates, protocols) come from ONE streamed
pass over the run's non-coverage assets (``yield_per``), judged today exactly as every run view judges them
(``classify.shown``) and written in the code-scan vocabulary by ``collections_view.node_row``.

Caching: the computed part is kept in-process per run, keyed by (run id, run.last_updated, UTC day, KB version) plus an
inputs digest (asset count, newest asset id, the team's risk model), one computation at a time per run (single-flight
lock). While the run is queued or running nothing is cached (``state: "live"``). Remediation status is never cached:
the stable asset keys are part of the computed result and the assignments are joined at request time, so a status
change shows at once.
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import heapq
import json
import re
import threading
import time
from collections import Counter, OrderedDict
from dataclasses import dataclass
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
from backend.utilities.cbom_sources import algid
from backend.utilities.cbom_sources import collections_view as CV
from backend.utilities.cbom_sources import crypto_kb
from backend.utilities.cbom_sources import identity as ID
from backend.utilities.cbom_sources import posture as POSTURE
from backend.utilities.cbom_sources.cbom_metrics import INFORMATIONAL, average_risk
from backend.utilities.cbom_sources.common import iso_z, log, utcnow

ACTIVE_STATUSES = ("queued", "running")
FRAMEWORKS = ("CERT-In", "RBI", "SEBI CSCRF", "NIST", "CNSA 2.0")
_FRAMEWORK_ALIAS = {"NSA CNSA 2.0": "CNSA 2.0"}
LIST_CAP = 2_000  # rows per list (certificates, key material, migration rows, orphaned, unmanaged)
YIELD_PER = 2_000
CACHE_RUNS = 256
NEAR_EXPIRY_DAYS = 30
_IMPACT_RANK = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
_STRENGTHS = ("weak", "moderate", "strong", "quantum_safe")  # the code lane's strength_distribution keys
_NOT_WEAKNESS = frozenset({"QUANTUM_VULNERABLE", "NO_PQ_KEX"})  # verdicts, not weaknesses (collections_view._NOT_WEAK)
_WEAK_SIGNATURE = frozenset({"SIG_MD5", "SIG_SHA1", "CERT_SELF_SHA1"})
_WEAK_KEY = frozenset({"RSA_LT_1024", "RSA_LT_2048", "EC_LT_224", "DH_LT_2048"})
_NETWORK_TYPES = CV.NETWORK_TYPES
_KEY_TYPES = frozenset({"private_key", "public_key", "keystore", "ssh_host_key", "ssh_user_key", "kms_key", "cloud_secret",
                        "signing_key", "host_secret"})
_PROTO = re.compile(r"^\s*(TLS|SSL|DTLS)\s*v?\s*(\d)(?:\.(\d))?\s*$", re.IGNORECASE)
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


def _cert_identity(row: CbomCollectedAsset) -> str | None:
    facts = row.facts or {}
    leaf = facts.get("leaf") if isinstance(facts.get("leaf"), dict) else {}
    return CV.cert_identity(facts.get("subject") or leaf.get("subject"), facts.get("issuer") or leaf.get("issuer"),
                            facts.get("not_before") or leaf.get("not_before"),
                            facts.get("not_after") or leaf.get("not_after"))


def _cert_ref(row: CbomCollectedAsset, source: str | None) -> dict[str, Any]:
    facts = row.facts or {}
    return {"asset_id": row.id, "subject": facts.get("subject"), "issuer": facts.get("issuer"),
            "not_after": facts.get("not_after"), "location": row.location, "target": row.target, "source": source,
            "type": row.asset_type}


def _parse_time(value: Any) -> _dt.datetime | None:
    from backend.utilities.cbom_sources.drift import parse_time

    try:
        return parse_time(value) if value else None
    except Exception:
        return None


class _Memo:
    """Per-pass memo of pure knowledge-base / algid lookups (codes and algorithm texts repeat across thousands of
    assets)."""

    def __init__(self) -> None:
        self.owasp: dict[tuple[str, ...], dict[str, str]] = {}
        self.controls: dict[tuple[str, ...], dict[str, str]] = {}
        self.ident: dict[str, Any] = {}
        self.titles: dict[str, str] = {}
        self.migration: dict[tuple[str, ...], tuple[str | None, str | None, str | None]] = {}

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

    def title(self, code: str) -> str:
        if code not in self.titles:
            self.titles[code] = (crypto_kb.entry("node", code) or {}).get("title") or code
        return self.titles[code]

    def migration_of(self, codes: tuple[str, ...]) -> tuple[str | None, str | None, str | None]:
        """(target, roadmap, suggested fix) from the knowledge base: the standards and the fix of the codes whose KB
        ``pqc`` field marks them quantum-broken, and the fix of the most important code."""
        if codes not in self.migration:
            broken = [c for c in codes if (crypto_kb.entry("node", c) or {}).get("pqc") == "quantum-broken"]
            standards: list[str] = []
            for code in broken:
                for s in (crypto_kb.entry("node", code) or {}).get("standards") or []:
                    if s not in standards:
                        standards.append(s)
            self.migration[codes] = ("; ".join(standards) or None,
                                     crypto_kb.summary_fix("node", broken) if broken else None,
                                     crypto_kb.summary_fix("node", list(codes)))
        return self.migration[codes]


# ----------------------------------------------------------------------------- the computed (cacheable) part
@dataclass
class _Computed:
    posture: dict[str, Any]
    dashboard: dict[str, Any]  # without the two remediation blocks (live)
    distributions: dict[str, Any]
    compliance: dict[str, Any]
    certificates_orphaned: list[dict[str, Any]]
    certificates_unmanaged: list[dict[str, Any]]
    certificates_orphaned_total: int
    certificates_unmanaged_total: int
    provenance: list[dict[str, Any]]
    finding_keys: list[tuple[str, str]]  # (stable asset key, today's impact) per finding row, for the live join
    rows: int
    computed_at: str


def _job_context(session: Session, team_id: int, run: CbomCollectionRun) -> tuple[
        dict[int, CbomCollectionJob], dict[int, CbomCollectionSource], dict[int, CbomScanNode]]:
    jobs = {j.id: j for j in session.exec(select(CbomCollectionJob).where(
        CbomCollectionJob.team_id == team_id, CbomCollectionJob.run_id == run.id)
        .order_by(CbomCollectionJob.id)).all()}  # type: ignore[arg-type]
    sources = {s.id: s for s in session.exec(select(CbomCollectionSource).where(
        CbomCollectionSource.team_id == team_id)).all()}
    nodes = {n.id: n for n in session.exec(select(CbomScanNode).where(CbomScanNode.team_id == team_id)).all()}
    return jobs, sources, nodes  # type: ignore[return-value]


def _collection(run: CbomCollectionRun, job: CbomCollectionJob | None, source: CbomCollectionSource | None,
                source_id: int | None) -> CV.Collection:
    if job is None:
        return CV.Collection(run_id=int(run.id or 0), job_id=0, source_ref=f"source-{source_id}",
                             source_name=source.name if source else "Unknown source",
                             source_kind=source.kind if source else "",
                             observed_at=CV._aware(run.finished_at or run.created_at))
    return CV.Collection(run_id=int(run.id or 0), job_id=int(job.id or 0), source_ref=ID.job_source_ref(job, source),
                         source_name=ID.job_source_name(job, source), source_kind=source.kind if source else "",
                         observed_at=CV._aware(job.finished_at or job.created_at))


def _duration_s(job: CbomCollectionJob) -> float | None:
    start = job.first_claimed_at or job.claimed_at
    if start is None or job.finished_at is None:
        return None
    return round(max((job.finished_at - start).total_seconds(), 0.0), 1)


def _compute(session: Session, run: CbomCollectionRun, team_id: int, risk_model: dict[str, Any] | None,
             now: _dt.datetime) -> _Computed:
    from backend.utilities.cbom_sources.classify import shown

    # Rule P: the one posture function, called as /runs/{id}/posture calls it
    posture = POSTURE.run_posture(session, team_id=team_id, run_id=int(run.id or 0), risk_model=risk_model)
    jobs, sources, nodes = _job_context(session, team_id, run)
    collections: dict[int, CV.Collection] = {}
    memo = _Memo()

    algorithm_types: Counter[str] = Counter()
    strengths = {s: 0 for s in _STRENGTHS}
    owasp: Counter[str] = Counter()
    controls: Counter[str] = Counter()
    weak = certificates = keys = rows = findings = 0
    primitives: Counter[str] = Counter()
    weakness: Counter[str] = Counter()
    nist_levels: Counter[str] = Counter()
    protocols: Counter[str] = Counter()
    expiry = {b: 0 for b in _EXPIRY_BUCKETS}
    cert_rows: list[dict[str, Any]] = []
    key_rows: list[dict[str, Any]] = []
    migration: list[tuple[tuple[int, str, str], dict[str, Any]]] = []  # bounded heap of the best LIST_CAP rows
    migration_total = 0
    finding_keys: list[tuple[str, str]] = []
    per_job: dict[int | None, Counter[str]] = {}
    # orphaned / unmanaged certificates (within this run)
    chain_ids: set[str] = set()
    managed_ids: set[str] = set()
    managed_secrets: set[tuple[str, str]] = set()  # (target, "<ns>/secret/<name>") a cert-manager Certificate owns
    cert_candidates: list[tuple[str | None, bool, str | None, tuple[str, str] | None, dict[str, Any]]] = []

    query = (select(CbomCollectedAsset)
             .where(CbomCollectedAsset.team_id == team_id, CbomCollectedAsset.run_id == run.id)
             .order_by(CbomCollectedAsset.id)  # type: ignore[arg-type]
             .execution_options(yield_per=YIELD_PER))
    for row in session.exec(query):
        counters = per_job.setdefault(row.job_id, Counter())
        if row.asset_type == "coverage":
            counters["coverage"] += 1
            continue
        counters["assets"] += 1
        if row.asset_type in _NETWORK_TYPES:
            counters["endpoints"] += 1
        rows += 1
        facts = row.facts if isinstance(row.facts, dict) else {}
        job = jobs.get(row.job_id)
        source = sources.get((job.source_id if job else row.source_id) or 0)
        coll = collections.get(row.job_id)
        if coll is None:
            coll = collections[row.job_id] = _collection(run, job, source, row.source_id)
        view = shown(row, now)  # date-based findings judged today, as posture and every run view judge them
        impact = view["impact"] if view["impact"] in _IMPACT_RANK else None
        codes = tuple(c for c in view["finding_codes"] or [] if isinstance(c, str) and not c.startswith("COVERAGE_"))
        code_row = CV.node_row(row, coll, {"impact": impact, "finding_codes": list(codes), "finding": view["finding"]})

        # dashboard inventory (code-lane vocabulary; no readiness, class or severity here)
        algorithm_types[code_row["algorithm_type"]] += 1
        if code_row["crypto_strength"] in strengths:
            strengths[code_row["crypto_strength"]] += 1
        if code_row["weak"]:
            weak += 1
        if code_row["algorithm_type"] == "certificate":
            certificates += 1
        elif code_row["algorithm_type"] == "key":
            keys += 1
        if impact:
            findings += 1
            for value in memo.owasp_of(codes).values():
                owasp[value] += 1
            for value in memo.controls_of(codes).values():
                controls[value] += 1
            finding_keys.append((ID.stable_key("node", coll.source_ref, ID.node_identity(row)), impact))
            for code in codes:
                if code not in _NOT_WEAKNESS:
                    weakness[code] += 1

        # algorithms by primitive (algid is the one name table)
        texts = [t for t in (row.algorithm, facts.get("key_alg"), facts.get("group"), facts.get("kex"),
                             facts.get("sig_alg")) if t]
        if texts:
            primitive = next((ident.primitive for ident in (memo.identity(t) for t in texts)
                              if ident is not None and ident.primitive), None)
            primitives[primitive or "other"] += 1

        # PQC: the class is posture's own function; counts are posture's (below), rows and levels are listings
        klass = POSTURE.pqc_class(row.asset_type, row.quantum_vulnerable, list(codes), facts)
        if klass == "quantum-vulnerable":
            nist_levels["0"] += 1
            migration_total += 1
            target, roadmap, fix = memo.migration_of(codes)
            ident = next((memo.identity(t) for t in texts if memo.identity(t) is not None), None)
            entry = {"name": row.name or row.algorithm or row.location, "primitive": ident.primitive if ident else None,
                     "key_size": None if row.key_size is None else str(row.key_size),
                     "curve": facts.get("curve") or facts.get("group"), "nist_quantum_security_level": 0,
                     "migration_target": target, "migration_roadmap": roadmap, "impact": impact,
                     "location": row.location, "bom_ref": f"zs-asset-{row.id}", "asset_id": row.id,
                     "description": view["finding"] or "", "suggested_fix": fix, "finding_codes": list(codes)}
            rank = (_IMPACT_RANK.get(impact or "", 9), str(entry["name"]), entry["bom_ref"])
            # keep the LIST_CAP best by (impact, name, ref): a max-heap on the negated key
            item = (tuple(-x if isinstance(x, int) else _neg(x) for x in rank), entry)
            if len(migration) < LIST_CAP:
                heapq.heappush(migration, item)  # type: ignore[arg-type]
            elif item[0] > migration[0][0]:
                heapq.heapreplace(migration, item)  # type: ignore[arg-type]
        elif klass in ("quantum-safe", "hybrid", "grover-weakened"):
            level = next((ident.nist_category for ident in (memo.identity(t) for t in texts)
                          if ident is not None and ident.nist_category), None)
            if level:
                nist_levels[str(level)] += 1

        # protocols offered
        offered = facts.get("protocols") if isinstance(facts.get("protocols"), list) else None
        if offered:
            for p in offered:
                label = _proto_label(p)
                if label:
                    protocols[label] += 1
        elif row.protocol and row.cdx_type == "protocol":
            label = _proto_label(row.protocol)
            if label:
                protocols[label] += 1

        # certificates (expiry buckets over all; rows capped)
        if ID.is_certificate(row):
            leaf = facts.get("leaf") if isinstance(facts.get("leaf"), dict) else {}
            raw_after = facts.get("not_after") or leaf.get("not_after")
            when = _parse_time(raw_after)
            days = None if when is None else (when.replace(tzinfo=None) - now).total_seconds() / 86400
            bucket = ("unknown" if days is None else "expired" if days < 0 else "within_30_days"
                      if days <= NEAR_EXPIRY_DAYS else "within_90_days" if days <= 90 else "within_365_days"
                      if days <= 365 else "later")
            expiry[bucket] += 1
            if len(cert_rows) < LIST_CAP:
                cert_rows.append({
                    "name": row.name or facts.get("subject") or row.location,
                    "not_valid_after": raw_after, "self_signed": bool(facts.get("self_signed")),
                    "expired": "CERT_EXPIRED" in codes or bucket == "expired",
                    "near_expiry": "CERT_EXPIRES_30D" in codes or bucket == "within_30_days",
                    "weak_signature": bool(_WEAK_SIGNATURE.intersection(codes)),
                    "weak_key_size": bool(_WEAK_KEY.intersection(codes)),
                    "signature_algorithm": facts.get("sig_alg"),
                    "key_size": None if row.key_size is None else str(row.key_size),
                    "location": row.location, "bom_ref": f"zs-asset-{row.id}", "asset_id": row.id,
                    "target": row.target, "days_left": None if days is None else int(days // 1),
                    "expiry_bucket": bucket, "source": coll.source_name})
            ident_c = _cert_identity(row)
            in_chain = "#chain[" in str(row.location or "")
            system = _managing_system(row)
            if system:
                if ident_c:
                    managed_ids.add(ident_c)
                if row.asset_type == "k8s_certificate" and facts.get("namespace") and facts.get("secret"):
                    managed_secrets.add((str(row.target or ""), f"{facts['namespace']}/secret/{facts['secret']}"))
            if in_chain and ident_c:
                chain_ids.add(ident_c)
            secret = (str(row.target or ""), str(row.location or "")) if row.asset_type == "k8s_tls_secret" else None
            cert_candidates.append((ident_c, in_chain, system, secret, _cert_ref(row, coll.source_name)))
        elif row.asset_type in _KEY_TYPES or row.cdx_type == "related-crypto-material":
            if len(key_rows) < LIST_CAP:
                key_rows.append({"name": row.name or row.algorithm or row.location, "material_kind": row.asset_type,
                                 "container_format": facts.get("format") or facts.get("container_format"),
                                 "parse_status": facts.get("parse_status"), "location": row.location,
                                 "bom_ref": f"zs-asset-{row.id}", "asset_id": row.id})

    # orphaned: a stored certificate no endpoint of this run presents; unmanaged: no managing system holds it
    orphaned: list[dict[str, Any]] = []
    unmanaged: list[dict[str, Any]] = []
    orphaned_total = unmanaged_total = 0
    for ident_c, in_chain, system, secret, ref in cert_candidates:
        if not in_chain and ident_c and ident_c not in chain_ids:
            orphaned_total += 1
            if len(orphaned) < LIST_CAP:
                orphaned.append({**ref, "managed_by": system})
        held = system is not None or (ident_c is not None and ident_c in managed_ids) or \
            (secret is not None and secret in managed_secrets)
        if ident_c and not held:
            unmanaged_total += 1
            if len(unmanaged) < LIST_CAP:
                unmanaged.append(ref)

    # ---------------------------------------------------------------- dashboard (Rule P figures from posture)
    classes = posture["pqc_classes"]
    impacts = posture["impacts"]
    severity = {k.lower(): int(impacts.get(k, 0)) for k in ("Critical", "High", "Medium", "Low")}
    posture_findings = sum(severity.values())
    readiness = posture["pqc_readiness_pct"]
    vulnerable = int(classes.get("quantum-vulnerable", 0))
    ready = int(classes.get("quantum-safe", 0)) + int(classes.get("hybrid", 0)) + int(classes.get("grover-weakened", 0))
    dashboard = {
        "card_data": {
            "total_crypto_assets": int(posture["assets"]),
            "total_crypto_vulnerabilities": posture_findings,
            "total_informational": int(posture["assets"]) - posture_findings,
            "total_weak_algorithms": weak,
            "total_quantum_vulnerable": vulnerable,
            "total_certificates": certificates,
            "total_keys": keys,
            "quantum_readiness_score": 0 if readiness is None else readiness,
            "quantum_readiness_judged": readiness is not None,
            "average_risk_score": average_risk(severity),
        },
        "severity_distribution": {**severity, INFORMATIONAL: int(posture["assets"]) - posture_findings},
        "algorithm_type_distribution": dict(sorted(algorithm_types.items())),
        "strength_distribution": strengths,
        "quantum_readiness": {"quantum_safe": ready, "quantum_vulnerable": vulnerable,
                              "unknown": int(classes.get("not-applicable", 0))},
        "owasp_top_10_issues": dict(sorted(owasp.items())),
        "compliance_controls": dict(sorted(controls.items())),
        "top_risks": _dashboard_top_risks(session, team_id, run, posture.get("top_risks") or [], collections, now),
    }

    pqc = {"quantum_vulnerable": vulnerable, "quantum_safe": ready, "hybrid": int(classes.get("hybrid", 0)),
           "grover_weakened": int(classes.get("grover-weakened", 0)), "readiness_pct": readiness,
           "nist_level_distribution": dict(sorted(nist_levels.items())),
           "migration": [entry for _key, entry in sorted(migration, key=lambda it: it[0], reverse=True)],
           "migration_total": migration_total, "migration_truncated": migration_total > len(migration)}
    distributions = {
        "algorithms": dict(sorted(primitives.items())),
        "weakness": dict(sorted(weakness.items())),
        "weakness_labels": {code: memo.title(code) for code in sorted(weakness)},
        "pqc": pqc,
        "certificates": sorted(cert_rows, key=lambda r: (str(r["not_valid_after"] or "~"), r["asset_id"] or 0)),
        "certificate_expiry": expiry,
        "certificates_truncated": certificates > len(cert_rows),
        "key_material": sorted(key_rows, key=lambda r: (str(r["material_kind"]), str(r["name"]))),
        "protocols": dict(sorted(protocols.items())),
    }

    provenance = []
    for job in jobs.values():
        source = sources.get(job.source_id or 0)
        node = nodes.get(job.node_id or 0)
        counts = per_job.get(job.id, Counter())
        provenance.append({
            "job_id": job.id, "source_id": job.source_id, "source": ID.job_source_name(job, source),
            "kind": source.kind if source else (job.params or {}).get("source_kind") or job.kind,
            "job_kind": job.kind, "node": node.name if node else None, "node_id": job.node_id,
            "runner": "node" if job.node_id else ("cloud" if job.kind == "collect" else "node"),
            "status": job.status, "outcome": job.outcome, "assets": int(counts["assets"]),
            "not_collected": int(counts["coverage"]), "endpoints_probed": int(counts["endpoints"]),
            "duration_s": _duration_s(job), "credits": round((job.weight_c or 0) / 100, 2),
            "refunded": bool(job.refunded), "attempts": job.attempts})

    return _Computed(posture=posture, dashboard=dashboard, distributions=distributions,
                     compliance=_compliance(posture.get("compliance") or []),
                     certificates_orphaned=orphaned, certificates_unmanaged=unmanaged,
                     certificates_orphaned_total=orphaned_total, certificates_unmanaged_total=unmanaged_total,
                     provenance=provenance, finding_keys=finding_keys, rows=rows, computed_at=iso_z(now) or "")


def _neg(text: str) -> tuple[int, ...]:
    """A key that sorts text in reverse (for the bounded max-heap of migration rows)."""
    return tuple(-ord(ch) for ch in text) + (1,)


def _dashboard_top_risks(session: Session, team_id: int, run: CbomCollectionRun, risks: list[dict[str, Any]],
                         collections: dict[int, CV.Collection], now: _dt.datetime) -> list[dict[str, Any]]:
    """Posture's top risks (same order, same score) in the dashboard's item shape."""
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
                "exposure": risk.get("exposure"), "hndl": risk.get("hndl"), "source_name": risk.get("source_name")}
        if row is not None:
            coll = collections.get(row.job_id) or _collection(run, None, None, row.source_id)
            view = shown(row, now)
            code_row = CV.node_row(row, coll, {"impact": view["impact"], "finding": view["finding"],
                                               "finding_codes": [c for c in view["finding_codes"] or []
                                                                 if not str(c).startswith("COVERAGE_")]})
            item.update({"algorithm_name": row.algorithm or row.name or item["algorithm_name"],
                         "algorithm_type": code_row["algorithm_type"], "crypto_strength": code_row["crypto_strength"],
                         "quantum_safe": bool(code_row["quantum_safe"])})
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
def _remediation(session: Session, team_id: int, finding_keys: list[tuple[str, str]]) -> tuple[dict, dict]:
    status: dict[str, str] = {}
    keys = list(dict.fromkeys(k for k, _impact in finding_keys))
    for start in range(0, len(keys), 500):
        for key, value in session.exec(select(CbomRemediationAssignment.asset_key, CbomRemediationAssignment.status)
                                       .where(CbomRemediationAssignment.team_id == team_id,
                                              CbomRemediationAssignment.asset_key.in_(  # type: ignore[attr-defined]
                                                  keys[start:start + 500]))).all():
            status[key] = value or "open"
    buckets = Counter(CV.REMEDIATION_BUCKET.get(status.get(k, "open"), "not_started") for k, _i in finding_keys)
    critical_fixed = sum(1 for k, impact in finding_keys if impact == "Critical" and status.get(k) == "done")
    backlog = sum(1 for k, impact in finding_keys
                  if impact in ("Critical", "High") and status.get(k, "open") not in ("done", "accepted_risk"))
    actions = {"total_findings": len(finding_keys), "total_fixed": buckets["fixed"],
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


_CACHE: "OrderedDict[int, _Entry]" = OrderedDict()
_CACHE_LOCK = threading.Lock()
_RUN_LOCKS: dict[int, threading.Lock] = {}
COMPUTE_COUNT = Counter()  # run id -> computations (tests and the bench read it)


def _run_lock(run_id: int) -> threading.Lock:
    with _CACHE_LOCK:
        lock = _RUN_LOCKS.get(run_id)
        if lock is None:
            lock = _RUN_LOCKS[run_id] = threading.Lock()
        return lock


def clear_cache() -> None:
    with _CACHE_LOCK:
        _CACHE.clear()
        _RUN_LOCKS.clear()
        COMPUTE_COUNT.clear()


def _inputs(session: Session, team_id: int, run: CbomCollectionRun, risk_model: dict[str, Any] | None,
            judged_on: str, kb_version: str) -> tuple[tuple[Any, ...], str]:
    count, newest = session.exec(select(func.count(), func.max(CbomCollectedAsset.id)).where(
        CbomCollectedAsset.team_id == team_id, CbomCollectedAsset.run_id == run.id)).one()
    key = (int(run.id or 0), iso_z(run.last_updated), judged_on, kb_version)
    material = {"key": list(key), "assets": int(count or 0), "newest": int(newest or 0), "status": run.status,
                "risk_model": {k: (risk_model or {}).get(k) for k in sorted(risk_model or {})}}
    digest = hashlib.sha256(json.dumps(material, sort_keys=True, default=str).encode()).hexdigest()[:16]
    return key, digest


def run_results(session: Session, run: CbomCollectionRun, *, team_id: int, risk_model: dict[str, Any] | None,
                run_detail: dict[str, Any], now: _dt.datetime | None = None) -> dict[str, Any]:
    now = now or utcnow()
    judged_on = now.date().isoformat()
    kb_version = crypto_kb.version()
    key, digest = _inputs(session, team_id, run, risk_model, judged_on, kb_version)
    live = run.status in ACTIVE_STATUSES
    computed: _Computed | None = None
    cause: str | None = None
    started = time.perf_counter()
    if live:
        cause = "live"
        computed = _compute(session, run, team_id, risk_model, now)
    else:
        with _run_lock(int(run.id or 0)):  # single flight: a second request waits, then reads the cache
            with _CACHE_LOCK:
                entry = _CACHE.get(int(run.id or 0))
                if entry is not None:
                    _CACHE.move_to_end(int(run.id or 0))
            if entry is not None and entry.key == key and entry.digest == digest:
                computed = entry.computed
            else:
                cause = "first" if entry is None else ("stale_day" if entry.key[2] != judged_on else "inputs")
                computed = _compute(session, run, team_id, risk_model, now)
                with _CACHE_LOCK:
                    _CACHE[int(run.id or 0)] = _Entry(key=key, digest=digest, computed=computed)
                    _CACHE.move_to_end(int(run.id or 0))
                    while len(_CACHE) > CACHE_RUNS:
                        _CACHE.popitem(last=False)
    if cause is not None:
        with _CACHE_LOCK:
            COMPUTE_COUNT[int(run.id or 0)] += 1
        log("run results", run=run.id, team=team_id, rows=computed.rows,
            ms=int((time.perf_counter() - started) * 1000), cause=cause, digest=digest)
    actions, metrics = _remediation(session, team_id, computed.finding_keys)  # never cached
    return {
        "run": run_detail,
        "dashboard": {**computed.dashboard, "remediation_actions_required": actions, "remediation_metrics": metrics},
        "distributions": computed.distributions,
        "compliance": computed.compliance,
        "certificates_orphaned": computed.certificates_orphaned,
        "certificates_unmanaged": computed.certificates_unmanaged,
        "certificates_orphaned_total": computed.certificates_orphaned_total,
        "certificates_unmanaged_total": computed.certificates_unmanaged_total,
        "certificates_scope": "run",
        "provenance": computed.provenance,
        "top_risks": computed.posture.get("top_risks") or [],
        "kb_version": kb_version,
        "judged_on": judged_on,
        "computed_at": computed.computed_at,
        "inputs_digest": digest,
        "state": "live" if live else "ready",
        "stale": False,
    }


__all__ = ["ACTIVE_STATUSES", "FRAMEWORKS", "LIST_CAP", "clear_cache", "run_results"]
