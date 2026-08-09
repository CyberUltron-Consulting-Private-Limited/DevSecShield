"""CBOM normalizer (C8): a scored crypto ``ScanResult`` -> the API run-object.

The peer of :func:`aibom.integrations.devsecshield.normalize` for the crypto
lane. It shapes a scanned + scored + compliance-mapped CBOM ``ScanResult`` into
the dict the DevSecShield frontend renders on the CBOM results page, carrying
**through** — never flattening — the per-asset severity, the five chart
distributions (algorithm / weak-crypto / PQC readiness / certificate-expiry /
protocol-TLS), the crypto dependency graph (``cbom_graph``, the normalized peer
of the AIBOM ``ai_bom_graph``), the tri-state compliance breakdown, and the
scores.

Pure + deterministic for a given ``ScanResult`` (``duration_of_scan`` aside): it
reads the EXPIRED_CERTIFICATE flag the scanner already computed rather than
re-evaluating "now", so identical input -> identical output. Lane discipline: it
computes no scores and raises no flags; it only reads + reshapes.
"""

from __future__ import annotations

import json
from typing import Any

from aibom.cbom.pqc import QUANTUM_VULNERABLE
from aibom.cbom.weakness import (
    CERT_NEAR_EXPIRY,
    EXPIRED_CERTIFICATE,
    WEAK_CERT_KEY_SIZE,
    WEAK_CERT_SIGNATURE,
    WEAK_CRYPTO_CODES,
)
from aibom.emit import get_reporter
from aibom.graph_view import (
    COMPACT_MAX_NODES,
    EXPANDED_MAX_NODES,
    build_graph_view,
    compact_cbom_graph,
)
from aibom.model.component import AIComponent
from aibom.model.result import ScanResult

# A crypto-asset weakness flag is any C5 weak-crypto code OR an expired cert.
_WEAKNESS_CODES = WEAK_CRYPTO_CODES | {EXPIRED_CERTIFICATE}

_SEVERITY_IMPACT = {"error": "High", "warning": "Medium", "note": "Low", "none": "Low"}
_IMPACT_RANK = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}


def _crypto_assets(result: ScanResult) -> list[AIComponent]:
    """The ``crypto_asset`` components — the CBOM inventory / risk-asset rows."""
    return [c for c in result.components if c.kind == "crypto_asset"]


def _impact_for(comp: AIComponent, result: ScanResult) -> str:
    """Stacked per-component severity (scorer) -> Impact, else top-flag, else Low."""
    stacked = (result.scores or {}).get("component_severity", {}).get(comp.bom_ref)
    if stacked:
        return str(stacked).capitalize()
    flags = result.flags_for(comp.bom_ref)
    if flags:
        return min(
            (_SEVERITY_IMPACT.get(f.severity, "Medium") for f in flags),
            key=lambda imp: _IMPACT_RANK[imp],
        )
    return "Low"


def _risk_score_for(comp: AIComponent, result: ScanResult) -> float:
    """0–10 differentiated risk from stacked flag weight + impact floor."""
    impact = _impact_for(comp, result)
    base = {"Critical": 7.5, "High": 5.5, "Medium": 3.5, "Low": 1.2}.get(impact, 1.2)
    raw = float((result.scores or {}).get("by_component", {}).get(comp.bom_ref, 0.0) or 0.0)
    # raw weights typically land 0–16; fold into remaining headroom above the floor.
    score = base + raw * 0.25
    return round(min(10.0, max(0.0, score)), 1)


def _finding_description(comp: AIComponent, result: ScanResult) -> str:
    """Join flag messages for a component (HoverCard / finding Dialog copy)."""
    props = comp.properties or {}
    flags = result.flags_for(comp.bom_ref)
    return "; ".join(f.message for f in flags if f.message) or (
        f"Inventoried crypto asset ({props.get('crypto:assetType') or comp.kind})."
    )


def _pqc_suggested_fix(props: dict[str, Any]) -> str:
    """Remediation string for a quantum-vulnerable algorithm (mirrors adapter)."""
    target = props.get("crypto:pqcMigrationTarget")
    if props.get("crypto:quantumVulnerable") == "true" and target:
        return (
            "Plan migration to post-quantum cryptography "
            f"({target}); NIST deprecates quantum-vulnerable public-key "
            "cryptography after 2030 and disallows it after 2035."
        )
    return (
        "Keep this cryptographic asset in the organization's crypto inventory "
        "and post-quantum migration plan."
    )


def _finding(comp: AIComponent, result: ScanResult) -> dict[str, Any]:
    """One crypto asset -> a CBOM finding row (carries every chart field)."""
    props = comp.properties or {}
    flags = result.flags_for(comp.bom_ref)
    codes = sorted(f.code for f in flags)
    nqsl = props.get("crypto:nistQuantumSecurityLevel")
    ssb = props.get("crypto:securityStrengthBits")
    return {
        "title": comp.name,
        # Stable inventory identity — FE joins charts → findings via bom_ref
        # (Mongo ObjectId overwrites ``id`` after persist; bom_ref stays).
        "bom_ref": comp.bom_ref,
        "impact": _impact_for(comp, result),
        "asset_type": props.get("crypto:assetType"),
        "primitive": props.get("crypto:primitive"),
        "key_size": props.get("crypto:keySize"),
        "security_strength_bits": int(ssb) if ssb is not None else None,
        "mode": props.get("crypto:mode"),
        "curve": props.get("crypto:curve"),
        "protocol_version": props.get("crypto:protocolVersion"),
        "not_valid_after": props.get("crypto:notValidAfter"),
        "self_signed": props.get("crypto:selfSigned") == "true",
        "expired": EXPIRED_CERTIFICATE in codes,
        "material_kind": props.get("crypto:materialKind"),
        "container_format": props.get("crypto:containerFormat"),
        "parse_status": props.get("crypto:parseStatus"),
        "quantum_vulnerable": props.get("crypto:quantumVulnerable") == "true",
        "nist_quantum_security_level": int(nqsl) if nqsl is not None else None,
        "pqc_migration_target": props.get("crypto:pqcMigrationTarget"),
        "pqc_migration_roadmap": props.get("crypto:pqcMigrationRoadmap"),
        "parameter_set": props.get("crypto:parameterSet"),
        "hybrid": props.get("crypto:hybrid") == "true",
        "weak": any(c in _WEAKNESS_CODES for c in codes),
        "finding_codes": codes,
        "description": _finding_description(comp, result),
        "location": props.get("crypto:source") or props.get("discovery:source") or "",
        "risk_score": _risk_score_for(comp, result),
    }


def _algorithm_distribution(assets: list[AIComponent]) -> dict[str, int]:
    """Algorithm assets bucketed by primitive (block-cipher / hash / pke / ...)."""
    dist: dict[str, int] = {}
    for c in assets:
        props = c.properties or {}
        if props.get("crypto:assetType") != "algorithm":
            continue
        primitive = props.get("crypto:primitive") or "other"
        dist[primitive] = dist.get(primitive, 0) + 1
    return dict(sorted(dist.items()))


def _weakness_distribution(result: ScanResult) -> dict[str, int]:
    """Weak-crypto findings bucketed by flag code (WEAK_* + EXPIRED_CERTIFICATE)."""
    dist: dict[str, int] = {}
    for f in result.flags:
        if f.code in _WEAKNESS_CODES:
            dist[f.code] = dist.get(f.code, 0) + 1
    return dict(sorted(dist.items()))


def _pqc_migration_rows(
    assets: list[AIComponent], result: ScanResult
) -> list[dict[str, Any]]:
    """One migration row per quantum-vulnerable algorithm asset (F2).

    Carries the C7 grader's per-asset PQC targets — the unsized target family
    (``ML-KEM (FIPS 203) / ML-DSA (FIPS 204)``) and the parameter-sized roadmap
    (``ML-KEM-768 / ML-DSA-65``) matched to the asset's classical strength —
    already rendered into ``crypto:pqcMigrationTarget`` / ``crypto:pqcMigrationRoadmap``
    by the PQC scanner, so the F2 quantum-vulnerable list + migration-roadmap
    panel render the exact algorithm-by-algorithm plan without re-deriving it.

    Additive enrichment for the grouped UX (location + bom_ref + HoverCard
    detail): ``location`` / ``bom_ref`` / ``description`` / ``suggested_fix`` /
    ``finding_codes``. Instance count stays 1:1 with ``quantum_vulnerable``;
    grouping is presentation-only on the frontend.

    Deterministic: sorted by impact rank then name then bom_ref.
    """
    rows: list[dict[str, Any]] = []
    for c in assets:
        props = c.properties or {}
        if props.get("crypto:assetType") != "algorithm":
            continue
        if props.get("crypto:quantumVulnerable") != "true":
            continue
        flags = result.flags_for(c.bom_ref)
        nqsl = props.get("crypto:nistQuantumSecurityLevel")
        rows.append(
            {
                "name": c.name,
                "primitive": props.get("crypto:primitive"),
                "key_size": props.get("crypto:keySize"),
                "curve": props.get("crypto:curve"),
                "nist_quantum_security_level": (
                    int(nqsl) if nqsl is not None else None
                ),
                "migration_target": props.get("crypto:pqcMigrationTarget"),
                "migration_roadmap": props.get("crypto:pqcMigrationRoadmap"),
                "impact": _impact_for(c, result),
                "location": (
                    props.get("crypto:source")
                    or props.get("discovery:source")
                    or ""
                ),
                "bom_ref": c.bom_ref,
                "description": _finding_description(c, result),
                "suggested_fix": _pqc_suggested_fix(props),
                "finding_codes": sorted(f.code for f in flags),
            }
        )
    rows.sort(
        key=lambda r: (
            _IMPACT_RANK.get(str(r["impact"]), 9),
            str(r["name"]),
            str(r.get("bom_ref") or ""),
        )
    )
    return rows


def _pqc_readiness(
    assets: list[AIComponent], result: ScanResult
) -> dict[str, Any]:
    """PQC readiness over algorithm assets: quantum-vulnerable vs quantum-safe.

    Carries the C7 grading surface for the PQC gauge / roadmap panel (F2):
    hybrid-KEX count, the NIST quantum-security-level histogram (0 = vulnerable,
    1-5 = quantum-safe category), and one ``migration`` row per quantum-vulnerable
    algorithm (its sized PQC target) for the quantum-vulnerable list + roadmap.
    """
    vulnerable = safe = hybrid = 0
    level_dist: dict[str, int] = {}
    for c in assets:
        props = c.properties or {}
        if props.get("crypto:assetType") != "algorithm":
            continue
        if props.get("crypto:quantumVulnerable") == "true":
            vulnerable += 1
        else:
            safe += 1
        if props.get("crypto:hybrid") == "true":
            hybrid += 1
        level = props.get("crypto:nistQuantumSecurityLevel")
        if level is not None:
            level_dist[level] = level_dist.get(level, 0) + 1
    graded = vulnerable + safe
    readiness = round(safe / graded * 100, 1) if graded else None
    return {
        "quantum_vulnerable": vulnerable,
        "quantum_safe": safe,
        "hybrid": hybrid,
        "readiness_pct": readiness,
        "nist_level_distribution": dict(sorted(level_dist.items())),
        "migration": _pqc_migration_rows(assets, result),
    }


def _certificate_expiry(
    assets: list[AIComponent], result: ScanResult
) -> list[dict[str, Any]]:
    """Per-certificate rows: expiry + the C4 weakness catalog verdicts.

    Carries the depth the C4 certificate-weakness lane raises (weak signature
    hash, undersized key, near-expiry) as booleans alongside the base
    expiry/self-signed fields, so the CBOM results page can surface every cert
    verdict without re-deriving it. Reads the flags the scanner already computed.
    """
    rows = []
    for c in assets:
        if (c.properties or {}).get("crypto:assetType") != "certificate":
            continue
        codes = {f.code for f in result.flags_for(c.bom_ref)}
        rows.append(
            {
                "name": c.name,
                "not_valid_after": (c.properties or {}).get("crypto:notValidAfter"),
                "self_signed": (c.properties or {}).get("crypto:selfSigned") == "true",
                "expired": EXPIRED_CERTIFICATE in codes,
                "near_expiry": CERT_NEAR_EXPIRY in codes,
                "weak_signature": WEAK_CERT_SIGNATURE in codes,
                "weak_key_size": WEAK_CERT_KEY_SIZE in codes,
                "signature_algorithm": (c.properties or {}).get(
                    "crypto:signatureAlgorithm"
                ),
                "key_size": (c.properties or {}).get("crypto:keySize"),
                "location": (c.properties or {}).get("discovery:source"),
                "bom_ref": c.bom_ref,
            }
        )
    rows.sort(key=lambda r: str(r["name"]))
    return rows


# Material kinds shown on the Certificate expiry / related UI alongside X.509.
# Keys and opaque keystores (credential) — not IV/salt/nonce misuse material.
_KEY_MATERIAL_KINDS = frozenset(
    {"private-key", "public-key", "secret-key", "key", "credential"}
)


def _key_material_rows(assets: list[AIComponent]) -> list[dict[str, Any]]:
    """Related key / keystore rows for the Certificate expiry chart (harden).

    X.509 certificates carry ``notValidAfter``; PEM keys and opaque JKS/PKCS#12
    containers do not. Surfacing them as a sibling series stops the empty-expiry
    chart from looking like a miss when the scan found keys but no certs.
    """
    rows: list[dict[str, Any]] = []
    for c in assets:
        props = c.properties or {}
        if props.get("crypto:assetType") != "related-crypto-material":
            continue
        kind = props.get("crypto:materialKind") or "unknown"
        if kind not in _KEY_MATERIAL_KINDS:
            continue
        rows.append(
            {
                "name": c.name,
                "material_kind": kind,
                "container_format": props.get("crypto:containerFormat"),
                "parse_status": props.get("crypto:parseStatus"),
                "location": props.get("discovery:source"),
                "bom_ref": c.bom_ref,
            }
        )
    rows.sort(key=lambda r: (str(r["material_kind"]), str(r["name"])))
    return rows


def _protocol_distribution(assets: list[AIComponent]) -> dict[str, int]:
    """Protocol assets bucketed by display label (e.g. ``TLS 1.0``)."""
    dist: dict[str, int] = {}
    for c in assets:
        if (c.properties or {}).get("crypto:assetType") != "protocol":
            continue
        dist[c.name] = dist.get(c.name, 0) + 1
    return dict(sorted(dist.items()))


def _iter_crypto_refs(node: Any) -> Any:
    """Yield ``(rel, target_ref)`` for every crypto bom-ref link inside a
    CycloneDX ``cryptoProperties`` subtree.

    The C9 emitter links assets via CycloneDX 1.6 ``*Ref`` fields
    (``subjectPublicKeyRef`` / ``signatureAlgorithmRef`` / ``algorithmRef``) and
    ref arrays (protocol ``cryptoRefArray`` / cipher-suite ``algorithms``). A
    single recursive walk collects them all — and any future ``*Ref`` field —
    without re-implementing the emitter's resolution logic. The ``rel`` label is
    derived from the field name (e.g. ``subjectPublicKeyRef`` -> ``subjectPublicKey``).
    """
    if isinstance(node, dict):
        for key, val in node.items():
            if isinstance(val, str) and key.endswith("Ref"):
                yield key[:-3] or "ref", val
            elif key in ("cryptoRefArray", "algorithms") and isinstance(val, list):
                rel = "cipherSuite" if key == "algorithms" else "cryptoRef"
                for item in val:
                    if isinstance(item, str):
                        yield rel, item
            else:
                yield from _iter_crypto_refs(val)
    elif isinstance(node, list):
        for item in node:
            yield from _iter_crypto_refs(item)


def _crypto_graph(
    result: ScanResult, bom: dict[str, Any]
) -> dict[str, list[dict[str, Any]]]:
    """The crypto dependency graph (nodes + edges) for the results-page viz (F1).

    The normalized peer of the AIBOM lane's ``ai_bom_graph``. The C9 dependency
    graph is emitted INTO ``cbom_json`` as CycloneDX 1.6 ``*Ref`` /
    ``cryptoRefArray`` links (a certificate -> its subject-public-key +
    signature-digest algorithm assets; a protocol -> its cipher-suite algorithm
    assets; related material -> the algorithm that produced it). This surfaces a
    flat, pre-joined nodes+edges projection of that graph — each node carrying
    its chart-relevant metadata (assetType / primitive / stacked severity /
    quantum-vulnerability / weakness) — so the frontend renders the dependency
    graph without re-walking the CycloneDX ``cryptoProperties`` structure.

    Nodes are the scanned inventory (``result.components``); edges are the
    ``bom``'s crypto refs whose endpoints BOTH resolve to inventory nodes (so no
    dangling refs to any emit-time-synthesized component), plus any native
    ``result.edges`` (empty today — the CBOM scanners link at emit time — but
    kept future-proof). Lane discipline: reads the scanned graph + the emitted
    BOM + the scorer's per-asset severity; computes no scores and raises no
    flags. Deterministic — nodes + edges are sorted — so identical input yields
    identical output.
    """
    nodes = [
        {
            "id": c.bom_ref,
            "label": c.name,
            "kind": c.kind,
            "asset_type": (c.properties or {}).get("crypto:assetType"),
            "primitive": (c.properties or {}).get("crypto:primitive"),
            "impact": _impact_for(c, result),
            "quantum_vulnerable": (c.properties or {}).get("crypto:quantumVulnerable")
            == "true",
            "weak": any(
                f.code in _WEAKNESS_CODES for f in result.flags_for(c.bom_ref)
            ),
        }
        for c in result.components
    ]
    node_ids = {n["id"] for n in nodes}
    edges: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()

    def _add(src: str, rel: str, dst: str) -> None:
        if src == dst or src not in node_ids or dst not in node_ids:
            return
        key = (src, rel, dst)
        if key not in seen:
            seen.add(key)
            edges.append({"source": src, "target": dst, "rel": rel})

    for comp in bom.get("components", []):
        src = comp.get("bom-ref")
        cp = comp.get("cryptoProperties")
        if isinstance(src, str) and isinstance(cp, dict):
            for rel, target in _iter_crypto_refs(cp):
                _add(src, rel, target)
    for e in result.edges:  # future-proof: native scanner edges (none today)
        _add(e.src, e.rel, e.dst)

    nodes.sort(key=lambda n: str(n["id"]))
    edges.sort(key=lambda e: (str(e["source"]), str(e["rel"]), str(e["target"])))
    return {"nodes": nodes, "edges": edges}


def _bom(result: ScanResult) -> dict[str, Any]:
    """Render the hand-built CycloneDX 1.6 CBOM to a dict (downloadable)."""
    return json.loads(get_reporter("cyclonedx").render(result))


def normalize_crypto(result: ScanResult, *, duration_of_scan: float) -> dict[str, Any]:
    """Normalize a scored CBOM ScanResult into the DevSecShield run-object.

    Carries the five CBOM chart distributions + the tri-state compliance + the
    scores through verbatim, so no chart can be starved by a flattened payload.
    """
    assets = _crypto_assets(result)
    findings = [_finding(c, result) for c in assets]
    findings.sort(
        key=lambda f: (_IMPACT_RANK.get(f["impact"], 9), str(f["title"]))
    )
    bom = _bom(result)  # render once; cbom_json + cbom_graph share it
    full_graph = _crypto_graph(result, bom)
    # Additive compact/expanded projections — full ``cbom_graph`` stays intact
    # for contracts; FE prefers compact for Card, expanded for Dialog.
    return {
        # --- inventory rows (every crypto asset, carrying its chart fields) ---
        "results": findings,
        # --- carried-through, never flattened ---
        "cbom_json": bom,
        "cbom_compliance": result.compliance or {},
        "cbom_scores": result.scores or {},
        "cbom_graph": full_graph,
        "cbom_graph_compact": compact_cbom_graph(
            full_graph,
            max_nodes=COMPACT_MAX_NODES,
            collapse_orphans=True,
            collapse_duplicate_labels=True,
        ),
        "cbom_graph_expanded": compact_cbom_graph(
            full_graph,
            max_nodes=EXPANDED_MAX_NODES,
            collapse_orphans=False,
            collapse_duplicate_labels=True,
        ),
        # Alias used by scan_metadata / FE (nodes+edges+meta).
        "cbom_graph_view": build_graph_view(
            full_graph, lane="cbom", max_nodes=COMPACT_MAX_NODES
        ),
        "cbom_distributions": {
            "algorithms": _algorithm_distribution(assets),
            "weakness": _weakness_distribution(result),
            "pqc": _pqc_readiness(assets, result),
            "certificates": _certificate_expiry(assets, result),
            "key_material": _key_material_rows(assets),
            "protocols": _protocol_distribution(assets),
        },
        "quantum_vulnerable_count": sum(
            1 for f in result.flags if f.code == QUANTUM_VULNERABLE
        ),
        "duration_of_scan": duration_of_scan,
    }


__all__ = ["normalize_crypto"]
