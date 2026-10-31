"""Post-quantum and risk posture of one collection run, computed from the stored assets (no model, no network).

* PQC class per asset: quantum-vulnerable (Shor breaks it), hybrid (a post-quantum key exchange is accepted next to
  the classical one), quantum-safe (symmetric, hash or post-quantum), grover-weakened (128-bit symmetric keys),
  not-applicable (inventory without a public-key algorithm, such as a database setting).
* PQC readiness: share of assets with a quantum verdict that are not quantum-vulnerable.
* Harvest-now-decrypt-later (HNDL): endpoints whose key exchange is quantum-vulnerable; traffic recorded today can be
  decrypted later. Certificates and signatures are not HNDL (a forged signature in future does not reveal past data).
* Mosca: data must stay secret for X years, migration takes Y years, a quantum computer arrives in Z years.
  X + Y > Z means data is already at risk. The team sets X, Y and Z; there is no built-in Z.
* Risk score per asset: impact weight times the source's business criticality.
* Compliance: which regulatory clauses (from the knowledge base) the run's findings touch.
"""
from __future__ import annotations

import re
from collections import Counter, defaultdict
from typing import Any

from sqlmodel import Session, select

from backend.new_models import CbomCollectedAsset, CbomCollectionSource
from backend.utilities.cbom_sources import crypto_kb

IN_TRANSIT = {"tls_endpoint", "ssh_endpoint", "ssh_server_config", "database_tls", "load_balancer_tls", "cdn_tls",
              "api_tls", "k8s_ingress_tls"}
IMPACT_WEIGHT = {"Critical": 10.0, "High": 7.0, "Medium": 4.0, "Low": 1.0}
CRITICALITY = {"low": 0.5, "medium": 1.0, "high": 1.5, "critical": 2.0}
PQC_CLASSES = ("quantum-vulnerable", "hybrid", "quantum-safe", "grover-weakened", "not-applicable")


def pqc_class(asset_type: str, quantum_vulnerable: bool | None, codes: list[str], facts: dict[str, Any]) -> str:
    if "DISK_XTS_128" in codes:
        return "grover-weakened"
    if asset_type == "disk_encryption" and quantum_vulnerable is False and \
            "128" in str(facts.get("method") or facts.get("cipher") or ""):
        return "grover-weakened"  # any 128-bit volume key (BitLocker Aes128, aes-cbc-128), not only XTS
    if quantum_vulnerable is True:
        return "quantum-vulnerable"
    if quantum_vulnerable is False:
        if facts.get("pq_hybrid") or facts.get("pq_group_supported"):
            return "hybrid"
        return "quantum-safe"
    return "not-applicable"


def hndl(asset_type: str, quantum_vulnerable: bool | None) -> bool:
    return asset_type in IN_TRANSIT and quantum_vulnerable is True


def mosca(risk_model: dict[str, Any] | None) -> dict[str, Any]:
    model = risk_model or {}
    x, y, z = (model.get(k) for k in ("data_shelf_life_years", "migration_years", "threat_years"))
    if not all(isinstance(v, (int, float)) for v in (x, y, z)):
        return {"configured": False, "x": x, "y": y, "z": z,
                "note": "Set how long your data must stay secret (X), how long migration takes (Y) and when you "
                        "expect a cryptographically relevant quantum computer (Z) in Settings."}
    gap = (x or 0) + (y or 0) - (z or 0)
    return {"configured": True, "x": x, "y": y, "z": z, "at_risk": gap > 0, "years_over": gap,
            "verdict": (f"At risk: X + Y = {x + y} years exceeds Z = {z}; data encrypted today with quantum-vulnerable "
                        f"key exchange can be decrypted while it still needs to be secret.") if gap > 0 else
                       (f"Inside the window: X + Y = {x + y} years does not exceed Z = {z}, with {-gap} year(s) "
                        "to spare.")}


def run_posture(session: Session, *, team_id: int, run_id: int, risk_model: dict[str, Any] | None,
                top: int = 10) -> dict[str, Any]:
    rows = session.exec(select(CbomCollectedAsset.id, CbomCollectedAsset.asset_type, CbomCollectedAsset.quantum_vulnerable,
                               CbomCollectedAsset.impact, CbomCollectedAsset.finding_codes, CbomCollectedAsset.facts,
                               CbomCollectedAsset.source_id, CbomCollectedAsset.location, CbomCollectedAsset.name,
                               CbomCollectedAsset.finding)
                        .where(CbomCollectedAsset.team_id == team_id, CbomCollectedAsset.run_id == run_id)).all()
    sources = {s.id: s for s in session.exec(select(CbomCollectionSource).where(
        CbomCollectionSource.team_id == team_id)).all()}
    classes: Counter[str] = Counter()
    impacts: Counter[str] = Counter()
    codes: Counter[str] = Counter()
    hndl_count = 0
    risky: list[dict[str, Any]] = []
    clause_assets: dict[tuple[str, str], set[int]] = defaultdict(set)
    clause_meta: dict[tuple[str, str], dict[str, Any]] = {}
    kb = crypto_kb.load()
    compliance = kb.get("compliance") or {}
    for (aid, a_type, qv, impact, a_codes, facts, source_id, location, name, finding) in rows:
        a_codes = [c for c in a_codes or [] if isinstance(c, str) and not c.startswith("COVERAGE_")]
        if a_type == "coverage":
            continue
        classes[pqc_class(a_type, qv, a_codes, facts or {})] += 1
        if impact:
            impacts[impact] += 1
        codes.update(a_codes)
        if hndl(a_type, qv):
            hndl_count += 1
        source = sources.get(source_id or 0)
        crit = str(((source.config or {}) if source else {}).get("business_criticality") or "medium").lower()
        if impact:
            risky.append({"id": aid, "type": a_type, "name": name or location, "location": location, "impact": impact,
                          "criticality": crit, "source_name": source.name if source else None,
                          "score": round(IMPACT_WEIGHT.get(impact, 0) * CRITICALITY.get(crit, 1.0), 1),
                          "hndl": hndl(a_type, qv), "finding": finding})
        for code in a_codes:
            for key in (crypto_kb.entry("node", code) or {}).get("compliance") or []:
                for ref in compliance.get(key) or []:
                    clause = (ref["framework"], ref["id"])
                    clause_assets[clause].add(aid)
                    meta = clause_meta.setdefault(clause, {**ref, "codes": set()})
                    meta["codes"].add(code)
    judged = classes["quantum-vulnerable"] + classes["hybrid"] + classes["quantum-safe"] + classes["grover-weakened"]
    readiness = round(100.0 * (judged - classes["quantum-vulnerable"]) / judged, 1) if judged else None
    frameworks: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for clause, assets in sorted(clause_assets.items(), key=lambda kv: (kv[0][0], -len(kv[1]))):
        meta = clause_meta[clause]
        frameworks[clause[0]].append({"id": meta["id"], "text": meta["text"], "source": meta["source"],
                                      "note": meta.get("note"), "assets": len(assets), "codes": sorted(meta["codes"])})
    risky.sort(key=lambda r: (-r["score"], r["id"]))
    return {
        "assets": sum(classes.values()),
        "pqc_classes": {c: classes.get(c, 0) for c in PQC_CLASSES},
        "pqc_readiness_pct": readiness,
        "hndl_assets": hndl_count,
        "impacts": {k: impacts.get(k, 0) for k in IMPACT_WEIGHT},
        "top_codes": [{"code": c, "count": n, "title": (crypto_kb.entry("node", c) or {}).get("title", c)}
                      for c, n in codes.most_common(15)],
        "mosca": mosca(risk_model),
        "top_risks": risky[:top],
        "compliance": [{"framework": fw, "clauses": items} for fw, items in sorted(frameworks.items())],
        "kb_version": crypto_kb.version(),
        "pqc_context": {k: v for k, v in crypto_kb.pqc_context().items() if k in ("mosca", "expert_survey",
                                                                                 "nist_ir_8547", "z_note")},
    }


def _host_port(value: str) -> tuple[str | None, str | None]:
    """Host and port from 'host:443', '[2001:db8::1]:443', a bare IPv6 address or a bare host; None for paths, ARNs
    and other values with colons. An IPv6 host keeps its brackets so 'openssl -connect {host}:{port}' stays valid."""
    v = (value or "").strip().split("#", 1)[0]  # '10.0.0.5:443#chain[0]': a certificate in an endpoint's chain
    m = re.match(r"^\[([0-9A-Fa-f:.]+)\](?::(\d{1,5}))?$", v)
    if m:
        return f"[{m.group(1)}]", m.group(2)
    if re.fullmatch(r"[0-9A-Fa-f]*:[0-9A-Fa-f:.]*:[0-9A-Fa-f:.]*", v):  # bare IPv6 (two or more colons, hex only)
        return f"[{v}]", None
    m = re.match(r"^([A-Za-z0-9.\-]+):(\d{1,5})$", v)
    if m:
        return m.group(1), m.group(2)
    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.\-]*", v):
        return v, None
    return None, None


def asset_detail(row: CbomCollectedAsset, source: CbomCollectionSource | None) -> dict[str, Any]:
    """Everything known about one collected asset: the knowledge-base explanation of each finding code (with commands
    filled in for this host), library CVEs and end-of-life, PQC class and HNDL."""
    facts = row.facts or {}
    codes = [c for c in row.finding_codes or [] if isinstance(c, str)]
    ctx: dict[str, Any] = {"name": facts.get("name") or facts.get("package") or row.name, "location": row.location,
                           "resource": facts.get("arn") or facts.get("resource") or facts.get("key_id")}
    host, port = _host_port(row.target or "")
    loc_host, loc_port = _host_port(row.location or "")
    ctx["host"] = facts.get("host") or host or loc_host or None
    ctx["port"] = facts.get("port") or port or loc_port or None
    if row.location.startswith("/"):
        ctx["path"] = row.location
    elif facts.get("path"):
        ctx["path"] = facts["path"]
    # the classifier is deterministic, so re-running it on the stored facts (as of collection time) gives the
    # sentence it wrote for each code
    from backend.utilities.cbom_sources.classify import classify
    verdict = classify(row.asset_type, row.algorithm, row.key_size, row.protocol, facts, row.created_at)
    texts = verdict["texts"]
    ordered = [c for c in codes if c != "QUANTUM_VULNERABLE"] + [c for c in codes if c == "QUANTUM_VULNERABLE"]
    library = None
    if row.asset_type in ("crypto_library", "process_library") and facts.get("version"):
        library = crypto_kb.library_status(str(facts.get("name") or facts.get("package") or ""), str(facts["version"]))
        if library:
            library = {**library, "cve_details": [crypto_kb.cve(c) for c in library["cves"]]}
    return {
        "id": row.id, "type": row.asset_type, "name": row.name, "location": row.location, "target": row.target,
        "impact": row.impact, "finding": row.finding, "finding_codes": codes, "algorithm": row.algorithm,
        "key_size": row.key_size, "protocol": row.protocol, "quantum_vulnerable": row.quantum_vulnerable,
        "pqc_class": pqc_class(row.asset_type, row.quantum_vulnerable, codes, facts),
        "hndl": hndl(row.asset_type, row.quantum_vulnerable),
        "source_name": source.name if source else None,
        "criticality": str(((source.config or {}) if source else {}).get("business_criticality") or "medium"),
        "facts": facts,
        "details": [{**d, "impact": verdict["impacts"].get(d["code"]) or d["impact"]}
                    for d in crypto_kb.render("node", ordered, context=ctx, evidence=row.finding or "", texts=texts,
                                              title=str(row.algorithm or row.name or ""))],
        "library": library,
        "kb_version": crypto_kb.version(),
    }
