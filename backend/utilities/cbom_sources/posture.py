"""Post-quantum and risk posture of one collection run, computed from the stored assets (no model, no network).

* PQC class per asset: quantum-vulnerable (Shor breaks it), hybrid (a post-quantum key exchange is accepted next to
  the classical one), quantum-safe (symmetric, hash or post-quantum), grover-weakened (128-bit symmetric keys),
  not-applicable (inventory without a public-key algorithm, such as a database setting).
* PQC readiness: share of assets with a quantum verdict that are not quantum-vulnerable (the one definition every CBOM
  view uses: ``cbom_metrics.quantum_readiness_pct``).
* Harvest-now-decrypt-later (HNDL): endpoints whose key exchange is quantum-vulnerable; traffic recorded today can be
  decrypted later. Certificates and signatures are not HNDL (a forged signature in future does not reveal past data).
* Mosca: data must stay secret for X years, migration takes Y years, a quantum computer arrives in Z years.
  X + Y > Z means data is already at risk. The team sets X, Y and Z; there is no built-in Z.
* Risk score per asset: impact weight x the source's business criticality x its internet exposure. Criticality and the
  exposure override are read from the job (snapshotted when the run was created), so later edits never re-score an old
  run; jobs created before the snapshot existed fall back to the source's current values.
* Compliance: which regulatory clauses (from the knowledge base) the run's findings touch.
"""
from __future__ import annotations

import datetime as _dt
import ipaddress
import re
from collections import Counter, defaultdict
from typing import Any

from sqlmodel import Session, select

from backend.new_models import CbomCollectedAsset, CbomCollectionJob, CbomCollectionSource, CbomScanNode
from backend.utilities.cbom_sources import crypto_kb
from backend.utilities.cbom_sources.cbom_metrics import quantum_readiness_pct
from backend.utilities.cbom_sources.classify import pq_kex_evidence

IN_TRANSIT = {"tls_endpoint", "ssh_endpoint", "ssh_server_config", "database_tls", "load_balancer_tls", "cdn_tls",
              "api_tls", "k8s_ingress_tls"}
IMPACT_WEIGHT = {"Critical": 10.0, "High": 7.0, "Medium": 4.0, "Low": 1.0}
CRITICALITY = {"low": 0.5, "medium": 1.0, "high": 1.5, "critical": 2.0}
# Internet exposure multiplier: a weakness anyone on the internet can reach ranks 1.5x. Internal and unknown are
# neutral (1.0), so a missing exposure fact never LOWERS a risk; only a positive internet signal raises it.
EXPOSURE_FACTOR = {"internet": 1.5, "internal": 1.0, "unknown": 1.0}
EXPOSURES = tuple(EXPOSURE_FACTOR)
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
        if pq_kex_evidence(facts):  # the raw facts, as stored: classify reads the same evidence (CB-04)
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


def _ip_of(value: str | None) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    host, _port = _host_port(value or "")
    if not host:
        return None
    try:
        return ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return None  # a host name: no DNS lookups here, so its exposure stays unknown


def asset_exposure(facts: dict[str, Any] | None, target: str | None, location: str | None, *,
                   override: str | None = None, node_segment: str | None = None) -> tuple[str, str]:
    """(exposure, basis): ``internet`` | ``internal`` | ``unknown`` and why; the first rule that applies wins:

    1. the source's exposure set by the team (``override``);
    2. the collector's own ``internet_facing`` fact (cloud collectors: load balancer scheme, public database, public IP,
       CloudFront, API Gateway, EKS endpoint ...);
    3. the scan node sits in a segment named DMZ;
    4. the target is an IP address: public (``ipaddress.is_global``) is internet, private / loopback / link-local is
       internal. Host names stay unknown (no DNS lookups).
    """
    if override in EXPOSURES:
        return override, "set on the source"
    facts = facts if isinstance(facts, dict) else {}
    flag = facts.get("internet_facing")
    if isinstance(flag, bool):
        reason = str(facts.get("internet_facing_reason") or "").strip()[:120]
        return ("internet" if flag else "internal"), ("reported by the collector" + (f": {reason}" if reason else ""))
    if str(node_segment or "").strip().lower() == "dmz":
        return "internet", "scan node segment DMZ"
    for value in (target, location):
        ip = _ip_of(value)
        if ip is None:
            continue
        if ip.is_global:
            return "internet", f"public IP address {ip}"
        if ip.is_private or ip.is_loopback or ip.is_link_local:
            return "internal", f"private IP address {ip}"
    return "unknown", "no exposure fact"


def job_metadata(params: dict[str, Any] | None, source: CbomCollectionSource | None,
                 node: CbomScanNode | None) -> dict[str, Any]:
    """Business criticality, exposure override and node segment for one job: the values snapshotted in the job when
    the run was created, else (jobs created before the snapshot) the source's and node's current values."""
    snap = (params or {}).get("metadata")
    if isinstance(snap, dict):
        return {"criticality": snap.get("business_criticality"), "exposure": snap.get("exposure"),
                "segment": snap.get("node_segment")}
    cfg = (source.config or {}) if source else {}
    return {"criticality": cfg.get("business_criticality"), "exposure": cfg.get("exposure"),
            "segment": node.segment if node else None}


def _job_context(session: Session, team_id: int, run_id: int, sources: dict[int, CbomCollectionSource]
                 ) -> dict[int, dict[str, Any]]:
    jobs = session.exec(select(CbomCollectionJob).where(CbomCollectionJob.team_id == team_id,
                                                        CbomCollectionJob.run_id == run_id)).all()
    nodes = {n.id: n for n in session.exec(select(CbomScanNode).where(CbomScanNode.team_id == team_id)).all()}
    return {job.id: job_metadata(job.params, sources.get(job.source_id or 0), nodes.get(job.node_id or 0))
            for job in jobs if job.id is not None}


def run_posture(session: Session, *, team_id: int, run_id: int, risk_model: dict[str, Any] | None,
                top: int = 10) -> dict[str, Any]:
    from backend.utilities.cbom_sources.classify import shown

    rows = session.exec(select(CbomCollectedAsset)
                        .where(CbomCollectedAsset.team_id == team_id, CbomCollectedAsset.run_id == run_id)).all()
    now = _dt.datetime.utcnow()
    sources = {s.id: s for s in session.exec(select(CbomCollectionSource).where(
        CbomCollectionSource.team_id == team_id)).all()}
    job_ctx = _job_context(session, team_id, run_id, sources)
    exposure_counts: Counter[str] = Counter()
    classes: Counter[str] = Counter()
    impacts: Counter[str] = Counter()
    codes: Counter[str] = Counter()
    hndl_count = 0
    risky: list[dict[str, Any]] = []
    clause_assets: dict[tuple[str, str], set[int]] = defaultdict(set)
    clause_meta: dict[tuple[str, str], dict[str, Any]] = {}
    kb = crypto_kb.load()
    compliance = kb.get("compliance") or {}
    for row in rows:
        aid, a_type, qv, facts, source_id = row.id, row.asset_type, row.quantum_vulnerable, row.facts, row.source_id
        location, name, job_id, target = row.location, row.name, row.job_id, row.target
        view = shown(row, now)  # date-based findings (certificate expiry, library end of life) judged today
        impact, a_codes, finding = view["impact"], view["finding_codes"], view["finding"]
        a_codes = [c for c in a_codes if not c.startswith("COVERAGE_")]
        if a_type == "coverage":
            continue
        classes[pqc_class(a_type, qv, a_codes, facts or {})] += 1
        if impact:
            impacts[impact] += 1
        codes.update(a_codes)
        if hndl(a_type, qv):
            hndl_count += 1
        source = sources.get(source_id or 0)
        ctx = job_ctx.get(job_id or 0) or {}
        crit = str(ctx.get("criticality") or "medium").lower()
        exposure, basis = asset_exposure(facts, target, location, override=ctx.get("exposure"),
                                         node_segment=ctx.get("segment"))
        exposure_counts[exposure] += 1
        if impact:
            risky.append({"id": aid, "type": a_type, "name": name or location, "location": location, "impact": impact,
                          "criticality": crit, "exposure": exposure, "exposure_basis": basis,
                          "source_name": source.name if source else None,
                          "score": round(IMPACT_WEIGHT.get(impact, 0) * CRITICALITY.get(crit, 1.0)
                                         * EXPOSURE_FACTOR[exposure], 1),
                          "hndl": hndl(a_type, qv), "finding": finding})
        for code in a_codes:
            for key in (crypto_kb.entry("node", code) or {}).get("compliance") or []:
                for ref in compliance.get(key) or []:
                    clause = (ref["framework"], ref["id"])
                    clause_assets[clause].add(aid)
                    meta = clause_meta.setdefault(clause, {**ref, "codes": set()})
                    meta["codes"].add(code)
    judged = classes["quantum-vulnerable"] + classes["hybrid"] + classes["quantum-safe"] + classes["grover-weakened"]
    readiness = quantum_readiness_pct(classes["quantum-vulnerable"], judged)
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
        "exposure": {e: exposure_counts.get(e, 0) for e in EXPOSURES},
        "exposure_factors": dict(EXPOSURE_FACTOR),
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


def asset_detail(row: CbomCollectedAsset, source: CbomCollectionSource | None, *,
                 job: CbomCollectionJob | None = None, node: CbomScanNode | None = None,
                 today: _dt.date | None = None) -> dict[str, Any]:
    """Everything known about one collected asset: the knowledge-base explanation of each finding code (with commands
    filled in for this host), library CVEs and end-of-life (as of the run, and today when that differs), PQC class,
    HNDL and internet exposure."""
    from backend.utilities.cbom_sources.classify import classify, shown

    facts = row.facts or {}
    now = _dt.datetime.combine(today, _dt.time()) if today else _dt.datetime.utcnow()
    view = shown(row, now)  # the finding as every other view shows it: date-based rules judged today
    codes = view["finding_codes"]
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
    # the classifier is deterministic, so re-running it on the stored facts (as of collection time, or today when a
    # date-based rule changed the finding since) gives the sentence it wrote for each code
    verdict = classify(row.asset_type, row.algorithm, row.key_size, row.protocol, facts,
                       now if view["as_of_run"] else row.created_at)
    texts = verdict["texts"]
    ordered = [c for c in codes if c != "QUANTUM_VULNERABLE"] + [c for c in codes if c == "QUANTUM_VULNERABLE"]
    library = None
    if row.asset_type in ("crypto_library", "process_library") and facts.get("version"):
        package, version = str(facts.get("name") or facts.get("package") or ""), str(facts["version"])
        # end of life as of the run (the classifier's LIB_EOL used the run date too), and today when that differs
        as_of = (row.created_at or _dt.datetime.utcnow()).date()
        library = crypto_kb.library_status(package, version, today=as_of)
        if library:
            eol_now = (crypto_kb.library_status(package, version, today=today or _dt.date.today()) or {}).get("eol")
            changed = (eol_now or {}).get("passed") != (library.get("eol") or {}).get("passed")
            library = {**library, "cve_details": [crypto_kb.cve(c) for c in library["cves"]],
                       "eol_as_of": as_of.isoformat(), "eol_today": eol_now if changed else None}
    meta = job_metadata(job.params if job is not None else None, source, node)
    crit = str(meta["criticality"] or "medium")
    exposure, exposure_basis = asset_exposure(facts, row.target, row.location, override=meta["exposure"],
                                              node_segment=meta["segment"])
    return {
        "id": row.id, "type": row.asset_type, "name": row.name, "location": row.location, "target": row.target,
        "impact": view["impact"], "finding": view["finding"], "finding_codes": codes, "as_of_run": view["as_of_run"],
        "algorithm": row.algorithm,
        "key_size": row.key_size, "protocol": row.protocol, "quantum_vulnerable": row.quantum_vulnerable,
        "pqc_class": pqc_class(row.asset_type, row.quantum_vulnerable, codes, facts),
        "hndl": hndl(row.asset_type, row.quantum_vulnerable),
        "source_name": source.name if source else None,
        "criticality": crit,
        "exposure": exposure,
        "exposure_basis": exposure_basis,
        "exposure_factor": EXPOSURE_FACTOR[exposure],
        "facts": facts,
        "details": [{**d, "impact": verdict["impacts"].get(d["code"]) or d["impact"]}
                    for d in crypto_kb.render("node", ordered, context=ctx, evidence=view["finding"] or "", texts=texts,
                                              title=str(row.algorithm or row.name or ""))],
        "library": library,
        "kb_version": crypto_kb.version(),
    }
