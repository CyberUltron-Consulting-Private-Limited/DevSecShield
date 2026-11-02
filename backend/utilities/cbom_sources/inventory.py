"""Read side of collected assets: the paged table, its facets, and the CycloneDX 1.6 export.

The table, the counts on the run and the export are built from the same query over
``cbomcollectedasset`` so they can never disagree.
"""
from __future__ import annotations

import datetime as _dt
import uuid
from typing import Any

from sqlalchemy import func, or_
from sqlmodel import Session, select

from backend.new_models import CbomCollectedAsset, CbomCollectionJob, CbomCollectionRun, CbomCollectionSource
from backend.utilities.cbom_sources import crypto_kb
from backend.utilities.cbom_sources.classify import classify
from backend.utilities.cbom_sources.common import iso_z

EXPORT_CAP = 50_000
# serialNumber = uuid5(this namespace, "<run id>:<KB version>"): the same run exported with the same knowledge base is
# the same BOM (same serial); a newer KB re-judges the findings, so it is a new serial.
_SERIAL_NS = uuid.uuid5(uuid.NAMESPACE_URL, "https://zeroshield.ai/cbom/sources/run")


def export_serial(run_id: int, kb_version: str) -> str:
    return f"urn:uuid:{uuid.uuid5(_SERIAL_NS, f'{run_id}:{kb_version}')}"
_IMPACT_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}


def _filtered(query, *, asset_type: str | None, impact: str | None, quantum: bool | None, text: str | None,
              source_id: int | None):
    if asset_type:
        query = query.where(CbomCollectedAsset.asset_type == asset_type)
    if impact == "none":
        query = query.where(CbomCollectedAsset.impact.is_(None))  # type: ignore[union-attr]
    elif impact:
        query = query.where(CbomCollectedAsset.impact == impact)
    if quantum is not None:
        query = query.where(CbomCollectedAsset.quantum_vulnerable == quantum)
    if source_id:
        query = query.where(CbomCollectedAsset.source_id == source_id)
    if text:
        like = f"%{text.lower()}%"
        query = query.where(or_(func.lower(CbomCollectedAsset.location).like(like),
                                func.lower(func.coalesce(CbomCollectedAsset.name, "")).like(like),
                                func.lower(func.coalesce(CbomCollectedAsset.finding, "")).like(like),
                                func.lower(func.coalesce(CbomCollectedAsset.algorithm, "")).like(like)))
    return query


def public_asset(row: CbomCollectedAsset, source_names: dict[int, str], job_names: dict[int, str] | None = None) -> dict[str, Any]:
    return {
        "id": row.id, "type": row.asset_type, "cdx_type": row.cdx_type, "job_id": row.job_id,
        "source_id": row.source_id,
        "source_name": source_names.get(row.source_id or 0) or (job_names or {}).get(row.job_id),
        "target": row.target, "location": row.location, "name": row.name, "algorithm": row.algorithm,
        "key_size": row.key_size, "protocol": row.protocol, "quantum_vulnerable": row.quantum_vulnerable,
        "impact": row.impact, "finding": row.finding, "finding_codes": row.finding_codes or [],
        "facts": row.facts or {},
    }


def _source_names(session: Session, team_id: int, jobs: list[CbomCollectionJob]) -> dict[int, str]:
    names = {s.id: s.name for s in session.exec(select(CbomCollectionSource).where(CbomCollectionSource.team_id == team_id)).all()}
    for job in jobs:  # deleted sources keep their name on the job
        if job.source_id and job.source_id not in names and (job.params or {}).get("source_name"):
            names[job.source_id] = job.params["source_name"]
    return names


def list_assets(session: Session, *, team_id: int, run_id: int | None = None, job_id: int | None = None,
                asset_type: str | None = None, impact: str | None = None, quantum: bool | None = None,
                text: str | None = None, source_id: int | None = None, page: int = 1, page_size: int = 50) -> dict[str, Any]:
    base = select(CbomCollectedAsset).where(CbomCollectedAsset.team_id == team_id)
    if run_id is not None:
        base = base.where(CbomCollectedAsset.run_id == run_id)
    if job_id is not None:
        base = base.where(CbomCollectedAsset.job_id == job_id)
    filtered = _filtered(base, asset_type=asset_type, impact=impact, quantum=quantum, text=text, source_id=source_id)
    total = int(session.exec(select(func.count()).select_from(filtered.subquery())).one())
    rows = session.exec(filtered.order_by(CbomCollectedAsset.id).offset((page - 1) * page_size).limit(page_size)).all()
    rows = sorted(rows, key=lambda r: (_IMPACT_ORDER.get(r.impact or "", 9), r.id or 0))

    # facets are over the whole run/job, not the filtered page, so the filter chips always add up
    scope = select(CbomCollectedAsset.asset_type, CbomCollectedAsset.impact, CbomCollectedAsset.quantum_vulnerable,
                   func.count()).where(CbomCollectedAsset.team_id == team_id)
    if run_id is not None:
        scope = scope.where(CbomCollectedAsset.run_id == run_id)
    if job_id is not None:
        scope = scope.where(CbomCollectedAsset.job_id == job_id)
    by_type: dict[str, int] = {}
    by_impact: dict[str, int] = {}
    quantum_count = 0
    all_total = 0
    for a_type, a_impact, a_qv, count in session.exec(scope.group_by(
            CbomCollectedAsset.asset_type, CbomCollectedAsset.impact, CbomCollectedAsset.quantum_vulnerable)).all():
        all_total += count
        by_type[a_type] = by_type.get(a_type, 0) + count
        by_impact[a_impact or "none"] = by_impact.get(a_impact or "none", 0) + count
        if a_qv:
            quantum_count += count
    jobs = session.exec(select(CbomCollectionJob).where(
        CbomCollectionJob.team_id == team_id,
        (CbomCollectionJob.run_id == run_id) if run_id is not None else (CbomCollectionJob.id == job_id))).all()
    names = _source_names(session, team_id, list(jobs))
    job_names = {j.id: names.get(j.source_id or 0) or (j.params or {}).get("source_name") for j in jobs}
    return {
        "total": total, "all_total": all_total, "page": page, "page_size": page_size,
        "items": [public_asset(r, names, job_names) for r in rows],
        "facets": {"type": by_type, "impact": by_impact, "quantum_vulnerable": quantum_count},
        "targets": [_job_targets(job, names) for job in jobs],
    }


def _job_targets(job: CbomCollectionJob, names: dict[int, str]) -> dict[str, Any]:
    result = job.result if isinstance(job.result, dict) else {}
    targets = result.get("targets") if isinstance(result.get("targets"), list) else []
    return {
        "job_id": job.id, "source_id": job.source_id, "source_name": names.get(job.source_id or 0) or (job.params or {}).get("source_name"),
        "status": job.status, "outcome": job.outcome, "attempt": job.attempts, "asset_count": job.asset_count,
        "counts": result.get("counts") if isinstance(result.get("counts"), dict) else None,
        "summary": result.get("summary"), "truncated": bool(result.get("truncated")),
        "asset_mismatch": result.get("asset_mismatch"), "error": job.error,
        "targets": [t for t in targets[:1000] if isinstance(t, dict)],
        "duration_s": result.get("duration_s"),
    }


# ----------------------------------------------------------------------------- CycloneDX 1.6
_REL_TYPE = {"private_key": "private-key", "public_key": "public-key", "ssh_host_key": "public-key",
             "signing_key": "public-key", "kms_key": "key", "cloud_secret": "secret-key", "host_secret": "secret-key", "keystore": "key",
             "k8s_certificate": "key", "managed_key": "key"}


# CycloneDX 1.6 enums (cryptoProperties): values outside them make the document invalid
_CDX_PRIMITIVES = {"drbg", "mac", "block-cipher", "stream-cipher", "signature", "hash", "pke", "xof", "kdf", "key-agree",
                   "kem", "ae", "combiner", "other", "unknown"}
_CDX_MODES = {"cbc", "ecb", "ccm", "gcm", "cfb", "ofb", "ctr", "other", "unknown"}
_KEY_STATE = {"Enabled": "active", "Disabled": "suspended", "PendingDeletion": "deactivated",
              "PendingImport": "pre-activation", "Unavailable": "suspended", "active": "active",
              # KMIP states (managed_key facts from KMIP servers)
              "Pre-Active": "pre-activation", "Active": "active", "Deactivated": "deactivated",
              "Compromised": "compromised", "Destroyed": "destroyed", "Destroyed Compromised": "compromised"}
_SEVERITY = {"Critical": "critical", "High": "high", "Medium": "medium", "Low": "low"}


def _rank(impact: str) -> int:
    order = list(_SEVERITY)
    value = str(impact or "").capitalize()
    return order.index(value) if value in order else len(order)


def _code_impacts(row: CbomCollectedAsset) -> dict[str, str | None]:
    """The impact the classifier gives each code on this asset (re-run on the stored facts; it is deterministic)."""
    try:
        return classify(row.asset_type, row.algorithm, row.key_size, row.protocol, row.facts or {}, row.created_at)["impacts"]
    except Exception:
        return {}


def vulnerabilities(rows: list[CbomCollectedAsset]) -> list[dict[str, Any]]:
    """CycloneDX vulnerabilities with VEX analysis.

    One entry per finding code (the weak setting was observed on the listed assets, so the analysis state is
    "exploitable", CERT-In's "Affected"), and one per CVE matched from that evidence or from a library version
    ("in_triage": a version or configuration match is not proof; distribution back-ports are not checked)."""
    by_code: dict[str, list[CbomCollectedAsset]] = {}
    code_impacts: dict[str, list[str]] = {}
    by_cve: dict[str, dict[str, Any]] = {}
    for row in rows:
        own = _code_impacts(row)
        for code in row.finding_codes or []:
            if isinstance(code, str) and crypto_kb.entry("node", code):
                by_code.setdefault(code, []).append(row)
                impact = own.get(code) or (crypto_kb.entry("node", code) or {}).get("default_impact")
                if impact:
                    code_impacts.setdefault(code, []).append(impact)
                for cve in crypto_kb.cves_for("node", code, row.finding or ""):
                    if code == "LIB_KNOWN_CVE":
                        continue
                    hit = by_cve.setdefault(cve["id"], {"cve": cve, "rows": [], "why": set()})
                    hit["rows"].append(row)
                    hit["why"].add(f"{code} ({cve.get('matched_on')})")
        facts = row.facts or {}
        if "LIB_KNOWN_CVE" in (row.finding_codes or []) and facts.get("version"):
            status = crypto_kb.library_status(str(facts.get("name") or facts.get("package") or ""), str(facts["version"]))
            for cid in (status or {}).get("cves") or []:
                hit = by_cve.setdefault(cid, {"cve": crypto_kb.cve(cid) or {"id": cid}, "rows": [], "why": set()})
                hit["rows"].append(row)
                hit["why"].add(f"{status['package']} {status['upstream_version']} is in the affected range")
    out: list[dict[str, Any]] = []
    for code, hits in sorted(by_code.items()):
        e = crypto_kb.entry("node", code) or {}
        # the severity of THIS finding (worst across the assets that have it), not the worst finding on those assets
        worst = min(code_impacts.get(code) or [], key=_rank, default=None)
        out.append({
            "bom-ref": f"zs-vuln-{code.lower()}", "id": f"ZS-CBOM-{code}",
            "source": {"name": "ZeroShield crypto knowledge base", "url": "https://cwe.mitre.org/"},
            "ratings": [{"severity": _SEVERITY.get(str(worst or "").capitalize(), "info"), "method": "other"}],
            "cwes": [int(c[4:]) for c in e.get("cwe") or []],
            "description": e.get("description"), "detail": e.get("attack"),
            "recommendation": (e.get("remediation") or {}).get("summary"),
            "analysis": {"state": "exploitable", "detail": "Observed directly by the collector on each affected asset."},
            "affects": [{"ref": f"zs-asset-{rid}"} for rid in list(dict.fromkeys(h.id for h in hits))[:5000]],
            "properties": [{"name": "zs:kb_version", "value": crypto_kb.version()}],
        })
    for cid, hit in sorted(by_cve.items()):
        cve = hit["cve"]
        cvss = cve.get("cvss") or {}
        rating = {"method": "CVSSv31" if cvss.get("version") == "3.1" else "CVSSv3" if cvss.get("version") == "3.0" else "other"}
        if cvss.get("score") is not None:
            rating.update({"score": cvss["score"], "severity": str(cvss.get("severity") or "unknown").lower(),
                           "vector": cvss.get("vector")})
        out.append({
            "bom-ref": f"zs-vuln-{cid.lower()}", "id": cid,
            "source": {"name": "NVD", "url": cve.get("url") or f"https://nvd.nist.gov/vuln/detail/{cid}"},
            "ratings": [{k: v for k, v in rating.items() if v is not None}],
            "cwes": [int(c[4:]) for c in cve.get("cwe") or [] if c[4:].isdigit()],
            "description": cve.get("summary") or f"{cid}: see the NVD record (not in the offline knowledge base).",
            "analysis": {"state": "in_triage",
                         "detail": "Matched on: " + "; ".join(sorted(hit["why"]))[:900] +
                                   ". A version or configuration match is not proof of exposure."},
            "affects": [{"ref": f"zs-asset-{rid}"} for rid in list(dict.fromkeys(r.id for r in hit["rows"]))[:5000]],
        })
    return out


def _component(row: CbomCollectedAsset, source_name: str | None) -> dict[str, Any]:
    facts = row.facts or {}
    ref = f"zs-asset-{row.id}"
    props = [
        {"name": "zs:location", "value": row.location},
        {"name": "zs:asset_type", "value": row.asset_type},
        {"name": "zs:target", "value": row.target or ""},
        {"name": "zs:source", "value": source_name or ""},
        {"name": "zs:impact", "value": row.impact or "Info"},
        {"name": "zs:quantum_vulnerable", "value": "unknown" if row.quantum_vulnerable is None else str(row.quantum_vulnerable).lower()},
    ]
    if row.finding:
        props.append({"name": "zs:finding", "value": row.finding})
    for code in row.finding_codes or []:
        props.append({"name": "zs:finding_code", "value": str(code)})
    name = row.name or row.algorithm or row.location
    if row.cdx_type == "library":
        from backend.utilities.cbom_sources.sbom_link import ecosystem_of, library_purl

        package, version = str(facts.get("package") or name)[:255], str(facts.get("version") or "")
        out = {"type": "library", "bom-ref": ref, "name": package, "version": version,
               "evidence": {"occurrences": [{"location": row.location}]}, "properties": props}
        purl = library_purl(package, version, ecosystem_of(facts.get("ecosystem") or facts.get("language")))
        if purl:
            out["purl"] = purl  # SBOM link: OS packages without an ecosystem are pkg:generic
        return out
    crypto: dict[str, Any] = {"assetType": row.cdx_type if row.cdx_type in ("certificate", "protocol", "related-crypto-material") else "algorithm"}
    if crypto["assetType"] == "certificate":
        crypto["certificateProperties"] = {
            "subjectName": facts.get("subject"), "issuerName": facts.get("issuer"),
            "notValidBefore": facts.get("not_before"), "notValidAfter": facts.get("not_after"),
            "certificateFormat": "X.509", "certificateExtension": facts.get("format") or "pem",
        }
        crypto["certificateProperties"] = {k: v for k, v in crypto["certificateProperties"].items() if v}
    elif crypto["assetType"] == "protocol":
        proto = (row.protocol or ("ssh" if "ssh" in row.asset_type else "tls")).lower()
        versions = facts.get("protocols") or ([row.protocol] if row.protocol else [])
        crypto["protocolProperties"] = {
            "type": "ssh" if proto.startswith("ssh") else ("tls" if "tls" in proto or "ssl" in proto or proto == "tls" else "other"),
            "version": ",".join(str(v) for v in versions)[:255] if versions else None,
            "cipherSuites": [{"name": str(c)} for c in (facts.get("ciphers") or ([facts["cipher"]] if facts.get("cipher") else []))][:200],
        }
        crypto["protocolProperties"] = {k: v for k, v in crypto["protocolProperties"].items() if v}
    elif crypto["assetType"] == "related-crypto-material":
        crypto["relatedCryptoMaterialProperties"] = {k: v for k, v in {
            "type": _REL_TYPE.get(row.asset_type, "other"), "size": row.key_size,
            "format": facts.get("format"), "state": _KEY_STATE.get(str(facts.get("key_state") or "")),
        }.items() if v}
    else:
        mode = str(facts.get("mode") or "").lower()
        crypto["algorithmProperties"] = {k: v for k, v in {
            "primitive": facts.get("primitive") if facts.get("primitive") in _CDX_PRIMITIVES else "other",
            "parameterSetIdentifier": str(row.key_size) if row.key_size else None,
            "mode": (mode if mode in _CDX_MODES else "other") if mode else None,
            # CycloneDX allows the quantum level only on algorithms: 0 means a quantum computer breaks it
            "nistQuantumSecurityLevel": 0 if row.quantum_vulnerable is True else None,
        }.items() if v is not None and v != ""}
    if row.algorithm:
        props.append({"name": "zs:algorithm", "value": row.algorithm})
    return {"type": "cryptographic-asset", "bom-ref": ref, "name": str(name)[:255], "cryptoProperties": crypto,
            "evidence": {"occurrences": [{"location": row.location}]}, "properties": props}


def cyclonedx(session: Session, run: CbomCollectionRun, now: _dt.datetime) -> dict[str, Any]:
    rows = session.exec(select(CbomCollectedAsset).where(CbomCollectedAsset.team_id == run.team_id,
                                                         CbomCollectedAsset.run_id == run.id)
                        .order_by(CbomCollectedAsset.id).limit(EXPORT_CAP + 1)).all()
    truncated = len(rows) > EXPORT_CAP
    rows = rows[:EXPORT_CAP]
    jobs = session.exec(select(CbomCollectionJob).where(CbomCollectionJob.run_id == run.id)).all()
    names = _source_names(session, run.team_id, list(jobs))
    job_names = {j.id: names.get(j.source_id or 0) or (j.params or {}).get("source_name") for j in jobs}
    gaps = []
    for job in jobs:
        info = _job_targets(job, names)
        for target in info["targets"]:
            if target.get("status") not in ("ok", None):
                gaps.append(f"{info['source_name']}: {target.get('target')} {target.get('status')}")
        if job.status != "success":
            gaps.append(f"{info['source_name']}: job {job.status}")
    kb_version = crypto_kb.version()
    versions = [(name, value) for name, value in (("zs:run_kb_version", run.kb_version),
                                                   ("zs:classifier_version", run.classifier_version),
                                                   ("zs:engine_version", run.engine_version)) if value]
    return {
        "bomFormat": "CycloneDX", "specVersion": "1.6", "serialNumber": export_serial(run.id or 0, kb_version),
        "version": 1,
        "metadata": {
            "timestamp": iso_z(now),
            "tools": {"components": [{"type": "application", "name": "ZeroShield CBOM Sources", "version": "1.0"}]},
            "properties": [
                {"name": "zs:run_id", "value": str(run.id)}, {"name": "zs:run_status", "value": run.status},
                {"name": "zs:asset_count", "value": str(len(rows))}, {"name": "zs:truncated", "value": str(truncated).lower()},
                {"name": "zs:kb_version", "value": kb_version},
                *[{"name": name, "value": str(value)} for name, value in versions],
                *[{"name": "zs:gap", "value": gap[:255]} for gap in gaps[:500]],
            ],
        },
        "components": [_component(row, names.get(row.source_id or 0) or job_names.get(row.job_id)) for row in rows],
        "vulnerabilities": vulnerabilities(list(rows)),
    }
