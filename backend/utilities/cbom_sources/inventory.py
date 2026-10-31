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
from backend.utilities.cbom_sources.common import iso_z

EXPORT_CAP = 50_000
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
             "signing_key": "public-key", "kms_key": "key", "cloud_secret": "secret-key", "keystore": "key",
             "k8s_certificate": "key"}


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
        return {"type": "library", "bom-ref": ref, "name": str(facts.get("package") or name)[:255],
                "version": str(facts.get("version") or ""), "evidence": {"occurrences": [{"location": row.location}]},
                "properties": props}
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
            "format": facts.get("format"), "state": facts.get("key_state"),
        }.items() if v}
    else:
        crypto["algorithmProperties"] = {k: v for k, v in {
            "primitive": facts.get("primitive") or "other", "parameterSetIdentifier": str(row.key_size) if row.key_size else None,
            "mode": facts.get("mode"),
        }.items() if v}
    if row.algorithm:
        props.append({"name": "zs:algorithm", "value": row.algorithm})
    if row.quantum_vulnerable is False and row.cdx_type in ("protocol", "related-crypto-material", "certificate"):
        crypto["nistQuantumSecurityLevel"] = 1
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
    return {
        "bomFormat": "CycloneDX", "specVersion": "1.6", "serialNumber": f"urn:uuid:{uuid.uuid4()}", "version": 1,
        "metadata": {
            "timestamp": iso_z(now),
            "tools": {"components": [{"type": "application", "name": "ZeroShield CBOM Sources", "version": "1.0"}]},
            "properties": [
                {"name": "zs:run_id", "value": str(run.id)}, {"name": "zs:run_status", "value": run.status},
                {"name": "zs:asset_count", "value": str(len(rows))}, {"name": "zs:truncated", "value": str(truncated).lower()},
                *[{"name": "zs:gap", "value": gap[:255]} for gap in gaps[:500]],
            ],
        },
        "components": [_component(row, names.get(row.source_id or 0) or job_names.get(row.job_id)) for row in rows],
    }
