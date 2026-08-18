"""CERT-In Phase 4 — attestation re-run + sign/vex helpers for scan_data.

Applies uploaded attestations to persisted ``*_compliance`` blobs (NBE →
``pass_with_evidence``) without a full Celery rescan. Prefer full
``run_sbom_compliance`` when SBOM finding rows are present.
"""

from __future__ import annotations

import copy
from datetime import datetime, timezone
from typing import Any

_BOM_TYPES = frozenset({"ai_bom", "cbom", "sbom_sca"})

_COMPLIANCE_KEY = {
    "ai_bom": "ai_bom_compliance",
    "cbom": "cbom_compliance",
    "sbom_sca": "sbom_compliance",
}

_BOM_JSON_KEY = {
    "ai_bom": "ai_bom_json",
    "cbom": "cbom_json",
    "sbom_sca": None,
}


def compliance_key_for(scan_type: str) -> str:
    if scan_type not in _COMPLIANCE_KEY:
        raise ValueError(f"unsupported scan_type for CERT-In attest: {scan_type}")
    return _COMPLIANCE_KEY[scan_type]


def evidence_map_from_attestations(
    attestations: dict[str, Any] | None,
) -> dict[str, dict[str, str]]:
    """Flatten persisted attestations to ``{fw: {rid: note}}`` for ``run_framework``."""
    out: dict[str, dict[str, str]] = {}
    if not isinstance(attestations, dict):
        return out
    for fw, reqs in attestations.items():
        if fw == "disclaimer" or not isinstance(reqs, dict):
            continue
        bucket: dict[str, str] = {}
        for rid, meta in reqs.items():
            if isinstance(meta, str) and meta.strip():
                bucket[rid] = meta.strip()
            elif isinstance(meta, dict):
                note = meta.get("note") or meta.get("filename") or meta.get("attestation")
                if note and str(note).strip():
                    bucket[rid] = str(note).strip()
        if bucket:
            out[str(fw)] = bucket
    return out


def apply_evidence_to_compliance(
    compliance: dict[str, Any],
    evidence: dict[str, dict[str, str]],
) -> dict[str, Any]:
    """Return a deep-copied compliance blob with NBE flipped where attested."""
    result = copy.deepcopy(compliance)
    for fw, fw_evidence in evidence.items():
        block = result.get(fw)
        if not isinstance(block, dict):
            continue
        reqs = block.get("requirements")
        if not isinstance(reqs, list):
            continue
        for req in reqs:
            if not isinstance(req, dict):
                continue
            rid = req.get("id")
            if rid in fw_evidence and req.get("verdict") == "not_bom_evidenceable":
                req["verdict"] = "pass_with_evidence"
                req["evidence"] = f"attested: {fw_evidence[rid]}"
                req["attestable"] = True
        _recount_framework(block)
    return result


def _recount_framework(block: dict[str, Any]) -> None:
    states = (
        "pass",
        "pass_with_evidence",
        "fail",
        "out_of_scope",
        "not_bom_evidenceable",
        "na",
    )
    counts = dict.fromkeys(states, 0)
    for req in block.get("requirements") or []:
        if not isinstance(req, dict):
            continue
        v = req.get("verdict")
        if v in counts:
            counts[v] += 1
    for k, n in counts.items():
        block[k] = n
    n_pass = counts["pass"] + counts["pass_with_evidence"]
    applicable = n_pass + counts["fail"]
    block["coverage"] = round(n_pass / applicable, 3) if applicable else None


def requirement_ids_in_compliance(
    compliance: dict[str, Any], framework: str
) -> set[str]:
    block = compliance.get(framework)
    if not isinstance(block, dict):
        return set()
    return {
        str(r["id"])
        for r in (block.get("requirements") or [])
        if isinstance(r, dict) and r.get("id")
    }


def recompute_compliance_for_scan(
    scan_type: str,
    scan_data: dict[str, Any],
    attestations: dict[str, Any],
) -> dict[str, Any]:
    """Recompute ``*_compliance`` using attestations; return updated scan_data copy."""
    if scan_type not in _BOM_TYPES:
        raise ValueError(f"unsupported scan_type: {scan_type}")
    data = copy.deepcopy(scan_data) if isinstance(scan_data, dict) else {}
    data["attestations"] = attestations
    evidence = evidence_map_from_attestations(attestations)
    ckey = compliance_key_for(scan_type)

    if scan_type == "sbom_sca":
        results = data.get("results")
        if isinstance(results, list):
            try:
                from aibom.sbom.compliance import run_sbom_compliance

                data[ckey] = run_sbom_compliance(results, evidence=evidence)
                return data
            except Exception:
                pass  # fall through to in-place flip

    existing = data.get(ckey)
    if not isinstance(existing, dict) or not existing:
        raise ValueError("scan has no compliance blob to re-evaluate")
    data[ckey] = apply_evidence_to_compliance(existing, evidence)
    return data


def upsert_attestation(
    attestations: dict[str, Any] | None,
    *,
    framework: str,
    requirement_id: str,
    filename: str,
    note: str | None = None,
) -> dict[str, Any]:
    out = copy.deepcopy(attestations) if isinstance(attestations, dict) else {}
    fw_bucket = out.setdefault(framework, {})
    if not isinstance(fw_bucket, dict):
        fw_bucket = {}
        out[framework] = fw_bucket
    fw_bucket[requirement_id] = {
        "filename": filename,
        "note": note or filename,
        "uploaded_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    return out


def delete_attestation(
    attestations: dict[str, Any] | None,
    *,
    framework: str,
    requirement_id: str,
) -> dict[str, Any]:
    out = copy.deepcopy(attestations) if isinstance(attestations, dict) else {}
    fw = out.get(framework)
    if isinstance(fw, dict) and requirement_id in fw:
        del fw[requirement_id]
        if not fw:
            del out[framework]
    return out


def bom_dict_from_scan_data(scan_type: str, scan_data: dict[str, Any]) -> dict[str, Any] | None:
    key = _BOM_JSON_KEY.get(scan_type)
    if key and isinstance(scan_data.get(key), dict):
        return scan_data[key]
    # Minimal SBOM stand-in from findings for signing/VEX when no CDX present.
    if scan_type == "sbom_sca":
        results = scan_data.get("results")
        if isinstance(results, list):
            comps = []
            for i, row in enumerate(results):
                if not isinstance(row, dict):
                    continue
                dep = str(row.get("dependency") or row.get("package_name") or "").strip()
                if not dep:
                    continue
                name = dep.split("@")[0].split("==")[0].strip()
                comps.append({"bom-ref": f"sbom-dep-{i}", "name": name, "type": "library"})
            return {
                "bomFormat": "CycloneDX",
                "specVersion": "1.6",
                "version": 1,
                "components": comps,
            }
    return None


__all__ = [
    "apply_evidence_to_compliance",
    "bom_dict_from_scan_data",
    "compliance_key_for",
    "delete_attestation",
    "evidence_map_from_attestations",
    "recompute_compliance_for_scan",
    "requirement_ids_in_compliance",
    "upsert_attestation",
]
