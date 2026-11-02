"""CERT-In Phase 4 — attestation re-run + sign/vex helpers for scan_data.

Applies uploaded attestations to persisted ``*_compliance`` blobs (NBE →
``pass_with_evidence``) without a full Celery rescan. Prefer full
``run_sbom_compliance`` when SBOM finding rows are present.
"""

from __future__ import annotations

import copy
import re
from datetime import datetime, timezone
from typing import Any

from backend.utilities.compliance.sbom_identity import parse_pkg

_BOM_TYPES = frozenset({"ai_bom", "cbom", "sbom_sca"})

_COMPLIANCE_KEY = {
    "ai_bom": "ai_bom_compliance",
    "cbom": "cbom_compliance",
    "sbom_sca": "sbom_compliance",
}

_BOM_JSON_KEY = {
    "ai_bom": "ai_bom_json",
    "cbom": "cbom_json",
    "sbom_sca": "sbom_json",
}

_PLACEHOLDER_RE = re.compile(
    r"^(?:sbom[\s_-]*dep(?:endency)?[\s_-]*\d+|sbom-dep-\d+|component-\d+)$",
    re.IGNORECASE,
)


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


def _is_placeholder(value: str) -> bool:
    return bool(_PLACEHOLDER_RE.match((value or "").strip()))


def _parse_name_version(dep: str) -> tuple[str, str]:
    raw = (dep or "").strip()
    if not raw:
        return "", ""
    if "==" in raw:
        name, _, ver = raw.partition("==")
        return name.strip(), ver.strip()
    if raw.startswith("@"):
        parts = raw.rsplit("@", 1)
        if len(parts) == 2 and "/" in parts[0]:
            return parts[0].strip(), parts[1].strip()
        return raw, ""
    if "@" in raw:
        name, _, ver = raw.partition("@")
        return name.strip(), ver.strip()
    return raw, ""


def _name_from_purl(purl: str) -> str:
    body = purl.split("?", 1)[0]
    if "@" in body:
        body = body.rsplit("@", 1)[0]
    if "/" in body:
        body = body.rsplit("/", 1)[-1]
    if body.startswith("pkg:"):
        body = body.split("/", 1)[-1]
    return body.strip()


def _row_identity(row: dict[str, Any]) -> tuple[str, str, str | None]:
    ident = parse_pkg(
        name="",
        version="",
        purl=str(row.get("purl") or "") if isinstance(row.get("purl"), str) else "",
        dependency=str(row.get("dependency") or row.get("package_name") or ""),
    )
    name, version, purl = ident.name, ident.version, ident.purl or None
    title = str(row.get("title") or "").strip()
    if _is_placeholder(name) and title.lower().startswith("inventory:"):
        fallback = parse_pkg(dependency=title.split(":", 1)[1].strip())
        name, version = fallback.name or name, fallback.version or version
        purl = purl or fallback.purl or None
    if _is_placeholder(name) and purl:
        name = _name_from_purl(purl)
    return name, version, purl


def _component_ref(name: str, version: str, purl: str | None, index: int) -> str:
    if purl:
        return purl
    if name and version:
        return f"{name}@{version}"
    if name and not _is_placeholder(name):
        return name
    return f"component-{index}"


def _component_from_finding(row: dict[str, Any], index: int) -> dict[str, Any] | None:
    name, version, purl = _row_identity(row)
    if not name or _is_placeholder(name):
        return None
    comp: dict[str, Any] = {
        "bom-ref": _component_ref(name, version, purl, index),
        "name": name,
        "type": "library",
    }
    if version:
        comp["version"] = version
    if purl:
        comp["purl"] = purl
    return comp


def _stub_sbom_from_findings(findings: list[Any] | None) -> dict[str, Any]:
    comps: list[dict[str, Any]] = []
    seen: set[str] = set()
    for i, row in enumerate(findings or []):
        if not isinstance(row, dict):
            continue
        comp = _component_from_finding(row, i)
        if not comp:
            continue
        ref = str(comp.get("bom-ref") or "")
        if ref in seen:
            continue
        seen.add(ref)
        comps.append(comp)
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "authors": [{"name": "DevSecShield"}],
            "tools": {
                "components": [
                    {"type": "application", "name": "DevSecShield SBOM", "publisher": "DevSecShield"}
                ]
            },
        },
        "components": comps,
    }


def _rewrite_placeholder_components(bom: dict[str, Any]) -> None:
    comps = bom.get("components")
    if not isinstance(comps, list):
        return
    rewritten: list[dict[str, Any]] = []
    for i, raw in enumerate(comps):
        if not isinstance(raw, dict):
            continue
        item = dict(raw)
        name = str(item.get("name") or "").strip()
        version = str(item.get("version") or "").strip()
        purl = item.get("purl") if isinstance(item.get("purl"), str) else None
        purl = purl.strip() if purl else None
        if _is_placeholder(name) and purl:
            name = _name_from_purl(purl)
            item["name"] = name
        ref = str(item.get("bom-ref") or "").strip()
        if not ref or _is_placeholder(ref):
            item["bom-ref"] = _component_ref(name, version, purl, i)
        if name and not _is_placeholder(name):
            rewritten.append(item)
    bom["components"] = rewritten


def overlay_compliance_on_bom(
    bom: dict[str, Any],
    compliance: dict[str, Any] | None,
    *,
    findings: list[Any] | None = None,
    subject_name: str | None = None,
) -> dict[str, Any]:
    """Copy ``bom`` into an industry CycloneDX document with one Pass/Fail field."""
    from backend.utilities.compliance.sbom_cyclonedx import sanitize_industry_sbom

    out = copy.deepcopy(bom) if isinstance(bom, dict) else {}
    if not isinstance(out, dict):
        out = {}
    out.setdefault("bomFormat", "CycloneDX")
    out.setdefault("specVersion", "1.6")
    out.setdefault("version", 1)
    _rewrite_placeholder_components(out)
    comps = out.get("components")
    if (not isinstance(comps, list) or not comps) and findings:
        stub = _stub_sbom_from_findings(findings)
        if stub["components"]:
            out["components"] = stub["components"]
    return sanitize_industry_sbom(
        out,
        compliance=compliance if isinstance(compliance, dict) else None,
        findings=findings,
        subject_name=subject_name,
    )


def bom_dict_from_scan_data(
    scan_type: str,
    scan_data: dict[str, Any],
    *,
    subject_name: str | None = None,
) -> dict[str, Any] | None:
    if not isinstance(scan_data, dict):
        scan_data = {}
    key = _BOM_JSON_KEY.get(scan_type)
    compliance_key = _COMPLIANCE_KEY.get(scan_type)
    compliance = scan_data.get(compliance_key) if compliance_key else None
    findings = scan_data.get("results") if isinstance(scan_data.get("results"), list) else None
    bom: dict[str, Any] | None = None
    if key and isinstance(scan_data.get(key), dict):
        bom = scan_data[key]
    elif scan_type == "sbom_sca":
        bom = _stub_sbom_from_findings(findings)
    if not isinstance(bom, dict):
        return None
    if scan_type == "sbom_sca":
        return overlay_compliance_on_bom(
            bom,
            compliance if isinstance(compliance, dict) else None,
            findings=findings,
            subject_name=subject_name,
        )
    if scan_type == "cbom":
        # library components get a purl (SBOM link); every export and its signature are built here, so they agree
        from backend.utilities.cbom_sources.sbom_link import with_library_purls

        return with_library_purls(bom)
    return bom


__all__ = [
    "apply_evidence_to_compliance",
    "bom_dict_from_scan_data",
    "compliance_key_for",
    "delete_attestation",
    "evidence_map_from_attestations",
    "overlay_compliance_on_bom",
    "recompute_compliance_for_scan",
    "requirement_ids_in_compliance",
    "upsert_attestation",
]
