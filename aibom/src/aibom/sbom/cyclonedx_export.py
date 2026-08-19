"""Stamp a single advisory Pass/Fail onto a CycloneDX SBOM (worker persist path).

Mirrors backend ``sbom_cyclonedx.sanitize_industry_sbom`` at a thinner layer:
strip Syft/tool noise and per-framework dumps; keep one ``dss:compliance``
property. The API re-sanitizes on read for licenses/CVEs/supplier.
"""
from __future__ import annotations

import copy
from typing import Any

_HIGH_IMPACT = frozenset({"critical", "high"})
_HIGH_LICENSE = frozenset(
    {"strong_copyleft", "network_copyleft", "source_available"}
)


def _overall_verdict(compliance: dict[str, Any] | None) -> str:
    if not isinstance(compliance, dict) or not compliance:
        return "unknown"
    fails = 0
    passes = 0
    for fw, block in compliance.items():
        if fw == "disclaimer" or not isinstance(block, dict):
            continue
        if int(block.get("fail") or 0) > 0:
            fails += 1
        elif int(block.get("pass") or 0) + int(block.get("pass_with_evidence") or 0) > 0:
            passes += 1
    if fails:
        return "fail"
    if passes:
        return "pass"
    return "unknown"


def _keep_prop(name: str) -> bool:
    if name == "dss:compliance":
        return True
    if name.startswith("dss:") or name.startswith("syft:"):
        return False
    return True


def _filter_props(props: Any, extra: dict[str, str] | None = None) -> list[dict[str, str]]:
    kept: list[dict[str, str]] = []
    seen: set[str] = set()
    if isinstance(props, list):
        for item in props:
            if not isinstance(item, dict):
                continue
            name = str(item.get("name") or "")
            if not name or not _keep_prop(name) or name in seen:
                continue
            kept.append({"name": name, "value": str(item.get("value") or "")})
            seen.add(name)
    if extra:
        for name, value in extra.items():
            if name not in seen:
                kept.append({"name": name, "value": value})
                seen.add(name)
    return kept


def overlay_sbom_document(
    bom: dict[str, Any] | None,
    compliance: dict[str, Any] | None,
) -> dict[str, Any] | None:
    if not isinstance(bom, dict):
        return bom
    out = copy.deepcopy(bom)
    out.setdefault("bomFormat", "CycloneDX")
    out.setdefault("specVersion", "1.6")
    meta = out.get("metadata")
    if not isinstance(meta, dict):
        meta = {}
        out["metadata"] = meta
    verdict = _overall_verdict(compliance)
    meta["properties"] = _filter_props(meta.get("properties"), {"dss:compliance": verdict})
    comps = out.get("components")
    if isinstance(comps, list):
        kept: list[dict[str, Any]] = []
        for comp in comps:
            if not isinstance(comp, dict):
                continue
            name = str(comp.get("name") or "").strip()
            ctype = str(comp.get("type") or "library").lower()
            purl = str(comp.get("purl") or "").strip()
            if not name:
                continue
            if ctype == "file" and not purl:
                continue
            if name.startswith("/tmp/") and not purl:
                continue
            kept.append(comp)
        out["components"] = kept
    return out


def stamp_component_compliance(
    bom: dict[str, Any] | None,
    findings: list[dict[str, Any]] | None,
) -> dict[str, Any] | None:
    """Add ``dss:compliance`` pass/fail on matching inventory components."""
    if not isinstance(bom, dict) or not findings:
        return bom
    by_purl: dict[str, str] = {}
    by_name: dict[str, str] = {}
    for row in findings:
        if not isinstance(row, dict):
            continue
        dep = str(row.get("dependency") or "").strip()
        name = dep.split("@")[0].split("==")[0].strip().lower()
        impact = str(row.get("impact") or "").strip()
        license_type = str(row.get("license_type") or "").strip()
        fail = impact.lower() in _HIGH_IMPACT or license_type.lower() in _HIGH_LICENSE
        verdict = "fail" if fail else "pass"
        purl = row.get("purl")
        if isinstance(purl, str) and purl.strip():
            by_purl[purl.strip().lower()] = verdict
        if name:
            by_name[name] = verdict
    comps = bom.get("components")
    if not isinstance(comps, list):
        return bom
    for comp in comps:
        if not isinstance(comp, dict):
            continue
        purl = str(comp.get("purl") or "").strip().lower()
        name = str(comp.get("name") or "").strip().lower()
        verdict = by_purl.get(purl) or by_name.get(name)
        extra = {"dss:compliance": verdict} if verdict else None
        filtered = _filter_props(comp.get("properties"), extra)
        if filtered:
            comp["properties"] = filtered
        elif "properties" in comp:
            del comp["properties"]
    return bom


__all__ = ["overlay_sbom_document", "stamp_component_compliance"]
