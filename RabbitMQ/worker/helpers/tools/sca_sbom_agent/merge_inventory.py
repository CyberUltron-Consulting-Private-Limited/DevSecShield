"""Merge Syft/cdxgen CycloneDX components and project SBOM finding rows."""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from helpers.tools.sca_sbom_agent.sbom_license import resolve_emit_license


def _norm_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", (name or "").strip().lower())


def _load_components(path: Path | None) -> list[dict[str, Any]]:
    if path is None or not path.is_file():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    except Exception:
        return []
    comps = data.get("components")
    return comps if isinstance(comps, list) else []


def _comp_key(c: dict[str, Any]) -> str:
    purl = c.get("purl")
    if isinstance(purl, str) and purl.strip():
        # strip version for key? keep full purl for uniqueness of version
        return purl.strip().lower()
    name = str(c.get("name") or "").strip()
    ver = str(c.get("version") or "").strip()
    return f"{_norm_name(name)}@{ver}"


def _license_str(c: dict[str, Any]) -> str:
    lic = c.get("licenses")
    if not isinstance(lic, list) or not lic:
        return ""
    first = lic[0]
    if isinstance(first, dict):
        license_obj = first.get("license") or first
        if isinstance(license_obj, dict):
            return str(license_obj.get("id") or license_obj.get("name") or "").strip()
        return str(license_obj).strip()
    return ""


def _hash_str(c: dict[str, Any]) -> str:
    hashes = c.get("hashes")
    if not isinstance(hashes, list):
        return ""
    for h in hashes:
        if isinstance(h, dict) and h.get("content"):
            alg = h.get("alg") or "hash"
            return f"{alg}:{h['content']}"
    return ""


def merge_cdx_components(*paths: Path | None) -> list[dict[str, Any]]:
    """Dedupe CycloneDX components by purl / name@version (later sources fill gaps)."""
    by_key: dict[str, dict[str, Any]] = {}
    for path in paths:
        for c in _load_components(path):
            if not isinstance(c, dict):
                continue
            name = str(c.get("name") or "").strip()
            if not name:
                continue
            key = _comp_key(c)
            existing = by_key.get(key)
            if existing is None:
                by_key[key] = dict(c)
            else:
                # Prefer non-empty fields from either side
                for field in ("version", "purl", "description", "publisher", "type"):
                    if not existing.get(field) and c.get(field):
                        existing[field] = c[field]
                if not existing.get("licenses") and c.get("licenses"):
                    existing["licenses"] = c["licenses"]
                if not existing.get("hashes") and c.get("hashes"):
                    existing["hashes"] = c["hashes"]
    return list(by_key.values())


def inventory_to_finding_rows(
    components: list[dict[str, Any]],
    *,
    vuln_assessed: bool = False,
) -> list[dict[str, Any]]:
    """Project merged inventory components into enrich_sbom_scan finding rows."""
    rows: list[dict[str, Any]] = []
    for c in components:
        name = str(c.get("name") or "").strip()
        if not name:
            continue
        version = str(c.get("version") or "").strip()
        dep = f"{name}=={version}" if version else name
        purl = c.get("purl") if isinstance(c.get("purl"), str) else None
        desc = str(c.get("description") or "").strip()
        lic_raw = _license_str(c)
        license_spdx, license_type = resolve_emit_license(name, lic_raw)
        h = _hash_str(c)
        supplier = str(c.get("publisher") or c.get("supplier") or "").strip()
        row: dict[str, Any] = {
            "dependency": dep,
            "title": f"Inventory: {name}",
            "description": desc or f"Inventoried component {dep}",
            "impact": "Low",
            "reachability": "not_reachable",
            "license": license_spdx,
            "license_type": license_type,
            "cves": {},
            "owasp_top_10": {},
            "compliance_controls": {},
            "suggested_fix": "n/a — inventory row",
            "dependency_type": "direct",
            "inventory_only": True,
            "vuln_assessed": bool(vuln_assessed),
        }
        if purl:
            row["purl"] = purl
        if h:
            row["hash"] = h
        if supplier:
            row["supplier"] = supplier
        rows.append(row)
    return rows


def load_cdx_json(path: Path | None) -> dict[str, Any] | None:
    if path is None or not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
        return data if isinstance(data, dict) else None
    except Exception:
        return None


_PLACEHOLDER_RE = re.compile(
    r"^(?:sbom[\s_-]*dep(?:endency)?[\s_-]*\d+|sbom-dep-\d+|component-\d+)$",
    re.IGNORECASE,
)


def _is_placeholder(value: str) -> bool:
    return bool(_PLACEHOLDER_RE.match((value or "").strip()))


def assemble_cyclonedx(
    components: list[dict[str, Any]],
    *,
    base: dict[str, Any] | None = None,
    tools: list[str] | None = None,
    subject_name: str | None = None,
) -> dict[str, Any]:
    """Build a CycloneDX 1.6 document from merged inventory components.

    Prefers metadata/dependencies from ``base`` (Syft or cdxgen) but always
    emits the merged component list with real package names — never
    ``sbom-dep-N`` placeholders.
    """
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    doc: dict[str, Any] = dict(base) if isinstance(base, dict) else {}
    doc["bomFormat"] = "CycloneDX"
    doc.setdefault("specVersion", "1.6")
    doc.setdefault("version", 1)
    if not doc.get("serialNumber"):
        doc["serialNumber"] = f"urn:uuid:{uuid4()}"

    cleaned: list[dict[str, Any]] = []
    seen: set[str] = set()
    for i, raw in enumerate(components):
        if not isinstance(raw, dict):
            continue
        name = str(raw.get("name") or "").strip()
        if not name or _is_placeholder(name):
            continue
        item = dict(raw)
        version = str(item.get("version") or "").strip()
        purl = item.get("purl") if isinstance(item.get("purl"), str) else None
        purl = purl.strip() if purl else None
        item["name"] = name
        item.setdefault("type", "library")
        ref = str(item.get("bom-ref") or "").strip()
        if not ref or _is_placeholder(ref):
            item["bom-ref"] = purl or (f"{name}@{version}" if version else name) or f"component-{i}"
        key = str(item["bom-ref"])
        if key in seen:
            continue
        seen.add(key)
        cleaned.append(item)
    doc["components"] = cleaned

    meta = doc.get("metadata")
    if not isinstance(meta, dict):
        meta = {}
        doc["metadata"] = meta
    meta.setdefault("timestamp", now)
    if not meta.get("authors"):
        meta["authors"] = [{"name": "DevSecShield"}]
    if subject_name:
        root = meta.get("component")
        if not isinstance(root, dict) or not str(root.get("name") or "").strip():
            meta["component"] = {"type": "application", "name": subject_name}
    if tools:
        meta["tools"] = {
            "components": [
                {"type": "application", "name": tool, "publisher": "DevSecShield"}
                for tool in tools
            ]
        }
    return doc
