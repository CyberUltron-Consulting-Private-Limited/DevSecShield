"""NTIA minimum elements and CERT-In SBOM fields, counted from the CycloneDX document itself (FIX-C1, SOW D4).

The SBOM PDF shows this table next to the framework results, so a reader can see how many components carry each
element in the very file they download (``/bom``), not a score derived from finding rows. Standard library only.

References: NTIA "The Minimum Elements For a Software Bill of Materials" (July 2021): supplier, component name,
version, other unique identifiers, dependency relationship, author of SBOM data, timestamp; CERT-In "Technical
Guidelines on SBOM, QBOM & CBOM, AIBOM and HBOM" v2.0 Table 5 (component fields incl. licence, checksums).
"""
from __future__ import annotations

from typing import Any, Callable

_UNKNOWN_LICENCE = {"", "noassertion", "none", "unknown", "not_declared", "licenseref-not-declared"}


def _supplier(c: dict[str, Any]) -> bool:
    sup = c.get("supplier")
    return bool((isinstance(sup, dict) and str(sup.get("name") or "").strip()) or str(c.get("publisher") or "").strip())


def _unique_id(c: dict[str, Any]) -> bool:
    return any(str(c.get(k) or "").strip() for k in ("purl", "cpe", "swid", "omniborId", "swhid"))


def _hash(c: dict[str, Any]) -> bool:
    return any(isinstance(h, dict) and str(h.get("content") or "").strip() for h in c.get("hashes") or [])


def _licence(c: dict[str, Any]) -> bool:
    for item in c.get("licenses") or []:
        if not isinstance(item, dict):
            continue
        lic = item.get("license") if isinstance(item.get("license"), dict) else {}
        token = str(lic.get("id") or lic.get("name") or item.get("expression") or "").strip().lower()
        if token not in _UNKNOWN_LICENCE:
            return True
    return False


def _reachable(bom: dict[str, Any]) -> set[str]:
    root = str(((bom.get("metadata") or {}).get("component") or {}).get("bom-ref") or "")
    graph: dict[str, list[str]] = {}
    for d in bom.get("dependencies") or []:
        if isinstance(d, dict) and d.get("ref"):
            graph.setdefault(str(d["ref"]), []).extend(str(k) for k in d.get("dependsOn") or [])
    seen: set[str] = set()
    todo = [root] if root else []
    while todo:
        for kid in graph.get(todo.pop(), []):
            if kid not in seen:
                seen.add(kid)
                todo.append(kid)
    return seen


# (element, NTIA element, CERT-In Table 5 field, required: False = "when known" (hashes), per-component test)
_COMPONENT_ELEMENTS: list[tuple[str, str, str, bool, Callable[[dict[str, Any]], bool]]] = [
    ("Supplier name", "NTIA-1", "T5-Component-Supplier", True, _supplier),
    ("Component name", "NTIA-2", "T5-Component-Name", True, lambda c: bool(str(c.get("name") or "").strip())),
    ("Version", "NTIA-3", "T5-Component-Version", True, lambda c: bool(str(c.get("version") or "").strip())),
    ("Unique identifier (purl / CPE)", "NTIA-4", "T5-Unique-Identifier", True, _unique_id),
    ("Hash / checksum (when known)", "NTIA-8", "T5-Checksums-or-Hashes", False, _hash),
    ("Licence", "NTIA-9", "T5-Component-License", True, _licence),
]


def minimum_elements(bom: dict[str, Any] | None) -> dict[str, Any]:
    """Rows ``{element, ntia, cert_in, present, total, status}``; status is pass / partial / missing (a "when
    known" element that is partly present is ``partial``, never a failure)."""
    bom = bom if isinstance(bom, dict) else {}
    comps = [c for c in bom.get("components") or [] if isinstance(c, dict) and str(c.get("name") or "").strip()]
    total = len(comps)
    rows: list[dict[str, Any]] = []

    def add(element: str, ntia: str, cert_in: str, present: int, of: int) -> None:
        status = "pass" if of and present == of else ("partial" if present else "missing")
        rows.append({"element": element, "ntia": ntia, "cert_in": cert_in, "present": present, "total": of,
                     "status": status})

    for element, ntia, cert_in, _required, test in _COMPONENT_ELEMENTS:
        add(element, ntia, cert_in, sum(1 for c in comps if test(c)), total)
    reach = _reachable(bom)
    add("Dependency relationship (reachable from the subject)", "NTIA-5", "T5-Component-Dependencies",
        sum(1 for c in comps if str(c.get("bom-ref") or "") in reach), total)
    meta = bom.get("metadata") if isinstance(bom.get("metadata"), dict) else {}
    authors = [a for a in meta.get("authors") or [] if isinstance(a, dict) and str(a.get("name") or "").strip()]
    add("Author of SBOM data", "NTIA-6", "T5-Author-of-SBOM-Data", 1 if authors else 0, 1)
    add("Timestamp", "NTIA-7", "T5-Timestamp", 1 if str(meta.get("timestamp") or "").strip() else 0, 1)
    tools = meta.get("tools") if isinstance(meta.get("tools"), dict) else {}
    named = [t for t in tools.get("components") or [] if isinstance(t, dict) and t.get("name")]
    add("Generating tools named, with versions", "—", "T5-Inventory-Tools",
        sum(1 for t in named if t.get("version")), len(named) or 1)
    vulns = bom.get("vulnerabilities")
    add("Known vulnerabilities linked", "—", "T5-Vulnerabilities", 1 if isinstance(vulns, list) else 0, 1)
    return {
        "spec_version": str(bom.get("specVersion") or ""),
        "components": total,
        "vulnerabilities": len(vulns) if isinstance(vulns, list) else 0,
        "rows": rows,
    }


__all__ = ["minimum_elements"]
