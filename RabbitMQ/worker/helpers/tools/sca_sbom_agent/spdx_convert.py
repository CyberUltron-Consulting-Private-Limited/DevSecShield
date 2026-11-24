"""Convert an uploaded SPDX SBOM to CycloneDX 1.6, offline (review 6028132826 M5).

An uploaded SPDX document used to be stored as uploaded with ``bomFormat: CycloneDX`` stamped on it: no inventory
rows, a ``/bom`` with only the vulnerable packages and no subject. Now it is converted first and then takes the same
path as a CycloneDX upload (``merge_cdx_components`` -> ``assemble_cyclonedx``).

* SPDX 2.2 / 2.3 JSON: every package becomes a component (name, version, supplier, purl and CPE from
  ``externalRefs``, checksums, licence, description); the element the document DESCRIBES is the subject
  (``metadata.component``); DEPENDS_ON and the *_DEPENDENCY_OF family become ``dependencies``. CONTAINS from the
  subject only says the package is part of it (every component is); other relationships are counted in
  ``dss:spdx_relationships_unmapped``, never turned into dependency edges.
* SPDX 3.0 JSON-LD: ``software_Package`` elements, ``dependsOn`` relationships and the document's ``rootElement``.

Standard library only.
"""
from __future__ import annotations

import re
from typing import Any

_HASH_ALG = {"SHA1": "SHA-1", "SHA256": "SHA-256", "SHA384": "SHA-384", "SHA512": "SHA-512", "MD5": "MD5",
             "SHA3-256": "SHA3-256", "SHA3-384": "SHA3-384", "SHA3-512": "SHA3-512", "BLAKE2B-256": "BLAKE2b-256",
             "BLAKE2B-384": "BLAKE2b-384", "BLAKE2B-512": "BLAKE2b-512", "BLAKE3": "BLAKE3",
             "SHA_1": "SHA-1", "SHA_256": "SHA-256", "SHA_384": "SHA-384", "SHA_512": "SHA-512"}
_HEX = re.compile(r"^[0-9a-fA-F]+$")
_NONE = frozenset({"", "NOASSERTION", "NONE"})
# A DEPENDENCY_OF B: B depends on A (reversed); A DEPENDS_ON B: A depends on B
_FORWARD = frozenset({"DEPENDS_ON"})
_REVERSED = frozenset({"DEPENDENCY_OF", "RUNTIME_DEPENDENCY_OF", "BUILD_DEPENDENCY_OF", "DEV_DEPENDENCY_OF",
                       "OPTIONAL_DEPENDENCY_OF", "PROVIDED_DEPENDENCY_OF", "TEST_DEPENDENCY_OF"})


def _list(value: Any) -> list[Any]:
    """A field that should be a list: anything else (a number, a string, an object from a hostile or broken
    document) is read as empty, never iterated (review 6032108510 m4)."""
    return value if isinstance(value, list) else []


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else (str(value) if isinstance(value, (int, float)) else "")


def is_spdx(doc: Any) -> bool:
    if not isinstance(doc, dict):
        return False
    if str(doc.get("spdxVersion") or "").startswith("SPDX-"):
        return True
    ctx = doc.get("@context")
    ctx_text = " ".join(ctx) if isinstance(ctx, list) else str(ctx or "")
    return "spdx.org/rdf/3" in ctx_text


def _supplier(raw: Any) -> dict[str, str] | None:
    text = _text(raw)
    if text.upper() in _NONE:
        return None
    for prefix in ("Organization:", "Person:", "Tool:"):
        if text.startswith(prefix):
            text = text[len(prefix):].strip()
    text = re.sub(r"\s*\([^)]*@[^)]*\)\s*$", "", text)  # "Name (email)"
    return {"name": text[:200]} if text else None


def _hashes(checksums: Any) -> list[dict[str, str]]:
    out = []
    for c in _list(checksums):
        if not isinstance(c, dict):
            continue
        alg = _HASH_ALG.get(_text(c.get("algorithm")).upper())
        value = _text(c.get("checksumValue") or c.get("hashValue"))
        if alg and value and _HEX.match(value):
            out.append({"alg": alg, "content": value.lower()})
    return out


def _licence(pkg: dict[str, Any]) -> str:
    for key in ("licenseConcluded", "licenseDeclared"):
        text = _text(pkg.get(key))
        if text.upper() not in _NONE:
            return text
    return ""


def _package_component(pkg: dict[str, Any]) -> dict[str, Any]:
    comp: dict[str, Any] = {"type": "library", "name": _text(pkg.get("name"))}
    version = _text(pkg.get("versionInfo"))
    if version and version.upper() not in _NONE:
        comp["version"] = version
    purpose = _text(pkg.get("primaryPackagePurpose")).upper()
    if purpose in {"APPLICATION", "FRAMEWORK", "CONTAINER", "OPERATING-SYSTEM", "DEVICE", "FIRMWARE", "FILE"}:
        comp["type"] = {"OPERATING-SYSTEM": "operating-system"}.get(purpose, purpose.lower())
    for ref in _list(pkg.get("externalRefs")):
        if not isinstance(ref, dict):
            continue
        rtype = _text(ref.get("referenceType")).lower()
        loc = _text(ref.get("referenceLocator"))
        if rtype == "purl" and loc and "purl" not in comp:
            comp["purl"] = loc
        elif rtype in {"cpe23type", "cpe22type"} and loc and "cpe" not in comp:
            comp["cpe"] = loc
    supplier = _supplier(pkg.get("supplier")) or _supplier(pkg.get("originator"))
    if supplier:
        comp["supplier"] = supplier
    hashes = _hashes(pkg.get("checksums"))
    if hashes:
        comp["hashes"] = hashes
    lic = _licence(pkg)
    if lic:
        comp["licenses"] = [{"expression": lic}] if re.search(r"\s(AND|OR|WITH)\s", lic) else [{"license": {"id": lic}}]
    desc = _text(pkg.get("description")) or _text(pkg.get("summary"))
    if desc:
        comp["description"] = desc[:2000]
    dl = _text(pkg.get("downloadLocation"))
    if dl and dl.upper() not in _NONE and re.match(r"^[a-z][a-z0-9+.-]*://", dl, re.I):
        comp["externalReferences"] = [{"type": "distribution", "url": dl}]
    comp["bom-ref"] = _text(pkg.get("SPDXID"))
    return comp


def _assemble(packages: list[dict[str, Any]], edges: list[tuple[str, str]], root_ids: list[str],
              unmapped: dict[str, int], created: str, creators: list[str], name: str,
              counts: dict[str, int] | None = None) -> dict[str, Any]:
    by_id = {c["bom-ref"]: c for c in packages if c.get("bom-ref")}
    root_id = next((r for r in root_ids if r in by_id), None)
    subject = None
    if root_id:
        subject = dict(by_id.pop(root_id))
        subject["type"] = "application"
    ref_of = {sid: (c.get("purl") or sid) for sid, c in by_id.items()}
    root_ref = (subject or {}).get("purl") or root_id or "urn:dss:spdx-subject"
    if subject is not None:
        ref_of[root_id] = root_ref
        subject["bom-ref"] = root_ref
    components = []
    for sid, comp in by_id.items():
        comp = dict(comp)
        comp["bom-ref"] = ref_of[sid]
        components.append(comp)
    graph: dict[str, dict[str, None]] = {}  # insertion-ordered sets: de-duplication is linear (m4)
    for src, dst in edges:
        a, b = ref_of.get(src), ref_of.get(dst)
        if a and b and a != b:
            graph.setdefault(a, {})[b] = None
    tools = []
    for c in creators:
        if isinstance(c, str) and c.startswith("Tool:"):
            tool = str(c)[5:].strip()
            tname, _, tver = tool.rpartition("-") if re.search(r"-\d", tool) else (tool, "", "")
            entry = {"type": "application", "name": tname or tool}
            if tver:
                entry["version"] = tver
            tools.append(entry)
    meta: dict[str, Any] = {"tools": {"components": tools}}
    if created:
        meta["timestamp"] = created
    if subject is not None:
        meta["component"] = subject
    props = [{"name": "dss:converted_from", "value": name}]
    if unmapped:
        props.append({"name": "dss:spdx_relationships_unmapped",
                      "value": ", ".join(f"{k}:{v}" for k, v in sorted(unmapped.items()))})
    for key, value in sorted((counts or {}).items()):
        if value:  # dss:spdx_packages_without_id, dss:spdx_invalid_entries: reported, never dropped silently
            props.append({"name": key, "value": str(value)})
    meta["properties"] = props
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "metadata": meta,
        "components": components,
        "dependencies": [{"ref": k, "dependsOn": list(v)} for k, v in graph.items()],
    }


def _packages(raw_packages: Any, counts: dict[str, int]) -> list[dict[str, Any]]:
    """Every package with a name becomes a component; one without an SPDXID gets a generated ref and is counted
    (``dss:spdx_packages_without_id``), not dropped; non-object entries are counted as invalid."""
    out: list[dict[str, Any]] = []
    for i, pkg in enumerate(_list(raw_packages)):
        if not isinstance(pkg, dict) or not _text(pkg.get("name")):
            counts["dss:spdx_invalid_entries"] = counts.get("dss:spdx_invalid_entries", 0) + 1
            continue
        comp = _package_component(pkg)
        if not comp["bom-ref"]:
            comp["bom-ref"] = f"urn:dss:spdx-package:{i}"
            counts["dss:spdx_packages_without_id"] = counts.get("dss:spdx_packages_without_id", 0) + 1
        out.append(comp)
    return out


def _from_spdx2(doc: dict[str, Any]) -> dict[str, Any]:
    if "packages" in doc and not isinstance(doc.get("packages"), list):
        raise ValueError("SPDX 'packages' is not a list")
    counts: dict[str, int] = {}
    packages = _packages(doc.get("packages"), counts)
    ids = {c["bom-ref"] for c in packages}
    roots = [_text(x) for x in _list(doc.get("documentDescribes")) if _text(x)]
    edges: list[tuple[str, str]] = []
    unmapped: dict[str, int] = {}
    doc_id = _text(doc.get("SPDXID")) or "SPDXRef-DOCUMENT"
    rels = [r for r in _list(doc.get("relationships")) if isinstance(r, dict)]
    for r in rels:
        kind = _text(r.get("relationshipType")).upper()
        a, b = _text(r.get("spdxElementId")), _text(r.get("relatedSpdxElement"))
        if kind == "DESCRIBES" and a == doc_id:
            roots.append(b)
        elif kind == "DESCRIBED_BY" and b == doc_id:
            roots.append(a)
    root_set = set(roots)
    for r in rels:
        kind = _text(r.get("relationshipType")).upper()
        a, b = _text(r.get("spdxElementId")), _text(r.get("relatedSpdxElement"))
        if kind in _FORWARD:
            edges.append((a, b))
        elif kind in _REVERSED:
            edges.append((b, a))
        elif kind in {"DESCRIBES", "DESCRIBED_BY"}:
            continue
        elif kind == "CONTAINS" and a in root_set and b in ids:
            continue  # the subject contains the package: it is a component of this SBOM
        else:
            unmapped[kind] = unmapped.get(kind, 0) + 1
    info = _dict(doc.get("creationInfo"))
    return _assemble(packages, edges, roots, unmapped, _text(info.get("created")),
                     [c for c in _list(info.get("creators")) if isinstance(c, str)],
                     _text(doc.get("spdxVersion")) or "SPDX-2", counts)


def _from_spdx3(doc: dict[str, Any]) -> dict[str, Any]:
    graph = doc.get("@graph") if isinstance(doc.get("@graph"), list) else [doc]
    counts: dict[str, int] = {}
    packages: list[dict[str, Any]] = []
    edges: list[tuple[str, str]] = []
    roots: list[str] = []
    unmapped: dict[str, int] = {}
    created = ""
    for el in graph:
        if not isinstance(el, dict):
            counts["dss:spdx_invalid_entries"] = counts.get("dss:spdx_invalid_entries", 0) + 1
            continue
        etype = _text(el.get("type")) or _text(el.get("@type"))
        sid = _text(el.get("spdxId")) or _text(el.get("@id"))
        if etype in {"SpdxDocument", "software_Sbom"}:
            roots.extend(_text(x) for x in _list(el.get("rootElement")) if _text(x))
        elif etype == "software_Package" and el.get("name"):
            pkg = {"name": el.get("name"), "versionInfo": el.get("software_packageVersion"), "SPDXID": sid,
                   "description": el.get("description") or el.get("summary"),
                   "downloadLocation": el.get("software_downloadLocation"),
                   "checksums": [{"algorithm": h.get("algorithm"), "checksumValue": h.get("hashValue")}
                                 for h in _list(el.get("verifiedUsing")) if isinstance(h, dict)],
                   "externalRefs": []}
            if el.get("software_packageUrl"):
                pkg["externalRefs"].append({"referenceType": "purl", "referenceLocator": el["software_packageUrl"]})
            for ident in _list(el.get("externalIdentifier")):
                if isinstance(ident, dict):
                    kind = str(ident.get("externalIdentifierType") or "").lower()
                    if kind in {"packageurl", "cpe23"}:
                        pkg["externalRefs"].append({"referenceType": "purl" if kind == "packageurl" else "cpe23Type",
                                                    "referenceLocator": ident.get("identifier")})
            supplier = el.get("suppliedBy")
            if isinstance(supplier, str):
                pkg["supplier"] = supplier
            packages.extend(_packages([pkg], counts))
        elif etype in {"Relationship", "LifecycleScopedRelationship"}:
            kind = _text(el.get("relationshipType"))
            src = _text(el.get("from"))
            tos = [_text(t) for t in (el.get("to") if isinstance(el.get("to"), list) else [el.get("to")])]
            if kind == "dependsOn":
                edges.extend((src, str(t)) for t in tos if t)
            elif kind == "describes":
                roots.extend(str(t) for t in tos if t)
            elif kind == "contains" and src in roots:
                continue
            else:
                unmapped[kind] = unmapped.get(kind, 0) + 1
        elif etype == "CreationInfo" and not created:
            created = _text(el.get("created"))
        elif etype:
            continue
        else:
            counts["dss:spdx_invalid_entries"] = counts.get("dss:spdx_invalid_entries", 0) + 1
    return _assemble(packages, edges, roots, unmapped, created, [], "SPDX-3.0", counts)


def spdx_to_cyclonedx(doc: dict[str, Any]) -> dict[str, Any]:
    """A CycloneDX 1.6 source document for ``assemble_cyclonedx`` (raises ValueError for a non-SPDX document)."""
    if not is_spdx(doc):
        raise ValueError("not an SPDX document")
    if str(doc.get("spdxVersion") or "").startswith("SPDX-2"):
        return _from_spdx2(doc)
    return _from_spdx3(doc)


__all__ = ["is_spdx", "spdx_to_cyclonedx"]
