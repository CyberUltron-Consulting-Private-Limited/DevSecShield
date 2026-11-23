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


def is_spdx(doc: Any) -> bool:
    if not isinstance(doc, dict):
        return False
    if str(doc.get("spdxVersion") or "").startswith("SPDX-"):
        return True
    ctx = doc.get("@context")
    ctx_text = " ".join(ctx) if isinstance(ctx, list) else str(ctx or "")
    return "spdx.org/rdf/3" in ctx_text


def _supplier(raw: Any) -> dict[str, str] | None:
    text = str(raw or "").strip()
    if text.upper() in _NONE:
        return None
    for prefix in ("Organization:", "Person:", "Tool:"):
        if text.startswith(prefix):
            text = text[len(prefix):].strip()
    text = re.sub(r"\s*\([^)]*@[^)]*\)\s*$", "", text)  # "Name (email)"
    return {"name": text[:200]} if text else None


def _hashes(checksums: Any) -> list[dict[str, str]]:
    out = []
    for c in checksums or []:
        if not isinstance(c, dict):
            continue
        alg = _HASH_ALG.get(str(c.get("algorithm") or "").upper())
        value = str(c.get("checksumValue") or c.get("hashValue") or "").strip()
        if alg and value and _HEX.match(value):
            out.append({"alg": alg, "content": value.lower()})
    return out


def _licence(pkg: dict[str, Any]) -> str:
    for key in ("licenseConcluded", "licenseDeclared"):
        text = str(pkg.get(key) or "").strip()
        if text.upper() not in _NONE:
            return text
    return ""


def _package_component(pkg: dict[str, Any]) -> dict[str, Any]:
    comp: dict[str, Any] = {"type": "library", "name": str(pkg.get("name") or "").strip()}
    version = str(pkg.get("versionInfo") or "").strip()
    if version and version.upper() not in _NONE:
        comp["version"] = version
    purpose = str(pkg.get("primaryPackagePurpose") or "").upper()
    if purpose in {"APPLICATION", "FRAMEWORK", "CONTAINER", "OPERATING-SYSTEM", "DEVICE", "FIRMWARE", "FILE"}:
        comp["type"] = {"OPERATING-SYSTEM": "operating-system"}.get(purpose, purpose.lower())
    for ref in pkg.get("externalRefs") or []:
        if not isinstance(ref, dict):
            continue
        rtype = str(ref.get("referenceType") or "").lower()
        loc = str(ref.get("referenceLocator") or "").strip()
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
    desc = str(pkg.get("description") or pkg.get("summary") or "").strip()
    if desc:
        comp["description"] = desc[:2000]
    dl = str(pkg.get("downloadLocation") or "").strip()
    if dl and dl.upper() not in _NONE and re.match(r"^[a-z][a-z0-9+.-]*://", dl, re.I):
        comp["externalReferences"] = [{"type": "distribution", "url": dl}]
    comp["bom-ref"] = str(pkg.get("SPDXID") or "")
    return comp


def _assemble(packages: list[dict[str, Any]], edges: list[tuple[str, str]], root_ids: list[str],
              unmapped: dict[str, int], created: str, creators: list[str], name: str) -> dict[str, Any]:
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
    graph: dict[str, list[str]] = {}
    for src, dst in edges:
        a, b = ref_of.get(src), ref_of.get(dst)
        if a and b and a != b:
            kids = graph.setdefault(a, [])
            if b not in kids:
                kids.append(b)
    tools = []
    for c in creators:
        if str(c).startswith("Tool:"):
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
    meta["properties"] = props
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "metadata": meta,
        "components": components,
        "dependencies": [{"ref": k, "dependsOn": v} for k, v in graph.items()],
    }


def _from_spdx2(doc: dict[str, Any]) -> dict[str, Any]:
    packages = [_package_component(p) for p in doc.get("packages") or [] if isinstance(p, dict) and p.get("name")]
    ids = {c["bom-ref"] for c in packages}
    roots = [str(x) for x in doc.get("documentDescribes") or []]
    edges: list[tuple[str, str]] = []
    unmapped: dict[str, int] = {}
    doc_id = str(doc.get("SPDXID") or "SPDXRef-DOCUMENT")
    rels = [r for r in doc.get("relationships") or [] if isinstance(r, dict)]
    for r in rels:
        kind = str(r.get("relationshipType") or "").upper()
        a, b = str(r.get("spdxElementId") or ""), str(r.get("relatedSpdxElement") or "")
        if kind == "DESCRIBES" and a == doc_id:
            roots.append(b)
        elif kind == "DESCRIBED_BY" and b == doc_id:
            roots.append(a)
    for r in rels:
        kind = str(r.get("relationshipType") or "").upper()
        a, b = str(r.get("spdxElementId") or ""), str(r.get("relatedSpdxElement") or "")
        if kind in _FORWARD:
            edges.append((a, b))
        elif kind in _REVERSED:
            edges.append((b, a))
        elif kind in {"DESCRIBES", "DESCRIBED_BY"}:
            continue
        elif kind == "CONTAINS" and a in roots and b in ids:
            continue  # the subject contains the package: it is a component of this SBOM
        else:
            unmapped[kind] = unmapped.get(kind, 0) + 1
    info = doc.get("creationInfo") if isinstance(doc.get("creationInfo"), dict) else {}
    return _assemble(packages, edges, roots, unmapped, str(info.get("created") or ""),
                     [str(c) for c in info.get("creators") or []], str(doc.get("spdxVersion") or "SPDX-2"))


def _from_spdx3(doc: dict[str, Any]) -> dict[str, Any]:
    graph = doc.get("@graph") if isinstance(doc.get("@graph"), list) else [doc]
    packages: list[dict[str, Any]] = []
    edges: list[tuple[str, str]] = []
    roots: list[str] = []
    unmapped: dict[str, int] = {}
    created = ""
    for el in graph:
        if not isinstance(el, dict):
            continue
        etype = str(el.get("type") or el.get("@type") or "")
        sid = str(el.get("spdxId") or el.get("@id") or "")
        if etype in {"SpdxDocument", "software_Sbom"}:
            roots.extend(str(x) for x in el.get("rootElement") or [])
        elif etype == "software_Package" and el.get("name"):
            pkg = {"name": el.get("name"), "versionInfo": el.get("software_packageVersion"), "SPDXID": sid,
                   "description": el.get("description") or el.get("summary"),
                   "downloadLocation": el.get("software_downloadLocation"),
                   "checksums": [{"algorithm": h.get("algorithm"), "checksumValue": h.get("hashValue")}
                                 for h in el.get("verifiedUsing") or [] if isinstance(h, dict)],
                   "externalRefs": []}
            if el.get("software_packageUrl"):
                pkg["externalRefs"].append({"referenceType": "purl", "referenceLocator": el["software_packageUrl"]})
            for ident in el.get("externalIdentifier") or []:
                if isinstance(ident, dict):
                    kind = str(ident.get("externalIdentifierType") or "").lower()
                    if kind in {"packageurl", "cpe23"}:
                        pkg["externalRefs"].append({"referenceType": "purl" if kind == "packageurl" else "cpe23Type",
                                                    "referenceLocator": ident.get("identifier")})
            supplier = el.get("suppliedBy")
            if isinstance(supplier, str):
                pkg["supplier"] = supplier
            packages.append(_package_component(pkg))
        elif etype in {"Relationship", "LifecycleScopedRelationship"}:
            kind = str(el.get("relationshipType") or "")
            src = str(el.get("from") or "")
            tos = el.get("to") if isinstance(el.get("to"), list) else [el.get("to")]
            if kind == "dependsOn":
                edges.extend((src, str(t)) for t in tos if t)
            elif kind == "describes":
                roots.extend(str(t) for t in tos if t)
            elif kind == "contains" and src in roots:
                continue
            else:
                unmapped[kind] = unmapped.get(kind, 0) + 1
        elif etype == "CreationInfo" and not created:
            created = str(el.get("created") or "")
    return _assemble(packages, edges, roots, unmapped, created, [], "SPDX-3.0")


def spdx_to_cyclonedx(doc: dict[str, Any]) -> dict[str, Any]:
    """A CycloneDX 1.6 source document for ``assemble_cyclonedx`` (raises ValueError for a non-SPDX document)."""
    if not is_spdx(doc):
        raise ValueError("not an SPDX document")
    if str(doc.get("spdxVersion") or "").startswith("SPDX-2"):
        return _from_spdx2(doc)
    return _from_spdx3(doc)


__all__ = ["is_spdx", "spdx_to_cyclonedx"]
