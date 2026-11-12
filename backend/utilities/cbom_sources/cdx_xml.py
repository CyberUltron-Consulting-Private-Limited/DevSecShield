"""CycloneDX 1.6 XML from the JSON model, and offline validation against the official XSD.

Both CBOM exports (a code scan's ``cbom_json`` and a scan-node run's ``inventory.cyclonedx``) are built as CycloneDX
JSON; this module writes the SAME document as XML, so the two formats never disagree. It is a mapping, not a second
renderer: every JSON key the exports emit has a place below, in the element order the XSD requires (XSD sequences
are ordered; JSON objects are not).

* Arrays become a wrapper with singular items (``components`` -> ``<components><component>``), except where the XSD
  repeats the element itself (``certificationLevel``, ``cryptoRefArray`` -> ``<cryptoRef>``, ``dependsOn`` ->
  ``<dependency ref=".."/>``).
* ``properties`` become ``<property name="..">value</property>``; ``hashes`` ``<hash alg="..">value</hash>``.
* Text that XML 1.0 cannot carry (control characters other than tab / newline / carriage return, lone surrogates,
  U+FFFE / U+FFFF) is removed; ``<`` / ``&`` / quotes are escaped by the XML library.
* A ``bom-ref`` that repeats (the XSD makes every bom-ref unique) is renamed ``<ref>#2``, ``#3`` ... in document
  order, skipping any name the document already holds, and logged; references keep pointing at the first holder.
  A ``bom-ref`` (or a dependency reference) that is empty once cleaned becomes ``zs-empty-ref`` (the XSD requires at
  least one character); an empty optional reference element (``algorithmRef`` ...) is left out.
* A key with no place in the mapping is left out and logged by its path (never its value); the tests assert that
  the product's own exports leave nothing out.

The schemas are vendored, unmodified, from the CycloneDX specification repository
(https://github.com/CycloneDX/specification, tag 1.6.2, commit e833d732337dd33aceb45ff1991f896796f1e5e7,
``schema/bom-1.6.xsd`` sha256 e2e09271aea918657f08b11c3d682413fddc8b1ee3944b9a902bf6d339a5b130 and ``schema/spdx.xsd``
sha256 cbc2211755af5ecf9b52dd514c14e4af6f74985b76cf75876ad2608741cb58dc). Validation never touches the network: the
XSD's ``http://cyclonedx.org/schema/spdx`` import is resolved to the vendored file.

Signature: for a code scan's BOM, ``bom_signature`` (HMAC over the canonical JSON) covers the JSON document only. The
XML is generated from that same JSON; to check integrity, verify the JSON download (the code-scan XML response says so
in ``X-ZS-Signature-Scope``). A collection run's CBOM is not signed, so its XML response carries no such header.
"""
from __future__ import annotations

import logging
import os
import re
from functools import lru_cache
from typing import Any

log = logging.getLogger(__name__)

NS = "http://cyclonedx.org/schema/bom/1.6"
SPDX_URL = "http://cyclonedx.org/schema/spdx"
_DATA = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "cyclonedx")
BOM_XSD = os.path.join(_DATA, "bom-1.6.xsd")
SPDX_XSD = os.path.join(_DATA, "spdx.xsd")
XML_MEDIA_TYPE = "application/vnd.cyclonedx+xml; version=1.6"
SIGNATURE_SCOPE = "json"  # the HMAC signature covers the JSON document; the XML is generated from it

# XML 1.0 Char production: everything else is removed
_INVALID_XML = re.compile("[^\u0009\u000A\u000D -퟿-�\U00010000-\U0010FFFF]")

# ---------------------------------------------------------------------------------------------------- mapping
# A spec is an ordered list of fields: (json key, xml name, kind, sub-spec or item name).
#   attr            attribute
#   text            element with text
#   obj             element built from a dict with the sub-spec
#   wrap:<item>     wrapper element; each array item is <item> (text when the sub-spec is None, else the sub-spec)
#   flat            the element itself repeats once per array item (text, or the sub-spec)
#   refs:<item>     wrapper-free repeated <item ref=".."/> from an array of strings (dependency lists)
#   props           <properties><property name="..">value</property></properties>
#   hashes          <hashes><hash alg="..">content</hash></hashes>
#   tools           legacy array of tools, or {components: [...], services: [...]}
#   skip            JSON-only key with no XML element (bomFormat / specVersion are the namespace)
Spec = list[tuple[str, str, str, Any]]

TOOL: Spec = [("vendor", "vendor", "text", None), ("name", "name", "text", None), ("version", "version", "text", None)]
OCCURRENCE: Spec = [("bom-ref", "bom-ref", "attr", None), ("location", "location", "text", None),
                    ("line", "line", "text", None), ("offset", "offset", "text", None),
                    ("symbol", "symbol", "text", None), ("additionalContext", "additionalContext", "text", None)]
EVIDENCE: Spec = [("occurrences", "occurrences", "wrap:occurrence", OCCURRENCE)]
ALGORITHM: Spec = [
    ("primitive", "primitive", "text", None), ("parameterSetIdentifier", "parameterSetIdentifier", "text", None),
    ("curve", "curve", "text", None), ("executionEnvironment", "executionEnvironment", "text", None),
    ("implementationPlatform", "implementationPlatform", "text", None),
    ("certificationLevel", "certificationLevel", "flat", None), ("mode", "mode", "text", None),
    ("padding", "padding", "text", None), ("cryptoFunctions", "cryptoFunctions", "wrap:cryptoFunction", None),
    ("classicalSecurityLevel", "classicalSecurityLevel", "text", None),
    ("nistQuantumSecurityLevel", "nistQuantumSecurityLevel", "text", None),
]
CERTIFICATE: Spec = [
    ("subjectName", "subjectName", "text", None), ("issuerName", "issuerName", "text", None),
    ("notValidBefore", "notValidBefore", "text", None), ("notValidAfter", "notValidAfter", "text", None),
    ("signatureAlgorithmRef", "signatureAlgorithmRef", "text", None),
    ("subjectPublicKeyRef", "subjectPublicKeyRef", "text", None),
    ("certificateFormat", "certificateFormat", "text", None),
    ("certificateExtension", "certificateExtension", "text", None),
]
SECURED_BY: Spec = [("mechanism", "mechanism", "text", None), ("algorithmRef", "algorithmRef", "text", None)]
MATERIAL: Spec = [
    ("type", "type", "text", None), ("id", "id", "text", None), ("state", "state", "text", None),
    ("algorithmRef", "algorithmRef", "text", None), ("creationDate", "creationDate", "text", None),
    ("activationDate", "activationDate", "text", None), ("updateDate", "updateDate", "text", None),
    ("expirationDate", "expirationDate", "text", None), ("value", "value", "text", None),
    ("size", "size", "text", None), ("format", "format", "text", None), ("securedBy", "securedBy", "obj", SECURED_BY),
]
SUITE: Spec = [("name", "name", "text", None), ("algorithms", "algorithms", "wrap:algorithm", None),
               ("identifiers", "identifiers", "wrap:identifier", None)]
PROTOCOL: Spec = [("type", "type", "text", None), ("version", "version", "text", None),
                  ("cipherSuites", "cipherSuites", "wrap:cipherSuite", SUITE),
                  ("cryptoRefArray", "cryptoRef", "flat", None)]
CRYPTO: Spec = [
    ("assetType", "assetType", "text", None), ("algorithmProperties", "algorithmProperties", "obj", ALGORITHM),
    ("certificateProperties", "certificateProperties", "obj", CERTIFICATE),
    ("relatedCryptoMaterialProperties", "relatedCryptoMaterialProperties", "obj", MATERIAL),
    ("protocolProperties", "protocolProperties", "obj", PROTOCOL), ("oid", "oid", "text", None),
]
EXTERNAL_REFERENCE: Spec = [("type", "type", "attr", None), ("url", "url", "text", None),
                            ("comment", "comment", "text", None)]
COMPONENT: Spec = [
    ("type", "type", "attr", None), ("mime-type", "mime-type", "attr", None), ("bom-ref", "bom-ref", "attr", None),
    ("author", "author", "text", None), ("publisher", "publisher", "text", None), ("group", "group", "text", None),
    ("name", "name", "text", None), ("version", "version", "text", None),
    ("description", "description", "text", None), ("scope", "scope", "text", None),
    ("hashes", "hashes", "hashes", None), ("copyright", "copyright", "text", None), ("cpe", "cpe", "text", None),
    ("purl", "purl", "text", None),
    ("externalReferences", "externalReferences", "wrap:reference", EXTERNAL_REFERENCE),
    ("properties", "properties", "props", None),
    ("components", "components", "wrap:component", "COMPONENT"),
    ("evidence", "evidence", "obj", EVIDENCE),
    ("cryptoProperties", "cryptoProperties", "obj", CRYPTO),
]
METADATA: Spec = [
    ("timestamp", "timestamp", "text", None), ("tools", "tools", "tools", None),
    ("component", "component", "obj", COMPONENT), ("properties", "properties", "props", None),
]
DEPENDENCY: Spec = [("ref", "ref", "attr", None), ("dependsOn", "dependency", "refs:dependency", None),
                    ("provides", "provides", "refs:provides", None)]
SOURCE: Spec = [("name", "name", "text", None), ("url", "url", "text", None)]
RATING: Spec = [("source", "source", "obj", SOURCE), ("score", "score", "text", None),
                ("severity", "severity", "text", None), ("method", "method", "text", None),
                ("vector", "vector", "text", None), ("justification", "justification", "text", None)]
ANALYSIS: Spec = [("state", "state", "text", None), ("justification", "justification", "text", None),
                  ("response", "responses", "wrap:response", None), ("detail", "detail", "text", None),
                  ("firstIssued", "firstIssued", "text", None), ("lastUpdated", "lastUpdated", "text", None)]
TARGET: Spec = [("ref", "ref", "text", None)]
VULNERABILITY: Spec = [
    ("bom-ref", "bom-ref", "attr", None), ("id", "id", "text", None), ("source", "source", "obj", SOURCE),
    ("ratings", "ratings", "wrap:rating", RATING), ("cwes", "cwes", "wrap:cwe", None),
    ("description", "description", "text", None), ("detail", "detail", "text", None),
    ("recommendation", "recommendation", "text", None), ("workaround", "workaround", "text", None),
    ("created", "created", "text", None), ("published", "published", "text", None),
    ("updated", "updated", "text", None), ("analysis", "analysis", "obj", ANALYSIS),
    ("affects", "affects", "wrap:target", TARGET), ("properties", "properties", "props", None),
]
BOM: Spec = [
    ("bomFormat", "", "skip", None), ("specVersion", "", "skip", None),
    ("serialNumber", "serialNumber", "attr", None), ("version", "version", "attr", None),
    ("metadata", "metadata", "obj", METADATA), ("components", "components", "wrap:component", COMPONENT),
    ("dependencies", "dependencies", "wrap:dependency", DEPENDENCY), ("properties", "properties", "props", None),
    ("vulnerabilities", "vulnerabilities", "wrap:vulnerability", VULNERABILITY),
]
_NAMED = {"COMPONENT": COMPONENT}  # a component nests components: the spec refers to itself by name


def _spec(sub: Any) -> Spec:
    return _NAMED[sub] if isinstance(sub, str) else sub


# ---------------------------------------------------------------------------------------------------- writing
def clean_text(value: Any) -> str:
    """The value as XML 1.0 text: booleans as true/false, characters XML cannot carry removed."""
    if isinstance(value, bool):
        return "true" if value else "false"
    return _INVALID_XML.sub("", str(value))


EMPTY_REF = "zs-empty-ref"  # stands in for a bom-ref that is empty once cleaned (the XSD refType has minLength 1)
# refType text elements: optional, so an empty one is left out (a reference to nothing)
_REF_TEXT = frozenset({"signatureAlgorithmRef", "subjectPublicKeyRef", "algorithmRef", "cryptoRef", "algorithm"})


def _all_refs(value: Any) -> set[str]:
    """Every cleaned ``bom-ref`` in the document (components, nested components, occurrences, vulnerabilities ...)."""
    found: set[str] = set()
    stack = [value]
    while stack:
        item = stack.pop()
        if isinstance(item, dict):
            ref = item.get("bom-ref")
            if ref is not None and not isinstance(ref, (dict, list)):
                found.add(clean_text(ref))
            stack.extend(item.values())
        elif isinstance(item, list):
            stack.extend(item)
    return found


class _Writer:
    def __init__(self, bom: dict[str, Any]) -> None:
        from lxml import etree

        self.etree = etree
        self.dropped: list[str] = []
        self.renamed: list[str] = []
        # a rename never takes a ref the document already holds (bom-refs a, a, a#2: the second a becomes a#3, not a
        # second a#2), nor one given out earlier
        self.taken: set[str] = _all_refs(bom)
        self.used: set[str] = set()
        self.empty_ref = self._free(EMPTY_REF)
        self.taken.add(self.empty_ref)

    def _free(self, base: str) -> str:
        if base not in self.taken:
            return base
        n = 2
        while f"{base}#{n}" in self.taken:
            n += 1
        return f"{base}#{n}"

    def link(self, value: Any) -> str:
        """A reference to a bom-ref (dependency ``ref`` / ``dependsOn`` / ``provides``): an empty one points at the
        placeholder an empty bom-ref was given."""
        text = clean_text(value)
        return text or self.empty_ref

    def el(self, parent: Any, name: str) -> Any:
        return self.etree.SubElement(parent, f"{{{NS}}}{name}")

    def text(self, parent: Any, name: str, value: Any) -> None:
        if value is None or isinstance(value, (dict, list)):
            return
        text = clean_text(value)
        if name in _REF_TEXT and not text:
            return
        if name == "ref":  # a vulnerability's affected target: required, so an empty one points at the placeholder
            text = self.link(text)
        self.el(parent, name).text = text

    def attr(self, node: Any, name: str, value: Any) -> None:
        if value is None or isinstance(value, (dict, list)):
            return
        text = clean_text(value)
        if name == "bom-ref":
            text = text or self.empty_ref
            if text in self.used:  # the XSD makes every bom-ref unique: keep the first, rename the repeats
                self.renamed.append(text)
                text = self._free(text)
                self.taken.add(text)
            self.used.add(text)
        elif name == "ref":
            text = self.link(text)
        node.set(name, text)

    def fill(self, node: Any, data: dict[str, Any], spec: Spec, path: str) -> None:
        known = {key for key, *_ in spec}
        for key in data:
            if key not in known:
                self.dropped.append(f"{path}.{key}")
        for key, name, kind, sub in spec:
            if key not in data or data[key] is None:
                continue
            value = data[key]
            here = f"{path}.{key}"
            if kind == "skip":
                continue
            if kind == "attr":
                self.attr(node, name, value)
            elif kind == "text":
                self.text(node, name, value)
            elif kind == "obj":
                if isinstance(value, dict):
                    self.fill(self.el(node, name), value, _spec(sub), here)
                else:
                    self.dropped.append(here)
            elif kind == "props":
                self.props(node, value, here)
            elif kind == "hashes":
                wrapper = self.el(node, "hashes")
                for item in value if isinstance(value, list) else []:
                    if isinstance(item, dict) and item.get("content") is not None:
                        h = self.el(wrapper, "hash")
                        h.set("alg", clean_text(item.get("alg") or ""))
                        h.text = clean_text(item["content"])
            elif kind == "tools":
                self.tools(node, value, here)
            elif kind == "flat":
                for item in value if isinstance(value, list) else [value]:
                    if isinstance(item, dict) and sub:
                        self.fill(self.el(node, name), item, _spec(sub), here)
                    else:
                        self.text(node, name, item)
            elif kind.startswith("refs:"):
                for item in value if isinstance(value, list) else []:
                    if item is not None and not isinstance(item, (dict, list)):
                        self.el(node, kind[5:]).set("ref", self.link(item))
            elif kind.startswith("wrap:"):
                if not isinstance(value, list):
                    self.dropped.append(here)
                    continue
                wrapper = self.el(node, name)
                item_name = kind[5:]
                for index, item in enumerate(value):
                    if sub is None:
                        self.text(wrapper, item_name, item)
                    elif isinstance(item, dict):
                        self.fill(self.el(wrapper, item_name), item, _spec(sub), f"{here}[{index}]")
                    else:
                        self.dropped.append(f"{here}[{index}]")

    def props(self, node: Any, value: Any, path: str) -> None:
        if not isinstance(value, list) or not value:
            return
        wrapper = self.el(node, "properties")
        for item in value:
            if not isinstance(item, dict) or item.get("name") is None:
                self.dropped.append(path + "[]")
                continue
            prop = self.el(wrapper, "property")
            prop.set("name", clean_text(item["name"]))
            if item.get("value") is not None:
                prop.text = clean_text(item["value"])

    def tools(self, node: Any, value: Any, path: str) -> None:
        wrapper = self.el(node, "tools")
        if isinstance(value, list):  # the legacy (1.4) form, still valid in 1.6
            for index, item in enumerate(value):
                if isinstance(item, dict):
                    self.fill(self.el(wrapper, "tool"), item, TOOL, f"{path}[{index}]")
            return
        if isinstance(value, dict):
            for key in value:
                if key != "components":
                    self.dropped.append(f"{path}.{key}")
            comps = value.get("components")
            if isinstance(comps, list) and comps:
                inner = self.el(wrapper, "components")
                for index, item in enumerate(comps):
                    if isinstance(item, dict):
                        self.fill(self.el(inner, "component"), item, COMPONENT, f"{path}.components[{index}]")


def to_xml(bom: dict[str, Any], *, strict: bool = False) -> bytes:
    """The CycloneDX JSON document ``bom`` as CycloneDX 1.6 XML (UTF-8 bytes with an XML declaration).

    ``strict``: raise ValueError when a key has no place in the mapping (tests use it to prove nothing is dropped);
    otherwise such keys are left out and their paths logged."""
    from lxml import etree

    if not isinstance(bom, dict):
        raise ValueError("not a CycloneDX JSON document")
    writer = _Writer(bom)
    root = etree.Element(f"{{{NS}}}bom", nsmap={None: NS})
    writer.fill(root, bom, BOM, "$")
    if writer.dropped:
        if strict:
            raise ValueError(f"no XML mapping for: {sorted(set(writer.dropped))[:20]}")
        log.warning("cyclonedx xml: left out %d key(s) with no XML mapping: %s", len(writer.dropped),
                    ", ".join(sorted(set(writer.dropped))[:20]))
    if writer.renamed:
        log.warning("cyclonedx xml: %d repeated bom-ref(s) renamed to stay unique", len(writer.renamed))
    return etree.tostring(root, xml_declaration=True, encoding="UTF-8", pretty_print=True)


# ---------------------------------------------------------------------------------------------------- validation
@lru_cache(maxsize=1)
def _schema() -> Any:
    from lxml import etree

    class _Local(etree.Resolver):
        """The XSD imports the SPDX licence list from cyclonedx.org: serve the vendored copy, never the network."""

        def resolve(self, url, _id, context):  # noqa: D401 - lxml API
            if url in (SPDX_URL, "spdx.xsd") or str(url).endswith("/spdx.xsd"):
                return self.resolve_filename(SPDX_XSD, context)
            return None

    parser = etree.XMLParser(no_network=True, resolve_entities=False)
    parser.resolvers.add(_Local())
    return etree.XMLSchema(etree.parse(BOM_XSD, parser))


def validate_xml(xml: bytes) -> list[str]:
    """Errors from validating ``xml`` against the vendored CycloneDX 1.6 XSD (empty when valid). Offline."""
    from lxml import etree

    parser = etree.XMLParser(no_network=True, resolve_entities=False, huge_tree=False)
    try:
        doc = etree.fromstring(xml, parser)
    except etree.XMLSyntaxError as exc:
        return [f"not well-formed: {exc}"]
    schema = _schema()
    if schema.validate(doc):
        return []
    return [f"line {e.line}: {e.message}" for e in list(schema.error_log)[:50]]


__all__ = ["NS", "SIGNATURE_SCOPE", "XML_MEDIA_TYPE", "clean_text", "to_xml", "validate_xml"]
