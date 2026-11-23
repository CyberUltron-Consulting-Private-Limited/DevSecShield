"""The one writer of the streamed CycloneDX CBOMs (a run's export, a run deliverable, the estate export): JSON with an
embedded JSF signature (``bom_signing.write_json``) or XML (``cdx_xml.write_xml``), both with the ``dependencies`` the
platform knows (``Links``). D11 / audit A-14: "linked to applications and owners", CycloneDX 1.6 dependency graph.

``Links`` (built while the components stream past, so the document is still never held):
* a certificate ``dependsOn`` its signature algorithm and subject public key (``signatureAlgorithmRef`` /
  ``subjectPublicKeyRef``), a key or other related material ``dependsOn`` its algorithm (``algorithmRef``), a protocol
  ``dependsOn`` the algorithms its cipher suites reference and its ``cryptoRefArray``: the uses relation of
  CycloneDX 1.6;
* every application a component names (``zs:application``, the C5 metadata of the source that collected it, or of
  every source that observes an estate asset) becomes one ``application`` component (``zs-application-<hash>``,
  ``zs:component_role`` = ``application``, one ``zs:owner`` per owner its assets' sources name) that ``dependsOn`` those
  assets. An application component is not an asset: it carries no ``zs-asset-`` ref and is not counted in
  ``zs:asset_count``.
Only references to components of the same document are written.
"""
from __future__ import annotations

import hashlib
from typing import Any, BinaryIO, Callable, Iterable, Iterator

from backend.utilities.cbom_sources import bom_signing as SIGN

APPLICATION_ROLE = {"name": "zs:component_role", "value": "application"}


def _uses(crypto: Any) -> list[str]:
    if not isinstance(crypto, dict):
        return []
    out: list[str] = []
    cert = crypto.get("certificateProperties") or {}
    out += [cert[k] for k in ("signatureAlgorithmRef", "subjectPublicKeyRef") if isinstance(cert.get(k), str)]
    material = crypto.get("relatedCryptoMaterialProperties") or {}
    if isinstance(material.get("algorithmRef"), str):
        out.append(material["algorithmRef"])
    proto = crypto.get("protocolProperties") or {}
    for suite in proto.get("cipherSuites") or []:
        out += [a for a in (suite.get("algorithms") or []) if isinstance(a, str)] if isinstance(suite, dict) else []
    out += [r for r in proto.get("cryptoRefArray") or [] if isinstance(r, str)]
    return out


def application_ref(name: str) -> str:
    return "zs-application-" + hashlib.sha256(name.encode("utf-8")).hexdigest()[:16]


class Links:
    """The document's dependency graph, collected from the components as they are written (module docstring)."""

    def __init__(self) -> None:
        self.refs: set[str] = set()
        self.uses: dict[str, list[str]] = {}
        self.apps: dict[str, dict[str, Any]] = {}

    def observe(self, components: Iterable[dict[str, Any]]) -> Iterator[dict[str, Any]]:
        for comp in components:
            ref = comp.get("bom-ref")
            if isinstance(ref, str):
                self.refs.add(ref)
                uses = _uses(comp.get("cryptoProperties"))
                if uses:
                    self.uses[ref] = uses
                props = [p for p in comp.get("properties") or [] if isinstance(p, dict)]
                owners = [str(p.get("value")) for p in props if p.get("name") == "zs:owner" and p.get("value")]
                for p in props:
                    if p.get("name") == "zs:application" and p.get("value"):
                        app = self.apps.setdefault(str(p["value"]), {"refs": [], "owners": set()})
                        app["refs"].append(ref)
                        app["owners"].update(owners)
            yield comp
        for name in sorted(self.apps):
            ref = application_ref(name)
            while ref in self.refs:  # never shares a ref with an asset
                ref += "x"
            self.apps[name]["ref"] = ref
            self.refs.add(ref)
            yield {"type": "application", "bom-ref": ref, "name": name[:255],
                   "properties": [APPLICATION_ROLE, *[{"name": "zs:owner", "value": o[:255]}
                                                      for o in sorted(self.apps[name]["owners"])]]}

    def dependencies(self) -> list[dict[str, Any]]:
        out = []
        for ref, uses in self.uses.items():
            targets = sorted({t for t in uses if t in self.refs and t != ref})
            if targets:
                out.append({"ref": ref, "dependsOn": targets})
        for app in self.apps.values():
            out.append({"ref": app["ref"], "dependsOn": sorted(set(app["refs"]))})
        return sorted(out, key=lambda d: d["ref"])


def write(out: BinaryIO | Any, head: dict[str, Any], components: Iterable[dict[str, Any]],
          vulnerabilities: Callable[[], list[dict[str, Any]]], fmt: str, *, sign: bool = True
          ) -> dict[str, Any] | None:
    """Write the document as ``fmt`` (json | xml) with its ``dependencies``; JSON is signed (JSF) when ``sign`` and a
    key is configured. Returns the JSF signature written (None for XML or unsigned JSON)."""
    links = Links()
    comps = links.observe(components)
    if fmt == "xml":
        from backend.utilities.cbom_sources import cdx_xml

        cdx_xml.write_xml(out, head, comps, vulnerabilities, dependencies=links.dependencies)
        return None
    return SIGN.write_json(out, head, comps, [("dependencies", links.dependencies),
                                              ("vulnerabilities", vulnerabilities)], sign=sign)


def document(head: dict[str, Any], components: Iterable[dict[str, Any]],
             vulnerabilities: Callable[[], list[dict[str, Any]]]) -> dict[str, Any]:
    """The same document as one (unsigned) dict."""
    links = Links()
    comps = list(links.observe(components))
    deps = links.dependencies()
    return {**head, "components": comps, **({"dependencies": deps} if deps else {}),
            "vulnerabilities": vulnerabilities()}


__all__ = ["APPLICATION_ROLE", "Links", "application_ref", "document", "write"]
