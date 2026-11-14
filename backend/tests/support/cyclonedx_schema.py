"""Independent CycloneDX 1.6 validation for tests (CB-06, oracle rule O-1: imports nothing from the product).

* JSON: the PUBLISHED schemas (``tests/fixtures/cyclonedx-1.6.2``: bom-1.6, spdx, jsf-0.82 at the CycloneDX/specification
  tag 1.6.2), JSON Schema Draft-07, with a format checker that really checks ``date-time`` (RFC 3339 section 5.6;
  jsonschema skips that format unless an optional package is installed, so it is checked here).
* XML: lxml against the published ``bom-1.6.xsd`` (+ ``spdx.xsd``), resolved offline. The product vendors those two files
  byte-identically; ``published_files()`` checks every file's sha256 against ``SOURCES.json`` before it is used, so a
  changed product copy fails the tests instead of silently validating against something else.
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Any

_TESTS = Path(__file__).resolve().parents[1]
_REPO = _TESTS.parents[1]
SCHEMA_DIR = _TESTS / "fixtures" / "cyclonedx-1.6.2"
SOURCES = json.loads((SCHEMA_DIR / "SOURCES.json").read_text())

# RFC 3339 section 5.6 date-time: full-date "T" full-time, with a mandatory offset
_DATE_TIME = re.compile(r"^(\d{4})-(\d{2})-(\d{2})[Tt](\d{2}):(\d{2}):(\d{2})(\.\d+)?([Zz]|[+-](\d{2}):(\d{2}))$")


def is_rfc3339_date_time(value: Any) -> bool:
    if not isinstance(value, str):
        return True  # formats apply to strings only (JSON Schema)
    m = _DATE_TIME.match(value)
    if not m:
        return False
    year, month, day, hour, minute, second = (int(m.group(i)) for i in range(1, 7))
    try:
        _dt.datetime(year, month, day, hour, minute, min(second, 59))  # a leap second (60) is allowed by RFC 3339
    except ValueError:
        return False
    if second > 60:
        return False
    if m.group(9) is not None and (int(m.group(9)) > 23 or int(m.group(10)) > 59):
        return False
    return True


def published_files() -> dict[str, Path]:
    """Path of every published schema file, after checking its sha256 against SOURCES.json."""
    out: dict[str, Path] = {}
    for name, meta in SOURCES["files"].items():
        path = _REPO / meta["path"] if "path" in meta else SCHEMA_DIR / name
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if digest != meta["sha256"]:
            raise AssertionError(f"{path} is not the published {name} (sha256 {digest} != {meta['sha256']})")
        out[name] = path
    return out


@lru_cache(maxsize=1)
def _json_validator():
    from jsonschema import Draft7Validator, FormatChecker
    from referencing import Registry, Resource

    files = published_files()
    docs = {name: json.loads(files[name].read_text()) for name in
            ("bom-1.6.schema.json", "spdx.schema.json", "jsf-0.82.schema.json")}
    registry = Registry().with_resources(
        (doc["$id"], Resource.from_contents(doc)) for doc in docs.values())
    checker = FormatChecker()
    checker.checks("date-time")(is_rfc3339_date_time)
    return Draft7Validator(docs["bom-1.6.schema.json"], registry=registry, format_checker=checker)


def json_errors(doc: dict[str, Any], limit: int = 50) -> list[str]:
    """Schema errors of a CycloneDX JSON document (empty when valid)."""
    errors = sorted(_json_validator().iter_errors(doc), key=lambda e: list(e.absolute_path))
    return [f"{'/'.join(str(p) for p in e.absolute_path) or '$'}: {e.message[:300]}" for e in errors[:limit]]


@lru_cache(maxsize=1)
def _xml_schema():
    from lxml import etree

    files = published_files()
    spdx = files["spdx.xsd"]

    class _Offline(etree.Resolver):
        def resolve(self, url, _id, context):  # noqa: D401 - lxml API
            if str(url).rstrip("/").endswith(("schema/spdx", "spdx.xsd")):
                return self.resolve_filename(str(spdx), context)
            return None

    parser = etree.XMLParser(no_network=True, resolve_entities=False)
    parser.resolvers.add(_Offline())
    return etree.XMLSchema(etree.parse(str(files["bom-1.6.xsd"]), parser))


def xml_errors(xml: bytes, limit: int = 50) -> list[str]:
    """XSD errors of a CycloneDX 1.6 XML document (empty when valid)."""
    from lxml import etree

    try:
        doc = etree.fromstring(xml, etree.XMLParser(no_network=True, resolve_entities=False))
    except etree.XMLSyntaxError as exc:
        return [f"not well-formed: {exc}"]
    schema = _xml_schema()
    if schema.validate(doc):
        return []
    return [f"line {e.line}: {e.message[:300]}" for e in list(schema.error_log)[:limit]]


def all_bom_refs(doc: Any) -> list[str]:
    """Every ``bom-ref`` in a JSON document, in document order (components, nested components, vulnerabilities ...)."""
    found: list[str] = []

    def walk(item: Any) -> None:
        if isinstance(item, dict):
            if isinstance(item.get("bom-ref"), str):
                found.append(item["bom-ref"])
            for value in item.values():
                walk(value)
        elif isinstance(item, list):
            for value in item:
                walk(value)

    walk(doc)
    return found


def all_references(doc: dict[str, Any]) -> list[tuple[str, str]]:
    """(where, ref) for every reference the CBOM parts of CycloneDX 1.6 define: certificate signatureAlgorithmRef /
    subjectPublicKeyRef, related-material algorithmRef, protocol cryptoRefArray, vulnerability affects[].ref."""
    out: list[tuple[str, str]] = []

    def walk(item: Any, where: str) -> None:
        if isinstance(item, dict):
            for key, value in item.items():
                here = f"{where}.{key}"
                if key in ("signatureAlgorithmRef", "subjectPublicKeyRef", "algorithmRef") and isinstance(value, str):
                    out.append((here, value))
                elif key == "cryptoRefArray" and isinstance(value, list):
                    out.extend((here, v) for v in value if isinstance(v, str))
                else:
                    walk(value, here)
        elif isinstance(item, list):
            for i, value in enumerate(item):
                walk(value, f"{where}[{i}]")

    walk(doc.get("components") or [], "$.components")
    for i, vuln in enumerate(doc.get("vulnerabilities") or []):
        for target in vuln.get("affects") or []:
            out.append((f"$.vulnerabilities[{i}].affects", target.get("ref")))
    return out
