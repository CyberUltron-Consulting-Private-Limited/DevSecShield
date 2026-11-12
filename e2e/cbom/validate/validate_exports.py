"""G12 export validators (DEVILS-ADVOCATE.md §4.3 G12), independent of the product (oracle rule O-1).

    uv run --no-project --with-requirements e2e/cbom/validate/requirements.txt \
        python3 -I e2e/cbom/validate/validate_exports.py --run-dir RUN --run 1 [--build SHA]

Reads RUN/exports/run<k>.cdx.json, run<k>.cdx.xml, run<k>.oscal.json and prints one JSON document
{"results": [{name, check, file, ok, expected, observed, reason}]}. Schemas are never the product's copies:
  * CycloneDX 1.6 JSON: the schema bundled in cyclonedx-python-lib (pinned in requirements.txt), checked twice: with
    jsonschema Draft-07 + FormatChecker (every error listed), and with the library's JsonStrictValidator;
  * CycloneDX 1.6 XML: the library's bundled XSD, through xmlschema (and the library's XmlValidator);
  * OSCAL: NIST's oscal_assessment-results_schema.json v1.2.3 vendored next to this file (SOURCES.md: URL + sha256),
    with ECMA-style patterns (\\p{..}) through the `regex` module;
  * `zs:engine_version` (metadata property) == the build under test, when --build is given.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

import jsonschema
import regex
import xmlschema
from cyclonedx.schema import SchemaVersion
from cyclonedx.validation.json import JsonStrictValidator
from cyclonedx.validation.xml import XmlValidator
from jsonschema import validators
from referencing import Registry, Resource

HERE = Path(__file__).resolve().parent
OSCAL_SCHEMA = HERE / "oscal_assessment-results_schema-1.2.3.json"


def _pattern(validator, pattern, instance, schema):  # noqa: ARG001 (jsonschema keyword signature)
    if validator.is_type(instance, "string") and not regex.search(pattern, instance):
        yield jsonschema.ValidationError(f"{instance!r} does not match {pattern!r}")


def _pattern_properties(validator, pattern_properties, instance, schema):  # noqa: ARG001
    if not validator.is_type(instance, "object"):
        return
    for pattern, subschema in pattern_properties.items():
        for k, v in instance.items():
            if regex.search(pattern, k):
                yield from validator.descend(v, subschema, path=k, schema_path=pattern)


EcmaDraft7 = validators.extend(jsonschema.Draft7Validator, {"pattern": _pattern, "patternProperties": _pattern_properties})


def _res_dir() -> Path:
    import cyclonedx
    return Path(os.path.dirname(cyclonedx.__file__)) / "schema" / "_res"


def _errors(validator, doc, limit=20):
    errs = sorted(validator.iter_errors(doc), key=lambda e: [str(p) for p in e.absolute_path])
    return len(errs), [f"/{'/'.join(str(p) for p in e.absolute_path)}: {e.message[:200]}" for e in errs[:limit]]


def result(name, check, file, ok, expected, observed, reason=""):
    return {"name": name, "check": check, "file": file, "ok": bool(ok), "expected": expected, "observed": observed,
            "reason": "" if ok else (reason or "schema-invalid")}


def cdx_json(path: Path, build: str | None) -> list[dict]:
    out = []
    if not path.is_file():
        return [result("cdx_json_schema", "schema_validation", path.name, False, "the download", "absent", "missing")]
    doc = json.loads(path.read_text(encoding="utf-8"))
    res = _res_dir()
    schema = json.loads((res / "bom-1.6.SNAPSHOT.schema.json").read_text(encoding="utf-8"))
    registry = Registry().with_resources([
        ("spdx.schema.json", Resource.from_contents(json.loads((res / "spdx.SNAPSHOT.schema.json").read_text()))),
        ("jsf-0.82.schema.json", Resource.from_contents(json.loads((res / "jsf-0.82.SNAPSHOT.schema.json").read_text()))),
    ])
    v = EcmaDraft7(schema, registry=registry, format_checker=jsonschema.Draft7Validator.FORMAT_CHECKER)
    n, errs = _errors(v, doc)
    out.append(result("cdx_json_schema", "schema_validation", path.name, n == 0, "0 errors (CycloneDX 1.6 JSON, format checker)",
                      {"errors": n, "first": errs}))
    strict = JsonStrictValidator(SchemaVersion.V1_6).validate_str(path.read_text(encoding="utf-8"))
    out.append(result("cdx_json_strict", "schema_validation", path.name, strict is None,
                      "cyclonedx-python-lib JsonStrictValidator 1.6: no error", None if strict is None else str(strict)[:400]))
    if build:
        props = {p.get("name"): p.get("value") for p in (doc.get("metadata") or {}).get("properties") or []}
        tool = json.dumps((doc.get("metadata") or {}).get("tools") or {})
        got = props.get("zs:engine_version")
        out.append(result("cdx_engine_version_eq_build", "engine_version", path.name,
                          bool(got) and (build[:7] in str(got)), f"zs:engine_version names the build {build[:12]}",
                          {"zs:engine_version": got, "tools": tool[:200]}, "mismatch"))
    return out


def cdx_xml(path: Path) -> list[dict]:
    if not path.is_file():
        return [result("cdx_xml_schema", "schema_validation", path.name, False, "the download", "absent", "missing")]
    res = _res_dir()
    schema = xmlschema.XMLSchema(str(res / "bom-1.6.SNAPSHOT.xsd"))
    errs = list(schema.iter_errors(str(path)))
    out = [result("cdx_xml_schema", "schema_validation", path.name, not errs, "0 errors (CycloneDX 1.6 XSD, xmlschema)",
                  {"errors": len(errs), "first": [str(e.reason or e)[:200] for e in errs[:10]]})]
    lib = XmlValidator(SchemaVersion.V1_6).validate_str(path.read_text(encoding="utf-8"))
    out.append(result("cdx_xml_lib", "schema_validation", path.name, lib is None,
                      "cyclonedx-python-lib XmlValidator 1.6: no error", None if lib is None else str(lib)[:400]))
    return out


def oscal(path: Path) -> list[dict]:
    if not path.is_file():
        return [result("oscal_schema", "schema_validation", path.name, False, "the download", "absent", "missing")]
    doc = json.loads(path.read_text(encoding="utf-8"))
    schema = json.loads(OSCAL_SCHEMA.read_text(encoding="utf-8"))
    v = EcmaDraft7(schema, format_checker=jsonschema.Draft7Validator.FORMAT_CHECKER)
    n, errs = _errors(v, doc)
    version = ((doc.get("assessment-results") or {}).get("metadata") or {}).get("oscal-version")
    return [result("oscal_schema", "schema_validation", path.name, n == 0,
                   "0 errors (NIST OSCAL 1.2.3 assessment-results JSON schema)", {"errors": n, "oscal-version": version, "first": errs})]


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--run-dir", type=Path, required=True)
    ap.add_argument("--run", default="1")
    ap.add_argument("--build", default=None)
    a = ap.parse_args(argv)
    ex = a.run_dir / "exports"
    results = (cdx_json(ex / f"run{a.run}.cdx.json", a.build) + cdx_xml(ex / f"run{a.run}.cdx.xml")
               + oscal(ex / f"run{a.run}.oscal.json"))
    print(json.dumps({"schema": "zs-cbom-export-validation/1", "run": a.run, "results": results}, indent=1, default=str))
    return 0


if __name__ == "__main__":
    sys.exit(main())
