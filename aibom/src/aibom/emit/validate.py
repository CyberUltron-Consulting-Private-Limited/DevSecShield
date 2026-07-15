"""Offline schema validation for every emitted format. No network (hard rule).

CycloneDX 1.6, SPDX 3.0.1 and SARIF 2.1.0 are all validated against schemas
bundled under ``aibom/schemas/``. A document that fails its schema is a build
failure, never a warning.
"""

import json
import pathlib
from functools import cache
from typing import Any

import jsonschema
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT7

_SCHEMA_DIR = pathlib.Path(__file__).resolve().parent.parent / "schemas"


@cache
def _load(name: str) -> dict:
    return json.loads((_SCHEMA_DIR / name).read_text())


def _errors(validator: Any, doc: dict) -> list[str]:
    errs = []
    for e in sorted(validator.iter_errors(doc), key=lambda x: list(x.path)):
        loc = "/".join(str(p) for p in e.path) or "(root)"
        errs.append(f"{loc}: {e.message}")
    return errs


# --------------------------------------------------------------------------- #
# CycloneDX 1.6 (Draft 7, with the SPDX-license + JSF sub-schemas $ref'd in)
# --------------------------------------------------------------------------- #


@cache
def _cdx_validator() -> jsonschema.Draft7Validator:
    # CycloneDX 1.6 is Draft-7 and $refs the SPDX-license + JSF sub-schemas by
    # bare filename (e.g. "spdx.schema.json"); those resolve against the bom
    # $id base to each sub-schema's own $id. Register all three in a
    # `referencing` Registry (replaces the deprecated jsonschema.RefResolver).
    bom = _load("bom-1.6.schema.json")
    registry: Registry = Registry().with_resources(
        (schema["$id"], Resource.from_contents(schema, default_specification=DRAFT7))
        for schema in (
            bom,
            _load("spdx.schema.json"),
            _load("jsf-0.82.schema.json"),
        )
    )
    return jsonschema.Draft7Validator(bom, registry=registry)


def validate_cyclonedx(bom: dict) -> list[str]:
    """Return human-readable CycloneDX 1.6 schema errors ([] == valid)."""
    return _errors(_cdx_validator(), bom)


# --------------------------------------------------------------------------- #
# SPDX 3.0.1 (Draft 2020-12, self-contained $defs, no external refs)
# --------------------------------------------------------------------------- #


@cache
def _spdx_validator() -> jsonschema.Draft202012Validator:
    schema = _load("spdx-3.0.1.schema.json")
    return jsonschema.Draft202012Validator(schema)


def validate_spdx(doc: dict) -> list[str]:
    """Return human-readable SPDX 3.0.1 schema errors ([] == valid)."""
    return _errors(_spdx_validator(), doc)


# --------------------------------------------------------------------------- #
# SARIF 2.1.0 (Draft 4)
# --------------------------------------------------------------------------- #


@cache
def _sarif_validator() -> jsonschema.Draft4Validator:
    schema = _load("sarif-2.1.0.schema.json")
    return jsonschema.Draft4Validator(schema)


def validate_sarif(doc: dict) -> list[str]:
    """Return human-readable SARIF 2.1.0 schema errors ([] == valid)."""
    return _errors(_sarif_validator(), doc)


# --------------------------------------------------------------------------- #
# Format auto-detection (for `aibom validate <file>`)
# --------------------------------------------------------------------------- #


def detect_format(doc: dict) -> str | None:
    """Best-effort format sniff: 'cyclonedx' | 'spdx' | 'sarif' | None."""
    if doc.get("bomFormat") == "CycloneDX":
        return "cyclonedx"
    ctx = doc.get("@context")
    if isinstance(ctx, str) and "spdx" in ctx:
        return "spdx"
    if isinstance(ctx, list) and any("spdx" in str(c) for c in ctx):
        return "spdx"
    if doc.get("version") == "2.1.0" and "runs" in doc:
        return "sarif"
    schema = doc.get("$schema", "")
    if isinstance(schema, str) and "sarif" in schema.lower():
        return "sarif"
    return None


def validate_auto(doc: dict) -> tuple[str | None, list[str]]:
    """Detect the format and validate. Returns ``(format, errors)``.

    If the format cannot be detected, returns ``(None, [message])``.
    """
    fmt = detect_format(doc)
    if fmt == "cyclonedx":
        return fmt, validate_cyclonedx(doc)
    if fmt == "spdx":
        return fmt, validate_spdx(doc)
    if fmt == "sarif":
        return fmt, validate_sarif(doc)
    return None, ["could not detect BOM format (not CycloneDX, SPDX 3.0, or SARIF)"]


if __name__ == "__main__":
    import sys

    with open(sys.argv[1]) as _fh:
        _doc = json.load(_fh)
    _fmt, _errs = validate_auto(_doc)
    if _errs:
        print(f"INVALID ({_fmt or 'unknown'}, {len(_errs)} errors):")
        for _e in _errs[:25]:
            print("  -", _e)
        sys.exit(1)
    print(f"VALID against {_fmt} schema")
