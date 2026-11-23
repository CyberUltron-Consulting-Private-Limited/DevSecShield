"""CycloneDX ``licenses`` entries that validate (review 6028132826 B1). Standard library only.

CycloneDX 1.6 allows ``license.id`` only for a member of the SPDX licence list (the JSON schema's ``spdx.schema.json``
enum, the XSD's ``spdx:licenseId``). A registry string such as ``LGPL`` or ``GPL`` is not one, so it goes in
``license.name``; a valid SPDX expression (``MIT OR Apache-2.0``) goes in ``expression``, which must then be the
list's only entry.

The id list is the one the aibom package vendors (``aibom/src/aibom/schemas/spdx.schema.json``, SPDX list 3.23): an
older list than any current validator's, so every id it accepts is accepted by them too. The worker loads this file
by path (RabbitMQ/worker/helpers/tools/sca_sbom_agent/registry_enrich.py), as it does ``address_rule.py``.
"""
from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Any

_SCHEMA_REL = Path("aibom") / "src" / "aibom" / "schemas" / "spdx.schema.json"
_UNKNOWN = frozenset({"", "noassertion", "none", "unknown", "not_declared", "n/a", "null"})
_REF = re.compile(r"^(?:DocumentRef-[A-Za-z0-9.-]+:)?LicenseRef-[A-Za-z0-9.-]+$")
_TOKENS = re.compile(r"\(|\)|\s+(?:AND|OR|WITH)\s+|\s+")


def _schema_candidates() -> list[Path]:
    here = Path(__file__).resolve()
    out = [parent / _SCHEMA_REL for parent in here.parents]  # a checkout, or /build in the scan-worker image
    out.append(Path("/opt/aibom/src/aibom/schemas/spdx.schema.json"))  # the backend image (backend/Dockerfile)
    return out


@lru_cache(maxsize=1)
def spdx_ids() -> dict[str, str]:
    """``lower-case id -> canonical id`` for every SPDX licence and exception id the schema lists ({} if absent)."""
    for path in _schema_candidates():
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        enum = data.get("enum") if isinstance(data, dict) else None
        if isinstance(enum, list) and enum:
            return {str(x).lower(): str(x) for x in enum}
    return {}


def canonical_id(raw: str | None) -> str | None:
    """The SPDX id ``raw`` names (any case), or None when it is not on the list."""
    return spdx_ids().get(str(raw or "").strip().lower())


def is_expression(raw: str | None) -> bool:
    """A compound SPDX expression whose every operand is a listed id (``+`` allowed) or a ``LicenseRef-``."""
    text = str(raw or "").strip()
    if not re.search(r"\s(?:AND|OR|WITH)\s", text):
        return False
    if text.count("(") != text.count(")"):
        return False
    operands = [t for t in _TOKENS.split(text) if t and t.strip()]
    if not operands:
        return False
    for op in operands:
        op = op.strip()
        if _REF.match(op):
            continue
        if canonical_id(op[:-1] if op.endswith("+") else op) is None:
            return False
    return True


def licence_choice(raw: str | None) -> list[dict[str, Any]] | None:
    """The ``licenses`` list for one licence string: ``id`` when listed, ``expression`` when a valid compound
    expression, else ``name`` (None for an empty or "unknown" value)."""
    text = str(raw or "").strip()
    if text.lower() in _UNKNOWN or text.lower().startswith("licenseref-not-declared"):
        return None
    cid = canonical_id(text)
    if cid:
        return [{"license": {"id": cid}}]
    if is_expression(text):
        return [{"expression": text}]
    return [{"license": {"name": text[:200]}}]


def sanitize_licenses(existing: Any) -> list[dict[str, Any]] | None:
    """A ``licenses`` list that validates: unlisted ids move to ``name``, an expression stands alone."""
    if not isinstance(existing, list):
        return None
    licences: list[dict[str, Any]] = []
    expression: str | None = None
    for item in existing:
        if not isinstance(item, dict):
            continue
        expr = str(item.get("expression") or "").strip()
        if expr:
            if expression is None and expr.lower() not in _UNKNOWN:
                expression = expr
            continue
        lic = item.get("license") if isinstance(item.get("license"), dict) else None
        if not lic:
            continue
        out = {k: v for k, v in lic.items() if k not in {"id", "name"}}
        lid = str(lic.get("id") or "").strip()
        name = str(lic.get("name") or "").strip()
        cid = canonical_id(lid) if lid else None
        if cid:
            out["id"] = cid
        elif lid or name:
            out["name"] = (name or lid)[:200]
        else:
            continue
        licences.append({"license": out})
    if expression is not None:
        if is_expression(expression) or canonical_id(expression):
            return [{"expression": expression}]
        if not licences:  # not SPDX: keep the text as a name
            return [{"license": {"name": expression[:200]}}]
    return licences or None


def licence_text(licenses: Any) -> str:
    """The first licence's text (id, name or expression), "" when none is declared."""
    for item in licenses or []:
        if not isinstance(item, dict):
            continue
        lic = item.get("license") if isinstance(item.get("license"), dict) else {}
        token = str(lic.get("id") or lic.get("name") or item.get("expression") or "").strip()
        if token and token.lower() not in _UNKNOWN and not token.lower().startswith("licenseref-not-declared"):
            return token
    return ""


__all__ = ["canonical_id", "is_expression", "licence_choice", "licence_text", "sanitize_licenses", "spdx_ids"]
