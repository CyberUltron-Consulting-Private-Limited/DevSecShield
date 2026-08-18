"""CERT-In SBOM lane checks — Table 5 auto + §7.1 manuals (Phase 3).

Registered under framework key ``cert_in_sbom``. Imported by the SBOM runner
(:mod:`aibom.sbom.compliance`) for side-effect registration only —
:mod:`aibom.compliance.__init__` must NEVER import this module.

Checks read the projected finding graph (FrameworkComponent props +
ScanResult.properties) only — never ``result.flags``. Missing inventable
facts → NBE (never invent). Automation SPDX/CDX FAIL unless BOM props prove emit.
"""

from __future__ import annotations

from collections.abc import Callable

from aibom.compliance.base import (
    FAIL,
    NOT_EVIDENCEABLE,
    PASS,
    CheckResult,
    Requirement,
    register_applicability,
    register_check,
    register_manual,
)
from aibom.compliance.cert_in.common import CERTIN_DISCLAIMER, load_ledger
from aibom.compliance.cert_in.predicates import has_nonempty, prop
from aibom.model.component import FrameworkComponent
from aibom.model.result import ScanResult

_FW = "cert_in_sbom"


def _sbom_components(r: ScanResult) -> list[FrameworkComponent]:
    return [c for c in r.components if c.kind == "framework"]


register_applicability(
    _FW,
    lambda r: bool(_sbom_components(r)),
    "no dependency components inventoried; CERT-In SBOM guidelines do not apply",
)


def _refs(comps: list[FrameworkComponent]) -> list[str]:
    return [c.bom_ref for c in comps if c.bom_ref]


def _bom_prop(r: ScanResult, key: str) -> str | None:
    val = (r.properties or {}).get(key)
    return val if has_nonempty(val) else None


def _field_value(r: ScanResult, c: FrameworkComponent, rid: str) -> str | None:
    """Resolve a Table-5 field off a component or BOM-level properties."""
    props = c.properties or {}

    if rid == "T5-Component-Name":
        return str(c.name).strip() if has_nonempty(c.name) else None
    if rid == "T5-Component-Version":
        return str(c.version).strip() if has_nonempty(c.version) else None
    if rid == "T5-Component-Description":
        return prop(c, "sbom:description")
    if rid == "T5-Component-Supplier":
        return (
            prop(c, "sbom:purl")
            or prop(c, "sbom:supplier")
            or (str(c.purl).strip() if has_nonempty(c.purl) else None)
            or (str(c.publisher).strip() if has_nonempty(c.publisher) else None)
        )
    if rid == "T5-Component-License":
        return prop(c, "sbom:license") or prop(c, "sbom:license_type")
    if rid == "T5-Component-Origin":
        return prop(c, "sbom:origin")
    if rid == "T5-Component-Dependencies":
        # Inventory of projected deps IS the dependency set of the scanned artifact.
        return "yes" if _sbom_components(r) else None
    if rid == "T5-Vulnerabilities":
        return "yes" if props.get("sbom:vuln_assessed") == "true" else None
    if rid == "T5-Patch-Status":
        return prop(c, "sbom:patch_status") or prop(c, "sbom:fix_state")
    if rid == "T5-Release-Date":
        return prop(c, "sbom:release_date")
    if rid == "T5-EOL-Date":
        return prop(c, "sbom:eol_date")
    if rid == "T5-Criticality":
        return prop(c, "sbom:criticality")
    if rid == "T5-Usage-Restrictions":
        return prop(c, "sbom:usage_restrictions")
    if rid == "T5-Checksums-or-Hashes":
        return prop(c, "sbom:hash")
    if rid == "T5-Comments-or-Notes":
        return prop(c, "sbom:comments")
    if rid == "T5-Author-of-SBOM-Data":
        return _bom_prop(r, "sbom:author")
    if rid == "T5-Timestamp":
        return _bom_prop(r, "sbom:timestamp")
    if rid == "T5-Executable-Property":
        return prop(c, "sbom:executable")
    if rid == "T5-Archive-Property":
        return prop(c, "sbom:archive")
    if rid == "T5-Structured-Property":
        return prop(c, "sbom:structured")
    if rid == "T5-Unique-Identifier":
        return (
            prop(c, "sbom:purl")
            or (str(c.purl).strip() if has_nonempty(c.purl) else None)
            or (str(c.bom_ref).strip() if has_nonempty(c.bom_ref) else None)
        )
    if rid == "T5-Automation-SPDX":
        return "yes" if _bom_prop(r, "sbom:automation_spdx") == "true" else None
    if rid == "T5-Automation-CycloneDX":
        return "yes" if _bom_prop(r, "sbom:automation_cyclonedx") == "true" else None
    if rid == "T5-Inventory-Tools":
        return _bom_prop(r, "sbom:inventory_tools")
    if rid == "T5-Vuln-Scanner":
        return _bom_prop(r, "sbom:vuln_scanner")
    if rid == "T5-Multi-Format-Emit":
        if _bom_prop(r, "sbom:multi_format_emit") == "true":
            return "yes"
        if _bom_prop(r, "sbom:automation_cyclonedx") == "true":
            return "yes"
        if _bom_prop(r, "sbom:automation_spdx") == "true":
            return "yes"
        return None
    return None


# BOM-level requirements: evaluate once against the scan, not per-component.
_BOM_LEVEL = frozenset(
    {
        "T5-Author-of-SBOM-Data",
        "T5-Timestamp",
        "T5-Automation-SPDX",
        "T5-Automation-CycloneDX",
        "T5-Component-Dependencies",
        "T5-Inventory-Tools",
        "T5-Vuln-Scanner",
        "T5-Multi-Format-Emit",
    }
)


def _make_auto_check(
    *,
    missing: str,
    rid: str,
) -> Callable[[ScanResult, Requirement], CheckResult]:
    def _check(r: ScanResult, req: Requirement) -> CheckResult:
        comps = _sbom_components(r)
        if not comps:
            return PASS(f"no dependencies; {rid} vacuously satisfied")

        # BOM-level checks: single fact on the scan.
        if rid in _BOM_LEVEL:
            val = _field_value(r, comps[0], rid)
            if has_nonempty(val):
                return PASS(f"{rid} present on SBOM scan metadata", _refs(comps))
            if missing == "nbe":
                return NOT_EVIDENCEABLE(
                    f"{rid}: not BOM-evidenceable from SBOM findings "
                    f"({CERTIN_DISCLAIMER})",
                    _refs(comps),
                )
            return FAIL(f"{rid}: required SBOM metadata missing", _refs(comps))

        present: list[FrameworkComponent] = []
        absent: list[FrameworkComponent] = []
        for c in comps:
            if has_nonempty(_field_value(r, c, rid)):
                present.append(c)
            else:
                absent.append(c)

        if missing == "nbe":
            if not absent:
                return PASS(
                    f"all {len(comps)} dependenc(ies) carry {rid}",
                    _refs(comps),
                )
            if present and absent:
                return NOT_EVIDENCEABLE(
                    f"{rid}: {len(absent)}/{len(comps)} dependenc(ies) lack "
                    f"inventable evidence; unknown → not BOM-evidenceable "
                    f"({CERTIN_DISCLAIMER})",
                    _refs(absent),
                )
            return NOT_EVIDENCEABLE(
                f"{rid}: not BOM-evidenceable from SBOM findings "
                f"({CERTIN_DISCLAIMER})",
                _refs(comps),
            )

        if absent:
            return FAIL(
                f"{rid}: {len(absent)}/{len(comps)} dependenc(ies) lack required field",
                _refs(absent),
            )
        return PASS(f"all {len(comps)} dependenc(ies) satisfy {rid}", _refs(comps))

    _check.__name__ = f"_certin_{rid.replace('.', '_').replace('-', '_')}"
    _check.__qualname__ = _check.__name__
    return _check


def _register_from_ledger() -> None:
    doc = load_ledger()
    for raw in doc.get("requirements") or []:
        rid = str(raw.get("id") or "")
        mode = str(raw.get("mode") or "")
        missing = str(raw.get("missing") or "fail")
        title = str(raw.get("title") or rid)
        source = str(raw.get("pdf") or "CERT-In TG v2.0")

        if mode == "manual" and rid.startswith("7.1."):
            req = Requirement(
                id=rid,
                framework=_FW,
                title=title,
                source=source,
            )
            register_manual(
                req,
                f"{CERTIN_DISCLAIMER} Process attestation for {rid}: "
                f"{raw.get('description') or raw.get('evidence_hint') or 'organizational evidence'}.",
            )
            continue

        if mode != "auto" or not rid.startswith("T5-"):
            continue

        req = Requirement(
            id=rid,
            framework=_FW,
            title=title,
            source=source,
        )
        register_check(req)(_make_auto_check(missing=missing, rid=rid))


_register_from_ledger()
