"""SEBI CSCRF SBOM lane — GV.SC.S5 + ID.AM / ID.RA BOM-evidenceable subset.

Registered under ``sebi_cscrf_sbom``. Imported only from
:mod:`aibom.sbom.compliance` — never from :mod:`aibom.compliance.__init__`.

Checks read projected ``sbom:*`` / component fields only (never ``result.flags``).
Does not claim full transitive DAG completeness or invent encryption-from-name.
"""

from __future__ import annotations

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
from aibom.compliance.sebi_cscrf.common import SEBI_DISCLAIMER, load_ledger
from aibom.model.component import FrameworkComponent
from aibom.model.result import ScanResult
from aibom.sbom.frameworks_supply import (
    _has_license,
    _has_supplier,
    _has_unique_id,
    _prop,
    _sbom_components,
)

_FW = "sebi_cscrf_sbom"
_SRC = "SEBI CSCRF CIR/2024/113"

_HIGH_IMPACT = frozenset({"Critical", "critical", "High", "high"})
_HIGH_LICENSE = frozenset(
    {
        "strong_copyleft",
        "network_copyleft",
        "source_available",
        "Strong Copyleft",
        "Network Copyleft",
        "Source Available",
    }
)


def _refs(comps: list[FrameworkComponent]) -> list[str]:
    return [c.bom_ref for c in comps if c.bom_ref]


def _bom_prop(r: ScanResult, key: str) -> str | None:
    val = (r.properties or {}).get(key)
    if isinstance(val, str) and val.strip():
        return val.strip()
    return None


register_applicability(
    _FW,
    lambda r: bool(_sbom_components(r)),
    "no dependency components inventoried; SEBI CSCRF SBOM controls do not apply",
)


def _req(rid: str, title: str, source: str) -> Requirement:
    return Requirement(rid, _FW, title, source)


R_NAME = _req("CSCRF-GV.SC.S5-name", "Component names present", f"{_SRC} GV.SC.S5.2")
R_VER = _req("CSCRF-GV.SC.S5-ver", "Component versions present", f"{_SRC} GV.SC.S5.2")
R_SUP = _req(
    "CSCRF-GV.SC.S5-sup", "Supplier name or purl present", f"{_SRC} GV.SC.S5.4.b"
)
R_UID = _req("CSCRF-GV.SC.S5-uid", "Unique component identifiers", f"{_SRC} Box Item 6")
R_LIC = _req(
    "CSCRF-GV.SC.S5-lic", "License information inventoriable", f"{_SRC} GV.SC.S5.4.a"
)
R_LIC_RISK = _req(
    "CSCRF-GV.SC.S5-lic-risk",
    "No untriaged high-risk licenses",
    f"{_SRC} GV.SC.S5.2 license risk",
)
R_DEPS = _req(
    "CSCRF-GV.SC.S5-deps",
    "Dependency relationship set present",
    f"{_SRC} GV.SC.S5.4.c",
)
R_HASH = _req(
    "CSCRF-GV.SC.S5-hash",
    "Cryptographic hashes of components",
    f"{_SRC} GV.SC.S5.4.e",
)
R_PATCH = _req(
    "CSCRF-GV.SC.S5-patch",
    "Patch or fix status recorded",
    f"{_SRC} GV.SC.S5.2 patch status",
)
R_ENC = _req(
    "CSCRF-GV.SC.S5-enc",
    "Encryption used recorded on SBOM",
    f"{_SRC} GV.SC.S5.4.d",
)
R_KU = _req(
    "CSCRF-GV.SC.S5-known-unknown",
    "Known-unknown / incomplete graph disclosed",
    f"{_SRC} GV.SC.S5.4.g",
)
R_INV = _req(
    "CSCRF-ID.AM-inv",
    "Software dependency inventory maintained",
    f"{_SRC} ID.AM.S1 / S4",
)
R_VULN = _req(
    "CSCRF-ID.RA-vuln-track",
    "Vulnerability tracking linkage",
    f"{_SRC} ID.RA / Box Item 6",
)
R_HIGH = _req(
    "CSCRF-ID.RA-high",
    "No critical or high severity vulnerabilities",
    f"{_SRC} ID.RA posture",
)
R_AUTHOR = _req(
    "CSCRF-GV.SC.S5-author", "Author of SBOM data", f"{_SRC} SBOM provenance"
)
R_TS = _req("CSCRF-GV.SC.S5-ts", "SBOM timestamp", f"{_SRC} SBOM provenance")


@register_check(R_NAME)
def _name(r: ScanResult, req: Requirement) -> CheckResult:
    comps = _sbom_components(r)
    bad = [c for c in comps if not (c.name and str(c.name).strip())]
    if bad:
        return FAIL(f"{len(bad)}/{len(comps)} lack component name", _refs(bad))
    return PASS("all components named", _refs(comps))


@register_check(R_VER)
def _ver(r: ScanResult, req: Requirement) -> CheckResult:
    comps = _sbom_components(r)
    bad = [c for c in comps if not (c.version and str(c.version).strip())]
    if bad:
        return FAIL(f"{len(bad)}/{len(comps)} lack version", _refs(bad))
    return PASS("all components versioned", _refs(comps))


@register_check(R_SUP)
def _sup(r: ScanResult, req: Requirement) -> CheckResult:
    comps = _sbom_components(r)
    bad = [c for c in comps if not _has_supplier(c)]
    if bad:
        return FAIL(f"{len(bad)}/{len(comps)} lack supplier/purl", _refs(bad))
    return PASS("all components carry supplier or purl", _refs(comps))


@register_check(R_UID)
def _uid(r: ScanResult, req: Requirement) -> CheckResult:
    comps = _sbom_components(r)
    bad = [c for c in comps if not _has_unique_id(c)]
    if bad:
        return FAIL(f"{len(bad)}/{len(comps)} lack unique identifier", _refs(bad))
    return PASS("all components have purl or bom-ref", _refs(comps))


@register_check(R_LIC)
def _lic(r: ScanResult, req: Requirement) -> CheckResult:
    comps = _sbom_components(r)
    present = [c for c in comps if _has_license(c)]
    absent = [c for c in comps if not _has_license(c)]
    if not absent:
        return PASS("all components carry license", _refs(comps))
    if present and absent:
        return NOT_EVIDENCEABLE(
            f"license not BOM-evidenceable for {len(absent)}/{len(comps)} "
            f"component(s) ({SEBI_DISCLAIMER})",
            _refs(absent),
        )
    return NOT_EVIDENCEABLE(
        f"licenses not BOM-evidenceable from SBOM findings ({SEBI_DISCLAIMER})",
        _refs(comps),
    )


@register_check(R_LIC_RISK)
def _lic_risk(r: ScanResult, req: Requirement) -> CheckResult:
    comps = _sbom_components(r)
    bad = [
        c
        for c in comps
        if (c.properties or {}).get("sbom:license_type") in _HIGH_LICENSE
    ]
    if bad:
        return FAIL(f"{len(bad)} high-risk license(s)", _refs(bad))
    return PASS("no high-risk copyleft / source-available licenses")


@register_check(R_DEPS)
def _deps(r: ScanResult, req: Requirement) -> CheckResult:
    comps = _sbom_components(r)
    if not comps:
        return FAIL("no dependency inventory")
    # Inventory IS the relationship set; do not claim full transitive completeness.
    if r.edges:
        return PASS(
            f"{len(comps)} dependenc(ies) with {len(r.edges)} relationship edge(s) "
            f"(inventory present; not a claim of complete transitive closure)",
            _refs(comps),
        )
    return PASS(
        f"{len(comps)} dependenc(ies) inventoried (relationship set present; "
        f"not a claim of complete transitive closure)",
        _refs(comps),
    )


@register_check(R_HASH)
def _hash(r: ScanResult, req: Requirement) -> CheckResult:
    comps = _sbom_components(r)
    present = [c for c in comps if _prop(c, "sbom:hash")]
    absent = [c for c in comps if not _prop(c, "sbom:hash")]
    if not absent:
        return PASS("all components carry hashes", _refs(comps))
    if present and absent:
        return NOT_EVIDENCEABLE(
            f"hash not BOM-evidenceable for {len(absent)}/{len(comps)} "
            f"component(s) ({SEBI_DISCLAIMER})",
            _refs(absent),
        )
    return NOT_EVIDENCEABLE(
        f"component hashes not BOM-evidenceable from SBOM findings "
        f"({SEBI_DISCLAIMER})",
        _refs(comps),
    )


@register_check(R_PATCH)
def _patch(r: ScanResult, req: Requirement) -> CheckResult:
    comps = _sbom_components(r)
    present = [
        c
        for c in comps
        if _prop(c, "sbom:patch_status") or _prop(c, "sbom:fix_state")
    ]
    absent = [
        c
        for c in comps
        if not (_prop(c, "sbom:patch_status") or _prop(c, "sbom:fix_state"))
    ]
    if not absent:
        return PASS("all components carry patch/fix status", _refs(comps))
    if present and absent:
        return NOT_EVIDENCEABLE(
            f"patch status not BOM-evidenceable for {len(absent)}/{len(comps)} "
            f"component(s) ({SEBI_DISCLAIMER})",
            _refs(absent),
        )
    return NOT_EVIDENCEABLE(
        f"patch/fix status not BOM-evidenceable from SBOM findings "
        f"({SEBI_DISCLAIMER})",
        _refs(comps),
    )


@register_check(R_ENC)
def _enc(r: ScanResult, req: Requirement) -> CheckResult:
    """Encryption-used on SBOM — stamped only; never openssl-name heuristic."""
    comps = _sbom_components(r)
    stamped = _bom_prop(r, "sbom:encryption_used") or _bom_prop(r, "sbom:encryption")
    if stamped:
        return PASS(f"encryption-used stamped on SBOM ({stamped})", _refs(comps))
    per_comp = [
        c
        for c in comps
        if _prop(c, "sbom:encryption_used") or _prop(c, "sbom:encryption")
    ]
    if per_comp and len(per_comp) == len(comps):
        return PASS("encryption-used stamped on all components", _refs(comps))
    return NOT_EVIDENCEABLE(
        f"encryption-used not stamped on SBOM; refusing package-name heuristics "
        f"({SEBI_DISCLAIMER})",
        _refs(comps),
    )


@register_check(R_KU)
def _known_unknown(r: ScanResult, req: Requirement) -> CheckResult:
    comps = _sbom_components(r)
    stamped = (
        _bom_prop(r, "sbom:known_unknown")
        or _bom_prop(r, "sbom:graph_complete")
        or _bom_prop(r, "sbom:incomplete")
    )
    if stamped:
        return PASS(
            f"known-unknown / graph-completeness disclosed ({stamped})",
            _refs(comps),
        )
    return NOT_EVIDENCEABLE(
        f"known-unknown / graph_complete not stamped on SBOM ({SEBI_DISCLAIMER})",
        _refs(comps),
    )


@register_check(R_INV)
def _inv(r: ScanResult, req: Requirement) -> CheckResult:
    comps = _sbom_components(r)
    if not comps:
        return FAIL("empty software dependency inventory")
    bad = [c for c in comps if not (c.name and c.version)]
    if bad:
        return FAIL(
            f"{len(bad)}/{len(comps)} inventoried dependenc(ies) lack name+version",
            _refs(bad),
        )
    return PASS(
        f"software dependency inventory of {len(comps)} component(s)",
        _refs(comps),
    )


@register_check(R_VULN)
def _vuln(r: ScanResult, req: Requirement) -> CheckResult:
    comps = _sbom_components(r)
    if _bom_prop(r, "sbom:vuln_scanner"):
        return PASS(
            f"vulnerability scanner stamped ({_bom_prop(r, 'sbom:vuln_scanner')})",
            _refs(comps),
        )
    assessed = [
        c for c in comps if (c.properties or {}).get("sbom:vuln_assessed") == "true"
    ]
    if assessed:
        return PASS(
            f"{len(assessed)} component(s) marked vulnerability-assessed",
            _refs(assessed),
        )
    return FAIL(
        "no vulnerability assessment tooling or vuln_assessed evidence on SBOM",
        _refs(comps),
    )


@register_check(R_HIGH)
def _high(r: ScanResult, req: Requirement) -> CheckResult:
    comps = _sbom_components(r)
    bad = [
        c
        for c in comps
        if (c.properties or {}).get("sbom:impact") in _HIGH_IMPACT
    ]
    if bad:
        return FAIL(f"{len(bad)} critical/high vulnerabilit(ies)", _refs(bad))
    return PASS("no critical or high severity vulnerabilities")


@register_check(R_AUTHOR)
def _author(r: ScanResult, req: Requirement) -> CheckResult:
    if _bom_prop(r, "sbom:author"):
        return PASS("SBOM author present on scan metadata")
    return FAIL("SBOM author (sbom:author) missing")


@register_check(R_TS)
def _ts(r: ScanResult, req: Requirement) -> CheckResult:
    if _bom_prop(r, "sbom:timestamp"):
        return PASS("SBOM timestamp present on scan metadata")
    return FAIL("SBOM timestamp (sbom:timestamp) missing")


def _register_manuals() -> None:
    doc = load_ledger()
    for raw in doc.get("requirements") or []:
        if raw.get("lane") != "sbom" or raw.get("mode") != "manual":
            continue
        rid = str(raw["id"])
        req = Requirement(
            id=rid,
            framework=_FW,
            title=str(raw["title"]),
            source=str(raw.get("pdf") or _SRC),
        )
        register_manual(
            req,
            f"{SEBI_DISCLAIMER} Process attestation for {rid} "
            f"(organizational / Board / procurement evidence).",
        )


_register_manuals()
