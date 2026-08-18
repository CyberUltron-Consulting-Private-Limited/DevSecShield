"""SBOM supply-chain frameworks — NTIA minimum elements + NIST SSDF.

Graph-only checks over projected ``sbom:*`` / component fields. Never reads
``result.flags``. Side-effect import from :mod:`aibom.sbom.compliance`.
"""

from __future__ import annotations

from aibom.compliance.base import (
    ADVISORY_DISCLAIMER,
    FAIL,
    NA,
    NOT_EVIDENCEABLE,
    PASS,
    CheckResult,
    Requirement,
    register_applicability,
    register_check,
    register_manual,
)
from aibom.model.component import FrameworkComponent
from aibom.model.result import ScanResult

_HIGH_IMPACT = frozenset({"Critical", "critical", "High", "high"})
_REACHABLE = frozenset(
    {"reachable", "Reachable", "potentially_reachable", "Potentially Reachable"}
)


def _sbom_components(r: ScanResult) -> list[FrameworkComponent]:
    return [c for c in r.components if c.kind == "framework"]


def _bom_prop(r: ScanResult, key: str) -> str | None:
    val = (r.properties or {}).get(key)
    if isinstance(val, str) and val.strip():
        return val.strip()
    return None


def _prop(c: FrameworkComponent, key: str) -> str | None:
    val = (c.properties or {}).get(key)
    if isinstance(val, str) and val.strip():
        return val.strip()
    return None


def _has_unique_id(c: FrameworkComponent) -> bool:
    if c.purl and str(c.purl).strip():
        return True
    if _prop(c, "sbom:purl"):
        return True
    if c.bom_ref and str(c.bom_ref).strip():
        return True
    return False


def _has_supplier(c: FrameworkComponent) -> bool:
    if c.publisher and str(c.publisher).strip():
        return True
    if _prop(c, "sbom:supplier"):
        return True
    # PURL namespace is an acceptable supplier proxy (NTIA practice).
    if c.purl and str(c.purl).strip():
        return True
    if _prop(c, "sbom:purl"):
        return True
    return False


def _has_license(c: FrameworkComponent) -> bool:
    lic = _prop(c, "sbom:license") or _prop(c, "sbom:license_type")
    if not lic:
        return False
    return lic.lower() not in {"unknown", "n/a", "none", ""}


# ── NTIA Minimum Elements (EO 14028) ─────────────────────────────────────────

_FW_NTIA = "ntia_minimum_elements"
_SRC_NTIA = "NTIA Minimum Elements for a Software Bill of Materials (EO 14028)"


def _ntia(rid: str, title: str) -> Requirement:
    return Requirement(rid, _FW_NTIA, title, _SRC_NTIA)


register_applicability(
    _FW_NTIA,
    lambda r: bool(_sbom_components(r)),
    "no dependency components inventoried; NTIA minimum elements out of scope",
)

R_NTIA_SUPPLIER = _ntia("NTIA-1", "Supplier name")
R_NTIA_NAME = _ntia("NTIA-2", "Component name")
R_NTIA_VERSION = _ntia("NTIA-3", "Component version")
R_NTIA_UID = _ntia("NTIA-4", "Other unique identifiers")
R_NTIA_DEPS = _ntia("NTIA-5", "Dependency relationship")
R_NTIA_AUTHOR = _ntia("NTIA-6", "Author of SBOM data")
R_NTIA_TS = _ntia("NTIA-7", "Timestamp")
R_NTIA_HASH = _ntia("NTIA-8", "Component hash / checksum")
R_NTIA_LICENSE = _ntia("NTIA-9", "Component license")
R_NTIA_VULN = _ntia("NTIA-10", "Vulnerability assessment linkage")


@register_check(R_NTIA_SUPPLIER)
def _ntia_supplier(r: ScanResult, req: Requirement) -> CheckResult:
    comps = _sbom_components(r)
    if not comps:
        return NA("no dependencies")
    bad = [c.bom_ref for c in comps if not _has_supplier(c)]
    if bad:
        return FAIL(f"{len(bad)}/{len(comps)} lack supplier/purl", bad)
    return PASS("all components carry supplier or purl", [c.bom_ref for c in comps])


@register_check(R_NTIA_NAME)
def _ntia_name(r: ScanResult, req: Requirement) -> CheckResult:
    comps = _sbom_components(r)
    if not comps:
        return NA("no dependencies")
    bad = [c.bom_ref for c in comps if not (c.name and str(c.name).strip())]
    if bad:
        return FAIL(f"{len(bad)}/{len(comps)} lack component name", bad)
    return PASS("all components named", [c.bom_ref for c in comps])


@register_check(R_NTIA_VERSION)
def _ntia_version(r: ScanResult, req: Requirement) -> CheckResult:
    comps = _sbom_components(r)
    if not comps:
        return NA("no dependencies")
    bad = [c.bom_ref for c in comps if not (c.version and str(c.version).strip())]
    if bad:
        return FAIL(f"{len(bad)}/{len(comps)} lack version", bad)
    return PASS("all components versioned", [c.bom_ref for c in comps])


@register_check(R_NTIA_UID)
def _ntia_uid(r: ScanResult, req: Requirement) -> CheckResult:
    comps = _sbom_components(r)
    if not comps:
        return NA("no dependencies")
    bad = [c.bom_ref for c in comps if not _has_unique_id(c)]
    if bad:
        return FAIL(f"{len(bad)}/{len(comps)} lack unique identifier", bad)
    return PASS("all components have purl or bom-ref", [c.bom_ref for c in comps])


@register_check(R_NTIA_DEPS)
def _ntia_deps(r: ScanResult, req: Requirement) -> CheckResult:
    comps = _sbom_components(r)
    if not comps:
        return NA("no dependencies")
    # Projected inventory + depends_on edges IS the dependency relationship set.
    if r.edges:
        return PASS(
            f"{len(comps)} dependenc(ies) with {len(r.edges)} relationship edge(s)",
            [c.bom_ref for c in comps],
        )
    return PASS(
        f"{len(comps)} dependenc(ies) inventoried (relationship set)",
        [c.bom_ref for c in comps],
    )


@register_check(R_NTIA_AUTHOR)
def _ntia_author(r: ScanResult, req: Requirement) -> CheckResult:
    if _bom_prop(r, "sbom:author"):
        return PASS("SBOM author present on scan metadata")
    return FAIL("SBOM author (sbom:author) missing")


@register_check(R_NTIA_TS)
def _ntia_timestamp(r: ScanResult, req: Requirement) -> CheckResult:
    if _bom_prop(r, "sbom:timestamp"):
        return PASS("SBOM timestamp present on scan metadata")
    return FAIL("SBOM timestamp (sbom:timestamp) missing")


@register_check(R_NTIA_HASH)
def _ntia_hash(r: ScanResult, req: Requirement) -> CheckResult:
    comps = _sbom_components(r)
    if not comps:
        return NA("no dependencies")
    present = [c for c in comps if _prop(c, "sbom:hash")]
    absent = [c for c in comps if not _prop(c, "sbom:hash")]
    if not absent:
        return PASS("all components carry hashes", [c.bom_ref for c in comps])
    if present and absent:
        return NOT_EVIDENCEABLE(
            f"hash not BOM-evidenceable for {len(absent)}/{len(comps)} "
            f"component(s) ({ADVISORY_DISCLAIMER})",
            [c.bom_ref for c in absent],
        )
    return NOT_EVIDENCEABLE(
        f"component hashes not BOM-evidenceable from SBOM findings "
        f"({ADVISORY_DISCLAIMER})",
        [c.bom_ref for c in comps],
    )


@register_check(R_NTIA_LICENSE)
def _ntia_license(r: ScanResult, req: Requirement) -> CheckResult:
    comps = _sbom_components(r)
    if not comps:
        return NA("no dependencies")
    present = [c for c in comps if _has_license(c)]
    absent = [c for c in comps if not _has_license(c)]
    if not absent:
        return PASS("all components carry license", [c.bom_ref for c in comps])
    if present and absent:
        return NOT_EVIDENCEABLE(
            f"license not BOM-evidenceable for {len(absent)}/{len(comps)} "
            f"component(s) ({ADVISORY_DISCLAIMER})",
            [c.bom_ref for c in absent],
        )
    return NOT_EVIDENCEABLE(
        f"licenses not BOM-evidenceable from SBOM findings ({ADVISORY_DISCLAIMER})",
        [c.bom_ref for c in comps],
    )


@register_check(R_NTIA_VULN)
def _ntia_vuln(r: ScanResult, req: Requirement) -> CheckResult:
    comps = _sbom_components(r)
    if not comps:
        return NA("no dependencies")
    if _bom_prop(r, "sbom:vuln_scanner"):
        return PASS(
            f"vulnerability scanner stamped ({_bom_prop(r, 'sbom:vuln_scanner')})",
            [c.bom_ref for c in comps],
        )
    assessed = [
        c
        for c in comps
        if (c.properties or {}).get("sbom:vuln_assessed") == "true"
    ]
    if assessed:
        return PASS(
            f"{len(assessed)} component(s) marked vulnerability-assessed",
            [c.bom_ref for c in assessed],
        )
    return FAIL(
        "no vulnerability assessment tooling or vuln_assessed evidence on SBOM",
        [c.bom_ref for c in comps],
    )


# ── NIST SSDF (SP 800-218) — thin auto + manuals ─────────────────────────────

_FW_SSDF = "nist_ssdf"
_SRC_SSDF = "NIST SP 800-218 Secure Software Development Framework (SSDF)"


def _ssdf(rid: str, title: str) -> Requirement:
    return Requirement(rid, _FW_SSDF, title, _SRC_SSDF)


register_applicability(
    _FW_SSDF,
    lambda r: bool(_sbom_components(r)),
    "no dependency components inventoried; NIST SSDF out of scope for this scan",
)

R_SSDF_INV = _ssdf("SSDF-PW-4.4", "Produce SBOM / dependency inventory")
R_SSDF_VULN = _ssdf("SSDF-RV-1.1", "Identify and confirm vulnerabilities")
R_SSDF_REACH = _ssdf(
    "SSDF-RV-1.2", "No reachable critical/high vulnerabilities without triage"
)

R_SSDF_PO = _ssdf("SSDF-PO-1.1", "Define security requirements for software development")
R_SSDF_PS = _ssdf("SSDF-PS-1.1", "Protect all forms of code from unauthorized access")
R_SSDF_PW = _ssdf("SSDF-PW-1.1", "Use well-secured design / architecture review")
R_SSDF_RV = _ssdf("SSDF-RV-3.1", "Analyze vulnerabilities to identify root causes")
R_SSDF_PO3 = _ssdf("SSDF-PO-3.2", "Implement roles for SDLC security")
R_SSDF_PW7 = _ssdf("SSDF-PW-7.1", "Review and/or analyze human-readable code")


@register_check(R_SSDF_INV)
def _ssdf_inventory(r: ScanResult, req: Requirement) -> CheckResult:
    comps = _sbom_components(r)
    if not comps:
        return NA("no dependencies")
    return PASS(
        f"SBOM inventory of {len(comps)} dependenc(ies) produced",
        [c.bom_ref for c in comps],
    )


@register_check(R_SSDF_VULN)
def _ssdf_vuln_id(r: ScanResult, req: Requirement) -> CheckResult:
    comps = _sbom_components(r)
    if not comps:
        return NA("no dependencies")
    if _bom_prop(r, "sbom:vuln_scanner"):
        return PASS(
            f"vuln identification via {_bom_prop(r, 'sbom:vuln_scanner')}",
            [c.bom_ref for c in comps],
        )
    assessed = any(
        (c.properties or {}).get("sbom:vuln_assessed") == "true" for c in comps
    )
    if assessed:
        return PASS("components carry vulnerability-assessed evidence")
    return FAIL("no vulnerability scanner / assessment evidence on SBOM scan")


@register_check(R_SSDF_REACH)
def _ssdf_reachable(r: ScanResult, req: Requirement) -> CheckResult:
    comps = _sbom_components(r)
    if not comps:
        return NA("no dependencies")
    bad = [
        c.bom_ref
        for c in comps
        if (c.properties or {}).get("sbom:impact") in _HIGH_IMPACT
        and (c.properties or {}).get("sbom:reachability") in _REACHABLE
        and (c.properties or {}).get("sbom:has_cves") == "true"
    ]
    if bad:
        return FAIL(
            f"{len(bad)} reachable critical/high CVE finding(s) need triage",
            bad,
        )
    return PASS("no reachable critical/high CVE findings")


_MANUAL_NOTE = (
    f"{ADVISORY_DISCLAIMER} Process / SDLC practice evidence is not visible "
    "in an SBOM inventory scan — organizational attestation required."
)

register_manual(R_SSDF_PO, _MANUAL_NOTE)
register_manual(R_SSDF_PS, _MANUAL_NOTE)
register_manual(R_SSDF_PW, _MANUAL_NOTE)
register_manual(R_SSDF_RV, _MANUAL_NOTE)
register_manual(R_SSDF_PO3, _MANUAL_NOTE)
register_manual(R_SSDF_PW7, _MANUAL_NOTE)
