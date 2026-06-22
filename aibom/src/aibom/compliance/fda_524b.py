"""FDA FD&C §524B — SBOM (NTIA minimum elements) + premarket cybersecurity.

Pure graph checks over component fields + depends_on edges + the emitter-stamped
metadata; never reads flags. NTIA minimum elements per the FDA June-2025
premarket cybersecurity guidance + §524B(b)(3).
"""

from __future__ import annotations

from aibom.compliance.base import (
    FAIL,
    NA,
    PASS,
    CheckResult,
    Requirement,
    datasets,
    depends_on_frameworks,
    frameworks,
    has_license,
    models,
    register_check,
    register_manual,
)
from aibom.model.result import ScanResult

_FW = "fda_524b"


def _r(rid: str, title: str, source: str) -> Requirement:
    return Requirement(rid, _FW, title, source)


R1 = _r("524B-1", "Component name + version",
        "NTIA minimum elements (component name, version)")
R2 = _r("524B-2", "Component hash + algorithm",
        "NTIA minimum elements (hash)")
R3 = _r("524B-3", "Dependency relationships present",
        "NTIA minimum elements (dependency relationship)")
R4 = _r("524B-4", "Unique identifier (purl) per library",
        "NTIA minimum elements (unique identifier)")
R5 = _r("524B-5", "Concluded license per component",
        "NTIA minimum elements (license) / §524B")
R6 = _r("524B-6", "Device class / SaMD classification asserted",
        "§524B cyber-device premarket")
R7 = _r("524B-7", "SBOM author + timestamp + machine-readable format",
        "NTIA minimum elements (author, timestamp, format)")


@register_check(R1)
def _name_version(r: ScanResult, req: Requirement) -> CheckResult:
    comps = [*models(r), *frameworks(r)]  # versionable artifacts
    if not comps:
        return NA("no versionable components")
    bad = [c.bom_ref for c in comps if not (c.name and c.version)]
    if bad:
        return FAIL(f"{len(bad)} component(s) lack name or version", bad)
    return PASS(f"all {len(comps)} components carry name + version")


@register_check(R2)
def _hash(r: ScanResult, req: Requirement) -> CheckResult:
    ms = models(r)
    if not ms:
        return NA("no model component")
    bad = [
        m.bom_ref
        for m in ms
        if not (m.hashes and all(h.alg and h.content for h in m.hashes))
    ]
    if bad:
        return FAIL(f"{len(bad)} model(s) lack a hash + algorithm", bad)
    return PASS("every model carries a hash + algorithm", [m.bom_ref for m in ms])


@register_check(R3)
def _deps(r: ScanResult, req: Requirement) -> CheckResult:
    ms = models(r)
    if not ms:
        return NA("no model component")
    bad = [m.bom_ref for m in ms if not depends_on_frameworks(r, m)]
    if bad:
        return FAIL(f"{len(bad)} model(s) declare no dependency edges", bad)
    return PASS("dependency relationships present", [m.bom_ref for m in ms])


@register_check(R4)
def _purl(r: ScanResult, req: Requirement) -> CheckResult:
    fws = frameworks(r)
    if not fws:
        return NA("no library components")
    bad = [f.bom_ref for f in fws if not (f.purl and f.purl.startswith("pkg:"))]
    if bad:
        return FAIL(f"{len(bad)} library(ies) lack a unique purl identifier", bad)
    return PASS(f"all {len(fws)} libraries carry a pkg: purl")


@register_check(R5)
def _license(r: ScanResult, req: Requirement) -> CheckResult:
    comps = [*models(r), *datasets(r), *frameworks(r)]
    if not comps:
        return NA("no components")
    bad = [c.bom_ref for c in comps if not has_license(c)]
    if bad:
        return FAIL(f"{len(bad)} component(s) declare no license", bad)
    return PASS(f"all {len(comps)} components declare a license")


@register_check(R6)
def _device_class(r: ScanResult, req: Requirement) -> CheckResult:
    ms = models(r)
    if not ms:
        return NA("no model component")
    classified = [m for m in ms if m.model_card.device_class]
    if not classified:
        return NA("no model asserts a device class (not a cyber device in scope)")
    bad = [m.bom_ref for m in ms if not m.model_card.device_class]
    if bad:
        return FAIL(f"{len(bad)} model(s) assert no device class", bad)
    return PASS("every model asserts its device class / SaMD classification",
                [m.bom_ref for m in ms])


@register_check(R7)
def _metadata(r: ScanResult, req: Requirement) -> CheckResult:
    if not r.subject.name:
        return FAIL("the SBOM has no subject (author/format cannot be stamped)")
    return PASS(
        "SBOM author, timestamp, and machine-readable format (CycloneDX 1.6 / "
        "SPDX 3.0) are stamped by the emitter"
    )


register_manual(_r("524B-8", "Vulnerability referencing (VEX)",
                   "FDA premarket cyber guidance (VEX)"),
                "VEX/CVE data is not modelled in the AI-BOM graph (advisory: "
                "provide a VEX document alongside the SBOM)")
