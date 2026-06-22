"""FDA FD&C §524B — SBOM (NTIA minimum elements) + premarket cybersecurity.

Pure graph checks; verdicts come from component fields + depends_on edges, never
from flags. NTIA minimum elements verified against the FDA June-2025 premarket
cybersecurity guidance + §524B(b)(3).
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
)
from aibom.model.result import ScanResult

_FW = "fda_524b"

R_COMPONENTS = Requirement(
    "524B-1", _FW, "SBOM enumerates components with version + identifier",
    "NTIA minimum elements (component name, version, unique id)",
)
R_DEPS = Requirement(
    "524B-2", _FW, "Dependency relationships present",
    "NTIA minimum elements (dependency relationship)",
)
R_LICENSE = Requirement(
    "524B-3", _FW, "Concluded license per component",
    "NTIA minimum elements (license) / §524B",
)
R_INTEGRITY = Requirement(
    "524B-4", _FW, "Component integrity / unique identifier",
    "NTIA minimum elements (unique identifier, hash)",
)
R_MACHINE = Requirement(
    "524B-5", _FW, "Machine-readable SBOM identifiers (purl)",
    "FDA premarket cyber guidance (machine-readable SPDX/CycloneDX)",
)
R_VEX = Requirement(
    "524B-6", _FW, "Vulnerability referencing (VEX)",
    "FDA premarket cyber guidance (VEX)",
)


@register_check(R_COMPONENTS)
def _components(r: ScanResult, req: Requirement) -> CheckResult:
    fws = frameworks(r)
    if not fws:
        return NA("no library/framework components to enumerate")
    missing = [f.bom_ref for f in fws if not (f.version and f.purl)]
    if missing:
        return FAIL(f"{len(missing)} component(s) lack version+purl", missing)
    return PASS(f"all {len(fws)} components carry version + purl",
                [f.bom_ref for f in fws])


@register_check(R_DEPS)
def _deps(r: ScanResult, req: Requirement) -> CheckResult:
    ms = models(r)
    if not ms:
        return NA("no model component")
    missing = [m.bom_ref for m in ms if not depends_on_frameworks(r, m)]
    if missing:
        return FAIL(f"{len(missing)} model(s) declare no depends_on edges", missing)
    return PASS("every model has depends_on dependency edges",
                [m.bom_ref for m in ms])


@register_check(R_LICENSE)
def _license(r: ScanResult, req: Requirement) -> CheckResult:
    comps = [*models(r), *datasets(r), *frameworks(r)]
    if not comps:
        return NA("no components")
    missing = [c.bom_ref for c in comps if not has_license(c)]
    if missing:
        return FAIL(f"{len(missing)} component(s) declare no license", missing)
    return PASS(f"all {len(comps)} components declare a license")


@register_check(R_INTEGRITY)
def _integrity(r: ScanResult, req: Requirement) -> CheckResult:
    ms = models(r)
    if not ms:
        return NA("no model component")
    missing = [m.bom_ref for m in ms if not m.hashes]
    if missing:
        return FAIL(f"{len(missing)} model(s) lack an integrity hash", missing)
    return PASS("every model carries an integrity hash", [m.bom_ref for m in ms])


@register_check(R_MACHINE)
def _machine_readable(r: ScanResult, req: Requirement) -> CheckResult:
    fws = frameworks(r)
    if not fws:
        return NA("no library components")
    bad = [f.bom_ref for f in fws if not (f.purl and f.purl.startswith("pkg:"))]
    if bad:
        return FAIL(f"{len(bad)} component(s) lack a machine-readable purl", bad)
    return PASS("all components carry a pkg: purl (machine-readable)")


@register_check(R_VEX)
def _vex(r: ScanResult, req: Requirement) -> CheckResult:
    return NA(
        "VEX/CVE vulnerability data is not modelled in the AI-BOM graph yet "
        "(advisory: provide a VEX document alongside the SBOM)"
    )
