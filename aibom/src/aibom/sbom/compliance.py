"""SBOM supply-chain compliance — RBI FREE-AI + NTIA + NIST SSDF + CERT-In + SEBI.

Deterministic checks over persisted SBOM/SCA finding rows (not LLM tags).
Never infers pass/fail from ``compliance_controls`` LLM assignments.

NTIA / SSDF register via :mod:`aibom.sbom.frameworks_supply`. CERT-In
``cert_in_sbom`` via :mod:`aibom.compliance.cert_in.sbom`. SEBI
``sebi_cscrf_sbom`` via :mod:`aibom.compliance.sebi_cscrf.sbom` — never from
:mod:`aibom.compliance.__init__`.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from aibom.compliance.base import ADVISORY_DISCLAIMER
from aibom.compliance.engine import run_framework
from aibom.model.component import FrameworkComponent, MetadataComponent
from aibom.model.result import REL_DEPENDS_ON, Edge, ScanResult

SBOM_FRAMEWORKS = [
    "rbi_free_ai_supply",
    "ntia_minimum_elements",
    "nist_ssdf",
    "cert_in_sbom",
    "sebi_cscrf_sbom",
]

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
_REACHABLE = frozenset({"reachable", "Reachable", "potentially_reachable", "Potentially Reachable"})


def _impact(f: dict[str, Any]) -> str:
    raw = f.get("impact") or ""
    return str(raw)


def _dependency(f: dict[str, Any]) -> str:
    return str(f.get("dependency") or f.get("package_name") or "").strip()


def _license(f: dict[str, Any]) -> str:
    raw = f.get("license_type") or f.get("license") or ""
    return str(raw).strip()


def _reachability(f: dict[str, Any]) -> str:
    raw = f.get("reachability") or ""
    return str(raw)


def _has_cves(f: dict[str, Any]) -> bool:
    cves = f.get("cves")
    if isinstance(cves, dict):
        return bool(cves)
    if isinstance(cves, list):
        return bool(cves)
    return False


def _cve_ids(f: dict[str, Any]) -> str:
    cves = f.get("cves")
    if isinstance(cves, dict):
        return ",".join(str(k) for k in cves.keys())
    if isinstance(cves, list):
        parts: list[str] = []
        for item in cves:
            if isinstance(item, str):
                parts.append(item)
            elif isinstance(item, dict) and item.get("id"):
                parts.append(str(item["id"]))
        return ",".join(parts)
    return ""


def _parse_name_version(dep: str) -> tuple[str, str]:
    name = dep.split("@")[0].split("==")[0].strip() or dep
    version = ""
    if "@" in dep:
        version = dep.split("@", 1)[1]
    elif "==" in dep:
        version = dep.split("==", 1)[1]
    return name, version


def findings_to_scan_result(
    findings: list[dict[str, Any]],
    *,
    bom_properties: dict[str, str] | None = None,
) -> ScanResult:
    """Project SBOM finding rows into a minimal ScanResult for the shared runner.

    Enrichment is defensive: only projects keys present on the row (plus honest
    scan-metadata stamps on ``ScanResult.properties``). Never invents Origin,
    EOL, hashes, or Automation emit flags.
    """
    subject = MetadataComponent(name="sbom-scan")
    components: list[FrameworkComponent] = []
    edges: list[Edge] = []
    subject_ref = "sbom-subject"

    for i, row in enumerate(findings):
        dep = _dependency(row)
        if not dep:
            continue
        name, version = _parse_name_version(dep)
        bom_ref = f"sbom-dep-{i}"
        # Legacy vuln rows default to assessed; inventory-only rows must opt in.
        vuln_assessed = row.get("vuln_assessed")
        if vuln_assessed is None:
            vuln_assessed = not bool(row.get("inventory_only"))
        props: dict[str, str] = {
            "sbom:impact": _impact(row),
            "sbom:reachability": _reachability(row),
            "sbom:license_type": _license(row),
            "sbom:has_cves": "true" if _has_cves(row) else "false",
            "sbom:vuln_assessed": "true" if vuln_assessed else "false",
        }
        lic = _license(row)
        if lic:
            props["sbom:license"] = lic
        cve_ids = _cve_ids(row)
        if cve_ids:
            props["sbom:cve_ids"] = cve_ids

        purl_raw = row.get("purl")
        purl = str(purl_raw).strip() if isinstance(purl_raw, str) and purl_raw.strip() else None
        if purl:
            props["sbom:purl"] = purl

        desc = str(row.get("description") or "").strip()
        title = str(row.get("title") or "").strip()
        text = desc or title
        if text:
            props["sbom:description"] = text

        for src_key, prop_key in (
            ("fix_state", "sbom:fix_state"),
            ("patch_status", "sbom:patch_status"),
            ("fix", "sbom:fix_state"),
            ("supplier", "sbom:supplier"),
            ("publisher", "sbom:supplier"),
            ("origin", "sbom:origin"),
            ("hash", "sbom:hash"),
            ("checksum", "sbom:hash"),
            ("license", "sbom:license"),
        ):
            raw = row.get(src_key)
            if isinstance(raw, str) and raw.strip():
                props[prop_key] = raw.strip()

        publisher = None
        if props.get("sbom:supplier"):
            publisher = props["sbom:supplier"]

        components.append(
            FrameworkComponent(
                bom_ref=bom_ref,
                name=name,
                version=version or None,
                publisher=publisher,
                purl=purl,
                properties=props,
            )
        )
        edges.append(Edge(src=subject_ref, rel=REL_DEPENDS_ON, dst=bom_ref))

    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    bom_props: dict[str, str] = {
        "sbom:author": "DevSecShield",
        "sbom:timestamp": now,
        # Automation flags omitted unless proven (honest FAIL on SCA findings path).
    }
    if bom_properties:
        for key, val in bom_properties.items():
            if isinstance(val, str) and val.strip():
                bom_props[str(key)] = val.strip()

    return ScanResult(
        subject=subject,
        components=components,
        edges=edges,
        properties=bom_props,
    )


# Register checks into the shared registry under rbi_free_ai_supply.
from aibom.compliance.base import (  # noqa: E402
    FAIL,
    NA,
    PASS,
    CheckResult,
    Requirement,
    register_applicability,
    register_check,
    register_manual,
)

_FW = "rbi_free_ai_supply"
_SRC = "RBI FREE-AI — Supply Chain (Rec 23 / Annexure IV)"


def _req(rid: str, title: str) -> Requirement:
    return Requirement(rid, _FW, title, _SRC)


def _sbom_components(r: ScanResult) -> list[FrameworkComponent]:
    return [c for c in r.components if c.kind == "framework"]


R_S1 = _req("FREEAI-SUPPLY-1", "Dependency inventory: components have name + version")
R_S2 = _req("FREEAI-SUPPLY-2", "No critical or high severity vulnerabilities")
R_S3 = _req("FREEAI-SUPPLY-3", "No reachable critical/high vulnerabilities")
R_S4 = _req("FREEAI-SUPPLY-4", "No high-risk copyleft / source-available licenses")
R_S5 = _req("FREEAI-SUPPLY-5", "Vulnerable crypto-related dependencies tracked")
R_S6 = _req("FREEAI-SUPPLY-6", "Third-party outsourcing due diligence")


register_applicability(
    _FW,
    lambda r: bool(_sbom_components(r)),
    "no dependency components inventoried; supply-chain framework out of scope",
)


@register_check(R_S1)
def _supply1(r: ScanResult, req: Requirement) -> CheckResult:
    comps = _sbom_components(r)
    if not comps:
        return NA("no dependencies inventoried")
    bad = [c.bom_ref for c in comps if not (c.name and c.version)]
    if bad:
        return FAIL(f"{len(bad)} dependenc(ies) lack name or version", bad)
    return PASS(f"{len(comps)} dependenc(ies) inventoried with name + version", [c.bom_ref for c in comps])


@register_check(R_S2)
def _supply2(r: ScanResult, req: Requirement) -> CheckResult:
    comps = _sbom_components(r)
    if not comps:
        return NA("no dependencies to assess")
    bad = [
        c.bom_ref
        for c in comps
        if (c.properties or {}).get("sbom:impact") in _HIGH_IMPACT
    ]
    if bad:
        return FAIL(f"{len(bad)} critical/high vulnerabilit(ies)", bad)
    return PASS("no critical or high severity vulnerabilities")


@register_check(R_S3)
def _supply3(r: ScanResult, req: Requirement) -> CheckResult:
    comps = _sbom_components(r)
    if not comps:
        return NA("no dependencies to assess")
    bad = [
        c.bom_ref
        for c in comps
        if (c.properties or {}).get("sbom:impact") in _HIGH_IMPACT
        and (c.properties or {}).get("sbom:reachability") in _REACHABLE
    ]
    if bad:
        return FAIL(f"{len(bad)} reachable critical/high vulnerabilit(ies)", bad)
    return PASS("no reachable critical/high vulnerabilities")


@register_check(R_S4)
def _supply4(r: ScanResult, req: Requirement) -> CheckResult:
    comps = _sbom_components(r)
    if not comps:
        return NA("no dependencies to assess")
    bad = [
        c.bom_ref
        for c in comps
        if (c.properties or {}).get("sbom:license_type") in _HIGH_LICENSE
    ]
    if bad:
        return FAIL(f"{len(bad)} high-risk license(s)", bad)
    return PASS("no high-risk copyleft / source-available licenses")


_CRYPTO_DEP_HINTS = (
    "cryptography",
    "openssl",
    "pycrypto",
    "pynacl",
    "jwt",
    "bcrypt",
    "passlib",
    "m2crypto",
)


@register_check(R_S5)
def _supply5(r: ScanResult, req: Requirement) -> CheckResult:
    comps = _sbom_components(r)
    crypto = [
        c
        for c in comps
        if any(h in (c.name or "").lower() for h in _CRYPTO_DEP_HINTS)
    ]
    if not crypto:
        return PASS("no crypto-related dependencies in inventory")
    bad = [
        c.bom_ref
        for c in crypto
        if (c.properties or {}).get("sbom:has_cves") == "true"
        and (c.properties or {}).get("sbom:impact") in _HIGH_IMPACT
    ]
    if bad:
        return FAIL(
            f"{len(bad)} crypto-related dependenc(ies) with critical/high CVEs",
            bad,
        )
    return PASS("crypto-related dependencies have no critical/high CVEs", [c.bom_ref for c in crypto])


register_manual(
    R_S6,
    "third-party outsourcing due diligence and vendor AI disclosure are "
    "contractual/process evidence not visible in an SBOM vulnerability scan",
)


def run_sbom_compliance(
    findings: list[dict[str, Any]],
    evidence: dict[str, dict[str, Any]] | None = None,
    *,
    bom_properties: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Run SBOM supply-chain frameworks; return ``sbom_compliance`` run-object slice."""
    evidence = evidence or {}
    result = findings_to_scan_result(findings, bom_properties=bom_properties)
    report: dict[str, Any] = {
        fw: run_framework(result, fw, evidence.get(fw)) for fw in SBOM_FRAMEWORKS
    }
    report["disclaimer"] = ADVISORY_DISCLAIMER
    return report


# Supply-chain frameworks (NTIA + NIST SSDF) + CERT-In / SEBI SBOM —
# side-effect registration. Keep SEBI/CERT-In SBOM out of aibom.compliance.__init__.
from aibom.sbom import frameworks_supply as _sbom_supply  # noqa: E402,F401
from aibom.compliance.cert_in import sbom as _cert_in_sbom  # noqa: E402,F401
from aibom.compliance.sebi_cscrf import sbom as _sebi_cscrf_sbom  # noqa: E402,F401

__all__ = ["SBOM_FRAMEWORKS", "findings_to_scan_result", "run_sbom_compliance"]
