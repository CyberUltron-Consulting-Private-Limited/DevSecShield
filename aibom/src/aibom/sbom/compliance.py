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
_REACHABLE = frozenset(
    {"reachable", "Reachable", "potentially_reachable", "Potentially Reachable"}
)


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


def _inventory_bom_ref(
    name: str,
    version: str,
    purl: str | None,
    index: int,
    used: set[str],
) -> str:
    """Stable CycloneDX bom-ref: purl, else name@version — never sbom-dep-N."""
    if purl:
        base = purl
    elif name and version:
        base = f"{name}@{version}"
    elif name:
        base = name
    else:
        base = f"component-{index}"
    ref = base
    n = 2
    while ref in used:
        ref = f"{base}#{n}"
        n += 1
    used.add(ref)
    return ref


def _bom_license(comp: dict[str, Any]) -> str:
    for item in comp.get("licenses") or []:
        if not isinstance(item, dict):
            continue
        lic = item.get("license") if isinstance(item.get("license"), dict) else {}
        token = str(
            lic.get("id") or lic.get("name") or item.get("expression") or ""
        ).strip()
        if token and token.lower() not in {
            "noassertion",
            "none",
            "unknown",
            "not_declared",
            "licenseref-not-declared",
        }:
            return token
    return ""


def _bom_hash(comp: dict[str, Any]) -> str:
    for h in comp.get("hashes") or []:
        if isinstance(h, dict) and str(h.get("content") or "").strip():
            return f"{h.get('alg') or 'hash'}:{str(h['content']).strip()}"
    return ""


def _bom_supplier(comp: dict[str, Any]) -> str:
    sup = comp.get("supplier")
    if isinstance(sup, dict) and str(sup.get("name") or "").strip():
        return str(sup["name"]).strip()
    return str(comp.get("publisher") or "").strip()


def _reachable(edges: dict[str, list[str]], root: str) -> set[str]:
    seen: set[str] = set()
    todo = [root]
    while todo:
        for kid in edges.get(todo.pop(), []):
            if kid not in seen:
                seen.add(kid)
                todo.append(kid)
    return seen


def bom_to_scan_result(
    sbom_json: dict[str, Any],
    findings: list[dict[str, Any]] | None = None,
    *,
    bom_properties: dict[str, str] | None = None,
) -> ScanResult:
    """Project the CycloneDX SBOM itself (FIX-C1, SOW D4: "computed from the actual
    fields").

    Every NTIA / CERT-In element is read off the document a customer downloads:
    supplier, version, purl, hashes, licences and description per component; author,
    timestamp and tools from ``metadata``; the dependency relationship from
    ``dependencies`` (a component counts only when it is reachable from the subject).
    Finding rows add only what the BOM does not carry: severity, reachability, CVE
    linkage and patch status.
    """
    meta = (
        sbom_json.get("metadata") if isinstance(sbom_json.get("metadata"), dict) else {}
    )
    root = meta.get("component") if isinstance(meta.get("component"), dict) else {}
    subject_ref = str(root.get("bom-ref") or "sbom-subject")
    rows_by_key: dict[str, list[dict[str, Any]]] = {}
    for row in findings or []:
        if not isinstance(row, dict):
            continue
        purl = str(row.get("purl") or "").split("?", 1)[0].lower()
        name, version = _parse_name_version(_dependency(row))
        for key in (purl, f"{name.lower()}@{version}" if name else ""):
            if key:
                rows_by_key.setdefault(key, []).append(row)

    graph: dict[str, list[str]] = {}
    for dep in sbom_json.get("dependencies") or []:
        if isinstance(dep, dict) and dep.get("ref"):
            graph.setdefault(str(dep["ref"]), []).extend(
                str(k) for k in dep.get("dependsOn") or []
            )
    reachable = _reachable(graph, subject_ref)

    components: list[FrameworkComponent] = []
    edges: list[Edge] = []
    for i, comp in enumerate(sbom_json.get("components") or []):
        if not isinstance(comp, dict) or not str(comp.get("name") or "").strip():
            continue
        ref = str(comp.get("bom-ref") or comp.get("purl") or f"component-{i}")
        purl = str(comp.get("purl") or "").split("?", 1)[0]
        name = str(comp["name"]).strip()
        version = str(comp.get("version") or "").strip()
        rows = (
            rows_by_key.get(purl.lower())
            or rows_by_key.get(f"{name.lower()}@{version}")
            or []
        )
        vuln_rows = [r for r in rows if not r.get("inventory_only")]
        worst = max(
            vuln_rows,
            key=lambda r: {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(
                _impact(r).lower(), 0
            ),
            default=None,
        )
        props: dict[str, str] = {
            "sbom:impact": _impact(worst) if worst else "",
            "sbom:reachability": _reachability(worst) if worst else "",
            "sbom:has_cves": "true"
            if any(_has_cves(r) for r in vuln_rows)
            else "false",
            "sbom:vuln_assessed": "true"
            if (rows and any(r.get("vuln_assessed") for r in rows))
            or isinstance(sbom_json.get("vulnerabilities"), list)
            else "false",
            "sbom:in_dependency_graph": "true" if ref in reachable else "false",
        }
        lic = _bom_license(comp)
        if lic:
            props["sbom:license"] = lic
        lic_type = next((_license(r) for r in rows if _license(r)), "")
        if lic_type:
            props["sbom:license_type"] = lic_type
        for key, val in (
            ("sbom:purl", purl),
            ("sbom:hash", _bom_hash(comp)),
            ("sbom:supplier", _bom_supplier(comp)),
            ("sbom:description", str(comp.get("description") or "").strip()),
            ("sbom:component_author", str(comp.get("author") or "").strip()),
            ("sbom:cve_ids", ",".join(_cve_ids(r) for r in vuln_rows if _cve_ids(r))),
        ):
            if val:
                props[key] = val
        fix_states = sorted(
            {str(r.get("fix_state")) for r in vuln_rows if r.get("fix_state")}
        )
        if fix_states:
            props["sbom:fix_state"] = ",".join(fix_states)
        elif rows and all(r.get("inventory_only") for r in rows):
            props["sbom:patch_status"] = "no known vulnerability"
        components.append(
            FrameworkComponent(
                bom_ref=ref,
                name=name,
                version=version or None,
                publisher=props.get("sbom:supplier"),
                purl=purl or None,
                properties=props,
            )
        )
    for src, kids in graph.items():
        for kid in kids:
            edges.append(Edge(src=src, rel=REL_DEPENDS_ON, dst=kid))

    tools = meta.get("tools") if isinstance(meta.get("tools"), dict) else {}
    tool_names = [
        str(t.get("name") or "").strip()
        for t in tools.get("components") or []
        if isinstance(t, dict)
    ]
    inventory = [
        t for t in tool_names if t and t.lower() not in {"devsecshield", "grype"}
    ]
    authors = [
        str(a.get("name") or "").strip()
        for a in meta.get("authors") or []
        if isinstance(a, dict)
    ]
    in_graph = sum(
        1
        for c in components
        if (c.properties or {}).get("sbom:in_dependency_graph") == "true"
    )
    bom_props: dict[str, str] = {
        "sbom:automation_cyclonedx": "true",
        "sbom:spec_version": str(sbom_json.get("specVersion") or ""),
        "sbom:dependency_graph": "complete"
        if components and in_graph == len(components)
        else ("partial" if in_graph else "absent"),
    }
    if any(authors):
        bom_props["sbom:author"] = ", ".join(a for a in authors if a)
    if meta.get("timestamp"):
        bom_props["sbom:timestamp"] = str(meta["timestamp"])
    if inventory:
        bom_props["sbom:inventory_tools"] = ",".join(inventory)
    if "grype" in {t.lower() for t in tool_names}:
        bom_props["sbom:vuln_scanner"] = "grype"
    for key, val in (bom_properties or {}).items():
        if (
            isinstance(val, str)
            and val.strip()
            and key not in {"sbom:author", "sbom:timestamp"}
        ):
            bom_props.setdefault(str(key), val.strip())
    subject = MetadataComponent(name=str(root.get("name") or "sbom-scan"))
    return ScanResult(
        subject=subject, components=components, edges=edges, properties=bom_props
    )


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

    used_refs: set[str] = set()
    for i, row in enumerate(findings):
        dep = _dependency(row)
        if not dep:
            continue
        name, version = _parse_name_version(dep)
        purl_raw = row.get("purl")
        purl = (
            str(purl_raw).strip()
            if isinstance(purl_raw, str) and purl_raw.strip()
            else None
        )
        bom_ref = _inventory_bom_ref(name, version, purl, i, used_refs)
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
    return PASS(
        f"{len(comps)} dependenc(ies) inventoried with name + version",
        [c.bom_ref for c in comps],
    )


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
        c for c in comps if any(h in (c.name or "").lower() for h in _CRYPTO_DEP_HINTS)
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
    return PASS(
        "crypto-related dependencies have no critical/high CVEs",
        [c.bom_ref for c in crypto],
    )


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
    sbom_json: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Run SBOM supply-chain frameworks; return ``sbom_compliance`` run-object slice.

    With ``sbom_json`` (a CycloneDX SBOM with components) the checks read the document's
    own fields (:func:`bom_to_scan_result`); without one, the finding rows (older
    scans).
    """
    evidence = evidence or {}
    if isinstance(sbom_json, dict) and sbom_json.get("components"):
        result = bom_to_scan_result(sbom_json, findings, bom_properties=bom_properties)
    else:
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

__all__ = [
    "SBOM_FRAMEWORKS",
    "bom_to_scan_result",
    "findings_to_scan_result",
    "run_sbom_compliance",
]
