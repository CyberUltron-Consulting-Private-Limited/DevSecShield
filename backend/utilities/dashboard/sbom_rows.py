"""Which SCA + SBOM result rows are vulnerabilities (#46).

The worker stores every package the inventory found (Syft, cdxgen) next to the vulnerability rows, each as a row
marked ``inventory_only`` with ``impact: Low`` and ``reachability: not_reachable``
(RabbitMQ/worker/helpers/tools/sca_sbom_agent/merge_inventory.py ``inventory_to_finding_rows``), and every row is
stored as a finding too (celery/create_findings.py). Those rows are the SBOM, not vulnerabilities: the vulnerability
metrics (totals, severities, reachability, license risk, average risk, remediation status, trends) leave them out by
this one rule. The findings table and the CycloneDX download still list them.
"""
from __future__ import annotations

from typing import Any, Iterable


def is_inventory_row(row: Any) -> bool:
    """A package the inventory found with no known vulnerability (stored ``inventory_only``)."""
    return isinstance(row, dict) and bool(row.get("inventory_only"))


def vulnerability_rows(rows: Iterable[Any] | None) -> list[dict[str, Any]]:
    """The result rows that are vulnerabilities: every row except the inventory rows."""
    return [row for row in rows or [] if isinstance(row, dict) and not is_inventory_row(row)]


def vulnerability_findings(findings: Iterable[Any] | None) -> list[Any]:
    """The stored findings (Mongo documents) that are vulnerabilities: their ``finding_data`` is not an inventory row."""
    return [f for f in findings or [] if not (isinstance(f, dict) and is_inventory_row(f.get("finding_data")))]


def is_unverified_version(row: Any) -> bool:
    """A vulnerability matched on a version guessed from a manifest range (``pillow>=10.0`` read as 10.0): the
    installed version is not known, so the match is possible, not confirmed (review 6028132826 M2). Such rows are
    shown as an "unverified version" count, never in the severity totals or the risk score."""
    return isinstance(row, dict) and not is_inventory_row(row) and bool(row.get("version_guessed_from"))


def severity_rows(rows: Iterable[Any] | None) -> list[dict[str, Any]]:
    """The vulnerability rows the severity totals, risk score and reachability count: confirmed versions only."""
    return [row for row in vulnerability_rows(rows) if not is_unverified_version(row)]


def unverified_version_rows(rows: Iterable[Any] | None) -> list[dict[str, Any]]:
    return [row for row in rows or [] if is_unverified_version(row)]


def severity_findings(findings: Iterable[Any] | None) -> list[Any]:
    """Stored findings for the severity trend: vulnerabilities on a confirmed version."""
    return [f for f in vulnerability_findings(findings)
            if not (isinstance(f, dict) and is_unverified_version(f.get("finding_data")))]


def component_licence_categories(scan_data: Any) -> list[str]:
    """One licence risk category per SBOM component (review 6028132826 M4: the licence chart and the high-risk count
    are over the components, not the vulnerability rows). The stored SBOM's licences are the ones the worker resolved
    once (registry_enrich.py) and ``/bom`` serves; a component without one falls back to the curated map, as ``/bom``
    does. A scan without a stored SBOM counts its rows, one per package."""
    from backend.utilities.compliance.spdx_license import licence_text
    from backend.utilities.dashboard.sbom_license import (
        resolve_sbom_license_category,
        spdx_to_license_category,
    )

    data = scan_data if isinstance(scan_data, dict) else {}
    comps = _components(data)
    out: list[str] = []
    if comps:
        for c in comps:
            text = licence_text(c.get("licenses"))
            purl = str(c.get("purl") or "")
            if not text and purl.startswith(("pkg:github/actions/", "pkg:github/github/", "pkg:github/pypa/")):
                text = "MIT"
            out.append(spdx_to_license_category(text) if text else
                       resolve_sbom_license_category({"dependency": str(c.get("name") or "")}))
        return out
    seen: set[str] = set()
    for row in data.get("results") or []:
        if not isinstance(row, dict):
            continue
        key = str(row.get("purl") or row.get("dependency") or "").lower()
        if not key or key in seen:
            continue
        seen.add(key)
        out.append(resolve_sbom_license_category(row))
    return out



def _components(data: dict) -> list[dict[str, Any]]:
    """The stored SBOM's package components (a file without a purl is not a package)."""
    bom = data.get("sbom_json") if isinstance(data.get("sbom_json"), dict) else {}
    return [c for c in bom.get("components") or [] if isinstance(c, dict) and str(c.get("name") or "").strip()
            and not (str(c.get("type") or "").lower() == "file" and not c.get("purl"))]


def is_incomplete(scan_data: Any) -> bool:
    """Whether a finished SBOM scan cannot be scored: it inventoried no package (no stored component and no result
    row: nothing was matched, so "no vulnerability" means nothing), or every vulnerability it matched is on a version
    guessed from a range (listed, not counted, review 6028132826 M2) so the zero is not a clean result. Its risk score is
    "incomplete", never 0 / A."""
    data = scan_data if isinstance(scan_data, dict) else {}
    rows = [r for r in data.get("results") or [] if isinstance(r, dict)]
    if not _components(data) and not rows:  # every row is a package (an inventory row or a vulnerable one)
        return True
    return not severity_rows(rows) and bool(unverified_version_rows(rows))


__all__ = ["component_licence_categories", "is_incomplete", "is_inventory_row", "is_unverified_version", "severity_findings", "severity_rows",
           "unverified_version_rows", "vulnerability_findings", "vulnerability_rows"]
