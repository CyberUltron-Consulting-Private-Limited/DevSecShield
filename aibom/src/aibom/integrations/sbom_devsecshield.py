"""DevSecShield adapter — enrich SBOM/SCA worker output with deterministic compliance."""

from __future__ import annotations

from typing import Any

from aibom.sbom.compliance import run_sbom_compliance


def enrich_sbom_scan(
    results: list[dict[str, Any]],
    duration_of_scan: float,
    *,
    bom_properties: dict[str, str] | None = None,
    sbom_json: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Add ``sbom_compliance`` to the worker return dict (drop-in for scan_worker).

    Optional multi-engine metadata (Syft/cdxgen/Grype) rides in ``bom_properties``
    and into CERT-In Table-5 provenance checks. A CycloneDX blob proves automation.
    """
    props: dict[str, str] = dict(bom_properties or {})
    if sbom_json is not None:
        props.setdefault("sbom:automation_cyclonedx", "true")
        props.setdefault("sbom:multi_format_emit", "true")
    out: dict[str, Any] = {
        "results": results,
        "duration_of_scan": duration_of_scan,
        "sbom_compliance": run_sbom_compliance(results, bom_properties=props),
    }
    if sbom_json is not None:
        out["sbom_json"] = sbom_json
    return out


__all__ = ["enrich_sbom_scan"]
