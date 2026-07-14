"""DevSecShield adapter — enrich SBOM/SCA worker output with deterministic compliance."""

from __future__ import annotations

from typing import Any

from aibom.sbom.compliance import run_sbom_compliance


def enrich_sbom_scan(
    results: list[dict[str, Any]],
    duration_of_scan: float,
) -> dict[str, Any]:
    """Add ``sbom_compliance`` to the worker return dict (drop-in for scan_worker)."""
    return {
        "results": results,
        "duration_of_scan": duration_of_scan,
        "sbom_compliance": run_sbom_compliance(results),
    }


__all__ = ["enrich_sbom_scan"]
