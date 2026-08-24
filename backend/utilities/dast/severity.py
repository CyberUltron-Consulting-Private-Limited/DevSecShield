"""Severity rollup for Jenkins DAST wait-and-gate."""
from __future__ import annotations


def dast_severity_counts(scan_data: dict | None) -> dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    if not isinstance(scan_data, dict):
        return counts
    results = scan_data.get("results")
    if not isinstance(results, list):
        return counts
    for row in results:
        if not isinstance(row, dict):
            continue
        impact = str(row.get("impact") or row.get("severity") or "").strip().lower()
        if impact in counts:
            counts[impact] += 1
    return counts
