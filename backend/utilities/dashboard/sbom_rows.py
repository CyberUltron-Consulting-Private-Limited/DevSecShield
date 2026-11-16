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


__all__ = ["is_inventory_row", "vulnerability_findings", "vulnerability_rows"]
