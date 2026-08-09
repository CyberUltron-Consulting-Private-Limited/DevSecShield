"""Pick the best SUCCESS BOM compliance blob for team posture rollups."""

from __future__ import annotations

from typing import Any


def _applicable_count(fw_block: dict[str, Any]) -> int:
    """Counts that mean the framework ran in-scope (not pure OOS)."""
    return int(fw_block.get("pass") or 0) + int(
        fw_block.get("pass_with_evidence") or 0
    ) + int(fw_block.get("fail") or 0) + int(
        fw_block.get("not_bom_evidenceable") or 0
    )


def compliance_blob_in_scope(
    blob: dict[str, Any] | None, frameworks: tuple[str, ...]
) -> bool:
    """True when any preferred framework has at least one non-OOS verdict bucket."""
    if not blob or not isinstance(blob, dict) or not frameworks:
        return False
    for fw in frameworks:
        block = blob.get(fw)
        if isinstance(block, dict) and _applicable_count(block) > 0:
            return True
    return False


def pick_latest_bom_compliance(
    scans: list[Any],
    *,
    scan_type: str,
    compliance_key: str,
    prefer_frameworks: tuple[str, ...] = (),
) -> dict[str, Any] | None:
    """Latest SUCCESS scan's compliance blob, preferring an in-scope framework.

    Team dashboards previously always took the newest SUCCESS scan. A newer
    framework-only AI BOM (0 models) marks ``rbi_free_ai`` / ``cert_in_aibom``
    entirely out_of_scope and poisoned FREEAI-* / T10-* drilldowns even when an
    older scan on the same team had real model fails. Prefer the newest blob
    where any ``prefer_frameworks`` entry is in-scope; fall back to newest.
    """
    candidates = [
        s
        for s in scans
        if getattr(s, "scan_type", None) == scan_type
        and (getattr(s, "scan_status", "") or "").strip().upper() == "SUCCESS"
        and isinstance(getattr(s, "scan_data", None), dict)
        and s.scan_data.get(compliance_key)
    ]
    if not candidates:
        return None
    candidates.sort(
        key=lambda s: getattr(s, "created_at", None) or "", reverse=True
    )
    if prefer_frameworks:
        for s in candidates:
            blob = s.scan_data.get(compliance_key)
            if isinstance(blob, dict) and compliance_blob_in_scope(
                blob, prefer_frameworks
            ):
                return blob
    blob = candidates[0].scan_data.get(compliance_key)
    return blob if isinstance(blob, dict) else None


__all__ = [
    "compliance_blob_in_scope",
    "pick_latest_bom_compliance",
]
