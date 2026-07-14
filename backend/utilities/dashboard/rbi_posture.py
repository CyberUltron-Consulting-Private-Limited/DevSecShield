"""Aggregate RBI CSF pillar coverage from per-BOM compliance run-objects."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

_ADVISORY_DISCLAIMER = (
    "Advisory mapping only. BOM evidence supports but does not satisfy "
    "regulatory obligations. Organizational/process controls require attestation."
)

_PILLARS = (
    "governance",
    "identification",
    "protection",
    "detection",
    "response",
)


def _rollup_yaml_path() -> Path:
    repo_root = Path(__file__).resolve().parents[3]
    return repo_root / "aibom" / "config" / "rbi-csf-rollup.yaml"


def _rollup_config() -> dict[str, Any]:
    raw = _rollup_yaml_path().read_text(encoding="utf-8")
    return yaml.safe_load(raw)


def _req_to_pillar_map() -> dict[str, str]:
    cfg = _rollup_config()
    mapping: dict[str, str] = {}
    for pillar, ids in (cfg.get("pillars") or {}).items():
        for rid in ids:
            mapping[str(rid)] = str(pillar)
    for rid in cfg.get("innovation_as_governance") or []:
        mapping[str(rid)] = "governance"
    return mapping


def _iter_requirements(compliance_blob: dict[str, Any] | None) -> list[dict[str, Any]]:
    if not compliance_blob or not isinstance(compliance_blob, dict):
        return []
    out: list[dict[str, Any]] = []
    for key, fw in compliance_blob.items():
        if key == "disclaimer" or not isinstance(fw, dict):
            continue
        for req in fw.get("requirements") or []:
            if isinstance(req, dict) and req.get("id"):
                out.append({**req, "_framework": key})
    return out


def _rollup_pillar(reqs: list[dict[str, Any]], pillar: str, id_map: dict[str, str]) -> dict[str, Any]:
    matched = [r for r in reqs if id_map.get(str(r.get("id"))) == pillar]
    counts = {v: 0 for v in ("pass", "pass_with_evidence", "fail", "out_of_scope", "not_bom_evidenceable", "na")}
    sources: list[dict[str, str]] = []
    for r in matched:
        v = str(r.get("verdict") or "na")
        counts[v] = counts.get(v, 0) + 1
        sources.append(
            {
                "id": str(r.get("id")),
                "framework": str(r.get("_framework")),
                "verdict": v,
                "title": str(r.get("title") or ""),
            }
        )
    n_pass = counts["pass"] + counts["pass_with_evidence"]
    applicable = n_pass + counts["fail"]
    coverage = round(n_pass / applicable, 3) if applicable else None
    return {
        **counts,
        "coverage": coverage,
        "requirements": sources,
    }


def build_rbi_csf_rollup(
    *,
    ai_bom_compliance: dict[str, Any] | None = None,
    cbom_compliance: dict[str, Any] | None = None,
    sbom_compliance: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Merge compliance blobs from up to three BOM scans into RBI CSF pillar rollups."""
    id_map = _req_to_pillar_map()
    all_reqs: list[dict[str, Any]] = []
    for blob, scanner in (
        (ai_bom_compliance, "ai_bom"),
        (cbom_compliance, "cbom"),
        (sbom_compliance, "sbom"),
    ):
        for req in _iter_requirements(blob):
            req = dict(req)
            req["_scanner"] = scanner
            all_reqs.append(req)

    rollup = {p: _rollup_pillar(all_reqs, p, id_map) for p in _PILLARS}
    return {
        "rbi_csf_rollup": rollup,
        "disclaimer": _ADVISORY_DISCLAIMER,
    }


def build_team_rbi_posture_from_scans(scans: list[Any]) -> dict[str, Any] | None:
    """Merge RBI CSF rollup from the latest successful BOM scan of each type on a team."""
    latest: dict[str, dict[str, Any]] = {}
    for scan_type, compliance_key in (
        ("ai_bom", "ai_bom_compliance"),
        ("cbom", "cbom_compliance"),
        ("sbom_sca", "sbom_compliance"),
    ):
        candidates = [
            s
            for s in scans
            if getattr(s, "scan_type", None) == scan_type
            and (getattr(s, "scan_status", "") or "").strip().upper() == "SUCCESS"
            and isinstance(getattr(s, "scan_data", None), dict)
            and s.scan_data.get(compliance_key)
        ]
        if not candidates:
            continue
        candidates.sort(key=lambda s: getattr(s, "created_at", None) or "", reverse=True)
        latest[compliance_key] = candidates[0].scan_data[compliance_key]

    if not latest:
        return None

    return build_rbi_csf_rollup(
        ai_bom_compliance=latest.get("ai_bom_compliance"),
        cbom_compliance=latest.get("cbom_compliance"),
        sbom_compliance=latest.get("sbom_compliance"),
    )


__all__ = ["build_rbi_csf_rollup", "build_team_rbi_posture_from_scans"]
