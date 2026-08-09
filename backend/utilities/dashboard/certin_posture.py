"""Aggregate CERT-In TG v2.0 requirement coverage into advisory posture dimensions.

Peer of ``rbi_posture.py``. Live-recomputed from compliance blobs at metadata /
team-dashboard read time — never a scan-write-only snapshot (attestation must
refresh posture on the next GET).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

# Product-facing copy omits "QBOM" (F10: docs/PDF citation only; zero product UI QBOM).
_ADVISORY_DISCLAIMER = (
    "Advisory mapping to CERT-In Technical Guidelines v2.0 (SBOM / CBOM / AIBOM; "
    "09.07.2025). Does not constitute CERT-In certification or regulatory "
    "approval. Process controls require attestation."
)

_HBOM_NOTE = "HBOM deferred — not in product scope."

# Lane → posture dimensions. Per-scan metadata only emits dims for lanes whose
# compliance blob was provided; the team dashboard merges multiple lanes.
_LANE_DIMENSIONS: dict[str, tuple[str, ...]] = {
    "sbom": ("sbom_minimum_elements", "sbom_recommendations"),
    "cbom": ("cbom_crypto_assets", "cbom_recommendations"),
    "aibom": ("aibom_ai_assets", "aibom_recommendations"),
}

_DIMENSIONS = tuple(d for dims in _LANE_DIMENSIONS.values() for d in dims)


def _rollup_yaml_path() -> Path:
    repo_root = Path(__file__).resolve().parents[3]
    return repo_root / "aibom" / "config" / "cert-in-rollup.yaml"


def _ledger_yaml_path() -> Path:
    repo_root = Path(__file__).resolve().parents[3]
    return (
        repo_root
        / "aibom"
        / "src"
        / "aibom"
        / "compliance"
        / "cert_in"
        / "ledger.yaml"
    )


def _rollup_config() -> dict[str, Any]:
    raw = _rollup_yaml_path().read_text(encoding="utf-8")
    return yaml.safe_load(raw) or {}


_LEDGER_META_CACHE: dict[str, dict[str, str]] | None = None


def _ledger_requirement_meta() -> dict[str, dict[str, str]]:
    """id → {title, description} from CERT-In ledger (read-time overlay)."""
    global _LEDGER_META_CACHE
    if _LEDGER_META_CACHE is not None:
        return _LEDGER_META_CACHE
    path = _ledger_yaml_path()
    meta: dict[str, dict[str, str]] = {}
    if path.is_file():
        doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        for raw in doc.get("requirements") or []:
            if not isinstance(raw, dict) or not raw.get("id"):
                continue
            rid = str(raw["id"])
            meta[rid] = {
                "title": str(raw.get("title") or ""),
                "description": str(raw.get("description") or ""),
            }
    _LEDGER_META_CACHE = meta
    return meta


def _req_to_dimension_map() -> dict[str, set[str]]:
    """requirement id -> SET of dimensions (set-valued; avoids last-write-wins)."""
    cfg = _rollup_config()
    mapping: dict[str, set[str]] = {}
    for dim, ids in (cfg.get("dimensions") or {}).items():
        for rid in ids or []:
            mapping.setdefault(str(rid), set()).add(str(dim))
    return mapping


def _iter_requirements(compliance_blob: dict[str, Any] | None) -> list[dict[str, Any]]:
    if not compliance_blob or not isinstance(compliance_blob, dict):
        return []
    out: list[dict[str, Any]] = []
    for key, fw in compliance_blob.items():
        if key == "disclaimer" or not isinstance(fw, dict):
            continue
        # CERT-In rollup only reads cert_in_* frameworks (ignore RBI/NIST peers).
        if not str(key).startswith("cert_in_"):
            continue
        for req in fw.get("requirements") or []:
            if isinstance(req, dict) and req.get("id"):
                out.append({**req, "_framework": key})
    return out


def _resolve_hint(verdict: str, *, refs: list[str], attestable: bool) -> str:
    """Actionable how-to-resolve copy for posture drilldown rows."""
    v = (verdict or "").lower()
    if v == "pass" or v == "pass_with_evidence":
        return "No action required"
    if v == "out_of_scope" or v == "na":
        return "Not applicable to this scan"
    if v == "fail":
        return "Fix related assets / findings"
    if v == "not_bom_evidenceable":
        if attestable and not refs:
            return "Upload process attestation to satisfy this control"
        if refs:
            return "Review related assets / findings"
        return "Upload process attestation to satisfy this control"
    return "Review this requirement"


def _rollup_dimension(
    reqs: list[dict[str, Any]], dimension: str, id_map: dict[str, set[str]]
) -> dict[str, Any]:
    matched = [r for r in reqs if dimension in id_map.get(str(r.get("id")), ())]
    counts = {
        v: 0
        for v in (
            "pass",
            "pass_with_evidence",
            "fail",
            "out_of_scope",
            "not_bom_evidenceable",
            "na",
        )
    }
    ledger = _ledger_requirement_meta()
    sources: list[dict[str, Any]] = []
    for r in matched:
        v = str(r.get("verdict") or "na")
        counts[v] = counts.get(v, 0) + 1
        raw_refs = r.get("refs") or []
        refs: list[str] = []
        if isinstance(raw_refs, list):
            refs = [str(x) for x in raw_refs if x is not None][:50]
        attestable = bool(r.get("attestable"))
        if v == "not_bom_evidenceable" and not refs:
            # Process manuals are always attestable even if the field was omitted.
            attestable = True
        rid = str(r.get("id"))
        overlay = ledger.get(rid) or {}
        stored_title = str(r.get("title") or "")
        title = str(overlay.get("title") or stored_title)
        evidence = str(r.get("evidence") or "")
        desc = str(overlay.get("description") or "")
        # Prefer ledger description so legacy scans still show why/how in drilldown.
        if desc and desc not in evidence:
            evidence = f"{desc} ({evidence})" if evidence else desc
        sources.append(
            {
                "id": rid,
                "framework": str(r.get("_framework")),
                "verdict": v,
                "title": title,
                "source": str(r.get("source") or ""),
                "evidence": evidence,
                "refs": refs,
                "attestable": attestable,
                "resolve_hint": _resolve_hint(v, refs=refs, attestable=attestable),
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


def build_certin_posture(
    *,
    ai_bom_compliance: dict[str, Any] | None = None,
    cbom_compliance: dict[str, Any] | None = None,
    sbom_compliance: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    """Merge compliance blobs into CERT-In posture dimensions.

    Only emits dimensions for lanes whose compliance kwargs were provided
    (SBOM scan → ``sbom_*`` only; team merge with three blobs → all lanes).

    Returns ``None`` when no ``cert_in_*`` requirements are present in any blob
    (honest empty — FE should not render an all-zero chart).
    """
    id_map = _req_to_dimension_map()
    all_reqs: list[dict[str, Any]] = []
    active_dims: list[str] = []
    for blob, scanner, lane in (
        (ai_bom_compliance, "ai_bom", "aibom"),
        (cbom_compliance, "cbom", "cbom"),
        (sbom_compliance, "sbom", "sbom"),
    ):
        if blob is None:
            continue
        active_dims.extend(_LANE_DIMENSIONS[lane])
        for req in _iter_requirements(blob):
            req = dict(req)
            req["_scanner"] = scanner
            all_reqs.append(req)

    if not all_reqs:
        return None

    rollup = {d: _rollup_dimension(all_reqs, d, id_map) for d in active_dims}
    return {
        "certin_posture": rollup,
        "disclaimer": _ADVISORY_DISCLAIMER,
        "hbom_note": _HBOM_NOTE,
    }


def build_team_certin_posture_from_scans(scans: list[Any]) -> dict[str, Any] | None:
    """Merge CERT-In posture from the latest successful BOM scan of each type."""
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

    return build_certin_posture(
        ai_bom_compliance=latest.get("ai_bom_compliance"),
        cbom_compliance=latest.get("cbom_compliance"),
        sbom_compliance=latest.get("sbom_compliance"),
    )


__all__ = [
    "build_certin_posture",
    "build_team_certin_posture_from_scans",
]
