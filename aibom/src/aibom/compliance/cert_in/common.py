"""CERT-In ledger loaders + Requirement builders (no register_check).

Phase 0 ships the machine ledger and helpers only. Framework runners stay
unwired until Phase 1+ so existing `*_compliance` shapes are unchanged.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from aibom.compliance.base import Requirement

__all__ = [
    "CERTIN_DISCLAIMER",
    "FRAMEWORK_LABELS",
    "load_ledger",
    "requirement_ids",
    "requirements_for",
]

_PACKAGE_DIR = Path(__file__).resolve().parent
_LEDGER_NAME = "ledger.yaml"


def _resolve_ledger_path() -> Path:
    """Prefer the co-located package file; fall back to source-tree layout."""
    packaged = _PACKAGE_DIR / _LEDGER_NAME
    if packaged.is_file():
        return packaged
    # src/aibom/compliance/cert_in -> parents[3] = aibom/
    return _PACKAGE_DIR.parents[3] / "src" / "aibom" / "compliance" / "cert_in" / _LEDGER_NAME


@lru_cache(maxsize=1)
def load_ledger() -> dict[str, Any]:
    """Load and return the CERT-In machine ledger (cached)."""
    path = _resolve_ledger_path()
    with path.open(encoding="utf-8") as fh:
        doc = yaml.safe_load(fh)
    if not isinstance(doc, dict) or "requirements" not in doc:
        raise ValueError(f"invalid CERT-In ledger at {path}")
    return doc


def _guideline_disclaimer(doc: dict[str, Any]) -> str:
    g = doc.get("guideline") or {}
    return str(g.get("disclaimer") or "").strip()


# Module constants resolved at import from the ledger (fail loud if missing).
_LEDGER = load_ledger()
CERTIN_DISCLAIMER: str = _guideline_disclaimer(_LEDGER)
if not CERTIN_DISCLAIMER:
    raise RuntimeError("CERT-In ledger missing guideline.disclaimer")

FRAMEWORK_LABELS: dict[str, str] = {
    key: str(meta.get("label") or key)
    for key, meta in (_LEDGER.get("frameworks") or {}).items()
}


def requirement_ids() -> frozenset[str]:
    """All requirement IDs in the machine ledger."""
    return frozenset(str(r["id"]) for r in load_ledger()["requirements"])


def _framework_for_lane(lane: str) -> str | None:
    for key, meta in (load_ledger().get("frameworks") or {}).items():
        if meta.get("lane") == lane:
            return str(key)
    return None


def requirements_for(
    lane_or_framework: str,
    *,
    include_process: bool = True,
) -> list[Requirement]:
    """Build ``Requirement`` objects for a CERT-In lane or framework key.

    Does **not** call ``register_check`` / ``register_manual``.
    Process-lane manuals (`lane=process`) are included when
    ``include_process`` is True and the caller asked for a BOM lane
    (cbom/aibom/sbom) or the matching ``cert_in_*`` framework.
    """
    doc = load_ledger()
    key = lane_or_framework
    frameworks = doc.get("frameworks") or {}
    if key in frameworks:
        lane = str(frameworks[key].get("lane") or "")
        framework = key
    else:
        lane = key
        framework = _framework_for_lane(lane) or f"cert_in_{lane}"

    out: list[Requirement] = []
    for raw in doc["requirements"]:
        rlane = str(raw.get("lane") or "")
        if rlane == lane or (include_process and rlane == "process" and lane in {"cbom", "aibom", "sbom"}):
            # Process manuals are shared across BOM lanes in the PDF; Phase 0
            # surfaces them under each framework so later registration can bind.
            if rlane == "process":
                # Bind process IDs only to the framework whose numeric prefix matches.
                rid = str(raw["id"])
                if lane == "sbom" and not rid.startswith("7.1."):
                    continue
                if lane == "cbom" and not rid.startswith("8.4.1."):
                    continue
                if lane == "aibom" and not rid.startswith("9.4.1."):
                    continue
            out.append(
                Requirement(
                    id=str(raw["id"]),
                    framework=framework,
                    title=str(raw.get("title") or raw["id"]),
                    source=str(raw.get("pdf") or "CERT-In TG v2.0"),
                )
            )
    return out
