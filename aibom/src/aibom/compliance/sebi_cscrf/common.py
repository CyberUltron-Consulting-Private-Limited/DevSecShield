"""Shared SEBI CSCRF ledger helpers (no register_check side effects)."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from aibom.compliance.base import Requirement

_LEDGER_PATH = Path(__file__).with_name("ledger.yaml")

__all__ = [
    "SEBI_DISCLAIMER",
    "FRAMEWORK_LABELS",
    "load_ledger",
    "requirement_ids",
    "requirements_for",
    "auto_ids_for",
    "manual_ids_for",
]


@lru_cache(maxsize=1)
def load_ledger() -> dict[str, Any]:
    with _LEDGER_PATH.open(encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    if not isinstance(data, dict) or "requirements" not in data:
        raise ValueError("sebi_cscrf ledger.yaml must be a mapping with requirements")
    return data


def _guideline_disclaimer(doc: dict[str, Any]) -> str:
    g = doc.get("guideline") or {}
    return str(g.get("disclaimer") or "").strip()


_LEDGER = load_ledger()
SEBI_DISCLAIMER: str = _guideline_disclaimer(_LEDGER)
if not SEBI_DISCLAIMER:
    raise RuntimeError("SEBI CSCRF ledger missing guideline.disclaimer")

FRAMEWORK_LABELS: dict[str, str] = {
    key: str(meta.get("label") or key)
    for key, meta in (_LEDGER.get("frameworks") or {}).items()
}


def requirement_ids() -> frozenset[str]:
    return frozenset(str(r["id"]) for r in load_ledger()["requirements"])


def _framework_for_lane(lane: str) -> str | None:
    for key, meta in (load_ledger().get("frameworks") or {}).items():
        if meta.get("lane") == lane:
            return str(key)
    return None


def requirements_for(lane_or_framework: str) -> list[Requirement]:
    """Return Requirement records for a lane (cbom|aibom|sbom) or framework key."""
    doc = load_ledger()
    frameworks = doc.get("frameworks") or {}
    if lane_or_framework in frameworks:
        fw_key: str = lane_or_framework
        lane = str(frameworks[fw_key].get("lane") or "")
    else:
        lane = lane_or_framework
        resolved = _framework_for_lane(lane)
        if not resolved:
            return []
        fw_key = resolved

    out: list[Requirement] = []
    for row in doc.get("requirements") or []:
        if row.get("lane") != lane:
            continue
        out.append(
            Requirement(
                id=str(row["id"]),
                framework=fw_key,
                title=str(row["title"]),
                source=str(row.get("pdf") or row["title"]),
            )
        )
    return out


def auto_ids_for(lane: str) -> frozenset[str]:
    return frozenset(
        str(row["id"])
        for row in (load_ledger().get("requirements") or [])
        if row.get("lane") == lane and row.get("mode") == "auto"
    )


def manual_ids_for(lane: str) -> frozenset[str]:
    return frozenset(
        str(row["id"])
        for row in (load_ledger().get("requirements") or [])
        if row.get("lane") == lane and row.get("mode") == "manual"
    )
