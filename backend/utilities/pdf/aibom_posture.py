"""The AI BOM posture score and grade, from the engine's own module.

``aibom/src/aibom/score/posture.py`` holds the one formula, cap table and band words of the AI BOM risk score. It is
standard library only, so it is loaded here by file path (never imported as the ``aibom`` package, whose name a
repository folder may shadow): the engine's ``risk_band`` on the dashboard and the PDF grade say the same word for the
same score (review of #487 m2). The backend image carries the engine under ``/opt/aibom/src`` (backend/Dockerfile,
named build context ``aibom``); tests and local runs use the repository checkout.
"""
from __future__ import annotations

import importlib.util
import os
import threading
from pathlib import Path
from types import ModuleType
from typing import Any, Tuple

_LOCK = threading.Lock()
_MODULE: list[ModuleType] = []


def _candidates() -> list[Path]:
    roots = []
    if os.environ.get("CBOM_AIBOM_SRC"):
        roots.append(Path(os.environ["CBOM_AIBOM_SRC"]))
    roots.append(Path("/opt/aibom/src"))
    roots.append(Path(__file__).resolve().parents[3] / "aibom" / "src")
    return [r / "aibom" / "score" / "posture.py" for r in roots]


def engine_posture() -> ModuleType:
    """The engine's posture module, loaded once per process."""
    with _LOCK:
        if _MODULE:
            return _MODULE[0]
        for path in _candidates():
            if path.is_file():
                spec = importlib.util.spec_from_file_location("dss_aibom_posture", path)
                if spec is None or spec.loader is None:
                    continue
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                _MODULE.append(module)
                return module
        raise ImportError("aibom/src/aibom/score/posture.py not found (CBOM_AIBOM_SRC, /opt/aibom/src, repository)")


def posture_risk(critical: int, high: int, medium: int, low: int) -> Tuple[int, str, str]:
    """``(score, grade, label)``, e.g. ``(14, "A", "Low risk")`` for seven lows: the engine's function."""
    score, grade, label = engine_posture().posture_risk(critical, high, medium, low)
    return int(score), str(grade), str(label)


def current_scores(scores: Any) -> Any:
    """A stored AI BOM ``ai_bom_scores`` with its headline recomputed from its own ``severity_counts`` by the engine's
    posture function: a scan stored before a posture change shows on the page what the PDF and the API compute now
    (Rule P; review 6037909737 of #498, M5). Anything without four severity counts is returned unchanged."""
    if not isinstance(scores, dict):
        return scores
    counts = scores.get("severity_counts")
    keys = ("critical", "high", "medium", "low")
    if not isinstance(counts, dict) or not all(isinstance(counts.get(k), (int, float)) for k in keys):
        return scores
    module = engine_posture()
    score = module.posture_score(*(int(counts[k]) for k in keys))
    grade, band = module.posture_grade(score)
    return {**scores, "risk_normalized": float(score), "risk_grade": grade, "risk_band": band,
            "risk_label": module.posture_label(band)}


__all__ = ["current_scores", "engine_posture", "posture_risk"]
