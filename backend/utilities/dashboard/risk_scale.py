"""The app's one risk-score scale, 0 to 10 (#35).

A finding scores by its impact: Critical 10, High 7.5, Medium 5, Low 2.5 (an unknown impact counts as Low), the values
every dashboard already used (``scan.risk_score_for_impact``, ``scan_list.DAST_RISK_SCORE_FOR_IMPACT``,
``cicd.RISK_SCORE_FOR_IMPACT``). A scan's score is the mean of its findings' scores rounded to one decimal, like the
dashboards' cards. The bands are the Risk score filter tiers of the list and results pages: Critical 9 or more,
High 7 to 9, Medium 5 to 7, Low under 5.

The SCA + SBOM, IaC, MCP and DAST scan lists, the IaC, MCP and DAST results APIs and the SBOM PDF read this module, so
a table, its filter, its dashboard and its export agree. Scores are computed when read: stored scans need no migration.

A scan's headline is one 0-100 risk score with a grade and words (``posture``): the engine's posture function
(``aibom/src/aibom/score/posture.py``, loaded by ``backend.utilities.pdf.aibom_posture``), the score the AI BOM and the
D3 code scans already show: ``min(100, 4 x (10 critical + 5 high + 2 medium + 1 low))`` capped by the worst severity,
graded A (< 15, "Low risk"), B (15-29, "Moderate risk"), C (30-49, "Elevated risk"), D (50-69, "High risk") and F
(70 or more, "Critical risk"). Every product's list, tiles, filter and PDF read it from here (one place, like
Snyk's, Black Duck's and Dependency-Track's single per-project score); the frontend's twin is
``frontend/utils/riskPosture.ts``. The 0-10 average above stays on the API (``average_risk_score``) for older clients.
"""
from __future__ import annotations

from typing import Any, Iterable, Mapping

IMPACT_RISK: dict[str, float] = {"critical": 10.0, "high": 7.5, "medium": 5.0, "low": 2.5}
RISK_BANDS: tuple[tuple[str, float], ...] = (("critical", 9.0), ("high", 7.0), ("medium", 5.0), ("low", 0.0))


def impact_risk(impact: Any) -> float:
    """One finding's score for its impact; Low for a missing or unknown impact."""
    return IMPACT_RISK.get(str(impact or "").strip().lower(), IMPACT_RISK["low"])


def average_risk(impact_counts: Mapping[str, int]) -> float | None:
    """The mean score of a scan's findings counted per impact, one decimal; None without findings."""
    total = sum(n for n in impact_counts.values() if n > 0)
    if total <= 0:
        return None
    weighted = sum(impact_risk(impact) * n for impact, n in impact_counts.items() if n > 0)
    return round(min(10.0, max(0.0, weighted / total)), 1)


def average_risk_of(impacts: Iterable[Any]) -> float | None:
    """The mean score of these findings' impacts, one decimal; None without findings."""
    counts: dict[str, int] = {}
    for impact in impacts:
        key = str(impact or "").strip().lower()
        counts[key] = counts.get(key, 0) + 1
    return average_risk(counts)


def risk_band(score: float | None) -> str | None:
    """The Risk score filter tier a score falls in; None for no score."""
    if score is None:
        return None
    return next(band for band, floor in RISK_BANDS if score >= floor or band == "low")


# The keys a product puts on its list rows, tiles and per-scan dashboard: one object, so no older field changes meaning
# (the SAST list's ``risk_score`` and the LLM card's ``risk_score`` keep their old values).
POSTURE_KEY = "risk_posture"
SEVERITIES = ("critical", "high", "medium", "low")


def _severity_counts(impact_counts: Mapping[str, int]) -> dict[str, int]:
    """Counts per severity, keys in any case ("Critical" or "critical"). An impact outside the four severities is not
    counted: the list rows, the dashboards' severity counts and the PDF headline never counted one, so the score is the
    same number on each of them."""
    counts = dict.fromkeys(SEVERITIES, 0)
    for impact, n in (impact_counts or {}).items():
        key = str(impact or "").strip().lower()
        if key in counts:
            counts[key] += max(0, int(n or 0))
    return counts


def posture(impact_counts: Mapping[str, int]) -> dict[str, Any]:
    """The one 0-100 risk score of these findings counted per impact: ``{"score", "grade", "label", "band"}``, e.g.
    ``{"score": 29, "grade": "B", "label": "Moderate risk", "band": "moderate"}`` for seven Lows; 0 / A without
    findings."""
    from backend.utilities.pdf.aibom_posture import engine_posture

    engine = engine_posture()
    c = _severity_counts(impact_counts)
    score = int(engine.posture_score(c["critical"], c["high"], c["medium"], c["low"]))
    grade, band = engine.posture_grade(score)
    return {"score": score, "grade": str(grade), "label": str(engine.posture_label(band)), "band": str(band)}


def posture_of(impacts: Iterable[Any]) -> dict[str, Any]:
    """``posture`` of these findings' impacts."""
    counts: dict[str, int] = {}
    for impact in impacts:
        key = str(impact or "").strip().lower()
        counts[key] = counts.get(key, 0) + 1
    return posture(counts)


def posture_field(impact_counts: Mapping[str, int], *, judged: bool = True) -> dict[str, Any]:
    """``{"risk_posture": posture(...)}`` to spread into a list row or a card; ``None`` when the scan has no result to
    judge (pending, running, failed): such a row shows "—", never "0 · A"."""
    return {POSTURE_KEY: posture(impact_counts) if judged else None}


__all__ = ["IMPACT_RISK", "POSTURE_KEY", "RISK_BANDS", "SEVERITIES", "average_risk", "average_risk_of", "impact_risk",
           "posture", "posture_field", "posture_of", "risk_band"]
