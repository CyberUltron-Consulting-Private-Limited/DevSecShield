"""The app's one risk-score scale, 0 to 10 (#35).

A finding scores by its impact: Critical 10, High 7.5, Medium 5, Low 2.5 (an unknown impact counts as Low), the values
every dashboard already used (``scan.risk_score_for_impact``, ``scan_list.DAST_RISK_SCORE_FOR_IMPACT``,
``cicd.RISK_SCORE_FOR_IMPACT``). A scan's score is the mean of its findings' scores rounded to one decimal, like the
dashboards' cards. The bands are the Risk score filter tiers of the list and results pages: Critical 9 or more,
High 7 to 9, Medium 5 to 7, Low under 5.

The SCA + SBOM, IaC, MCP and DAST scan lists, the IaC, MCP and DAST results APIs and the SBOM PDF read this module, so
a table, its filter, its dashboard and its export agree. Scores are computed when read: stored scans need no migration.
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


__all__ = ["IMPACT_RISK", "RISK_BANDS", "average_risk", "average_risk_of", "impact_risk", "risk_band"]
