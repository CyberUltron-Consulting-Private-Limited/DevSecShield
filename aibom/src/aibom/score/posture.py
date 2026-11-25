"""The AI BOM posture score and its grade: one function and one table.

Standard library only, with no package imports, so the backend PDF reports load
this very file (``backend/utilities/pdf/aibom_posture.py`` imports it by path)
instead of keeping a copy of the table: the engine's ``risk_band`` (shown by the
dashboard) and the PDF's grade say the same word for the same score (review of
#487 m2).

score = min(100, 4 x (10 critical + 5 high + 2 medium + 1 low)), capped by the
worst severity present: no critical -> at most 69 (D), no critical or high -> at
most 49 (C), low only -> at most 29 (B), nothing -> 0 (A). Without the cap 32 low
and 10 medium inventory rows scored 100 / F "Critical risk" with zero critical or
high findings (audit-C G-D5-4).

Severity floor (review 6064315680 of #505, the worst-severity rating SonarQube
uses): any critical -> at least 70 (F, "Critical risk"); any high -> at least 50
(D, "High risk"). One Critical scored 40 / C and fell into the "Medium" filter
before. Medium and low are unchanged. The cap is still the ceiling, so a score
with a high and no critical stays within 50-69 (D).
"""

from __future__ import annotations

POSTURE_WEIGHTS = {"critical": 10, "high": 5, "medium": 2, "low": 1}
POSTURE_MULTIPLIER = 4
POSTURE_CAPS = (("critical", 100), ("high", 69), ("medium", 49), ("low", 29))
# the lowest score of the worst severity present (none for medium and low)
POSTURE_FLOORS = (("critical", 70), ("high", 50))
# (lowest score of the grade, grade, band word). The PDF prints "<Band> risk".
POSTURE_GRADES = (
    (70, "F", "critical"),
    (50, "D", "high"),
    (30, "C", "elevated"),
    (15, "B", "moderate"),
    (0, "A", "low"),
)


def posture_score(critical: int, high: int, medium: int, low: int) -> int:
    """0-100 risk score from severity counts, bounded by the worst severity: at
    most its cap, at least its floor."""
    counts = {"critical": critical, "high": high, "medium": medium, "low": low}
    score = min(100, posture_weighted(critical, high, medium, low) * POSTURE_MULTIPLIER)
    cap = next((c for sev, c in POSTURE_CAPS if int(counts[sev] or 0) > 0), 0)
    worst = next((sev for sev, _ in POSTURE_CAPS if int(counts[sev] or 0) > 0), None)
    floor = dict(POSTURE_FLOORS).get(worst or "", 0)
    return max(min(score, cap), floor)


def posture_weighted(critical: int, high: int, medium: int, low: int) -> int:
    """The uncapped weighted sum (10 critical + 5 high + 2 medium + 1 low): the
    lists' second sort key, so four highs and a thousand (both 69 / D) still
    sort apart."""
    counts = {"critical": critical, "high": high, "medium": medium, "low": low}
    return sum(POSTURE_WEIGHTS[k] * max(0, int(n or 0)) for k, n in counts.items())


def posture_grade(score: float) -> tuple[str, str]:
    """``(grade, band)`` of a 0-100 score: ``("B", "moderate")`` for 29."""
    return next(
        (g, band) for floor, g, band in POSTURE_GRADES if score >= floor or floor == 0
    )


def posture_label(band: str) -> str:
    """The words a report prints for a band: ``"Moderate risk"``."""
    return f"{band.capitalize()} risk"


def posture_risk(
    critical: int, high: int, medium: int, low: int
) -> tuple[int, str, str]:
    """``(score, grade, label)`` from severity counts: ``(29, "B", "Moderate risk")``
    for seven lows."""
    score = posture_score(critical, high, medium, low)
    grade, band = posture_grade(score)
    return score, grade, posture_label(band)


__all__ = [
    "POSTURE_CAPS",
    "POSTURE_FLOORS",
    "POSTURE_GRADES",
    "POSTURE_MULTIPLIER",
    "POSTURE_WEIGHTS",
    "posture_grade",
    "posture_label",
    "posture_risk",
    "posture_score",
    "posture_weighted",
]
