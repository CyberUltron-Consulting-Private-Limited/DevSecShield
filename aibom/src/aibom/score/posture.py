"""The AI BOM posture score and its grade: one function and one table.

Standard library only, with no package imports, so the backend PDF reports load
this very file (``backend/utilities/pdf/aibom_posture.py`` imports it by path)
instead of keeping a copy of the table: the engine's ``risk_band`` (shown by the
dashboard) and the PDF's grade say the same word for the same score (review of
#487 m2).

score = min(100, 4 x (10 critical + 5 high + 2 medium + 1 low)), capped by the
worst severity present: no critical -> at most 69 (D), no critical or high -> at
most 49 (C), low only -> at most 14 (A), nothing -> 0 (A). Without the cap 32 low
and 10 medium inventory rows scored 100 / F "Critical risk" with zero critical or
high findings (audit-C G-D5-4). Low only was capped at 29 (B, "Moderate risk")
until staging QA round 2: every unflagged inventory item counts as Low, so a
repository with no finding at all read "29 / B Moderate risk" (SmarterRouter). A
posture whose worst severity is Low is graded Low risk (A).
"""

from __future__ import annotations

POSTURE_WEIGHTS = {"critical": 10, "high": 5, "medium": 2, "low": 1}
POSTURE_MULTIPLIER = 4
POSTURE_CAPS = (("critical", 100), ("high", 69), ("medium", 49), ("low", 14))
# (lowest score of the grade, grade, band word). The PDF prints "<Band> risk".
POSTURE_GRADES = (
    (70, "F", "critical"),
    (50, "D", "high"),
    (30, "C", "elevated"),
    (15, "B", "moderate"),
    (0, "A", "low"),
)


def posture_score(critical: int, high: int, medium: int, low: int) -> int:
    """0-100 risk score from severity counts, bounded by the worst severity."""
    counts = {"critical": critical, "high": high, "medium": medium, "low": low}
    weighted = sum(POSTURE_WEIGHTS[k] * max(0, int(n or 0)) for k, n in counts.items())
    score = min(100, weighted * POSTURE_MULTIPLIER)
    cap = next((c for sev, c in POSTURE_CAPS if int(counts[sev] or 0) > 0), 0)
    return min(score, cap)


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
    "POSTURE_GRADES",
    "POSTURE_MULTIPLIER",
    "POSTURE_WEIGHTS",
    "posture_grade",
    "posture_label",
    "posture_risk",
    "posture_score",
]
