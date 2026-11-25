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
    args = (c["critical"], c["high"], c["medium"], c["low"])
    score = int(engine.posture_score(*args))
    grade, band = engine.posture_grade(score)
    # ``weighted``: the uncapped 10C + 5H + 2M + 1L, the lists' second sort key (4 Highs and 1000 are both 69 / D)
    return {"score": score, "grade": str(grade), "label": str(engine.posture_label(band)), "band": str(band),
            "weighted": int(engine.posture_weighted(*args))}


def posture_of(impacts: Iterable[Any]) -> dict[str, Any]:
    """``posture`` of these findings' impacts."""
    counts: dict[str, int] = {}
    for impact in impacts:
        key = str(impact or "").strip().lower()
        counts[key] = counts.get(key, 0) + 1
    return posture(counts)


STATUS_KEY = "risk_posture_status"
# "scored": the scan completed and the score stands (0 / A only for a completed scan with no finding); "unverified":
# an SBOM whose only vulnerabilities are matches on versions guessed from a range: the worst-case score over them,
# marked unverified, so the scan still meets the filter tier it could be in (review 6064315680 of #505, finding 5);
# "incomplete": it finished but did not cover what a score needs (an SBOM with no package inventoried), shown
# "incomplete", never A; "not_scored": pending, running, failed or cancelled, shown "—".
STATUSES = ("scored", "unverified", "incomplete", "not_scored")
UNVERIFIED_KEY = "risk_unverified"


def posture_field(impact_counts: Mapping[str, int], *, judged: bool = True, incomplete: bool = False,
                  unverified: Mapping[str, int] | None = None,
                  confirmed: Mapping[str, int] | None = None) -> dict[str, Any]:
    """``{"risk_posture": posture(...), "risk_posture_status": "scored"}`` to spread into a list row or a card. No
    score (``None``) when the scan has no result to judge (``judged=False``: pending, running, failed) or its result is
    incomplete: such a row shows "—" or "incomplete", never "0 · A".

    ``unverified``: an SBOM's matches on guessed versions per severity, never in the confirmed score. They add
    ``risk_unverified`` = ``{"count", "worst", "worst_case"}`` (the note "unverified: N guessed-version matches (worst:
    Critical)"; ``worst_case``: the posture of the confirmed and the guessed findings together, which the lists' risk
    filter and sort read, so 1 confirmed Low + 10 guessed Criticals is shown 4 · A and also found under "Critical";
    review 6065663183 of #505, 6). When they are the only vulnerabilities, the score is their worst case, status
    "unverified". ``confirmed``: the confirmed counts when ``impact_counts`` is not (the SBOM tile, whose
    ``impact_counts`` already hold an unverified target's worst case)."""
    if not judged:
        return {POSTURE_KEY: None, STATUS_KEY: "not_scored"}
    if incomplete:
        return {POSTURE_KEY: None, STATUS_KEY: "incomplete"}
    out: dict[str, Any] = {POSTURE_KEY: posture(impact_counts), STATUS_KEY: "scored"}
    if unverified is not None:
        guessed = _severity_counts(unverified)
        sure = _severity_counts(impact_counts if confirmed is None else confirmed)
        n = sum(guessed.values())
        worst = next((sev for sev in SEVERITIES if guessed[sev] > 0), None)
        out[UNVERIFIED_KEY] = {"count": n, "worst": worst,
                               "worst_case": posture({k: sure[k] + guessed[k] for k in SEVERITIES})} if n else None
        if n and not sum(_severity_counts(impact_counts).values()):
            out = {**out, POSTURE_KEY: posture(guessed), STATUS_KEY: "unverified"}
    return out


def ai_bom_scores_now(scores: Any, rows: Any = None) -> Any:
    """A stored AI BOM ``ai_bom_scores`` with its headline (``risk_normalized``, ``risk_band``, ``risk_grade``,
    ``risk_label``: the page's "Risk by Component · Normalized risk N/100 · BAND") recomputed by the engine's posture
    function at read time, like the results card and the PDF: a scan stored before the floor reads 70 · F for one
    Critical, not the 40 / ELEVATED it was saved with (review 6065663183 of #505, 3). The counts are the stored
    ``severity_counts`` (what the engine scored), else the scan's rows by impact (what the headline and PDF count).
    The per-component weights (``by_component``) are not a 0-100 score and stay as stored. Not a dict: unchanged."""
    if not isinstance(scores, Mapping):
        return scores
    stored = scores.get("severity_counts")
    if isinstance(stored, Mapping) and all(isinstance(stored.get(k), (int, float)) for k in SEVERITIES):
        counts = {k: int(stored[k]) for k in SEVERITIES}
    else:
        counts = dict.fromkeys(SEVERITIES, 0)
        for row in rows if isinstance(rows, list) else []:
            key = str((row or {}).get("impact") or "").strip().lower() if isinstance(row, Mapping) else ""
            if key in counts:
                counts[key] += 1
    p = posture(counts)
    return {**scores, "risk_normalized": float(p["score"]), "risk_band": p["band"], "risk_grade": p["grade"],
            "risk_label": p["label"], "severity_counts": counts}


def unverified_note(unverified: Mapping[str, Any] | None) -> str | None:
    """"unverified: 10 guessed-version matches (worst: Critical)"; None without any."""
    if not unverified or not unverified.get("count"):
        return None
    n = int(unverified["count"])
    worst = str(unverified.get("worst") or "").capitalize()
    return f"unverified: {n} guessed-version match{'es' if n != 1 else ''}" + (f" (worst: {worst})" if worst else "")


def gate_dashboard(scan_type: str, dashboard: Any, scan_status: Any) -> Any:
    """A results page's dashboard for a scan that did not succeed carries no score (review 6064315680 of #505, 4):
    ``risk_posture`` null and ``not_scored`` on its card (and at the top, where SAST and IaC keep it), and the CBOM
    card's flat ``risk_score`` / ``risk_grade`` / ``risk_label`` (#500) nulled. A successful scan's is unchanged."""
    if str(scan_status or "").lower() == "success" or not isinstance(dashboard, Mapping):
        return dashboard
    nothing = {POSTURE_KEY: None, STATUS_KEY: "not_scored"}
    out = dict(dashboard)
    if POSTURE_KEY in out:
        out.update(nothing)
    card = out.get("card_data")
    if isinstance(card, Mapping):
        card = {**card, **nothing}
        if scan_type == "cbom":
            card.update({"risk_score": None, "risk_grade": None, "risk_label": None})
        out["card_data"] = card
    return out


__all__ = ["ai_bom_scores_now", "IMPACT_RISK", "POSTURE_KEY", "RISK_BANDS", "SEVERITIES", "STATUSES", "STATUS_KEY", "UNVERIFIED_KEY", "gate_dashboard", "unverified_note", "average_risk", "average_risk_of", "impact_risk",
           "posture", "posture_field", "posture_of", "risk_band"]
