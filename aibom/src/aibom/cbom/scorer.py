"""CBOM scorer (C8): ``ScanResult.flags`` (crypto) -> ``ScanResult.scores``.

A thin peer of :mod:`aibom.score.scorer` for the crypto lane. It adds no scoring
machinery of its own — it delegates to the AIBOM :func:`score_result` with a
SEPARATE weights file (``config/crypto-risk-weights.yaml``) so the stacking,
per-component severity bands, and 0-100 normalization are shared, while the
crypto flag weights (weak crypto -> high, quantum-vulnerable -> medium, expired
certificate -> high) live in their own config. Lane discipline is intact: the
CBOM scanners EMIT flags (C5/C6/C8 expired-cert); this module only WEIGHTS them.

Wired into :func:`aibom.cbom.pipeline.scan_crypto` after inventory + compliance,
so a CBOM ``ScanResult`` carries ``scores`` exactly like an AIBOM one.
"""

from __future__ import annotations

from importlib import resources
from pathlib import Path
from typing import Any

from aibom.model.result import ScanResult
from aibom.score.posture import posture_grade, posture_label, posture_score
from aibom.score.scorer import score_result


def _resolve_cbom_weights_path() -> Path:
    """Locate config/crypto-risk-weights.yaml in both wheel and source layouts.

    Mirrors :func:`aibom.score.scorer._resolve_default_weights_path`: an installed
    wheel force-includes ``config`` at ``aibom/config`` (see pyproject), reachable
    via importlib.resources; in the source tree config/ lives at the repo root
    (``src/aibom/cbom/scorer.py -> parents[3]/config``).
    """
    try:
        packaged = resources.files("aibom") / "config" / "crypto-risk-weights.yaml"
        if Path(str(packaged)).is_file():
            return Path(str(packaged))
    except (ModuleNotFoundError, FileNotFoundError, TypeError):
        pass
    return Path(__file__).resolve().parents[3] / "config" / "crypto-risk-weights.yaml"


_CBOM_WEIGHTS_PATH = _resolve_cbom_weights_path()


def score_crypto(result: ScanResult) -> ScanResult:
    """Compute ``result.scores`` from the crypto flags (in place) and return it.

    Uses the CBOM weights file so weak crypto bands to high, quantum-vulnerable
    to medium, and per-asset flags stack (RSA-1024 weak + quantum-vulnerable ->
    high). Identical ``scores`` shape as the AIBOM scorer: ``risk_total`` /
    ``risk_normalized`` / ``risk_band`` / ``by_flag`` / ``by_component`` /
    ``component_severity`` / ``flag_count``.
    """
    # the CBOM keeps its own flag-weight scale: the AI BOM posture score (#487) does
    # not change CBOM scores. Findings in test, fixture or example code are listed but
    # weigh nothing (PR #500 review 6061095673): their components' flags are left out
    # of every sum, and their stacked severity is low.
    from aibom.cbom.code_context import is_unscored

    # test code and unconfirmed settings (review 6063599094) are listed, never scored
    test_refs = {
        c.bom_ref for c in result.components if is_unscored(c.properties or {})
    }
    if not test_refs:
        return score_result(result, str(_CBOM_WEIGHTS_PATH), posture=False)
    flags = result.flags
    result.flags = [f for f in flags if f.target not in test_refs]
    try:
        score_result(result, str(_CBOM_WEIGHTS_PATH), posture=False)
    finally:
        result.flags = flags
    result.scores["flag_count"] = len(flags)
    severity = result.scores.setdefault("component_severity", {})
    for ref in test_refs & {f.target for f in flags}:
        severity[ref] = "low"
    return result


_SEVERITIES = ("critical", "high", "medium", "low")


def finding_severity_counts(rows: list[dict[str, Any]]) -> dict[str, int]:
    """Findings by severity over the run-object's result rows, by the rule every D3
    surface counts with (the
    backend's ``cbom_rows.is_finding`` / ``cbom_metrics.finding_severity``): a row with
    a finding code, or one
    still marked weak or quantum-vulnerable, is a finding; its impact, Low when it has
    none it recognises."""
    counts = dict.fromkeys(_SEVERITIES, 0)
    for row in rows:
        if not isinstance(row, dict):
            continue
        codes = [c for c in row.get("finding_codes") or [] if isinstance(c, str) and c]
        unscored = row.get("code_context") == "test" or (
            row.get("config_status") == "unconfirmed"
        )
        if unscored:
            continue  # listed, labelled "test code" / "unconfirmed", never scored
        if (
            "finding_codes" in row
            and not codes
            and not (row.get("weak") is True or row.get("quantum_vulnerable") is True)
        ):
            continue  # clean inventory
        impact = str(row.get("impact") or "").strip().lower()
        counts[impact if impact in counts else "low"] += 1
    return counts


def posture_scores(
    scores: dict[str, Any], rows: list[dict[str, Any]]
) -> dict[str, Any]:
    """The D3 risk score (staging QA Q2-01, Rule P): the engine's one posture function
    (``score/posture.py``, with its
    worst-severity cap) over the scan's findings by severity. ``risk_normalized`` /
    ``risk_band`` / ``risk_grade`` /
    ``risk_label`` are what the PDF headline, the PDF summary page, the results page and
    the API show; the flag-weight
    sum stays in ``risk_total`` and ``by_flag`` / ``by_component`` /
    ``component_severity`` are unchanged."""
    counts = finding_severity_counts(rows)
    score = posture_score(**counts)
    grade, band = posture_grade(score)
    return {
        **scores,
        "risk_normalized": float(score),
        "risk_band": band,
        "risk_grade": grade,
        "risk_label": posture_label(band),
        "severity_counts": counts,
        "risk_scale": "posture",
    }


__all__ = [
    "finding_severity_counts",
    "posture_scores",
    "score_crypto",
    "_CBOM_WEIGHTS_PATH",
]
