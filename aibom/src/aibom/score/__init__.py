"""Config-driven scoring layer: flags -> ScanResult.scores."""

from aibom.score.scorer import (
    load_weights,
    normalize_score,
    risk_band,
    score_result,
)

__all__ = ["load_weights", "score_result", "normalize_score", "risk_band"]
