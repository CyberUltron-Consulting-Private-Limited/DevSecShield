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

from aibom.model.result import ScanResult
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
    return score_result(result, str(_CBOM_WEIGHTS_PATH))


__all__ = ["score_crypto", "_CBOM_WEIGHTS_PATH"]
