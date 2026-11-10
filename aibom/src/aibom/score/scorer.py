"""Config-driven scorer: ``ScanResult.flags`` -> ``ScanResult.scores``.

Reads ``config/risk-weights.yaml`` and writes a deterministic score block onto
the result. Trivial for now (sum of flag weights) — but it is the only place
scores are computed: scanners raise flags, the scorer turns them into numbers.
Swapping in a richer model (per-severity multipliers, decay, normalization) is a
change here and in the YAML, nowhere else.
"""

from __future__ import annotations

from functools import lru_cache
from importlib import resources
from pathlib import Path
from typing import Any

import yaml

from aibom.model.result import ScanResult


def _resolve_default_weights_path() -> Path:
    """Locate config/risk-weights.yaml in both wheel and source-tree layouts.

    An installed wheel force-includes the config at ``aibom/config`` (see
    pyproject ``[tool.hatch.build.targets.wheel.force-include]``), reachable via
    importlib.resources. In the source tree config/ lives at the repo root
    (``src/aibom/score/scorer.py -> parents[3]/config``). Try the packaged copy
    first so the config-driven seam keeps working post-install.
    """
    try:
        packaged = resources.files("aibom") / "config" / "risk-weights.yaml"
        if Path(str(packaged)).is_file():
            return Path(str(packaged))
    except (ModuleNotFoundError, FileNotFoundError, TypeError):
        pass
    return Path(__file__).resolve().parents[3] / "config" / "risk-weights.yaml"


_DEFAULT_WEIGHTS_PATH = _resolve_default_weights_path()

# Used only if the YAML is missing (e.g. an installed wheel without config/).
_FALLBACK_WEIGHTS: dict[str, float] = {
    "MODEL_NO_LICENSE": 8.0,
    "DATASET_NO_DEIDENT": 10.0,
    "MODEL_EU_AI_ACT_HIGH_RISK": 5.0,
    "MODEL_PHI_AT_INFERENCE": 4.0,
}
_FALLBACK_DEFAULT = 1.0


# Default scale if the YAML omits a `scale:` block (max_raw None -> auto-cap).
_FALLBACK_BANDS: dict[str, float] = {"low": 33.0, "medium": 66.0}

# Default per-component SEVERITY thresholds (inclusive lower bounds on the
# component's STACKED raw flag-weight) if the YAML omits a `severity:` block.
_FALLBACK_SEVERITY: dict[str, float] = {
    "critical": 12.0,
    "high": 8.0,
    "medium": 4.0,
    "low": 1.0,
}


def _mtime_ns(path: str | None) -> int | None:
    """Modification time of the weights file (cache-busting key); None if absent."""
    p = Path(path) if path else _DEFAULT_WEIGHTS_PATH
    try:
        return p.stat().st_mtime_ns
    except OSError:
        return None


@lru_cache(maxsize=8)
def _load_weights_cached(
    path: str | None, _mtime: int | None
) -> tuple[tuple[str, float], ...]:
    p = Path(path) if path else _DEFAULT_WEIGHTS_PATH
    if p.is_file():
        data = yaml.safe_load(p.read_text()) or {}
        flags = data.get("flags", {}) if isinstance(data, dict) else {}
        default = data.get("default", _FALLBACK_DEFAULT)
        weights = {str(k): float(v) for k, v in (flags or {}).items()}
        default_w = float(default)
    else:
        weights = dict(_FALLBACK_WEIGHTS)
        default_w = _FALLBACK_DEFAULT
    weights["__default__"] = default_w
    return tuple(sorted(weights.items()))


def load_weights(path: str | None = None) -> tuple[tuple[str, float], ...]:
    """Load (flag -> weight) + a ``("__default__", w)`` sentinel.

    Cached by ``(path, mtime)`` so an edited weights file is picked up within a
    process while unchanged reads still hit the cache.
    """
    return _load_weights_cached(path, _mtime_ns(path))


def _weight_for(code: str, weights: dict[str, float]) -> float:
    return weights.get(code, weights["__default__"])


@lru_cache(maxsize=8)
def _load_scale_cached(
    path: str | None, _mtime: int | None
) -> tuple[tuple[str, Any], ...]:
    p = Path(path) if path else _DEFAULT_WEIGHTS_PATH
    scale: dict[str, Any] = {}
    if p.is_file():
        data = yaml.safe_load(p.read_text()) or {}
        if isinstance(data, dict) and isinstance(data.get("scale"), dict):
            scale = data["scale"]
    raw_bands = scale.get("bands")
    bands: dict[str, float] = (
        {str(k): float(v) for k, v in raw_bands.items()}
        if isinstance(raw_bands, dict)
        else dict(_FALLBACK_BANDS)
    )
    return (("max_raw", scale.get("max_raw")), ("bands", tuple(sorted(bands.items()))))


def _load_scale(path: str | None = None) -> tuple[tuple[str, Any], ...]:
    """Load the `scale:` block (max_raw + bands), cached by ``(path, mtime)``."""
    return _load_scale_cached(path, _mtime_ns(path))


def _calibration_cap(weights: dict[str, float], scale: dict[str, Any]) -> float:
    """The raw sum that maps to 100. Explicit max_raw, else sum of flag weights."""
    explicit = scale.get("max_raw")
    if explicit:
        return float(explicit)
    catalog = sum(w for k, w in weights.items() if k != "__default__" and w > 0)
    return float(catalog) if catalog > 0 else 1.0


def normalize_score(raw: float, weights_path: str | None = None) -> float:
    """Scale a raw flag-weight sum to a 0-100 risk score (capped at 100)."""
    weights = dict(load_weights(weights_path))
    scale = dict(_load_scale(weights_path))
    cap = _calibration_cap(weights, scale)
    return min(100.0, round(raw / cap * 100, 1))


def risk_band(normalized: float, weights_path: str | None = None) -> str:
    """Map a 0-100 normalized score to a low / medium / high band."""
    bands = dict(dict(_load_scale(weights_path))["bands"])
    low = float(bands.get("low", 33))
    medium = float(bands.get("medium", 66))
    if normalized <= low:
        return "low"
    if normalized <= medium:
        return "medium"
    return "high"


@lru_cache(maxsize=8)
def _load_severity_cached(
    path: str | None, _mtime: int | None
) -> tuple[tuple[str, float], ...]:
    p = Path(path) if path else _DEFAULT_WEIGHTS_PATH
    sev: dict[str, float] = {}
    if p.is_file():
        data = yaml.safe_load(p.read_text()) or {}
        if isinstance(data, dict) and isinstance(data.get("severity"), dict):
            sev = {str(k): float(v) for k, v in data["severity"].items()}
    if not sev:
        sev = dict(_FALLBACK_SEVERITY)
    return tuple(sorted(sev.items(), key=lambda kv: kv[1], reverse=True))


def _load_severity(path: str | None = None) -> tuple[tuple[str, float], ...]:
    """Per-component severity thresholds (band -> min stacked weight), high first."""
    return _load_severity_cached(path, _mtime_ns(path))


def component_severity(raw: float, weights_path: str | None = None) -> str:
    """Map a component's STACKED raw flag-weight to critical/high/medium/low.

    Inclusive lower bounds from the YAML ``severity:`` block; a component with no
    flags (raw 0) is ``low`` — the inventory floor (clean library / vector store).
    """
    for band, threshold in _load_severity(weights_path):  # high -> low
        if raw >= threshold:
            return band
    return "low"


def score_result(result: ScanResult, weights_path: str | None = None) -> ScanResult:
    """Compute ``result.scores`` from ``result.flags`` (in place) and return it."""
    weights = dict(load_weights(weights_path))
    by_flag: dict[str, float] = {}
    by_component: dict[str, float] = {}
    total = 0.0
    for flag in result.flags:
        # ``CODE@severity`` in the weights file weighs a code raised at a lower severity on its own (an encrypted
        # committed private key: HARDCODED_KEY at warning); otherwise the code's weight
        w = weights.get(f"{flag.code}@{flag.severity}", _weight_for(flag.code, weights))
        by_flag[flag.code] = by_flag.get(flag.code, 0.0) + w
        if flag.target:
            by_component[flag.target] = by_component.get(flag.target, 0.0) + w
        total += w

    normalized = normalize_score(total, weights_path)
    # Per-component severity from the STACKED weight (flags stack per component).
    component_severity_map = {
        ref: component_severity(raw, weights_path) for ref, raw in by_component.items()
    }
    scores: dict[str, Any] = {
        "risk_total": total,  # raw internal sum
        "risk_normalized": normalized,  # 0-100 (Trusera-style), defined scale
        "risk_band": risk_band(normalized, weights_path),  # low / medium / high
        "by_flag": dict(sorted(by_flag.items())),
        "by_component": dict(sorted(by_component.items())),
        # bom_ref -> critical/high/medium/low (stacked); absent ref -> low (no flags)
        "component_severity": dict(sorted(component_severity_map.items())),
        "flag_count": len(result.flags),
    }
    result.scores = scores
    return result


__all__ = [
    "load_weights",
    "score_result",
    "normalize_score",
    "risk_band",
    "component_severity",
    "_DEFAULT_WEIGHTS_PATH",
]
