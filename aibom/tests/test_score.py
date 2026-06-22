"""Config-driven scorer: flags -> scores (sum of YAML weights)."""

from __future__ import annotations

import textwrap
from pathlib import Path

from aibom.model.component import MetadataComponent
from aibom.model.result import Flag, ScanResult
from aibom.score.scorer import _DEFAULT_WEIGHTS_PATH, load_weights, score_result


def _result_with_flags(*codes: str) -> ScanResult:
    return ScanResult(
        subject=MetadataComponent(name="app"),
        flags=[Flag(code, "model-x", "warning", code) for code in codes],
    )


def test_default_weights_file_exists_and_loads() -> None:
    assert Path(_DEFAULT_WEIGHTS_PATH).is_file()
    weights = dict(load_weights())
    assert weights["MODEL_NO_LICENSE"] == 8.0
    assert weights["__default__"] == 1.0


def test_score_sums_flag_weights() -> None:
    r = _result_with_flags("MODEL_EU_AI_ACT_HIGH_RISK", "MODEL_PHI_AT_INFERENCE")
    score_result(r)
    assert r.scores["risk_total"] == 5.0 + 4.0
    assert r.scores["by_flag"] == {
        "MODEL_EU_AI_ACT_HIGH_RISK": 5.0,
        "MODEL_PHI_AT_INFERENCE": 4.0,
    }
    assert r.scores["by_component"]["model-x"] == 9.0
    assert r.scores["flag_count"] == 2


def test_unknown_flag_uses_default_weight() -> None:
    r = _result_with_flags("SOME_NOVEL_FLAG")
    score_result(r)
    assert r.scores["risk_total"] == 1.0  # the YAML default


def test_no_flags_scores_zero() -> None:
    r = ScanResult(subject=MetadataComponent(name="app"))
    score_result(r)
    assert r.scores["risk_total"] == 0.0
    assert r.scores["flag_count"] == 0


def test_custom_weights_path(tmp_path: Path) -> None:
    """The scorer is config-driven: a different YAML changes the score."""
    custom = tmp_path / "w.yaml"
    custom.write_text(textwrap.dedent("""
        default: 2
        flags:
          MODEL_NO_LICENSE: 100
    """))
    r = _result_with_flags("MODEL_NO_LICENSE", "OTHER")
    score_result(r, weights_path=str(custom))
    assert r.scores["risk_total"] == 100.0 + 2.0
