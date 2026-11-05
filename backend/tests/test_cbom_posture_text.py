"""Authored posture text: ten codes, labels, and the limit sentences."""

from __future__ import annotations

import sys
from pathlib import Path

_REPO = Path(__file__).resolve().parents[2]
if str(_REPO) not in sys.path:
    sys.path.insert(0, str(_REPO))

from backend.utilities.pdf import cbom_posture_text as text  # noqa: E402

_BANNED = ("bedrock", "anthropic", "openai", "get_llm", "chatbedrock")


def test_every_posture_finding_has_a_label_impact_and_action() -> None:
    assert len(text.FINDING_CODES) == 12  # the engine's POSTURE_CODES (test_cbom_finding_code_tables)
    for code in text.FINDING_CODES:
        assert text.finding_label(code)
        assert text.finding_action(code)
        assert text.FINDING_IMPACT[code] in {"High", "Medium", "Low"}


def test_limit_sentences_are_the_recorded_ones() -> None:
    assert "not proof of operation" in text.INFRA_LIMIT
    assert "did not probe any endpoint" in text.ENDPOINT_LIMIT
    assert "stored data was not inspected" in text.STORED_DATA_LIMIT


def test_posture_text_names_no_model_client() -> None:
    source = Path(text.__file__).read_text(encoding="utf-8").lower()
    for word in _BANNED:
        assert word not in source
