"""Linear blanking matches detect.strip_noncode without calling it."""

from __future__ import annotations

import random
from pathlib import Path

import pytest

from aibom.cbom.detect import strip_noncode
from aibom.cbom.posture.textscan import XML_PAIRS, blank_noncode, blank_spans
from support.generators import mutate_bytes

_SOURCE = (
    Path(__file__).resolve().parents[1]
    / "src"
    / "aibom"
    / "cbom"
    / "posture"
    / "textscan.py"
)


def test_module_does_not_call_strip_noncode() -> None:
    text = _SOURCE.read_text(encoding="utf-8")
    assert "strip_noncode" not in text
    assert "aibom.cbom.detect" not in text


def test_blank_noncode_matches_strip_noncode_on_random_texts() -> None:
    rng = random.Random(1)
    alphabet = ["a", "\n", " ", '"', "'", "/", "*", "/*", "*/", '"""', "'''", "x"]
    for _ in range(20_000):
        parts = [rng.choice(alphabet) for _ in range(rng.randint(1, 40))]
        sample = "".join(parts)
        assert blank_noncode(sample) == strip_noncode(sample)


def test_blank_spans_keeps_newlines_and_blanks_both_pairs() -> None:
    text = "a\n<!-- secret -->\nb\n<![CDATA[hidden]]>\nc"
    blanked = blank_spans(text, XML_PAIRS, unterminated="error")
    assert blanked is not None
    assert blanked.count("\n") == text.count("\n")
    assert "secret" not in blanked
    assert "hidden" not in blanked
    assert "a" in blanked and "c" in blanked


def test_unterminated_xml_span_is_an_error() -> None:
    assert blank_spans("<!-- no end", XML_PAIRS, unterminated="error") is None


def test_unterminated_block_comment_stays() -> None:
    sample = "/* stays"
    assert blank_noncode(sample) == sample
    assert blank_noncode(sample) == strip_noncode(sample)


@pytest.mark.parametrize("seed", range(1, 21))
def test_mutated_bytes_never_raise(seed: int) -> None:
    for payload in mutate_bytes(seed, base=b'/* comment */ """doc"""\n'):
        blank_noncode(payload.decode("utf-8", "replace"))
