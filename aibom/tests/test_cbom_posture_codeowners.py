"""CODEOWNERS uses globmatch. Negation and classes are unsupported."""

from __future__ import annotations

import pytest

from aibom.cbom.posture.codeowners import (
    load_codeowners,
    normalize_pattern,
    parse_codeowners,
)
from aibom.cbom.posture.diagnostics import DiagnosticSink
from aibom.cbom.posture.limits import GlobBudget
from support.generators import mutate_bytes


def test_last_match_wins_and_anchors() -> None:
    text = "*.js @js\n/docs/readme.md @root\napps/foo @apps\n"
    sink = DiagnosticSink()
    doc = parse_codeowners(text, path="CODEOWNERS", sink=sink)
    assert doc is not None
    budget = GlobBudget()
    assert doc.owner_of("src/app.js", budget) == ("@js",)
    assert doc.owner_of("docs/readme.md", budget) == ("@root",)
    assert doc.owner_of("nested/docs/readme.md", budget) is None
    assert doc.owner_of("apps/foo", budget) == ("@apps",)
    assert doc.owner_of("x/apps/foo", budget) is None
    assert sink.stored() == ()


def test_directory_pattern_and_double_star() -> None:
    text = "docs/ @docs\na/**/b @ab\n"
    doc = parse_codeowners(text, path="CODEOWNERS", sink=DiagnosticSink())
    assert doc is not None
    budget = GlobBudget()
    assert doc.owner_of("docs/file.txt", budget) == ("@docs",)
    assert doc.owner_of("pkg/docs/file.txt", budget) == ("@docs",)
    assert doc.owner_of("a/b", budget) == ("@ab",)
    assert doc.owner_of("a/x/b", budget) == ("@ab",)
    assert normalize_pattern("*.js") == "**/*.js"
    assert normalize_pattern("/docs/a") == "docs/a"
    assert normalize_pattern("docs/") == "**/docs/**"


def test_negation_and_character_class_are_unsupported() -> None:
    text = "!secret @no\nfoo[ab].js @no\n*.md @yes\n"
    sink = DiagnosticSink()
    doc = parse_codeowners(text, path="CODEOWNERS", sink=sink)
    assert doc is not None
    assert [rule.pattern for rule in doc.rules] == ["*.md"]
    codes = [item.code for item in sink.stored()]
    assert codes == ["codeowners_pattern_unsupported", "codeowners_pattern_unsupported"]


def test_escaped_space_stays_in_the_pattern() -> None:
    text = r"docs/my\ file.txt @owner" + "\n"
    doc = parse_codeowners(text, path="CODEOWNERS", sink=DiagnosticSink())
    assert doc is not None
    assert doc.rules[0].pattern == "docs/my file.txt"
    budget = GlobBudget()
    assert doc.owner_of("docs/my file.txt", budget) == ("@owner",)


def test_budget_exhaustion_records_one_diagnostic() -> None:
    text = "a/**/b @owner\n"
    sink = DiagnosticSink()
    doc = parse_codeowners(text, path="CODEOWNERS", sink=sink)
    assert doc is not None
    budget = GlobBudget(steps_left=1)
    assert doc.owner_of("a/x/y/b", budget, path="CODEOWNERS", sink=sink) is None
    assert [item.code for item in sink.stored()] == ["glob_budget"]


def test_bytes_return_a_result_or_one_diagnostic() -> None:
    seen: list[str] = []
    result = load_codeowners(b"\xff *.js @a\n", seen.append)
    assert result is None or result.rules == () or result.rules
    assert seen == [] or seen == ["parse_error"]


@pytest.mark.parametrize("seed", range(1, 21))
def test_mutated_bytes_never_raise(seed: int) -> None:
    for payload in mutate_bytes(seed, base=b"*.js @js\n/docs/readme.md @root\n"):
        load_codeowners(payload, lambda _code: None)
