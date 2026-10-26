"""Glob matching is a charged dynamic program and builds no regex."""

from __future__ import annotations

from pathlib import Path

from aibom.cbom.posture.globmatch import compile_glob
from aibom.cbom.posture.limits import GlobBudget

_SOURCE = (
    Path(__file__).resolve().parents[1]
    / "src"
    / "aibom"
    / "cbom"
    / "posture"
    / "globmatch.py"
)


def test_module_builds_no_regular_expression() -> None:
    text = _SOURCE.read_text(encoding="utf-8")
    assert "re.compile" not in text
    assert "import re" not in text


def test_star_question_and_double_star() -> None:
    budget = GlobBudget()
    assert compile_glob("*.txt").match("a.txt", budget)
    assert not compile_glob("*.txt").match("dir/a.txt", budget)
    assert compile_glob("a?c").match("abc", budget)
    assert not compile_glob("a?c").match("a/c", budget)
    program = compile_glob("a/**/b")
    assert program.match("a/b", budget)
    assert program.match("a/x/b", budget)
    assert program.match("a/x/y/b", budget)
    assert not program.match("a/b/c", budget)
    assert not program.match("z/a/b", budget)
    assert compile_glob("abc").match("abc", budget)
    assert not compile_glob("abc").match("abcd", budget)


def test_many_double_stars_finish_quickly() -> None:
    import time

    budget = GlobBudget()
    program = compile_glob("a/**/b/**/c/**/d")
    path = ("a/" * 256)[:512]
    started = time.perf_counter()
    assert program.match(path, budget) is False
    assert time.perf_counter() - started < 0.1


def test_budget_exhaustion_returns_false() -> None:
    budget = GlobBudget(steps_left=1)
    assert compile_glob("a/**/b").match("a/x/y/b", budget) is False
    assert budget.skipped == 1
    assert budget.steps_left == 0
