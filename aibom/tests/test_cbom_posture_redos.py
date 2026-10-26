"""Parser patterns and scanners stay linear on hostile input."""

from __future__ import annotations

import subprocess
import sys
import time

from aibom.cbom.posture import hcl, xmlsafe
from support.generators import fragments, structure_aware

_LIMIT = 1.0


def _token_loop(pattern: object, text: str) -> None:
    pos = 0
    length = len(text)
    compiled = pattern
    while pos < length:
        matched = compiled.match(text, pos)  # type: ignore[attr-defined]
        if matched is None:
            return
        nxt = matched.end()
        if nxt <= pos:
            return
        pos = nxt


def test_token_patterns_finish_on_structure_aware_input() -> None:
    patterns = (*hcl.TOKEN_PATTERNS, *xmlsafe.TOKEN_PATTERNS)
    samples = structure_aware(65_536)
    for pattern in patterns:
        for _name, text in samples:
            started = time.perf_counter()
            _token_loop(pattern, text)
            assert time.perf_counter() - started < _LIMIT


def test_fragments_cover_literal_runs() -> None:
    pieces = fragments(hcl.TOKEN_PATTERNS[0].pattern)
    assert any(len(piece) >= 2 for piece in pieces)


def test_quadratic_controls_time_out() -> None:
    script = r"""
import re
text = "/* " * 50000
pat = re.compile(r"/\*.*?\*/|/")
pos = 0
limit = len(text)
while pos < limit:
    matched = pat.match(text, pos)
    if matched is None:
        pos += 1
        continue
    nxt = matched.end()
    pos = nxt if nxt > pos else pos + 1
"""
    with subprocess.Popen(
        [sys.executable, "-c", script],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    ) as proc:
        try:
            proc.wait(timeout=1.0)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)
            return
    raise AssertionError("quadratic control finished inside 1 second")
