"""Glob matcher. A dynamic program charged to GlobBudget. No regex."""

from __future__ import annotations

from dataclasses import dataclass

from aibom.cbom.posture.limits import PATH_MAX_BYTES, GlobBudget

LINE_PATTERNS: tuple[object, ...] = ()
TOKEN_PATTERNS: tuple[object, ...] = ()
ALL_PATTERNS = LINE_PATTERNS + TOKEN_PATTERNS

_LIT = "lit"
_Q = "q"
_STAR = "star"
_DSTAR = "dstar"
_SLASH = "slash"


@dataclass(frozen=True, slots=True)
class GlobProgram:
    """Literal prefix plus a token list. ``match`` never backtracks."""

    prefix: str
    tokens: tuple[tuple[str, str], ...]
    pattern: str

    def match(self, text: str, budget: GlobBudget) -> bool:
        if (
            len(self.pattern) > PATH_MAX_BYTES
            or len(text.encode("utf-8")) > PATH_MAX_BYTES
        ):
            return False
        if not text.startswith(self.prefix):
            return False
        rest = text[len(self.prefix) :]
        width = len(rest) + 1
        steps = max(1, (len(self.tokens) + 1) * width)
        if budget.steps_left < steps:
            budget.steps_left = 0
            budget.skipped += 1
            return False
        budget.steps_left -= steps
        return _run(self.tokens, rest)


def compile_glob(pattern: str, star_crosses_slash: bool = False) -> GlobProgram:
    """Split ``pattern`` into its longest literal prefix and tokens."""
    limit = pattern[:PATH_MAX_BYTES]
    cut = 0
    while cut < len(limit) and limit[cut] not in "*?":
        cut += 1
    return GlobProgram(limit[:cut], _tokens(limit[cut:], star_crosses_slash), limit)


def _tokens(pattern: str, star_crosses_slash: bool) -> tuple[tuple[str, str], ...]:
    tokens: list[tuple[str, str]] = []
    index = 0
    length = len(pattern)
    while index < length:
        if pattern.startswith("**", index):
            kind = _STAR if star_crosses_slash else _DSTAR
            tokens.append((kind, ""))
            index += 2
            if index < length and pattern[index] == "/":
                tokens.append((_SLASH, ""))
                index += 1
            continue
        char = pattern[index]
        if char == "*":
            tokens.append((_STAR, ""))
            index += 1
            continue
        if char == "?":
            tokens.append((_Q, ""))
            index += 1
            continue
        end = index + 1
        while end < length and pattern[end] not in "*?":
            end += 1
        tokens.append((_LIT, pattern[index:end]))
        index = end
    return tuple(tokens)


def _charge_row(active: list[bool], text: str, star: bool) -> list[bool]:
    width = len(text) + 1
    nxt = [False] * width
    index = 0
    while index < width:
        if not active[index]:
            index += 1
            continue
        nxt[index] = True
        cursor = index
        while cursor < len(text) and (star or text[cursor] != "/"):
            cursor += 1
            nxt[cursor] = True
        index = cursor + 1 if cursor > index else index + 1
    return nxt


def _run(tokens: tuple[tuple[str, str], ...], text: str) -> bool:
    width = len(text) + 1
    active = [False] * width
    active[0] = True
    for kind, value in tokens:
        if not any(active):
            return False
        if kind == _LIT:
            nxt = [False] * width
            size = len(value)
            for index, on in enumerate(active):
                end = index + size
                if on and end <= len(text) and text.startswith(value, index):
                    nxt[end] = True
            active = nxt
            continue
        if kind == _Q:
            nxt = [False] * width
            for index, on in enumerate(active):
                if on and index < len(text) and text[index] != "/":
                    nxt[index + 1] = True
            active = nxt
            continue
        if kind == _SLASH:
            nxt = [False] * width
            for index, on in enumerate(active):
                if not on:
                    continue
                nxt[index] = True
                if index < len(text) and text[index] == "/":
                    nxt[index + 1] = True
            active = nxt
            continue
        active = _charge_row(active, text, star=(kind == _DSTAR))
    return bool(active[-1])
