"""CODEOWNERS parser. Patterns are matched by globmatch, not by a regex."""

from __future__ import annotations

from dataclasses import dataclass

from aibom.cbom.posture.diagnostics import safe_parse
from aibom.cbom.posture.globmatch import GlobProgram, compile_glob
from aibom.cbom.posture.limits import PATH_MAX_BYTES, GlobBudget

LINE_PATTERNS: tuple[object, ...] = ()
TOKEN_PATTERNS: tuple[object, ...] = ()
ALL_PATTERNS = LINE_PATTERNS + TOKEN_PATTERNS

_MAX_RULES = 1_000


@dataclass(frozen=True, slots=True)
class OwnerRule:
    pattern: str
    owners: tuple[str, ...]
    program: GlobProgram
    line: int


@dataclass(frozen=True, slots=True)
class CodeOwners:
    rules: tuple[OwnerRule, ...]

    def owner_of(
        self,
        rel: str,
        budget: GlobBudget,
        *,
        path: str = "",
        sink: object | None = None,
    ) -> tuple[str, ...] | None:
        """Last matching pattern wins. Exhausting the budget records one code."""
        before = budget.skipped
        found: tuple[str, ...] | None = None
        for rule in self.rules:
            if rule.program.match(rel, budget):
                found = rule.owners
        if before == 0 and budget.skipped:
            _add(sink, "glob_budget", path, budget.skipped)
        return found


def _add(sink: object | None, code: str, path: str, line: int = 0) -> None:
    if sink is None:
        return
    target = getattr(sink, "diagnostics", sink)
    target.add(code, path, line)


def normalize_pattern(pattern: str) -> str:
    """GitHub anchors: root ``/``, any-depth without a slash, trailing ``/``."""
    anchored = pattern.startswith("/")
    if anchored:
        pattern = pattern[1:]
    if pattern.endswith("/") and not pattern.endswith("**/"):
        body = pattern[:-1]
        pattern = body + "/**"
        if not anchored and "/" not in body:
            pattern = "**/" + pattern
        return pattern
    if not anchored and "/" not in pattern:
        pattern = "**/" + pattern
    return pattern


def _split_rule(line: str) -> tuple[str, tuple[str, ...]] | None:
    pattern: list[str] = []
    owners: list[str] = []
    buf: list[str] = []
    index = 0
    in_pattern = True
    length = len(line)
    while index < length:
        char = line[index]
        if char == "\\" and index + 1 < length and line[index + 1] == " ":
            buf.append(" ")
            index += 2
            continue
        if char == "#" and not buf:
            break
        if char.isspace() and in_pattern and buf:
            pattern.append("".join(buf))
            buf = []
            in_pattern = False
            index += 1
            continue
        if char.isspace() and not in_pattern:
            if buf:
                owners.append("".join(buf))
                buf = []
            index += 1
            continue
        buf.append(char)
        index += 1
    if buf:
        if in_pattern:
            pattern.append("".join(buf))
        else:
            owners.append("".join(buf))
    if not pattern:
        return None
    return pattern[0], tuple(owners)


def parse_codeowners(
    text: str,
    *,
    path: str = "",
    sink: object | None = None,
    budget: GlobBudget | None = None,
) -> CodeOwners | None:
    """Parse CODEOWNERS. ``!`` and ``[`` patterns are unsupported."""
    try:
        rules: list[OwnerRule] = []
        for number, raw in enumerate(text.splitlines(), 1):
            stripped = raw.strip()
            if not stripped or stripped.startswith("#"):
                continue
            parts = _split_rule(stripped)
            if parts is None:
                continue
            pattern, owners = parts
            if not owners:
                continue
            unsupported = (
                pattern.startswith("!")
                or "[" in pattern
                or len(pattern) > PATH_MAX_BYTES
                or len(rules) >= _MAX_RULES
            )
            if unsupported:
                _add(sink, "codeowners_pattern_unsupported", path, number)
                continue
            program = compile_glob(normalize_pattern(pattern))
            rules.append(OwnerRule(pattern, owners, program, number))
        return CodeOwners(tuple(rules))
    except Exception:
        _add(sink, "parse_error", path, 0)
        return None


def load_codeowners(
    data: bytes,
    record,
    *,
    path: str = "",
    sink: object | None = None,
) -> CodeOwners | None:
    def run(raw: bytes) -> CodeOwners | None:
        result = parse_codeowners(raw.decode("utf-8", "replace"), path=path, sink=sink)
        if result is None and sink is None:
            raise RuntimeError("parse failed")
        return result

    return safe_parse(run, data, record)  # type: ignore[return-value]
