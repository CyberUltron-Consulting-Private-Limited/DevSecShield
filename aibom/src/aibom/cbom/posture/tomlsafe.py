"""TOML loader. A depth scan, then stdlib tomllib."""

from __future__ import annotations

import tomllib
from dataclasses import dataclass
from typing import Literal

from aibom.cbom.posture.diagnostics import safe_parse
from aibom.cbom.posture.limits import NESTING_DEPTH

LINE_PATTERNS: tuple[object, ...] = ()
TOKEN_PATTERNS: tuple[object, ...] = ()
ALL_PATTERNS = LINE_PATTERNS + TOKEN_PATTERNS

TomlStatus = Literal["ok", "depth_cap", "unterminated"]


@dataclass(frozen=True, slots=True)
class TomlDoc:
    value: dict[str, object]
    headers: dict[str, int]


def _add(sink: object | None, code: str, path: str, line: int = 0) -> None:
    if sink is None:
        return
    target = getattr(sink, "diagnostics", sink)
    target.add(code, path, line)


def toml_scan(text: str, depth_limit: int = NESTING_DEPTH) -> TomlStatus:
    """One pass. Brackets inside strings and comments do not add depth."""
    index = 0
    length = len(text)
    depth = 0
    while index < length:
        char = text[index]
        if char == "#":
            newline = text.find("\n", index)
            if newline < 0:
                return "ok"
            index = newline + 1
            continue
        if text.startswith('"""', index):
            closed = _skip_multiline(text, index + 3, '"""', escapes=True)
            if closed < 0:
                return "unterminated"
            index = closed
            continue
        if text.startswith("'''", index):
            closed = _skip_multiline(text, index + 3, "'''", escapes=False)
            if closed < 0:
                return "unterminated"
            index = closed
            continue
        if char == '"':
            closed = _skip_basic(text, index + 1)
            if closed < 0:
                return "unterminated"
            index = closed
            continue
        if char == "'":
            closed = _skip_literal(text, index + 1)
            if closed < 0:
                return "unterminated"
            index = closed
            continue
        if char == "[" or char == "{":
            depth += 1
            if depth > depth_limit:
                return "depth_cap"
        elif char == "]" or char == "}":
            if depth > 0:
                depth -= 1
        index += 1
    return "ok"


def _skip_basic(text: str, index: int) -> int:
    length = len(text)
    while index < length:
        char = text[index]
        if char == "\\":
            if index + 1 >= length:
                return -1
            index += 2
            continue
        if char == "\n":
            return -1
        if char == '"':
            return index + 1
        index += 1
    return -1


def _skip_literal(text: str, index: int) -> int:
    length = len(text)
    while index < length:
        char = text[index]
        if char == "\n":
            return -1
        if char == "'":
            return index + 1
        index += 1
    return -1


def _skip_multiline(text: str, index: int, closer: str, *, escapes: bool) -> int:
    length = len(text)
    marks = len(closer)
    while index < length:
        if escapes and text[index] == "\\":
            index += 2
            continue
        if text.startswith(closer, index):
            return index + marks
        index += 1
    return -1


def header_lines(text: str) -> dict[str, int]:
    """Table header line numbers. No regular expression."""
    found: dict[str, int] = {}
    for number, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if not stripped.startswith("["):
            continue
        end = stripped.find("]")
        if end <= 0:
            continue
        inner = stripped[1:end].strip()
        if inner.startswith("["):
            inner = inner[1:].strip()
        if inner:
            found[inner] = number
    return found


def parse_toml(
    text: str,
    *,
    path: str = "",
    sink: object | None = None,
    depth_limit: int = NESTING_DEPTH,
) -> TomlDoc | None:
    """Load TOML. A repeated key is ``parse_error`` because tomllib rejects it."""
    try:
        status = toml_scan(text, depth_limit=depth_limit)
        if status == "depth_cap":
            _add(sink, "depth_cap", path, 0)
            return None
        if status == "unterminated":
            _add(sink, "parse_error", path, 0)
            return None
        value = tomllib.loads(text)
    except (tomllib.TOMLDecodeError, RecursionError, ValueError, MemoryError):
        _add(sink, "parse_error", path, 0)
        return None
    except Exception:
        _add(sink, "parse_error", path, 0)
        return None
    if not isinstance(value, dict):
        _add(sink, "parse_error", path, 0)
        return None
    return TomlDoc(value, header_lines(text))


def load_toml(
    data: bytes,
    record,
    *,
    path: str = "",
    sink: object | None = None,
) -> TomlDoc | None:
    def run(raw: bytes) -> TomlDoc | None:
        result = parse_toml(raw.decode("utf-8", "replace"), path=path, sink=sink)
        if result is None and sink is None:
            raise RuntimeError("parse failed")
        return result

    return safe_parse(run, data, record)  # type: ignore[return-value]
