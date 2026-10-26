"""JSON loader. One character scan, then the stdlib parser."""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Literal, NamedTuple

from aibom.cbom.posture.diagnostics import safe_parse
from aibom.cbom.posture.limits import NESTING_DEPTH

LINE_PATTERNS: tuple[object, ...] = ()
TOKEN_PATTERNS: tuple[object, ...] = ()
ALL_PATTERNS = LINE_PATTERNS + TOKEN_PATTERNS

ScanStatus = Literal["ok", "depth_cap", "unterminated"]


class JsonScan(NamedTuple):
    status: ScanStatus
    key_lines: Mapping[tuple[str, ...], int]
    duplicate_lines: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class JsonDoc:
    value: object
    key_lines: Mapping[tuple[str, ...], int]


class _Frame:
    __slots__ = ("expect_key", "key", "kind", "key_line", "seen")

    def __init__(self, kind: str) -> None:
        self.kind = kind
        self.expect_key = kind == "{"
        self.key: str | None = None
        self.key_line = 1
        self.seen: set[str] = set()


def _add(sink: object | None, code: str, path: str, line: int = 0) -> None:
    if sink is None:
        return
    target = getattr(sink, "diagnostics", sink)
    target.add(code, path, line)


def _decode_key(raw: str) -> str | None:
    try:
        value = json.loads('"' + raw + '"')
    except (json.JSONDecodeError, ValueError, RecursionError):
        return None
    if isinstance(value, str):
        return value
    return None


def json_scan(
    text: str,
    depth_limit: int = NESTING_DEPTH,
    key_depth: int = 3,
    max_keys: int = 50_000,
) -> JsonScan:
    """Single pass. ``{`` and ``[`` above ``depth_limit`` stop the scan."""
    in_str = False
    escape = False
    depth = 0
    line = 1
    key_start = -1
    key_line = 1
    frames: list[_Frame] = []
    key_lines: dict[tuple[str, ...], int] = {}
    duplicates: list[int] = []
    index = 0
    length = len(text)
    while index < length:
        char = text[index]
        if char == "\n":
            line += 1
        if in_str:
            if escape:
                escape = False
            elif char == "\\":
                escape = True
            elif char == '"':
                in_str = False
                if key_start >= 0:
                    raw = text[key_start + 1 : index]
                    decoded = _decode_key(raw)
                    frame = frames[-1] if frames else None
                    if decoded is not None and frame is not None and frame.kind == "{":
                        if decoded in frame.seen:
                            duplicates.append(key_line)
                        frame.seen.add(decoded)
                        frame.key = decoded
                        frame.key_line = key_line
                        path = _key_path(frames)
                        if (
                            path is not None
                            and len(path) <= key_depth
                            and (path in key_lines or len(key_lines) < max_keys)
                        ):
                            key_lines[path] = key_line
                    key_start = -1
            index += 1
            continue
        if char == '"':
            in_str = True
            frame = frames[-1] if frames else None
            if frame is not None and frame.kind == "{" and frame.expect_key:
                key_start = index
                key_line = line
            index += 1
            continue
        if char == "{" or char == "[":
            depth += 1
            if depth > depth_limit:
                return JsonScan("depth_cap", key_lines, tuple(duplicates))
            frames.append(_Frame(char))
            index += 1
            continue
        if char == "}" or char == "]":
            if depth > 0:
                depth -= 1
            if frames:
                frames.pop()
            index += 1
            continue
        if char == ":" and frames and frames[-1].kind == "{":
            frames[-1].expect_key = False
        elif char == "," and frames and frames[-1].kind == "{":
            frames[-1].expect_key = True
        index += 1
    if in_str:
        return JsonScan("unterminated", key_lines, tuple(duplicates))
    return JsonScan("ok", key_lines, tuple(duplicates))


def _key_path(frames: list[_Frame]) -> tuple[str, ...] | None:
    path: list[str] = []
    for frame in frames:
        if frame.kind != "{":
            return None
        if frame.key is None:
            return None
        path.append(frame.key)
    return tuple(path)


def _reject_constant(_name: str) -> object:
    raise ValueError("json constant")


def _pairs(pairs: list[tuple[object, object]]) -> dict[object, object]:
    obj: dict[object, object] = {}
    for key, value in pairs:
        obj[key] = value
    return obj


def parse_json(
    text: str,
    *,
    path: str = "",
    sink: object | None = None,
    depth_limit: int = NESTING_DEPTH,
) -> JsonDoc | None:
    """Parse JSON. Repeated keys keep the last value and record ``duplicate_key``."""
    try:
        scan = json_scan(text, depth_limit=depth_limit)
        if scan.status == "depth_cap":
            _add(sink, "depth_cap", path, 0)
            return None
        if scan.status == "unterminated":
            _add(sink, "parse_error", path, 0)
            return None
        value = json.loads(
            text,
            object_pairs_hook=_pairs,
            parse_constant=_reject_constant,
        )
    except (json.JSONDecodeError, ValueError, RecursionError, MemoryError):
        _add(sink, "parse_error", path, 0)
        return None
    except Exception:
        _add(sink, "parse_error", path, 0)
        return None
    for line in scan.duplicate_lines:
        _add(sink, "duplicate_key", path, line)
    return JsonDoc(value, scan.key_lines)


def load_json(
    data: bytes,
    record,
    *,
    path: str = "",
    sink: object | None = None,
) -> JsonDoc | None:
    def run(raw: bytes) -> JsonDoc | None:
        result = parse_json(raw.decode("utf-8", "replace"), path=path, sink=sink)
        if result is None and sink is None:
            raise RuntimeError("parse failed")
        return result

    return safe_parse(run, data, record)  # type: ignore[return-value]
