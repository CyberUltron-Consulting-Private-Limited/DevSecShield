"""Diagnostics. A record holds a path, a line, and a closed code."""

from __future__ import annotations

from dataclasses import dataclass

from aibom.cbom.posture.limits import STORED_DIAGNOSTICS

DIAGNOSTIC_CODES: frozenset[str] = frozenset(
    {
        "alias_cap",
        "binary_skipped",
        "codeowners_pattern_unsupported",
        "conflicting_declaration",
        "depth_cap",
        "duplicate_key",
        "duplicate_resource",
        "encoding_fallback",
        "facts_truncated",
        "glob_budget",
        "helm_template_skipped",
        "include_cycle",
        "include_depth",
        "internal_error",
        "kustomize_not_applied",
        "line_cap",
        "mapping_entry_invalid",
        "mapping_file_ignored",
        "mapping_unknown_key",
        "module_call",
        "node_cap",
        "parse_error",
        "run_object_budget",
        "scan_budget_exhausted",
        "size_cap",
        "special_file_skipped",
        "state_file_ignored",
        "unsafe_tag",
        "unsafe_xml",
        "unknown_tag",
        "unsupported_format",
        "unsupported_result_format",
    }
)


@dataclass(frozen=True, slots=True)
class Diagnostic:
    code: str
    path: str
    line: int = 0

    def __post_init__(self) -> None:
        if self.code not in DIAGNOSTIC_CODES:
            raise ValueError(f"unknown diagnostic code: {self.code}")


class DiagnosticSink:
    """Idempotent on (code, path, line). Stores at most the limit, keeps totals."""

    def __init__(self, limit: int = STORED_DIAGNOSTICS) -> None:
        self.limit = limit
        self._seen: set[tuple[str, str, int]] = set()
        self._stored: list[Diagnostic] = []
        self.totals: dict[str, int] = {}

    def add(self, code: str, path: str, line: int = 0) -> Diagnostic:
        item = Diagnostic(code, path, line)
        key = (code, path, line)
        self.totals[code] = self.totals.get(code, 0) + (0 if key in self._seen else 1)
        if key in self._seen:
            return item
        self._seen.add(key)
        if len(self._stored) < self.limit:
            self._stored.append(item)
        return item

    def stored(self) -> tuple[Diagnostic, ...]:
        def sort_key(item: Diagnostic) -> tuple[str, int, str]:
            return (item.path, item.line, item.code)

        return tuple(sorted(self._stored, key=sort_key))


def safe_parse(fn, data: bytes, record) -> object:
    """Return a result, or one diagnostic. Never let a parser exception escape."""
    try:
        return fn(data)
    except Exception:
        record("parse_error")
        return None
