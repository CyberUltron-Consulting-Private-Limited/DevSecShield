"""TOML depth is capped before tomllib, and a repeated key is a parse error."""

from __future__ import annotations

import pytest

from aibom.cbom.posture.diagnostics import DiagnosticSink
from aibom.cbom.posture.tomlsafe import load_toml, parse_toml, toml_scan
from support.generators import mutate_bytes


def test_table_header_line_and_value() -> None:
    sink = DiagnosticSink()
    doc = parse_toml("[server]\nenabled = true\n", path="a.toml", sink=sink)
    assert doc is not None
    assert doc.value == {"server": {"enabled": True}}
    assert doc.headers["server"] == 1
    assert sink.stored() == ()


def test_repeated_key_is_parse_error() -> None:
    sink = DiagnosticSink()
    assert parse_toml("a = 1\na = 2\n", path="a.toml", sink=sink) is None
    assert [item.code for item in sink.stored()] == ["parse_error"]


def test_depth_100_is_accepted_and_101_is_capped() -> None:
    assert toml_scan("[" * 100 + "1" + "]" * 100) == "ok"
    sink = DiagnosticSink()
    nested = "a = " + ("[" * 100) + "1" + ("]" * 100)
    assert parse_toml(nested, path="d.toml", sink=sink) is not None
    assert toml_scan("[" * 101) == "depth_cap"
    sink = DiagnosticSink()
    assert parse_toml("a = " + "[" * 101, path="d.toml", sink=sink) is None
    assert [item.code for item in sink.stored()] == ["depth_cap"]


def test_unterminated_string_is_parse_error() -> None:
    sink = DiagnosticSink()
    assert parse_toml('a = "oops\n', path="u.toml", sink=sink) is None
    assert [item.code for item in sink.stored()] == ["parse_error"]


def test_bytes_return_a_result_or_one_diagnostic() -> None:
    seen: list[str] = []
    assert load_toml(b"\xff[[[", seen.append) is None
    assert seen == ["parse_error"]


@pytest.mark.parametrize("seed", range(1, 21))
def test_mutated_bytes_never_raise(seed: int) -> None:
    for payload in mutate_bytes(seed, base=b"[server]\nenabled = true\n"):
        load_toml(payload, lambda _code: None)
