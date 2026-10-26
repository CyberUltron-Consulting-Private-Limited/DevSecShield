"""Pattern linter. Backtracking shapes fail before a registry accepts them."""

from __future__ import annotations

import json

import pytest

from aibom.cbom.posture.defaults import (
    MATCHER_KINDS,
    TOKEN_PATTERNS,
    RegistryError,
    build_registry,
    compiled_registry_patterns,
    lint_pattern,
    lint_token_pattern,
)


def _patterns(rows: list[dict[str, object]]) -> bytes:
    body = {"data_version": 1, "valid_as_of": "2026-10-26", "rows": rows}
    return json.dumps(body).encode("utf-8")


def test_matcher_kinds_are_literal_command_flag_and_anchor_window() -> None:
    assert frozenset({"literal", "command_flag", "anchor_window"}) == MATCHER_KINDS


@pytest.mark.parametrize(
    "source",
    [
        "a.*b",
        "a.+b",
        r"a\S*b",
        r"\bwget\b.*--no-check-certificate",
        "(a+)+",
        "(a|b)*",
        "(?<=a)b",
        r"a{0,257}",
        "a+b+",
    ],
)
def test_control_patterns_that_backtrack_fail(source: str) -> None:
    assert lint_pattern(source)


def test_bounded_and_whitespace_shapes_pass() -> None:
    assert lint_pattern(r"\bwget\b\s+--no-check-certificate\b") == ()
    assert lint_pattern(r"TLS_AES_128_GCM_SHA256") == ()
    assert lint_pattern(r"prefix\s*suffix") == ()
    assert lint_token_pattern(TOKEN_PATTERNS[0].pattern) == ()


def test_registry_rejects_a_backtracking_control_pattern() -> None:
    rows = [
        {"id": "bad.literal", "matcher": "literal", "pattern": "insecure.*transport"},
        {
            "id": "bad.anchor",
            "matcher": "anchor_window",
            "anchor": "callback",
            "window": 64,
            "tail": ".*true",
        },
    ]
    for row in rows:
        with pytest.raises(RegistryError, match="backtracking"):
            build_registry({"verification_patterns.json": _patterns([row])})


def test_three_matcher_kinds_load_when_the_pattern_is_safe() -> None:
    rows = [
        {"id": "pin.literal", "matcher": "literal", "pattern": "ssl_verify = false"},
        {
            "id": "pin.flag",
            "matcher": "command_flag",
            "command": "curl",
            "short_flags": ["k"],
            "long_flags": ["--insecure"],
            "max_tokens": 64,
        },
        {
            "id": "pin.anchor",
            "matcher": "anchor_window",
            "anchor": "ServerCertificateValidationCallback",
            "window": 256,
            "tail": r"\s*true",
        },
    ]
    registry = build_registry({"verification_patterns.json": _patterns(rows)})
    assert [item.matcher for item in registry.patterns] == [
        "literal",
        "command_flag",
        "anchor_window",
    ]
    compiled = compiled_registry_patterns(registry)
    assert len(compiled) == 1
    assert compiled[0].search(" true")


def test_unknown_matcher_and_oversized_window_fail() -> None:
    with pytest.raises(RegistryError, match="matcher"):
        build_registry(
            {
                "verification_patterns.json": _patterns(
                    [{"id": "x", "matcher": "regex", "pattern": "tls"}]
                )
            }
        )
    with pytest.raises(RegistryError, match="window"):
        build_registry(
            {
                "verification_patterns.json": _patterns(
                    [
                        {
                            "id": "wide",
                            "matcher": "anchor_window",
                            "anchor": "callback",
                            "window": 257,
                            "tail": "true",
                        }
                    ]
                )
            }
        )
