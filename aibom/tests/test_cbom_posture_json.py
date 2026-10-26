"""JSON scan is linear, rejects depth 101, and keeps the last duplicate."""

from __future__ import annotations

import pytest

from aibom.cbom.posture.diagnostics import DiagnosticSink
from aibom.cbom.posture.jsonsafe import json_scan, load_json, parse_json
from support.generators import mutate_bytes


def test_duplicate_key_keeps_the_last_value() -> None:
    sink = DiagnosticSink()
    doc = parse_json('{\n  "a": 1,\n  "a": 2\n}\n', path="a.json", sink=sink)
    assert doc is not None
    assert doc.value == {"a": 2}
    assert [item.code for item in sink.stored()] == ["duplicate_key"]
    assert sink.stored()[0].line == 3


def test_nan_and_infinity_are_rejected() -> None:
    for text in ("[NaN]", "[Infinity]", "[-Infinity]"):
        sink = DiagnosticSink()
        assert parse_json(text, path="n.json", sink=sink) is None
        assert [item.code for item in sink.stored()] == ["parse_error"]


def test_depth_100_is_accepted_and_101_is_capped() -> None:
    assert json_scan("[" * 100 + "0" + "]" * 100).status == "ok"
    sink = DiagnosticSink()
    assert parse_json("[" * 100 + "0" + "]" * 100, path="d.json", sink=sink) is not None
    assert sink.stored() == ()
    capped = json_scan("[" * 101 + "0" + "]" * 101)
    assert capped.status == "depth_cap"
    sink = DiagnosticSink()
    assert parse_json("[" * 101 + "0" + "]" * 101, path="d.json", sink=sink) is None
    assert [item.code for item in sink.stored()] == ["depth_cap"]


def test_key_lines_follow_the_object_path() -> None:
    text = (
        '{\n  "Resources": {\n    "Bucket": {\n'
        '      "Type": "AWS::S3::Bucket"\n    }\n  }\n}\n'
    )
    doc = parse_json(text, path="cfn.json", sink=DiagnosticSink())
    assert doc is not None
    assert doc.key_lines[("Resources",)] == 2
    assert doc.key_lines[("Resources", "Bucket")] == 3
    assert doc.key_lines[("Resources", "Bucket", "Type")] == 4


def test_unterminated_string_is_parse_error() -> None:
    sink = DiagnosticSink()
    assert parse_json('{"a": "oops}', path="u.json", sink=sink) is None
    assert [item.code for item in sink.stored()] == ["parse_error"]


def test_bytes_return_a_result_or_one_diagnostic() -> None:
    seen: list[str] = []
    assert load_json(b"\xff\x00 not json", seen.append) is None
    assert seen == ["parse_error"]


@pytest.mark.parametrize("seed", range(1, 21))
def test_mutated_bytes_never_raise(seed: int) -> None:
    base = b'{"Resources": {"Bucket": {"Type": "AWS::S3::Bucket"}}}\n'
    for payload in mutate_bytes(seed, base=base):
        load_json(payload, lambda _code: None)
