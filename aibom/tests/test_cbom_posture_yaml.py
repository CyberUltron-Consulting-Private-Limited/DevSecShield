"""YAML uses a pure SafeLoader and caps a document before it builds objects."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from aibom.cbom.posture.diagnostics import DiagnosticSink
from aibom.cbom.posture.yamlsafe import (
    CFN_TAGS,
    LineDict,
    Tagged,
    _Loader,
    flatten_dotted,
    load_yaml,
    parse_yaml,
)
from support.generators import mutate_bytes

_SOURCE = (
    Path(__file__).resolve().parents[1]
    / "src"
    / "aibom"
    / "cbom"
    / "posture"
    / "yamlsafe.py"
)


def test_safe_loader_table_is_not_replaced() -> None:
    base = yaml.SafeLoader.yaml_constructors["tag:yaml.org,2002:map"]
    assert base is not _Loader.construct_yaml_map
    registered = _Loader.yaml_constructors["tag:yaml.org,2002:map"]
    assert registered is _Loader.construct_yaml_map
    assert "CSafeLoader" not in _SOURCE.read_text(encoding="utf-8")


def test_nested_maps_are_line_dicts() -> None:
    sink = DiagnosticSink()
    docs = parse_yaml("a: 1\nb:\n  c: 2\n", path="a.yml", sink=sink)
    assert docs is not None
    root = docs[0]
    assert isinstance(root, LineDict)
    assert root.line == 1
    assert isinstance(root["b"], LineDict)
    assert root["b"].line == 3


def test_cloudformation_tags_are_unresolved_nodes() -> None:
    text = "Ref: !Ref Bucket\nAtt: !GetAtt [Bucket, Arn]\nPlain: !reset later\n"
    sink = DiagnosticSink()
    docs = parse_yaml(text, path="cfn.yml", sink=sink)
    assert docs is not None
    doc = docs[0]
    assert doc["Ref"] == Tagged("Ref", "Bucket")
    assert doc["Att"] == Tagged("GetAtt", ["Bucket", "Arn"])
    assert doc["Plain"] == Tagged("reset", "later")
    assert [item.code for item in sink.stored()] == ["unknown_tag"]
    assert set(CFN_TAGS) >= {
        "Ref",
        "GetAtt",
        "Sub",
        "Join",
        "If",
        "FindInMap",
        "ImportValue",
        "Select",
        "Split",
        "Equals",
        "And",
        "Or",
        "Not",
        "Condition",
        "Base64",
        "Cidr",
        "GetAZs",
        "Transform",
    }


def test_python_object_tag_executes_nothing() -> None:
    called: list[str] = []

    def boom(command: str) -> None:
        called.append(command)

    original = __import__("os").system
    __import__("os").system = boom
    try:
        sink = DiagnosticSink()
        text = 'x: !!python/object/apply:os.system ["echo hi"]\n'
        docs = parse_yaml(text, path="bad.yml", sink=sink)
    finally:
        __import__("os").system = original
    assert docs == []
    assert called == []
    assert [item.code for item in sink.stored()] == ["unsafe_tag"]


def test_duplicate_key_keeps_the_last_value() -> None:
    sink = DiagnosticSink()
    docs = parse_yaml("a: 1\na: 2\n", path="d.yml", sink=sink)
    assert docs == [{"a": 2}]
    assert [(item.code, item.line) for item in sink.stored()] == [("duplicate_key", 2)]


def test_node_cap_drains_and_keeps_later_documents() -> None:
    stream = "a: 1\nb: 2\nc: 3\n---\nok: 1\n---\nz: 2\n"
    sink = DiagnosticSink()
    docs = parse_yaml(stream, path="s.yml", sink=sink, node_limit=3)
    assert docs == [{"ok": 1}, {"z": 2}]
    assert [item.code for item in sink.stored()] == ["node_cap"]


def test_alias_cap_drains_and_keeps_later_documents() -> None:
    stream = "a: &a 1\nb: *a\nc: *a\n---\nok: 1\n---\nz: 2\n"
    sink = DiagnosticSink()
    docs = parse_yaml(stream, path="a.yml", sink=sink, alias_limit=1)
    assert docs == [{"ok": 1}, {"z": 2}]
    assert [item.code for item in sink.stored()] == ["alias_cap"]


def test_alias_expansion_is_capped_before_construction() -> None:
    lines = ["l0: &a0 [1, 1]"]
    for index in range(17):
        lines.append(f"l{index + 1}: &a{index + 1} [*a{index}, *a{index}]")
    sink = DiagnosticSink()
    docs = parse_yaml("\n".join(lines) + "\n", path="bomb.yml", sink=sink)
    assert docs == []
    assert [item.code for item in sink.stored()] == ["alias_cap"]


def test_truncated_capped_document_records_parse_error() -> None:
    sink = DiagnosticSink()
    docs = parse_yaml("ok: 1\n---\na: [\n", path="cut.yml", sink=sink, node_limit=2)
    assert docs == [{"ok": 1}] or docs is None or docs == []
    codes = {item.code for item in sink.stored()}
    assert "parse_error" in codes or "node_cap" in codes


def test_depth_over_100_is_capped() -> None:
    value = "1"
    for _ in range(101):
        value = "{a: " + value + "}"
    sink = DiagnosticSink()
    assert parse_yaml(value + "\n", path="deep.yml", sink=sink) == []
    assert [item.code for item in sink.stored()] == ["depth_cap"]


def test_flatten_dotted_accepts_nested_and_dotted_keys() -> None:
    nested = flatten_dotted({"server": {"ssl": {"enabled": True}}})
    dotted = flatten_dotted({"server.ssl.enabled": True})
    assert nested["server.ssl.enabled"] is True
    assert dotted["server.ssl.enabled"] is True


def test_bytes_return_a_result_or_one_diagnostic() -> None:
    seen: list[str] = []
    assert load_yaml(b"\xff: [", seen.append) is None
    assert seen == ["parse_error"]


@pytest.mark.parametrize("seed", range(1, 21))
def test_mutated_bytes_never_raise(seed: int) -> None:
    for payload in mutate_bytes(seed, base=b"a: 1\nb:\n  c: 2\n"):
        load_yaml(payload, lambda _code: None)
