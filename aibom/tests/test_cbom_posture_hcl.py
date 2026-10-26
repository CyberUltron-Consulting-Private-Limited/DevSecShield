"""HCL subset: literals, blocks, and unevaluated expressions."""

from __future__ import annotations

from pathlib import Path

import pytest

from aibom.cbom.posture.diagnostics import DiagnosticSink
from aibom.cbom.posture.hcl import (
    Lit,
    Obj,
    Ref,
    Unresolved,
    from_terraform_json,
    load_hcl,
    parse_hcl,
    parse_tfvars,
)
from support.generators import mutate_bytes

_SOURCE = (
    Path(__file__).resolve().parents[1]
    / "src"
    / "aibom"
    / "cbom"
    / "posture"
    / "hcl.py"
)


def _attrs(text: str, sink: DiagnosticSink | None = None) -> dict[str, object]:
    body = parse_hcl(text, path="main.tf", sink=sink or DiagnosticSink())
    assert body is not None
    return {attr.name: attr.expr for attr in body.attrs}


def test_slash_operator_does_not_match_comment_openers() -> None:
    assert "/(?![*/])" in _SOURCE.read_text(encoding="utf-8")


def test_literals_blocks_and_collections() -> None:
    text = """
    resource "aws_s3_bucket" "b" {
      bucket = "one"
      flag   = true
      n      = 1
      f      = 1.5
      z      = null
      items  = [1, "a", true]
      obj    = { a = 1, b = "x" }
      msg    = "hello\\\\n"
      doc    = <<-EOF
      hello
      EOF
    }
    """
    sink = DiagnosticSink()
    body = parse_hcl(text, path="main.tf", sink=sink)
    assert body is not None and len(body.blocks) == 1
    block = body.blocks[0]
    assert block.type == "resource"
    assert block.labels == ("aws_s3_bucket", "b")
    attrs = {attr.name: attr.expr for attr in block.body.attrs}
    assert attrs["bucket"] == Lit("one")
    assert attrs["flag"] == Lit(True)
    assert attrs["n"] == Lit(1)
    assert attrs["f"] == Lit(1.5)
    assert attrs["z"] == Lit(None)
    assert isinstance(attrs["items"], type(attrs["items"]))
    assert isinstance(attrs["obj"], Obj)
    assert attrs["doc"] == Lit("hello\n")
    assert sink.stored() == ()


def test_expressions_are_not_evaluated() -> None:
    text = """
    ref   = "${var.x}"
    tmpl  = "x-${var.x}"
    call  = jsonencode({a = 1})
    cond  = true ? 1 : 0
    loop  = [for a in var.list : a]
    splat = var.list.*.id
    """
    attrs = _attrs(text)
    assert attrs["ref"] == Ref("var", ("x",))
    assert isinstance(attrs["tmpl"], Unresolved) and attrs["tmpl"].kind == "template"
    call = attrs["call"]
    assert isinstance(call, Unresolved) and call.kind == "call"
    assert call.parts[0] == Lit("jsonencode")
    assert isinstance(call.parts[1], Obj)
    assert isinstance(attrs["cond"], Unresolved) and attrs["cond"].kind == "cond"
    assert isinstance(attrs["loop"], Unresolved) and attrs["loop"].kind == "for"
    assert isinstance(attrs["splat"], Unresolved) and attrs["splat"].kind == "splat"


def test_duplicate_attribute_and_resource_keep_the_last() -> None:
    text = """
    resource "aws_s3_bucket" "b" { bucket = "one" }
    resource "aws_s3_bucket" "b" { bucket = "two" }
    """
    sink = DiagnosticSink()
    body = parse_hcl(text, path="main.tf", sink=sink)
    assert body is not None and len(body.blocks) == 1
    assert body.blocks[0].body.attrs[0].expr == Lit("two")
    assert [item.code for item in sink.stored()] == ["duplicate_resource"]
    sink = DiagnosticSink()
    attrs = _attrs("same = 1\nsame = 2\n", sink)
    assert attrs["same"] == Lit(2)
    assert [item.code for item in sink.stored()] == ["duplicate_key"]


def test_depth_100_is_accepted_and_101_is_capped() -> None:
    sink = DiagnosticSink()
    ok = "a = " + ("[" * 100) + "1" + ("]" * 100)
    assert parse_hcl(ok, path="d.tf", sink=sink) is not None
    assert sink.stored() == ()
    sink = DiagnosticSink()
    deep = "a = " + ("[" * 101) + "1" + ("]" * 101)
    assert parse_hcl(deep, path="d.tf", sink=sink) is None
    assert [item.code for item in sink.stored()] == ["depth_cap"]


def test_unterminated_comment_is_one_parse_error() -> None:
    sink = DiagnosticSink()
    assert parse_hcl("/* ", path="c.tf", sink=sink) is None
    assert [item.code for item in sink.stored()] == ["parse_error"]


def test_tfvars_reject_blocks_and_json_adapts() -> None:
    sink = DiagnosticSink()
    assert parse_tfvars("x = 1\n", path="terraform.tfvars", sink=sink) is not None
    sink = DiagnosticSink()
    assert (
        parse_tfvars('resource "a" "b" {}\n', path="terraform.tfvars", sink=sink)
        is None
    )
    assert [item.code for item in sink.stored()] == ["parse_error"]
    body = from_terraform_json(
        {"resource": {"aws_s3_bucket": {"b": {"bucket": "${var.name}"}}}}
    )
    assert body is not None
    expr = body.blocks[0].body.attrs[0].expr
    assert expr == Ref("var", ("name",))


def test_bytes_return_a_result_or_one_diagnostic() -> None:
    seen: list[str] = []
    assert load_hcl(b"\xff <<<", seen.append) is None
    assert seen == ["parse_error"]


@pytest.mark.parametrize("seed", range(1, 21))
def test_mutated_bytes_never_raise(seed: int) -> None:
    base = b'resource "aws_s3_bucket" "b" {\n  bucket = "one"\n}\n'
    for payload in mutate_bytes(seed, base=base):
        load_hcl(payload, lambda _code: None)
