"""XML rejects a dangerous DOCTYPE before ElementTree parses it."""

from __future__ import annotations

import pytest

from aibom.cbom.posture.diagnostics import DiagnosticSink
from aibom.cbom.posture.xmlsafe import load_xml, parse_xml, xml_start_lines
from support.generators import mutate_bytes


def test_bare_doctype_parses() -> None:
    text = (
        '<?xml version="1.0"?>\n<!DOCTYPE nmaprun>\n<nmaprun>\n  <host/>\n</nmaprun>\n'
    )
    sink = DiagnosticSink()
    doc = parse_xml(text, path="scan.xml", sink=sink)
    assert doc is not None
    assert doc.root.tag == "nmaprun"
    assert doc.root.find("host") is not None
    assert sink.stored() == ()
    assert doc.start_lines["nmaprun"] == (3,)
    assert doc.start_lines["host"] == (4,)


def test_external_and_entity_doctypes_are_unsafe() -> None:
    samples = (
        '<!DOCTYPE x SYSTEM "file:///etc/passwd"><x/>',
        '<!DOCTYPE x PUBLIC "-//x" "http://example.test/x.dtd"><x/>',
        "<!DOCTYPE x [<!ELEMENT x ANY>]><x/>",
        '<!DOCTYPE x [<!ENTITY a "b">]><x>&a;</x>',
        "<!DOCTYPE nmaprun><!DOCTYPE nmaprun><nmaprun/>",
    )
    for text in samples:
        sink = DiagnosticSink()
        assert parse_xml(text, path="bad.xml", sink=sink) is None
        assert [item.code for item in sink.stored()] == ["unsafe_xml"]


def test_entity_inside_a_comment_is_not_a_doctype() -> None:
    text = '<!-- <!ENTITY a "b"> --><root/>'
    sink = DiagnosticSink()
    doc = parse_xml(text, path="ok.xml", sink=sink)
    assert doc is not None
    assert doc.root.tag == "root"
    assert sink.stored() == ()


def test_unterminated_comment_is_parse_error() -> None:
    sink = DiagnosticSink()
    assert parse_xml("<!-- no end <root/>", path="c.xml", sink=sink) is None
    assert [item.code for item in sink.stored()] == ["parse_error"]


def test_depth_101_is_capped() -> None:
    sink = DiagnosticSink()
    text = "<a>" * 101 + "</a>" * 101
    assert parse_xml(text, path="deep.xml", sink=sink) is None
    assert [item.code for item in sink.stored()] == ["depth_cap"]
    sink = DiagnosticSink()
    shallow = "<a>" * 100 + "</a>" * 100
    assert parse_xml(shallow, path="deep.xml", sink=sink) is not None


def test_start_lines_are_linear_on_brackets() -> None:
    lines = xml_start_lines("<root><child/></root>")
    assert lines["root"] == (1,)
    assert lines["child"] == (1,)


def test_bytes_return_a_result_or_one_diagnostic() -> None:
    seen: list[str] = []
    assert load_xml(b"\xff<not", seen.append) is None
    assert seen == ["parse_error"]


@pytest.mark.parametrize("seed", range(1, 21))
def test_mutated_bytes_never_raise(seed: int) -> None:
    base = b"<!DOCTYPE nmaprun><nmaprun><host/></nmaprun>"
    for payload in mutate_bytes(seed, base=base):
        load_xml(payload, lambda _code: None)
