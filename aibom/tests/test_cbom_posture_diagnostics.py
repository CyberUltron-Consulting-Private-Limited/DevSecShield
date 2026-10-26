"""Diagnostic sink bounds and idempotence."""

from aibom.cbom.posture.diagnostics import DIAGNOSTIC_CODES, DiagnosticSink, safe_parse


def test_add_is_idempotent_and_sorted() -> None:
    sink = DiagnosticSink(limit=10)
    sink.add("size_cap", "b.txt", 2)
    sink.add("size_cap", "b.txt", 2)
    sink.add("line_cap", "a.txt", 1)
    stored = sink.stored()
    assert [(item.path, item.line, item.code) for item in stored] == [
        ("a.txt", 1, "line_cap"),
        ("b.txt", 2, "size_cap"),
    ]
    assert sink.totals["size_cap"] == 1


def test_stored_cap_keeps_the_exact_total() -> None:
    sink = DiagnosticSink(limit=1)
    sink.add("parse_error", "a", 1)
    sink.add("parse_error", "b", 1)
    assert len(sink.stored()) == 1
    assert sink.totals["parse_error"] == 2


def test_unknown_code_is_rejected() -> None:
    try:
        DiagnosticSink().add("not-a-code", "a", 1)
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_codes_cover_the_walker() -> None:
    codes = (
        "special_file_skipped",
        "size_cap",
        "binary_skipped",
        "scan_budget_exhausted",
    )
    for code in codes:
        assert code in DIAGNOSTIC_CODES


def test_safe_parse_swallows_parser_errors() -> None:
    seen: list[str] = []

    def boom(_data: bytes) -> None:
        raise RuntimeError("bad")

    assert safe_parse(boom, b"x", seen.append) is None
    assert seen == ["parse_error"]
