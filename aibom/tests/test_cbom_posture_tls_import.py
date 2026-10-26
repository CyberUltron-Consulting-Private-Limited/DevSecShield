"""TLS imports stay UNKNOWN and do not score BEAST."""

from aibom.cbom.posture.tls_import import import_tls_result

_TESTSSL = """
{"scanResult":[{"targetHost":"example.com","port":"443","findings":[
{"id":"HEARTBLEED","severity":"HIGH"},{"id":"BEAST","severity":"LOW"}]}]}
""".strip()

_NOT_TESTED = """
{"scanResult":[{"targetHost":"example.com","port":"443","severity":"not_tested"}]}
""".strip()


def test_scored_and_unscored_vulnerabilities_split() -> None:
    batch = import_tls_result(_TESTSSL.encode(), "a.json")
    fact = batch.facts[0]
    assert fact.verdict == "UNKNOWN"
    basis = {item.name: item.value for item in fact.basis}
    assert basis["reported"] == "BEAST"
    assert basis["vulnerabilities"] == "HEARTBLEED"
    assert "NOT_ENCRYPTED" not in fact.layers.values()


def test_not_tested_raises_nothing() -> None:
    batch = import_tls_result(_NOT_TESTED.encode(), "b.json")
    fact = batch.facts[0]
    assert fact.unknown_reason == "import_not_tested"
    assert all(item.name != "signal" for item in fact.basis)


def test_same_endpoint_in_two_files_stays_two_facts() -> None:
    body = (
        b'{"server_scan_results":[{"server_location":'
        b'{"hostname":"example.org","port":443}}]}'
    )
    left = import_tls_result(body, "one.json")
    right = import_tls_result(body, "two.json")
    assert left.facts[0].id != right.facts[0].id


def test_oversize_and_unknown_format() -> None:
    huge = b'{"scanResult":[]}' + b" " * 20_971_520
    assert import_tls_result(huge, "big.json").notes[0].code == "size_cap"
    assert import_tls_result(b"hello", "note.txt").notes[0].code == (
        "unsupported_result_format"
    )


def test_public_host_is_redacted() -> None:
    body = b'{"scanResult":[{"targetHost":"bank.example","port":"443"}]}'
    fact = import_tls_result(body, "c.json").facts[0]
    basis = {item.name: item.value for item in fact.basis}
    assert basis["host"] == "redacted"
