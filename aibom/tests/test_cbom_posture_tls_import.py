"""TLS imports stay UNKNOWN and do not score BEAST."""

from aibom.cbom.posture.tls_import import import_tls_result

_TESTSSL = """
{"scanResult":[{"targetHost":"example.com","port":"443","findings":[
{"id":"HEARTBLEED","severity":"HIGH"},{"id":"BEAST","severity":"LOW"}]}]}
""".strip()

_NOT_TESTED = """
{"scanResult":[{"targetHost":"example.com","port":"443","severity":"not_tested"}]}
""".strip()


def test_testssl_host_ip_splits_the_name_and_the_address() -> None:
    body = (
        b'{"scanResult":[{"ip":"example.com/192.0.2.10","port":"443",'
        b'"protocols":["TLSv1"]}]}'
    )
    fact = import_tls_result(body, "flat.json").facts[0]
    basis = {item.name: item.value for item in fact.basis}
    assert basis["endpoint"] == "example.com:443"
    assert basis["endpoint_alt"] == "192.0.2.10:443"
    assert basis["offered"] == "1.0"
    bare = (
        b'{"scanResult":[{"ip":"/192.0.2.10","port":"443"}]}'
    )
    other = import_tls_result(bare, "bare.json").facts[0]
    other_basis = {item.name: item.value for item in other.basis}
    assert other_basis["endpoint"] == "192.0.2.10:443"


def test_sslyze_and_nmap_record_the_endpoint() -> None:
    sslyze = (
        b'{"server_scan_results":[{"server_location":'
        b'{"hostname":"example.org","port":443}}]}'
    )
    left = import_tls_result(sslyze, "sslyze.json").facts[0]
    left_basis = {item.name: item.value for item in left.basis}
    assert left_basis["endpoint"] == "example.org:443"
    nmap = """
    <nmaprun>
      <host>
        <address addr="192.0.2.10" addrtype="ipv4"/>
        <hostnames><hostname name="app.example.test" type="user"/></hostnames>
        <ports><port protocol="tcp" portid="8443"/></ports>
      </host>
    </nmaprun>
    """.strip()
    right = import_tls_result(nmap.encode(), "nmap.xml").facts[0]
    right_basis = {item.name: item.value for item in right.basis}
    assert right_basis["endpoint"] == "app.example.test:8443"
    assert right_basis["endpoint_alt"] == "192.0.2.10:8443"


def test_offered_protocol_is_recorded_on_the_endpoint() -> None:
    body = (
        b'{"scanResult":[{"targetHost":"example.com","port":"443",'
        b'"protocols":["TLSv1","TLSv1.2"]}]}'
    )
    fact = import_tls_result(body, "versions.json").facts[0]
    basis = {item.name: item.value for item in fact.basis}
    assert basis["endpoint"] == "example.com:443"
    assert basis["offered"] == "1.0,1.2"


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


def test_fallback_scsv_problem_is_missing_downgrade_protection(tmp_path) -> None:
    from aibom.cbom.pipeline import scan_crypto

    (tmp_path / "result.json").write_text(
        '{"scanResult":[{"targetHost":"example.com","port":"443",'
        '"protocols":["TLSv1"],"findings":['
        '{"id":"TLS_FALLBACK_SCSV","severity":"LOW"}]}]}',
        encoding="utf-8",
    )
    result = scan_crypto(tmp_path)
    assert "DOWNGRADE_PROTECTION_MISSING" in {flag.code for flag in result.flags}
    ok = tmp_path / "ok.json"
    ok.write_text(
        '{"scanResult":[{"targetHost":"example.org","port":"443","findings":['
        '{"id":"TLS_FALLBACK_SCSV","severity":"OK"}]}]}',
        encoding="utf-8",
    )
    (tmp_path / "result.json").unlink()
    quiet = scan_crypto(tmp_path)
    assert "DOWNGRADE_PROTECTION_MISSING" not in {flag.code for flag in quiet.flags}
    (tmp_path / "ok.json").unlink()
    (tmp_path / "alone.json").write_text(
        '{"scanResult":[{"targetHost":"example.com","port":"443","findings":['
        '{"id":"TLS_FALLBACK_SCSV","severity":"LOW"}]}]}',
        encoding="utf-8",
    )
    alone = scan_crypto(tmp_path)
    assert "DOWNGRADE_PROTECTION_MISSING" not in {flag.code for flag in alone.flags}


def test_scored_import_is_a_known_vulnerability_flag(tmp_path) -> None:
    from aibom.cbom.pipeline import scan_crypto

    (tmp_path / "result.json").write_text(_TESTSSL + "\n", encoding="utf-8")
    result = scan_crypto(tmp_path)
    assert "KNOWN_TLS_VULNERABILITY" in {flag.code for flag in result.flags}
    assert all(flag.code != "NOT_ENCRYPTED" for flag in result.flags)
