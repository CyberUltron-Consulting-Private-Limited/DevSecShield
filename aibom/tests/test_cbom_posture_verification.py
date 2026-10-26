"""Verification facts stay UNKNOWN and still record the explicit signal."""

from aibom.cbom.posture.verification import detect_verification


def test_one_fact_per_pattern_keeps_the_first_lines() -> None:
    lines = ["ok"] + ["verify CERT_NONE"] * 25
    facts = detect_verification("\n".join(lines), "app.py")
    assert len(facts) == 1
    fact = facts[0]
    assert fact.verdict == "UNKNOWN"
    assert fact.unknown_reason == "attribute_not_modeled"
    assert fact.finding_codes == ()
    basis = {item.name: item.value for item in fact.basis}
    assert basis["signal"] == "TLS_VERIFICATION_DISABLED"
    assert basis["match_count"] == "25"
    assert len(basis["match_lines"].split(",")) == 20


def test_disabled_algorithms_line_is_not_a_verification_hit() -> None:
    text = "jdk.tls.disabledAlgorithms=TLSv1, TLSv1.1\n"
    assert detect_verification(text, "java.security") == ()


def test_curl_insecure_flag_is_a_hit() -> None:
    facts = detect_verification("curl -k https://example.com\n", "fetch.sh")
    assert [fact.native_type for fact in facts] == ["curl.insecure"]
