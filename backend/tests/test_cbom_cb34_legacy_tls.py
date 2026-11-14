"""CB-34 legacy TLS: what the classifier makes of an endpoint the scan node found accepting SSLv3 / TLS 1.0 / 1.1 and
EXPORT, NULL, anonymous, RC4 and 3DES suites (scan_node/tests/test_legacy_tls.py produces these facts from local
servers). EXPORT, NULL and anonymous suites get their own codes next to WEAK_CIPHER: their impact is worse than
"weak", and each has its own fix."""
from __future__ import annotations

import datetime as dt

import pytest

from backend.utilities.cbom_sources import crypto_kb
from backend.utilities.cbom_sources import classify as C

NOW = dt.datetime(2026, 11, 15)


def _codes(facts: dict, cipher: str = "TLS_RSA_WITH_RC4_128_MD5", proto: str = "SSLv3") -> dict:
    out = C.classify("tls_endpoint", cipher, None, proto, facts, NOW)
    return {c: (out.get("impacts") or {}).get(c) for c in out["finding_codes"]}


def test_a_legacy_only_server_gets_its_protocol_and_suite_findings():
    facts = {"versions": {"SSLv3": True, "TLSv1.0": True, "TLSv1.1": False, "TLSv1.2": False, "TLSv1.3": False},
             "weak_ciphers_accepted": {"obsolete": [
                 "TLS_RSA_WITH_RC4_128_MD5", "TLS_RSA_EXPORT_WITH_RC4_40_MD5", "TLS_RSA_WITH_NULL_SHA",
                 "TLS_DH_anon_WITH_AES_128_CBC_SHA", "TLS_RSA_WITH_3DES_EDE_CBC_SHA"]},
             "certificate_source": "raw_flight", "tls": True}
    codes = _codes(facts)
    assert codes["TLS_EXPORT_CIPHER"] == "Critical" and codes["TLS_NULL_CIPHER"] == "Critical"
    assert codes["TLS_ANON_CIPHER"] == "High"
    assert {"PROTO_SSLv3", "PROTO_TLS10", "NO_TLS12", "WEAK_CIPHER", "TLS_EXPORT_CIPHER", "TLS_NULL_CIPHER",
            "TLS_ANON_CIPHER"} <= set(codes)


@pytest.mark.parametrize("suite,code", [
    ("TLS_RSA_EXPORT_WITH_DES40_CBC_SHA", "TLS_EXPORT_CIPHER"),
    ("TLS_RSA_EXPORT1024_WITH_RC4_56_SHA", "TLS_EXPORT_CIPHER"),
    ("EXP-RC4-MD5", "TLS_EXPORT_CIPHER"),
    ("TLS_ECDHE_RSA_WITH_NULL_SHA", "TLS_NULL_CIPHER"),
    ("NULL-SHA256", "TLS_NULL_CIPHER"),
    ("TLS_ECDH_anon_WITH_AES_256_CBC_SHA", "TLS_ANON_CIPHER"),
    ("ADH-AES128-GCM-SHA256", "TLS_ANON_CIPHER"),
])
def test_each_class_in_iana_and_openssl_spelling(suite, code):
    codes = _codes({"versions": {"TLSv1.2": True}, "ciphers": [suite], "tls": True}, suite, "TLSv1.2")
    assert code in codes and "WEAK_CIPHER" in codes


@pytest.mark.parametrize("suite", ["TLS_RSA_WITH_RC4_128_SHA", "TLS_RSA_WITH_3DES_EDE_CBC_SHA", "DES-CBC3-SHA"])
def test_rc4_and_3des_stay_weak_cipher_only(suite):
    codes = _codes({"versions": {"TLSv1.2": True}, "ciphers": [suite], "tls": True}, suite, "TLSv1.2")
    assert "WEAK_CIPHER" in codes
    assert not {"TLS_EXPORT_CIPHER", "TLS_NULL_CIPHER", "TLS_ANON_CIPHER"} & set(codes)


def test_a_modern_endpoint_gets_none_of_them():
    facts = {"versions": {"TLSv1.2": True, "TLSv1.3": True, "TLSv1.1": False, "TLSv1.0": False, "SSLv3": False},
             "ciphers": ["TLS_AES_128_GCM_SHA256", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"],
             "weak_ciphers_accepted": {}, "tls": True}
    codes = _codes(facts, "TLS_AES_128_GCM_SHA256", "TLSv1.3")
    assert not {"PROTO_SSLv3", "PROTO_TLS10", "PROTO_TLS11", "WEAK_CIPHER", "TLS_EXPORT_CIPHER", "TLS_NULL_CIPHER",
                "TLS_ANON_CIPHER"} & set(codes)


@pytest.mark.parametrize("code,impact", [("TLS_EXPORT_CIPHER", "Critical"), ("TLS_NULL_CIPHER", "Critical"),
                                         ("TLS_ANON_CIPHER", "High")])
def test_the_codes_are_in_the_kb_with_fix_class_vex_and_clauses(code, impact):
    entry = crypto_kb.entry("node", code)
    assert entry["default_impact"] == impact
    assert entry["fix_class"]["class"] == "configurable"
    assert entry["vex_default"]["basis"] == "observed"
    assert "rbi-cb-2026-para-140" in entry["clauses"] and "certin-bom-8.4.2.2" in entry["clauses"]
