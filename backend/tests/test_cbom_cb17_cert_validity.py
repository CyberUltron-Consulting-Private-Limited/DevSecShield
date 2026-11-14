"""CB-17: certificate validity, chain and keystore rules (DEVILS-ADVOCATE CB-17; R5 X7/X9a probes).

* CERT_NOT_YET_VALID: a certificate whose validity has not started;
* CERT_EXPIRES_30D is relative to the certificate's lifetime (a fresh 30-day or 6-day certificate is not flagged);
* CERT_CHAIN_EXTRA_EXPIRED (Low): an expired cross-sign clients do not need, instead of CERT_EXPIRED (High);
* CHAIN_INCOMPLETE: the server does not send a certificate the chain needs;
* the asset name falls back to the first SAN; keystore entries are certificates judged like any other.
Every new code has a knowledge-base entry with its fix_class and VEX rows (single source: build_kb.py).
"""
from __future__ import annotations

import datetime as dt
import json
import pathlib
import types

import pytest

from backend.utilities.cbom_sources import classify as C
from backend.utilities.cbom_sources import crypto_kb, exploit_demo, jobs

NOW = dt.datetime(2026, 11, 14, 12, 0, 0)
ROOT = pathlib.Path(__file__).resolve().parents[2]
NEW_CODES = ("CERT_NOT_YET_VALID", "CERT_CHAIN_EXTRA_EXPIRED", "CHAIN_INCOMPLETE")


def _iso(days: float) -> str:
    return (NOW + dt.timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _cert(**facts):
    base = {"subject": "CN=shop.example.com", "issuer": "CN=Issuing R3", "sig_alg": "sha256WithRSAEncryption",
            "not_before": _iso(-10), "not_after": _iso(300)}
    return C.classify("certificate", "RSA", 2048, None, {**base, **facts}, NOW)


def test_a_not_yet_valid_certificate_is_a_finding():
    v = _cert(not_before=_iso(200), not_after=_iso(565))
    assert "CERT_NOT_YET_VALID" in v["finding_codes"] and v["impacts"]["CERT_NOT_YET_VALID"] == "Medium"
    assert "2027-06-02" in v["texts"]["CERT_NOT_YET_VALID"]
    # a start date hours ahead (clock skew, a keytool date in a local time zone) is not a finding
    assert "CERT_NOT_YET_VALID" not in _cert(not_before=_iso(0.5))["finding_codes"]


def test_expiry_warning_is_relative_to_the_certificate_lifetime():
    fresh30 = _cert(not_before=_iso(0), not_after=_iso(30))
    assert "CERT_EXPIRES_30D" not in fresh30["finding_codes"]  # R5 X7c: fresh 30-day lab certificates were flagged
    late30 = _cert(not_before=_iso(-21), not_after=_iso(9))
    assert "CERT_EXPIRES_30D" in late30["finding_codes"] and "30-day lifetime" in late30["texts"]["CERT_EXPIRES_30D"]
    assert "CERT_EXPIRES_30D" not in _cert(not_before=_iso(0), not_after=_iso(6))["finding_codes"]
    assert "CERT_EXPIRES_30D" in _cert(not_before=_iso(-5), not_after=_iso(1))["finding_codes"]
    # a 90-day (or longer) certificate keeps the 30-day window, and so does one without a start date
    assert "CERT_EXPIRES_30D" in _cert(not_before=_iso(-61), not_after=_iso(29))["finding_codes"]
    assert "CERT_EXPIRES_30D" in _cert(not_before=None, not_after=_iso(29))["finding_codes"]


def test_an_expired_extra_cross_sign_is_low_and_a_needed_intermediate_stays_high():
    extra = _cert(subject="CN=Root X1", issuer="CN=Old Root", is_ca=True, not_before=_iso(-900),
                  not_after=_iso(-30), chain_index=2, chain_extra=True, chain_top=True, chain_issuer="missing")
    assert "CERT_EXPIRED" not in extra["finding_codes"] and extra["impact"] == "Low"
    assert extra["impacts"]["CERT_CHAIN_EXTRA_EXPIRED"] == "Low"
    needed = _cert(subject="CN=Issuing R3", issuer="CN=Root X1", is_ca=True, not_after=_iso(-5), chain_index=1,
                   chain_extra=False, chain_top=True, chain_issuer="missing")
    assert "CERT_EXPIRED" in needed["finding_codes"] and needed["impact"] == "High"
    # chain_extra on the leaf position is never trusted (a leaf is always needed)
    assert "CERT_EXPIRED" in _cert(not_after=_iso(-1), chain_index=0, chain_extra=True)["finding_codes"]


def test_chain_incomplete_when_the_server_leaves_out_a_needed_certificate():
    # the leaf alone, issued by an intermediate the CA publishes for download (AIA caIssuers)
    alone = _cert(chain_index=0, chain_top=True, chain_issuer="missing", aia_ca_issuers=True, is_ca=False)
    assert "CHAIN_INCOMPLETE" in alone["finding_codes"] and "CN=Issuing R3" in alone["texts"]["CHAIN_INCOMPLETE"]
    # a gap inside the chain: the certificate above the leaf is not its issuer
    gap = _cert(chain_index=0, chain_top=False, chain_issuer="missing")
    assert "CHAIN_INCOMPLETE" in gap["finding_codes"]
    # not findings: a top intermediate whose root is not sent (roots are not sent), an issuer the node trusts,
    # a leaf alone without AIA (a private root may issue it directly), a self-signed certificate
    assert "CHAIN_INCOMPLETE" not in _cert(is_ca=True, chain_index=1, chain_top=True, chain_issuer="missing",
                                           aia_ca_issuers=True)["finding_codes"]
    assert "CHAIN_INCOMPLETE" not in _cert(chain_index=0, chain_top=True, chain_issuer="trusted",
                                           aia_ca_issuers=True)["finding_codes"]
    assert "CHAIN_INCOMPLETE" not in _cert(chain_index=0, chain_top=True, chain_issuer="missing",
                                           aia_ca_issuers=False)["finding_codes"]
    assert "CHAIN_INCOMPLETE" not in _cert(chain_index=0, chain_top=True, chain_issuer="self")["finding_codes"]


def test_k8s_tls_secret_leaf_gets_the_chain_rules_too():
    v = C.classify("k8s_tls_secret", "EC", 256, None, {"subject": "CN=a", "issuer": "CN=I", "not_before": _iso(-1),
                                                      "not_after": _iso(80), "chain_index": 0, "chain_top": True,
                                                      "chain_issuer": "missing", "aia_ca_issuers": True}, NOW)
    assert "CHAIN_INCOMPLETE" in v["finding_codes"]


def test_a_jks_entry_with_an_expired_rsa_1024_key_is_judged_as_a_certificate():
    v = C.classify("certificate", "RSA", 1024, None, {"source": "keystore", "keystore": "/opt/a.jks", "alias": "old",
                                                     "subject": "CN=old", "issuer": "CN=old", "self_signed": True,
                                                     "not_before": "2024-01-01T00:00:00Z",
                                                     "not_after": "2025-01-01T00:00:00Z", "sig_alg": "SHA256withRSA"},
                   NOW)
    assert {"CERT_EXPIRED", "RSA_LT_2048"} <= set(v["finding_codes"])


def test_not_yet_valid_and_extra_expiry_are_judged_today_not_frozen_at_the_run():
    assert {"CERT_NOT_YET_VALID", "CERT_CHAIN_EXTRA_EXPIRED"} <= C.DATE_CODES
    facts = {"subject": "CN=a", "issuer": "CN=I", "not_before": _iso(3), "not_after": _iso(400)}
    stored = C.classify("certificate", "RSA", 2048, None, facts, NOW)
    row = types.SimpleNamespace(asset_type="certificate", algorithm="RSA", key_size=2048, protocol=None, facts=facts,
                                created_at=NOW, impact=stored["impact"], finding=stored["finding"],
                                finding_codes=stored["finding_codes"])
    assert "CERT_NOT_YET_VALID" in stored["finding_codes"]
    today = C.shown(row, NOW + dt.timedelta(days=10))
    assert "CERT_NOT_YET_VALID" not in today["finding_codes"] and today["as_of_run"] is not None


def test_the_asset_name_falls_back_to_the_first_san_and_the_key_does_not_move():
    job = types.SimpleNamespace(team_id=1, run_id=1, id=1, source_id=1, attempts=1)
    raw = {"type": "certificate", "location": "10.0.0.5:443#chain[0]", "name": "", "algorithm": "EC",
           "facts": {"subject": "", "san": ["shop.example.com", "www.example.com"], "san_count": 2,
                     "fingerprint_sha256": "ab" * 32}}
    rows, rejected, _dups = jobs.asset_rows(job, [raw], [], NOW)
    assert rejected == 0 and rows[0]["name"] == "shop.example.com"
    assert rows[0]["asset_key"] == jobs._asset_key("certificate", None, "10.0.0.5:443#chain[0]", raw["facts"], None)
    named = {**raw, "name": "CN=shop"}
    assert jobs.asset_rows(job, [named], [], NOW)[0][0]["name"] == "CN=shop"


@pytest.mark.parametrize("code", NEW_CODES)
def test_every_new_code_has_a_kb_entry_with_fix_class_and_vex_rows(code):
    entry = crypto_kb.entry("node", code)
    assert entry and entry["title"] and entry["default_impact"] in ("Medium", "Low")
    assert entry["fix_class"]["class"] == "configurable" and entry["vex_default"]["basis"]
    src = ROOT / "scripts/crypto_kb/sources"
    assert code in json.loads((src / "fix_class.json").read_text())["node"]
    assert code in json.loads((src / "vex_default.json").read_text())["node"]


@pytest.mark.parametrize("code", NEW_CODES)
def test_every_new_code_gets_a_read_only_proof(code):
    entries = crypto_kb.render("node", [code], context={"host": "shop.example.com", "port": "443"}, evidence="",
                               title="shop.example.com")
    demo = exploit_demo.build({"title": "shop.example.com", "finding_codes": [code], "location": "shop.example.com"},
                              entries)
    assert demo is not None and demo["code"] == code and demo["poc"] is None
