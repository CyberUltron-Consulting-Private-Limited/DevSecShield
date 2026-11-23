"""S1 (SOW Table 5): the CBOM CI/CD policy gate blocks banned algorithms and weak key sizes, per team policy.

The policy (``utilities/cicd/gate_policy.py``, vendored byte-identical into ``aibom/src/aibom/cbom/gate_policy.py`` for
the offline ``aibom cbom`` gate) is judged on the run-object rows the hosted scan returns. Expected verdicts come from
NIST SP 800-131A Rev. 2 (RSA, DSA and DH below 2048 bits, and two-key/three-key TDEA for encryption after 2023, are
disallowed; SHA-1 is deprecated / disallowed for signature generation), FIPS 186-5 (DSA is no longer approved for
signature generation) and CNSA 2.0 (RSA 3072, P-384, AES-256; quantum-vulnerable public-key algorithms are phased
out), never from a product view.

Run (repo root): cd backend && PYTHONPATH=.. python -m pytest tests/test_cbom_gate_policy.py -q
"""
from __future__ import annotations

import datetime as dt
import json
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.utilities.cicd import cbom_gate  # noqa: E402
from backend.utilities.cicd import gate_policy as GP  # noqa: E402

TODAY = dt.date(2026, 11, 23)


def _row(title, codes=(), *, primitive=None, key_size=None, curve=None, qv=False, location="app/keys.py", line=5,
         asset_type="algorithm"):
    return {"title": title, "finding_codes": list(codes), "primitive": primitive, "key_size": key_size,
            "curve": curve, "quantum_vulnerable": qv, "location": location, "line": line, "impact": "High",
            "asset_type": asset_type, "bom_ref": f"ref-{title}"}


def _policy(**over):
    raw = json.loads(json.dumps(GP.DEFAULT_POLICY))
    raw.update(over)
    return GP.validate_policy(raw)


def _rules(gate, bucket="failing"):
    return [[r["rule"] for r in entry["rules"]] for entry in gate[bucket]]


# ------------------------------------------------------------------------------------------------ the vendored copy
def test_the_offline_gate_uses_the_same_policy_code_byte_for_byte():
    backend_copy = (ROOT / "backend/utilities/cicd/gate_policy.py").read_bytes()
    engine_copy = (ROOT / "aibom/src/aibom/cbom/gate_policy.py").read_bytes()
    assert backend_copy == engine_copy


def test_the_default_policy_keeps_every_legacy_fail_code():
    assert set(GP.DEFAULT_POLICY["block_codes"]) == set(cbom_gate.FAIL_CODES)


def test_default_matches_sp800_131a_and_cnsa_preset_is_stricter():
    d, c = GP.DEFAULT_POLICY, GP.PRESETS["cnsa-2.0"]
    assert d["min_key_bits"] == {"rsa": 2048, "dsa": 2048, "dh": 2048, "ec": 256, "symmetric": 128}
    assert d["quantum_vulnerable"] == "warn" and d["deprecated"] == "warn"
    assert {"MD5", "DES", "3DES", "RC4"} <= set(d["banned_algorithms"])
    assert c["min_key_bits"] == {"rsa": 3072, "dsa": 3072, "dh": 3072, "ec": 384, "symmetric": 256}
    assert c["quantum_vulnerable"] == "fail" and c["deprecated"] == "fail"
    for preset in GP.PRESETS.values():
        assert GP.validate_policy(preset) == preset


# ------------------------------------------------------------------------------------------------ per rule: fail/pass
@pytest.mark.parametrize(("row", "fails"), [
    (_row("MD5", primitive="hash"), True),
    (_row("DES-ECB", primitive="block-cipher", key_size="56"), True),
    (_row("DESede", primitive="block-cipher"), True),  # 3DES alias
    (_row("TripleDES-CBC", primitive="block-cipher"), True),
    (_row("RC4", primitive="stream-cipher"), True),
    (_row("HMAC-MD5", primitive="mac"), True),
    (_row("MD5withRSA", primitive="signature", key_size="2048"), True),
    (_row("AES-256-GCM", primitive="ae", key_size="256"), False),
    (_row("SHA-256", primitive="hash"), False),
    (_row("ChaCha20-Poly1305", primitive="ae"), False),
])
def test_banned_algorithm_rule(row, fails):
    gate = cbom_gate.evaluate({"results": [row]}, policy=_policy(block_codes=[]))
    assert (gate["verdict"] == "fail") is fails, gate
    if fails:
        assert _rules(gate) == [["banned_algorithm"]]
        assert gate["rules_failed"] == {"banned_algorithm": 1}


@pytest.mark.parametrize(("row", "fails"), [
    (_row("RSA-1024", primitive="pke", key_size="1024", qv=True), True),
    (_row("RSA-2048", primitive="pke", key_size="2048", qv=True), False),
    (_row("RSA", primitive="pke", key_size=None, qv=True), False),  # unknown size: never guessed
    (_row("DSA-1024", primitive="signature"), True),
    (_row("DH", primitive="key-agree", key_size="1024", qv=True), True),
    (_row("ffdhe2048", primitive="key-agree", qv=True), False),
    (_row("ECDSA", primitive="signature", curve="SECP256R1", qv=True), False),
    (_row("ECDSA", primitive="signature", curve="secp224r1", qv=True), True),
    (_row("ECDH", primitive="key-agree", curve="prime192v1", qv=True), True),
    (_row("P-384", primitive="signature", qv=True), False),
    (_row("brainpoolP160r1", primitive="signature", qv=True), True),
    (_row("Ed25519", primitive="signature", qv=True), False),
    (_row("AES-128-GCM", primitive="ae", key_size="128"), False),
    (_row("Blowfish", primitive="block-cipher", key_size="64"), True),
    (_row("AES", primitive="block-cipher"), False),
])
def test_min_key_size_rule(row, fails):
    gate = cbom_gate.evaluate({"results": [row]}, policy=_policy(block_codes=[], deprecated="off",
                                                                     quantum_vulnerable="off"))
    assert (gate["verdict"] == "fail") is fails, gate
    if fails:
        assert _rules(gate) == [["min_key_size"]]
        detail = gate["failing"][0]["rules"][0]["detail"]
        assert "below the policy minimum" in detail


def test_min_key_size_follows_the_team_numbers():
    rsa2048 = _row("RSA-2048", primitive="pke", key_size="2048", qv=True)
    strict = _policy(block_codes=[], quantum_vulnerable="off", min_key_bits={**GP.DEFAULT_POLICY["min_key_bits"], "rsa": 3072})
    assert cbom_gate.evaluate({"results": [rsa2048]}, policy=strict)["verdict"] == "fail"
    assert cbom_gate.evaluate({"results": [rsa2048]}, policy=_policy(block_codes=[]))["verdict"] == "pass"
    aes128 = _row("AES-128-GCM", primitive="ae", key_size="128")
    sym256 = _policy(block_codes=[], min_key_bits={**GP.DEFAULT_POLICY["min_key_bits"], "symmetric": 256})
    assert _rules(cbom_gate.evaluate({"results": [aes128]}, policy=sym256)) == [["min_key_size"]]


@pytest.mark.parametrize("mode", ["off", "warn", "fail"])
def test_quantum_vulnerable_rule_off_warn_fail(mode):
    rows = [_row("RSA-3072", ["QUANTUM_VULNERABLE"], primitive="pke", key_size="3072", qv=True),
            _row("ECDSA", ["QUANTUM_VULNERABLE"], primitive="signature", curve="P-384", qv=True)]
    gate = cbom_gate.evaluate({"results": rows}, policy=_policy(quantum_vulnerable=mode))
    if mode == "fail":
        assert gate["verdict"] == "fail" and gate["failing_count"] == 2
        assert _rules(gate) == [["quantum_vulnerable"], ["quantum_vulnerable"]]
    else:
        assert gate["verdict"] == "pass"
        assert gate["warning_count"] == (2 if mode == "warn" else 0)
        if mode == "warn":
            assert {r["outcome"] for e in gate["warnings"] for r in e["rules"]} == {"warn"}


@pytest.mark.parametrize("mode", ["off", "warn", "fail"])
def test_deprecated_sp800_131a_rule(mode):
    rows = [_row("SHA-1", primitive="hash"), _row("DSA", primitive="signature", key_size="3072", qv=True),
            _row("HMAC-SHA1", primitive="mac"), _row("SHA-256", primitive="hash")]
    gate = cbom_gate.evaluate({"results": rows}, policy=_policy(deprecated=mode, quantum_vulnerable="off"))
    flagged = gate["failing"] if mode == "fail" else gate["warnings"]
    titles = sorted(e["title"] for e in flagged)
    if mode == "off":
        assert gate["verdict"] == "pass" and gate["warning_count"] == 0
    else:
        assert titles == ["DSA", "SHA-1"]  # HMAC-SHA1 is still allowed for HMAC by SP 800-131A Rev. 2
        assert gate["verdict"] == ("fail" if mode == "fail" else "pass")
        assert all(r["rule"] == "deprecated_algorithm" and "SP 800-131A" in r["detail"]
                   for e in flagged for r in e["rules"])


def test_finding_code_rule_is_configurable():
    row = _row("secret-key (inline, app.py)", ["HARDCODED_KEY"], asset_type="related-crypto-material")
    assert _rules(cbom_gate.evaluate({"results": [row]})) == [["finding_code"]]
    relaxed = _policy(block_codes=[c for c in GP.DEFAULT_POLICY["block_codes"] if c != "HARDCODED_KEY"])
    assert cbom_gate.evaluate({"results": [row]}, policy=relaxed)["verdict"] == "pass"


def test_one_finding_reports_every_rule_it_broke():
    row = _row("RSA-1024", ["QUANTUM_VULNERABLE", "WEAK_ALGORITHM"], primitive="pke", key_size="1024", qv=True)
    gate = cbom_gate.evaluate({"results": [row]}, policy=_policy(quantum_vulnerable="fail"))
    assert gate["failing_count"] == 1
    assert _rules(gate) == [["finding_code", "min_key_size", "quantum_vulnerable"]]
    assert gate["failing"][0]["codes"] == ["WEAK_ALGORITHM"]
    assert gate["rules_failed"] == {"finding_code": 1, "min_key_size": 1, "quantum_vulnerable": 1}
    assert "min_key_size" in gate["reason"]


def test_a_warn_and_a_fail_on_one_row_keeps_the_row_failing_and_shows_both():
    row = _row("RSA-1024", ["QUANTUM_VULNERABLE"], primitive="pke", key_size="1024", qv=True)
    gate = cbom_gate.evaluate({"results": [row]}, policy=_policy(block_codes=[]))
    assert gate["verdict"] == "fail"
    outcomes = {r["rule"]: r["outcome"] for r in gate["failing"][0]["rules"]}
    assert outcomes == {"min_key_size": "fail", "quantum_vulnerable": "warn"}
    assert gate["warning_count"] == 0  # the row is listed once, under failing


# ------------------------------------------------------------------------------------------------ exceptions
def _exc(**kw):
    base = {"id": "legacy-hsm", "rule": None, "algorithm": None, "location": None,
            "reason": "Vendor HSM firmware upgrade booked for Q1", "expires": "2027-01-31"}
    base.update(kw)
    return base


def test_an_allow_list_exception_waives_until_it_expires():
    row = _row("RSA-1024", primitive="pke", key_size="1024", qv=True, location="vendor/hsm/client.py")
    policy = _policy(block_codes=[], quantum_vulnerable="off",
                     exceptions=[_exc(algorithm="RSA-1024", location="vendor/hsm/*", rule="min_key_size")])
    gate = cbom_gate.evaluate({"results": [row]}, policy=policy, today=TODAY)
    assert gate["verdict"] == "pass" and gate["waived_count"] == 1
    waived = gate["waived"][0]["rules"][0]
    assert waived["outcome"] == "waived" and waived["exception_id"] == "legacy-hsm"
    assert waived["reason"].startswith("Vendor HSM") and waived["expires"] == "2027-01-31"
    later = cbom_gate.evaluate({"results": [row]}, policy=policy, today=dt.date(2027, 2, 1))
    assert later["verdict"] == "fail" and later["waived_count"] == 0
    assert later["expired_exceptions"] == [{"id": "legacy-hsm", "expires": "2027-01-31",
                                            "reason": "Vendor HSM firmware upgrade booked for Q1"}]


def test_an_exception_waives_only_its_rule_and_its_location():
    row = _row("RSA-1024", ["WEAK_ALGORITHM"], primitive="pke", key_size="1024", qv=True, location="app/keys.py")
    only_size = _policy(exceptions=[_exc(algorithm="RSA-1024", rule="min_key_size")])
    gate = cbom_gate.evaluate({"results": [row]}, policy=only_size, today=TODAY)
    assert gate["verdict"] == "fail"  # finding_code still fails
    outcomes = {r["rule"]: r["outcome"] for r in gate["failing"][0]["rules"]}
    assert outcomes["min_key_size"] == "waived" and outcomes["finding_code"] == "fail"
    elsewhere = _policy(block_codes=[], exceptions=[_exc(location="vendor/*")])
    assert cbom_gate.evaluate({"results": [row]}, policy=elsewhere, today=TODAY)["verdict"] == "fail"


# ------------------------------------------------------------------------------------------------ validation
@pytest.mark.parametrize(("change", "field"), [
    ({"min_key_bits": {"rsa": 512, "dsa": 2048, "dh": 2048, "ec": 256, "symmetric": 128}}, "min_key_bits.rsa"),
    ({"min_key_bits": {"rsa": 2048}}, "min_key_bits.dsa"),
    ({"quantum_vulnerable": "maybe"}, "quantum_vulnerable"),
    ({"deprecated": True}, "deprecated"),
    ({"banned_algorithms": ["MD5", "x" * 41]}, "banned_algorithms"),
    ({"block_codes": ["weak algorithm"]}, "block_codes"),
    ({"exceptions": [_exc(reason="")]}, "exceptions[0].reason"),
    ({"exceptions": [_exc(expires="31/01/2027")]}, "exceptions[0].expires"),
    ({"exceptions": [_exc()]}, "exceptions[0]"),  # neither algorithm nor location: no blanket waiver
    ({"exceptions": [_exc(algorithm="MD5", rule="everything")]}, "exceptions[0].rule"),
    ({"surprise": 1}, "surprise"),
    ({"version": 2}, "version"),
])
def test_invalid_policies_are_refused_with_the_field(change, field):
    raw = {**json.loads(json.dumps(GP.DEFAULT_POLICY)), **change}
    with pytest.raises(GP.PolicyError) as err:
        GP.validate_policy(raw)
    assert err.value.field == field


def test_saving_refuses_an_expired_or_far_exception_but_a_file_may_hold_one():
    past = _policy  # noqa: F841  (readability)
    raw = {**json.loads(json.dumps(GP.DEFAULT_POLICY)), "exceptions": [_exc(algorithm="MD5", expires="2026-01-01")]}
    with pytest.raises(GP.PolicyError) as err:
        GP.validate_policy(raw, today=TODAY, for_save=True)
    assert err.value.field == "exceptions[0].expires"
    far = {**raw, "exceptions": [_exc(algorithm="MD5", expires="2028-12-31")]}
    with pytest.raises(GP.PolicyError):
        GP.validate_policy(far, today=TODAY, for_save=True)
    assert GP.validate_policy(raw)["exceptions"][0]["expires"] == "2026-01-01"  # an old file still loads


def test_the_policy_file_round_trips_and_carries_a_digest():
    policy = _policy(name="Payments team", quantum_vulnerable="fail")
    text = GP.dump_policy_file(policy)
    assert json.loads(text)["kind"] == GP.FILE_KIND
    assert GP.load_policy_file(text) == policy
    assert GP.policy_digest(policy) == GP.policy_digest(GP.load_policy_file(text))
    assert GP.policy_digest(policy) != GP.policy_digest(GP.DEFAULT_POLICY)


# ------------------------------------------------------------------------------------------------ verdict shape
def test_the_verdict_names_its_policy_and_source():
    gate = cbom_gate.evaluate({"results": []}, policy=_policy(name="Payments"), source="integration", version=4)
    assert gate["verdict"] == "pass"
    assert gate["policy"] == "Payments" and gate["policy_source"] == "integration" and gate["policy_version"] == 4
    assert len(gate["policy_digest"]) == 16
    default = cbom_gate.evaluate({"results": []})
    assert default["policy_source"] == "default" and default["policy"] == GP.DEFAULT_POLICY["name"]
    json.dumps(gate)


def test_summary_line_is_safe_for_grep_and_sed():
    row = _row('RSA-1024 "quoted" \\ back', ["WEAK_ALGORITHM"], primitive="pke", key_size="1024")
    gate = cbom_gate.evaluate({"results": [row]})
    line = cbom_gate.summary_line(gate)
    assert line.startswith("FAIL ") and '"' not in line and "\\" not in line and "\n" not in line
    assert "finding_code" in line
    assert cbom_gate.summary_line(cbom_gate.evaluate(None)).startswith("NO_RESULT ")
