"""What merged on dev since the golden run (#103 CB-06 v2 export, #113 fix class, #114 Q-grade) and how the judge
reads it. Every case fails on the harness at 72afd95 (failing first), and each rule has a mutant in tools/mutants.py.
"""
from __future__ import annotations

import json

import pytest

from harness import fieldmap as F
from harness import riskfields
from harness.checks import Checks

from fakerun import FakeRun
from test_gate_judge import empty_ledger, judge  # noqa: F401 (pytest fixture)


# the only non-PASS check a complete, correct fake run has (test_gate_judge.test_correct_cbom_passes)
POSTURE_ONLY = {"G11/derived/run1/posture"}


# ----------------------------------------------------------------------------- Q-grade (#114, CB-19 PLAN §2, §5)
@pytest.mark.parametrize("item, problems", [
    ({"q_grade": "Q1", "q_label": "Critical", "q_reason": "qv_exceeds_internet"}, []),
    ({"q_grade": "Q0", "q_label": "Unknown", "q_reason": "coverage_gap"}, []),
    ({"q_grade": "Q4", "q_label": "Low", "q_reason": "pq_observed"}, []),
    ({"q_grade": None, "q_label": None, "q_reason": "not_applicable"}, []),           # §5: N/A has no grade
    ({"q_grade": None, "q_label": None, "q_reason": "attested_no_class"}, []),
    ({}, ["absent"]),                                                                # pre-#114 product
    ({"q_grade": "Q5", "q_label": "Low", "q_reason": "pq_observed"}, ["grade 'Q5' not one of Q0..Q4"]),
    ({"q_grade": "Q1", "q_label": "High", "q_reason": "qv_exceeds_internet"}, ["label 'High' for Q1 (want 'Critical')"]),
    ({"q_grade": "Q4", "q_label": "Low", "q_reason": "qv_exceeds"},
     ["reason 'qv_exceeds' is not one the formula gives Q4"]),
    ({"q_grade": None, "q_label": None, "q_reason": "mosca_missing"},
     ["no grade with reason 'mosca_missing' (not one of ['attested_no_class', 'not_applicable'])"]),
    ({"q_grade": None, "q_label": "Unknown", "q_reason": "not_applicable"}, ["no grade with label 'Unknown'"]),
])
def test_q_grade_rules(item, problems):
    assert riskfields.qgrade_problems(item) == problems


def test_every_formula_reason_belongs_to_exactly_one_grade():
    seen = [r for reasons in riskfields.Q_REASONS.values() for r in reasons]
    assert len(seen) == len(set(seen)) == 23 and not set(seen) & riskfields.NO_GRADE_REASONS


# ----------------------------------------------------------------------------- fix class (#113, CB-24 PLAN §4, §12)
@pytest.mark.parametrize("item, problems", [
    ({"finding_codes": ["NO_PQ_KEX"], "fix_class": "configurable", "fix_class_floor": None,
      "fix_class_confidence": "observed"}, []),
    ({"finding_codes": [], "fix_class": "none", "fix_class_floor": None, "fix_class_confidence": None}, []),
    ({"finding_codes": ["X"], "fix_class": "unknown", "fix_class_floor": "vendor-fixed",
      "fix_class_confidence": None}, []),
    ({"finding_codes": ["X"]}, ["absent"]),
    ({"finding_codes": ["X"], "fix_class": "easy", "fix_class_floor": None, "fix_class_confidence": None},
     ["fix_class 'easy' not one of ['configurable', 'code-fixed', 'vendor-fixed', 'hardware-fixed', 'unknown', 'none']"]),
    ({"finding_codes": [], "fix_class": "configurable", "fix_class_floor": None, "fix_class_confidence": "observed"},
     ["fix_class 'configurable' with 0 finding code(s) (none exactly when there is no code)"]),
    ({"finding_codes": ["X"], "fix_class": "none", "fix_class_floor": None, "fix_class_confidence": None},
     ["fix_class 'none' with 1 finding code(s) (none exactly when there is no code)"]),
    ({"finding_codes": ["X"], "fix_class": "vendor-fixed", "fix_class_floor": None, "fix_class_confidence": None},
     ["confidence None on vendor-fixed (want observed|inferred)"]),
    ({"finding_codes": ["X"], "fix_class": "unknown", "fix_class_floor": None, "fix_class_confidence": "observed"},
     ["confidence 'observed' on unknown (want null)"]),
    ({"finding_codes": ["X"], "fix_class": "code-fixed", "fix_class_floor": "configurable",
      "fix_class_confidence": "inferred"}, ["floor 'configurable' on code-fixed (a floor only on unknown)"]),
])
def test_fix_class_rules(item, problems):
    assert riskfields.fixclass_problems(item) == problems


def test_risk_fields_are_judged_per_asset_and_block_the_gate(tmp_path, empty_ledger):
    fr = FakeRun(tmp_path)
    fr.write()
    assert set(judge(fr.dir, empty_ledger)[1]) == POSTURE_ONLY
    fr.edit_json("api/assets-run1.json", lambda d: (d["items"][0].pop("q_grade"),
                                                    d["items"][1].__setitem__("fix_class", "none")))
    passed, blocking, _ = judge(fr.dir, empty_ledger)
    assert not passed
    assert blocking["G11/qgrade/run1/asset/101"]["reason"] == "qgrade-absent"
    assert blocking["G11/fixclass/run1/asset/102"]["reason"] == "fixclass-malformed"
    assert set(k for k in blocking if "/qgrade/" in k or "/fixclass/" in k) == {
        "G11/qgrade/run1/asset/101", "G11/fixclass/run1/asset/102"}


def test_risk_fields_without_an_api_capture_are_not_run():
    checks = Checks()
    riskfields.judge("1", checks, None)
    assert checks.get("G11/qgrade/run1").verdict == "NOT-RUN" and checks.get("G11/fixclass/run1").verdict == "NOT-RUN"


def test_a_stated_oracle_grade_and_class_are_judged(tmp_path, empty_ledger):
    """CB-02 INTERFACES v8 (expect.q_grade / expect.fix_class): judged like any stated key once the lab writes them."""
    fr = FakeRun(tmp_path)
    fr.assets[1]["oracle"]["expect"].update({"q_grade": "Q2", "fix_class": "configurable"})
    fr.write()
    assert set(judge(fr.dir, empty_ledger)[1]) == POSTURE_ONLY
    fr.edit_json("api/assets-run1.json", lambda d: d["items"][1].update(
        {"q_grade": "Q3", "q_label": "Medium", "q_reason": "qv_within", "fix_class": "vendor-fixed"}))
    passed, blocking, _ = judge(fr.dir, empty_ledger)
    assert not passed
    assert {k for k in blocking if k.startswith("G11/oracle/")} == {"G11/oracle/run1/z01/tls_endpoint/q_grade",
                                                                     "G11/oracle/run1/z01/tls_endpoint/fix_class"}


# ----------------------------------------------------------------------------- export readers (#103, CB-06 v2)
def test_protocol_is_joined_with_the_exports_zs_protocol(tmp_path, empty_ledger):
    """CB-06 v2 §4: the API protocol equals zs:protocol exactly; protocolProperties.type (CycloneDX's enum) is never
    the comparison, so "https" vs "TLSv1.2" is a mismatch even though both are TLS."""
    fr = FakeRun(tmp_path)
    fr.write()

    def edit(d):
        comp = next(c for c in d["components"] if c["bom-ref"] == "zs-asset-102")
        next(p for p in comp["properties"] if p["name"] == "zs:protocol")["value"] = "TLSv1.2"
    fr.edit_json("exports/run1.cdx.json", edit)
    passed, blocking, _ = judge(fr.dir, empty_ledger)
    assert not passed and blocking["G11/join/run1/asset/102/protocol/export"]["reason"] == "mismatch"
    fr.edit_json("exports/run1.cdx.json", lambda d: [c.__setitem__("properties", [
        p for p in c["properties"] if p["name"] != "zs:protocol"]) for c in d["components"]])
    passed, blocking, _ = judge(fr.dir, empty_ledger)
    assert blocking["G11/join/run1/asset/102/protocol/export"]["reason"] == "export-missing"


def test_suites_join_by_iana_name_each_once():
    """CB-06 v2 §2: the export lists IANA names once; a row stored with OpenSSL names is the same set."""
    assert F.view_eq("cipher_suites", ["AES128-SHA", "TLS_RSA_WITH_AES_128_CBC_SHA", "ECDHE-RSA-AES128-GCM-SHA256"]) \
        == F.view_eq("cipher_suites", ["TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "TLS_RSA_WITH_AES_128_CBC_SHA"])
    assert F.view_eq("cipher_suites", ["AES128-SHA"]) != F.view_eq("cipher_suites", ["TLS_RSA_WITH_AES_256_CBC_SHA"])


def test_sentinels_are_never_suites_or_groups():
    assert F._groups_of({"groups": ["<NULL>"]}) == [] and F._groups_of({"negotiated_group": "(NONE)"}) is None
    assert F._groups_of({"groups": ["x25519", "<NULL>"]}) == ["x25519"]
    assert F.norm_groups("x25519:<NULL>") == ["x25519"] and F.norm_suites(["(NONE)"]) == []
    assert F._ciphers_of({"cipher": "(NONE)"}) is None


def test_database_connection_suites_are_the_endpoints_suites():
    facts = {"own_connection": {"version": "TLSv1.3", "cipher": "TLS_AES_256_GCM_SHA384"},
             "live_connections": [{"cipher": "TLS_AES_128_GCM_SHA256"}, {"variable": "Ssl_cipher", "value": "AES128-SHA"},
                                  {"variable": "Ssl_version", "value": "TLSv1.2"}]}
    assert F._ciphers_of(facts) == ["AES128-SHA", "TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384"]
    assert F._ciphers_of({"own_connection": {"Ssl_cipher": "ECDHE-RSA-AES128-GCM-SHA256"}}) == [
        "ECDHE-RSA-AES128-GCM-SHA256"]
    assert json.dumps(F._ciphers_of({})) == "null"


# ----------------------------------------------------------------------------- control listener (#110, CB-12 v1 §5a)
def test_control_listener_coverage_row_is_judged_by_status_and_scope(tmp_path):
    """The lab's control listener (.34) expects one coverage row, status not_tls, scope the port, and no TLS asset;
    the product's row is located "<ip>#not TLS <ip:port>" and matched on the part before '#'."""
    from harness import oracle
    run = tmp_path / "run"
    (run / "oracle").mkdir(parents=True)
    (run / "lab").mkdir()
    (run / "lab" / "selfcheck.json").write_text(json.dumps({"targets": []}), encoding="utf-8")
    target = {"target_id": "control", "address": "10.231.0.34", "source": "S-canary", "world": "closed",
              "assets": [{"oracle_id": "control/not_tls", "asset_type": "coverage", "location": "10.231.0.34",
                          "expect": {"status": "not_tls", "scope": ["10.231.0.34:443"]}}],
              "must_not_appear": [{"asset_type": "tls_endpoint", "location": "10.231.0.34:443"}]}
    (run / "oracle" / "run1.json").write_text(json.dumps({"schema": oracle.ORACLE_SCHEMA, "targets": [target]}),
                                              encoding="utf-8")

    def verdicts(items):
        checks = Checks()
        oracle.match(run, "1", checks, items, {})
        return {c.id: (c.verdict, c.reason) for c in checks if c.id.startswith("G11/oracle/run1/control")}
    row = {"id": 7, "type": "coverage", "location": "10.231.0.34#not TLS 10.231.0.34:443", "target": "10.231.0.34",
           "facts": {"check": "not TLS 10.231.0.34:443", "status": "not_tls", "scope": ["10.231.0.34:443"],
                     "incomplete": False}}
    good = verdicts({7: row})
    assert {k: v[0] for k, v in good.items() if "not_tls" in k} == {
        "G11/oracle/run1/control/not_tls/present": "PASS", "G11/oracle/run1/control/not_tls/status": "PASS",
        "G11/oracle/run1/control/not_tls/scope": "PASS",
        # codes and impact the lab does not state: NOT-RUN(no-expectation) with the shown value (review 5878413538)
        "G11/oracle/run1/control/not_tls/finding_codes": "NOT-RUN", "G11/oracle/run1/control/not_tls/impact": "NOT-RUN"}
    assert not [k for k, v in good.items() if v[0] == "FAIL"]
    wrong = verdicts({7: {**row, "facts": {**row["facts"], "status": "error"}}})
    assert wrong["G11/oracle/run1/control/not_tls/status"] == ("FAIL", "wrong-value")
    # the pre-#110 product (run 6, KF-5): a tls_endpoint at the port and no coverage row
    old = verdicts({8: {"id": 8, "type": "tls_endpoint", "location": "10.231.0.34:443", "target": "10.231.0.34",
                        "facts": {}}})
    assert old["G11/oracle/run1/control/not_tls/present"] == ("FAIL", "missing")
    assert any(v[0] == "FAIL" and "8" in k for k, v in old.items())
