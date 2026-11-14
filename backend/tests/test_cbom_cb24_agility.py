"""CB-24 PR-1: crypto-agility fix class per finding code and per asset (pure; plan cb-24 §14 T1-T5, T7, T8, AG-7).

The class of every finding code comes from the reviewed table built into the knowledge base
(scripts/crypto_kb/sources/fix_class.json -> crypto_kb.json findings.<ns>.<CODE>.fix_class); context rules in
agility.py decide capability codes; the asset takes the hardest class of its codes.
"""
from __future__ import annotations

import importlib.util
import json
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.utilities.cbom_sources import agility as AG  # noqa: E402
from backend.utilities.cbom_sources import crypto_kb  # noqa: E402
from backend.utilities.cbom_sources.cbom_rows import page_row  # noqa: E402
from backend.utilities.cbom_sources.classify import classify  # noqa: E402

TABLE = ROOT / "scripts/crypto_kb/sources/fix_class.json"
NODE = {"lane": "node", "source_kind": "linux_servers", "provider": None, "operated_by": None, "application": None}


def _asset(asset_type, facts, ctx=NODE, algorithm=None, key_size=None, location=None):
    verdict = classify(asset_type, algorithm, key_size, None, facts, None)
    return verdict["finding_codes"], AG.evaluate("node", asset_type, verdict["finding_codes"], facts, ctx, location)


def _by_code(result):
    return {p["code"]: p for p in result["by_code"]}


# ------------------------------------------------------------------------------------------------ T8 table
def test_every_kb_code_has_a_fix_class_and_the_table_justifies_every_row():
    data = crypto_kb.load()
    table = json.loads(TABLE.read_text())
    for ns in ("node", "code"):
        codes = set(data["findings"][ns])
        assert codes and set(table[ns]) == codes, (ns, sorted(codes ^ set(table[ns])))
        for code, entry in data["findings"][ns].items():
            row = table[ns][code]
            assert entry["fix_class"] == {"class": row["class"], "capability": row["capability"], "basis": row["basis"]}
            assert row["class"] in AG.CLASSES, (ns, code)
            assert row["basis"].strip(), (ns, code)  # the justification column is never empty
            assert row["sources"] and all(s.strip() for s in row["sources"]), (ns, code)
            assert (ns, code) in AG.table()


def test_reviewed_counts_and_capability_codes_match_the_plan():
    table = json.loads(TABLE.read_text())
    count = {ns: {c: sum(1 for r in table[ns].values() if r["class"] == c) for c in AG.CLASSES} for ns in ("node", "code")}
    assert count["node"] == {"configurable": 112, "code-fixed": 0, "vendor-fixed": 9, "hardware-fixed": 1}
    assert count["code"] == {"configurable": 17, "code-fixed": 15, "vendor-fixed": 1, "hardware-fixed": 0}
    caps = {(ns, c) for ns in table if ns in ("node", "code") for c, r in table[ns].items() if r["capability"]}
    assert caps == {("node", c) for c in ("IKE_NO_PQ", "MODBUS_PLAINTEXT", "NO_PQ_KEX", "NO_TLS12",
                                          "QUANTUM_VULNERABLE", "SSH_NO_PQ_KEX")} | {("code", "QUANTUM_VULNERABLE")}


def _build_kb_module():
    spec = importlib.util.spec_from_file_location("cb24_build_kb", ROOT / "scripts/crypto_kb/build_kb.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.mark.parametrize("damage, message", [
    (lambda t: t["node"].pop("PROTO_TLS10"), "no row for node:PROTO_TLS10"),
    (lambda t: t["code"].__setitem__("NOT_A_CODE", {"class": "configurable", "capability": False, "basis": "x",
                                                   "sources": ["x"]}), "which the KB does not have"),
    (lambda t: t["node"]["DSA"].__setitem__("class", "easy"), "is not one of"),
    (lambda t: t["node"]["DSA"].__setitem__("basis", " "), "needs a basis"),
    (lambda t: t["node"]["DSA"].__setitem__("sources", []), "needs a basis"),
])
def test_build_kb_refuses_a_table_with_a_missing_extra_or_unjustified_row(damage, message):
    mod = _build_kb_module()
    table = mod.load_fix_class()
    damage(table)
    findings = {ns: {c: {} for c in mod.load_fix_class()[ns]} for ns in ("node", "code")}
    with pytest.raises(SystemExit, match=message):
        mod.attach_fix_class(findings, table)


def test_agility_version_follows_the_module_and_the_table():
    v = AG.version()
    assert v.startswith("fx-1+") and len(v) == len("fx-1+") + 12 and v == AG.version()
    model = AG.model()
    assert [c["key"] for c in model["classes"]] == list(AG.VALUES)
    assert [c["rank"] for c in model["classes"][:4]] == [1, 2, 3, 4]
    assert {r["id"] for r in model["rules"]} == {"R-TABLE", "R-HW", "R-HW-UNREAD", "R-STACK", "R-TYPE", "R-VENDOR",
                                                 "R-INFERRED", "CL-1", "CL-2", "R-NO-ROW"}
    assert all(c["what"] and c["example"] for c in model["classes"])


# ------------------------------------------------------------------------------------------------ anchor cases
def test_t1_nginx_tls10_is_configurable_and_no_pq_kex_is_likely_vendor_fixed():
    codes, result = _asset("tls_endpoint", {"protocols": ["TLSv1", "TLSv1.2", "TLSv1.3"], "pq_group_supported": True})
    assert codes == ["PROTO_TLS10"]
    assert _by_code(result)["PROTO_TLS10"]["class"] == "configurable"
    assert _by_code(result)["PROTO_TLS10"]["rule"] == "R-TABLE"
    assert (result["fix_class"], result["confidence"]) == ("configurable", "observed")
    codes, result = _asset("tls_endpoint", {"protocols": ["TLSv1", "TLSv1.2", "TLSv1.3"], "pq_group_supported": False})
    per = _by_code(result)
    assert per["PROTO_TLS10"]["class"] == "configurable"
    assert (per["NO_PQ_KEX"]["class"], per["NO_PQ_KEX"]["rule"], per["NO_PQ_KEX"]["confidence"]) == \
        ("vendor-fixed", "R-INFERRED", "inferred")
    assert (result["fix_class"], result["confidence"]) == ("vendor-fixed", "inferred")
    assert AG.excluding_pq(result) == "configurable"


def test_t2_code_rsa1024_is_code_fixed_and_a_certificate_row_configurable():
    row = page_row({"asset_type": "algorithm", "finding_codes": ["WEAK_KEY_SIZE", "QUANTUM_VULNERABLE"],
                    "location": "src/Keys.java", "algorithm_type": "pke", "crypto_strength": "weak"})
    assert (row["fix_class"], row["fix_class_floor"], row["fix_class_confidence"]) == ("code-fixed", None, "observed")
    per = _by_code(AG.evaluate("code", "algorithm", ["WEAK_KEY_SIZE", "QUANTUM_VULNERABLE"], {}, AG.CODE_CONTEXT))
    assert per["QUANTUM_VULNERABLE"]["rule"] == "CL-1" and per["QUANTUM_VULNERABLE"]["class"] == "code-fixed"
    assert per["WEAK_KEY_SIZE"]["class"] == "code-fixed"
    cert = page_row({"asset_type": "certificate", "finding_codes": ["WEAK_CERTIFICATE_KEY"], "location": "certs/a.pem"})
    assert cert["fix_class"] == "configurable"
    # CL-1: a certificate row's post-quantum code needs the CA and peers: likely vendor-fixed
    cert_qv = page_row({"asset_type": "certificate", "finding_codes": ["QUANTUM_VULNERABLE"], "location": "c.pem"})
    assert (cert_qv["fix_class"], cert_qv["fix_class_confidence"]) == ("vendor-fixed", "inferred")
    clean = page_row({"asset_type": "algorithm", "finding_codes": [], "location": "x.py"})
    assert (clean["fix_class"], clean["fix_class_confidence"]) == ("none", None)


def test_cl2_library_codes_follow_the_artifact_kind_when_a_row_states_it():
    base = {"asset_type": "related-crypto-material", "finding_codes": ["EOL_CRYPTO_LIBRARY"], "location": "fw.bin!lib"}
    assert page_row(base)["fix_class"] == "code-fixed"  # table default: a bump in the team's own build
    assert page_row({**base, "artifact_kind": "firmware"})["fix_class"] == "hardware-fixed"
    assert page_row({**base, "artifact_kind": "binary"})["fix_class"] == "vendor-fixed"
    assert page_row({**base, "artifact_kind": "image"})["fix_class"] == "code-fixed"


def test_t3_schannel_tls10_is_configurable():
    codes, result = _asset("os_crypto_policy", {"schannel_protocols": {"TLS 1.0": {"server": {"enabled": True}}}})
    assert "PROTO_TLS10" in codes
    assert _by_code(result)["PROTO_TLS10"]["class"] == "configurable"
    assert result["fix_class"] == "configurable"


def test_t4_hsm_firmware_area_is_hardware_fixed_and_pkcs11_keys_follow_the_token():
    assert AG.evidence_area_fields("hsm_firmware", {"model": "Thales Luna 7", "firmware": "7.8.4"}) == \
        {"fix_class": "hardware-fixed", "not_assessed": False}
    assert AG.evidence_area_fields("hsm_firmware", {}) == {"fix_class": None, "not_assessed": True}
    assert AG.evidence_area_fields("key_ceremonies", {"ceremony": "yes"}) == {"fix_class": None, "not_assessed": False}
    key = {"store": "pkcs11", "key_class": "private", "key_type": "RSA", "key_size": 2048}
    hw = AG.evaluate("node", "managed_key", ["QUANTUM_VULNERABLE"], {**key, "token_class": "hardware"},
                     {**NODE, "source_kind": "key_manager"})
    assert (hw["fix_class"], _by_code(hw)["QUANTUM_VULNERABLE"]["rule"]) == ("hardware-fixed", "R-HW")
    unread = AG.evaluate("node", "managed_key", ["QUANTUM_VULNERABLE"], key, {**NODE, "source_kind": "key_manager"})
    assert (unread["fix_class"], unread["floor"], _by_code(unread)["QUANTUM_VULNERABLE"]["rule"]) == \
        ("unknown", None, "R-HW-UNREAD")
    soft = AG.evaluate("node", "managed_key", ["QUANTUM_VULNERABLE"], {**key, "token_class": "software"},
                       {**NODE, "source_kind": "key_manager"})
    assert (soft["fix_class"], soft["confidence"], _by_code(soft)["QUANTUM_VULNERABLE"]["rule"]) == \
        ("vendor-fixed", "observed", "R-TYPE")


def test_t5_vendors_and_vendor_operated_sources_are_vendor_fixed():
    assert AG.evidence_vendor_fields() == {"fix_class": "vendor-fixed", "not_assessed": False}
    assert AG.evidence_area_fields("third_party_vendors", {"tls": "TLS 1.2 only"})["fix_class"] == "vendor-fixed"
    facts = {"protocols": ["TLSv1", "TLSv1.2", "TLSv1.3"], "pq_group_supported": True}
    _codes, ours = _asset("tls_endpoint", facts)
    assert ours["fix_class"] == "configurable"
    _codes, saas = _asset("tls_endpoint", facts, {**NODE, "operated_by": "vendor"})
    assert (saas["fix_class"], saas["confidence"], _by_code(saas)["PROTO_TLS10"]["rule"]) == \
        ("vendor-fixed", "observed", "R-VENDOR")
    okta = {**NODE, "source_kind": "idp", "provider": "okta"}
    signing = AG.evaluate("node", "signing_key", ["QUANTUM_VULNERABLE"], {"kty": "RSA"}, okta)
    assert signing["fix_class"] == "vendor-fixed" and signing["confidence"] == "observed"
    # vendor-operated never lowers a harder class: an appliance's capability code stays hardware-fixed
    appliance = AG.evaluate("node", "appliance_config", ["NO_PQ_KEX"], {},
                            {**NODE, "source_kind": "appliance", "operated_by": "vendor"})
    assert appliance["fix_class"] == "hardware-fixed"


def test_ag7_ssh_banner_decides_the_post_quantum_kex_class():
    def ssh(banner):
        return AG.evaluate("node", "ssh_endpoint", ["SSH_NO_PQ_KEX"], {"banner": banner} if banner else {}, NODE)
    new = ssh("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5")
    assert (new["fix_class"], new["confidence"], _by_code(new)["SSH_NO_PQ_KEX"]["rule"]) == \
        ("configurable", "observed", "R-STACK")
    old = ssh("SSH-2.0-OpenSSH_8.7")
    assert (old["fix_class"], old["confidence"]) == ("vendor-fixed", "observed")
    assert "OpenSSH 8.7" in _by_code(old)["SSH_NO_PQ_KEX"]["fact"]
    none = ssh(None)
    assert (none["fix_class"], none["confidence"]) == ("vendor-fixed", "inferred")


def test_r_hw_and_r_type_cover_ot_aws_kms_acm_and_windows_keys():
    modbus = AG.evaluate("node", "ot_endpoint", ["MODBUS_PLAINTEXT"], {}, {**NODE, "source_kind": "network_range"})
    assert (modbus["fix_class"], _by_code(modbus)["MODBUS_PLAINTEXT"]["rule"]) == ("hardware-fixed", "R-HW")
    aws = {**NODE, "source_kind": "aws_account"}
    kms = AG.evaluate("node", "kms_key", ["QUANTUM_VULNERABLE"], {"key_spec": "RSA_2048"}, aws,
                      "arn:aws:kms:eu-west-1:111122223333:key/abc")
    assert (kms["fix_class"], kms["confidence"]) == ("code-fixed", "observed")
    azure = AG.evaluate("node", "kms_key", ["QUANTUM_VULNERABLE"], {}, {**NODE, "source_kind": "azure_subscription"},
                        "https://v.vault.azure.net/keys/k")
    assert (azure["fix_class"], azure["confidence"]) == ("vendor-fixed", "inferred")  # no AWS fact: never easier
    acm = AG.evaluate("node", "certificate", ["QUANTUM_VULNERABLE"], {}, aws,
                      "arn:aws:acm:eu-west-1:111122223333:certificate/x")
    assert (acm["fix_class"], acm["confidence"]) == ("vendor-fixed", "observed")
    win = {"source": "windows-store", "has_private_key": True}
    unread = AG.evaluate("node", "certificate", ["QUANTUM_VULNERABLE"], win, {**NODE, "source_kind": "windows_servers"})
    assert unread["fix_class"] == "unknown"
    tpm = AG.evaluate("node", "certificate", ["QUANTUM_VULNERABLE"], {**win, "key_provider_class": "tpm"}, NODE)
    assert tpm["fix_class"] == "hardware-fixed"
    no_key = AG.evaluate("node", "certificate", ["QUANTUM_VULNERABLE"], {"source": "windows-store"}, NODE)
    assert (no_key["fix_class"], no_key["confidence"]) == ("vendor-fixed", "inferred")


# ------------------------------------------------------------------------------------------------ T7 asset rule
def _p(cls, floor=None, confidence="observed"):
    return {"code": "X", "class": cls, "floor": floor, "confidence": None if cls == "unknown" else confidence}


def test_t7_asset_rule_hardest_unknown_with_floor_and_none():
    assert AG.asset_class([_p("configurable"), _p("unknown")]) == \
        {"fix_class": "unknown", "floor": "configurable", "confidence": None}
    assert AG.asset_class([_p("unknown"), _p("hardware-fixed")])["fix_class"] == "hardware-fixed"
    assert AG.asset_class([]) == {"fix_class": "none", "floor": None, "confidence": None}
    assert AG.asset_class([_p("configurable"), _p("vendor-fixed", confidence="inferred"), _p("code-fixed")]) == \
        {"fix_class": "vendor-fixed", "floor": None, "confidence": "inferred"}
    coverage = AG.evaluate("node", "tls_endpoint", ["COVERAGE_DENIED"], {}, NODE)
    assert coverage["fix_class"] == "none" and coverage["by_code"] == []
    legacy = AG.evaluate("code", "algorithm", ["FINDING"], {}, AG.CODE_CONTEXT)
    assert (legacy["fix_class"], _by_code(legacy)["FINDING"]["rule"]) == ("unknown", "R-NO-ROW")
    assert _by_code(legacy)["FINDING"]["unknown_reason"] == "no_fix_class"


def test_a_kb_without_fix_classes_makes_every_code_unknown_never_configurable(monkeypatch):
    data = json.loads(json.dumps(crypto_kb.load()))
    for ns in ("node", "code"):
        for entry in data["findings"][ns].values():
            entry.pop("fix_class", None)
    data["kb_version"] = "2099.01.01.1"
    monkeypatch.setattr(crypto_kb, "load", lambda: data)
    result = AG.evaluate("node", "tls_endpoint", ["PROTO_TLS10"], {}, NODE)
    assert result["fix_class"] == "unknown" and result["by_code"][0]["rule"] == "R-NO-ROW"
    assert AG.version().startswith("fx-1+")


def test_self_fixable_share():
    assert AG.self_fixable_pct({"configurable": 3, "code-fixed": 1, "vendor-fixed": 4, "unknown": 9, "none": 5}) == 50.0
    assert AG.self_fixable_pct({"unknown": 2, "none": 1}) is None
