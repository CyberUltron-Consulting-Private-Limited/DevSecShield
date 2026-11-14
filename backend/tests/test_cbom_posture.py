"""Scan-node runs: PQC classes, readiness, HNDL, Mosca, risk ranking, compliance, asset detail and the VEX export.

Uses the same SQLite + real-router harness as test_cbom_sources_api.py.
"""
from __future__ import annotations

import datetime as dt
import json
from pathlib import Path

import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_cbom_sources_api import CERT_FACTS, _collect_job, api, world  # noqa: E402,F401  (shared fixtures)

from backend.utilities.cbom_sources import posture as P  # noqa: E402
from backend.utilities.cbom_sources.classify import classify  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
NOW = dt.datetime(2026, 10, 31)

WIN_FACTS = {"os": {"Caption": "Windows Server 2022"},
             "schannel_protocols": {"TLS 1.0": {"server": {"enabled": True}}, "SSL 3.0": {"server": {"enabled": False}},
                                    "TLS 1.1": {"client": {"enabled": True}}, "SSL 2.0": {"server": {"enabled": None}}},
             "cipher_suites": ["TLS_AES_256_GCM_SHA384", "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                               "TLS_RSA_WITH_AES_256_CBC_SHA", "TLS_RSA_WITH_3DES_EDE_CBC_SHA"],
             "rdp": {"security_layer": 0, "nla": False}}


def test_windows_schannel_rdp_rules_flag_only_explicit_settings():
    v = classify("os_crypto_policy", None, None, None, WIN_FACTS, NOW)
    assert v["finding_codes"] == ["PROTO_TLS10", "WEAK_CIPHER", "STATIC_RSA_KEX", "CBC_ACCEPTED", "RDP_NO_TLS", "RDP_NO_NLA"]
    assert v["texts"]["PROTO_TLS10"] == "SCHANNEL enables TLS 1.0 for servers (registry)"
    hardened = classify("os_crypto_policy", None, None, None, {"schannel_protocols": {"TLS 1.0": {"server": {"enabled": False}}},
                                                               "cipher_suites": ["TLS_AES_256_GCM_SHA384"],
                                                               "rdp": {"security_layer": 2, "nla": True}}, NOW)
    assert hardened["finding_codes"] == [] and hardened["impact"] is None


@pytest.mark.parametrize("facts,codes", [
    ({"status": "FullyDecrypted", "method": "None", "protection": "Off"}, ["DISK_UNENCRYPTED"]),
    ({"status": "FullyEncrypted", "method": "XtsAes128", "protection": "Off"}, ["DISK_XTS_128", "DISK_PROTECTION_OFF"]),
    ({"status": "FullyEncrypted", "method": "Aes256", "protection": "On"}, ["DISK_CBC"]),
    ({"status": "FullyEncrypted", "method": "XtsAes256", "protection": "On"}, []),
])
def test_bitlocker_rules(facts, codes):
    v = classify("disk_encryption", facts["method"], None, None, {**facts, "source": "bitlocker", "mount": "C:"}, NOW)
    assert v["finding_codes"] == codes


def test_library_versions_use_the_knowledge_base():
    eol = classify("crypto_library", None, None, None, {"name": "openssl", "version": "3.0.2-0ubuntu1.15"}, NOW)
    assert eol["finding_codes"] == ["LIB_EOL", "LIB_KNOWN_CVE"] and eol["impact"] == "Medium"
    assert "2026-09-07" in eol["texts"]["LIB_EOL"] and "in triage" in eol["texts"]["LIB_KNOWN_CVE"]
    current = classify("crypto_library", None, None, None, {"name": "openssl", "version": "3.5.4-1"}, NOW)
    assert current["finding_codes"] == []
    old = classify("crypto_library", None, None, None, {"name": "openssl", "version": "1.1.1k-12.el8_9"}, NOW)
    assert "LIB_EOL" in old["finding_codes"]


def cls(asset_type, qv, codes, facts, algorithm=None):
    """The class through the product's one class function (CB-18: ``posture.classify_pqc``)."""
    return P.classify_pqc({"asset_type": asset_type, "quantum_vulnerable": qv, "facts": facts,
                           "algorithm": algorithm}, codes)[0]


def test_pqc_class_hndl_and_mosca():
    assert cls("tls_endpoint", True, [], {}) == "quantum-vulnerable"
    assert cls("tls_endpoint", False, [], {"pq_hybrid": True, "pq_group": "X25519MLKEM768"}) == "hybrid"
    assert cls("tls_endpoint", False, [], {"pq_hybrid": True}) == "unknown"  # CB-18: an unnamed PQ group
    assert cls("kms_key", False, [], {}) == "quantum-safe"
    assert cls("disk_encryption", False, ["DISK_XTS_128"], {}) == "grover-weakened"
    assert cls("database_config", None, [], {}) == "not-applicable"
    assert P.hndl("tls_endpoint", True) and not P.hndl("certificate", True) and not P.hndl("tls_endpoint", False)
    assert P.mosca({})["configured"] is False
    risk = P.mosca({"data_shelf_life_years": 10, "migration_years": 5, "threat_years": 12})
    assert risk["at_risk"] is True and risk["years_over"] == 3
    safe = P.mosca({"data_shelf_life_years": 2, "migration_years": 3, "threat_years": 12})
    assert safe["at_risk"] is False and "7 year(s)" in safe["verdict"]


def _store(api, engine, assets):
    src, run, claim, hdr = _collect_job(api, engine)
    job, lease = claim["job"], claim["job"]["lease_id"]
    r = api("POST", f"/cbom/node/jobs/{job['id']}/assets", None, headers=hdr,
            json={"lease_id": lease, "batch_id": "p1", "assets": assets})
    assert r.status_code == 200, r.text
    return src, run


ASSETS = [
    {"type": "certificate", "target": "10.20.0.1", "location": "/etc/ssl/pay.pem", "name": "pay", "algorithm": "RSA",
     "key_size": 1024, "facts": CERT_FACTS},
    {"type": "tls_endpoint", "target": "10.20.0.1", "location": "10.20.0.1:443",
     "facts": {"protocols": ["TLSv1.0", "TLSv1.2"], "group": "x25519", "weak_ciphers": ["DES-CBC3-SHA", "RC4-SHA"]}},
    {"type": "tls_endpoint", "target": "10.20.0.2", "location": "10.20.0.2:443",
     "facts": {"protocols": ["TLSv1.3"], "group": "X25519MLKEM768", "pq_hybrid": True}},
    {"type": "crypto_library", "target": "10.20.0.1", "location": "package:openssl", "name": "openssl",
     "facts": {"name": "openssl", "version": "3.0.2-0ubuntu1.15", "source": "package"}},
    {"type": "os_crypto_policy", "target": "10.20.0.3", "location": "os", "name": "Windows Server 2022", "facts": WIN_FACTS},
    {"type": "kms_key", "target": "aws", "location": "arn:aws:kms:ap-south-1:111122223333:key/abc", "algorithm": "SYMMETRIC_DEFAULT",
     "facts": {"key_spec": "SYMMETRIC_DEFAULT", "key_manager": "CUSTOMER", "rotation_enabled": False, "key_state": "Enabled"}},
]


def test_run_posture_endpoint(api, world):
    engine, _ = world
    src, run = _store(api, engine, ASSETS)
    r = api("PATCH", f"/1/cbom/sources/items/{src['id']}", json={"config": {**src["config"], "business_criticality": "critical"},
                                                              "expected_version": src["row_version"]})
    assert r.status_code == 200, r.text
    out = api("GET", f"/1/cbom/sources/runs/{run['id']}/posture").json()["posture"]
    assert out["pqc_classes"]["quantum-vulnerable"] == 2 and out["pqc_classes"]["hybrid"] == 1
    assert out["pqc_classes"]["quantum-safe"] == 1  # the KMS symmetric key
    assert out["pqc_readiness_pct"] == 50.0 and out["hndl_assets"] == 1
    assert out["mosca"]["configured"] is False
    # the run was created while the source was "medium": a later edit never re-scores it (snapshot on the job)
    top = out["top_risks"][0]
    assert (top["criticality"], top["score"], top["exposure"]) == ("medium", 10.0, "internal")
    assert top["exposure_basis"] == "private IP address 10.20.0.1"
    frameworks = {f["framework"] for f in out["compliance"]}
    assert {"NIST", "RBI", "SEBI CSCRF", "CERT-In"} <= frameworks
    patched = api("PATCH", "/1/cbom/sources/settings", json={"risk_model": {"data_shelf_life_years": 10,
                                                                              "migration_years": 5, "threat_years": 12}})
    assert patched.status_code == 200 and patched.json()["settings"]["risk_model"]["threat_years"] == 12
    assert api("PATCH", "/1/cbom/sources/settings", "bob", json={"risk_model": {"threat_years": 1}}).status_code == 400  # admins only
    assert api("PATCH", "/1/cbom/sources/settings", json={"risk_model": {"threat_years": 500}}).status_code == 400
    out = api("GET", f"/1/cbom/sources/runs/{run['id']}/posture").json()["posture"]
    # CB-19 PR-2: the run keeps the Mosca it was started with (unset); the team's new values are shown beside it
    assert out["mosca"]["configured"] is False
    assert out["mosca_now"]["at_risk"] is True and out["mosca_now"]["years_over"] == 3
    assert api("GET", f"/2/cbom/sources/runs/{run['id']}/posture", "carol").status_code == 404


def test_asset_detail_endpoint(api, world):
    engine, _ = world
    _src, run = _store(api, engine, ASSETS)
    items = {a["location"]: a for a in api("GET", f"/1/cbom/sources/runs/{run['id']}/assets").json()["items"]}
    tls = api("GET", f"/1/cbom/sources/assets/{items['10.20.0.1:443']['id']}").json()["asset"]
    by_code = {d["code"]: d for d in tls["details"]}
    assert {"PROTO_TLS10", "WEAK_CIPHER"} <= set(by_code) and tls["pqc_class"] == "quantum-vulnerable" and tls["hndl"]
    assert {c["id"] for c in by_code["WEAK_CIPHER"]["cves"]} == {"CVE-2013-2566", "CVE-2015-2808", "CVE-2016-2183"}
    assert any("-p 443 10.20.0.1" in v["command"] for v in by_code["PROTO_TLS10"]["verify"])
    assert by_code["PROTO_TLS10"]["observed"] == "Endpoint accepts TLS 1.0"
    lib = api("GET", f"/1/cbom/sources/assets/{items['package:openssl']['id']}").json()["asset"]
    assert lib["library"]["eol"]["branch"] == "3.0" and "CVE-2022-3602" in lib["library"]["cves"]
    assert any(d["code"] == "LIB_KNOWN_CVE" for d in lib["details"])
    win = api("GET", f"/1/cbom/sources/assets/{items['os']['id']}").json()["asset"]
    assert {"RDP_NO_TLS", "RDP_NO_NLA", "PROTO_TLS10"} <= {d["code"] for d in win["details"]}
    assert api("GET", f"/2/cbom/sources/assets/{items['os']['id']}", "carol").status_code == 404
    assert api("GET", "/1/cbom/sources/assets/999999").status_code == 404


def test_export_is_schema_valid_with_vex(api, world):
    jsonschema = pytest.importorskip("jsonschema")
    from referencing import Registry, Resource
    engine, _ = world
    _src, run = _store(api, engine, ASSETS)
    bom = api("GET", f"/1/cbom/sources/runs/{run['id']}/cbom").json()
    schemas = ROOT / "aibom/src/aibom/schemas"
    main = json.loads((schemas / "bom-1.6.schema.json").read_text())
    registry = Registry().with_resources([
        (json.loads((schemas / name).read_text())["$id"], Resource.from_contents(json.loads((schemas / name).read_text())))
        for name in ("spdx.schema.json", "jsf-0.82.schema.json")
    ] + [("spdx.schema.json", Resource.from_contents(json.loads((schemas / "spdx.schema.json").read_text()))),
         ("jsf-0.82.schema.json", Resource.from_contents(json.loads((schemas / "jsf-0.82.schema.json").read_text())))])
    validator = jsonschema.Draft7Validator(main, registry=registry)
    errors = sorted(validator.iter_errors(bom), key=lambda e: list(e.path))
    assert not errors, [f"{list(e.path)}: {e.message}" for e in errors[:5]]
    vulns = {v["id"]: v for v in bom["vulnerabilities"]}
    assert vulns["ZS-CBOM-WEAK_CIPHER"]["analysis"]["state"] == "exploitable"
    assert vulns["CVE-2016-2183"]["analysis"]["state"] == "in_triage" and vulns["CVE-2016-2183"]["ratings"][0]["score"] == 7.5
    assert vulns["CVE-2022-3602"]["analysis"]["state"] == "in_triage"
    refs = {c["bom-ref"] for c in bom["components"]}
    assert all(a["ref"] in refs for v in bom["vulnerabilities"] for a in v["affects"])


def test_changing_business_criticality_keeps_the_connection_test(api, world):
    engine, _ = world
    src, _run = _store(api, engine, ASSETS[:1])
    from sqlmodel import Session
    from backend.new_models import CbomCollectionSource
    with Session(engine) as s:  # as if its connection test had passed
        row = s.get(CbomCollectionSource, src["id"])
        row.last_test_status, row.last_test_summary = "ok", "2 of 2 targets read"
        s.add(row)
        s.commit()
    before = api("GET", f"/1/cbom/sources/items/{src['id']}").json()["source"]
    r = api("PATCH", f"/1/cbom/sources/items/{src['id']}", json={"config": {**before["config"], "business_criticality": "high"},
                                                              "expected_version": before["row_version"]})
    after = r.json()["source"]
    assert r.status_code == 200 and after["config"]["business_criticality"] == "high"
    assert after["last_test_status"] == before["last_test_status"] != "never"
    bad = api("PATCH", f"/1/cbom/sources/items/{src['id']}", json={"config": {**before["config"], "business_criticality": "extreme"},
                                                                "expected_version": after["row_version"]})
    assert bad.status_code == 400


def test_editing_a_source_form_keeps_its_business_criticality(api, world):
    """The Servers / Databases / Cloud forms send only their own fields; the criticality set on Review & Run stays."""
    engine, _ = world
    src, _run = _store(api, engine, ASSETS[:1])
    cur = api("GET", f"/1/cbom/sources/items/{src['id']}").json()["source"]
    r = api("PATCH", f"/1/cbom/sources/items/{src['id']}", json={"config": {**cur["config"], "business_criticality": "critical"},
                                                              "expected_version": cur["row_version"]})
    cur = r.json()["source"]
    form = {k: v for k, v in cur["config"].items() if k != "business_criticality"}
    form["timeout_s"] = (cur["config"].get("timeout_s") or 300) + 1 if "timeout_s" in cur["config"] else None
    form = {k: v for k, v in form.items() if v is not None}
    r = api("PATCH", f"/1/cbom/sources/items/{src['id']}", json={"config": form, "expected_version": cur["row_version"]})
    assert r.status_code == 200 and r.json()["source"]["config"]["business_criticality"] == "critical"
    cur = r.json()["source"]
    r = api("PATCH", f"/1/cbom/sources/items/{src['id']}", json={"config": {**form, "business_criticality": None},
                                                              "expected_version": cur["row_version"]})
    assert r.status_code == 200 and r.json()["source"]["config"]["business_criticality"] is None


@pytest.mark.parametrize("value,expected", [
    ("[2001:db8::1]:443", ("[2001:db8::1]", "443")), ("2001:db8::1", ("[2001:db8::1]", None)),
    ("db.example.com:5432", ("db.example.com", "5432")), ("10.0.0.5:443#chain[0]", ("10.0.0.5", "443")),
    ("/etc/ssl/k.pem", (None, None)), ("arn:aws:kms:ap-south-1:1:key/x", (None, None)),
])
def test_host_and_port_for_proof_commands(value, expected):
    assert P._host_port(value) == expected


def test_disk_quantum_classes():
    off = classify("disk_encryption", None, None, None, {"source": "bitlocker", "status": "FullyDecrypted", "method": "None"})
    assert "DISK_UNENCRYPTED" in off["finding_codes"] and off["quantum_vulnerable"] is None
    assert cls("disk_encryption", off["quantum_vulnerable"], off["finding_codes"], {}) == "not-applicable"
    aes128 = classify("disk_encryption", None, None, None, {"source": "bitlocker", "status": "FullyEncrypted",
                                                            "method": "Aes128", "protection": "On"})
    assert cls("disk_encryption", aes128["quantum_vulnerable"], aes128["finding_codes"],
               {"method": "Aes128"}) == "grover-weakened"
    luks_off = classify("disk_encryption", None, None, None, {"encrypted": False})
    assert luks_off["quantum_vulnerable"] is None


def test_windows_cbc_only_and_bad_fact_types():
    cbc = classify("os_crypto_policy", None, None, None, {"source": "windows",
                                                          "cipher_suites": ["TLS_DHE_RSA_WITH_AES_128_CBC_SHA"]})
    both = classify("os_crypto_policy", None, None, None, {"source": "windows", "cipher_suites": [
        "TLS_DHE_RSA_WITH_AES_128_CBC_SHA", "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"]})
    assert "CBC_ONLY" in cbc["finding_codes"] and "CBC_ACCEPTED" in both["finding_codes"]
    classify("os_crypto_policy", None, None, None, {"source": "windows", "cipher_suites": 5})  # never raises


def test_vex_severity_is_the_findings_own():
    from types import SimpleNamespace
    from backend.utilities.cbom_sources import inventory
    now = dt.datetime(2026, 10, 31)
    row = SimpleNamespace(id=1, asset_type="tls_endpoint", algorithm=None, key_size=None, protocol="TLSv1.3",
                          facts={"protocols": ["SSLv3", "TLSv1.2"], "ciphers": ["ECDHE-RSA-AES128-SHA", "ECDHE-RSA-AES128-GCM-SHA256"]},
                          created_at=now, impact="Critical", finding="", finding_codes=None)
    row.finding_codes = classify(row.asset_type, None, None, row.protocol, row.facts, now)["finding_codes"]
    vulns = {v["id"]: v for v in inventory.vulnerabilities([row])}
    if "ZS-CBOM-CBC_ACCEPTED" in vulns:
        assert vulns["ZS-CBOM-CBC_ACCEPTED"]["ratings"][0]["severity"] == "low"
    assert any(v["ratings"][0]["severity"] == "critical" for k, v in vulns.items() if "SSL" in k)
