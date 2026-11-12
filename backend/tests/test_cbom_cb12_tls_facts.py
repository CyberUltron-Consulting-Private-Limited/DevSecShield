"""CB-12 on the backend: what a scan node reports about TLS is stored without sentinels and with one name per suite
(IANA name + code, for nodes of every version); a non-TLS listener's coverage row is not a TLS asset, not "not
applicable" and not in the posture classes; an alert-only TLS endpoint is a TLS row with no verdict; new teams get the
handshake budget that full suite enumeration needs; the backend's suite table is the scan node's.

Uses the SQLite + real-router harness of test_cbom_sources_api.py (assets go through the node API's add_assets).
"""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_cbom_sources_api import _collect_job, api, world  # noqa: E402,F401  (shared fixtures)

from backend.utilities.cbom_sources import node_facts  # noqa: E402
from backend.utilities.cbom_sources.classify import classify  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]


def _post(api, claim, hdr, assets):  # noqa: F811  (shared fixtures)
    r = api("POST", f"/cbom/node/jobs/{claim['job']['id']}/assets", None, headers=hdr,
            json={"lease_id": claim["job"]["lease_id"], "batch_id": "cb12", "assets": assets})
    assert r.status_code == 200, r.text
    return r.json()


# a row as nodes before CB-12 sent it for an SNI-only or non-TLS port (DA-P2, CB-05 runs): OpenSSL names and "<NULL>"
OLD_NODE_TLS = {"type": "tls_endpoint", "target": "10.20.0.1", "location": "10.20.0.1:443",
                "algorithm": "ECDHE-RSA-AES128-SHA", "protocol": "TLSv1.2",
                "facts": {"negotiated_version": "TLSv1.2", "negotiated_cipher": "ECDHE-RSA-AES128-SHA",
                          "negotiated_group": "<NULL>", "versions": {"TLSv1.2": True},
                          "weak_ciphers_accepted": {"cbc": ["TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"]}}}
NOT_TLS = {"type": "coverage", "target": "10.20.0.1", "location": "10.20.0.1#not TLS 10.20.0.1:8443",
           "name": "not TLS 10.20.0.1:8443",
           "facts": {"check": "not TLS 10.20.0.1:8443", "status": "not_tls", "scope": ["10.20.0.1:8443"],
                     "incomplete": False, "detail": "https 10.20.0.1:8443 answered TCP on a port listed as TLS but did "
                                                     "not speak TLS: closed the connection without a TLS answer (2 handshakes)"}}
ALERT_ONLY = {"type": "tls_endpoint", "target": "10.20.0.2", "location": "10.20.0.2:443", "protocol": "tls",
              "facts": {"tls": True, "negotiation": "no_common_parameters", "alerts": ["handshake_failure"],
                        "versions": {"SSLv3": False, "TLSv1.0": False, "TLSv1.1": False, "TLSv1.2": False,
                                     "TLSv1.3": False}}}


def test_sentinels_are_never_stored_and_a_suite_has_one_name(api, world):  # noqa: F811  (shared fixtures)
    engine, _ = world
    src, run, claim, hdr = _collect_job(api, engine)
    assert _post(api, claim, hdr, [OLD_NODE_TLS])["accepted"] == 1
    item = api("GET", f"/1/cbom/sources/runs/{run['id']}/assets").json()["items"][0]
    f = item["facts"]
    assert "negotiated_group" not in f
    assert f["negotiated_cipher"] == "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA" and f["negotiated_cipher_code"] == "0xC013"
    assert item["algorithm"] == "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"
    assert "CBC_ACCEPTED" in item["finding_codes"]


def test_a_non_tls_listener_is_a_coverage_row_outside_the_posture_classes(api, world):  # noqa: F811  (shared fixtures)
    engine, _ = world
    src, run, claim, hdr = _collect_job(api, engine)
    assert _post(api, claim, hdr, [NOT_TLS, ALERT_ONLY])["accepted"] == 2
    items = {a["location"]: a for a in api("GET", f"/1/cbom/sources/runs/{run['id']}/assets").json()["items"]}
    cov = items["10.20.0.1#not TLS 10.20.0.1:8443"]
    assert cov["type"] == "coverage" and cov["finding_codes"] == ["COVERAGE_NOT_TLS"]
    assert cov["quantum_vulnerable"] is None
    assert not [a for a in items.values() if a["type"] == "tls_endpoint" and a["location"] == "10.20.0.1:8443"]
    posture = api("GET", f"/1/cbom/sources/runs/{run['id']}/posture").json()["posture"]
    # only the alert-only TLS row is classed; the coverage row is in no class (never "not applicable")
    assert sum(posture["pqc_classes"].values()) == 1, posture["pqc_classes"]
    alert = items["10.20.0.2:443"]
    assert alert["facts"]["negotiation"] == "no_common_parameters" and alert["quantum_vulnerable"] is None
    assert not [c for c in alert["finding_codes"] if c.startswith(("PROTO_", "NO_TLS"))]


def test_new_teams_get_the_budget_full_enumeration_needs(api, world):  # noqa: F811  (shared fixtures)
    settings = api("GET", "/1/cbom/sources/settings").json()["settings"]
    assert settings["rate_handshakes_per_endpoint"] == 128


def test_classify_reads_a_full_suite_list():
    facts = {"versions": {"TLSv1.0": True, "TLSv1.2": True, "TLSv1.3": True},
             "ciphers": ["TLS_RSA_WITH_3DES_EDE_CBC_SHA", "TLS_AES_128_GCM_SHA256"],
             "weak_ciphers_accepted": {"obsolete": ["TLS_RSA_WITH_3DES_EDE_CBC_SHA"],
                                       "static_rsa": []}, "groups": ["x25519", "X25519MLKEM768"],
             "pq_hybrid": True, "negotiated_group": "x25519"}
    out = classify("tls_endpoint", "TLS_AES_128_GCM_SHA256", None, "TLSv1.3", facts)
    assert {"PROTO_TLS10", "WEAK_CIPHER"} <= set(out["finding_codes"]) and out["quantum_vulnerable"] is False


def test_the_backend_suite_table_is_the_scan_node_table():
    spec = importlib.util.spec_from_file_location("tls_registry", ROOT / "scan_node/zs_scan_node/tls_registry.py")
    reg = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(reg)
    data = json.loads((ROOT / "backend/utilities/cbom_sources/data/tls_cipher_suites.json").read_text())
    assert {int(k, 16): v["iana"] for k, v in data["suites"].items()} == reg.SUITES
    assert {int(k, 16): v["openssl"] for k, v in data["suites"].items() if "openssl" in v} == reg.OPENSSL_NAMES
    assert {int(k): v for k, v in data["groups"].items()} == reg.GROUP_NAMES
    assert data["sources"] == reg.SOURCES
    assert node_facts.iana_suite("ECDHE-RSA-AES128-SHA") == (0xC013, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA")
    assert node_facts.iana_suite("TLS_AES_256_GCM_SHA384") == (0x1302, "TLS_AES_256_GCM_SHA384")
    assert node_facts.iana_suite("<NULL>") is None


def test_rows_that_are_not_tls_pass_unchanged():
    facts = {"negotiated_group": "<NULL>", "cipher": "(NONE)"}
    assert node_facts.normalise_tls("certificate", facts, "RSA") == (facts, "RSA")
    out, alg = node_facts.normalise_tls("database_tls", {"cipher": "(NONE)", "group": "NONE"}, "(NONE)")
    assert out == {} and alg is None
