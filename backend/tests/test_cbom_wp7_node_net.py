"""WP7 server side: classification of IKE / OT / appliance / mesh assets, knowledge-base entries and exploit demos for
the new codes (built into a temporary KB; the integrator rebuilds the shipped one), the appliance source kind, port
protocols, and the Kubernetes ClusterRole granting the Linkerd policy reads."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.utilities.cbom_sources import crypto_kb, exploit_demo, kinds, schemas, settings, templates  # noqa: E402
from backend.utilities.cbom_sources.classify import classify  # noqa: E402

NEW_CODES = ["IKE_WEAK_ENCR", "IKE_WEAK_INTEG", "IKE_WEAK_DH", "IKEV1_ENABLED", "IKE_AGGRESSIVE", "IKE_NO_PQ",
             "IPSEC_WEAK_TRANSFORM", "OPCUA_NONE_POLICY", "OPCUA_DEPRECATED_POLICY", "OPCUA_ANON",
             "OPCUA_USERNAME_PLAINTEXT", "MODBUS_PLAINTEXT", "MESH_DR_TLS_DISABLED", "LINKERD_UNAUTHENTICATED_SERVER",
             "SSH_V1_ENABLED"]


def _c(asset_type, facts, algorithm=None, key_size=None):
    return classify(asset_type, algorithm, key_size, None, facts)


# ----------------------------------------------------------------------------- IKE (facts as the node reports them;
# the three gateways are the strongSwan lab of the WP7 proof)
LEGACY_GW = {
    "service": "ike", "port": 500,
    "ikev2": {"supported": True, "baseline": "accepted",
              "chosen": {"encryption": "AES-CBC-256", "prf": "HMAC-SHA2-256", "integrity": "HMAC-SHA2-256-128",
                         "group": "MODP-2048"},
              "weak": {"dh": {"accepted": ["MODP-1024", "MODP-1536", "MODP-768"], "complete": True},
                       "encryption": {"accepted": ["DES", "3DES"], "complete": True},
                       "integrity": {"accepted": ["HMAC-MD5-96", "HMAC-SHA1-96"], "complete": False},
                       "prf": {"accepted": [], "any_of": ["HMAC-MD5", "HMAC-SHA1"], "complete": False}},
              "pq": {"supported": False, "method": None}},
    "ikev1": {"supported": True, "accepts": True, "aggressive": True, "aggressive_auth": "PSK",
              "weak": {"encryption": {"accepted": ["3DES"]}, "hash": {"accepted": ["SHA1"]},
                       "group": {"accepted": ["MODP-1024"]}}},
}
MLKEM_GW = {"service": "ike", "port": 500,
            "ikev2": {"supported": True, "chosen": {"encryption": "AES-GCM-16-256", "prf": "HMAC-SHA2-256",
                                                    "integrity": None, "group": "CURVE25519"},
                      "weak": {k: {"accepted": [], "complete": True} for k in ("dh", "encryption", "integrity", "prf")},
                      "pq": {"supported": True, "method": "ML-KEM-768"}},
            "ikev1": {"supported": True, "accepts": False, "baseline": "no_proposal"}}
V1_ONLY_GW = {"service": "ike", "ikev2": {"supported": True, "proposals_accepted": False,
                                          "pq": {"supported": False, "method": None}},
              "ikev1": {"supported": True, "accepts": True, "chosen": {"encryption": "AES-CBC-256", "hash": "SHA2-256",
                                                                         "group": "MODP-2048"}}}


def test_legacy_gateway():
    out = _c("ike_endpoint", LEGACY_GW, "AES-CBC-256")
    assert out["finding_codes"] == ["IKE_WEAK_ENCR", "IKE_WEAK_INTEG", "IKE_WEAK_DH", "IKEV1_ENABLED", "IKE_AGGRESSIVE",
                                    "IKE_NO_PQ"]
    assert out["impact"] == "High" and out["quantum_vulnerable"] is True
    assert "QUANTUM_VULNERABLE" not in out["finding_codes"]  # IKE_NO_PQ says it (like NO_PQ_KEX for TLS)
    assert "PRF one of HMAC-MD5/HMAC-SHA1" in out["texts"]["IKE_WEAK_INTEG"]
    assert "crackable offline" in out["texts"]["IKE_AGGRESSIVE"]
    assert out["cdx_type"] == "protocol"


def test_ml_kem_gateway_is_clean_and_not_quantum_vulnerable():
    out = _c("ike_endpoint", MLKEM_GW, "AES-GCM-16-256")
    assert out["finding_codes"] == [] and out["quantum_vulnerable"] is False and out["impact"] is None


def test_ikev1_only_gateway_and_daemon_that_merely_answers_ikev1():
    out = _c("ike_endpoint", V1_ONLY_GW)
    assert out["finding_codes"] == ["IKEV1_ENABLED", "IKE_NO_PQ"] and "IKEv1 only" in out["texts"]["IKE_NO_PQ"]
    assert "IKEV1_ENABLED" not in _c("ike_endpoint", MLKEM_GW)["finding_codes"]  # NO-PROPOSAL-CHOSEN is not enabled


def test_untested_pq_gives_no_quantum_verdict():
    secondary = {"service": "ike", "ikev2": {"supported": True, "chosen": {"encryption": "AES-GCM-16-256",
                                                                           "group": "CURVE25519"}}, "ikev1": {}}
    out = _c("ike_endpoint", secondary)
    assert out["finding_codes"] == [] and out["quantum_vulnerable"] is None


# ----------------------------------------------------------------------------- OT
def _opcua(endpoints):
    return {"service": "opcua", "endpoints": endpoints}


def test_opcua_rules():
    legacy = _opcua([
        {"security_mode": "None", "security_policy": "None",
         "user_tokens": [{"type": "Anonymous", "security_policy": "None"}, {"type": "UserName", "security_policy": None}]},
        {"security_mode": "SignAndEncrypt", "security_policy": "Basic128Rsa15",
         "user_tokens": [{"type": "UserName", "security_policy": "None"}]},
        {"security_mode": "Sign", "security_policy": "Basic256Sha256",
         "user_tokens": [{"type": "UserName", "security_policy": "None"}]}])
    out = _c("ot_endpoint", legacy)
    assert out["finding_codes"] == ["OPCUA_NONE_POLICY", "OPCUA_DEPRECATED_POLICY", "OPCUA_ANON",
                                    "OPCUA_USERNAME_PLAINTEXT", "QUANTUM_VULNERABLE"]  # RSA-based policies too
    assert out["impacts"]["OPCUA_ANON"] == "High"  # anonymous on the None endpoint
    hardened = _opcua([{"security_mode": "SignAndEncrypt", "security_policy": "Aes256_Sha256_RsaPss",
                        "user_tokens": [{"type": "UserName", "security_policy": "None"}]}])
    out = _c("ot_endpoint", hardened)
    assert out["finding_codes"] == ["QUANTUM_VULNERABLE"]  # RSA-based secure channel; password encrypted by it
    # asyncua: a UserName token on the None endpoint with its own policy (encrypted password) is not plaintext
    own = _opcua([{"security_mode": "None", "security_policy": "None",
                   "user_tokens": [{"type": "UserName", "security_policy": "Basic256Sha256"}]}])
    assert "OPCUA_USERNAME_PLAINTEXT" not in _c("ot_endpoint", own)["finding_codes"]


def test_modbus_rule():
    out = _c("ot_endpoint", {"service": "modbus", "tls": False})
    assert out["finding_codes"] == ["MODBUS_PLAINTEXT"] and out["impact"] == "High"


# ----------------------------------------------------------------------------- mesh
def test_destination_rule_and_linkerd_rules():
    out = _c("k8s_mesh_destination", {"host": "legacy.pay", "tls_mode": "ISTIO_MUTUAL", "port_tls_modes": {"8080": "DISABLE"},
                                      "subset_tls_modes": {"v1": "DISABLE", "v2": "SIMPLE"}})
    assert out["finding_codes"] == ["MESH_DR_TLS_DISABLED"] and "port 8080, subset v1" in out["finding"]
    assert _c("k8s_mesh_destination", {"tls_mode": "ISTIO_MUTUAL"})["finding_codes"] == []
    srv = _c("k8s_mesh_server", {"namespace": "vote", "name": "metrics", "port": 9100, "unauthenticated": True,
                                 "unauthenticated_by": ["AuthorizationPolicy metrics-net requires no mesh identity"]})
    assert srv["finding_codes"] == ["LINKERD_UNAUTHENTICATED_SERVER"] and srv["impact"] == "Medium"
    assert _c("k8s_mesh_server", {"unauthenticated": False, "unauthenticated_by": []})["finding_codes"] == []


def test_implicit_mesh_default_text():
    out = _c("k8s_mesh_policy", {"mtls_mode": "UNSET", "scope": "mesh", "implicit": True})
    assert out["finding_codes"] == ["MESH_MTLS_PERMISSIVE"] and out["finding"].startswith("No mesh-wide PeerAuthentication")


# ----------------------------------------------------------------------------- appliance rows (parser output shape)
def test_appliance_rows():
    ike = _c("appliance_config", {"kind": "ike_policy", "vendor_label": "FortiOS", "section": "phase1 to-branch",
                                  "version": 1, "encryption": ["DES", "3DES", "AES-CBC-128"], "integrity": ["MD5", "SHA1"],
                                  "groups": ["MODP-1024", "MODP-1536"], "aggressive": True,
                                  "aggressive_reason": "set mode aggressive"})
    assert ike["finding_codes"] == ["IKE_WEAK_ENCR", "IKE_WEAK_INTEG", "IKE_WEAK_DH", "IKEV1_ENABLED", "IKE_AGGRESSIVE",
                                    "QUANTUM_VULNERABLE"]
    gcm = _c("appliance_config", {"kind": "ike_policy", "version": 2, "encryption": ["AES-GCM-16-256"],
                                  "prf": ["SHA2-384"], "groups": ["ECP-384"]})
    assert gcm["finding_codes"] == ["QUANTUM_VULNERABLE"]
    esp = _c("appliance_config", {"kind": "ipsec_policy", "encryption": ["3DES"], "integrity": ["MD5"],
                                  "pfs_groups": ["MODP-1024"]})
    assert esp["finding_codes"] == ["IPSEC_WEAK_TRANSFORM"]
    ssh = _c("appliance_config", {"kind": "ssh", "vendor_label": "Cisco ASA", "section": "ssh", "versions": [1],
                                  "kex": ["diffie-hellman-group1-sha1"]})
    assert ssh["finding_codes"][:2] == ["SSH_V1_ENABLED", "SSH_DH_GROUP1"]
    tls = _c("appliance_config", {"kind": "tls", "vendor_label": "FortiOS", "section": "system global",
                                  "min_version": "TLSv1.1", "protocols": ["TLSv1.1", "TLSv1.2"], "strong_crypto": False})
    assert set(tls["finding_codes"]) == {"PROTO_TLS11", "MIN_TLS11", "WEAK_CIPHER"}
    key = _c("public_key", {"kind": "appliance_key", "key_alg": "RSA", "key_size": 1024}, "RSA", 1024)
    assert "RSA_LT_2048" in key["finding_codes"]


# ----------------------------------------------------------------------------- knowledge base + exploit demos
@pytest.fixture(scope="module")
def built_kb(tmp_path_factory):
    out = tmp_path_factory.mktemp("kb") / "kb.json"
    shipped = json.loads((ROOT / "backend/utilities/cbom_sources/data/crypto_kb.json").read_text())
    subprocess.run([sys.executable, str(ROOT / "scripts/crypto_kb/build_kb.py"), shipped["kb_version"], str(out)],
                   check=True, capture_output=True)
    return json.loads(out.read_text())


def test_every_new_code_has_a_kb_entry(built_kb):
    node = built_kb["findings"]["node"]
    for code in NEW_CODES:
        e = node[code]
        assert e["title"] and len(e["description"]) >= 20 and len(e["attack"]) >= 20, code
        assert e["owasp_2021"] and e["owasp_2025"] and e["remediation"]["summary"] and e["verify"], code
        for c in e["cwe"]:
            assert built_kb["cwe"][c], (code, c)


def test_every_new_code_gets_a_demo(built_kb, monkeypatch):
    monkeypatch.setattr(crypto_kb, "load", lambda: built_kb)
    for code in NEW_CODES:
        entries = crypto_kb.render("node", [code], context={"host": "10.0.0.5", "port": 500}, evidence="", title=code)
        demo = exploit_demo.build({"title": code, "finding_codes": [code], "location": "10.0.0.5:500"}, entries)
        assert demo is not None and demo["description"] and demo["attack_vector"], code
        assert demo["verify"] and all("{host}" not in v["command"] for v in demo["verify"]), code


def test_classifier_codes_are_all_in_the_new_kb_list():
    src = (ROOT / "backend/utilities/cbom_sources/classify_ext/node_net.py").read_text()
    import re

    raised = set(re.findall(r'out\.add\(\s*"([A-Z0-9_]+)"', src)) | {"IKE_WEAK_ENCR", "IKE_WEAK_INTEG", "IKE_WEAK_DH"}
    reused = {"WEAK_CIPHER"}  # existing code (FortiOS strong-crypto off)
    assert raised - reused <= set(NEW_CODES)


# ----------------------------------------------------------------------------- source kind, protocols, RBAC
KNOWN = "10.1.1.1 ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEm"


def test_appliance_kind_validation():
    cfg = kinds.ApplianceConfig(vendor="cisco_ios", targets=["10.1.1.1"], known_hosts=KNOWN)
    assert cfg.port == 22 and cfg.host_key_policy == "pinned"
    assert kinds.ApplianceConfig(vendor="f5_bigip", targets=["10.1.1.2"]).port == 443
    with pytest.raises(ValueError, match="known_hosts"):
        kinds.ApplianceConfig(vendor="fortios", targets=["10.1.1.1"])
    with pytest.raises(ValueError):
        kinds.ApplianceConfig(vendor="juniper", targets=["10.1.1.1"], known_hosts=KNOWN)
    spec = kinds.KINDS["appliance"]
    assert spec.group == "network" and "appliance" in kinds.KIND_NAMES
    assert spec.secret_fields(kinds.ApplianceConfig(vendor="panos", targets=["fw.corp"])) == {"api_key"}
    assert spec.secret_fields(cfg) == {"password"}
    tofu = kinds.ApplianceConfig(vendor="cisco_ios", targets=["10.1.1.1"], host_key_policy="tofu")
    assert "pinned host key" in kinds.credential_target_problem("appliance", tofu, {"password": "x"})
    assert {"targets", "known_hosts", "vendor"} <= set(spec.where_fields)


def test_ot_port_protocols_accepted_but_not_default():
    for proto in ("opcua", "modbus", "modbus-tls"):
        assert schemas.PortItem(port=502, protocol=proto).protocol == proto and proto in settings.PORT_PROTOCOLS
        assert not any(p["protocol"] == proto for p in settings.DEFAULT_PORTS)


def test_cluster_role_grants_linkerd_policy_reads():
    role = next(d for d in yaml.safe_load_all(templates.K8S_TIER1) if d["kind"] == "ClusterRole")
    rule = next(r for r in role["rules"] if r["apiGroups"] == ["policy.linkerd.io"])
    assert set(rule["resources"]) == {"servers", "serverauthorizations", "authorizationpolicies",
                                      "meshtlsauthentications", "networkauthentications"}
    assert rule["verbs"] == ["get", "list"]
    assert "policy.linkerd.io" in templates.K8S_TIER2
