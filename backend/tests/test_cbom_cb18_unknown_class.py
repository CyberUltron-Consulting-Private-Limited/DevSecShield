"""CB-18 PR-1: the ``unknown`` PQC class, one class function on every surface, hybrid only with an identified
post-quantum component, the read-elsewhere rule, readiness that is never 100 % on an unidentified estate, export totals
past the cap, and the code lane never counting an unidentified algorithm as quantum-safe.

SQLite + the real routers (fixtures of test_cbom_cb19_run_grades / test_cbom_sources_api).

    cd backend && PYTHONPATH=.. python -m pytest tests/test_cbom_cb18_unknown_class.py -q
"""
from __future__ import annotations

import ast
import datetime as dt
import sys
from collections import Counter
from pathlib import Path

import pytest
from sqlmodel import Session, select

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_cbom_cb19_run_grades as RG  # noqa: E402  (seed / items / detail / posture over the real routers)

from backend.new_models import CbomCollectedAsset, CbomCollectionRun  # noqa: E402
from backend.utilities.cbom_sources import cbom_metrics  # noqa: E402
from backend.utilities.cbom_sources import drift as D  # noqa: E402
from backend.utilities.cbom_sources import heatmap as HEAT  # noqa: E402
from backend.utilities.cbom_sources import inventory as INV  # noqa: E402
from backend.utilities.cbom_sources import posture as P  # noqa: E402

world = RG.world
api = RG.api
_asset = RG._asset
BACKEND = Path(__file__).resolve().parents[1]
NOW = dt.datetime(2026, 11, 14, 9, 0)

UNKNOWN_OID_CERT = {"key_alg": "1.3.9999.6.4.13", "not_after": "2030-01-01T00:00:00Z", "subject": "CN=odd",
                    "issuer": "CN=odd ca"}
RSA_CERT = {"key_alg": "RSA", "key_size": 2048, "not_after": "2030-01-01T00:00:00Z", "subject": "CN=rsa",
            "issuer": "CN=ca", "sig_alg": "sha256WithRSAEncryption"}


def row(asset_type, qv, facts=None, algorithm=None):
    return {"asset_type": asset_type, "quantum_vulnerable": qv, "facts": facts or {}, "algorithm": algorithm}


# ----------------------------------------------------------------------------- the rule, one row per basis
@pytest.mark.parametrize("asset_type,qv,facts,algorithm,expected", [
    # unknown: public-key cryptography that was not identified or not read (never "not applicable")
    ("certificate", None, UNKNOWN_OID_CERT, "1.3.9999.6.4.13", ("unknown", "key_unidentified")),
    ("private_key", None, {"encrypted": True, "detail": "passphrase-protected"}, None, ("unknown", "key_encrypted")),
    ("private_key", None, {"path": "/etc/ssl/private/web.key", "readable": False}, None, ("unknown", "not_readable")),
    ("private_key", None, {"parsed": False, "detail": "not a PEM/PKCS#8 key"}, None, ("unknown", "key_format_unread")),
    ("private_key", None, {"format": "openssh", "readable": True, "parsed": False}, None,
     ("unknown", "key_format_unread")),  # EC-2: an OpenSSH key without .pub is a key, never N/A
    ("certificate", None, {"path": "/etc/x.pem", "readable": False, "parsed": False}, None, ("unknown", "not_readable")),
    ("tls_endpoint", None, {"tls": None, "detail": "no TLS version accepted"}, None, ("unknown", "no_tls_handshake")),
    ("api_tls", None, {"min_version": "TLSv1.2"}, None, ("unknown", "kex_not_read")),
    ("ssh_server_config", None, {"path": "/etc/ssh/sshd_config"}, None, ("unknown", "kex_not_read")),
    ("ike_endpoint", None, {"service": "ike", "mode": "fragile", "ikev2": {"supported": True}}, None,
     ("unknown", "kex_not_read")),
    ("managed_key", None, {"algorithm_unknown": True}, "VENDOR_X", ("unknown", "algorithm_unknown")),
    # hybrid needs an identified post-quantum component (EC-1); a prefix or marker hit alone is unknown
    ("certificate", False, {"key_alg_oid": "1.3.6.1.5.5.7.6.40"}, "MLDSA44-ECDSA-P256-SHA256",
     ("hybrid", "hybrid_construction")),
    ("certificate", False, {"key_alg": "2.16.840.1.114027.80.8.1.99"}, "2.16.840.1.114027.80.8.1.99",
     ("unknown", "pq_component_unidentified")),
    ("managed_key", False, {}, "rsa3072_dilithium2", ("unknown", "pq_component_unidentified")),
    ("tls_endpoint", False, {"protocols": ["TLSv1.3"], "pq_hybrid": True}, None, ("unknown", "pq_group_unnamed")),
    ("tls_endpoint", False, {"protocols": ["TLSv1.3"], "pq_hybrid": True, "pq_group": "X25519MLKEM768"}, None,
     ("hybrid", "pq_kex_accepted")),
    ("ssh_endpoint", False, {"kex": ["mlkem768x25519-sha256", "curve25519-sha256"]}, None,
     ("hybrid", "hybrid_construction")),
    ("appliance_config", False, {"kind": "ike_policy", "groups": ["MODP-2048", "ML-KEM-768"]}, None,
     ("hybrid", "pq_with_classical")),
    ("ike_endpoint", False, {"ikev2": {"supported": True, "pq": {"supported": True, "method": "ML-KEM-768"}}}, None,
     ("hybrid", "pq_with_classical")),
    # quantum-safe: pure post-quantum or symmetric
    ("certificate", False, {"key_alg": "2.16.840.1.101.3.4.3.18"}, "2.16.840.1.101.3.4.3.18",
     ("quantum-safe", "pq_or_symmetric")),
    ("appliance_config", False, {"kind": "ike_policy", "groups": ["group 36"]}, None, ("quantum-safe", "pq_or_symmetric")),
    ("managed_key", False, {}, "AES-256", ("quantum-safe", "pq_or_symmetric")),
    # not applicable: no key there, no TLS in use, or judged on another row
    ("certificate", None, {"trust_store": True, "count": 140}, None, ("not-applicable", "trust_store_summary")),
    ("certificate", None, {"path": "/etc/dh.pem", "readable": True, "parsed": False, "detail": "no certificate found"},
     None, ("not-applicable", "no_key_material")),
    ("public_key", None, {"path": "/root/.ssh/authorized_keys", "readable": True, "parsed": False}, None,
     ("not-applicable", "no_key_material")),
    ("tls_endpoint", None, {"tls": False, "plaintext_only": True}, None, ("not-applicable", "no_tls_in_use")),
    ("load_balancer_tls", None, {"tls": False, "port": 80}, None, ("not-applicable", "no_tls_in_use")),
    ("database_tls", None, {"own_connection": {"version": "TLSv1.3"}}, None, ("not-applicable", "kex_judged_elsewhere")),
    ("k8s_ingress_tls", None, {"hosts": ["a"], "secret": "s"}, None, ("not-applicable", "kex_judged_elsewhere")),
    ("ike_endpoint", None, {"service": "ike", "port": 4500, "mode": "normal", "ikev2": {"supported": True}}, None,
     ("not-applicable", "kex_judged_elsewhere")),
    ("kms_key", None, {"key_spec": "HMAC_256"}, "HMAC_256", ("not-applicable", "no_public_key")),
    ("database_config", None, {"password_encryption": "scram-sha-256"}, None, ("not-applicable", "no_public_key")),
    ("tls_endpoint", True, {}, None, ("quantum-vulnerable", "shor_breaks")),
    ("disk_encryption", False, {"method": "XtsAes128"}, None, ("grover-weakened", "grover_128_bit")),
])
def test_class_and_basis(asset_type, qv, facts, algorithm, expected):
    got = P.classify_pqc(row(asset_type, qv, facts, algorithm))
    assert got == expected
    assert P.CLASS_BASIS[got[1]][0] == got[0]  # every basis belongs to exactly one class
    assert got[0] in P.PQC_CLASSES


def test_unknown_is_its_own_class_outside_readiness():
    assert P.PQC_CLASSES.index("unknown") < P.PQC_CLASSES.index("not-applicable")
    assert "unknown" not in P.JUDGED_CLASSES and "not-applicable" not in P.JUDGED_CLASSES


@pytest.mark.parametrize("classes,pct,status", [
    ({"unknown": 999, "quantum-safe": 1}, None, "not_enough_identified"),  # EC-4: never "100 %" on 0.1 % of the estate
    ({"unknown": 10}, None, "not_enough_identified"),
    ({}, None, "nothing_judged"),
    ({"quantum-vulnerable": 1, "quantum-safe": 1, "unknown": 2}, 50.0, "ok"),
    ({"quantum-vulnerable": 1, "hybrid": 3, "not-applicable": 9}, 75.0, "ok"),
])
def test_readiness_basis(classes, pct, status):
    value, basis = P.readiness(classes)
    assert value == pct and basis["status"] == status
    assert basis["unknown"] == classes.get("unknown", 0)
    assert basis["judged"] == sum(classes.get(c, 0) for c in P.JUDGED_CLASSES)


def test_one_class_function_in_the_product():
    """Every surface calls posture.classify_pqc; there is no second class function to drift from it (OB-1)."""
    assert not hasattr(P, "pqc_class")
    callers = []
    for path in list((BACKEND / "utilities").rglob("*.py")) + list((BACKEND / "routers").rglob("*.py")):
        if ".venv" in path.parts:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                name = node.func.attr if isinstance(node.func, ast.Attribute) else getattr(node.func, "id", "")
                if name == "classify_pqc":
                    callers.append(path.name)
                assert name != "pqc_class", path
    assert {"posture.py", "drift.py", "inventory.py", "qgrade.py", "heatmap.py"} <= set(callers)


# ----------------------------------------------------------------------------- every surface, one answer
MIX = [
    _asset("certificate", "/etc/ssl/rsa.pem", facts=RSA_CERT, algorithm="RSA", key_size=2048),
    _asset("certificate", "/etc/ssl/odd.pem", facts=UNKNOWN_OID_CERT, algorithm="1.3.9999.6.4.13"),
    _asset("certificate", "/etc/ssl/certs/ca-bundle.crt", facts={"trust_store": True, "count": 140}),
    _asset("tls_endpoint", "10.20.0.9:443", target="10.20.0.9", facts={"tls": None, "detail": "no TLS version accepted"}),
    _asset("private_key", "/etc/ssl/private/enc.key", facts={"encrypted": True, "detail": "passphrase-protected"}),
    _asset("kms_key", "arn:aws:kms:eu-west-1:1:key/h", target="aws", facts={"key_spec": "HMAC_256"},
           algorithm="HMAC_256"),
    _asset("certificate", "/etc/ssl/composite.pem", facts={"key_alg_oid": "1.3.6.1.5.5.7.6.40", "subject": "CN=c",
                                                           "issuer": "CN=c", "not_after": "2030-01-01T00:00:00Z"},
           algorithm="MLDSA44-ECDSA-P256-SHA256"),
]
EXPECTED = {"/etc/ssl/rsa.pem": "quantum-vulnerable", "/etc/ssl/odd.pem": "unknown",
            "/etc/ssl/certs/ca-bundle.crt": "not-applicable", "10.20.0.9:443": "unknown",
            "/etc/ssl/private/enc.key": "unknown", "arn:aws:kms:eu-west-1:1:key/h": "not-applicable",
            "/etc/ssl/composite.pem": "hybrid"}


def _export(engine, run_id):
    with Session(engine) as s:
        return INV.cyclonedx(s, s.get(CbomCollectionRun, run_id), NOW)


def _props(comp: dict) -> dict[str, str]:
    return {p["name"]: p["value"] for p in comp.get("properties") or []}


def test_every_surface_shows_the_same_class(api, world):
    w = RG.seed(world[0], sources=[{"name": "S-mix", "assets": MIX}])
    ids = w["S-mix"]["assets"]
    listed = RG.items(api, w["run"])
    post = RG.posture(api, w["run"])
    doc = _export(world[0], w["run"])
    exported = {_props(c)["zs:location"]: _props(c) for c in doc["components"] if "zs:location" in _props(c)}
    with Session(world[0]) as s:
        rows = s.exec(select(CbomCollectedAsset).where(CbomCollectedAsset.run_id == w["run"])).all()
        views = D.node_views(rows, "src", reclassify=False)
        heat = HEAT.run_heatmap(s, 1, w["run"])
    drift_class = Counter(v.extra["pqc_class"] for v in views.values())
    for location, cls in EXPECTED.items():
        aid = ids[location]
        d = RG.detail(api, aid)
        assert d["pqc_class"] == listed[aid]["pqc_class"] == exported[location]["zs:pqc_class"] == cls, location
        assert d["pqc_class_basis"] == listed[aid]["pqc_class_basis"] == exported[location]["zs:pqc_class_basis"]
        assert d["pqc_class_basis_text"] == P.CLASS_BASIS[d["pqc_class_basis"]][1]
        # one "unknown" per document: a verdict-less row says unknown only when its class does (OB-7)
        qv = exported[location]["zs:quantum_vulnerable"]
        assert qv in ("true", "false") or qv == ("unknown" if cls == "unknown" else "not-applicable"), location
        if cls == "unknown":  # CB-19: an unknown class is a Q0 "unknown verdict", never "not applicable"
            assert (d["q_grade"], d["q_reason"]) == ("Q0", "unknown_verdict")
    counts = Counter(EXPECTED.values())
    assert post["pqc_classes"] == {c: counts.get(c, 0) for c in P.PQC_CLASSES}
    assert drift_class == counts
    assert Counter(i["pqc_class"] for i in listed.values()) == counts
    heat_counts = Counter()
    for cell in heat["cells"]:
        heat_counts.update({k: v for k, v in cell["pqc_classes"].items() if v})
    assert heat_counts == counts
    assert post["readiness_basis"] == {"judged": 2, "ready": 1, "unknown": 3, "not_applicable": 2,
                                       "status": "not_enough_identified"}
    assert post["pqc_readiness_pct"] is None
    assert post["pqc_class_bases"]["key_unidentified"] == 1 and post["pqc_class_bases"]["no_tls_handshake"] == 1
    meta = {p["name"]: p["value"] for p in doc["metadata"]["properties"]}
    assert meta["zs:pqc_class_model"] == P.PQC_CLASS_MODEL and meta["zs:run_asset_count"] == "7"
    assert {c: int(meta[f"zs:pqc_class_count:{c}"]) for c in P.PQC_CLASSES} == post["pqc_classes"]
    assert meta["zs:pqc_readiness_status"] == "not_enough_identified" and "zs:pqc_readiness_pct" not in meta
    assert post["q_grades"]["Q0"] >= 3


def test_export_past_the_cap_keeps_the_runs_unknown_count(api, world, monkeypatch):
    """EC-8: the first rows by id fill the cap; the unknown rows after it are still counted in the metadata."""
    rsa = [_asset("certificate", f"/etc/ssl/rsa{i}.pem", facts=RSA_CERT, algorithm="RSA", key_size=2048)
           for i in range(3)]
    odd = [_asset("certificate", f"/etc/ssl/odd{i}.pem", facts=UNKNOWN_OID_CERT, algorithm="1.3.9999.6.4.13")
           for i in range(2)]
    w = RG.seed(world[0], sources=[{"name": "S-cap", "assets": rsa + odd}])
    monkeypatch.setattr(INV, "EXPORT_CAP", 3)
    doc = _export(world[0], w["run"])
    meta = {p["name"]: p["value"] for p in doc["metadata"]["properties"]}
    assert meta["zs:truncated"] == "true" and meta["zs:asset_count"] == "3"
    assert meta["zs:run_asset_count"] == "5" and meta["zs:pqc_class_count:unknown"] == "2"
    post = RG.posture(api, w["run"])
    assert {c: int(meta[f"zs:pqc_class_count:{c}"]) for c in P.PQC_CLASSES} == post["pqc_classes"]


def test_a_key_another_collector_read_is_not_unknown(api, world):
    """EC-3: Tier-1 SSH could not read the key (no permission), the host agent read it as RSA: one judged key."""
    w = RG.seed(world[0], sources=[
        {"name": "S-ssh", "assets": [_asset("private_key", "/etc/ssl/private/web.key", target="web1",
                                            facts={"path": "/etc/ssl/private/web.key", "readable": False})]},
        {"name": "S-agent", "assets": [_asset("private_key", "/etc/ssl/private/web.key", target="web1",
                                              facts={"path": "/etc/ssl/private/web.key", "key_alg": "RSA",
                                                     "key_size": 2048, "encrypted": False},
                                              algorithm="RSA", key_size=2048)]},
    ])
    unread = w["S-ssh"]["assets"]["/etc/ssl/private/web.key"]
    read = w["S-agent"]["assets"]["/etc/ssl/private/web.key"]
    post = RG.posture(api, w["run"])
    assert post["pqc_classes"]["unknown"] == 0 and post["pqc_classes"]["quantum-vulnerable"] == 1
    d = RG.detail(api, unread)
    assert (d["pqc_class"], d["pqc_class_basis"], d["pqc_class_read_elsewhere"]) == ("not-applicable",
                                                                                       "read_elsewhere", read)
    assert d["q_reason"] == "not_applicable"
    assert RG.items(api, w["run"])[unread]["pqc_class_basis"] == "read_elsewhere"
    doc = _export(world[0], w["run"])
    meta = {p["name"]: p["value"] for p in doc["metadata"]["properties"]}
    assert meta["zs:pqc_class_count:unknown"] == "0"
    # the same unreadable key with no other collector stays unknown
    alone = RG.seed(world[0], sources=[{"name": "S-alone", "assets": [_asset(
        "private_key", "/etc/ssl/private/web.key", target="web2", facts={"readable": False})]}])
    assert RG.posture(api, alone["run"])["pqc_classes"]["unknown"] == 1


def test_drift_keeps_unknown_out_of_readiness_and_withholds_it():
    def asset(i, asset_type, qv, facts, algorithm=None, codes=()):
        return CbomCollectedAsset(id=i, team_id=1, run_id=1, job_id=1, source_id=1, attempt=1, asset_key=f"k{i}",
                                  asset_type=asset_type, target="h", location=f"/x{i}", algorithm=algorithm,
                                  quantum_vulnerable=qv, finding_codes=list(codes), facts=facts, created_at=NOW)

    rsa = asset(1, "certificate", True, RSA_CERT, "RSA", ["QUANTUM_VULNERABLE"])
    aes = asset(2, "managed_key", False, {}, "AES-256")
    odd = [asset(10 + i, "certificate", None, UNKNOWN_OID_CERT, "1.3.9999.6.4.13") for i in range(3)]
    views = D.node_views([rsa, aes] + odd[:1], "src", reclassify=False)
    by_id = {v.asset_id: v for v in views.values()}
    assert by_id[10].judged is False and by_id[10].extra["pqc_class"] == "unknown"  # HF-7: not counted as ready
    assert D.readiness(views) == 50.0
    assert D.readiness(D.node_views([aes] + odd, "src", reclassify=False)) is None  # 3 unknown > 1 judged


def test_serial_changes_with_the_class_model():
    """ST-A: the same run exported under other class rules is another BOM."""
    assert INV.export_serial(7, "kb-1") != INV.export_serial(7, "kb-1", class_model=P.PQC_CLASS_MODEL)
    assert INV.export_serial(7, "kb-1", class_model="pc-2") == INV.export_serial(7, "kb-1", class_model="pc-2")


# ----------------------------------------------------------------------------- the code lane (HF-1)
def test_code_lane_unidentified_algorithm_is_not_quantum_safe():
    stored = {"algorithm_name": "1.3.9999.6.4.13", "algorithm_type": "algorithm", "crypto_strength": "unknown",
              "quantum_safe": True}  # as an engine before CB-18 stored it
    assert cbom_metrics.code_row_quantum_vulnerable(stored) is None
    rsa = {"algorithm_name": "RSA-2048", "algorithm_type": "algorithm", "crypto_strength": "strong",
           "quantum_safe": False}
    summary = cbom_metrics.summarize_code_rows([stored, rsa])
    assert summary.quantum == {"quantum_safe": 0, "quantum_vulnerable": 1, "broken_today": 0}
    assert summary.readiness_pct == 0.0
    aes = {"algorithm_name": "AES-256-GCM", "algorithm_type": "algorithm", "crypto_strength": "strong",
           "quantum_safe": True}
    assert cbom_metrics.code_row_quantum_vulnerable(aes) is False
