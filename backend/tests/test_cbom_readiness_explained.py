"""Issue #271: the run results page explains PQC readiness, the quantum-vulnerable list and the remediation waves.

The page may not recompute any readiness or class figure (CB-38 Rule P), so everything it explains comes from the API:
* ``posture.readiness_actions``: the quantum-vulnerable assets grouped by asset type and quantum finding code, largest
  first (top 3), each with its knowledge-base title and fix and the readiness the run would have with that group fixed
  (posture's own ``readiness`` function);
* ``posture.readiness_excluded``: the assets left out of the readiness denominator (classes unknown and
  not-applicable), per reason, with the reason's sentence;
* ``/results`` migration rows carry ``asset_type`` and ``algorithm`` so near-identical rows (one per endpoint) group
  into one card by algorithm, finding and fix;
* ``/remediation`` carries ``rules``: what puts an asset in each wave (the one ``suggested_wave`` rule set).

Same SQLite + real-router harness as test_cbom_sources_api.py.
"""
from __future__ import annotations

import sys
from pathlib import Path

from backend.utilities.cbom_sources import crypto_kb
from backend.utilities.cbom_sources import posture as P
from backend.utilities.cbom_sources import waves as W

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_cbom_sources_api as SOURCES_API  # shared SQLite + real-router harness

api = SOURCES_API.api  # fixtures
world = SOURCES_API.world
_collect_job = SOURCES_API._collect_job


def _tls(ip: str, group: str = "x25519", **facts) -> dict:
    return {"type": "tls_endpoint", "target": ip, "location": f"{ip}:443", "name": f"HTTPS {ip}:443",
            "algorithm": "TLS_AES_256_GCM_SHA384",
            "facts": {"protocols": ["TLSv1.3"], "group": group, **facts}}


ASSETS = [
    _tls("10.20.0.11"), _tls("10.20.0.12"), _tls("10.20.0.13"),  # three endpoints, same kex, same finding, same fix
    _tls("10.20.0.14", "X25519MLKEM768", pq_hybrid=True),  # hybrid: ready
    {"type": "certificate", "target": "10.20.0.11", "location": "/etc/ssl/api.pem", "name": "api", "algorithm": "RSA",
     "key_size": 2048, "facts": {"subject": "CN=api.bank.local", "issuer": "CN=Bank CA", "not_after": "2031-01-01T00:00:00Z",
                                 "sig_alg": "sha256WithRSAEncryption", "key_alg": "RSA", "key_size": 2048,
                                 "fingerprint_sha256": "cd" * 32}},
    {"type": "kms_key", "target": "aws", "location": "arn:aws:kms:ap-south-1:111122223333:key/abc",
     "algorithm": "SYMMETRIC_DEFAULT", "facts": {"key_spec": "SYMMETRIC_DEFAULT", "key_manager": "CUSTOMER",
                                                 "rotation_enabled": True, "key_state": "Enabled"}},  # AES-256: ready
    {"type": "database_config", "target": "10.20.0.2", "location": "10.20.0.2:5432",
     "facts": {"password_encryption": "scram-sha-256"}},  # no public-key algorithm: not judged
]


def _store(api, engine, assets):
    src, run, claim, hdr = _collect_job(api, engine)
    job, lease = claim["job"], claim["job"]["lease_id"]
    r = api("POST", f"/cbom/node/jobs/{job['id']}/assets", None, headers=hdr,
            json={"lease_id": lease, "batch_id": "r271", "assets": assets})
    assert r.status_code == 200, r.text
    return src, run


def test_posture_lists_the_actions_that_raise_readiness(api, world):
    engine, _ = world
    _src, run = _store(api, engine, ASSETS)
    out = api("GET", f"/1/cbom/sources/runs/{run['id']}/posture").json()["posture"]
    # 3 TLS endpoints + 1 certificate quantum-vulnerable, 1 hybrid, 1 symmetric KMS key: 2 of 6 judged are ready
    assert out["pqc_classes"]["quantum-vulnerable"] == 4 and out["readiness_basis"]["judged"] == 6
    assert out["pqc_readiness_pct"] == 33.3
    actions = out["readiness_actions"]
    assert [(a["asset_type"], a["assets"]) for a in actions] == [("tls_endpoint", 3), ("certificate", 1)]
    tls = actions[0]
    assert tls["type_label"] == "TLS endpoint"
    entry = crypto_kb.entry("node", tls["code"])
    assert entry is not None and entry.get("pqc") == "quantum-broken"  # the quantum finding, not a classical weakness
    assert tls["title"] == entry["title"] and tls["fix"] == crypto_kb.summary_fix("node", [tls["code"]])
    # with the 3 endpoints fixed: 5 of 6 judged ready (posture's own readiness function, never the browser)
    assert tls["readiness_after"] == 83.3
    assert actions[1]["readiness_after"] == 50.0
    # the sum of the groups is the quantum-vulnerable class count (each vulnerable asset is in exactly one group)
    assert sum(a["assets"] for a in out["readiness_actions_all"]) == out["pqc_classes"]["quantum-vulnerable"]


def test_posture_says_which_assets_are_left_out_and_why(api, world):
    engine, _ = world
    _src, run = _store(api, engine, ASSETS)
    out = api("GET", f"/1/cbom/sources/runs/{run['id']}/posture").json()["posture"]
    excluded = out["readiness_excluded"]
    assert excluded == [{"class": "not-applicable", "basis": "no_public_key", "assets": 1,
                         "text": P.CLASS_BASIS["no_public_key"][1]}]
    assert sum(e["assets"] for e in excluded) == out["readiness_basis"]["unknown"] + out["readiness_basis"]["not_applicable"]


def test_nothing_vulnerable_means_no_actions():
    assert P.readiness_actions({}, {"quantum-safe": 3}) == ([], [])


def test_actions_are_capped_and_ordered_by_size_then_code():
    groups = {("tls_endpoint", "NO_PQ_KEX"): 2, ("ssh_endpoint", "SSH_NO_PQ_KEX"): 5, ("certificate", "QUANTUM_VULNERABLE"): 2,
              ("ike_endpoint", "IKE_NO_PQ"): 1}
    top, everything = P.readiness_actions(groups, {"quantum-vulnerable": 10, "quantum-safe": 10})
    assert [(a["asset_type"], a["assets"]) for a in top] == [("ssh_endpoint", 5), ("certificate", 2), ("tls_endpoint", 2)]
    assert len(everything) == 4 and top[0]["readiness_after"] == 75.0
    # a group without a quantum finding code still gets a readable title
    (no_code,), _ = P.readiness_actions({("private_key", None): 1}, {"quantum-vulnerable": 1})
    assert no_code["code"] is None and no_code["title"] and no_code["readiness_after"] == 100.0


def test_results_migration_rows_carry_asset_type_and_algorithm(api, world):
    engine, _ = world
    _src, run = _store(api, engine, ASSETS)
    body = api("GET", f"/1/cbom/sources/runs/{run['id']}/results").json()
    rows = body["distributions"]["pqc"]["migration"]
    tls = [r for r in rows if r["asset_type"] == "tls_endpoint"]
    assert len(tls) == 3 and {r["type_label"] for r in tls} == {"TLS endpoint"}
    assert {r["finding_title"] for r in tls} == {crypto_kb.entry("node", tls[0]["migration_code"])["title"]}
    # the algorithm is the quantum-vulnerable component (the key exchange), not the AES bulk cipher of the endpoint
    assert {r["algorithm"] for r in tls} == {"X25519"}
    assert {r["migration_code"] for r in tls} == {next(a["code"] for a in api(
        "GET", f"/1/cbom/sources/runs/{run['id']}/posture").json()["posture"]["readiness_actions"])}


def test_remediation_waves_carry_their_rules(api, world):
    engine, _ = world
    _src, run = _store(api, engine, ASSETS)
    out = api("GET", f"/1/cbom/sources/runs/{run['id']}/remediation").json()
    assert set(out["rules"]) == {"1", "2", "3", "4", "none"}
    assert out["rules"] == {str(k): v for k, v in W.WAVE_RULE.items()}
    assert all(isinstance(v, str) and len(v) > 20 for v in out["rules"].values())
