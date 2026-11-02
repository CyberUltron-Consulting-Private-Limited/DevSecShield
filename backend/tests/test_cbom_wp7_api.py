"""WP7 through the real routers (SQLite): an appliance source is created with a write-only secret, its connection
test and collect jobs carry the device list as targets, and the IKE / appliance / OT / mesh rows a node posts are
stored and classified.  Reuses the fixtures of test_cbom_sources_api.py."""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_cbom_sources_api as base  # noqa: E402

world, api, enroll_node, PASSWORD = base.world, base.api, base.enroll_node, base.PASSWORD
KNOWN = "10.30.0.1 ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEmKSENjQEezOmxkZMy7opKgwFB9nkt5YRrYMjNuG5N87uRgg6CLrbo5wAdT/y6v0mKV0U2w0WZ2YB/++Tpockg="


def appliance_body(node_id, **cfg):
    return {"kind": "appliance", "name": "edge-asa", "node_id": node_id,
            "config": {"vendor": "cisco_asa", "targets": ["10.30.0.1", "10.30.0.2"], "login_user": "zs-cbom",
                       "credential_type": "password", "host_key_policy": "pinned", "known_hosts": KNOWN, **cfg},
            "secrets": {"password": PASSWORD}}


def test_appliance_source_round_trip(api, world):
    node_id, token, _ = enroll_node(api)
    r = api("POST", "/1/cbom/sources/items", json=appliance_body(node_id))
    assert r.status_code == 201, r.text
    src = r.json()["source"]
    assert src["kind"] == "appliance" and src["group"] == "network" and src["secrets_set"] == ["password"]
    assert PASSWORD not in r.text and src["config"]["port"] == 22
    bad = api("POST", "/1/cbom/sources/items", json={**appliance_body(node_id, known_hosts=None), "name": "x"})
    assert bad.status_code == 400 and "known_hosts" in bad.text
    t = api("POST", f"/1/cbom/sources/items/{src['id']}/test").json()
    assert t["status"] == "queued"
    claim = api("POST", "/cbom/node/jobs/claim", None, headers={"X-ZS-Node-Token": token})
    assert claim.status_code == 200, claim.text
    payload = claim.json()
    assert payload["source"]["kind"] == "appliance" and payload["source"]["secrets"]["password"] == PASSWORD
    assert payload["scope"]["targets"] == ["10.30.0.1", "10.30.0.2"]


def test_wp7_rows_are_stored_and_classified(api, world):
    engine, _ = world
    src, run, claim, hdr = base._collect_job(api, engine)
    job, lease = claim["job"], claim["job"]["lease_id"]
    ike = {"service": "ike", "port": 500, "ikev2": {"supported": True, "pq": {"supported": False},
                                                    "weak": {"dh": {"accepted": ["MODP-1024"]}}},
           "ikev1": {"supported": True, "accepts": True, "aggressive": True, "aggressive_auth": "PSK"}}
    batch = [
        {"type": "ike_endpoint", "target": "10.20.0.1", "location": "10.20.0.1:500", "name": "IKE",
         "algorithm": "AES-CBC-256", "protocol": "IKEv2", "facts": ike},
        {"type": "ot_endpoint", "target": "10.20.0.1", "location": "10.20.0.1:502", "protocol": "modbus",
         "facts": {"service": "modbus", "tls": False}},
        {"type": "appliance_config", "target": "10.20.0.1", "location": "10.20.0.1:22#ssh",
         "facts": {"kind": "ssh", "versions": [1], "vendor_label": "Cisco ASA"}},
        {"type": "k8s_mesh_destination", "target": "10.20.0.1", "location": "pay/destinationrule/x",
         "facts": {"host": "x.pay", "tls_mode": "DISABLE"}},
        {"type": "k8s_mesh_server", "target": "10.20.0.1", "location": "vote/server/metrics",
         "facts": {"namespace": "vote", "name": "metrics", "port": 9100, "unauthenticated": True,
                   "unauthenticated_by": ["accessPolicy all-unauthenticated"]}},
    ]
    r = api("POST", f"/cbom/node/jobs/{job['id']}/assets", None, headers=hdr,
            json={"lease_id": lease, "batch_id": "w7", "assets": batch})
    assert r.status_code == 200 and r.json()["accepted"] == 5 and r.json()["rejected"] == 0, r.text
    items = {a["location"]: a for a in api("GET", f"/1/cbom/sources/runs/{run['id']}/assets").json()["items"]}
    assert {"IKE_WEAK_DH", "IKEV1_ENABLED", "IKE_AGGRESSIVE", "IKE_NO_PQ"} <= set(items["10.20.0.1:500"]["finding_codes"])
    assert items["10.20.0.1:502"]["finding_codes"] == ["MODBUS_PLAINTEXT"]
    assert items["10.20.0.1:22#ssh"]["finding_codes"] == ["SSH_V1_ENABLED"]
    assert items["pay/destinationrule/x"]["finding_codes"] == ["MESH_DR_TLS_DISABLED"]
    assert items["vote/server/metrics"]["finding_codes"] == ["LINKERD_UNAUTHENTICATED_SERVER"]
    assert json.dumps(items).count("High") >= 4
