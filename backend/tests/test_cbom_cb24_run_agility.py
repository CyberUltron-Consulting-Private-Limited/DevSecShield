"""CB-24 PR-1: the fix class on every run surface, computed at view time (SQLite + the real routers).

Run asset list items, the asset detail, the run posture counts (all codes and without the post-quantum codes,
unknown reasons, self-fixable share, systems by application), evidence items, the agility model route, and the new
source metadata ``operated_by`` (snapshotted on the job, so a later edit never re-classifies an old run).
Uses the same harness as test_cbom_sources_api.py / test_cbom_wp10_outputs.py.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest
from sqlmodel import Session, select

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_cbom_sources_api as HARNESS  # noqa: E402
from test_cbom_sources_api import enroll_node, linux_body  # noqa: E402
from test_cbom_wp10_outputs import _claim, _collect, _run  # noqa: E402

from backend.new_models import CbomCollectionJob  # noqa: E402

api, world = HARNESS.api, HARNESS.world  # the harness's fixtures, used by name below

SIX = {"configurable", "code-fixed", "vendor-fixed", "hardware-fixed", "unknown", "none"}
TLS10 = {"type": "tls_endpoint", "target": "10.20.0.1", "location": "10.20.0.1:443",
         "facts": {"protocols": ["TLSv1.0", "TLSv1.2", "TLSv1.3"], "pq_group_supported": True}}
TLS_NO_PQ = {"type": "tls_endpoint", "target": "10.20.0.1", "location": "10.20.0.1:8443",
             "facts": {"protocols": ["TLSv1.2", "TLSv1.3"], "pq_group_supported": False}}
SSH_96 = {"type": "ssh_endpoint", "target": "10.20.0.1", "location": "10.20.0.1:22",
          "facts": {"banner": "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5", "kex": ["curve25519-sha256"]}}
WIN_CERT = {"type": "certificate", "target": "10.20.0.1", "location": "Cert:\\LocalMachine\\My\\AB12", "name": "web",
            "algorithm": "RSA", "key_size": 2048,
            "facts": {"subject": "CN=web.bank.local", "issuer": "CN=Bank CA", "not_after": "2030-01-01T00:00:00Z",
                      "key_alg": "RSA", "key_size": 2048, "source": "windows-store", "has_private_key": True}}
AES = {"type": "kms_key", "target": "10.20.0.1", "location": "vault:transit/aes", "name": "aes",
       "algorithm": "AES", "key_size": 256, "facts": {"key_spec": "SYMMETRIC_DEFAULT"}}


@pytest.fixture()
def runs(api, world):
    """Two sources on one node: A (application "Card switch", operated by us) and B (operated by a vendor)."""
    engine, _ = world
    node_id, token, _ = enroll_node(api)
    hdr = {"X-ZS-Node-Token": token}
    a = api("POST", "/1/cbom/sources/items", json=linux_body(
        "src-a", node_id=node_id, targets=["10.20.0.1"], window="any", application="Card switch")).json()["source"]
    b = api("POST", "/1/cbom/sources/items", json=linux_body(
        "src-b", node_id=node_id, targets=["10.20.0.2"], window="any", operated_by="vendor")).json()["source"]
    assert b["config"]["operated_by"] == "vendor" and a["config"].get("operated_by") is None
    run = _run(api, "cb24-run-0001")
    _collect(api, hdr, _claim(api, hdr), [TLS10, TLS_NO_PQ, SSH_96, WIN_CERT, AES])
    _collect(api, hdr, _claim(api, hdr), [{**TLS10, "target": "10.20.0.2", "location": "10.20.0.2:443"}])
    return {"engine": engine, "a": a, "b": b, "run": run, "hdr": hdr}


def _items(api, run_id):
    r = api("GET", f"/1/cbom/sources/runs/{run_id}/assets?page_size=200")
    assert r.status_code == 200, r.text
    return r.json()["items"]


def test_run_asset_list_items_carry_the_fix_class(api, runs):
    items = _items(api, runs["run"]["id"])
    for item in items:
        assert item["fix_class"] in SIX and "fix_class_floor" in item and "fix_class_confidence" in item
    by = {(i["source_name"], i["location"]): i for i in items}
    ours = by[("src-a", "10.20.0.1:443")]
    assert (ours["fix_class"], ours["fix_class_confidence"]) == ("configurable", "observed")
    theirs = by[("src-b", "10.20.0.2:443")]  # the same weakness on a vendor-operated source
    assert (theirs["fix_class"], theirs["fix_class_confidence"]) == ("vendor-fixed", "observed")
    no_pq = by[("src-a", "10.20.0.1:8443")]
    assert (no_pq["fix_class"], no_pq["fix_class_confidence"]) == ("vendor-fixed", "inferred")
    assert by[("src-a", "10.20.0.1:22")]["fix_class"] == "configurable"  # OpenSSH 9.6: R-STACK
    win = by[("src-a", "Cert:\\LocalMachine\\My\\AB12")]
    assert (win["fix_class"], win["fix_class_floor"]) == ("unknown", "vendor-fixed")  # key provider not read yet
    assert by[("src-a", "vault:transit/aes")]["fix_class"] == "none"
    job_id = ours["job_id"]
    r = api("GET", f"/1/cbom/sources/jobs/{job_id}/assets")
    assert r.status_code == 200 and all(i["fix_class"] in SIX for i in r.json()["items"])


def test_asset_detail_explains_the_class_per_code(api, runs):
    items = _items(api, runs["run"]["id"])
    no_pq = next(i for i in items if i["location"] == "10.20.0.1:8443")
    r = api("GET", f"/1/cbom/sources/assets/{no_pq['id']}")
    assert r.status_code == 200, r.text
    agility = r.json()["asset"]["agility"]
    assert (agility["fix_class"], agility["confidence"], agility["source"]) == ("vendor-fixed", "inferred", "view")
    assert agility["model"] == "fx-1" and agility["model_version"].startswith("fx-1+")
    per = {p["code"]: p for p in agility["by_code"]}
    assert per["NO_PQ_KEX"]["rule"] == "R-INFERRED" and per["NO_PQ_KEX"]["basis"]
    assert agility["fix_class_excl_pq"] == "none"
    vendor = next(i for i in items if i["source_name"] == "src-b")
    detail = api("GET", f"/1/cbom/sources/assets/{vendor['id']}").json()["asset"]["agility"]
    assert {p["rule"] for p in detail["by_code"]} == {"R-VENDOR"}
    assert all(p["fact"] == "source operated by a vendor (source metadata)" for p in detail["by_code"])


def test_run_posture_counts_classes_with_and_without_post_quantum_codes(api, runs):
    r = api("GET", f"/1/cbom/sources/runs/{runs['run']['id']}/posture")
    assert r.status_code == 200, r.text
    p = r.json()["posture"]
    assert set(p["fix_classes"]) == SIX and set(p["fix_classes_excl_pq"]) == SIX
    assert sum(p["fix_classes"].values()) == p["assets"] == sum(p["fix_classes_excl_pq"].values())
    assert p["fix_classes"] == {"configurable": 2, "code-fixed": 0, "vendor-fixed": 2, "hardware-fixed": 0,
                                "unknown": 1, "none": 1}
    # without the post-quantum codes the no-PQ endpoint, the SSH server (only SSH_NO_PQ_KEX) and the Windows
    # certificate have nothing to change
    assert p["fix_classes_excl_pq"] == {"configurable": 1, "code-fixed": 0, "vendor-fixed": 1, "hardware-fixed": 0,
                                        "unknown": 0, "none": 4}
    assert p["unknown_reasons"] == {"key_provider_not_read": 1}
    assert p["fix_class_self_fixable_pct"] == 50.0
    assert p["agility_version"].startswith("fx-1+")
    systems = {s["label"]: s for s in p["fix_class_systems"]}
    assert set(systems) == {"Card switch", "src-b"}
    assert systems["Card switch"]["kind"] == "application" and systems["Card switch"]["assets"] == 5
    assert systems["Card switch"]["hardest"] == "vendor-fixed"
    assert systems["src-b"]["kind"] == "source" and systems["src-b"]["counts"]["vendor-fixed"] == 1
    assert p["fix_class_systems_truncated"] is False


def test_operated_by_is_validated_snapshotted_and_a_later_edit_never_reclassifies_the_run(api, runs):
    b = api("GET", f"/1/cbom/sources/items/{runs['b']['id']}").json()["source"]
    bad = api("PATCH", f"/1/cbom/sources/items/{b['id']}", json={"config": {**b["config"], "operated_by": "them"},
                                                                  "expected_version": b["row_version"]})
    assert bad.status_code == 400
    with Session(runs["engine"]) as s:
        job = s.exec(select(CbomCollectionJob).where(CbomCollectionJob.run_id == runs["run"]["id"],
                                                     CbomCollectionJob.source_id == b["id"])).one()
        assert job.params["metadata"]["operated_by"] == "vendor"
    ok = api("PATCH", f"/1/cbom/sources/items/{b['id']}", json={"config": {**b["config"], "operated_by": "us"},
                                                                 "expected_version": b["row_version"]})
    assert ok.status_code == 200, ok.text
    assert ok.json()["source"]["last_test_status"] == b["last_test_status"]  # metadata: no connection re-test
    theirs = next(i for i in _items(api, runs["run"]["id"]) if i["source_name"] == "src-b")
    assert theirs["fix_class"] == "vendor-fixed"  # the run keeps the snapshot it was created with


def test_evidence_items_carry_their_class(api, runs):
    ev = api("GET", "/1/cbom/sources/evidence").json()
    areas = {a["area_key"]: a for a in ev["areas"]}
    assert (areas["hsm_firmware"]["fix_class"], areas["hsm_firmware"]["not_assessed"]) == (None, True)
    assert (areas["key_hierarchy"]["fix_class"], areas["key_hierarchy"]["not_assessed"]) == (None, False)
    r = api("PATCH", "/1/cbom/sources/evidence/hsm_firmware", json={
        "answers": {"model": "SoftHSM v2", "firmware": "2.6"}, "expected_version": areas["hsm_firmware"]["row_version"]})
    assert r.status_code == 200, r.text
    v = api("POST", "/1/cbom/sources/evidence/vendors", json={"name": "Card processor"})
    assert v.status_code == 201, v.text
    assert v.json()["vendor"]["fix_class"] == "vendor-fixed"
    ev = api("GET", "/1/cbom/sources/evidence").json()
    areas = {a["area_key"]: a for a in ev["areas"]}
    assert (areas["hsm_firmware"]["fix_class"], areas["hsm_firmware"]["not_assessed"]) == ("hardware-fixed", False)
    assert [x["fix_class"] for x in ev["vendors"]] == ["vendor-fixed"]


def test_agility_model_route(api, runs):
    r = api("GET", "/1/cbom/sources/agility-model")
    assert r.status_code == 200, r.text
    m = r.json()
    assert m["model"] == "fx-1" and [c["key"] for c in m["classes"][:4]] == [
        "configurable", "code-fixed", "vendor-fixed", "hardware-fixed"]
    assert m["kb_version"] and m["model_version"].startswith("fx-1+") and len(m["rules"]) == 10
    assert api("GET", "/1/cbom/sources/agility-model", who=None).status_code in (401, 403)


# ------------------------------------------------------------------------------------------- review A (PR #113)
def test_a_malformed_fact_never_breaks_the_run_views_and_reads_as_unread(api, world):
    """One asset whose deciding facts are lists or dicts (node facts are free-form) must not turn the run's asset
    list, posture and detail into HTTP 500: the fact is treated as not read (unknown, reason fact_unreadable)."""
    node_id, token, _ = enroll_node(api)
    hdr = {"X-ZS-Node-Token": token}
    api("POST", "/1/cbom/sources/items", json=linux_body("src-m", node_id=node_id, targets=["10.20.0.1"], window="any"))
    run = _run(api, "cb24-run-0009")
    bad = {"type": "managed_key", "target": "10.20.0.1", "location": "pkcs11:slot0/kx", "name": "kx",
           "algorithm": "RSA", "key_size": 2048,
           "facts": {"store": ["pkcs11"], "token_class": {"x": 1}, "source": ["a"], "key_provider_class": [1],
                     "banner": {"b": 2}, "key_class": "private"}}
    _collect(api, hdr, _claim(api, hdr), [TLS10, bad])
    listed = api("GET", f"/1/cbom/sources/runs/{run['id']}/assets?page_size=200")
    assert listed.status_code == 200, listed.text
    item = next(i for i in listed.json()["items"] if i["location"] == "pkcs11:slot0/kx")
    assert (item["fix_class"], item["fix_class_floor"]) == ("unknown", "vendor-fixed")
    posture = api("GET", f"/1/cbom/sources/runs/{run['id']}/posture")
    assert posture.status_code == 200, posture.text
    assert posture.json()["posture"]["unknown_reasons"] == {"fact_unreadable": 1}
    detail = api("GET", f"/1/cbom/sources/assets/{item['id']}")
    assert detail.status_code == 200, detail.text
    assert {p["rule"] for p in detail.json()["asset"]["agility"]["by_code"]} == {"R-HW-UNREAD"}


def test_deleting_a_source_never_reclassifies_its_old_runs(api, world):
    """R-HW (appliance) and R-VENDOR (SaaS IdP) read the source; after the source is deleted, its old runs keep the
    class they had (the kind and provider are kept on the job when the source goes)."""
    engine, _ = world
    from backend.new_models import CbomCollectedAsset, CbomCollectionSource
    from backend.utilities.cbom_sources import agility as AGILITY

    node_id, token, _ = enroll_node(api)
    hdr = {"X-ZS-Node-Token": token}
    src = api("POST", "/1/cbom/sources/items", json=linux_body("src-d", node_id=node_id, targets=["10.20.0.1"],
                                                               window="any")).json()["source"]
    run = _run(api, "cb24-run-0010")
    _collect(api, hdr, _claim(api, hdr), [TLS_NO_PQ])
    with Session(engine) as s:  # make it an appliance source (the kind is fixed at creation in the API)
        row = s.get(CbomCollectionSource, src["id"])
        row.kind = "appliance"
        s.add(row)
        s.commit()
    before = next(i for i in _items(api, run["id"]) if i["location"] == "10.20.0.1:8443")
    assert (before["fix_class"], before["fix_class_confidence"]) == ("hardware-fixed", "observed")
    with Session(engine) as s:
        assert s.get(CbomCollectionSource, src["id"]) is not None
    assert api("DELETE", f"/1/cbom/sources/items/{src['id']}").status_code == 200
    after = next(i for i in _items(api, run["id"]) if i["location"] == "10.20.0.1:8443")
    assert (after["fix_class"], after["fix_class_confidence"]) == ("hardware-fixed", "observed")
    with Session(engine) as s:
        asset = s.exec(select(CbomCollectedAsset).where(CbomCollectedAsset.location == "10.20.0.1:8443")).one()
        job = s.get(CbomCollectionJob, asset.job_id)
        assert AGILITY.node_context(job, None)["source_kind"] == "appliance"
