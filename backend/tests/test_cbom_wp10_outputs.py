"""CBOM outputs B (WP10): diff and drift between runs (renewal, partial job, deleted source, rule change), drift
events, remediation waves that persist across runs, heat-map and certificate list, source metadata, SBOM link, and
the code-scan comparison with Mongo "fixed" + Jira close-on-fixed.

Uses the same SQLite + real-router harness as test_cbom_sources_api.py.
"""
from __future__ import annotations

import datetime as dt
import json
import sys
from pathlib import Path

import pytest
from sqlmodel import Session, select

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_cbom_sources_api import CERT_FACTS, PASSWORD, api, enroll_node, linux_body, world  # noqa: E402,F401

from backend.new_models import (  # noqa: E402
    CbomCollectedAsset,
    CbomCollectionJob,
    CbomCollectionRun,
    CbomDriftEvent,
    CbomRemediationAssignment,
    Scan,
)
from backend.utilities.cbom_sources import drift as DRIFT  # noqa: E402
from backend.utilities.cbom_sources import heatmap as HEAT  # noqa: E402
from backend.utilities.cbom_sources import identity as ID  # noqa: E402
from backend.utilities.cbom_sources import sbom_link as SBOM  # noqa: E402
from backend.utilities.cbom_sources import waves as W  # noqa: E402

NOW = dt.datetime.utcnow()
SOON = (NOW + dt.timedelta(days=12)).strftime("%Y-%m-%dT%H:%M:%SZ")
LATER = (NOW + dt.timedelta(days=400)).strftime("%Y-%m-%dT%H:%M:%SZ")

OLD_CERT = {"type": "certificate", "target": "10.20.0.1", "location": "10.20.0.1:443#chain[0]", "name": "pay",
            "algorithm": "RSA", "key_size": 1024, "facts": CERT_FACTS}
NEW_CERT = {**OLD_CERT, "key_size": 2048, "facts": {**CERT_FACTS, "not_after": SOON, "sig_alg": "sha256WithRSAEncryption",
                                                    "key_size": 2048, "fingerprint_sha256": "cd" * 32}}
WEAK_TLS = {"type": "tls_endpoint", "target": "10.20.0.1", "location": "10.20.0.1:443",
            "facts": {"protocols": ["TLSv1.0", "TLSv1.2"], "group": "x25519", "weak_ciphers": ["DES-CBC3-SHA"]}}
FIXED_TLS = {**WEAK_TLS, "facts": {"protocols": ["TLSv1.2", "TLSv1.3"], "group": "x25519"}}
GONE = {"type": "ssh_host_key", "target": "10.20.0.1", "location": "/etc/ssh/ssh_host_dsa_key.pub", "name": "DSA host key",
        "algorithm": "ssh-dss", "key_size": 1024, "facts": {"type": "ssh-dss", "bits": 1024}}
ADDED = {"type": "ssh_host_key", "target": "10.20.0.1", "location": "/etc/ssh/ssh_host_ed25519_key.pub",
         "name": "ED25519 host key", "algorithm": "ssh-ed25519", "key_size": 256, "facts": {"type": "ssh-ed25519", "bits": 256}}
OPENSSL = {"type": "crypto_library", "target": "10.20.0.1", "location": "package:openssl", "name": "openssl",
           "facts": {"name": "openssl", "version": "3.0.2", "source": "package"}}


def _run(api, rid: str) -> dict:
    r = api("POST", "/1/cbom/sources/runs", json={"include": {"servers": True}, "client_request_id": rid})
    assert r.status_code == 201, r.text
    return r.json()["run"]


def _claim(api, hdr) -> dict:
    r = api("POST", "/cbom/node/jobs/claim", None, headers=hdr)
    assert r.status_code == 200 and r.json(), r.text
    return r.json()


def _collect(api, hdr, claim: dict, assets: list[dict], *, ok=1, failed=0) -> None:
    job = claim["job"]
    if assets:
        r = api("POST", f"/cbom/node/jobs/{job['id']}/assets", None, headers=hdr,
                json={"lease_id": job["lease_id"], "batch_id": "b1", "assets": assets})
        assert r.status_code == 200, r.text
    r = api("POST", f"/cbom/node/jobs/{job['id']}/result", None, headers=hdr, json={
        "lease_id": job["lease_id"], "status": "success",
        "result": {"counts": {"total": ok + failed, "ok": ok, "failed": failed, "skipped": 0}, "asset_count": len(assets),
                   "targets": [{"target": "10.20.0.1", "status": "ok"}]
                   + [{"target": "10.20.0.2", "status": "unreachable"}] * failed}})
    assert r.status_code == 200, r.text


@pytest.fixture()
def two_runs(api, world):
    """Sources A (complete twice) and B (complete, then partial). Between the runs: A's certificate was renewed, its
    TLS endpoint fixed, the DSA host key removed and an Ed25519 key added."""
    engine, _ = world
    node_id, token, _ = enroll_node(api)
    hdr = {"X-ZS-Node-Token": token}
    a = api("POST", "/1/cbom/sources/items", json=linux_body("src-a", node_id=node_id, targets=["10.20.0.1"],
                                                            window="any")).json()["source"]
    b = api("POST", "/1/cbom/sources/items", json=linux_body("src-b", node_id=node_id, targets=["10.20.0.2"],
                                                            window="any")).json()["source"]
    run1 = _run(api, "wp10-run-0001")
    _collect(api, hdr, _claim(api, hdr), [OLD_CERT, WEAK_TLS, GONE, OPENSSL])
    _collect(api, hdr, _claim(api, hdr), [{**WEAK_TLS, "target": "10.20.0.2", "location": "10.20.0.2:443"}])
    run2 = _run(api, "wp10-run-0002")
    _collect(api, hdr, _claim(api, hdr), [NEW_CERT, FIXED_TLS, ADDED, OPENSSL])
    # B: partial (one target unreachable): its missing assets are never reported as removed
    _collect(api, hdr, _claim(api, hdr), [OPENSSL | {"target": "10.20.0.2"}], ok=1, failed=1)
    return {"engine": engine, "a": a, "b": b, "run1": run1, "run2": run2, "hdr": hdr, "node_id": node_id}


# ------------------------------------------------------------------------------------------- diff
def test_diff_shows_renewal_fix_add_remove_and_never_compares_a_partial_job(api, two_runs):
    run1, run2 = two_runs["run1"], two_runs["run2"]
    r = api("GET", f"/1/cbom/sources/runs/{run2['id']}/diff")
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["against_run_id"] == run1["id"]  # the previous comparable run by default
    status = {s["name"]: s for s in d["sources"]}
    assert status["src-a"]["status"] == "compared"
    assert status["src-b"]["status"] == "not_compared" and "partial" in status["src-b"]["reason"]
    renewed = [c for c in d["changed"] if c.get("renewed")]
    assert len(renewed) == 1 and renewed[0]["type"] == "certificate"  # renewal: changed, not removed + added
    assert not any(x["type"] == "certificate" for x in d["added"] + d["removed"])
    resolved = {(x["type"], x["code"]) for x in d["resolved"]}
    assert ("tls_endpoint", "PROTO_TLS10") in resolved and ("tls_endpoint", "WEAK_CIPHER") in resolved
    assert ("certificate", "SIG_MD5") in resolved and ("certificate", "RSA_LT_2048") in resolved
    assert {x["label"].split(" · ")[0] for x in d["removed"]} == {"DSA host key"}
    assert {x["label"].split(" · ")[0] for x in d["added"]} == {"ED25519 host key"}
    assert not any(x["type"] == "tls_endpoint" and x.get("target") == "10.20.0.2" for x in d["removed"])  # B untouched
    assert d["versions"]["rules_changed"] is False and d["rule_changes"] == []
    assert d["readiness"]["before"] is not None and d["readiness"]["after"] >= d["readiness"]["before"]
    # explicit against, either order: the older run is always "before"
    again = api("GET", f"/1/cbom/sources/runs/{run1['id']}/diff?against={run2['id']}").json()
    assert again["against_run_id"] == run1["id"] and again["counts"] == d["counts"]
    assert api("GET", f"/1/cbom/sources/runs/{run1['id']}/diff?against={run1['id']}").status_code == 400
    assert api("GET", f"/2/cbom/sources/runs/{run2['id']}/diff", "carol").status_code == 404


def test_a_deleted_source_still_compares_and_a_new_source_with_its_name_is_another_source(api, two_runs):
    run2, a = two_runs["run2"], two_runs["a"]
    assert api("DELETE", f"/1/cbom/sources/items/{a['id']}").status_code == 200
    d = api("GET", f"/1/cbom/sources/runs/{run2['id']}/diff").json()
    by_name = {s["name"]: s for s in d["sources"]}
    assert by_name["src-a"]["status"] == "compared"  # uid snapshotted on the jobs survives the delete
    again = api("POST", "/1/cbom/sources/items", json=linux_body("src-a", node_id=two_runs["node_id"],
                                                                targets=["10.20.0.1"], window="any")).json()["source"]
    with Session(two_runs["engine"]) as s:
        old_uid = s.exec(select(CbomCollectionJob).where(CbomCollectionJob.run_id == run2["id"])).first().params["source_uid"]
    assert again["id"] != a["id"]
    with Session(two_runs["engine"]) as s:
        from backend.new_models import CbomCollectionSource
        assert s.get(CbomCollectionSource, again["id"]).source_uid != old_uid


def test_a_rule_change_is_re_judged_and_labelled_not_reported_as_drift(api, two_runs):
    engine, run1, run2 = two_runs["engine"], two_runs["run1"], two_runs["run2"]
    with Session(engine) as s:  # run 1 was judged by an older knowledge base whose rule also flagged OLD_RULE
        run = s.get(CbomCollectionRun, run1["id"])
        run.kb_version = "2026.01.01.1"
        s.add(run)
        lib = s.exec(select(CbomCollectedAsset).where(CbomCollectedAsset.run_id == run1["id"],
                                                      CbomCollectedAsset.asset_type == "crypto_library")).one()
        lib.finding_codes = [*(lib.finding_codes or []), "OLD_RULE"]
        s.add(lib)
        s.commit()
    d = api("GET", f"/1/cbom/sources/runs/{run2['id']}/diff").json()
    assert d["versions"]["rules_changed"] is True and d["versions"]["reclassified"] is True
    assert not any(x["code"] == "OLD_RULE" for x in d["resolved"])  # the estate did not change
    rc = [x for x in d["rule_changes"] if x["code"] == "OLD_RULE"]
    assert rc and rc[0]["label_change"] == "rule change" and rc[0]["direction"] == "resolved"
    assert ("tls_endpoint", "PROTO_TLS10") in {(x["type"], x["code"]) for x in d["resolved"]}  # real fixes still shown


# ------------------------------------------------------------------------------------------- drift events
def test_drift_events_are_recorded_once_per_run(api, two_runs):
    engine, run2 = two_runs["engine"], two_runs["run2"]
    first = api("GET", f"/1/cbom/sources/runs/{run2['id']}/changes").json()
    assert first["recorded"] is True
    kinds = first["counts"]
    for kind in ("cert_renewed", "resolved", "new_asset", "removed_asset", "cert_expiring"):
        assert kinds.get(kind, 0) >= 1, (kind, kinds)
    resolved = [e for e in first["events"] if e["kind"] == "resolved"]
    assert all(e["run_id"] == run2["id"] and e["baseline_run_id"] == two_runs["run1"]["id"] for e in resolved)
    again = api("GET", f"/1/cbom/sources/runs/{run2['id']}/changes").json()
    assert again["counts"] == kinds
    # the scheduler path is idempotent too (drift_at compare-and-set; dedupe keys)
    assert DRIFT.record_pending_drift(engine, dt.datetime.utcnow()) == 1  # run 1 (no baseline: nothing to compare)
    assert DRIFT.record_pending_drift(engine, dt.datetime.utcnow()) == 0
    with Session(engine) as s:
        total = len(s.exec(select(CbomDriftEvent).where(CbomDriftEvent.team_id == 1)).all())
    assert total == sum(kinds.values())
    # expiring: once per certificate and expiry date, not once per run
    with Session(engine) as s:
        assert len(s.exec(select(CbomDriftEvent).where(CbomDriftEvent.kind == "cert_expiring")).all()) == 1
    team = api("GET", "/1/cbom/sources/drift?kind=resolved").json()
    assert team["events"] and all(e["kind"] == "resolved" for e in team["events"])
    assert api("GET", "/1/cbom/sources/drift?kind=nope").status_code == 400
    assert api("GET", "/2/cbom/sources/drift", "carol").json()["events"] == []


# ------------------------------------------------------------------------------------------- waves
def test_suggested_wave_rules():
    assert W.suggested_wave("High", ["PROTO_TLS10"], False, internet=True) == 1
    assert W.suggested_wave("Medium", ["QUANTUM_VULNERABLE"], True, hndl=True) == 1
    assert W.suggested_wave("Critical", ["SIG_MD5"], True) == 2
    assert W.suggested_wave("Medium", ["DB_MD5_DEFAULT"], None) == 3
    assert W.suggested_wave("Low", ["QUANTUM_VULNERABLE"], True) == 4
    assert W.suggested_wave(None, [], False) is None


def test_waves_persist_across_runs_and_keys_must_belong_to_the_run(api, two_runs):
    run1, run2 = two_runs["run1"], two_runs["run2"]
    items = api("GET", f"/1/cbom/sources/runs/{run1['id']}/remediation").json()["items"]
    lib = next(i for i in items if i["type"] == "crypto_library")
    tls = next(i for i in items if i["type"] == "tls_endpoint" and i["source_name"] == "src-a")
    # High, private address, but x25519 key exchange in transit: harvest-now-decrypt-later -> wave 1
    assert tls["wave"] == tls["suggested_wave"] == 1 and tls["wave_source"] == "suggested" and tls["hndl"]
    r = api("PUT", "/1/cbom/remediation", json={"run_id": run1["id"], "items": [
        {"asset_key": lib["asset_key"], "wave": 1, "owner": "Platform team", "target_date": "2027-03-31",
         "status": "in_progress"},
        {"asset_key": tls["asset_key"], "owner": "Network team"}]})
    assert r.status_code == 200 and r.json()["updated"] == 2, r.text
    later = {i["asset_key"]: i for i in api("GET", f"/1/cbom/sources/runs/{run2['id']}/remediation").json()["items"]}
    assert later[lib["asset_key"]]["wave"] == 1 and later[lib["asset_key"]]["assignment"]["owner"] == "Platform team"
    assert later[lib["asset_key"]]["assignment"]["target_date"] == "2027-03-31"
    # a partial update keeps the other fields; the owner-only item keeps the suggested wave
    api("PUT", "/1/cbom/remediation", json={"run_id": run2["id"], "items": [{"asset_key": lib["asset_key"], "note": "ok"}]})
    with Session(two_runs["engine"]) as s:
        row = s.exec(select(CbomRemediationAssignment).where(CbomRemediationAssignment.asset_key == lib["asset_key"])).one()
        assert (row.wave, row.owner, row.status, row.note) == (1, "Platform team", "in_progress", "ok")
    bad = api("PUT", "/1/cbom/remediation", json={"run_id": run1["id"], "items": [{"asset_key": "0" * 40, "wave": 2}]})
    assert bad.status_code == 400
    assert api("PUT", "/1/cbom/remediation", json={"run_id": run1["id"], "items": [
        {"asset_key": lib["asset_key"], "target_date": "2027-02-31"}]}).status_code == 400
    assert api("PUT", "/2/cbom/remediation", "carol", json={"run_id": run1["id"], "items": [
        {"asset_key": lib["asset_key"], "wave": 4}]}).status_code == 404


# ------------------------------------------------------------------------------------------- heat-map, calendar
def test_heatmap_matrix_and_certificate_list(api, two_runs):
    run2 = two_runs["run2"]
    h = api("GET", f"/1/cbom/sources/runs/{run2['id']}/heatmap").json()
    assert "RSA" in h["rows"] and "src-a" in h["columns"]
    cell = next(c for c in h["cells"] if c["row"] == "RSA" and c["column"] == "src-a")
    assert cell["count"] >= 1 and cell["worst"] in ("Critical", "High", "Medium", "Low", "none")
    assert sum(cell["by_impact"].values()) == cell["count"]
    assert [c["subject"] for c in h["certificates"]] == ["CN=pay.bank.local"] and 0 <= h["certificates"][0]["days_left"] <= 12
    by_type = api("GET", f"/1/cbom/sources/runs/{run2['id']}/heatmap?by=type").json()
    assert "certificate" in by_type["columns"]
    assert api("GET", f"/1/cbom/sources/runs/{run2['id']}/heatmap?by=nope").status_code == 400


@pytest.mark.parametrize("algorithm,asset_type,facts,family", [
    ("RSA", "certificate", {}, "RSA"),
    (None, "tls_endpoint", {"group": "X25519MLKEM768"}, "Post-quantum"),
    (None, "tls_endpoint", {"group": "x25519"}, "Elliptic curve"),
    ("ssh-ed25519", "ssh_host_key", {}, "EdDSA"),
    ("ssh-dss", "ssh_host_key", {}, "DSA"),
    (None, "certificate", {"key_alg": "EC", "sig_alg": "ecdsa-with-SHA256"}, "Elliptic curve"),
    ("DES-CBC3-SHA", "tls_endpoint", {}, "DES / 3DES"),
    (None, "tls_endpoint", {}, "Protocol (no key data)"),
    (None, "crypto_library", {}, "Library"),
    ("md5WithRSAEncryption", "certificate", {}, "RSA"),
])
def test_algorithm_family(algorithm, asset_type, facts, family):
    assert HEAT.algorithm_family(algorithm, asset_type, facts) == family


# ------------------------------------------------------------------------------------------- metadata
def test_owner_application_classification_are_metadata_kept_and_snapshotted(api, two_runs):
    a = api("GET", f"/1/cbom/sources/items/{two_runs['a']['id']}").json()["source"]
    meta = {"owner": "Payments SRE", "application": "Card switch", "data_classification": "restricted",
            "data_lifetime_years": 10}
    r = api("PATCH", f"/1/cbom/sources/items/{a['id']}", json={"config": {**a["config"], **meta},
                                                                "expected_version": a["row_version"]})
    assert r.status_code == 200, r.text
    cur = r.json()["source"]
    assert {k: cur["config"][k] for k in meta} == meta
    assert cur["last_test_status"] == a["last_test_status"]  # metadata never resets the connection test
    form = {k: v for k, v in cur["config"].items() if k not in meta}
    kept = api("PATCH", f"/1/cbom/sources/items/{a['id']}", json={"config": form, "expected_version": cur["row_version"]})
    assert {k: kept.json()["source"]["config"][k] for k in meta} == meta  # a form without them keeps them
    for bad in ({"data_classification": "secret"}, {"data_lifetime_years": 101}, {"owner": "x" * 129}):
        assert api("PATCH", f"/1/cbom/sources/items/{a['id']}", json={
            "config": {**form, **bad}, "expected_version": kept.json()["source"]["row_version"]}).status_code == 400
    run3 = _run(api, "wp10-run-0003")
    with Session(two_runs["engine"]) as s:
        job = s.exec(select(CbomCollectionJob).where(CbomCollectionJob.run_id == run3["id"],
                                                     CbomCollectionJob.source_id == a["id"])).one()
        assert job.params["metadata"]["owner"] == "Payments SRE" and job.params["source_uid"]


# ------------------------------------------------------------------------------------------- SBOM link
def test_node_library_links_to_the_team_sbom_scan_by_name_and_version(api, two_runs):
    engine = two_runs["engine"]
    with Session(engine) as s:
        s.add(Scan(id=90, team_id=1, owner_user_id=1, scan_type="sbom_sca", title="debian image", scan_status="success",
                   scan_data={"sbom_json": {"components": [
                       {"name": "openssl", "version": "3.0.2", "purl": "pkg:deb/ubuntu/openssl@3.0.2"},
                       {"name": "zlib", "version": "1.2.13"}]}, "results": []}))
        s.add(Scan(id=91, team_id=2, owner_user_id=1, scan_type="sbom_sca", title="other team", scan_status="success",
                   scan_data={"sbom_json": {"components": [{"name": "openssl", "version": "3.0.2"}]}}))
        s.commit()
        lib = s.exec(select(CbomCollectedAsset).where(CbomCollectedAsset.run_id == two_runs["run2"]["id"],
                                                      CbomCollectedAsset.asset_type == "crypto_library",
                                                      CbomCollectedAsset.target == "10.20.0.1")).one()
    r = api("GET", f"/1/cbom/sources/assets/{lib.id}/sbom").json()
    assert r["purl"] == "pkg:generic/openssl@3.0.2"
    assert r["matches"] == [{"scan_id": 90, "scan_title": "debian image", "match": "name_version",
                             "component": "openssl@3.0.2", "purl": "pkg:deb/ubuntu/openssl@3.0.2"}]
    export = api("GET", f"/1/cbom/sources/runs/{two_runs['run2']['id']}/cbom").json()
    libs = [c for c in export["components"] if c["type"] == "library"]
    assert libs and libs[0]["purl"] == "pkg:generic/openssl@3.0.2"


def test_code_library_components_get_a_purl():
    bom = {"components": [
        {"type": "library", "name": "pyca/cryptography", "properties": [{"name": "crypto:language", "value": "pip-requirements"}]},
        {"type": "library", "name": "hashlib (stdlib)", "properties": [{"name": "crypto:language", "value": "python"}]},
        {"type": "library", "name": "lodash@4.17.20", "properties": [{"name": "crypto:ecosystem", "value": "npm"}]},
        {"type": "library", "name": "x", "purl": "pkg:pypi/x@1"},
        {"type": "cryptographic-asset", "name": "AES"}]}
    out = SBOM.with_library_purls(bom)
    assert [c.get("purl") for c in out["components"]] == ["pkg:pypi/cryptography", None, "pkg:npm/lodash@4.17.20",
                                                          "pkg:pypi/x@1", None]
    assert "purl" not in bom["components"][0]  # a copy: the stored document is not changed


# ------------------------------------------------------------------------------------------- code scans
def _row(title, location, codes, *, impact="High", line=10, ref=None, **extra):
    return {"title": title, "algorithm_name": title, "asset_type": extra.pop("asset_type", "algorithm"),
            "location": location, "line": line, "bom_ref": ref or f"crypto-algo-{title.lower()}-{location}",
            "finding_codes": codes, "impact": impact if codes else None, "quantum_safe": extra.pop("quantum_safe", None),
            **extra}


class _FakeMongo:
    def __init__(self, docs):
        self.docs = docs

    def __getitem__(self, _name):
        return self

    def find(self, query):
        return [d for d in self.docs if all(d.get(k) == v for k, v in query.items())]

    def update_one(self, query, change):
        hit = [d for d in self.docs if d["_id"] == query["_id"]]
        for d in hit:
            d.update(change["$set"])
        return type("R", (), {"modified_count": len(hit)})()


def test_code_scans_compare_line_independently_and_mark_fixed_findings(world, monkeypatch):
    engine, ids = world
    meta = {"repo_url": "https://github.com/acme/pay.git", "branch": "main"}
    misuse_old = _row("static-iv (iv, app.py)", "app.py", ["STATIC_IV"], line=40,
                      ref="crypto-material-misuse-static-iv-iv-app-py-l40", asset_type="related-crypto-material")
    misuse_new = {**misuse_old, "line": 55, "bom_ref": "crypto-material-misuse-static-iv-iv-app-py-l55"}
    des = _row("3DES-CBC", "app.py", ["WEAK_ALGORITHM"])
    rsa = _row("RSA-2048", "keys.py", ["QUANTUM_VULNERABLE"], impact="Low", quantum_safe=False)
    aes = _row("AES-256-GCM", "app.py", [], quantum_safe=True)
    with Session(engine) as s:
        s.add(Scan(id=40, team_id=1, owner_user_id=ids["alice"], scan_type="cbom", title="pay", scan_status="success",
                   scan_metadata=meta, created_at=dt.datetime(2026, 10, 1),
                   scan_data={"results": [misuse_old, des, rsa], "cbom_json": {"metadata": {"tools": [{"name": "aibom", "version": "1"}]}}}))
        s.add(Scan(id=41, team_id=1, owner_user_id=ids["alice"], scan_type="cbom", title="pay", scan_status="success",
                   scan_metadata={**meta, "repo_url": "https://user:tok@github.com/acme/pay"}, created_at=dt.datetime(2026, 10, 9),
                   scan_data={"results": [misuse_new, rsa, aes], "cbom_json": {"metadata": {"tools": [{"name": "aibom", "version": "1"}]}}}))
        s.add(Scan(id=42, team_id=1, owner_user_id=ids["alice"], scan_type="cbom", title="pay", scan_status="success",
                   scan_metadata={**meta, "branch": "dev"}, created_at=dt.datetime(2026, 10, 10), scan_data={"results": [des]}))
        s.commit()
        scan41 = s.get(Scan, 41)
        base = DRIFT.previous_code_scan(s, scan41)
        assert base is not None and base.id == 40  # same repository and branch (credentials and .git ignored)
        assert DRIFT.previous_code_scan(s, s.get(Scan, 42)) is None  # another branch
        diff = DRIFT.code_scan_diff(scan41, base)
    assert diff["removed"] and [x["label"].split(" · ")[0] for x in diff["removed"]] == ["3DES-CBC"]
    assert not any("static-iv" in x["label"] for x in diff["added"] + diff["removed"])  # the line moved, nothing else
    assert [x["code"] for x in diff["resolved"]] == ["WEAK_ALGORITHM"]
    assert [x["label"].split(" · ")[0] for x in diff["added"]] == ["AES-256-GCM"] and not diff["opened"]
    docs = [{"_id": 1, "scan_id": 40, "finding_data": des, "finding_status": "not_started",
             "info": {"jira_issue_key": "SEC-1"}},
            {"_id": 2, "scan_id": 40, "finding_data": misuse_old, "finding_status": "in_progress"},
            {"_id": 3, "scan_id": 40, "finding_data": {**des, "location": "other.py"}, "finding_status": "ignored"}]
    closed = []
    from backend.utilities.integrations import jira_ticketing
    monkeypatch.setattr(jira_ticketing, "close_jira_issue_for_finding", lambda doc, team: closed.append(doc["_id"]))
    import backend.get_db as get_db_module
    monkeypatch.setattr(get_db_module, "get_mongo_client_db", lambda: _FakeMongo(docs))
    out = DRIFT.on_code_scan_success(41, engine, now=dt.datetime(2026, 10, 9, 12))
    assert out["fixed"] == 1 and closed == [1]
    assert docs[0]["finding_status"] == "fixed" and docs[0]["info"]["resolved_in_scan"] == 41
    assert docs[0]["info"]["jira_issue_key"] == "SEC-1"
    assert docs[1]["finding_status"] == "in_progress" and docs[2]["finding_status"] == "ignored"
    with Session(engine) as s:
        events = s.exec(select(CbomDriftEvent).where(CbomDriftEvent.scan_id == 41)).all()
    assert {(e.kind, e.code) for e in events} >= {("resolved", "WEAK_ALGORITHM"), ("removed_asset", None),
                                                  ("new_asset", None)}
    assert all(e.source_ref == "repo:github.com/acme/pay@main" for e in events)
    assert DRIFT.on_code_scan_success(41, engine, now=dt.datetime(2026, 10, 9, 12))["events"] == 0  # once


def test_code_identity_ignores_line_markers_only():
    a = {"asset_type": "related-crypto-material", "location": "a.py", "title": "k", "bom_ref": "crypto-material-x-l12"}
    assert ID.code_identity(a) == ID.code_identity({**a, "bom_ref": "crypto-material-x-l99", "line": 99})
    assert ID.code_identity(a) != ID.code_identity({**a, "location": "b.py"})


def test_code_scan_api_diff_and_remediation(api, world):
    engine, ids = world
    meta = {"repo_url": "https://github.com/acme/web", "branch": "main"}
    des = _row("3DES-CBC", "app.py", ["WEAK_ALGORITHM"])
    rsa = _row("RSA-2048", "keys.py", ["QUANTUM_VULNERABLE"], impact="Low", quantum_safe=False)
    with Session(engine) as s:
        s.add(Scan(id=50, team_id=1, owner_user_id=ids["alice"], scan_type="cbom", title="web", scan_status="success",
                   scan_metadata=meta, created_at=dt.datetime(2026, 10, 1), scan_data={"results": [des, rsa]}))
        s.add(Scan(id=51, team_id=1, owner_user_id=ids["alice"], scan_type="cbom", title="web", scan_status="success",
                   scan_metadata=meta, created_at=dt.datetime(2026, 10, 2), scan_data={"results": [rsa]}))
        s.commit()
    d = api("GET", "/1/cbom/code-scans/51/diff").json()
    assert d["against_scan_id"] == 50 and [x["code"] for x in d["resolved"]] == ["WEAK_ALGORITHM"]
    assert api("GET", "/1/cbom/code-scans/77/diff").status_code == 409  # not completed
    items = api("GET", "/1/cbom/code-scans/51/remediation").json()["items"]
    assert [(i["label"].split(" · ")[0], i["suggested_wave"]) for i in items] == [("RSA-2048", 4)]
    r = api("PUT", "/1/cbom/remediation", json={"scan_id": 51, "items": [{"asset_key": items[0]["asset_key"], "wave": 3,
                                                                          "owner": "AppSec"}]})
    assert r.status_code == 200
    assert api("GET", "/1/cbom/code-scans/50/remediation").json()["items"][1]["assignment"]["owner"] == "AppSec"


def test_roadmap_pdf_fills_wave_owner_target_and_lists_node_assets(api, two_runs):
    from backend.utilities.dashboard.cbom_team_rollup import load_team_cbom_view
    from backend.utilities.pdf import cbom_pqc_roadmap_pdf as roadmap
    from backend.utilities.pdf.cbom_deliverable_common import get_deliverable_styles

    engine, run2 = two_runs["engine"], two_runs["run2"]
    items = api("GET", f"/1/cbom/sources/runs/{run2['id']}/remediation").json()["items"]
    cert = next(i for i in items if i["type"] == "certificate")
    api("PUT", "/1/cbom/remediation", json={"run_id": run2["id"], "items": [
        {"asset_key": cert["asset_key"], "wave": 2, "owner": "PKI team", "target_date": "2027-06-30", "status": "open"}]})
    rsa = _row("RSA-1024", "pay.py", ["WEAK_ALGORITHM", "QUANTUM_VULNERABLE"], quantum_safe=False,
               nist_quantum_security_level=0, security_strength_bits=80, primitive="pke", key_size="1024")
    with Session(engine) as s:
        s.add(Scan(id=60, team_id=1, owner_user_id=1, scan_type="cbom", title="pay", scan_status="success",
                   scan_metadata={"repo_url": "https://github.com/acme/pay", "branch": "main"},
                   scan_data={"results": [rsa], "cbom_json": {"components": []}}))
        s.commit()
    view = load_team_cbom_view(engine, 1)
    assert view.remediation is not None and view.remediation["node_rows"]
    code = next(i for i in api("GET", "/1/cbom/code-scans/60/remediation").json()["items"])
    api("PUT", "/1/cbom/remediation", json={"scan_id": 60, "items": [
        {"asset_key": code["asset_key"], "wave": 1, "owner": "AppSec", "target_date": "2027-01-15"}]})
    view = load_team_cbom_view(engine, 1)
    body = roadmap.build_body(view, get_deliverable_styles(), 720)
    tables = [f for f in body if f.__class__.__name__ == "Table"]

    def cells(table):
        out = []
        for row in table._cellvalues:
            out.append([getattr(c, "text", c if isinstance(c, str) else "") for c in row])
        return out

    flat = json.dumps([cells(t) for t in tables])
    assert "2027-01-15" in flat and "AppSec" in flat  # code-scan roadmap row: assigned
    assert "PKI team / open" in flat and "2027-06-30" in flat  # scan-node certificate: assigned
    assert "(suggested)" in flat  # node assets without an assignment show the suggested wave
    assert "(assessor)" not in flat
    pdf = roadmap.build_pdf(view)
    assert pdf.startswith(b"%PDF")
