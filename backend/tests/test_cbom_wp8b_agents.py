"""WP8b: agent-mode scan nodes and agent pool tokens (Helm DaemonSet), container-image sources, purls from node
package databases, and code-scan coverage notes.

Runs on SQLite with the real routers, real JWTs and the REAL scan-node client and collectors (``scan_node/`` on the
path), so the node's agent-mode enrollment, claim, host collection and result posting go through the actual routes.
"""
from __future__ import annotations

import base64
import datetime as dt
import json
import sys
import time
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519
from sqlmodel import Session, select

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scan_node"))

from test_cbom_sources_api import PASSWORD, api, linux_body, world  # noqa: E402,F401  (fixtures)
from backend.new_models import (  # noqa: E402
    CbomCollectedAsset,
    CbomCollectionJob,
    CbomCollectionSource,
    CbomNodePool,
    CbomScanNode,
)
from backend.utilities.cbom_sources import agents as AG  # noqa: E402
from backend.utilities.cbom_sources import secret_refs as SR  # noqa: E402
from backend.utilities.dashboard.cbom_coverage import coverage_report  # noqa: E402
from zs_scan_node import api as node_api  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]


def _client(api, key=None, token=None) -> node_api.Api:
    client = node_api.Api("http://testserver", token, signing_key=key)
    client.client = api.client  # the TestClient is an httpx.Client: the real node code talks to the real routes
    client._wait = lambda seconds: None
    return client


def _pool(api, who="alice", **kw):
    body = {"name": "k8s-prod", "segment": "Cluster", "expires_in_hours": 24, "max_enrollments": 3, **kw}
    r = api("POST", "/1/cbom/sources/node-pools", who, json=body)
    assert r.status_code == 201, r.text
    return r.json()["pool"], r.json()["registration_token"]


def _enroll_agent(api, token, node_name, signed=True):
    key = ed25519.Ed25519PrivateKey.generate() if signed else None
    client = _client(api, key)
    body = {"registration_token": token, "hostname": f"zs-agent-{node_name}", "version": "1.0.0", "mode": "agent",
            "node_name": node_name, "capabilities": {"collectors": ["host_agent"], "mode": "agent"},
            "clock": dt.datetime.utcnow().isoformat() + "Z"}
    if key:
        body["signing_public_key"] = base64.b64encode(key.public_key().public_bytes_raw()).decode()
    data = client.enroll(body)
    client.token, client.deployment_id = data["node_token"], data["deployment_id"]
    return client, data


# ----------------------------------------------------------------------------- pool tokens
def test_pool_token_is_shown_once_listed_without_it_and_revocable_by_owner_or_admin(api, world):
    pool, token = _pool(api, who="bob")
    assert token.startswith("zsp_") and pool["status"] == "active" and pool["enrollments"] == 0
    listed = api("GET", "/1/cbom/sources/node-pools").json()["pools"]
    assert listed[0]["id"] == pool["id"] and token not in json.dumps(listed)
    assert api("GET", "/1/cbom/sources/node-pools", "carol").status_code == 403  # another team: not a member
    assert api("POST", f"/2/cbom/sources/node-pools/{pool['id']}/revoke", "carol").status_code == 404
    other, _ = _pool(api, who="alice", name="other")
    assert api("POST", f"/1/cbom/sources/node-pools/{other['id']}/revoke", "bob").status_code == 400  # not his
    r = api("POST", f"/1/cbom/sources/node-pools/{pool['id']}/revoke", "alice")  # admin
    assert r.status_code == 200 and r.json()["pool"]["status"] == "revoked"
    bad = api("POST", "/1/cbom/sources/node-pools", json={"name": "x", "expires_in_hours": 24 * 91})
    assert bad.status_code == 400


def test_each_pod_enrolls_as_its_own_agent_node_with_its_own_host_source(api, world):
    engine, _ = world
    pool, token = _pool(api, max_enrollments=3)
    a, data_a = _enroll_agent(api, token, "k3s-worker-a")
    b, data_b = _enroll_agent(api, token, "k3s-worker-a")  # same Kubernetes node name: a suffix keeps names unique
    assert data_a["mode"] == "agent" and data_a["signing"] == "required"
    nodes = {n["id"]: n for n in api("GET", "/1/cbom/sources/nodes").json()["nodes"]}
    na, nb = nodes[data_a["node_id"]], nodes[data_b["node_id"]]
    assert (na["name"], nb["name"]) == ("k3s-worker-a", "k3s-worker-a-2")
    assert na["mode"] == nb["mode"] == "agent" and na["pool_id"] == pool["id"] and na["deployment"] == "helm"
    with Session(engine) as s:
        hosts = s.exec(select(CbomCollectionSource).where(CbomCollectionSource.kind == "host_agent")).all()
        assert sorted(h.node_id for h in hosts) == sorted([data_a["node_id"], data_b["node_id"]])
        assert all(not h.secret_encrypted or h.secret_fields == [] for h in hosts)
        assert s.get(CbomNodePool, pool["id"]).enrollments == 2
    _enroll_agent(api, token, "k3s-worker-c")
    with pytest.raises(node_api.Unauthorized):  # the cap is 3
        _enroll_agent(api, token, "k3s-worker-d")
    with Session(engine) as s:
        assert s.get(CbomNodePool, pool["id"]).enrollments == 3
        assert len(s.exec(select(CbomScanNode).where(CbomScanNode.pool_id == pool["id"])).all()) == 3


def test_expired_revoked_and_unknown_pool_tokens_enroll_nothing(api, world):
    engine, _ = world
    pool, token = _pool(api)
    with Session(engine) as s:
        row = s.get(CbomNodePool, pool["id"])
        row.expires_at = dt.datetime.utcnow() - dt.timedelta(seconds=1)
        s.add(row)
        s.commit()
    with pytest.raises(node_api.Unauthorized):
        _enroll_agent(api, token, "n1")
    pool2, token2 = _pool(api, name="second")
    api("POST", f"/1/cbom/sources/node-pools/{pool2['id']}/revoke")
    with pytest.raises(node_api.Unauthorized):
        _enroll_agent(api, token2, "n1")
    with pytest.raises(node_api.Unauthorized):
        _enroll_agent(api, "zsp_" + "x" * 43, "n1")
    with Session(engine) as s:
        assert not s.exec(select(CbomScanNode).where(CbomScanNode.mode == "agent")).all()


def test_a_bad_enrollment_signature_takes_no_pool_slot(api, world):
    engine, _ = world
    pool, token = _pool(api)
    key = ed25519.Ed25519PrivateKey.generate()
    other = ed25519.Ed25519PrivateKey.generate()
    client = _client(api, other)  # signs with a key other than the one it registers
    with pytest.raises(node_api.ApiError) as err:
        client.enroll({"registration_token": token, "mode": "agent", "node_name": "n1",
                       "signing_public_key": base64.b64encode(key.public_key().public_bytes_raw()).decode()})
    assert err.value.status == 403
    with Session(engine) as s:
        assert s.get(CbomNodePool, pool["id"]).enrollments == 0
        assert not s.exec(select(CbomScanNode).where(CbomScanNode.mode == "agent")).all()
        assert not s.exec(select(CbomCollectionSource).where(CbomCollectionSource.kind == "host_agent")).all()


# ----------------------------------------------------------------------------- agent nodes never get credentials
def test_sources_with_credentials_cannot_use_an_agent_node_and_host_sources_need_one(api, world):
    pool, token = _pool(api)
    _client_a, data = _enroll_agent(api, token, "k3s-a")
    r = api("POST", "/1/cbom/sources/items", json=linux_body(node_id=data["node_id"]))
    assert r.status_code == 400 and "agent mode" in r.text
    reg = api("POST", "/1/cbom/sources/nodes", json={"name": "dc-01"}).json()
    r = api("POST", "/1/cbom/sources/items", json={"kind": "host_agent", "name": "manual", "node_id": reg["node"]["id"],
                                                   "config": {}})
    assert r.status_code == 400 and "not in agent mode" in r.text
    linux = api("POST", "/1/cbom/sources/items", json=linux_body(node_id=reg["node"]["id"])).json()["source"]
    r = api("PATCH", f"/1/cbom/sources/items/{linux['id']}", json={"node_id": data["node_id"]})
    assert r.status_code == 400 and "agent mode" in r.text


def test_a_claim_never_gives_an_agent_node_another_job_or_a_secret(api, world, monkeypatch):
    engine, _ = world
    # an agentless node with a password source and a queued connection test ...
    reg = api("POST", "/1/cbom/sources/nodes", json={"name": "dc-01"}).json()
    body = linux_body(node_id=reg["node"]["id"], targets=["10.0.0.1"])
    body["test_after_save"] = True
    created = api("POST", "/1/cbom/sources/items", json=body)
    assert created.status_code == 201 and created.json()["test"], created.text
    linux = created.json()["source"]
    key = ed25519.Ed25519PrivateKey.generate()
    client = _client(api, key)
    data = client.enroll({"registration_token": reg["registration_token"], "mode": "agent", "node_name": "dc-01",
                          "signing_public_key": base64.b64encode(key.public_key().public_bytes_raw()).decode()})
    client.token = data["node_token"]
    # ... re-enrolls in agent mode: it gets its own host source, and the password job is cancelled, never decrypted
    assert data["mode"] == "agent"
    calls = []
    monkeypatch.setattr(SR, "decrypt_secrets", lambda blob: calls.append(blob) or {"password": PASSWORD})
    payload = client.claim()
    assert payload is None  # the only job was the password test: cancelled, nothing handed out
    with Session(engine) as s:
        job = s.exec(select(CbomCollectionJob).where(CbomCollectionJob.source_id == linux["id"])).first()
        assert job.status == "cancelled" and "own host" in job.error
    assert not calls
    host = api("GET", "/1/cbom/sources/items?kind=host_agent").json()["sources"][0]
    test = api("POST", f"/1/cbom/sources/items/{host['id']}/test")
    assert test.status_code == 200, test.text
    payload = client.claim()
    assert payload["source"]["kind"] == "host_agent" and payload["source"]["secrets"] == {}
    assert PASSWORD not in json.dumps(payload) and not calls
    plan = api("POST", "/1/cbom/sources/estimate", json={"include": {"servers": True}}).json()
    reasons = {i["name"]: i["reason"] for i in plan["items"]}
    assert "agent mode" in (reasons[linux["name"]] or "")


def test_agent_node_end_to_end_with_the_real_node_collector(api, world, tmp_path, monkeypatch):
    """Pool enrollment -> run -> claim -> the node's host_agent collector on a fake /host -> assets and result."""
    from zs_scan_node.collectors import run_job
    from zs_scan_node.jobctx import JobContext
    from zs_scan_node.netutil import NeverScan
    from zs_scan_node.scrub import Scrubber

    engine, _ = world
    root = tmp_path / "host"
    (root / "etc").mkdir(parents=True)
    (root / "var/lib/dpkg").mkdir(parents=True)
    (root / "etc/os-release").write_text('ID=debian\nVERSION_ID="11"\nPRETTY_NAME="Debian GNU/Linux 11"\n')
    (root / "var/lib/dpkg/status").write_text("Package: libssl1.1\nStatus: install ok installed\nArchitecture: amd64\n"
                                             "Version: 1.1.1n-0+deb11u5\n\n")
    monkeypatch.setenv("ZS_HOST_ROOT", str(root))
    monkeypatch.setenv("ZS_NODE_NAME", "k3s-worker-1")
    _pool_row, token = _pool(api)
    client, data = _enroll_agent(api, token, "k3s-worker-1")
    # host agents follow the team's scan window like servers do; open it for the test
    api("PATCH", "/1/cbom/sources/settings", json={"scan_window": [[True] * 24 for _ in range(7)]})
    run = api("POST", "/1/cbom/sources/runs", json={"include": {"servers": True}, "client_request_id": "agent-run-0001"})
    assert run.status_code == 201, run.text
    assert run.json()["run"]["credits"]["charged"] == pytest.approx(0.2)  # one host, the server rate
    payload = client.claim()
    job, source = payload["job"], payload["source"]
    assert source["kind"] == "host_agent" and source["secrets"] == {}
    posted = []
    ctx = JobContext(job_id=job["id"], attempt=job["attempt"], run_id=job.get("run_id"), kind=job["kind"],
                     source_kind="host_agent", scrubber=Scrubber(), never_scan=NeverScan(), agent_mode=True,
                     deadline=time.monotonic() + 600,
                     poster=lambda assets, batch: posted.append(len(assets)) or client.assets(
                         job["id"], job["attempt"], job["lease_id"], batch, assets))
    status, error, summary = run_job(ctx, job, payload["scope"], source)
    ctx.flush()
    assert status == "success", error
    done = client.result(job["id"], job["attempt"], {"lease_id": job["lease_id"], "status": status,
                                                     "result": ctx.result(summary)})
    assert done["status"] == "success"
    with Session(engine) as s:
        rows = s.exec(select(CbomCollectedAsset).where(CbomCollectedAsset.job_id == job["id"])).all()
        lib = next(r for r in rows if r.asset_type == "crypto_library")
        assert lib.target == "k3s-worker-1" and "LIB_EOL" in (lib.finding_codes or [])  # OpenSSL 1.1.1 is EOL
        assert lib.facts["purl"] == "pkg:deb/debian/libssl1.1@1.1.1n-0+deb11u5?arch=amd64&distro=debian-11"
    run_id = run.json()["run"]["id"]
    bom = api("GET", f"/1/cbom/sources/runs/{run_id}/cbom").json()
    purls = [c.get("purl") for c in bom["components"] if c.get("type") == "library"]
    assert "pkg:deb/debian/libssl1.1@1.1.1n-0+deb11u5?arch=amd64&distro=debian-11" in purls


def test_a_single_docker_host_agent_enrolls_with_a_node_token_too(api, world):
    reg = api("POST", "/1/cbom/sources/nodes", json={"name": "bastion-01"}).json()
    client = _client(api)
    data = client.enroll({"registration_token": reg["registration_token"], "mode": "agent"})
    assert data["mode"] == "agent"
    sources = api("GET", "/1/cbom/sources/items?kind=host_agent").json()["sources"]
    assert [s["node_id"] for s in sources] == [reg["node"]["id"]]


def test_deleting_an_agent_node_removes_its_host_source(api, world):
    engine, _ = world
    _pool_row, token = _pool(api)
    _c, data = _enroll_agent(api, token, "k3s-gone")
    r = api("DELETE", f"/1/cbom/sources/nodes/{data['node_id']}")
    assert r.status_code == 200, r.text
    with Session(engine) as s:
        assert not s.exec(select(CbomCollectionSource).where(CbomCollectionSource.kind == "host_agent")).all()


def test_agent_nodes_do_not_count_against_the_agentless_node_cap(api, world, monkeypatch):
    monkeypatch.setenv("CBOM_MAX_AGENTLESS_NODES", "1")
    _pool_row, token = _pool(api)
    _enroll_agent(api, token, "k3s-1")
    _enroll_agent(api, token, "k3s-2")
    assert api("POST", "/1/cbom/sources/nodes", json={"name": "dc-01"}).status_code == 201
    assert api("POST", "/1/cbom/sources/nodes", json={"name": "dc-02"}).status_code == 400


# ----------------------------------------------------------------------------- container images
def test_container_image_sources_validate_and_are_priced_per_image(api, world):
    reg = api("POST", "/1/cbom/sources/nodes", json={"name": "dc-01"}).json()
    node_id = reg["node"]["id"]
    _client(api).enroll({"registration_token": reg["registration_token"]})
    bad = api("POST", "/1/cbom/sources/items", json={"kind": "container_images", "name": "imgs", "node_id": node_id,
                                                     "config": {"images": ["UPPER/app"]}})
    assert bad.status_code == 400
    vault_by_member = api("POST", "/1/cbom/sources/items", "bob", json={
        "kind": "container_images", "name": "imgs", "node_id": node_id,
        "config": {"images": ["harbor.corp/app:1"], "credential_type": "vault",
                   "vault": {"provider": "hashicorp", "path": "secret/zs/harbor"}}})
    assert vault_by_member.status_code == 400 and "admin" in vault_by_member.text
    ok = api("POST", "/1/cbom/sources/items", json={
        "kind": "container_images", "name": "imgs", "node_id": node_id,
        "config": {"images": ["harbor.corp:8443/team/app:1.2", "alpine", "alpine",
                              "ghcr.io/org/svc@sha256:" + "a" * 64]}})
    assert ok.status_code == 201, ok.text
    assert ok.json()["source"]["config"]["images"][1:3] == ["alpine", "ghcr.io/org/svc@sha256:" + "a" * 64]
    plan = api("POST", "/1/cbom/sources/estimate", json={"include": {"kubernetes": True}}).json()
    item = next(i for i in plan["items"] if i["kind"] == "container_images")
    assert (item["units"], item["unit"], item["credits"]) == (3, "images", 3.0)


# ----------------------------------------------------------------------------- outputs
def test_coverage_report_turns_engine_counts_into_notes():
    bom = {"metadata": {"properties": [
        {"name": "crypto:coverage:image:layersNotRead", "value": "2"},
        {"name": "crypto:coverage:unpackRefused:pathTraversal", "value": "1"},
        {"name": "crypto:coverage:binariesRead", "value": "4"},
        {"name": "crypto:coverage:skippedSymlinks", "value": "0"},
        {"name": "crypto:coverage:somethingNew", "value": "7"},
        {"name": "regulatory:disclaimer", "value": "x"}]}}
    report = coverage_report(bom)
    texts = [n["text"] for n in report["notes"]]
    assert "2 image layer(s) were not read" in texts
    assert any("refused" in t and "'..'" in t for t in texts)
    assert "somethingNew: 7" in texts and not any("symbolic" in t for t in texts)
    assert report["notes"][-1]["kind"] == "info" and report["skipped"] == 3
    assert coverage_report({"metadata": {"properties": []}}) is None and coverage_report(None) is None


def test_the_scan_options_are_info_not_skipped_input():
    """rev6 #6: with "Scan binaries" (and "Scan vendored") on, the engine records crypto:coverage:binariesIncluded=true
    and vendoredIncluded=true (aibom/src/aibom/cbom/files.py coverage()); both fell through to the unknown-key branch
    as "skipped", so turning the option on showed the amber alert "2 kind(s) of input were skipped"."""
    bom = {"metadata": {"properties": [
        {"name": "crypto:coverage:binariesIncluded", "value": "true"},
        {"name": "crypto:coverage:vendoredIncluded", "value": "true"},
        {"name": "crypto:coverage:binariesRead", "value": "12"}]}}
    report = coverage_report(bom)
    assert report["skipped"] == 0 and {n["kind"] for n in report["notes"]} == {"info"}
    by_key = {n["key"]: n["text"] for n in report["notes"]}
    assert by_key["binariesIncluded"].startswith('"Scan binaries, container images and firmware" was on')
    assert by_key["vendoredIncluded"].startswith('"Scan vendored and build directories" was on')
    # with vendored code off, the walk counts the directories it left out: a labelled skipped note
    off = coverage_report({"metadata": {"properties": [{"name": "crypto:coverage:skippedVendoredDirs", "value": "3"}]}})
    assert off["skipped"] == 1 and off["notes"][0]["kind"] == "skipped"
    assert off["notes"][0]["text"].startswith("3 vendored or build director(ies) (vendor/, dist/, build/, node_modules/)")


def test_scan_metadata_carries_the_coverage_notes_of_a_code_scan_only():
    import types

    from backend.utilities.dashboard.scan_metadata import get_scan_metadata

    bom = {"metadata": {"properties": [{"name": "crypto:coverage:binariesTooLarge", "value": "3"}]}}
    code = get_scan_metadata("cbom", types.SimpleNamespace(scan_metadata={"scan_binaries": True},
                                                           scan_data={"cbom_json": bom, "results": []}))
    assert code["cbom_coverage"]["notes"][0]["text"] == "3 binary file(s) over the size cap were not read"
    upload = get_scan_metadata("cbom", types.SimpleNamespace(scan_metadata={"cbom_file_used": True},
                                                             scan_data={"cbom_json": bom, "results": []}))
    assert upload["cbom_coverage"] is None  # an uploaded CBOM file has its own import notes


def test_migration_matches_the_models():
    text = (ROOT / "prod_database_migrations/migrations/versions/wp8b0agent001_node_mode_agent_pools.py").read_text()
    assert "down_revision: Union[str, Sequence[str], None] = 'wp11a0integr001'" in text
    for column in CbomNodePool.model_fields:
        assert f"'{column}'" in text, column
    assert "'mode'" in text and "'pool_id'" in text and "server_default='agentless'" in text
    from backend.utilities.cbom_sources import limits

    assert "POOL_PREFIX" in AG.__dict__ and "CBOM_MAX_AGENT_NODES" in limits._SPEC  # caps moved to limits.py (F1.1)


def test_every_coverage_key_the_engine_writes_has_a_label():
    """Review fix E added gitHistoryObjectsUnreadable and archiveDirectoryTooLarge; a key without a label reaches the
    results page as raw "key: value" text."""
    import re
    from pathlib import Path

    from backend.utilities.dashboard import cbom_coverage

    src = Path(__file__).resolve().parents[2] / "aibom/src/aibom/cbom"
    keys = set()
    for path in src.glob("*.py"):
        keys |= set(re.findall(r"crypto:coverage:([A-Za-z]+)[\"']", path.read_text()))  # literal keys, not docs
    keys -= {"unpackRefused"}  # unpackRefused:<reason> is labelled by its prefix
    labels = set(re.findall(r'^\s+"([A-Za-z]+)": \(', Path(cbom_coverage.__file__).read_text(), re.M))
    assert keys and not sorted(keys - labels)
