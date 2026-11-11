"""Round-5 review (lens 6) of agent pools: a DaemonSet pod whose node was reset or deleted enrolls again with its pool
token (the real scan-node agent against the real routes), within the pool's expiry, revocation and cap; a node's mode
follows what it reports (a node restarted in agent mode is never handed a secret); and the per-team caps on agent
nodes and pool tokens hold when requests race."""
from __future__ import annotations

import base64
import datetime as dt
import hashlib
import sys
import threading
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519
from sqlmodel import Session, select

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scan_node"))

from test_cbom_sources_api import PASSWORD, api, linux_body, world  # noqa: E402,F401  (fixtures)
from test_cbom_wp8b_agents import _client, _enroll_agent, _pool  # noqa: E402
from backend.new_models import CbomCollectionJob, CbomCollectionSource, CbomNodePool, CbomScanNode  # noqa: E402
from backend.routers import cbom_node, cbom_node_pools  # noqa: E402
from backend.utilities.cbom_sources import agents as AG  # noqa: E402
from backend.utilities.cbom_sources import secret_refs as SR  # noqa: E402
from backend.utilities.cbom_sources import node_auth as NA  # noqa: E402
from backend.utilities.cbom_sources.schemas import EnrollBody, PoolCreate  # noqa: E402
from zs_scan_node import api as node_api  # noqa: E402


def _pod(api, tmp_path, monkeypatch, token: str, node_name: str = "k8s-worker-a"):
    """The real scan-node agent of one DaemonSet pod (state on its own host path), talking to the real routes."""
    from zs_scan_node import agent as A

    monkeypatch.setenv("ZS_API_URL", "http://testserver")
    monkeypatch.setenv("ZS_ALLOW_INSECURE_HTTP", "1")
    monkeypatch.setenv("ZS_STATE_DIR", str(tmp_path / f"state-{node_name}"))
    monkeypatch.setenv("ZS_MODE", "agent")
    monkeypatch.setenv("ZS_NODE_NAME", node_name)
    monkeypatch.setenv("ZS_REGISTRATION_TOKEN", token)
    pod = A.Agent()
    pod.api.client = api.client
    pod.api._wait = lambda seconds: None
    waits = []

    def wait(seconds):  # ensure_enrolled waits after a refusal: count, and end the loop
        waits.append(seconds)
        pod.shutdown.set()
        return True

    pod.shutdown.wait = wait
    pod.waits = waits
    return pod


def test_a_reset_pool_node_is_taken_back_by_its_pod_with_the_pool_token(api, world, tmp_path, monkeypatch):
    engine, _ = world
    pool, token = _pool(api, max_enrollments=1)
    pod = _pod(api, tmp_path, monkeypatch, token)
    pod.ensure_enrolled()
    node_id = pod.state.node_id
    pod.heartbeat_once()
    reset = api("POST", f"/1/cbom/sources/nodes/{node_id}/reset")
    assert reset.status_code == 200
    with pytest.raises(node_api.Unauthorized):  # the pod's next heartbeat
        pod.heartbeat_once()
    pod.on_unauthorized()
    assert pod.state.node_token is None
    pod.ensure_enrolled()  # before: "already used ... Scan nodes > Reset", waiting forever
    assert pod.state.node_token and pod.state.node_id == node_id and not pod.waits
    pod.heartbeat_once()  # the new credential and signing key work
    with Session(engine) as s:
        rows = s.exec(select(CbomScanNode).where(CbomScanNode.pool_id == pool["id"])).all()
        assert [(n.id, n.name, n.mode) for n in rows] == [(node_id, "k8s-worker-a", "agent")]  # no duplicate
        assert s.get(CbomNodePool, pool["id"]).enrollments == 1  # a full pool still takes its node back
        assert len(s.exec(select(CbomCollectionSource).where(CbomCollectionSource.node_id == node_id)).all()) == 1
    # a reset pool node gets no registration token at all (r1 N1): nothing a standalone install could take it with
    assert reset.json()["registration_token"] is None
    with Session(engine) as s:
        assert s.get(CbomScanNode, node_id).registration_token_hash is None


def test_a_deleted_pool_node_comes_back_as_a_new_node_within_the_cap(api, world, tmp_path, monkeypatch):
    engine, _ = world
    pool, token = _pool(api, max_enrollments=2)
    pod = _pod(api, tmp_path, monkeypatch, token)
    pod.ensure_enrolled()
    first = pod.state.node_id
    assert api("DELETE", f"/1/cbom/sources/nodes/{first}").status_code == 200
    with pytest.raises(node_api.Unauthorized):
        pod.heartbeat_once()
    pod.on_unauthorized()
    pod.ensure_enrolled()
    second = pod.state.node_id  # a new node (SQLite may hand out the deleted node's id again; PostgreSQL never does)
    assert second and pod.state.node_token and not pod.waits
    with Session(engine) as s:
        assert s.get(CbomNodePool, pool["id"]).enrollments == 2
        assert [n.name for n in s.exec(select(CbomScanNode).where(CbomScanNode.pool_id == pool["id"])).all()] == [
            "k8s-worker-a"]
    pod.heartbeat_once()
    assert api("DELETE", f"/1/cbom/sources/nodes/{second}").status_code == 200
    with pytest.raises(node_api.Unauthorized):
        pod.heartbeat_once()
    pod.on_unauthorized()
    pod.ensure_enrolled()  # both enrollments used: refused, and not tried again
    assert pod.state.node_token is None and pod.waits == [300]
    assert pod.state.refused_with == hashlib.sha256(token.encode()).hexdigest()
    with Session(engine) as s:
        assert s.get(CbomNodePool, pool["id"]).enrollments == 2


@pytest.mark.parametrize("how", ["revoke", "expire"])
def test_a_revoked_or_expired_pool_does_not_give_a_reset_node_back(api, world, how):
    engine, _ = world
    pool, token = _pool(api)
    _c, data = _enroll_agent(api, token, "k8s-worker-a")
    api("POST", f"/1/cbom/sources/nodes/{data['node_id']}/reset")
    if how == "revoke":
        api("POST", f"/1/cbom/sources/node-pools/{pool['id']}/revoke")
    else:
        with Session(engine) as s:
            row = s.get(CbomNodePool, pool["id"])
            row.expires_at = dt.datetime.utcnow() - dt.timedelta(seconds=1)
            s.add(row)
            s.commit()
    key = ed25519.Ed25519PrivateKey.generate()
    with pytest.raises(node_api.Unauthorized):
        _client(api, key).enroll({"registration_token": token, "mode": "agent", "node_name": "k8s-worker-a",
                                  "node_id": data["node_id"],
                                  "signing_public_key": base64.b64encode(key.public_key().public_bytes_raw()).decode()})
    with Session(engine) as s:
        assert s.get(CbomScanNode, data["node_id"]).node_token_hash is None


def test_a_node_that_holds_a_credential_is_never_taken_over(api, world):
    engine, _ = world
    pool, token = _pool(api)
    owner, data = _enroll_agent(api, token, "k8s-worker-a")
    key = ed25519.Ed25519PrivateKey.generate()
    other = _client(api, key).enroll({"registration_token": token, "mode": "agent", "node_name": "k8s-worker-a",
                                      "node_id": data["node_id"], "signing_public_key":
                                      base64.b64encode(key.public_key().public_bytes_raw()).decode()})
    assert other["node_id"] != data["node_id"]  # a new node, "k8s-worker-a-2"
    owner.heartbeat({"capabilities": {"mode": "agent"}})  # the first pod's credential still works
    with Session(engine) as s:
        assert s.get(CbomScanNode, other["node_id"]).name == "k8s-worker-a-2"
    # without a node id (state lost), the reset node is found by its Kubernetes node name, when only one matches
    api("POST", f"/1/cbom/sources/nodes/{data['node_id']}/reset")
    with Session(engine) as s:
        pool_row = s.get(CbomNodePool, pool["id"])
        assert AG.node_to_rebind(s, pool_row, None, "k8s-worker-a").id == data["node_id"]
        assert AG.node_to_rebind(s, pool_row, None, "k8s-worker-z") is None
        assert AG.node_to_rebind(s, pool_row, other["node_id"], None) is None  # holds a credential


def test_enroll_body_accepts_a_node_id():
    body = EnrollBody.model_validate({"registration_token": "zsp_" + "a" * 40, "node_id": 7})
    assert body.node_id == 7
    with pytest.raises(Exception):
        EnrollBody.model_validate({"registration_token": "zsp_" + "a" * 40, "node_id": 0})


# ----------------------------------------------------------------------------- finding 10: the mode follows the node
def _agentless_with_a_password_job(api):
    reg = api("POST", "/1/cbom/sources/nodes", json={"name": "dc-01"}).json()
    key = ed25519.Ed25519PrivateKey.generate()
    client = _client(api, key)
    data = client.enroll({"registration_token": reg["registration_token"], "signing_public_key":
                          base64.b64encode(key.public_key().public_bytes_raw()).decode()})
    client.token, client.deployment_id = data["node_token"], data["deployment_id"]
    body = linux_body(node_id=data["node_id"], targets=["10.0.0.1"])
    body["test_after_save"] = True
    created = api("POST", "/1/cbom/sources/items", json=body)
    assert created.status_code == 201 and created.json()["test"], created.text
    return client, data["node_id"], created.json()["source"]


def test_a_node_restarted_in_agent_mode_is_never_handed_a_secret(api, world, monkeypatch):
    engine, _ = world
    client, node_id, linux = _agentless_with_a_password_job(api)
    calls = []
    monkeypatch.setattr(SR, "decrypt_secrets", lambda blob: calls.append(blob) or {"password": PASSWORD})
    # restarted with ZS_MODE=agent, it claims before its first heartbeat: the claim says so
    assert client.claim({"mode": "agent"}) is None
    assert not calls  # before: the password was decrypted and sent (the node then refused it)
    with Session(engine) as s:
        node = s.get(CbomScanNode, node_id)
        assert node.mode == "agent"
        job = s.exec(select(CbomCollectionJob).where(CbomCollectionJob.source_id == linux["id"])).first()
        assert job.status == "cancelled" and "own host" in job.error
        hosts = s.exec(select(CbomCollectionSource).where(CbomCollectionSource.node_id == node_id,
                                                          CbomCollectionSource.kind == "host_agent")).all()
        assert len(hosts) == 1


def test_the_heartbeat_reconciles_the_mode_one_way_only(api, world):
    engine, _ = world
    client, node_id, _linux = _agentless_with_a_password_job(api)
    client.heartbeat({"capabilities": {"mode": "agentless"}})
    with Session(engine) as s:
        assert s.get(CbomScanNode, node_id).mode == "agentless"
    client.heartbeat({"capabilities": {"mode": "agent"}})  # before: the mode was set at enrollment only
    with Session(engine) as s:
        assert s.get(CbomScanNode, node_id).mode == "agent"
    client.heartbeat({"capabilities": {"mode": "agentless"}})  # back to agentless needs a new enrollment
    with Session(engine) as s:
        node = s.get(CbomScanNode, node_id)
        assert node.mode == "agent" and "Reset it and register it again" in (node.last_node_error or "")


def test_claim_bodies_of_older_and_newer_nodes(api, world):
    client, _node_id, _linux = _agentless_with_a_password_job(api)
    payload = client.claim()  # an older node sends no body: still accepted (and still agentless here)
    assert payload["source"]["kind"] == "linux_servers"
    with pytest.raises(node_api.ApiError) as err:
        client.claim({"mode": "root"})
    assert err.value.status == 400


# ----------------------------------------------------------------------------- finding 10: atomic team caps
def _race(n: int, target, *args):
    out: list = [None] * n

    def run(i):
        try:
            out[i] = target(*args[i])
        except Exception as exc:  # HTTPException 400 / 401 is the expected loser
            out[i] = exc

    threads = [threading.Thread(target=run, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(30)
    return out


def _hold(barrier):
    """Wait for the other request at the point between the cap's count and its insert (up to 2 s: with the team
    lock the other request cannot get there until this one commits)."""
    def wait(*args, **kwargs):
        try:
            barrier.wait(timeout=2)
        except threading.BrokenBarrierError:
            pass
    return wait


def test_two_pool_tokens_created_at_once_cannot_pass_the_cap(api, world, monkeypatch):
    engine, ids = world
    monkeypatch.setenv("CBOM_MAX_POOLS", "1")
    barrier = threading.Barrier(2)
    real = cbom_node_pools.sha256_hex
    hold = _hold(barrier)
    monkeypatch.setattr(cbom_node_pools, "sha256_hex", lambda v: hold() or real(v))
    body = PoolCreate(name="k8s", max_enrollments=5)
    out = _race(2, cbom_node_pools._create, (engine, 1, ids["alice"], body), (engine, 1, ids["alice"], body))
    with Session(engine) as s:
        assert len(s.exec(select(CbomNodePool).where(CbomNodePool.team_id == 1)).all()) == 1, out
    assert sum(isinstance(o, dict) for o in out) == 1


def test_two_pods_of_two_pools_cannot_pass_the_agent_node_cap(api, world, monkeypatch):
    engine, _ = world
    monkeypatch.setenv("CBOM_MAX_AGENT_NODES", "1")
    (_p1, t1), (_p2, t2) = _pool(api, name="one"), _pool(api, name="two")
    barrier = threading.Barrier(2)
    real = NA.check_mtls
    hold = _hold(barrier)
    monkeypatch.setattr(NA, "check_mtls", lambda node, req: hold() or real(node, req))
    req = NA.NodeRequest(method="POST", path="/cbom/node/enroll", timestamp=None, nonce=None, signature=None,
                         client_cert=None, client_verify=None)
    bodies = [EnrollBody.model_validate({"registration_token": t, "mode": "agent", "node_name": f"n{i}"})
              for i, t in enumerate((t1, t2))]
    out = _race(2, cbom_node._enroll_pool, (bodies[0], req, b"{}", "10.0.0.1"), (bodies[1], req, b"{}", "10.0.0.2"))
    with Session(engine) as s:
        assert len(s.exec(select(CbomScanNode).where(CbomScanNode.mode == "agent")).all()) == 1, out
    assert sum(isinstance(o, dict) for o in out) == 1
