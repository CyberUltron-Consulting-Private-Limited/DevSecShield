"""Lab UI r1 N1: Reset on an agent pool node opened "Register <node> again" with a standalone Helm command and a fresh
24-hour zsr_ registration token, although its pod enrolls again by itself with the pool token.  A pool node's reset
now revokes the credential and issues no registration token (nor can one be asked for); a standalone node is
unchanged, and a node whose pool was deleted is a standalone node again."""
from __future__ import annotations

from sqlmodel import Session

from test_cbom_sources_api import api, world  # noqa: F401  (fixtures)
from test_cbom_wp8b_agents import _enroll_agent, _pool
from backend.new_models import CbomScanNode
from backend.routers.cbom_sources import POOL_NODE_NO_TOKEN


def test_reset_of_a_pool_node_issues_no_registration_token(api, world):
    engine, _ = world
    _pool_row, token = _pool(api)
    _client, data = _enroll_agent(api, token, "k8s-worker-a")
    node_id = data["node_id"]
    reset = api("POST", f"/1/cbom/sources/nodes/{node_id}/reset")
    assert reset.status_code == 200, reset.text
    body = reset.json()
    assert body["registration_token"] is None  # before: a fresh zsr_ token the UI turned into a Helm command
    assert body["node"]["pool_id"] is not None and body["node"]["status"] == "pending_registration"
    assert body["node"]["registration_expires_at"] is None
    with Session(engine) as s:
        row = s.get(CbomScanNode, node_id)
        assert row.node_token_hash is None and row.registration_token_hash is None
    # "New registration token" is refused for it too, with the reason
    again = api("POST", f"/1/cbom/sources/nodes/{node_id}/registration-token")
    assert again.status_code == 409 and again.json()["detail"] == POOL_NODE_NO_TOKEN
    with Session(engine) as s:
        assert s.get(CbomScanNode, node_id).registration_token_hash is None


def test_reset_of_a_standalone_node_still_issues_a_token(api, world):
    created = api("POST", "/1/cbom/sources/nodes", json={"name": "dc-1", "segment": "DC", "deployment": "docker"})
    assert created.status_code == 201, created.text
    node_id = created.json()["node"]["id"]
    reset = api("POST", f"/1/cbom/sources/nodes/{node_id}/reset")
    assert reset.status_code == 200 and reset.json()["registration_token"].startswith("zsr_")
    assert reset.json()["node"]["registration_expires_at"]


def test_a_node_whose_pool_was_deleted_gets_a_token_again(api, world):
    engine, _ = world
    _pool_row, token = _pool(api)
    _client, data = _enroll_agent(api, token, "k8s-worker-b")
    with Session(engine) as s:  # the pool row deleted (FK ondelete SET NULL)
        row = s.get(CbomScanNode, data["node_id"])
        row.pool_id = None
        s.add(row)
        s.commit()
    reset = api("POST", f"/1/cbom/sources/nodes/{data['node_id']}/reset")
    assert reset.status_code == 200 and reset.json()["registration_token"].startswith("zsr_")
