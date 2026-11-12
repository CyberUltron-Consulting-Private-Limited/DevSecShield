"""CBOM Sources API end to end on SQLite (real JWTs, real routers, foreign keys enforced).

Covers tenancy, write-only secrets, node enrollment and job leasing, credits and refunds, settings
permissions, evidence and single-use vendor links.  Run:

    cd backend && PYTHONPATH=.. JWT_SECRET_KEY=t JWT_REFRESH_SECRET_KEY=r AWS_ACCESS_KEY_ID=x \
      AWS_SECRET_ACCESS_KEY=y AWS_DEFAULT_REGION=us-east-1 uv run --with pytest python -m pytest \
      tests/test_cbom_sources_api.py -q -p no:cacheprovider
"""
from __future__ import annotations

import datetime as dt
import json
import os
import sys
from pathlib import Path

import pytest
from cryptography.fernet import Fernet

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))
os.environ.setdefault("JWT_SECRET_KEY", "cbom-sources-test-secret")
os.environ.setdefault("JWT_REFRESH_SECRET_KEY", "cbom-sources-test-refresh")
os.environ["ENCRYPTION_KEY"] = Fernet.generate_key().decode()

from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import event  # noqa: E402
from sqlmodel import Session, SQLModel, create_engine, select  # noqa: E402

from backend.main import app  # noqa: E402
from backend.new_models import (  # noqa: E402
    CbomCollectionJob,
    CbomCollectionRun,
    CbomCollectionSource,
    CbomScanNode,
    Scan,
    Team,
    TeamMembership,
    User,
)
from backend.routers import cbom_node, cbom_sources, cbom_vendor_public  # noqa: E402
from backend.utilities.auth import auth_utils  # noqa: E402
from backend.utilities.cbom_sources import http as cbom_http  # noqa: E402
from backend.utilities.cbom_sources import jobs as J  # noqa: E402
from backend.utilities.cbom_sources import node_auth  # noqa: E402
from backend.utilities.cbom_sources import targets as T  # noqa: E402
from backend.utilities.cbom_sources.cleanup import delete_cbom_sources_for_team  # noqa: E402
from backend.utilities.cbom_sources.settings import default_window, next_window_start  # noqa: E402
from backend.utilities.db.encryption import _get_fernet  # noqa: E402

PASSWORD = "Canary-Pa55word-7f3a91"
PEM_KEY = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQ\n-----END PRIVATE KEY-----"
USERS = {"alice": ("alice@t1.test", 1, "admin"), "bob": ("bob@t1.test", 1, "member"), "carol": ("carol@t2.test", 2, "admin")}


@pytest.fixture()
def world(tmp_path, monkeypatch):
    _get_fernet.cache_clear()
    engine = create_engine(f"sqlite:///{tmp_path / 'w.db'}", connect_args={"check_same_thread": False})

    @event.listens_for(engine, "connect")
    def _fk(dbapi_conn, _record):  # enforce foreign keys like Postgres does
        dbapi_conn.execute("PRAGMA foreign_keys=ON")

    SQLModel.metadata.create_all(engine)
    ids = {}
    with Session(engine) as s:
        s.add(Team(id=1, name="Bank One", credit_balance=100.0))
        s.add(Team(id=2, name="Bank Two", credit_balance=0.5))
        s.commit()
        for who, (email, team, role) in USERS.items():
            user = User(email=email, password="x", first_name=who, last_name="t", profile_photo=None,
                        session_active=True, default_team_id=team)
            s.add(user)
            s.commit()
            s.refresh(user)
            ids[who] = user.id
            s.add(TeamMembership(team_id=team, user_id=user.id, role=role))
        s.add(Scan(id=77, team_id=1, owner_user_id=ids["alice"], scan_type="cbom", title="code", scan_status="NOT_STARTED"))
        s.add(Scan(id=78, team_id=1, owner_user_id=ids["alice"], scan_type="sast", title="sast", scan_status="NOT_STARTED"))
        s.commit()
    for module in (cbom_http, cbom_node, cbom_vendor_public, node_auth):
        monkeypatch.setattr(module, "get_db", lambda: engine)
    for limiter in (cbom_http.read_limiter, cbom_http.write_limiter, cbom_http.node_limiter,
                    cbom_http.enroll_limiter, cbom_http.vendor_limiter):
        limiter.requests.clear()
    return engine, ids


@pytest.fixture()
def api(world):
    client = TestClient(app)
    tokens = {who: auth_utils.create_access_token(email) for who, (email, _t, _r) in USERS.items()}
    seen: list[str] = []

    def call(method: str, url: str, who: str | None = "alice", **kwargs):
        headers = dict(kwargs.pop("headers", {}) or {})
        if who:
            headers["Authorization"] = f"Bearer {tokens[who]}"
        response = client.request(method, url, headers=headers, **kwargs)
        seen.append(response.text)
        return response

    call.seen = seen  # type: ignore[attr-defined]
    call.client = client  # type: ignore[attr-defined]
    return call


KNOWN_HOSTS = "10.20.0.1 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIE0Bq1hQ0j7lC1n6x3o0b9Z7w2YtqXxw9i6ZQ5mM2kHq"


def linux_body(name="linux-dc", node_id=None, targets=None, **cfg):
    # password logins need pinned host keys (verified identity only, 2026-10-31)
    return {"kind": "linux_servers", "name": name, "node_id": node_id,
            "config": {"targets": targets or ["10.20.0.0/29", "app-01.bank.local"], "credential_type": "password",
                       "login_user": "zs-cbom", "host_key_policy": "pinned", "known_hosts": KNOWN_HOSTS, **cfg},
            "secrets": {"password": PASSWORD}}


def enroll_node(api, team=1, who="alice", name="dc-mumbai-01"):
    r = api("POST", f"/{team}/cbom/sources/nodes", who, json={"name": name, "segment": "Data centre"})
    assert r.status_code == 201, r.text
    node, reg = r.json()["node"], r.json()["registration_token"]
    e = api("POST", "/cbom/node/enroll", None, json={"registration_token": reg, "hostname": "n1", "version": "1.0",
                                                     "source_ips": ["10.20.1.15"], "clock": dt.datetime.utcnow().isoformat() + "Z"})
    assert e.status_code == 200, e.text
    return node["id"], e.json()["node_token"], reg


# ----------------------------------------------------------------------------- targets (pure)
def test_target_counting_rules():
    p = T.parse_targets(["ip", "10.0.0.0/24", "10.0.0.128/25", "10.0.1.1-10.0.1.10", "Host.Example.COM.", "host.example.com",
                         "::ffff:10.0.2.1", "# comment", ""])
    # what the scan node scans: the /24's 254 host addresses (not its network and broadcast addresses; the /25 is
    # inside it), the 10 of the range, and the mapped address as its IPv4 address
    assert T.size(p.intervals) == 254 + 10 + 1
    assert p.hostnames == ["host.example.com"]
    excl = T.parse_exclusions(["10.0.0.0/26", "host.example.com"])
    assert T.count_in_scope(p, excl) == 254 + 10 + 1 - 63
    assert T.count_blocks([(4, 0x0A000080, 0x0A0000FF), (4, 0x0A000100, 0x0A00017F)]) == 2
    assert T.parse_targets(["10.0.0.0/31"]).intervals[0][2] - T.parse_targets(["10.0.0.0/31"]).intervals[0][1] == 1
    with pytest.raises(T.TargetError, match="did you mean 10.0.0.0/24"):
        T.parse_targets(["10.0.0.5/24"])
    with pytest.raises(T.TargetError, match="larger than /16"):
        T.parse_targets(["10.0.0.0/12"])
    with pytest.raises(T.TargetError, match="limit is 1,000"):
        T.parse_targets([f"10.1.{i // 250}.{i % 250}" for i in range(1001)])
    with pytest.raises(T.TargetError, match="at least one"):
        T.parse_targets(["", "# nothing"])


def test_window_and_next_start():
    grid = default_window()
    assert sum(sum(r) for r in grid) == 35  # 5 evenings x 2 h + 5 early mornings x 5 h
    monday_noon_ist = dt.datetime(2026, 11, 2, 6, 30)  # 12:00 IST
    nxt = next_window_start(grid, "Asia/Kolkata", monday_noon_ist)
    assert nxt == dt.datetime(2026, 11, 2, 16, 30)  # 22:00 IST


# ----------------------------------------------------------------------------- nodes
def test_node_enrollment_is_single_use_and_tokens_never_come_back(api, world):
    node_id, node_token, reg = enroll_node(api)
    again = api("POST", "/cbom/node/enroll", None, json={"registration_token": reg})
    assert again.status_code == 401
    got = api("GET", f"/1/cbom/sources/nodes/{node_id}").json()["node"]
    assert got["status"] == "online" and got["source_ips"] == ["10.20.1.15"]
    blob = json.dumps(got)
    assert reg not in blob and node_token not in blob and "hash" not in blob
    hb = api("POST", "/cbom/node/heartbeat", None, headers={"X-ZS-Node-Token": node_token}, json={"version": "1.1"})
    assert hb.status_code == 200 and hb.json()["stop_all_network"] is False
    assert api("POST", "/cbom/node/heartbeat", None, json={}).status_code == 401
    assert api("POST", "/cbom/node/heartbeat", None, headers={"X-ZS-Node-Token": "zsn_wrong"}, json={}).status_code == 401
    assert api("POST", f"/1/cbom/sources/nodes/{node_id}/registration-token").status_code == 409
    reset = api("POST", f"/1/cbom/sources/nodes/{node_id}/reset")
    assert reset.status_code == 200 and reset.json()["node"]["status"] == "pending_registration"
    assert api("POST", "/cbom/node/heartbeat", None, headers={"X-ZS-Node-Token": node_token}, json={}).status_code == 401


def test_expired_registration_token(api, world):
    engine, _ = world
    r = api("POST", "/1/cbom/sources/nodes", json={"name": "late-node"})
    node_id, reg = r.json()["node"]["id"], r.json()["registration_token"]
    with Session(engine) as s:
        node = s.get(CbomScanNode, node_id)
        node.registration_expires_at = dt.datetime.utcnow() - dt.timedelta(minutes=1)
        s.add(node)
        s.commit()
    assert api("POST", "/cbom/node/enroll", None, json={"registration_token": reg}).status_code == 401
    assert api("GET", f"/1/cbom/sources/nodes/{node_id}").json()["node"]["status"] == "registration_expired"
    fresh = api("POST", f"/1/cbom/sources/nodes/{node_id}/registration-token")
    assert fresh.status_code == 200 and fresh.json()["registration_token"] != reg


def test_install_command_inputs_are_validated(api):
    assert api("POST", "/1/cbom/sources/nodes", json={"name": "x';curl evil|sh;'"}).status_code == 400
    assert api("POST", "/1/cbom/sources/nodes", json={"name": "ok", "proxy_url": "http://u:p@proxy:8080"}).status_code == 400
    assert api("POST", "/1/cbom/sources/nodes", json={"name": "ok", "proxy_url": "http://proxy.bank.local:8080"}).status_code == 201


# ----------------------------------------------------------------------------- sources and secrets
def test_secrets_are_write_only_and_encrypted(api, world):
    engine, _ = world
    node_id, _tok, _ = enroll_node(api)
    r = api("POST", "/1/cbom/sources/items", json=linux_body(node_id=node_id))
    assert r.status_code == 201, r.text
    src = r.json()["source"]
    assert src["secrets_set"] == ["password"] and src["target_count"] == 7  # the /29's 6 hosts + 1 name
    api("GET", "/1/cbom/sources/items")
    api("GET", f"/1/cbom/sources/items/{src['id']}")
    api("GET", "/1/cbom/sources/overview")
    assert not any(PASSWORD in body for body in api.seen)
    with Session(engine) as s:
        row = s.get(CbomCollectionSource, src["id"])
        assert PASSWORD not in (row.secret_encrypted or "") and PASSWORD not in json.dumps(row.config)


def test_validation_errors_are_400_and_never_echo_input(api, world):
    node_id, _t, _ = enroll_node(api)
    body = linux_body(node_id=node_id, port=70000)
    r = api("POST", "/1/cbom/sources/items", json=body)
    assert r.status_code == 400 and r.json()["detail"].startswith("Port: ") and PASSWORD not in r.text
    bad = linux_body(node_id=node_id, targets=["10.0.0.5/24"])
    r = api("POST", "/1/cbom/sources/items", json=bad)
    assert r.status_code == 400 and "did you mean 10.0.0.0/24" in r.json()["detail"]


def test_tenancy(api, world):
    node_id, _t, _ = enroll_node(api)
    src = api("POST", "/1/cbom/sources/items", json=linux_body(node_id=node_id)).json()["source"]
    assert api("GET", f"/1/cbom/sources/items/{src['id']}", "carol").status_code == 403  # not a member (existing rule)
    assert api("GET", f"/2/cbom/sources/items/{src['id']}", "carol").status_code == 404
    assert api("POST", "/2/cbom/sources/items", "carol", json=linux_body(node_id=node_id)).status_code == 400
    assert api("POST", "/2/cbom/sources/runs", "carol", json={"include": {"servers": True}, "scan_id": 77,
                                                              "client_request_id": "carol-run-0001"}).status_code == 404


def test_owner_or_admin_rule_returns_400_not_403(api, world):
    node_id, _t, _ = enroll_node(api)
    src = api("POST", "/1/cbom/sources/items", json=linux_body(node_id=node_id)).json()["source"]
    r = api("PATCH", f"/1/cbom/sources/items/{src['id']}", "bob", json={"name": "renamed"})
    assert r.status_code == 400 and "team admin" in r.json()["detail"]
    mine = api("POST", "/1/cbom/sources/items", "bob", json=linux_body(name="bob-src", node_id=node_id)).json()["source"]
    assert api("PATCH", f"/1/cbom/sources/items/{mine['id']}", "bob", json={"name": "bob-renamed"}).status_code == 200
    assert api("PATCH", f"/1/cbom/sources/items/{mine['id']}", "alice", json={"enabled": False}).status_code == 200


def test_secret_is_cleared_when_where_it_is_used_changes(api, world):
    node_id, _t, _ = enroll_node(api)
    src = api("POST", "/1/cbom/sources/items", json=linux_body(node_id=node_id)).json()["source"]
    cfg = {**src["config"], "targets": ["10.99.0.1"]}
    r = api("PATCH", f"/1/cbom/sources/items/{src['id']}", json={"config": cfg, "expected_version": src["row_version"]})
    assert r.status_code == 400 and "re-enter" in r.json()["detail"]
    r = api("PATCH", f"/1/cbom/sources/items/{src['id']}",
            json={"config": cfg, "secrets": {"password": "NewPass-123"}, "expected_version": src["row_version"]})
    assert r.status_code == 200 and r.json()["source"]["target_count"] == 1
    stale = api("PATCH", f"/1/cbom/sources/items/{src['id']}", json={"name": "x2", "expected_version": src["row_version"]})
    assert stale.status_code == 409
    node_key = {**r.json()["source"]["config"], "credential_type": "node_key"}
    r2 = api("PATCH", f"/1/cbom/sources/items/{src['id']}", json={"config": node_key})
    assert r2.status_code == 200 and r2.json()["source"]["secrets_set"] == []
    assert api("PATCH", f"/1/cbom/sources/items/{src['id']}", json={"kind": "database"}).status_code == 400


def test_duplicate_names_and_node_delete_guard(api, world):
    node_id, _t, _ = enroll_node(api)
    assert api("POST", "/1/cbom/sources/items", json=linux_body(node_id=node_id)).status_code == 201
    dup = api("POST", "/1/cbom/sources/items", json=linux_body(name="LINUX-DC", node_id=node_id))
    assert dup.status_code == 409
    blocked = api("DELETE", f"/1/cbom/sources/nodes/{node_id}")
    assert blocked.status_code == 400 and "linux-dc" in blocked.json()["detail"]


# ----------------------------------------------------------------------------- jobs
def test_connection_test_round_trip_with_lease_and_scrub(api, world):
    node_id, token, _ = enroll_node(api)
    src = api("POST", "/1/cbom/sources/items", json=linux_body(node_id=node_id)).json()["source"]
    t = api("POST", f"/1/cbom/sources/items/{src['id']}/test").json()
    assert t["status"] == "queued"
    job_id = t["job"]["id"]
    hdr = {"X-ZS-Node-Token": token}
    claim = api("POST", "/cbom/node/jobs/claim", None, headers=hdr)
    assert claim.status_code == 200
    payload = claim.json()
    assert payload["source"]["secrets"]["password"] == PASSWORD  # only the owning node ever sees it
    assert payload["scope"]["targets"] == ["10.20.0.1", "10.20.0.2", "10.20.0.3", "10.20.0.4", "10.20.0.5"]
    assert api("POST", "/cbom/node/jobs/claim", None, headers=hdr).status_code == 204
    wrong = api("POST", f"/cbom/node/jobs/{job_id}/result", None, headers=hdr,
                json={"lease_id": "x" * 24, "status": "success", "result": {}})
    assert wrong.status_code == 409
    samples = [{"target": f"10.20.0.{i}", "status": "ready"} for i in range(1, 4)] + \
              [{"target": "10.20.0.4", "status": "sudoers_missing", "note": f"leak {PASSWORD} {PEM_KEY}"}]
    done = api("POST", f"/cbom/node/jobs/{job_id}/result", None, headers=hdr,
               json={"lease_id": payload["job"]["lease_id"], "status": "success", "result": {"samples": samples}})
    assert done.status_code == 200, done.text
    got = api("GET", f"/1/cbom/sources/items/{src['id']}").json()["source"]
    assert got["last_test_status"] == "partial" and got["last_test_summary"].startswith("3 of 4 samples ready: leak")
    assert PASSWORD not in got["last_test_summary"]
    job = api("GET", f"/1/cbom/sources/jobs/{job_id}").json()["job"]
    assert PASSWORD not in json.dumps(job) and "PRIVATE KEY" not in json.dumps(job)


def _finish_test(api, token, src_id, samples):
    job_id = api("POST", f"/1/cbom/sources/items/{src_id}/test").json()["job"]["id"]
    hdr = {"X-ZS-Node-Token": token}
    payload = api("POST", "/cbom/node/jobs/claim", None, headers=hdr).json()
    assert payload["job"]["id"] == job_id
    r = api("POST", f"/cbom/node/jobs/{job_id}/result", None, headers=hdr,
            json={"lease_id": payload["job"]["lease_id"], "status": "success", "result": {"samples": samples}})
    assert r.status_code == 200, r.text
    return api("GET", f"/1/cbom/sources/items/{src_id}").json()["source"]


def test_silent_range_samples_do_not_block_the_sweep(api, world):
    """AWS lab: a /24 whose first addresses are cloud-reserved answered nothing and was skipped from every run."""
    node_id, token, _ = enroll_node(api)
    rng = api("POST", "/1/cbom/sources/items", json={"kind": "network_range", "name": "sparse", "node_id": node_id,
                                                     "config": {"cidr": "10.60.20.0/24"}}).json()["source"]
    silent = [{"target": f"10.60.20.{i}", "status": "unreachable", "note": "no answer on the listed ports"}
              for i in range(1, 6)]
    got = _finish_test(api, token, rng["id"], silent)
    assert got["last_test_status"] == "partial" and "will be swept" in got["last_test_summary"]
    est = api("POST", "/1/cbom/sources/estimate", json={"include": {"network": True}, "source_ids": [rng["id"]]}).json()
    assert not [s for s in est.get("skipped") or [] if s["source_id"] == rng["id"]], est
    # a range the node cannot route to at all is still a failure
    no_route = [{"target": f"10.60.20.{i}", "status": "no_route"} for i in range(1, 6)]
    assert _finish_test(api, token, rng["id"], no_route)["last_test_status"] == "failed"
    # silence from a server list is not excused: the listed servers should answer
    srv = api("POST", "/1/cbom/sources/items", json=linux_body(node_id=node_id, name="silent-servers")).json()["source"]
    assert _finish_test(api, token, srv["id"], silent)["last_test_status"] == "failed"


def test_expired_lease_requeues_then_fails(api, world):
    engine, _ = world
    node_id, token, _ = enroll_node(api)
    src = api("POST", "/1/cbom/sources/items", json=linux_body(node_id=node_id)).json()["source"]
    job_id = api("POST", f"/1/cbom/sources/items/{src['id']}/test").json()["job"]["id"]
    hdr = {"X-ZS-Node-Token": token}
    for attempt in range(1, 4):
        assert api("POST", "/cbom/node/jobs/claim", None, headers=hdr).status_code == 200
        with Session(engine) as s:
            job = s.get(CbomCollectionJob, job_id)
            job.lease_expires_at = dt.datetime.utcnow() - dt.timedelta(seconds=1)
            s.add(job)
            s.commit()
        status = api("GET", f"/1/cbom/sources/jobs/{job_id}").json()["job"]["status"]
        assert status == ("pending" if attempt < 3 else "failure")
    assert api("GET", f"/1/cbom/sources/items/{src['id']}").json()["source"]["last_test_status"] == "failed"


def test_edit_cancels_pending_jobs_and_node_cannot_claim_stale_work(api, world):
    node_id, token, _ = enroll_node(api)
    src = api("POST", "/1/cbom/sources/items", json=linux_body(node_id=node_id)).json()["source"]
    job_id = api("POST", f"/1/cbom/sources/items/{src['id']}/test").json()["job"]["id"]
    api("PATCH", f"/1/cbom/sources/items/{src['id']}", json={"config": {**src["config"], "port": 2222},
                                                             "secrets": {"password": "x-new-1"}})
    assert api("GET", f"/1/cbom/sources/jobs/{job_id}").json()["job"]["status"] == "cancelled"
    assert api("POST", "/cbom/node/jobs/claim", None, headers={"X-ZS-Node-Token": token}).status_code == 204


# ----------------------------------------------------------------------------- credits and runs
def test_run_charges_once_refunds_on_cancel(api, world):
    engine, _ = world
    node_id, _t, _ = enroll_node(api)
    src = api("POST", "/1/cbom/sources/items", json=linux_body(node_id=node_id)).json()["source"]
    est = api("POST", "/1/cbom/sources/estimate", json={"include": {"servers": True}}).json()
    assert est["total_credits"] == 1.4  # 7 targets x 0.2 (the /29's 6 host addresses + 1 name: what the node scans)
    body = {"include": {"servers": True}, "client_request_id": "run-req-000001", "expected_credits": 1.0, "scan_id": 77}
    assert api("POST", "/1/cbom/sources/runs", json=body).status_code == 409
    body["expected_credits"] = 1.4
    first = api("POST", "/1/cbom/sources/runs", json=body)
    assert first.status_code == 201, first.text
    replay = api("POST", "/1/cbom/sources/runs", json=body)
    assert replay.status_code == 200 and replay.json()["replayed"] is True
    with Session(engine) as s:
        assert round(s.get(Team, 1).credit_balance, 2) == 98.6
    again = api("POST", "/1/cbom/sources/runs", json={**body, "client_request_id": "run-req-000002"})
    assert again.status_code == 409
    run_id = first.json()["run"]["id"]
    assert api("POST", f"/1/cbom/sources/runs/{run_id}/cancel", "bob").status_code == 400
    c1 = api("POST", f"/1/cbom/sources/runs/{run_id}/cancel").json()
    c2 = api("POST", f"/1/cbom/sources/runs/{run_id}/cancel").json()
    assert c1["refunded"] == 1.4 and c2["refunded"] == 0 and c1["run"]["status"] == "cancelled"
    with Session(engine) as s:
        assert round(s.get(Team, 1).credit_balance, 2) == 100.0
    assert src["id"]
    assert api("POST", "/1/cbom/sources/runs", json={**body, "client_request_id": "run-req-000003", "scan_id": 78}).status_code == 400


def test_insufficient_credits_creates_nothing(api, world):
    engine, _ = world
    node_id, _t, _ = enroll_node(api, team=2, who="carol")
    api("POST", "/2/cbom/sources/items", "carol", json=linux_body(node_id=node_id))
    r = api("POST", "/2/cbom/sources/runs", "carol", json={"include": {"servers": True}, "client_request_id": "poor-team-001"})
    assert r.status_code == 400 and "needs 1.4" in r.json()["detail"]
    with Session(engine) as s:
        assert s.exec(select(CbomCollectionRun)).all() == []
        assert s.get(Team, 2).credit_balance == 0.5


def test_aws_needs_a_passed_validation_then_charges_and_runs_in_the_cloud(api, world, monkeypatch):
    engine, _ = world
    r = api("POST", "/1/cbom/sources/items", json={"kind": "aws_account", "name": "payments-prod", "config": {
        "role_arn": "arn:aws:iam::111122223333:role/ZeroShieldCBOMReader", "regions": ["ap-south-1", "us-east-1"]}})
    assert r.status_code == 201, r.text
    src = r.json()["source"]
    est = api("POST", "/1/cbom/sources/estimate", json={"include": {"cloud": True}}).json()
    assert est["total_credits"] == 0 and est["skipped"][0]["reason"].startswith("Validate the AWS role first")
    run = api("POST", "/1/cbom/sources/runs", json={"include": {"cloud": True}, "client_request_id": "cloud-only-01"})
    assert run.status_code == 400
    monkeypatch.setattr(cbom_sources, "validate_aws_role", lambda *a, **_opts: {"status": "passed", "checks": [
        {"check": "Role assumed with external ID", "status": "pass", "detail": "ok"}]})
    assert api("POST", f"/1/cbom/sources/items/{src['id']}/test").json()["status"] == "passed"
    est = api("POST", "/1/cbom/sources/estimate", json={"include": {"cloud": True}}).json()
    assert est["total_credits"] == 4.0
    run = api("POST", "/1/cbom/sources/runs", json={"include": {"cloud": True}, "client_request_id": "cloud-only-02"})
    assert run.status_code == 201, run.text
    job = run.json()["run"]["jobs"][0]
    assert job["node_id"] is None and job["waiting_reason"] == "Queued for the ZeroShield cloud worker"
    node_id, token, _ = enroll_node(api)  # a scan node can never claim a cloud job
    assert api("POST", "/cbom/node/jobs/claim", None, headers={"X-ZS-Node-Token": token}).status_code == 204


def test_aws_validation_uses_external_id_and_stores_checks(api, world, monkeypatch):
    calls = {}

    def fake(team_id, role_arn, external_id, regions, scope, **_opts):
        calls.update(team_id=team_id, external_id=external_id)
        return {"status": "passed", "checks": [{"check": "Role assumed with external ID", "status": "pass", "detail": "ok"}]}

    monkeypatch.setattr(cbom_sources, "validate_aws_role", fake)
    src = api("POST", "/1/cbom/sources/items", json={"kind": "aws_account", "name": "core", "config": {
        "role_arn": "arn:aws:iam::111122223333:role/ZeroShieldCBOMReader"}}).json()["source"]
    r = api("POST", f"/1/cbom/sources/items/{src['id']}/test").json()
    settings = api("GET", "/1/cbom/sources/settings").json()["settings"]
    assert r["status"] == "passed" and calls["external_id"] == settings["aws_external_id"]
    assert api("GET", f"/1/cbom/sources/items/{src['id']}").json()["source"]["last_test_status"] == "passed"
    monkeypatch.setenv("CBOM_AWS_PRINCIPAL_ARN", "arn:aws:iam::123456789012:role/zeroshield-cbom")
    tpl = api("GET", "/1/cbom/sources/aws/template?scope=organization")
    assert tpl.status_code == 200 and settings["aws_external_id"] in tpl.text and "secretsmanager:GetSecretValue" in tpl.text


def test_aws_validation_reports_platform_errors_without_crashing(monkeypatch):
    from backend.utilities.cbom_sources import aws_validate

    def boom():
        raise RuntimeError("no boto")

    monkeypatch.setattr(aws_validate, "_boto", boom)
    monkeypatch.setenv("CBOM_AWS_PRINCIPAL_ARN", "arn:aws:iam::123456789012:role/zeroshield-cbom")
    out = aws_validate.validate_aws_role(1, "arn:aws:iam::111122223333:role/R", "zs-ext-AAAA-BBBB-CCCC-DDDD", ["us-east-1"], "account")
    assert out["status"] == "error" and all(c["status"] == "error" for c in out["checks"])


# ----------------------------------------------------------------------------- settings and network
def test_settings_permissions_and_stop_all(api, world):
    assert api("PATCH", "/1/cbom/sources/settings", "bob", json={"soc_email": "soc@bank.test"}).status_code == 400
    ok = api("PATCH", "/1/cbom/sources/settings", json={"soc_email": "soc@bank.test", "network_exclusions": [
        {"cidr": "10.20.99.0/24", "reason": "OT plant"}, {"cidr": "10.20.99.0/24", "reason": "dup"}]})
    assert ok.status_code == 200 and len(ok.json()["settings"]["network_exclusions"]) == 1
    bad = api("PATCH", "/1/cbom/sources/settings", json={"scan_window": [[False] * 24 for _ in range(7)]})
    assert bad.status_code == 400 and "no allowed hours" in bad.json()["detail"]
    assert api("POST", "/1/cbom/sources/settings/stop-all", "bob", json={"on": True}).status_code == 200
    assert api("POST", "/1/cbom/sources/settings/stop-all", "bob", json={"on": False}).status_code == 400
    assert api("POST", "/1/cbom/sources/settings/stop-all", json={"on": False}).json()["settings"]["stop_all_network"] is False


def test_the_team_never_scan_list_takes_addresses_and_ranges_only(api, world):
    """The UI's team list refuses host names (NetworkTab rangeError); the API must too. On the node a listed name that
    does not resolve holds every target of every job of the team, so names belong in a server source's own list."""
    for name in ("printer.corp.invalid", "Web-01.Corp.", "printer", "localhost", "bücher.corp", "10.0.0.0-24"):
        r = api("PATCH", "/1/cbom/sources/settings", json={"network_exclusions": [
            {"cidr": "10.20.99.0/24", "reason": "OT plant"}, {"cidr": f" {name} ", "reason": "printer"}]})
        assert r.status_code == 422, (name, r.text)
        # the whole detail, word for word, with the entry as typed (trimmed, not normalized, not quoted): the UI shows
        # the same words for a typed entry (teamNeverScan.ts; test_never_scan_node_agreement compares the templates)
        assert r.json()["detail"] == (
            f"network_exclusions: {name} is not an address or range (it reads as a host name); the team never-scan "
            "list takes addresses and ranges only. List host names in a server source's own Never scan field")
        assert r.json()["detail"] == "network_exclusions: " + T.HOST_NAME_NOT_ALLOWED.format(entry=name)
    got = api("GET", "/1/cbom/sources/settings").json()["settings"]
    assert got["network_exclusions"] == []  # nothing of the refused request was stored
    ok = api("PATCH", "/1/cbom/sources/settings", json={"network_exclusions": [
        {"cidr": "10.20.99.0/24", "reason": "OT plant"}, {"cidr": "fd00::1-fd00::5", "reason": "v6"},
        {"cidr": "fe80::1%br-ab12", "reason": "bridge"}]})
    assert ok.status_code == 200, ok.text
    assert len(ok.json()["settings"]["network_exclusions"]) == 3


def test_a_loopback_name_in_a_source_never_scan_list_is_kept_and_counted_as_loopback_only(api, world):
    """Re-review 5879769432 (netutil.py:53): a server source may list localhost (or another name that is loopback by
    definition).  The API keeps it, and the count, the credits and the connection-test samples leave out exactly
    what the node leaves out for it: the loopback addresses, and nothing else (the node never holds on it)."""
    node_id, _t, _ = enroll_node(api)
    body = linux_body(node_id=node_id, targets=["127.0.0.0/29", "10.20.0.0/30", "::1", "localhost", "app-01.bank.local"],
                      exclusions=["LOCALHOST.", "10.20.0.2", "db.localhost"])
    r = api("POST", "/1/cbom/sources/items", json=body)
    assert r.status_code == 201, r.text
    src = r.json()["source"]
    assert src["config"]["exclusions"] == ["localhost", "10.20.0.2", "db.localhost"]
    assert src["target_count"] == 2  # 10.20.0.1 and app-01.bank.local: loopback (and the name localhost) left out
    count = api("POST", "/1/cbom/sources/targets/count", json={
        "targets": ["127.0.0.0/29", "10.20.0.0/30", "64:ff9b::7f00:1", "::ffff:127.0.0.9"], "exclusions": ["localhost"]}).json()
    assert (count["valid"], count["count"], count["samples"]) == (True, 2, ["10.20.0.1", "10.20.0.2"])
    other = api("POST", "/1/cbom/sources/targets/count", json={
        "targets": ["127.0.0.0/29"], "exclusions": ["localhost.corp.internal"]}).json()
    assert other["count"] == 6  # any other name: matched by the node only, by what it resolves to there


@pytest.mark.parametrize("cidr, team, units", [
    ("10.0.0.0/29", [], 6),  # the sweep visits the 6 host addresses, not the network and broadcast addresses
    ("10.0.0.0/29", ["10.0.0.1"], 5),
    ("10.0.0.0/31", [], 2),
    ("0.0.0.0/29", [], 0),  # 0.0.0.0/8 reaches the node itself: never swept
    ("fd00::/125", ["fd00::1-fd00::5"], 3),
])
def test_network_range_units_are_the_addresses_the_node_sweeps(api, world, cidr, team, units):
    node_id, _t, _ = enroll_node(api)
    r = api("POST", "/1/cbom/sources/items", json={"kind": "network_range", "name": "range", "node_id": node_id,
                                                  "config": {"cidr": cidr, "mode": "full"}})
    assert r.status_code == 201, r.text
    if team:
        assert api("PATCH", "/1/cbom/sources/settings", json={"network_exclusions": [
            {"cidr": c, "reason": "x"} for c in team]}).status_code == 200
    plan = api("POST", "/1/cbom/sources/estimate", json={"include": {"network": True}}).json()
    item = next(i for i in plan["items"] if i["kind"] == "network_range")
    assert (item["units"], item["unit"]) == (units, "addresses")


def test_network_run_needs_soc_ack_and_respects_stop(api, world):
    node_id, _t, _ = enroll_node(api)
    r = api("POST", "/1/cbom/sources/items", json={"kind": "network_range", "name": "dc-range", "node_id": node_id,
                                                  "config": {"cidr": "10.20.0.0/22", "mode": "full"}})
    assert r.status_code == 201, r.text
    api("PATCH", "/1/cbom/sources/settings", json={"network_exclusions": [{"cidr": "10.20.3.0/24", "reason": "x"}]})
    est = api("POST", "/1/cbom/sources/estimate", json={"include": {"network": True}}).json()
    assert est["total_credits"] == 3.0  # 3 /24 blocks after the never-scan list
    body = {"include": {"network": True}, "client_request_id": "net-run-0001"}
    assert "soc_ack" in api("POST", "/1/cbom/sources/runs", json=body).json()["detail"]
    api("POST", "/1/cbom/sources/settings/stop-all", json={"on": True})
    est = api("POST", "/1/cbom/sources/estimate", json={"include": {"network": True}}).json()
    assert est["skipped"][0]["reason"] == "Network scanning is stopped"


# ----------------------------------------------------------------------------- evidence and vendors
def test_evidence_confidence_rules(api):
    r = api("PATCH", "/1/cbom/sources/evidence/hsm_firmware", json={"confidence": "Q2"})
    assert r.status_code == 400 and "evidence" in r.json()["detail"]
    today = dt.date.today().isoformat()
    r = api("PATCH", "/1/cbom/sources/evidence/hsm_firmware", json={
        "confidence": "Q3", "evidence_title": "FIPS cert", "evidence_url": "https://csrc.nist.gov/x", "evidence_date": today,
        "answers": {"model": "<script>alert(1)</script>", "process": "yes"}})
    assert r.status_code == 200 and r.json()["area"]["effective_confidence"] == "Q3"
    old = (dt.date.today() - dt.timedelta(days=400)).isoformat()
    r = api("PATCH", "/1/cbom/sources/evidence/hsm_firmware", json={"evidence_date": old})
    assert r.json()["area"]["effective_confidence"] == "Q0"
    assert api("PATCH", "/1/cbom/sources/evidence/hsm_firmware", json={"answers": {"process": "maybe"}}).status_code == 400
    assert api("PATCH", "/1/cbom/sources/evidence/nope", json={}).status_code == 404


def test_vendor_link_is_single_use_and_replaceable(api):
    vendor = api("POST", "/1/cbom/sources/evidence/vendors", json={"name": "Core banking vendor"}).json()["vendor"]
    first = api("POST", f"/1/cbom/sources/evidence/vendors/{vendor['id']}/link").json()
    second = api("POST", f"/1/cbom/sources/evidence/vendors/{vendor['id']}/link").json()
    t1, t2 = first["path"].rsplit("/", 1)[-1], second["path"].rsplit("/", 1)[-1]
    assert api("GET", f"/cbom/vendor-questionnaire/{t1}", None).status_code == 404
    shown = api("GET", f"/cbom/vendor-questionnaire/{t2}", None)
    assert shown.status_code == 200 and shown.json()["team_name"] == "Bank One"
    assert shown.headers["referrer-policy"] == "no-referrer"
    ans = api("POST", f"/cbom/vendor-questionnaire/{t2}", None, json={"answers": {"tls": "TLS 1.2+", "junk": "x"}})
    assert ans.status_code == 200 and ans.json()["confidence"] == "Q1"
    assert api("POST", f"/cbom/vendor-questionnaire/{t2}", None, json={"answers": {"tls": "again"}}).status_code == 404
    assert api("GET", f"/cbom/vendor-questionnaire/{t2}", None).status_code == 404
    ev = api("GET", "/1/cbom/sources/evidence").json()
    assert ev["vendors"][0]["status"] == "answered" and ev["vendors"][0]["answers"] == {"tls": "TLS 1.2+"}
    big = api("POST", f"/cbom/vendor-questionnaire/{t2}", None, content=b"x" * (40 * 1024),
              headers={"content-type": "application/json"})
    assert big.status_code == 413


# ----------------------------------------------------------------------------- misc
def test_templates_and_overview(api):
    sudoers = api("GET", "/1/cbom/sources/templates/sudoers")
    rules = "\n".join(line for line in sudoers.text.splitlines() if not line.startswith("#"))
    assert sudoers.status_code == 200 and "NOPASSWD: ZS_CBOM_TIER2" in rules
    assert not any(ch in rules.split("Cmnd_Alias", 1)[1].replace(".+", "") for ch in "*?[")  # no argument wildcards
    assert api("GET", "/1/cbom/sources/templates/../../etc/passwd").status_code == 404
    ov = api("GET", "/1/cbom/sources/overview").json()
    assert ov["code"]["cbom_scans"] == 1 and ov["evidence"]["areas"] == 6 and ov["rates"]["server"] == 0.2


def test_team_cleanup_removes_every_row(api, world):
    engine, _ = world
    node_id, _t, _ = enroll_node(api)
    src = api("POST", "/1/cbom/sources/items", json=linux_body(node_id=node_id)).json()["source"]
    api("POST", f"/1/cbom/sources/items/{src['id']}/test")
    api("GET", "/1/cbom/sources/evidence")
    counts = delete_cbom_sources_for_team(engine, 1)
    assert counts["cbomcollectionjob"] == 1 and counts["cbomscannode"] == 1 and counts["cbomevidencearea"] == 6
    with Session(engine) as s:
        assert s.exec(select(CbomScanNode)).all() == [] and s.exec(select(CbomCollectionSource)).all() == []


# ----------------------------------------------------------------------------- collected assets
def _collect_job(api, engine, *, targets=None):
    node_id, token, _ = enroll_node(api)
    src = api("POST", "/1/cbom/sources/items", json=linux_body(node_id=node_id, targets=targets or ["10.20.0.1", "10.20.0.2"],
                                                               window="any")).json()["source"]
    run = api("POST", "/1/cbom/sources/runs", json={"include": {"servers": True}, "client_request_id": f"assets-{src['id']}-01"})
    assert run.status_code == 201, run.text
    hdr = {"X-ZS-Node-Token": token}
    claim = api("POST", "/cbom/node/jobs/claim", None, headers=hdr)
    assert claim.status_code == 200, claim.text
    return src, run.json()["run"], claim.json(), hdr


CERT_FACTS = {"subject": "CN=pay.bank.local", "issuer": "CN=pay.bank.local", "not_after": "2020-01-01T00:00:00Z",
              "sig_alg": "md5WithRSAEncryption", "key_alg": "RSA", "key_size": 1024, "self_signed": True,
              "fingerprint_sha256": "ab" * 32}


def test_assets_are_stored_classified_deduplicated_and_scrubbed(api, world):
    engine, _ = world
    src, run, claim, hdr = _collect_job(api, engine)
    job, lease = claim["job"], claim["job"]["lease_id"]
    assert claim["scope"]["max_runtime_s"] > 0 and "window_ends_at" in claim["scope"]
    batch = [
        {"type": "certificate", "target": "10.20.0.1", "location": "/etc/ssl/pay.pem", "name": "pay", "algorithm": "RSA",
         "key_size": 1024, "facts": CERT_FACTS},
        {"type": "certificate", "target": "10.20.0.1", "location": "/etc/ssl/pay.pem", "name": "pay", "algorithm": "RSA",
         "key_size": 1024, "facts": CERT_FACTS},  # duplicate in the same batch
        {"type": "tls_endpoint", "target": "10.20.0.1", "location": "10.20.0.1:443", "facts": {
            "protocols": ["TLSv1.0", "TLSv1.2"], "group": "x25519", "weak_ciphers": ["DES-CBC3-SHA"]}},
        {"type": "database_config", "target": "10.20.0.2", "location": "10.20.0.2:5432", "facts": {
            "password_encryption": "md5", "password": PASSWORD, "note": f"leak {PASSWORD} {PEM_KEY[:60]}"}},
        {"type": "not_a_type", "location": "x"},
        {"type": "certificate", "location": ""},
        {"type": "tls_endpoint", "location": "10.20.0.2:443", "impact": "Low", "facts": {"protocols": ["SSLv3"]}},
    ]
    r = api("POST", f"/cbom/node/jobs/{job['id']}/assets", None, headers=hdr, json={"lease_id": lease, "batch_id": "b1", "assets": batch})
    assert r.status_code == 200, r.text
    out = r.json()
    assert out["accepted"] == 4 and out["duplicate"] == 1 and out["rejected"] == 2 and out["total_for_attempt"] == 4
    again = api("POST", f"/cbom/node/jobs/{job['id']}/assets", None, headers=hdr, json={"lease_id": lease, "batch_id": "b1", "assets": batch[:1]})
    assert again.json()["accepted"] == 0 and again.json()["duplicate"] == 1  # a retried batch is idempotent
    listed = api("GET", f"/1/cbom/sources/runs/{run['id']}/assets").json()
    text = json.dumps(listed)
    assert PASSWORD not in text and "PRIVATE KEY" not in text
    by_loc = {a["location"]: a for a in listed["items"]}
    cert = by_loc["/etc/ssl/pay.pem"]
    assert cert["impact"] == "Critical" and {"SIG_MD5", "CERT_EXPIRED", "RSA_LT_2048"} <= set(cert["finding_codes"])
    assert cert["quantum_vulnerable"] is True
    tls = by_loc["10.20.0.1:443"]
    assert tls["impact"] == "High" and "PROTO_TLS10" in tls["finding_codes"] and "WEAK_CIPHER" in tls["finding_codes"]
    assert by_loc["10.20.0.2:443"]["impact"] == "Critical"  # the node's own "impact" is ignored
    db = by_loc["10.20.0.2:5432"]
    assert db["facts"]["password_encryption"] == "md5" and db["facts"]["password"] == "[redacted]" and "DB_MD5_DEFAULT" in db["finding_codes"]
    assert listed["facets"]["impact"]["Critical"] == 2 and listed["all_total"] == 4
    only = api("GET", f"/1/cbom/sources/runs/{run['id']}/assets?impact=Critical").json()
    assert only["total"] == 2
    assert api("GET", f"/2/cbom/sources/runs/{run['id']}/assets", "carol").status_code == 404
    done = api("POST", f"/cbom/node/jobs/{job['id']}/result", None, headers=hdr, json={"lease_id": lease, "status": "success",
               "result": {"counts": {"total": 2, "ok": 1, "failed": 1, "skipped": 0}, "asset_count": 4,
                          "targets": [{"target": "10.20.0.1", "status": "ok"}, {"target": "10.20.0.2", "status": "auth_failed",
                                                                                  "error": f"bad {PASSWORD}"}]}})
    assert done.status_code == 200, done.text
    detail = api("GET", f"/1/cbom/sources/runs/{run['id']}").json()["run"]
    assert detail["status"] == "partial" and detail["jobs"][0]["outcome"] == "partial" and detail["jobs"][0]["asset_count"] == 4
    assert "targets" not in detail["jobs"][0]["result"]
    listed = api("GET", f"/1/cbom/sources/runs/{run['id']}/assets").json()
    assert listed["targets"][0]["targets"][1]["status"] == "auth_failed" and PASSWORD not in json.dumps(listed)
    cdx = api("GET", f"/1/cbom/sources/runs/{run['id']}/cbom")
    assert cdx.status_code == 200 and "attachment" in cdx.headers["content-disposition"]
    bom = cdx.json()
    assert bom["specVersion"] == "1.6" and len(bom["components"]) == listed["all_total"]
    kinds = {c.get("cryptoProperties", {}).get("assetType") for c in bom["components"]}
    assert {"certificate", "protocol"} <= kinds
    assert any(p["name"] == "zs:gap" and "auth_failed" in p["value"] for p in bom["metadata"]["properties"])
    late = api("POST", f"/cbom/node/jobs/{job['id']}/assets", None, headers=hdr, json={"lease_id": lease, "assets": batch[:1]})
    assert late.status_code == 409


def test_a_classifier_error_stores_that_asset_unjudged_and_keeps_the_batch(api, world, monkeypatch):
    """Regression: the except branch in jobs.add_assets called log.warning on the common.log function, so one asset
    the classifier could not read turned the whole batch into a 500."""
    engine, _ = world
    src, run, claim, hdr = _collect_job(api, engine)
    job, lease = claim["job"], claim["job"]["lease_id"]
    real = J.classify

    def flaky(asset_type, *args, **kwargs):
        if asset_type == "tls_endpoint":
            raise ValueError("unreadable facts")
        return real(asset_type, *args, **kwargs)

    monkeypatch.setattr(J, "classify", flaky)
    batch = [
        {"type": "tls_endpoint", "target": "10.20.0.1", "location": "10.20.0.1:443", "facts": {"protocols": ["TLSv1.0"]}},
        {"type": "certificate", "target": "10.20.0.1", "location": "/etc/ssl/pay.pem", "name": "pay", "algorithm": "RSA",
         "key_size": 1024, "facts": CERT_FACTS},
    ]
    r = api("POST", f"/cbom/node/jobs/{job['id']}/assets", None, headers=hdr, json={"lease_id": lease, "batch_id": "b1", "assets": batch})
    assert r.status_code == 200, r.text
    assert r.json()["accepted"] == 2
    by_loc = {a["location"]: a for a in api("GET", f"/1/cbom/sources/runs/{run['id']}/assets").json()["items"]}
    assert by_loc["10.20.0.1:443"]["impact"] is None and by_loc["10.20.0.1:443"]["finding_codes"] == []
    assert "RSA_LT_2048" in by_loc["/etc/ssl/pay.pem"]["finding_codes"]


def test_failed_or_cancelled_collect_jobs_are_refunded(api, world):
    engine, _ = world
    src, run, claim, hdr = _collect_job(api, engine)
    with Session(engine) as s:
        before = s.get(Team, 1).credit_balance
    r = api("POST", f"/cbom/node/jobs/{claim['job']['id']}/result", None, headers=hdr,
            json={"lease_id": claim["job"]["lease_id"], "status": "failure", "error": "every target refused"})
    assert r.status_code == 200
    with Session(engine) as s:
        assert round(s.get(Team, 1).credit_balance - before, 2) == 0.4  # 2 targets x 0.2 back
        assert s.get(CbomCollectionJob, claim["job"]["id"]).refunded is True


def test_same_location_on_two_hosts_is_two_assets(api, world):
    """Security review 2026-10-31: host collectors report host-relative locations, so the key must include the target."""
    engine, _ = world
    src, run, claim, hdr = _collect_job(api, engine)
    job, lease = claim["job"], claim["job"]["lease_id"]
    batch = [{"type": "ssh_server_config", "target": t, "location": "sshd -T", "name": "sshd effective configuration",
              "facts": {"ciphers": c}} for t, c in (("10.20.0.1", ["aes128-cbc"]), ("10.20.0.2", ["chacha20-poly1305@openssh.com"]))]
    batch += [{"type": "crypto_library", "target": t, "location": "package:openssl", "name": "openssl",
               "facts": {"name": "openssl", "version": v}} for t, v in (("10.20.0.1", "1.0.2k"), ("10.20.0.2", "3.0.13"))]
    out = api("POST", f"/cbom/node/jobs/{job['id']}/assets", None, headers=hdr,
              json={"lease_id": lease, "batch_id": "hosts", "assets": batch}).json()
    assert out["accepted"] == 4 and out["duplicate"] == 0
    items = api("GET", f"/1/cbom/sources/runs/{run['id']}/assets").json()["items"]
    assert sorted((a["target"], a["location"]) for a in items) == [
        ("10.20.0.1", "package:openssl"), ("10.20.0.1", "sshd -T"), ("10.20.0.2", "package:openssl"), ("10.20.0.2", "sshd -T")]


def test_a_job_whose_every_target_was_skipped_is_refunded(api, world):
    engine, _ = world
    src, run, claim, hdr = _collect_job(api, engine)
    with Session(engine) as s:
        before = s.get(Team, 1).credit_balance
    r = api("POST", f"/cbom/node/jobs/{claim['job']['id']}/result", None, headers=hdr,
            json={"lease_id": claim["job"]["lease_id"], "status": "success",
                  "result": {"counts": {"total": 2, "ok": 0, "failed": 0, "skipped": 2}, "asset_count": 0}})
    assert r.status_code == 200
    with Session(engine) as s:
        job = s.get(CbomCollectionJob, claim["job"]["id"])
        assert job.outcome == "failed" and job.refunded is True
        assert round(s.get(Team, 1).credit_balance - before, 2) == 0.4


def test_heartbeat_running_list_renews_only_live_jobs_and_releases_orphans(api, world):
    engine, _ = world
    src, run, claim, hdr = _collect_job(api, engine)
    job_id, lease = claim["job"]["id"], claim["job"]["lease_id"]
    hb = api("POST", "/cbom/node/heartbeat", None, headers=hdr, json={"running": [{"job_id": job_id, "lease_id": lease}]})
    assert hb.status_code == 200 and hb.json()["cancel_job_ids"] == [] and "never_scan" in hb.json()
    with Session(engine) as s:  # the node restarted and lost the job
        job = s.get(CbomCollectionJob, job_id)
        job.claimed_at = dt.datetime.utcnow() - dt.timedelta(minutes=5)
        s.add(job)
        s.commit()
    hb = api("POST", "/cbom/node/heartbeat", None, headers=hdr, json={"running": []})
    assert hb.status_code == 200
    with Session(engine) as s:
        job = s.get(CbomCollectionJob, job_id)
        assert job.status == "pending" and job.lease_id is None
    # the next attempt starts clean: assets of attempt 1 are dropped
    claim2 = api("POST", "/cbom/node/jobs/claim", None, headers=hdr).json()
    assert claim2["job"]["attempt"] == 2
    old = api("POST", f"/cbom/node/jobs/{job_id}/assets", None, headers=hdr, json={"lease_id": lease, "assets": []})
    assert old.status_code == 409  # the old lease is dead


def test_run_cancel_stops_a_claimed_job_through_the_heartbeat(api, world):
    engine, _ = world
    src, run, claim, hdr = _collect_job(api, engine)
    job_id, lease = claim["job"]["id"], claim["job"]["lease_id"]
    c = api("POST", f"/1/cbom/sources/runs/{run['id']}/cancel").json()
    assert c["refunded"] == 0 and c["run"]["jobs"][0]["waiting_reason"].startswith("Stop requested")
    hb = api("POST", "/cbom/node/heartbeat", None, headers=hdr, json={"running": [{"job_id": job_id, "lease_id": lease}]})
    assert hb.json()["cancel_job_ids"] == [job_id]
    stale = api("POST", f"/cbom/node/jobs/{job_id}/assets", None, headers=hdr, json={"lease_id": lease, "assets": [
        {"type": "open_port", "location": "10.20.0.1:22"}]})
    assert stale.status_code == 409
    with Session(engine) as s:
        job = s.get(CbomCollectionJob, job_id)
        assert job.status == "cancelled" and job.refunded is True
        assert s.get(CbomCollectionRun, run["id"]).status == "cancelled"


def test_source_edit_mid_job_cancels_the_job_and_rejects_its_result(api, world):
    engine, _ = world
    src, run, claim, hdr = _collect_job(api, engine)
    job_id, lease = claim["job"]["id"], claim["job"]["lease_id"]
    api("PATCH", f"/1/cbom/sources/items/{src['id']}", json={"config": {**src["config"], "port": 2222},
                                                             "secrets": {"password": "x-new-2"}})
    hb = api("POST", "/cbom/node/heartbeat", None, headers=hdr, json={"running": [{"job_id": job_id, "lease_id": lease}]})
    assert job_id in hb.json()["cancel_job_ids"]
    done = api("POST", f"/cbom/node/jobs/{job_id}/result", None, headers=hdr,
               json={"lease_id": lease, "status": "success", "result": {"counts": {"total": 2, "ok": 2}}})
    assert done.status_code == 200 and done.json()["status"] == "cancelled"
    with Session(engine) as s:
        assert s.get(CbomCollectionJob, job_id).refunded is True


def test_deleting_a_source_keeps_its_assets(api, world):
    engine, _ = world
    src, run, claim, hdr = _collect_job(api, engine)
    api("POST", f"/cbom/node/jobs/{claim['job']['id']}/assets", None, headers=hdr, json={
        "lease_id": claim["job"]["lease_id"], "assets": [{"type": "open_port", "location": "10.20.0.1:22"}]})
    assert api("DELETE", f"/1/cbom/sources/items/{src['id']}").status_code == 200
    listed = api("GET", f"/1/cbom/sources/runs/{run['id']}/assets").json()
    assert listed["all_total"] == 1 and listed["items"][0]["source_name"] == src["name"]
    counts = delete_cbom_sources_for_team(engine, 1)
    assert counts["cbomcollectedasset"] == 1


def test_classify_rules():
    from backend.utilities.cbom_sources.classify import classify, quantum_vulnerable

    assert quantum_vulnerable("RSA") is True and quantum_vulnerable("X25519MLKEM768") is False
    assert quantum_vulnerable("ECC_NIST_P256") is True and quantum_vulnerable("ML_DSA_65") is False
    ssh = classify("ssh_endpoint", None, None, None, {"kex": ["diffie-hellman-group1-sha1"], "ciphers": ["aes128-cbc"],
                                                      "hostkey_algorithms": ["ssh-dss"]})
    assert ssh["impact"] == "High" and ssh["quantum_vulnerable"] is True
    pq = classify("ssh_endpoint", None, None, None, {"kex": ["mlkem768x25519-sha256", "curve25519-sha256"]})
    assert pq["quantum_vulnerable"] is False and pq["impact"] is None
    hybrid = classify("tls_endpoint", None, None, None, {"protocols": ["TLSv1.3"], "group": "X25519MLKEM768"})
    assert hybrid["quantum_vulnerable"] is False and hybrid["impact"] is None
    luks = classify("disk_encryption", "aes-cbc-essiv:sha256", 256, None, {"luks_version": 1})
    assert luks["impact"] == "Medium" and "LUKS1" in luks["finding_codes"]
    kms = classify("kms_key", "SYMMETRIC_DEFAULT", 256, None, {"key_spec": "SYMMETRIC_DEFAULT", "key_manager": "CUSTOMER",
                                                                "rotation_enabled": False})
    assert kms["impact"] == "Medium" and kms["quantum_vulnerable"] is False
    gap = classify("coverage", None, None, None, {"check": "sshd -T", "status": "denied"})
    assert gap["impact"] is None and gap["finding"].startswith("Not collected")


def test_safe_fetch_refuses_private_and_mapped_addresses(monkeypatch):
    from backend.utilities.cbom_sources import safe_fetch

    for address in ("10.0.0.1", "127.0.0.1", "169.254.169.254", "100.64.1.1", "::ffff:10.0.0.1", "fd00:ec2::254", "::1"):
        assert not safe_fetch.public_address(address), address
    assert safe_fetch.public_address("8.8.8.8")
    monkeypatch.delenv("CBOM_LAB_ALLOW_PRIVATE_FETCH", raising=False)
    monkeypatch.setattr(safe_fetch.socket, "getaddrinfo", lambda *a, **k: [(2, 1, 6, "", ("169.254.169.254", 443))])
    with pytest.raises(safe_fetch.FetchError, match="private or reserved"):
        safe_fetch.fetch("https://metadata.example.com/.well-known/openid-configuration")
    with pytest.raises(safe_fetch.FetchError, match="https"):
        safe_fetch.fetch("http://example.com/")
    # lab mode allows RFC 1918 targets but never the metadata service, loopback or CGNAT
    assert safe_fetch.lab_address("10.77.0.50") and safe_fetch.lab_address("192.168.1.5")
    for address in ("169.254.169.254", "127.0.0.1", "100.64.0.1", "fd00:ec2::254", "::ffff:169.254.169.254"):
        assert not safe_fetch.lab_address(address), address
    monkeypatch.setenv("CBOM_LAB_ALLOW_PRIVATE_FETCH", "1")
    with pytest.raises(safe_fetch.FetchError, match="private or reserved"):
        safe_fetch.fetch("https://metadata.example.com/latest")


def test_passwords_only_go_to_servers_whose_identity_is_checked(api, world):
    """Product decision 2026-10-31: verified identity before any password; vault references are for team admins."""
    node_id, _t, _ = enroll_node(api)
    tofu = linux_body(name="pw-tofu", node_id=node_id, host_key_policy="tofu", known_hosts=None)
    r = api("POST", "/1/cbom/sources/items", json=tofu)
    assert r.status_code == 400 and "pinned host keys" in r.json()["detail"]
    key = linux_body(name="key-tofu", node_id=node_id, host_key_policy="tofu", known_hosts=None, credential_type="node_key")
    key["secrets"] = {}
    assert api("POST", "/1/cbom/sources/items", json=key).status_code == 201  # key logins reveal nothing
    pinned = api("POST", "/1/cbom/sources/items", json=linux_body(name="pw-pinned", node_id=node_id)).json()["source"]
    weaken = api("PATCH", f"/1/cbom/sources/items/{pinned['id']}", json={
        "config": {**pinned["config"], "host_key_policy": "tofu", "known_hosts": None}, "secrets": {"password": PASSWORD},
        "expected_version": pinned["row_version"]})
    assert weaken.status_code == 400 and "pinned host keys" in weaken.json()["detail"]
    win = {"kind": "windows_servers", "name": "win-http", "node_id": node_id,
           "config": {"targets": ["10.20.5.10"], "port": 5985, "credential_type": "password"}, "secrets": {"password": PASSWORD}}
    r = api("POST", "/1/cbom/sources/items", json=win)
    assert r.status_code == 400 and "HTTPS (5986)" in r.json()["detail"]
    win["config"]["port"] = 5986
    win["name"] = "win-https"
    assert api("POST", "/1/cbom/sources/items", json=win).status_code == 201
    db = {"kind": "database", "name": "my-noca", "node_id": node_id,
          "config": {"engine": "mysql", "host": "10.20.6.1", "login": "zs_cbom"}, "secrets": {"password": PASSWORD}}
    r = api("POST", "/1/cbom/sources/items", json=db)
    assert r.status_code == 400 and "CA certificate" in r.json()["detail"]
    redis_open = {"kind": "database", "name": "redis-noauth", "node_id": node_id,
                  "config": {"engine": "redis", "host": "10.20.6.2"}, "secrets": {}}
    assert api("POST", "/1/cbom/sources/items", json=redis_open).status_code == 201  # no password, nothing to leak
    pg = {"kind": "database", "name": "pg-noca", "node_id": node_id,
          "config": {"engine": "postgres", "host": "10.20.6.3", "login": "zs_cbom"}, "secrets": {"password": PASSWORD}}
    assert api("POST", "/1/cbom/sources/items", json=pg).status_code == 201  # the node holds it to SCRAM
    vault = linux_body(name="vault-src", node_id=node_id, credential_type="vault",
                       vault={"provider": "hashicorp", "path": "secret/zs-cbom/ssh"})
    vault["secrets"] = {}
    r = api("POST", "/1/cbom/sources/items", "bob", json=vault)
    assert r.status_code == 400 and "team admin" in r.json()["detail"]
    made = api("POST", "/1/cbom/sources/items", json=vault)
    assert made.status_code == 201, made.text


def test_review2_edge_rules(api, world):
    """Second independent review, 2026-10-31: a source saved before the identity rules can still be disabled; a
    rename does not stop a running discovery; a job that stored assets is never refunded as 'nothing collected'."""
    engine, _ = world
    node_id, token, _ = enroll_node(api)
    hdr = {"X-ZS-Node-Token": token}
    src = api("POST", "/1/cbom/sources/items", json=linux_body(node_id=node_id)).json()["source"]
    with Session(engine) as s:  # saved before the rule: password + trust on first use
        row = s.get(CbomCollectionSource, src["id"])
        row.config = {**row.config, "host_key_policy": "tofu", "known_hosts": None}
        s.add(row)
        s.commit()
        version = row.row_version
    r = api("PATCH", f"/1/cbom/sources/items/{src['id']}", json={"enabled": False, "expected_version": version})
    assert r.status_code == 200, r.text
    api("PATCH", "/1/cbom/sources/settings", json={"scan_window": [[True] * 24 for _ in range(7)]})
    rng = api("POST", "/1/cbom/sources/items", json={"kind": "network_range", "name": "r-a", "node_id": node_id,
                                                    "config": {"cidr": "10.30.0.0/24", "mode": "full"}}).json()["source"]
    assert api("POST", "/1/cbom/sources/discovery").status_code == 200
    claim = api("POST", "/cbom/node/jobs/claim", None, headers=hdr).json()
    assert claim["job"]["kind"] == "discovery"
    assert api("PATCH", f"/1/cbom/sources/items/{rng['id']}",
               json={"name": "r-a-renamed", "expected_version": rng["row_version"]}).status_code == 200
    hb = api("POST", "/cbom/node/heartbeat", None, headers=hdr,
             json={"running": [{"job_id": claim["job"]["id"], "lease_id": claim["job"]["lease_id"]}]}).json()
    assert claim["job"]["id"] not in hb["cancel_job_ids"]


def test_a_job_that_stored_assets_is_not_refunded_as_empty(api, world):
    engine, _ = world
    src, run, claim, hdr = _collect_job(api, engine, targets=["10.20.0.1"])
    job, lease = claim["job"], claim["job"]["lease_id"]
    out = api("POST", f"/cbom/node/jobs/{job['id']}/assets", None, headers=hdr, json={"lease_id": lease, "batch_id": "b1", "assets": [
        {"type": "crypto_library", "target": "10.20.0.1", "location": f"package:lib{i}", "name": f"lib{i}",
         "facts": {"name": f"lib{i}", "version": "1"}} for i in range(5)]}).json()
    assert out["accepted"] == 5
    r = api("POST", f"/cbom/node/jobs/{job['id']}/result", None, headers=hdr, json={"lease_id": lease, "status": "success",
            "result": {"counts": {"total": 1, "ok": 0, "failed": 0, "skipped": 1}, "asset_count": 5}})
    assert r.status_code == 200
    with Session(engine) as s:
        j = s.get(CbomCollectionJob, job["id"])
        assert j.asset_count == 5 and j.refunded is False


def test_safe_fetch_blocks_ipv4_carried_in_ipv6():
    from backend.utilities.cbom_sources import safe_fetch

    for address in ("64:ff9b::a9fe:a9fe", "64:ff9b:1::a00:1", "2002:a9fe:a9fe::1",  # NAT64, local NAT64, 6to4
                    "::ffff:0:7f00:1", "::7f00:1"):  # IPv4-translated, IPv4-compatible
        assert not safe_fetch.public_address(address), address
    assert safe_fetch.public_address("2606:4700:4700::1111")


def test_saml_doctype_is_refused_in_any_encoding():
    """Security review 2026-10-31: a UTF-16 document hid its DOCTYPE from the byte search."""
    from backend.utilities.cbom_sources.idp_collect import FetchError, saml_assets_from_xml

    doc = ('<?xml version="1.0" encoding="UTF-16"?><!DOCTYPE x [<!ENTITY a "aaaa">]>'
           '<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="&a;"/>')
    with pytest.raises(FetchError, match="DOCTYPE"):
        saml_assets_from_xml(doc.encode("utf-16"), "u", "l")


def test_discovery_only_sweeps_ranges_that_still_apply(api, world):
    """Security review 2026-10-31: a deleted, disabled or changed range was still swept by a queued or running discovery."""
    node_id, token, _ = enroll_node(api)
    hdr = {"X-ZS-Node-Token": token}
    api("PATCH", "/1/cbom/sources/settings", json={"scan_window": [[True] * 24 for _ in range(7)]})
    ids = {}
    for name, cidr in (("r-a", "10.30.0.0/24"), ("r-b", "10.31.0.0/24")):
        r = api("POST", "/1/cbom/sources/items", json={"kind": "network_range", "name": name, "node_id": node_id,
                                                      "config": {"cidr": cidr, "mode": "full"}})
        assert r.status_code == 201, r.text
        ids[name] = r.json()["source"]["id"]
    assert api("POST", "/1/cbom/sources/discovery").status_code == 200
    assert api("DELETE", f"/1/cbom/sources/items/{ids['r-b']}").status_code == 200
    claim = api("POST", "/cbom/node/jobs/claim", None, headers=hdr).json()
    assert claim["job"]["kind"] == "discovery" and [r["cidr"] for r in claim["scope"]["ranges"]] == ["10.30.0.0/24"]
    src = api("GET", f"/1/cbom/sources/items/{ids['r-a']}").json()["source"]
    edit = api("PATCH", f"/1/cbom/sources/items/{ids['r-a']}", json={"config": {**src["config"], "cidr": "10.30.1.0/24"},
                                                                       "expected_version": src["row_version"]})
    assert edit.status_code == 200, edit.text
    hb = api("POST", "/cbom/node/heartbeat", None, headers=hdr,
             json={"running": [{"job_id": claim["job"]["id"], "lease_id": claim["job"]["lease_id"]}]}).json()
    assert claim["job"]["id"] in hb["cancel_job_ids"]
    # a queued sweep whose every range is gone is cancelled at claim, never handed out
    assert api("POST", "/1/cbom/sources/discovery").status_code == 200
    src = api("GET", f"/1/cbom/sources/items/{ids['r-a']}").json()["source"]
    assert api("PATCH", f"/1/cbom/sources/items/{ids['r-a']}",
               json={"enabled": False, "expected_version": src["row_version"]}).status_code == 200
    assert api("POST", "/cbom/node/jobs/claim", None, headers=hdr).status_code == 204


def test_saml_parser_refuses_entities_and_reads_signing_certs():
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    from backend.utilities.cbom_sources.idp_collect import FetchError, saml_assets_from_xml

    with pytest.raises(FetchError):
        saml_assets_from_xml(b'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a SYSTEM "file:///etc/passwd">]><x>&a;</x>', "u", "l")
    key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "idp.test")])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(7).not_valid_before(now - dt.timedelta(days=2)).not_valid_after(now - dt.timedelta(days=1))
            .sign(key, hashes.SHA256()))
    import base64

    b64 = base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode()
    xml = (f'<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" '
           f'entityID="https://idp.test/"><md:IDPSSODescriptor><md:KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data>'
           f'<ds:X509Certificate>{b64}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>'
           f'</md:IDPSSODescriptor></md:EntityDescriptor>').encode()
    assets = saml_assets_from_xml(xml, "https://idp.test/metadata", "idp")
    types = sorted(a["type"] for a in assets)
    assert types == ["certificate", "identity_provider", "signing_key"]
    cert_asset = next(a for a in assets if a["type"] == "certificate")
    assert cert_asset["key_size"] == 1024 and cert_asset["facts"]["self_signed"] is True


def test_command_lists_shown_to_customers_match_the_server_and_sudoers():
    """The Servers tab, templates.py and the sudoers file must name the same commands."""
    import re as _re

    from backend.utilities.cbom_sources import templates

    tsx = (_REPO_ROOT / "frontend/components/cbom/sources/ServersTab.tsx").read_text()

    def ts_array(name):
        body = _re.search(rf"const {name} = \[(.*?)\];", tsx, _re.S).group(1)
        return [json.loads(item) for item in _re.findall(r'"(?:[^"\\]|\\.)*"', body)]

    assert ts_array("TIER1_COMMANDS") == templates.TIER1_COMMANDS
    assert ts_array("TIER2_COMMANDS") == templates.TIER2_COMMANDS
    sudoers = templates.SUDOERS
    assert "-exec /usr/bin/readlink" not in sudoers and "-printf %h\\\\\\\\t%l\\\\\\\\n" in sudoers
    # the scan node is the single source of truth for what runs on a customer server
    sys.path.insert(0, str(_REPO_ROOT / "scan_node"))
    from zs_scan_node import commands as node_commands

    assert templates.TIER1_COMMANDS == node_commands.TIER1_DISPLAY
    assert templates.TIER2_COMMANDS == node_commands.tier2_display()

    def cmnd_entries(text):
        body = text[text.index("Cmnd_Alias"):text.index("zs-cbom ALL=")]
        return [line.strip().rstrip(", \\").strip() for line in body.splitlines()[1:] if line.strip()]

    assert cmnd_entries(sudoers) == cmnd_entries(node_commands.sudoers_file())
    # what the Databases form says the login reads is exactly what templates.py says (it once promised per-role
    # password hashes and Redis ACL users that the read-only logins cannot see)
    db_tsx = (_REPO_ROOT / "frontend/components/cbom/sources/ClustersDatabasesTab.tsx").read_text()
    block = _re.search(r"const DB_READS: Record<Engine, string\[\]> = \{(.*?)\n\};", db_tsx, _re.S).group(1)
    ui_reads = {m.group(1): [json.loads(x) for x in _re.findall(r'"(?:[^"\\]|\\.)*"', m.group(2))]
                for m in _re.finditer(r"(\w+): \[(.*?)\]", block, _re.S)}
    assert ui_reads == templates.DB_READS
