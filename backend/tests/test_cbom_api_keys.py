"""Team-scoped CBOM API keys (issue #226): create / list / revoke, ``Authorization: Bearer zsk_...`` on the CBOM
Sources, runs and export routes within the key's scopes and team, refused everywhere else; hash-only storage, the
secret never logged, every use rate-limited and audited; and a full onboarding scripted with a key only.

SQLite, real JWTs, the real ``backend.main`` app (same pattern as ``test_cbom_sources_api.py``).
"""
from __future__ import annotations

import datetime as dt
import hashlib
import logging
import os
import re
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

from fastapi.routing import APIRoute  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import event  # noqa: E402
from sqlmodel import Session, SQLModel, create_engine, select  # noqa: E402

from backend.main import app  # noqa: E402
from backend.new_models import CbomCollectionAuditEvent, Team, TeamMembership, User  # noqa: E402
from backend.routers import auth as auth_router  # noqa: E402
from backend.routers import cbom_api_keys as key_router  # noqa: E402
from backend.routers import cbom_node, cbom_node_sshca, cbom_vendor_public  # noqa: E402
from backend.routers import team as team_router  # noqa: E402
from backend.utilities.auth import auth_utils  # noqa: E402
from backend.utilities.cbom_sources import api_keys as AK  # noqa: E402
from backend.utilities.cbom_sources import http as cbom_http  # noqa: E402
from backend.utilities.cbom_sources import node_auth  # noqa: E402
from backend.utilities.db.encryption import _get_fernet  # noqa: E402

SECRET_RE = re.compile(r"^zsk_[A-Za-z0-9_-]{43}$")
PASSWORD = "Canary-Pa55word-7f3a91"
KNOWN_HOSTS = "10.20.0.1 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIE0Bq1hQ0j7lC1n6x3o0b9Z7w2YtqXxw9i6ZQ5mM2kHq"
USERS = {"alice": ("alice@t1.test", 1, "admin"), "bob": ("bob@t1.test", 1, "member"),
         "carol": ("carol@t2.test", 2, "admin")}
GUIDE = _REPO_ROOT / "docs" / "cbom" / "api-keys.md"


@pytest.fixture()
def world(tmp_path, monkeypatch):
    _get_fernet.cache_clear()
    db = tmp_path / "w.db"
    engine = create_engine(f"sqlite:///{db}", connect_args={"check_same_thread": False})

    @event.listens_for(engine, "connect")
    def _fk(dbapi_conn, _record):
        dbapi_conn.execute("PRAGMA foreign_keys=ON")

    SQLModel.metadata.create_all(engine)
    ids = {}
    with Session(engine) as s:
        s.add(Team(id=1, name="Bank One", credit_balance=100.0))
        s.add(Team(id=2, name="Bank Two", credit_balance=100.0))
        s.commit()
        for who, (email, team, role) in USERS.items():
            user = User(email=email, password="x", first_name=who, last_name="t", profile_photo=None,
                        session_active=True, default_team_id=team)
            s.add(user)
            s.commit()
            s.refresh(user)
            ids[who] = user.id
            s.add(TeamMembership(team_id=team, user_id=user.id, role=role))
        s.commit()
    # every module these tests reach get_db() through, so they never depend on the process env (#433)
    for module in (cbom_http, cbom_node, cbom_node_sshca, cbom_vendor_public, node_auth, AK, key_router, auth_router,
                   team_router):
        monkeypatch.setattr(module, "get_db", lambda: engine)
    for limiter in (cbom_http.read_limiter, cbom_http.write_limiter, cbom_http.node_limiter,
                    cbom_http.enroll_limiter, cbom_http.vendor_limiter):
        limiter.requests.clear()
    return engine, ids, db


@pytest.fixture()
def api(world):
    client = TestClient(app)
    tokens = {who: auth_utils.create_access_token(email) for who, (email, _t, _r) in USERS.items()}

    def call(method: str, url: str, who: str | None = "alice", key: str | None = None, **kwargs):
        headers = dict(kwargs.pop("headers", {}) or {})
        if key is not None:
            headers["Authorization"] = f"Bearer {key}"
        elif who:
            headers["Authorization"] = f"Bearer {tokens[who]}"
        return client.request(method, url, headers=headers, **kwargs)

    return call


def make_key(api, scopes, team=1, who="alice", name="cmdb-sync", **extra):
    r = api("POST", f"/{team}/cbom/api-keys", who, json={"name": name, "scopes": scopes, **extra})
    assert r.status_code == 201, r.text
    body = r.json()
    return body["api_key"], body["secret"]


def linux_body(name="linux-dc", node_id=None):
    return {"kind": "linux_servers", "name": name, "node_id": node_id,
            "config": {"targets": ["10.20.0.0/29", "app-01.bank.local"], "credential_type": "password",
                       "login_user": "zs-cbom", "host_key_policy": "pinned", "known_hosts": KNOWN_HOSTS,
                       "window": "any"},
            "secrets": {"password": PASSWORD}}


def enroll_node(api, team=1, who="alice", name="dc-mumbai-01"):
    r = api("POST", f"/{team}/cbom/sources/nodes", who, json={"name": name, "segment": "Data centre"})
    assert r.status_code == 201, r.text
    node, reg = r.json()["node"], r.json()["registration_token"]
    e = api("POST", "/cbom/node/enroll", None, json={"registration_token": reg, "hostname": "n1", "version": "1.0",
                                                     "source_ips": ["10.20.1.15"],
                                                     "clock": dt.datetime.utcnow().isoformat() + "Z"})
    assert e.status_code == 200, e.text
    return node["id"], e.json()["node_token"]


def audit_rows(engine, team_id):
    with Session(engine) as s:
        return s.exec(select(CbomCollectionAuditEvent).where(CbomCollectionAuditEvent.team_id == team_id)
                      .order_by(CbomCollectionAuditEvent.id)).all()


# ----------------------------------------------------------------------------- creation and storage
def test_an_admin_creates_a_key_the_secret_is_shown_once_and_only_its_hash_is_stored(api, world):
    engine, ids, db = world
    r = api("POST", "/1/cbom/api-keys", json={"name": "cmdb-sync", "scopes": ["cbom.sources:write"],
                                              "expires_in_days": 90})
    assert r.status_code == 201, r.text
    assert "no-store" in r.headers.get("cache-control", "")
    secret = r.json()["secret"]
    assert SECRET_RE.match(secret)
    meta = r.json()["api_key"]
    assert meta["name"] == "cmdb-sync" and meta["scopes"] == ["cbom.sources:write"] and meta["status"] == "active"
    assert meta["hint"] == secret[-4:] and meta["expires_at"] and meta["last_used_at"] is None
    assert meta["created_by"] == "alice@t1.test"
    with Session(engine) as s:
        row = s.get(AK.CbomApiKey, meta["id"])
        assert row.key_hash == hashlib.sha256(secret.encode()).hexdigest()
        stored = " ".join(str(v) for v in row.model_dump().values())
    assert secret not in stored and secret[4:] not in stored
    engine.dispose()
    assert secret.encode() not in db.read_bytes()  # nowhere in the database file, only its SHA-256
    listed = api("GET", "/1/cbom/api-keys")
    assert listed.status_code == 200
    text = listed.text
    assert secret not in text and row.key_hash not in text and row.key_hash[:12] not in text
    assert [k["id"] for k in listed.json()["api_keys"]] == [meta["id"]]
    assert {s["name"] for s in listed.json()["scopes"]} == {"cbom.read", "cbom.sources:write", "cbom.runs:write"}
    assert listed.json()["can_manage"] is True


def test_key_creation_is_validated_and_admin_only(api, world):
    assert api("POST", "/1/cbom/api-keys", json={"name": "x", "scopes": ["billing:write"]}).status_code == 400
    assert api("POST", "/1/cbom/api-keys", json={"name": "x", "scopes": []}).status_code == 400
    assert api("POST", "/1/cbom/api-keys", json={"name": "", "scopes": ["cbom.read"]}).status_code == 400
    assert api("POST", "/1/cbom/api-keys", json={"name": "x", "scopes": ["cbom.read"],
                                                  "expires_in_days": 0}).status_code == 400
    assert api("POST", "/1/cbom/api-keys", json={"name": "x", "scopes": ["cbom.read"],
                                                  "expires_in_days": 10_000}).status_code == 400
    member = api("POST", "/1/cbom/api-keys", "bob", json={"name": "x", "scopes": ["cbom.read"]})
    assert member.status_code == 400 and "admin" in member.json()["detail"]
    assert api("POST", "/1/cbom/api-keys", "carol", json={"name": "x", "scopes": ["cbom.read"]}).status_code == 403
    assert api("GET", "/1/cbom/api-keys", "carol").status_code == 403
    listed = api("GET", "/1/cbom/api-keys", "bob")  # members see the keys (never a secret) but cannot manage them
    assert listed.status_code == 200 and listed.json()["can_manage"] is False


# ----------------------------------------------------------------------------- scope refusal
def test_a_key_works_only_within_its_scopes(api, world):
    node_id, _t = enroll_node(api)
    _m, read = make_key(api, ["cbom.read"], name="reader")
    _m, sources = make_key(api, ["cbom.sources:write"], name="cmdb")
    _m, runs = make_key(api, ["cbom.runs:write"], name="nightly")

    assert api("GET", "/1/cbom/sources/items", key=read).status_code == 200
    assert api("GET", "/1/cbom/sources/runs", key=read).status_code == 200
    refused = api("POST", "/1/cbom/sources/items", key=read, json=linux_body(node_id=node_id))
    assert refused.status_code == 403 and "cbom.sources:write" in refused.json()["detail"]
    run_body = {"include": {"servers": True}, "client_request_id": "scope-run-0001"}
    refused = api("POST", "/1/cbom/sources/runs", key=read, json=run_body)
    assert refused.status_code == 403 and "cbom.runs:write" in refused.json()["detail"]

    created = api("POST", "/1/cbom/sources/items", key=sources, json=linux_body(node_id=node_id))
    assert created.status_code == 201, created.text
    source_id = created.json()["source"]["id"]
    assert api("GET", f"/1/cbom/sources/items/{source_id}", key=sources).status_code == 200  # write implies read
    assert api("POST", "/1/cbom/sources/runs", key=sources, json=run_body).status_code == 403

    assert api("POST", "/1/cbom/sources/items", key=runs, json=linux_body(name="other", node_id=node_id)).status_code == 403
    assert api("DELETE", f"/1/cbom/sources/items/{source_id}", key=runs).status_code == 403
    started = api("POST", "/1/cbom/sources/runs", key=runs, json=run_body)
    assert started.status_code == 201, started.text


def test_a_key_is_refused_on_every_route_outside_the_cbom_sources_runs_and_export_routes(api, world):
    _m, key = make_key(api, ["cbom.read", "cbom.sources:write", "cbom.runs:write"], name="everything")
    # CBOM routes that are not sources / runs / export: settings, nodes (registration tokens), evidence, audit
    for method, url, body in [
        ("PATCH", "/1/cbom/sources/settings", {}),
        ("GET", "/1/cbom/sources/settings", None),
        ("POST", "/1/cbom/sources/nodes", {"name": "sneaky"}),
        ("GET", "/1/cbom/sources/evidence", None),
        ("GET", "/1/cbom/sources/audit", None),
        ("GET", "/1/cbom/sources/schedules", None),
        ("GET", "/1/cbom/estate", None),
        ("GET", "/1/integrations", None),
    ]:
        r = api(method, url, key=key, json=body)
        assert r.status_code == 403, (method, url, r.status_code, r.text)
        assert "API key" in r.json()["detail"]
    # account settings, team / billing, key management, other products: a key is not a session
    for method, url, body in [
        ("GET", "/get_user", None),
        ("POST", "/account/password", {"current_password": "x", "new_password": "y" * 12}),
        ("GET", "/team/1", None),
        ("PUT", "/team/1", {"name": "renamed"}),
        ("GET", "/teams", None),
        ("GET", "/1/cbom/api-keys", None),
        ("POST", "/1/cbom/api-keys", {"name": "child", "scopes": ["cbom.read"]}),
    ]:
        r = api(method, url, key=key, json=body)
        assert r.status_code == 401, (method, url, r.status_code, r.text)


def test_every_route_a_key_may_call_exists_and_is_a_sources_runs_or_export_route():
    routes = {(m, r.path) for r in app.routes if isinstance(r, APIRoute) for m in r.methods}
    for (method, path), scope in AK.ROUTE_SCOPES.items():
        assert (method, path) in routes, (method, path)
        assert path.startswith("/{team_id}/cbom/sources/"), path
        assert scope in AK.SCOPES
        assert not any(word in path for word in ("/settings", "/nodes/{node_id}/", "/evidence", "/audit", "api-keys"))
        if method != "GET" and not path.endswith(("/estimate", "/targets/count")):
            assert scope != "cbom.read", (method, path)


# ----------------------------------------------------------------------------- team, revocation, expiry
def test_a_key_of_one_team_is_refused_on_another_team(api, world):
    engine, _ids, _db = world
    meta, key = make_key(api, ["cbom.read", "cbom.sources:write"])
    r = api("GET", "/2/cbom/sources/items", key=key)
    assert r.status_code == 403 and "another team" in r.json()["detail"]
    assert api("POST", "/2/cbom/sources/items", key=key, json=linux_body()).status_code == 403
    refusals = [e for e in audit_rows(engine, 1) if e.action == "api_key.refused"]
    assert refusals and refusals[-1].object_id == meta["id"] and "team" in refusals[-1].changed_fields
    assert not [e for e in audit_rows(engine, 2) if e.action.startswith("api_key")]  # nothing written for team 2


def test_revoked_and_expired_keys_are_refused(api, world):
    engine, _ids, _db = world
    meta, key = make_key(api, ["cbom.read"], name="revoke-me")
    assert api("GET", "/1/cbom/sources/items", key=key).status_code == 200
    assert api("POST", f"/1/cbom/api-keys/{meta['id']}/revoke", "bob").status_code == 400  # members cannot
    assert api("POST", f"/1/cbom/api-keys/{meta['id']}/revoke", "carol").status_code == 403  # other team
    r = api("POST", f"/1/cbom/api-keys/{meta['id']}/revoke")
    assert r.status_code == 200 and r.json()["api_key"]["status"] == "revoked"
    assert api("POST", f"/1/cbom/api-keys/{meta['id']}/revoke").status_code == 200  # idempotent
    refused = api("GET", "/1/cbom/sources/items", key=key)
    assert refused.status_code == 401 and "revoked" in refused.json()["detail"]

    meta2, key2 = make_key(api, ["cbom.read"], name="short-lived", expires_in_days=1)
    assert api("GET", "/1/cbom/sources/items", key=key2).status_code == 200
    with Session(engine) as s:
        row = s.get(AK.CbomApiKey, meta2["id"])
        row.expires_at = AK.utcnow() - dt.timedelta(seconds=1)
        s.add(row)
        s.commit()
    refused = api("GET", "/1/cbom/sources/items", key=key2)
    assert refused.status_code == 401 and "expired" in refused.json()["detail"]
    statuses = {k["id"]: k["status"] for k in api("GET", "/1/cbom/api-keys").json()["api_keys"]}
    assert statuses == {meta["id"]: "revoked", meta2["id"]: "expired"}

    for bogus in ("zsk_" + "A" * 43, "zsk_", "zsk_" + "x" * 300, "zsk_not valid"):
        assert api("GET", "/1/cbom/sources/items", key=bogus).status_code == 401


def test_a_key_stops_working_when_its_creator_is_no_longer_a_team_admin(api, world):
    engine, ids, _db = world
    _m, key = make_key(api, ["cbom.read"])
    assert api("GET", "/1/cbom/sources/items", key=key).status_code == 200
    with Session(engine) as s:
        membership = s.exec(select(TeamMembership).where(TeamMembership.user_id == ids["alice"])).one()
        membership.role = "member"
        s.add(membership)
        s.commit()
    r = api("GET", "/1/cbom/sources/items", key=key)
    assert r.status_code == 403 and "no longer" in r.json()["detail"]


# ----------------------------------------------------------------------------- logging, audit, rate limit
def test_the_secret_is_never_logged_returned_again_or_audited(api, world, caplog, capsys):
    engine, _ids, db = world
    caplog.set_level(logging.DEBUG)
    meta, key = make_key(api, ["cbom.read"])
    api("GET", "/1/cbom/sources/items", key=key)
    api("POST", "/1/cbom/sources/items", key=key, json=linux_body())  # scope refusal
    api("GET", "/2/cbom/sources/items", key=key)  # team refusal
    api("GET", "/get_user", key=key)  # not a session
    api("POST", f"/1/cbom/api-keys/{meta['id']}/revoke")
    api("GET", "/1/cbom/sources/items", key=key)  # revoked
    out = capsys.readouterr()
    for text in (caplog.text, out.out, out.err):
        assert key not in text and key[4:] not in text and key[4:20] not in text
    rows = " ".join(str(e.model_dump()) for e in audit_rows(engine, 1))
    assert key not in rows and key[4:20] not in rows
    with Session(engine) as s:
        assert key not in str(s.get(AK.CbomApiKey, meta["id"]).model_dump())
    assert key[4:] not in api("GET", "/1/cbom/api-keys").text
    engine.dispose()
    assert key.encode() not in db.read_bytes()


def test_every_use_is_audited_as_the_key_and_updates_last_used(api, world):
    engine, _ids, _db = world
    node_id, _t = enroll_node(api)
    meta, key = make_key(api, ["cbom.sources:write"])
    assert api("GET", "/1/cbom/sources/items", key=key).status_code == 200
    created = api("POST", "/1/cbom/sources/items", key=key, json=linux_body(node_id=node_id))
    assert created.status_code == 201
    assert api("POST", "/1/cbom/sources/runs", key=key, json={"include": {"servers": True},
                                                            "client_request_id": "audit-run-001"}).status_code == 403
    events = audit_rows(engine, 1)
    uses = [e for e in events if e.action == "api_key.use"]
    assert [e.changed_fields for e in uses] == [["GET /{team_id}/cbom/sources/items"],
                                                ["POST /{team_id}/cbom/sources/items"]]
    assert all(e.actor_type == "api_key" and e.actor_id == meta["id"] and e.object_id == meta["id"] for e in uses)
    refused = [e for e in events if e.action == "api_key.refused"]
    assert len(refused) == 1 and "scope" in refused[0].changed_fields
    # the change itself is marked as a machine call in the CBOM audit log
    create = [e for e in events if e.action == "source.create"]
    assert create and create[-1].actor_type == "api_key" and create[-1].actor_id == meta["id"]
    created_by_admin = [e for e in events if e.action == "api_key.create"]
    assert created_by_admin and created_by_admin[0].actor_type == "user"
    listed = {k["id"]: k for k in api("GET", "/1/cbom/api-keys").json()["api_keys"]}
    assert listed[meta["id"]]["last_used_at"] is not None


def test_every_use_is_rate_limited_per_key(api, world, monkeypatch):
    monkeypatch.setattr(cbom_http.read_limiter, "times", 3)
    _m, key = make_key(api, ["cbom.read"], name="busy")
    _m, other = make_key(api, ["cbom.read"], name="quiet")
    codes = [api("GET", "/1/cbom/sources/items", key=key).status_code for _ in range(4)]
    assert codes == [200, 200, 200, 429]
    assert api("GET", "/1/cbom/sources/runs", key=other).status_code == 200  # its own budget
    assert api("GET", "/1/cbom/sources/items").status_code == 200  # the signed-in admin's own budget too


# ----------------------------------------------------------------------------- the onboarding, scripted
def test_a_full_scripted_onboarding_with_a_key_only(api, world):
    """What a CMDB sync job does: the admin enrolled a scan node once in the UI and created one key; the job then
    adds a source, prices and starts a run, follows it and downloads the CBOM, with nothing but the key."""
    engine, _ids, _db = world
    node_id, node_token = enroll_node(api)
    _meta, key = make_key(api, ["cbom.sources:write", "cbom.runs:write"], name="cmdb-nightly", expires_in_days=365)

    nodes = api("GET", "/1/cbom/sources/nodes", key=key)
    assert nodes.status_code == 200 and node_id in [n["id"] for n in nodes.json()["nodes"]]
    src = api("POST", "/1/cbom/sources/items", key=key, json=linux_body(name="cmdb-linux", node_id=node_id))
    assert src.status_code == 201, src.text
    source_id = src.json()["source"]["id"]
    assert "secrets_set" in src.json()["source"] and PASSWORD not in src.text
    est = api("POST", "/1/cbom/sources/estimate", key=key, json={"include": {"servers": True}})
    assert est.status_code == 200, est.text
    run = api("POST", "/1/cbom/sources/runs", key=key,
              json={"include": {"servers": True}, "source_ids": [source_id], "client_request_id": "cmdb-2026-11-14",
                    "expected_credits": est.json()["total_credits"]})
    assert run.status_code == 201, run.text
    run_id = run.json()["run"]["id"]
    replay = api("POST", "/1/cbom/sources/runs", key=key,
                 json={"include": {"servers": True}, "source_ids": [source_id], "client_request_id": "cmdb-2026-11-14",
                       "expected_credits": est.json()["total_credits"]})
    assert replay.status_code == 200 and replay.json()["replayed"] is True  # a retried job starts nothing twice
    claim = api("POST", "/cbom/node/jobs/claim", None, headers={"X-ZS-Node-Token": node_token})
    assert claim.status_code == 200, claim.text
    status = api("GET", f"/1/cbom/sources/runs/{run_id}", key=key)
    assert status.status_code == 200 and status.json()["run"]["id"] == run_id
    assert api("GET", "/1/cbom/sources/runs", key=key).status_code == 200
    export = api("GET", f"/1/cbom/sources/runs/{run_id}/cbom", key=key)
    assert export.status_code == 200 and export.json()["bomFormat"] == "CycloneDX"
    with Session(engine) as s:
        from backend.new_models import CbomCollectionRun
        assert s.get(CbomCollectionRun, run_id).owner_user_id == _ids["alice"]  # the key acts as its creator


def test_the_guide_curl_example_calls_only_routes_a_key_may_call():
    text = GUIDE.read_text()
    assert "zsk_" in text and "Authorization: Bearer" in text
    calls = re.findall(r"-X (GET|POST|PATCH|DELETE)[^\n]*\$API(/[^\"' ]+)", text)
    assert len(calls) >= 4, calls
    allowed = set(AK.ROUTE_SCOPES)
    for method, url in calls:
        template = re.sub(r"^/\$TEAM", "/{team_id}", url)
        template = re.sub(r"/\$[A-Z_]+", lambda m: {"/$NODE": "/{node_id}", "/$SOURCE": "/{source_id}",
                                                     "/$RUN": "/{run_id}"}[m.group(0)], template)
        template = template.split("?")[0]
        assert (method, template) in allowed, (method, template)
    assert any(m == "POST" and u.endswith("/cbom/sources/items") for m, u in calls)
    assert any(m == "POST" and u.endswith("/cbom/sources/runs") for m, u in calls)


# ----------------------------------------------------------------------------- migration
def test_the_migration_is_the_one_head_and_round_trips(tmp_path):
    import importlib.util

    import sqlalchemy as sa
    from alembic.migration import MigrationContext
    from alembic.operations import Operations

    versions = _REPO_ROOT / "prod_database_migrations" / "migrations" / "versions"
    revisions, parents = set(), set()
    for path in versions.glob("*.py"):
        text = path.read_text()
        rev = re.search(r"^revision(?::\s*str)?\s*=\s*['\"]([^'\"]+)['\"]", text, re.M)
        down = re.search(r"^down_revision[^=]*=\s*(.+)$", text, re.M)
        if rev:
            revisions.add(rev.group(1))
        if down:
            parents.update(re.findall(r"""['"]([^'"]+)['"]""", down.group(1)))
    assert len(revisions - parents) == 1 and ("cb226apikey001" in parents or revisions - parents == {"cb226apikey001"})
    spec = importlib.util.spec_from_file_location("m226", versions / "cb226apikey001_cbom_api_keys.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    assert mod.down_revision in revisions
    engine = sa.create_engine(f"sqlite:///{tmp_path / 'm.db'}")

    def run(step):
        with engine.begin() as conn:
            with Operations.context(MigrationContext.configure(conn)):
                getattr(mod, step)()

    with engine.begin() as conn:
        conn.execute(sa.text("CREATE TABLE team (id integer PRIMARY KEY)"))
        conn.execute(sa.text("INSERT INTO team (id) VALUES (1)"))
    run("upgrade")
    ins = sa.text("INSERT INTO cbomapikey (team_id, name, scopes, key_hash, hint, created_by_user_id) "
                  "VALUES (1, 'k', '[\"cbom.read\"]', :h, 'abcd', 7)")
    with engine.begin() as conn:
        conn.execute(ins, {"h": "a" * 64})
        with pytest.raises(sa.exc.IntegrityError):  # one row per hash
            with conn.begin_nested():
                conn.execute(ins, {"h": "a" * 64})
    model_cols = set(AK.CbomApiKey.__table__.columns.keys())
    assert {c["name"] for c in sa.inspect(engine).get_columns("cbomapikey")} == model_cols
    run("downgrade")
    assert "cbomapikey" not in sa.inspect(engine).get_table_names()
    run("upgrade")
    assert {"ix_cbomapikey_team_created", "ix_cbomapikey_team_id"} <= {
        i["name"] for i in sa.inspect(engine).get_indexes("cbomapikey")}
    engine.dispose()
