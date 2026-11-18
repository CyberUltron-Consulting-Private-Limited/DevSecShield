"""#433: a missing, malformed or forged credential is refused BEFORE ``get_db()``.

When the database settings are missing (``get_db()`` raises ``KeyError`` for ``PG_USER``) or the database is down,
an anonymous or malformed request used to get 403 or 500, because the route asked for the engine before it looked
at the credential.  It now gets the answer a healthy server gives (401; 403 for a refresh token, as ``/refresh``
always answered) and ``get_db()`` is never called for it.  A valid credential works as before.  ``get_db()`` names a
missing setting (never a value) instead of claiming that a connection failed.

SQLite, real JWTs, the real ``backend.main`` app (the shared CBOM Sources fixtures of ``test_cbom_sources_api.py``).
"""
from __future__ import annotations

import datetime as dt
import importlib
import logging
import os
import sys
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))
os.environ.setdefault("JWT_SECRET_KEY", "cbom-sources-test-secret")
os.environ.setdefault("JWT_REFRESH_SECRET_KEY", "cbom-sources-test-refresh")

from fastapi.testclient import TestClient  # noqa: E402
from jose import jwt  # noqa: E402

from test_cbom_sources_api import USERS, api, enroll_node, world  # noqa: E402
from backend.main import app  # noqa: E402
from backend.routers import auth as auth_router  # noqa: E402
from backend.routers import cbom_node, cbom_node_sshca  # noqa: E402
from backend.utilities.auth import auth_utils  # noqa: E402
from backend.utilities.cbom_sources import http as cbom_http  # noqa: E402
from backend.utilities.cbom_sources import node_auth  # noqa: E402

DB = importlib.import_module("backend.get_db")
FIXTURES = (api, world)  # the shared CBOM Sources fixtures (SQLite world, real JWTs), used by name below

ALICE = USERS["alice"][0]
_FAR = dt.datetime(2100, 1, 1, tzinfo=dt.timezone.utc)
FORGED_ACCESS = jwt.encode({"sub": ALICE, "exp": _FAR, "typ": "access", "ver": 0}, "not-the-secret", "HS256")
FORGED_REFRESH = jwt.encode({"sub": ALICE, "exp": _FAR, "typ": "refresh", "ver": 0}, "not-the-secret", "HS256")
EXPIRED_ACCESS = auth_utils.create_access_token(ALICE, expires_delta=dt.timedelta(seconds=-5))
EXPIRED_REFRESH = auth_utils.create_refresh_token(ALICE, expires_delta=dt.timedelta(seconds=-5))

# The modules these routes reach get_db() through: the auth and scan-node routers, the CBOM limiter keys, and the node
# middleware's deployment-id lookup (which catches the error by design and answers without X-ZS-Deployment).
DB_MODULES = (auth_router, cbom_node, cbom_node_sshca, cbom_http, node_auth)


def no_database(monkeypatch) -> list[str]:
    """From here on get_db() raises what it raises when PG_USER is not set, in every module above; returns the list
    of the modules that called it."""
    calls: list[str] = []
    for module in DB_MODULES:
        def missing(name: str = module.__name__):
            calls.append(name)
            raise KeyError("PG_USER")
        monkeypatch.setattr(module, "get_db", missing)
    return calls


def _twice(monkeypatch, send):
    """The answer of a healthy server (the SQLite world), then the answer once get_db() raises."""
    healthy = send()
    calls = no_database(monkeypatch)
    return healthy, send(), calls


# ----------------------------------------------------------------------------- session (JWT) routes
BAD_HEADERS = {
    "no-header": None,
    "wrong-scheme": "Token abc",
    "no-token": "Bearer",
    "three-parts": "Bearer a b",
    "not-a-jwt": "Bearer not-a-jwt",
    "forged-signature": f"Bearer {FORGED_ACCESS}",
    "expired": f"Bearer {EXPIRED_ACCESS}",
    "refresh-token": f"Bearer {auth_utils.create_refresh_token(ALICE)}",
}
SESSION_ROUTES = {
    "get_user": ("GET", "/get_user", None),
    "version": ("GET", "/version", None),
    "account-password": ("POST", "/account/password",
                         {"current_password": "Old-Pa55word-1", "new_password": "New-Pa55word-22"}),
    "logout": ("GET", "/logout", None),
}


@pytest.mark.parametrize("route", SESSION_ROUTES.values(), ids=list(SESSION_ROUTES))
@pytest.mark.parametrize("header", BAD_HEADERS.values(), ids=list(BAD_HEADERS))
def test_a_bad_session_credential_is_a_401_without_get_db(world, monkeypatch, route, header):
    method, url, body = route
    client = TestClient(app)
    headers = {} if header is None else {"Authorization": header}
    healthy, broken, calls = _twice(monkeypatch, lambda: client.request(method, url, headers=headers, json=body))
    assert healthy.status_code == 401, healthy.text
    assert (broken.status_code, broken.json()) == (401, healthy.json())  # the same answer, detail included
    assert calls == []  # refused without asking for the engine


BAD_REFRESH = {
    "not-a-jwt": "not-a-jwt",
    "forged-signature": FORGED_REFRESH,
    "expired": EXPIRED_REFRESH,
    "access-token": auth_utils.create_access_token(ALICE),
}


@pytest.mark.parametrize("token", BAD_REFRESH.values(), ids=list(BAD_REFRESH))
def test_a_bad_refresh_token_gets_the_healthy_answer_without_get_db(world, monkeypatch, token):
    client = TestClient(app)
    healthy, broken, calls = _twice(monkeypatch, lambda: client.post("/refresh", json={"refresh_token": token}))
    assert (healthy.status_code, healthy.json()) == (403, {"detail": "Could not validate credentials"})
    assert (broken.status_code, broken.json()) == (403, healthy.json())
    assert calls == []


# ----------------------------------------------------------------------------- scan-node routes
NODE_ROUTES = ["/cbom/node/heartbeat", "/cbom/node/jobs/claim", "/cbom/node/jobs/1/assets",
               "/cbom/node/jobs/1/result", "/cbom/node/jobs/1/ssh-cert", "/cbom/node/jobs/1/ssh-cert/report"]
BAD_NODE_TOKENS = {"no-token": None, "not-zsn": "not-a-node-token", "with-scheme": "Bearer zsn_abc",
                   "too-long": "zsn_" + "a" * 125}


@pytest.mark.parametrize("url", NODE_ROUTES)
@pytest.mark.parametrize("token", BAD_NODE_TOKENS.values(), ids=list(BAD_NODE_TOKENS))
def test_a_missing_or_malformed_node_token_is_a_401_without_get_db(world, monkeypatch, url, token):
    monkeypatch.setenv("CBOM_SSH_CA", "1")  # the node certificate routes exist only while the flag is on
    client = TestClient(app)
    headers = {} if token is None else {"X-ZS-Node-Token": token}
    healthy, broken, calls = _twice(monkeypatch, lambda: client.post(url, headers=headers, content=b"{}"))
    assert healthy.status_code == 401, healthy.text
    for answer in (healthy, broken):  # "missing", never "revoked": the node keeps its token
        assert answer.headers[node_auth.REFUSED_HEADER] == "node_token_missing"
    assert (broken.status_code, broken.json()) == (401, healthy.json())
    # only the middleware asked, for the deployment id; it answered without it (the request did not fail)
    assert set(calls) <= {node_auth.__name__}
    assert node_auth.DEPLOYMENT_HEADER in healthy.headers and node_auth.DEPLOYMENT_HEADER not in broken.headers


# ----------------------------------------------------------------------------- valid credentials: as before
def test_a_valid_credential_still_works(api):
    me = api("GET", "/get_user")
    assert me.status_code == 200 and me.json()["email"] == ALICE
    assert api("GET", "/version").status_code == 200
    refreshed = TestClient(app).post("/refresh", json={"refresh_token": auth_utils.create_refresh_token(ALICE)})
    assert refreshed.status_code == 200 and refreshed.json()["access_token"]
    _node_id, token, _reg = enroll_node(api)
    beat = api("POST", "/cbom/node/heartbeat", None, headers={"X-ZS-Node-Token": token}, json={"version": "1.1"})
    assert beat.status_code == 200, beat.text
    assert api("POST", "/cbom/node/heartbeat", None, headers={"X-ZS-Node-Token": "zsn_wrong"},
               json={}).headers[node_auth.REFUSED_HEADER] == "node_token_revoked"  # well formed, no such node
    assert api("GET", "/logout").status_code == 200
    assert api("GET", "/get_user").status_code == 401  # logout revoked the token


# ----------------------------------------------------------------------------- get_db() log line
def _db_messages(caplog) -> list[str]:
    return [r.getMessage() for r in caplog.records if r.name == "backend.db"]


def test_a_missing_database_setting_is_logged_by_name_and_no_connection_is_claimed(monkeypatch, caplog):
    monkeypatch.setattr(DB, "_pg_engine", None)
    monkeypatch.setenv("PG_USER", "canary-user-5e1f")
    monkeypatch.setenv("PG_USER_PASS", "canary-pass-9c8b")
    monkeypatch.delenv("PG_DB", raising=False)
    with caplog.at_level(logging.ERROR, logger="backend.db"), pytest.raises(KeyError):
        DB.get_db()
    assert DB._pg_engine is None
    assert _db_messages(caplog) == ["Error getting database: KeyError (PG_DB not set)"]
    assert "canary" not in caplog.text and "connection" not in caplog.text
    assert f"{DB.PG_HOST}:{DB.PG_PORT}" not in caplog.text


def test_every_missing_database_setting_is_named(monkeypatch, caplog):
    monkeypatch.setattr(DB, "_pg_engine", None)
    for name in ("PG_USER", "PG_USER_PASS", "PG_DB"):
        monkeypatch.delenv(name, raising=False)
    with caplog.at_level(logging.ERROR, logger="backend.db"), pytest.raises(KeyError):
        DB.get_db()
    assert _db_messages(caplog) == ["Error getting database: KeyError (PG_USER, PG_USER_PASS, PG_DB not set)"]


def test_an_engine_error_is_logged_by_its_class_only(monkeypatch, caplog):
    monkeypatch.setattr(DB, "_pg_engine", None)
    for name in ("PG_USER", "PG_USER_PASS", "PG_DB"):
        monkeypatch.setenv(name, f"canary-{name.lower()}")

    def broken(url, **_kwargs):
        raise ValueError(f"cannot use {url}")  # the URL carries the password: it must not reach the log

    monkeypatch.setattr(DB, "create_engine", broken)
    with caplog.at_level(logging.ERROR, logger="backend.db"), pytest.raises(ValueError):
        DB.get_db()
    assert _db_messages(caplog) == ["Error getting database: ValueError"]
    assert "canary" not in caplog.text and "connection" not in caplog.text
