"""The in-process rate limiter, its keys, the routes that use it, and the policy around them.

Run (no .env is read):

    cd backend && PYTHON_DOTENV_DISABLED=1 PYTHONPATH=.. JWT_SECRET_KEY=t JWT_REFRESH_SECRET_KEY=r \
      AWS_ACCESS_KEY_ID=x AWS_SECRET_ACCESS_KEY=y AWS_DEFAULT_REGION=us-east-1 \
      python -m pytest tests/test_ratelimit.py -q -p no:cacheprovider
"""
import ast
import asyncio
import datetime as dt
import logging
import os
import re
import sys
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))
os.environ.setdefault("JWT_SECRET_KEY", "ratelimit-test-access-secret")
os.environ.setdefault("JWT_REFRESH_SECRET_KEY", "ratelimit-test-refresh-secret")

from fastapi import HTTPException  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from jose import jwt as jose_jwt  # noqa: E402
from sqlmodel import Session, SQLModel, create_engine  # noqa: E402
from starlette.requests import Request  # noqa: E402

from backend.main import app  # noqa: E402
from backend.new_models import CbomScanNode, CicdIntegration, Team, User  # noqa: E402
from backend.routers import auth as auth_router  # noqa: E402
from backend.utilities import ratelimit  # noqa: E402
from backend.utilities.auth import auth_utils  # noqa: E402
from backend.utilities.cbom_sources import http as cbom_http  # noqa: E402
from backend.utilities.cicd import auth as cicd_auth  # noqa: E402

ROUTERS = _REPO_ROOT / "backend" / "routers"


def request(headers: dict[str, str] | None = None, client: str = "198.51.100.7", path: str = "/x") -> Request:
    raw = [(k.lower().encode(), v.encode()) for k, v in (headers or {}).items()]
    return Request({"type": "http", "method": "GET", "path": path, "headers": raw, "query_string": b"",
                    "client": (client, 50000)})


class Clock:
    def __init__(self, now: float) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


def run(coro):
    return asyncio.run(coro)


# ------------------------------------------------------------------------------------------- addresses


@pytest.mark.parametrize("host, key", [
    ("203.0.113.5", "203.0.113.5"),
    ("::ffff:203.0.113.5", "203.0.113.5"),
    ("2001:db8:1:2:aaaa::1", "2001:db8:1:2::/64"),
    ("2001:db8:1:2:ffff:ffff:ffff:ffff", "2001:db8:1:2::/64"),
    ("fe80::1%eth0", "fe80::/64"),
    ("testclient", "unknown"),
    ("", "unknown"),
    (None, "unknown"),
])
def test_client_addresses_are_normalised(host, key):
    assert ratelimit.normalise_ip(host) == key


def test_x_forwarded_for_is_never_read_by_app_code():
    """uvicorn applies X-Forwarded-For (only from FORWARDED_ALLOW_IPS) before the app sees the request."""
    spoofed = request({"X-Forwarded-For": "10.9.9.9"}, client="198.51.100.7")
    assert ratelimit.client_ip(spoofed) == "198.51.100.7"
    assert cbom_http.client_ip(spoofed) == "198.51.100.7"
    assert run(ratelimit.ip_key(spoofed)) == ("ip", "198.51.100.7")
    header_literal = re.compile(r"[\"']x-forwarded-for[\"']", re.I)  # a quoted header name = code reading it
    for path in (_REPO_ROOT / "backend").rglob("*.py"):
        if ".venv" in path.parts or "tests" in path.parts:
            continue
        assert not header_literal.search(path.read_text(encoding="utf-8", errors="replace")), path


# ------------------------------------------------------------------------------------------------ keys


def test_a_verified_token_is_charged_to_its_subject_anything_else_to_the_address():
    token = auth_utils.create_access_token("kim@example.test")
    assert run(ratelimit.user_key(request({"Authorization": f"Bearer {token}"}))) == ("user", "kim@example.test")
    assert run(ratelimit.user_key(request({"Authorization": f"bearer {token}"}))) == ("user", "kim@example.test")
    exp = dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=5)
    forged = jose_jwt.encode({"sub": "kim@example.test", "exp": exp}, "attacker-secret", "HS256")
    expired = auth_utils.create_access_token("kim@example.test", expires_delta=dt.timedelta(seconds=-5))
    refresh = auth_utils.create_refresh_token("kim@example.test")
    for header in (f"Bearer {forged}", f"Bearer {expired}", f"Bearer {refresh}", "Bearer garbage", "Basic x", ""):
        assert run(ratelimit.user_key(request({"Authorization": header}))) == ("ip", "198.51.100.7"), header


def test_forged_tokens_never_open_buckets_of_their_own(monkeypatch):
    limiter = ratelimit.RateLimiter("test.forged", times=3, seconds=60)
    monkeypatch.setattr(limiter, "clock", Clock(1_000_000.0))
    exp = dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=5)
    codes = []
    for i in range(10):
        forged = jose_jwt.encode({"sub": f"user{i}@example.test", "exp": exp}, f"guess-{i}", "HS256")
        try:
            run(limiter(request({"Authorization": f"Bearer {forged}"})))
            codes.append(200)
        except HTTPException as exc:
            codes.append(exc.status_code)
    assert codes == [200] * 3 + [429] * 7
    assert list(limiter.requests) == ["ip:198.51.100.7"]


@pytest.fixture()
def db(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite:///{tmp_path / 'rl.db'}", connect_args={"check_same_thread": False})
    SQLModel.metadata.create_all(engine)
    with Session(engine) as s:
        s.add(Team(id=1, name="T"))
        s.add(User(id=1, email="o@example.test", password="x", first_name="o", last_name="o", profile_photo=None,
                   default_team_id=1))
        s.commit()
        s.add(CicdIntegration(id=7, team_id=1, owner_user_id=1, api_key=cicd_auth.hash_api_key("cicd1-good-key"),
                              scan_type="dast", title="ci"))
        s.add(CbomScanNode(id=9, team_id=1, owner_user_id=1, name="n", node_token_hash=cbom_http.sha256_hex("zsn_good")))
        s.commit()
    monkeypatch.setattr(cicd_auth, "get_db", lambda: engine)
    monkeypatch.setattr(cbom_http, "get_db", lambda: engine)
    return engine


def test_ci_routes_are_charged_to_the_verified_integration(db):
    assert run(cicd_auth.ci_key(request({"cicd-api-key": " cicd1-good-key "}))) == ("ci", "7")
    for header in ({"cicd-api-key": "cicd1-guess"}, {"cicd-api-key": "x" * 600}, {}):
        assert run(cicd_auth.ci_key(request(header))) == ("ip", "198.51.100.7")


def test_scan_nodes_are_charged_to_the_verified_node(db):
    assert run(cbom_http.node_key(request({"X-ZS-Node-Token": "zsn_good"}))) == ("node", "9")
    for header in ({"X-ZS-Node-Token": "zsn_guess"}, {"X-ZS-Node-Token": "nope"}, {}):
        assert run(cbom_http.node_key(request(header))) == ("ip", "198.51.100.7")


# ------------------------------------------------------------------------------------------- the window


def test_429_with_retry_after_until_the_window_ends(monkeypatch):
    limiter = ratelimit.RateLimiter("test.window", times=2, seconds=60, key_func=ratelimit.ip_key)
    clock = Clock(6_000_000.0 + 15.2)  # 15.2 s into a window
    monkeypatch.setattr(limiter, "clock", clock)
    run(limiter(request()))
    run(limiter(request()))
    with pytest.raises(HTTPException) as refused:
        run(limiter(request()))
    assert refused.value.status_code == 429
    assert refused.value.detail == "Too Many Requests"
    assert refused.value.headers == {"Retry-After": "45"}
    run(limiter(request(client="198.51.100.8")))  # another address has its own budget
    clock.now += 44.7  # 59.9 s into the window
    with pytest.raises(HTTPException):
        run(limiter(request()))
    clock.now += 0.2  # next window
    run(limiter(request()))


def test_the_sweep_drops_every_stale_count_and_the_table_is_capped(monkeypatch, caplog):
    limiter = ratelimit.RateLimiter("test.cap", times=1, seconds=10, key_func=ratelimit.ip_key, max_keys=3)
    clock = Clock(7_000_000.0)
    monkeypatch.setattr(limiter, "clock", clock)
    with caplog.at_level(logging.WARNING, logger="backend.ratelimit"):
        for i in range(6):
            run(limiter(request(client=f"192.0.2.{i}")))  # keys 4..6 are let through untracked
        assert len(limiter.requests) == 3
        run(limiter(request(client="192.0.2.5")))  # untracked, so never refused in this window
    assert [r.getMessage() for r in caplog.records].count(
        "rate_limit_table_full limiter=test.cap max_keys=3") == 1, "logged once per window"
    clock.now += 10
    run(limiter(request(client="192.0.2.9")))
    assert list(limiter.requests) == ["ip:192.0.2.9"], "a new window starts from an empty table"


def test_a_refusal_is_logged_once_per_key_per_window_without_the_token(monkeypatch, caplog):
    limiter = ratelimit.RateLimiter("test.log", times=1, seconds=60)
    monkeypatch.setattr(limiter, "clock", Clock(8_000_000.0))
    token = auth_utils.create_access_token("quiet@example.test")
    with caplog.at_level(logging.WARNING, logger="backend.ratelimit"):
        for _ in range(5):
            try:
                run(limiter(request({"Authorization": f"Bearer {token}"}, path="/7/sast/scans")))
            except HTTPException:
                pass
    lines = [r.getMessage() for r in caplog.records if r.getMessage().startswith("rate_limited")]
    assert len(lines) == 1
    assert "limiter=test.log" in lines[0] and "key_kind=user" in lines[0] and "route=/7/sast/scans" in lines[0]
    assert token not in caplog.text and "quiet@example.test" not in caplog.text


# --------------------------------------------------------------------------------------- through the app


def test_the_21st_get_user_in_a_window_is_429_with_retry_after(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite:///{tmp_path / 'app.db'}", connect_args={"check_same_thread": False})
    SQLModel.metadata.create_all(engine)
    with Session(engine) as s:
        s.add(User(email="busy@example.test", password="x", first_name="b", last_name="u", profile_photo=None,
                   session_active=True))
        s.commit()
    monkeypatch.setattr(auth_router, "get_db", lambda: engine)
    monkeypatch.setattr(auth_router.session_limiter, "clock", Clock(9_000_000.0 + 3))
    client = TestClient(app)
    headers = {"Authorization": f"Bearer {auth_utils.create_access_token('busy@example.test')}"}
    statuses = [client.get("/get_user", headers=headers).status_code for _ in range(21)]
    assert statuses == [200] * 20 + [429]
    refused = client.get("/get_user", headers=headers)
    assert refused.status_code == 429 and refused.headers["retry-after"] == "27"
    other = {"Authorization": f"Bearer {auth_utils.create_access_token('someone@example.test')}"}
    assert client.get("/get_user", headers=other).status_code == 401, "another user still has a budget"


# ------------------------------------------------------------------------------------------------- policy


def _route_functions(tree: ast.AST):
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            calls = [d for d in node.decorator_list if isinstance(d, ast.Call) and isinstance(d.func, ast.Attribute)
                     and isinstance(d.func.value, ast.Name) and d.func.value.id == "router"]
            if calls:
                yield node, calls[0]


def test_every_route_has_its_limiter_in_the_decorator():
    """``dependencies=[Depends(limiter)]`` as a PARAMETER is a query parameter and limits nothing; the 48
    routes that had it were never rate limited."""
    problems, routes = [], 0
    for path in sorted(ROUTERS.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        limiters = {t.id for n in ast.walk(tree) if isinstance(n, ast.Assign) and isinstance(n.value, ast.Call)
                    and getattr(n.value.func, "id", None) == "RateLimiter" for t in n.targets if isinstance(t, ast.Name)}
        imported = {a.asname or a.name for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) for a in n.names
                    if a.name.endswith("_limiter") or a.name == "limiter"}
        # module-level dependency lists, e.g. READ = [Depends(read_limiter)] used as dependencies=READ
        lists = {t.id: n.value for n in tree.body if isinstance(n, ast.Assign) and isinstance(n.value, ast.List)
                 for t in n.targets if isinstance(t, ast.Name)}
        for node, decorator in _route_functions(tree):
            routes += 1
            params = {a.arg for a in node.args.args + node.args.kwonlyargs}
            if "dependencies" in params:
                problems.append(f"{path.name}:{node.name} takes a `dependencies` parameter")
            deps = [k.value for k in decorator.keywords if k.arg == "dependencies"]
            deps = [lists.get(d.id, d) if isinstance(d, ast.Name) else d for d in deps]
            names ={getattr(c.args[0], "id", None) for d in deps if isinstance(d, ast.List) for c in d.elts
                     if isinstance(c, ast.Call) and getattr(c.func, "id", None) == "Depends" and c.args}
            if not names & (limiters | imported):
                problems.append(f"{path.name}:{node.name} has no rate limiter in its decorator")
        if re.search(r"^\s*(from|import) fastapi_throttle", path.read_text(encoding="utf-8"), re.M):
            problems.append(f"{path.name} imports fastapi_throttle (per-IP behind the proxy, no sweep)")
    assert routes >= 100
    assert problems == []


def test_every_registered_api_route_is_limited_at_runtime():
    from fastapi.routing import APIRoute

    unlimited = [r.path for r in app.routes if isinstance(r, APIRoute) and r.path != "/health"
                 and not any(isinstance(d.dependency, ratelimit.RateLimiter) for d in r.dependencies)]
    assert unlimited == []


# A line that assigns a value (compose `KEY: "1"` / `KEY=1`, `ENV KEY 1`, `-e KEY=1`), not a comment or a guard that
# merely names the variable (deploy/staging/docker-compose.yml warns against it; scripts/deploy/staging.sh refuses it).
_SETS_DEV_MODE = re.compile(r"^(?![ \t]*#)[^\n#]*\bDSS_DEV_MODE\b[ \t]*(?:[:=]|[ \t]+(?=\S))[ \t]*[\"']?\w", re.M)


def test_dss_dev_mode_is_only_ever_set_by_the_e2e_harness():
    """The fixed sign-in code must never be switched on by a deployment file."""
    offenders = []
    for path in _REPO_ROOT.rglob("*"):
        parts = set(path.parts)
        if not path.is_file() or parts & {".git", "node_modules", ".venv", "e2e", ".claude", "graphify-out"}:
            continue
        name = path.name.lower()
        if name.startswith(".env") or name.endswith(".pem"):
            continue  # never opened
        deploy_file = (name.endswith((".yml", ".yaml")) and ("compose" in name or "compose" in parts)) \
            or name.startswith("dockerfile") or name.endswith(".sh") or name in {"gunicorn.conf.py"}
        if deploy_file and _SETS_DEV_MODE.search(path.read_text(encoding="utf-8", errors="replace")):
            offenders.append(str(path.relative_to(_REPO_ROOT)))
    assert offenders == []
