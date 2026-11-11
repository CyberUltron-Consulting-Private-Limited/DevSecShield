"""F1.2-a0 scaffold of the CBOM fleet routes (contract $R6/f1/CONTRACT.md, sections 3, 5 and 6).

* ``GET /{team_id}/cbom/sources/fleet/status`` answers members of the team with the four product flags, read from the
  environment on every call (default: all off), so the frontend can hide the Fleet tab and its sections;
* a fleet route behind a flag that is off answers exactly like a route that does not exist (404 ``Not Found``), before
  authentication and before the body is read;
* every route of the aggregator (checked with every flag on) is a ``CbomRoute`` behind a flag, rate limited, declares
  its permission for F4's route-coverage test, and authenticates through the ``ctx: Member`` dependency after the
  limiter: anonymous -> 401, another team's member -> 403 (security review 5858172203).  A negative control proves the
  guard reports each mistake;
* the aggregator keeps the import and router markers F1.3 and F1.4 insert under.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest
from fastapi import APIRouter, Depends, FastAPI, Header
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

from test_cbom_sources_api import api, world
from backend.main import app
from backend.routers import cbom_fleet
from backend.utilities.cbom_sources import http as cbom_http
from backend.utilities.cbom_sources.fleet import flags as FLAGS
from backend.utilities.cbom_sources.fleet import http as fleet_http
from backend.utilities.cbom_sources.fleet.http import FLEET, Member, permission, require_member
from backend.utilities.cbom_sources.http import CbomRoute, TeamId, read_limiter
from backend.utilities.ratelimit import RateLimiter

FLAG_ENV = ("CBOM_FLEET_INVENTORY", "CBOM_FLEET_POLICIES", "CBOM_FLEET_MATERIALIZE", "CBOM_FLEET_TRANSPORTS",
            "CBOM_SSH_CA")
STATUS = "/1/cbom/sources/fleet/status"
FIXTURES = (api, world)  # the shared CBOM Sources fixtures (SQLite world, real JWTs), used by name below


@pytest.fixture(autouse=True)
def _flags_off(monkeypatch):
    for name in FLAG_ENV:
        monkeypatch.delenv(name, raising=False)


def test_status_is_all_off_by_default(api):
    r = api("GET", STATUS)
    assert r.status_code == 200, r.text
    assert r.json() == {"inventory": False, "policies": False, "transports": False, "ssh_ca": False}
    assert r.headers["cache-control"] == "no-store"


@pytest.mark.parametrize("env,key", [("CBOM_FLEET_INVENTORY", "inventory"), ("CBOM_FLEET_POLICIES", "policies"),
                                     ("CBOM_FLEET_TRANSPORTS", "transports"), ("CBOM_SSH_CA", "ssh_ca")])
def test_status_reads_each_flag_on_every_call(api, monkeypatch, env, key):
    monkeypatch.setenv(env, "1")
    body = api("GET", STATUS).json()
    assert body[key] is True and sum(body.values()) == 1
    monkeypatch.setenv(env, "0")
    assert api("GET", STATUS).json()[key] is False


@pytest.mark.parametrize("value,on", [("1", True), ("true", True), ("TRUE", True), ("yes", True), ("on", True),
                                      ("0", False), ("", False), ("false", False), ("no", False), ("2", False),
                                      (" 1 ", True)])
def test_flag_values(monkeypatch, value, on):
    monkeypatch.setenv("CBOM_FLEET_INVENTORY", value)
    assert FLAGS.inventory_enabled() is on


def test_status_needs_a_member_of_the_team(api):
    assert api("GET", STATUS, None).status_code == 401
    assert api("GET", STATUS, "carol").status_code == 403  # carol is in team 2: the existing non-member answer
    assert api("GET", STATUS, "bob").status_code == 200  # any member may read it


def _guarded_app() -> FastAPI:
    """A router behind the inventory flag, included twice deep (like the aggregator inside main.app)."""
    probe = APIRouter(route_class=FLAGS.route_class("inventory"))

    @probe.post("/probe")
    async def handler(body: dict, x_need: str = Header()):  # needs a header: an auth-like check
        return {"ok": True, "body": body}

    middle = APIRouter()
    middle.include_router(probe)
    test_app = FastAPI()
    test_app.include_router(middle)
    return test_app


def test_a_route_behind_an_off_flag_does_not_exist(monkeypatch):
    client = TestClient(_guarded_app())
    missing = client.post("/no-such-route", json={})
    off_bad_body = client.post("/probe", content=b"not json", headers={"content-type": "application/json"})
    off_no_header = client.post("/probe", json={"a": 1})
    off_wrong_method = client.get("/probe")
    for off in (off_bad_body, off_no_header, off_wrong_method):  # not 400/422 (body, header) and not 405 (method)
        assert off.status_code == 404 and off.json() == missing.json() == {"detail": "Not Found"}
    monkeypatch.setenv("CBOM_FLEET_INVENTORY", "1")
    on = client.post("/probe", json={"a": 1}, headers={"x-need": "y"})
    assert on.status_code == 200 and on.json() == {"ok": True, "body": {"a": 1}}
    assert client.post("/probe", content=b"not json", headers={"content-type": "application/json",
                                                                "x-need": "y"}).status_code == 400  # CbomRoute
    assert client.get("/probe").status_code == 405


def test_another_parts_flag_can_guard_its_own_routes(monkeypatch):
    route = FLAGS.flagged_route("CBOM_FLEET_TRANSPORTS")
    assert route is FLAGS.flagged_route("CBOM_FLEET_TRANSPORTS")  # one class per flag
    assert FLAGS.route_class("inventory") is FLAGS.flagged_route("CBOM_FLEET_INVENTORY")
    assert route.flag_env == "CBOM_FLEET_TRANSPORTS"
    monkeypatch.setenv("CBOM_FLEET_TRANSPORTS", "1")
    assert FLAGS.env_flag("CBOM_FLEET_TRANSPORTS") is True


def test_an_unknown_flag_name_is_a_programming_error():
    with pytest.raises(KeyError):
        FLAGS.route_class("inventroy")
    with pytest.raises(ValueError):
        FLAGS.flagged_route("PATH")  # only CBOM_* names


# ----------------------------------------------------------------------------- the route guard (fail closed)
def _fleet_routes():
    return [r for r in app.routes if getattr(r, "path", "").startswith(FLEET)]


def test_the_aggregator_is_registered_and_every_fleet_route_declares_its_permission():
    routes = _fleet_routes()
    assert any(r.path == FLEET + "/status" for r in routes)
    assert {r.path for r in routes} >= {r.path for r in cbom_fleet.router.routes if r.path.startswith(FLEET)}
    for route in routes:
        extra = getattr(route, "openapi_extra", None) or {}
        assert str(extra.get("x-zs-permission", "")).startswith("cbom."), route.path


def route_problems(routes) -> list[str]:
    """The rules every route of the aggregator follows (``cbom_fleet.py`` and ``fleet/http.py`` docstrings)."""
    problems = []
    for route in routes:
        if not isinstance(route, APIRoute):
            continue
        name = f"{sorted(route.methods)} {route.path}"
        if not isinstance(route, CbomRoute):
            problems.append(f"{name}: not a CbomRoute (a bad body would be a 422 that echoes the input)")
        if not (route.path.endswith("/fleet/status") or str(getattr(route, "flag_env", "")).startswith("CBOM_")):
            problems.append(f"{name}: not behind a flag (flagged_route)")
        if not str((route.openapi_extra or {}).get("x-zs-permission", "")).startswith("cbom."):
            problems.append(f"{name}: no x-zs-permission")
        calls = [d.call for d in route.dependant.dependencies]
        limiters = [i for i, call in enumerate(calls) if isinstance(call, RateLimiter)]
        if not limiters:
            problems.append(f"{name}: no rate limiter")
        if route.path.startswith(FLEET):
            if require_member not in calls:
                problems.append(f"{name}: no ctx: Member (authentication is not a dependency)")
            elif limiters and calls.index(require_member) < limiters[0]:
                problems.append(f"{name}: authentication runs before the rate limiter")
    return problems


def _concrete(path: str) -> str:
    return re.sub(r"\{[a-z_]+\}", "1", path)


def test_every_aggregator_route_is_authenticated_limited_flagged_and_a_cbom_route(api, monkeypatch):
    """Fail closed: every route F1.2, F1.3 and F1.4 add through the aggregator, checked statically and live."""
    for name in FLAG_ENV:
        monkeypatch.setenv(name, "1")
    routes = [r for r in cbom_fleet.router.routes if isinstance(r, APIRoute)]
    assert routes and route_problems(routes) == []
    for route in routes:
        for method in sorted(route.methods):
            url = _concrete(route.path)
            anonymous = api(method, url, None, content=b"")
            assert anonymous.status_code == 401, (method, route.path, anonymous.text)
            if route.path.startswith(FLEET):
                other_team = api(method, url, "carol", content=b"")  # carol is a member of team 2 only
                assert other_team.status_code == 403, (method, route.path, other_team.text)
            else:  # F1.4's node route: a scan node signs in with X-ZS-Node-Token, which was not sent
                assert "x-zs-node-token" not in {k.lower() for k in anonymous.request.headers}


def test_the_route_guard_reports_each_mistake():
    """Negative control: a router built wrongly in each way the guard checks is reported."""
    plain = APIRouter()  # plain APIRoute, no flag
    flagged = APIRouter(route_class=FLAGS.flagged_route("CBOM_FLEET_TRANSPORTS"))
    limit = [Depends(read_limiter)]
    read = permission("cbom.fleet.read")

    @plain.get(FLEET + "/plain", dependencies=limit, openapi_extra=read)
    async def plain_route(team_id: TeamId, ctx: Member):  # pragma: no cover - never called
        return {}

    @flagged.get(FLEET + "/no-auth", dependencies=limit, openapi_extra=read)
    async def no_auth(team_id: TeamId):  # pragma: no cover - never called (the reviewer's open route)
        return {"open": True}

    @flagged.get(FLEET + "/no-limit", openapi_extra=read)
    async def no_limit(team_id: TeamId, ctx: Member):  # pragma: no cover - never called
        return {}

    @flagged.get(FLEET + "/auth-first", dependencies=[Depends(require_member), Depends(read_limiter)], openapi_extra=read)
    async def auth_first(team_id: TeamId):  # pragma: no cover - never called
        return {}

    @flagged.get(FLEET + "/no-permission", dependencies=limit)
    async def no_permission(team_id: TeamId, ctx: Member):  # pragma: no cover - never called
        return {}

    aggregator = APIRouter(route_class=CbomRoute)  # include_router keeps each route's own class
    aggregator.include_router(plain)
    aggregator.include_router(flagged)
    problems = "\n".join(route_problems(aggregator.routes))
    assert "/plain: not a CbomRoute" in problems and "/plain: not behind a flag" in problems
    assert "/no-auth: no ctx: Member" in problems
    assert "/no-limit: no rate limiter" in problems
    assert "/auth-first: authentication runs before the rate limiter" in problems
    assert "/no-permission: no x-zs-permission" in problems
    assert len(problems.splitlines()) == 6


def test_requests_over_the_limit_never_reach_authentication(api, monkeypatch):
    """Limiter, then authentication: an over-budget request costs no user SELECT and no last_active UPDATE."""
    calls = []
    real = fleet_http.authorize

    async def counting(team_id, authorization):
        calls.append(team_id)
        return await real(team_id, authorization)

    monkeypatch.setattr(fleet_http, "authorize", counting)
    monkeypatch.setattr(cbom_http.read_limiter, "times", 2)
    codes = [api("GET", STATUS, "bob").status_code for _ in range(4)]
    assert codes == [200, 200, 429, 429] and len(calls) == 2


def test_the_aggregator_keeps_the_markers_other_parts_insert_under():
    text = Path(cbom_fleet.__file__).read_text()
    imports = [text.index(f"# F1.{n} imports\n") for n in (2, 3, 4)]
    routers = [text.index(f"# F1.{n} routers\n") for n in (2, 3, 4)]
    assert imports == sorted(imports) and routers == sorted(routers)
    # imports stay in the top import block (no E402); routers are included after the router exists
    assert imports[-1] < text.index("router = APIRouter(") < routers[0]
