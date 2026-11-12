"""F1.2-a0 scaffold of the CBOM fleet routes (contract $R6/f1/CONTRACT.md, sections 3, 5 and 6).

* ``GET /{team_id}/cbom/sources/fleet/status`` answers members of the team with the four product flags, read from the
  environment on every call (default: all off), so the frontend can hide the Fleet tab and its sections;
* a fleet route behind a flag that is off answers exactly like a route that does not exist (404 ``Not Found``), before
  authentication and before the body is read;
* every route the app serves under ``FLEET`` (whichever router registered it) and every route of the aggregator,
  checked with every flag on, is a ``CbomRoute`` behind a flag, rate limited, declares its permission for F4's
  route-coverage test, and authenticates through the ``ctx: Member`` dependency right after the limiter with nothing
  in between: anonymous -> 401, another team's member -> 403 (security reviews 5858172203 and 5858732570).  Team
  routes live under ``FLEET``; the only other path is a scan-node route.  Each fleet URL reaches the route that was
  checked.  Negative controls prove the guard reports each mistake;
* the aggregator keeps the import and router markers F1.3 and F1.4 insert under.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Annotated

import pytest
from fastapi import APIRouter, Depends, FastAPI, Header, Request
from fastapi.responses import JSONResponse
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient
from starlette.routing import Match

from test_cbom_sources_api import api, world
from backend.main import app
from backend.routers import cbom_fleet
from backend.utilities.cbom_sources import http as cbom_http
from backend.utilities.cbom_sources.fleet import flags as FLAGS
from backend.utilities.cbom_sources.fleet import http as fleet_http
from backend.utilities.cbom_sources.fleet.http import FLEET, Member, permission, require_member
from backend.utilities.cbom_sources.http import CbomRoute, TeamId, node_limiter, read_limiter
from backend.utilities.ratelimit import RateLimiter

# The paths outside FLEET a fleet part may add: F1.4's machine routes, whose caller is not a person with a team role
# (the scan node's certificate route; the servers' trust-bundle fetch).  They declare "machine:<credential>" (F4's
# marker form, rbac/policy.py) or a cbom.* permission.
NODE = "/cbom/node/"
MACHINE_PATHS = (NODE, "/cbom/ssh-ca-trust/")
MACHINE_MARKER = "machine:"
FLAG_ENV =("CBOM_FLEET_INVENTORY", "CBOM_FLEET_POLICIES", "CBOM_FLEET_MATERIALIZE", "CBOM_FLEET_TRANSPORTS",
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
def _key(route) -> tuple:
    return getattr(route, "path", None), frozenset(getattr(route, "methods", None) or ())


def _in_fleet(path: str) -> bool:
    return path == FLEET or path.startswith(FLEET + "/")


def guarded_routes(app_routes, aggregator_routes) -> list:
    """The routes the fleet rules apply to, as the app serves them: every route under ``FLEET`` whichever router
    registered it (security re-review 5858732570, M5), plus every route of the aggregator (F1.4's node route is
    outside ``FLEET``).  Route objects of ``app_routes`` (``include_router`` copies routes), of every type."""
    aggregator = {_key(r) for r in aggregator_routes}
    return [r for r in app_routes if _in_fleet(str(getattr(r, "path", ""))) or _key(r) in aggregator]


def _fleet_routes():
    return guarded_routes(app.routes, cbom_fleet.router.routes)


def _served_by(an_app, method: str, url: str):
    """The route ``an_app`` dispatches ``method url`` to: the first full match, as Starlette's router does."""
    scope = {"type": "http", "method": method, "path": url, "root_path": ""}
    return next((r for r in an_app.router.routes if r.matches(scope)[0] is Match.FULL), None)


def test_the_aggregator_is_registered_and_every_fleet_route_declares_its_permission():
    routes = _fleet_routes()
    assert any(r.path == FLEET + "/status" for r in routes)
    assert {_key(r) for r in cbom_fleet.router.routes} <= {_key(r) for r in app.routes}  # main.app serves them all
    for route in routes:
        marker = str((getattr(route, "openapi_extra", None) or {}).get("x-zs-permission", ""))
        machine = marker.startswith(MACHINE_MARKER) and route.path.startswith(MACHINE_PATHS)
        assert marker.startswith("cbom.") or machine, route.path


def route_problems(routes) -> list[str]:
    """The rules every route of the aggregator follows (``cbom_fleet.py`` and ``fleet/http.py`` docstrings)."""
    problems = []
    for route in routes:
        if not isinstance(route, APIRoute):  # a Starlette route or mount: no limiter, flag or authentication (M4)
            problems.append(f"{getattr(route, 'path', route)}: not an APIRoute")
            continue
        name = f"{sorted(route.methods)} {route.path}"
        machine_path = route.path.startswith(MACHINE_PATHS)
        if not (_in_fleet(route.path) or machine_path):  # M9: team routes live under FLEET
            problems.append(f"{name}: outside {FLEET} and not a machine route ({', '.join(MACHINE_PATHS)}...)")
        if not isinstance(route, CbomRoute):
            problems.append(f"{name}: not a CbomRoute (a bad body would be a 422 that echoes the input)")
        if not (route.path.endswith("/fleet/status") or str(getattr(route, "flag_env", "")).startswith("CBOM_")):
            problems.append(f"{name}: not behind a flag (flagged_route)")
        marker = str((route.openapi_extra or {}).get("x-zs-permission", ""))
        machine_marker = marker.startswith(MACHINE_MARKER) and bool(marker[len(MACHINE_MARKER):].strip())
        if not (marker.startswith("cbom.") or (machine_marker and machine_path)):
            problems.append(f"{name}: no x-zs-permission" + (" (machine: only on machine routes)" if machine_marker else ""))
        calls = [d.call for d in route.dependant.dependencies]
        limiters = [i for i, call in enumerate(calls) if isinstance(call, RateLimiter)]
        if not limiters:
            problems.append(f"{name}: no rate limiter")
        if _in_fleet(route.path):
            if require_member not in calls:
                problems.append(f"{name}: no ctx: Member (authentication is not a dependency)")
                continue
            before = calls[: calls.index(require_member)]  # dependencies run in this order
            if limiters and not any(isinstance(call, RateLimiter) for call in before):
                problems.append(f"{name}: authentication runs before the rate limiter")
            others = [getattr(c, "__name__", type(c).__name__) for c in before if not isinstance(c, RateLimiter)]
            if others:  # M6: nothing but the limiter may run before authentication (a body read, say)
                problems.append(f"{name}: {', '.join(others)} runs before authentication")
    return problems


def _concrete(path: str) -> str:
    return re.sub(r"\{[a-z_]+\}", "1", path)


def test_every_aggregator_route_is_authenticated_limited_flagged_and_a_cbom_route(api, monkeypatch):
    """Fail closed: every route F1.2, F1.3 and F1.4 add through the aggregator, checked statically and live."""
    for name in FLAG_ENV:
        monkeypatch.setenv(name, "1")
    routes = _fleet_routes()
    assert routes and route_problems(routes) == []
    for route in routes:
        for method in sorted(route.methods):
            url = _concrete(route.path)
            assert _served_by(app, method, url) is route, (method, route.path, "answered by another route")
            anonymous = api(method, url, None, content=b"")
            assert anonymous.status_code == 401, (method, route.path, anonymous.text)
            if route.path.startswith(FLEET):
                other_team = api(method, url, "carol", content=b"")  # carol is a member of team 2 only
                assert other_team.status_code == 403, (method, route.path, other_team.text)
            else:  # F1.4's node route: a scan node signs in with X-ZS-Node-Token, which was not sent
                assert "x-zs-node-token" not in {k.lower() for k in anonymous.request.headers}


async def read_body(request: Request) -> dict:  # pragma: no cover - never called
    """A body-reading dependency (module level: this file's annotations are strings, resolved from its globals)."""
    return await request.json()


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

    @flagged.post(FLEET + "/body-first",dependencies=limit, openapi_extra=read)  # M6: parsed before auth
    async def body_first(team_id: TeamId, body: Annotated[dict, Depends(read_body)], ctx: Member):  # pragma: no cover
        return {}

    @flagged.post(FLEET + "/body-before-limiter", dependencies=[Depends(read_body), Depends(read_limiter)],
                  openapi_extra=read)
    async def body_before_limiter(team_id: TeamId, ctx: Member):  # pragma: no cover - never called
        return {}

    @flagged.get("/{team_id}/cbom/ssh-ca", dependencies=limit, openapi_extra=read)  # M9: a team route outside FLEET
    async def outside(team_id: TeamId):  # pragma: no cover - never called
        return {}

    @flagged.post(NODE + "jobs/{job_id}/ssh-cert", dependencies=[Depends(node_limiter)], openapi_extra=read)
    async def node_route(job_id: int):  # pragma: no cover - positive control: node routes sign in with their token
        return {}

    @flagged.post(NODE + "jobs/{job_id}/machine-marked", dependencies=[Depends(node_limiter)],
                  openapi_extra={"x-zs-permission": "machine:scan-node token"})
    async def machine_marked(job_id: int):  # pragma: no cover - positive control: F4's machine marker
        return {}

    @flagged.get(FLEET + "/machine-on-team-route", dependencies=limit,
                 openapi_extra={"x-zs-permission": "machine:anything"})
    async def machine_on_team(team_id: TeamId, ctx: Member):  # pragma: no cover - a machine marker on a team route
        return {}

    async def raw(request):  # pragma: no cover - never called
        return JSONResponse({})

    aggregator = APIRouter(route_class=CbomRoute)  # include_router keeps each route's own class
    aggregator.include_router(plain)
    aggregator.include_router(flagged)
    aggregator.add_route(FLEET + "/raw", raw, methods=["GET"])  # M4: a plain Starlette route
    problems = "\n".join(route_problems(aggregator.routes))
    assert "/plain: not a CbomRoute" in problems and "/plain: not behind a flag" in problems
    assert "/no-auth: no ctx: Member" in problems
    assert "/no-limit: no rate limiter" in problems
    assert "/auth-first: authentication runs before the rate limiter" in problems
    assert "/no-permission: no x-zs-permission" in problems
    assert "/body-first: read_body runs before authentication" in problems
    assert "/body-before-limiter: read_body runs before authentication" in problems
    assert "/{team_id}/cbom/ssh-ca: outside " + FLEET in problems
    assert "/fleet/raw: not an APIRoute" in problems
    assert "ssh-cert" not in problems and "machine-marked" not in problems
    assert "/machine-on-team-route: no x-zs-permission (machine: only on machine routes)" in problems
    assert len(problems.splitlines()) == 11, problems


def test_the_guard_checks_fleet_paths_whichever_router_registers_them():
    """M5: a FLEET path on another router (``cbom_ops`` say) is checked like the aggregator's own routes, and a route
    registered earlier whose template captures a fleet URL is caught by the live check (``_served_by``)."""
    limit, read = [Depends(read_limiter)], permission("cbom.fleet.read")
    aggregator = APIRouter(route_class=CbomRoute)
    other = APIRouter(route_class=CbomRoute)  # included into the app before the aggregator, as cbom_ops is

    @aggregator.get(FLEET + "/status", dependencies=limit, openapi_extra=read)
    async def status(team_id: TeamId, ctx: Member):  # pragma: no cover - never called
        return {}

    @other.get(FLEET + "/side", dependencies=limit, openapi_extra=read)
    async def side(team_id: TeamId):  # pragma: no cover - never called (open: no ctx: Member, no flag)
        return {}

    @other.get("/{team_id}/cbom/sources/{section}/status", dependencies=limit)
    async def captures(team_id: TeamId, section: str):  # pragma: no cover - never called
        return {}

    test_app = FastAPI()
    test_app.include_router(other)
    test_app.include_router(aggregator)
    selected = guarded_routes(test_app.routes, aggregator.routes)
    assert sorted(r.path for r in selected) == [FLEET + "/side", FLEET + "/status"]
    problems = "\n".join(route_problems(selected))
    assert "/fleet/side: no ctx: Member" in problems and "/fleet/side: not behind a flag" in problems
    assert "/fleet/status" not in problems
    served = _served_by(test_app, "GET", _concrete(FLEET + "/status"))
    assert served is not None and served.path.endswith("{section}/status")  # the live check reports this one


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
