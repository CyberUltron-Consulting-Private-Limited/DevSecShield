"""F1.2-a0 scaffold of the CBOM fleet routes (contract $R6/f1/CONTRACT.md, sections 3, 5 and 6).

* ``GET /{team_id}/cbom/sources/fleet/status`` answers members of the team with the four product flags, read from the
  environment on every call (default: all off), so the frontend can hide the Fleet tab and its sections;
* a fleet route behind a flag that is off answers exactly like a route that does not exist (404 ``Not Found``), before
  authentication and before the body is read;
* every fleet route declares its permission for F4's route-coverage test (``openapi_extra["x-zs-permission"]``);
* the aggregator keeps the insertion markers F1.3 and F1.4 add their routers under.
"""
from __future__ import annotations

from pathlib import Path

import pytest
from fastapi import APIRouter, FastAPI, Header
from fastapi.testclient import TestClient

from test_cbom_sources_api import api, world
from backend.main import app
from backend.routers import cbom_fleet
from backend.utilities.cbom_sources.fleet import flags as FLAGS

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
    monkeypatch.setenv("CBOM_FLEET_TRANSPORTS", "1")
    assert FLAGS.env_flag("CBOM_FLEET_TRANSPORTS") is True


def test_an_unknown_flag_name_is_a_programming_error():
    with pytest.raises(KeyError):
        FLAGS.route_class("inventroy")
    with pytest.raises(ValueError):
        FLAGS.flagged_route("PATH")  # only CBOM_* names


def _fleet_routes():
    return [r for r in app.routes if getattr(r, "path", "").startswith("/{team_id}/cbom/sources/fleet")]


def test_the_aggregator_is_registered_and_every_fleet_route_declares_its_permission():
    routes = _fleet_routes()
    assert any(r.path == "/{team_id}/cbom/sources/fleet/status" for r in routes)
    for route in routes:
        extra = getattr(route, "openapi_extra", None) or {}
        assert str(extra.get("x-zs-permission", "")).startswith("cbom."), route.path


def test_the_aggregator_keeps_the_markers_other_parts_insert_under():
    text = Path(cbom_fleet.__file__).read_text()
    assert "# F1.3 routers" in text and "# F1.4 routers" in text
    assert text.index("# F1.3 routers") < text.index("# F1.4 routers")
