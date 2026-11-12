"""Every route declares an access policy, and the policy is enforced before the handler runs (F4 RBAC).

1. Declarations: ``coverage.violations(app)`` is empty for the real app, and it does catch an undeclared route,
   two policies on one route, a team path without a team permission and a team permission without a team path.
2. Enforcement over HTTP, for every route of the real app: the route is copied with its real dependencies (rate
   limiter and policy) onto a sentinel handler.  For each team route and each actor (outsider, superuser who is not
   a member, viewer, member, admin, owner) a role below the route's permission gets the RBAC 403 and never reaches
   the sentinel; a role that holds it reaches the sentinel.  Signed-in, superuser, public and machine routes are
   checked the same way.  Token edge cases (tampered, refresh token, revoked, closed session, bad team ids) too.

    cd backend && PYTHON_DOTENV_DISABLED=1 PYTHONPATH=.. JWT_SECRET_KEY=t JWT_REFRESH_SECRET_KEY=r \
      AWS_ACCESS_KEY_ID=x AWS_SECRET_ACCESS_KEY=y AWS_DEFAULT_REGION=us-east-1 \
      python -m pytest tests/test_rbac_route_coverage.py -q -p no:cacheprovider
"""
import os
import re
import sys
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))
os.environ.setdefault("JWT_SECRET_KEY", "rbac-coverage-test-access-secret-0123456789")
os.environ.setdefault("JWT_REFRESH_SECRET_KEY", "rbac-coverage-test-refresh-secret-0123456789")

from fastapi import APIRouter, Depends, FastAPI, Request  # noqa: E402
from fastapi.routing import APIRoute  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlmodel import Session, SQLModel, create_engine, select  # noqa: E402

from backend.main import app  # noqa: E402
from backend.new_models import AuditEvent, Team, TeamMembership, User  # noqa: E402
from backend.utilities import ratelimit  # noqa: E402
from backend.utilities.auth.auth_utils import create_access_token, create_refresh_token  # noqa: E402
from backend.utilities.rbac import coverage  # noqa: E402
from backend.utilities.rbac.permissions import role_has  # noqa: E402
from backend.utilities.rbac.policy import (  # noqa: E402
    NOT_IN_TEAM, SESSION_NOT_ACTIVE, SUPERUSER_REQUIRED, Access, AccessPolicy, PermissionMarker, TeamPermission,
    marker_of, public,
)

TEAM = 1
OTHER_TEAM = 2
ACTORS = ("outsider", "superuser", "viewer", "member", "admin", "owner")


# ------------------------------------------------------------------------------------------------ declarations

def test_every_route_of_the_app_declares_exactly_one_fitting_policy():
    problems = coverage.violations(app)
    assert problems == [], "\n".join(problems)


def test_the_app_has_the_routes_the_inventory_counts():
    rows = coverage.inventory(app)
    assert len(rows) >= 150
    assert sum(1 for r in rows if r["kind"] == "team") >= 115
    assert all(r["kind"] != "MISSING" for r in rows)


def _engine_getter():
    raise AssertionError("not called")


def test_the_coverage_check_catches_each_kind_of_mistake():
    access = Access(_engine_getter)
    router = APIRouter()

    @router.get("/{team_id}/forgot")
    async def forgot(team_id: int):
        return {}

    @router.get("/{team_id}/signed-in-only", dependencies=[access.authenticated()])
    async def signed_in_only(team_id: int):
        return {}

    @router.get("/no-team", dependencies=[access.team("scan.read")])
    async def no_team():
        return {}

    @router.get("/{team_id}/twice", dependencies=[access.team("scan.read"), public("why not")])
    async def twice(team_id: int):
        return {}

    @router.get("/{team_id}/fine", dependencies=[access.team("scan.read")])
    async def fine(team_id: int):
        return {}

    probe = FastAPI()
    probe.include_router(router)
    problems = "\n".join(coverage.violations(probe))
    assert "GET /{team_id}/forgot: declares no access policy" in problems
    assert "GET /{team_id}/signed-in-only: has {team_id} in its path but its policy is authenticated" in problems
    assert "GET /no-team: a team permission needs {team_id}" in problems
    assert "GET /{team_id}/twice: declares 2 access policies" in problems
    assert "/{team_id}/fine" not in problems


def test_an_unknown_permission_fails_when_the_route_is_declared():
    with pytest.raises(ValueError, match="unknown permission"):
        Access(_engine_getter).team("scan.everything")


def test_a_public_route_must_say_why():
    with pytest.raises(ValueError):
        public("  ")


# ------------------------------------------------------------------------------------------------ enforcement

@pytest.fixture()
def world(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite:///{tmp_path / 'rbac.db'}", connect_args={"check_same_thread": False})
    SQLModel.metadata.create_all(engine)
    for name, module in list(sys.modules.items()):
        if module is None:
            continue
        if (name.startswith("backend.routers.") or name == "backend.utilities.cbom_sources.http") \
                and hasattr(module, "get_db"):
            monkeypatch.setattr(module, "get_db", lambda: engine)
    import backend.get_db as get_db_module
    monkeypatch.setattr(get_db_module, "get_db", lambda: engine)  # PermissionMarker's last resort
    users = {}
    with Session(engine) as s:
        s.add(Team(id=TEAM, name="Acme"))
        s.add(Team(id=OTHER_TEAM, name="Other"))
        s.commit()
        for actor in ACTORS:
            u = User(email=f"{actor}@acme.test", password="x", first_name=actor, last_name="t", profile_photo=None,
                     session_active=True, is_superuser=(actor == "superuser"), default_team_id=OTHER_TEAM)
            s.add(u)
            s.commit()
            s.refresh(u)
            users[actor] = u.id
            s.add(TeamMembership(team_id=OTHER_TEAM, user_id=u.id, role="owner"))
            if actor not in ("outsider", "superuser"):
                s.add(TeamMembership(team_id=TEAM, user_id=u.id, role=actor))
            s.commit()
    ratelimit.reset_all()
    yield engine, users
    ratelimit.reset_all()


def token(actor: str) -> dict:
    return {"Authorization": f"Bearer {create_access_token(f'{actor}@acme.test', version=0)}"}


_PARAM_VALUES = {"team_id": str(TEAM), "type": "sast", "kind": "servicenow", "token": "a" * 64}


def _url(path: str) -> str:
    return re.sub(r"\{([^}:]+)(:[^}]*)?\}", lambda m: _PARAM_VALUES.get(m.group(1), "1"), path)


def _sentinel_app():
    """The real routes (same paths, methods and dependencies, same order) on handlers that only say "reached"."""
    probe = FastAPI()
    routes = [r for r in app.routes if isinstance(r, APIRoute)]
    for index, route in enumerate(routes):
        def make(i):
            async def sentinel(request: Request):
                return {"reached": i}
            return sentinel
        probe.router.routes.append(APIRoute(route.path, make(index), methods=list(route.methods),
                                            dependencies=list(route.dependencies),
                                            openapi_extra=route.openapi_extra))
    return probe, routes


def _policy(route) -> AccessPolicy:
    declared = [d.call for d in route.dependant.dependencies if isinstance(d.call, AccessPolicy)]
    if declared:
        return declared[0]
    return TeamPermission(marker_of(route), lambda: None)  # an x-zs-permission route (PermissionMarker enforces it)


def _call(client, method, url, headers):
    ratelimit.reset_all()
    return client.request(method, url, headers=headers)


def test_every_team_route_refuses_roles_below_its_permission_before_the_handler_runs(world):
    probe, routes = _sentinel_app()
    client = TestClient(probe)
    checked = 0
    for index, route in enumerate(routes):
        policy = _policy(route)
        if not isinstance(policy, TeamPermission):
            continue
        method = sorted(route.methods)[0]
        url = _url(route.path)
        for actor in ACTORS:
            response = _call(client, method, url, token(actor))
            role = actor if actor not in ("outsider", "superuser") else None
            label = f"{method} {route.path} as {actor}"
            if role is not None and role_has(role, policy.permission.name):
                assert response.status_code == 200, (label, response.status_code, response.text)
                assert response.json() == {"reached": index}, (label, "another route answered", response.json())
            else:
                assert response.status_code == 403, (label, response.status_code, response.text)
                assert "reached" not in response.text, label
                detail = response.json()["detail"]
                if role is None:
                    assert detail == NOT_IN_TEAM, label
                else:
                    assert detail.startswith(f"Your role ({role}) cannot "), (label, detail)
            checked += 1
        # no token at all
        response = _call(client, method, url, {})
        assert response.status_code == 401 and "reached" not in response.text, (route.path, response.text)
    assert checked >= 115 * len(ACTORS)


def test_signed_in_superuser_public_and_machine_routes(world):
    probe, routes = _sentinel_app()
    client = TestClient(probe)
    kinds = set()
    for index, route in enumerate(routes):
        policy = _policy(route)
        if isinstance(policy, TeamPermission):
            continue
        kinds.add(policy.kind)
        method = sorted(route.methods)[0]
        url = _url(route.path)
        anonymous = _call(client, method, url, {})
        as_member = _call(client, method, url, token("member"))
        as_superuser = _call(client, method, url, token("superuser"))
        label = f"{method} {route.path} ({policy.kind})"
        if policy.kind in ("public", "machine"):
            assert anonymous.json() == {"reached": index}, (label, anonymous.text)
        elif policy.kind == "authenticated":
            assert anonymous.status_code == 401, label
            assert as_member.json() == {"reached": index}, (label, as_member.text)
        elif policy.kind == "platform_admin":
            assert anonymous.status_code == 401, label
            assert as_member.status_code == 403 and as_member.json()["detail"] == SUPERUSER_REQUIRED, label
            assert as_superuser.json() == {"reached": index}, (label, as_superuser.text)
        else:  # pragma: no cover
            pytest.fail(f"unexpected policy kind {policy.kind}")
    assert kinds == {"public", "machine", "authenticated", "platform_admin"}


def _team_read_route():
    return next(r for r in app.routes if isinstance(r, APIRoute) and r.path == "/team/{team_id}" and "GET" in r.methods)


def test_token_edge_cases_on_a_team_route(world):
    engine, users = world
    probe, _ = _sentinel_app()
    client = TestClient(probe)
    good = create_access_token("viewer@acme.test", version=0)
    cases = {
        "tampered signature": (f"Bearer {good[:-3]}{'A' if good[-3] != 'A' else 'B'}{good[-2:]}", 401),
        "refresh token as access": (f"Bearer {create_refresh_token('viewer@acme.test', version=0)}", 401),
        "unknown account": (f"Bearer {create_access_token('ghost@acme.test', version=0)}", 401),
        "basic scheme": (f"Basic {good}", 401),
        "no scheme": (good, 401),
        "empty bearer": ("Bearer ", 401),
    }
    for label, (header, expected) in cases.items():
        response = _call(client, "GET", f"/team/{TEAM}", {"Authorization": header})
        assert response.status_code == expected, (label, response.text)
        assert "reached" not in response.text

    # a token issued before the account's tokens were revoked (logout, reset, password change)
    with Session(engine) as s:
        u = s.get(User, users["viewer"])
        u.token_version = 3
        s.add(u)
        s.commit()
    assert _call(client, "GET", f"/team/{TEAM}", {"Authorization": f"Bearer {good}"}).status_code == 401
    fresh = create_access_token("viewer@acme.test", version=3)
    assert _call(client, "GET", f"/team/{TEAM}", {"Authorization": f"Bearer {fresh}"}).status_code == 200

    # a closed session: the one 403 the frontend signs out on
    with Session(engine) as s:
        u = s.get(User, users["viewer"])
        u.session_active = False
        s.add(u)
        s.commit()
    closed = _call(client, "GET", f"/team/{TEAM}", {"Authorization": f"Bearer {fresh}"})
    assert closed.status_code == 403 and closed.json()["detail"] == SESSION_NOT_ACTIVE


@pytest.mark.parametrize("team_id,expected", [
    ("abc", 422), ("0", 422), ("-1", 422), ("2147483648", 422), ("1.0", 422), ("99999", 403), (str(OTHER_TEAM), 200),
])
def test_team_ids_in_the_path(world, team_id, expected):
    probe, _ = _sentinel_app()
    client = TestClient(probe)
    response = _call(client, "GET", f"/team/{team_id}", token("member"))
    assert response.status_code == expected, response.text  # member is owner of OTHER_TEAM, not in 99999


def test_a_refused_team_write_is_in_the_audit_log_and_a_refused_read_is_not(world):
    engine, users = world
    probe, _ = _sentinel_app()
    client = TestClient(probe)
    assert _call(client, "PUT", f"/team/{TEAM}", token("viewer")).status_code == 403
    assert _call(client, "PUT", f"/team/{TEAM}", token("outsider")).status_code == 403
    assert _call(client, "GET", f"/team/{TEAM}", token("outsider")).status_code == 403
    with Session(engine) as s:
        rows = s.exec(select(AuditEvent).order_by(AuditEvent.id)).all()
    assert [(r.actor_user_id, r.action, r.outcome, r.team_id) for r in rows] == [
        (users["viewer"], "team.update", "denied", TEAM),
        (users["outsider"], "team.update", "denied", TEAM),
    ]
    assert rows[0].details["reason"] == "role viewer below admin" and rows[1].details["reason"] == "not a member"
    assert rows[0].ip == "testclient"


def test_policy_objects_are_reachable_from_the_route_table():
    """The coverage check finds the policy through FastAPI's own dependency tree (``route.dependant``), so a policy
    hidden inside another dependency would not count: it must be listed in ``dependencies=`` itself."""
    route = _team_read_route()
    assert isinstance(_policy(route), TeamPermission)
    assert any(isinstance(d, type(Depends(lambda: None))) for d in route.dependencies)


# ------------------------------------------------------------------------------------------------ markers (F1, F3)

def test_x_zs_permission_markers_are_accepted_and_enforced(world):
    """Parallel tracks declare ``openapi_extra={"x-zs-permission": name}`` without importing F4 code; the app-level
    PermissionMarker enforces it like ``access.team(name)``, and the coverage check accepts it."""
    engine, users = world
    router = APIRouter()

    @router.get("/{team_id}/cbom/sources/fleet/inventory", openapi_extra={"x-zs-permission": "cbom.fleet.read"})
    async def fleet_inventory(team_id: int):
        return {"reached": "read"}

    @router.post("/{team_id}/cbom/sources/fleet/inventory", openapi_extra={"x-zs-permission": "cbom.inventory.write"})
    async def fleet_import(team_id: int):
        return {"reached": "write"}

    probe = FastAPI(dependencies=[Depends(PermissionMarker())])
    probe.include_router(router)
    assert coverage.violations(probe) == []
    client = TestClient(probe)
    for actor in ("viewer", "member", "admin", "owner"):
        assert _call(client, "GET", f"/{TEAM}/cbom/sources/fleet/inventory", token(actor)).json() == {"reached": "read"}
    for actor, allowed in (("viewer", False), ("member", False), ("admin", True), ("owner", True)):
        response = _call(client, "POST", f"/{TEAM}/cbom/sources/fleet/inventory", token(actor))
        assert (response.status_code == 200) is allowed, (actor, response.text)
        if not allowed:
            assert response.status_code == 403 and response.json()["detail"].startswith(f"Your role ({actor}) cannot")
    assert _call(client, "GET", f"/{TEAM}/cbom/sources/fleet/inventory", token("outsider")).json()["detail"] == NOT_IN_TEAM
    assert _call(client, "GET", f"/{TEAM}/cbom/sources/fleet/inventory", {}).status_code == 401


def test_marker_mistakes_are_violations():
    router = APIRouter()

    @router.get("/{team_id}/a", openapi_extra={"x-zs-permission": "cbom.fleet.everything"})
    async def unknown(team_id: int):
        return {}

    @router.get("/b", openapi_extra={"x-zs-permission": "cbom.fleet.read"})
    async def no_team():
        return {}

    @router.get("/{team_id}/c", openapi_extra={"x-zs-permission": "cbom.fleet.read"},
                dependencies=[Access(_engine_getter).team("cbom.write")])
    async def disagree(team_id: int):
        return {}

    enforced = FastAPI(dependencies=[Depends(PermissionMarker())])
    enforced.include_router(router)
    problems = "\n".join(coverage.violations(enforced))
    assert "GET /{team_id}/a: x-zs-permission names an unknown permission" in problems
    assert "GET /b: x-zs-permission is a team permission and needs {team_id}" in problems
    assert "GET /{team_id}/c: x-zs-permission 'cbom.fleet.read' disagrees with its policy" in problems

    fine = APIRouter()

    @fine.get("/{team_id}/d", openapi_extra={"x-zs-permission": "cbom.fleet.read"})
    async def unenforced(team_id: int):
        return {}

    bare = FastAPI()  # no PermissionMarker: the marker would be decoration only
    bare.include_router(fine)
    assert "is not enforced" in "\n".join(coverage.violations(bare))


# ------------------------------------------------------------------------------------------------ review 5869394244 / 5869356370

def test_the_matrix_holds_the_names_the_parallel_tracks_use():
    """F4 owns the matrix (permissions.py:81): F3 (#40) declares scm.*; F1.2 cbom.*; F1.4's node route is machine()."""
    from backend.utilities.rbac.permissions import PERMISSIONS, get_permission
    expected = {"scm.read": "viewer", "scm.connections.write": "admin", "scm.repos.write": "admin",
                "scm.policies.write": "admin", "scm.scans.run": "admin",
                "cbom.fleet.read": "viewer", "cbom.inventory.write": "admin", "cbom.policies.write": "admin",
                "cbom.credentials.write": "admin", "cbom.transports.write": "admin", "cbom.sshca.admin": "admin"}
    assert {name: get_permission(name).min_role for name in expected} == expected
    assert "repos.read" not in PERMISSIONS and "repos.manage" not in PERMISSIONS  # nobody declares them


def test_public_and_machine_markers_need_no_rbac_import():
    """A webhook (F3) or a node route (F1.4) declares itself without importing F4: "public:<reason>",
    "machine:<credential>"."""
    router = APIRouter()

    @router.post("/scm/webhooks/{provider}/{webhook_uid}",
                 openapi_extra={"x-zs-permission": "public:the provider's HMAC signature is the credential"})
    async def webhook(provider: str, webhook_uid: str):
        return {"reached": "webhook"}

    @router.post("/cbom/node/jobs/{job_id}/ssh-cert", openapi_extra={"x-zs-permission": "machine:scan-node token"})
    async def node(job_id: int):
        return {"reached": "node"}

    marker = PermissionMarker()
    probe = FastAPI(dependencies=[Depends(marker)])
    probe.include_router(router)
    marker.prepare(probe)
    assert coverage.violations(probe) == []
    client = TestClient(probe)
    assert client.post("/scm/webhooks/github/abc").json() == {"reached": "webhook"}
    assert client.post("/cbom/node/jobs/1/ssh-cert").json() == {"reached": "node"}
    kinds = {r["path"]: r["kind"] for r in coverage.inventory(probe)}
    assert kinds == {"/scm/webhooks/{provider}/{webhook_uid}": "public", "/cbom/node/jobs/{job_id}/ssh-cert": "machine"}


@pytest.mark.parametrize("bad", ["scm.everything", "public:", "machine:  ", "public.scm_webhook", "node"])
def test_an_unknown_or_malformed_marker_stops_the_app_at_startup(bad):
    """permissions.py:81 / policy.py:372: a bad marker answered 500 on every request; now the app refuses to start."""
    router = APIRouter()

    @router.get("/{team_id}/x", openapi_extra={"x-zs-permission": bad})
    async def x(team_id: int):
        return {}

    marker = PermissionMarker()
    probe = FastAPI(dependencies=[Depends(marker)])
    probe.include_router(router)
    with pytest.raises(ValueError, match="x-zs-permission"):
        marker.prepare(probe)
    assert any("x-zs-permission" in p for p in coverage.violations(probe))


def test_the_real_app_resolved_every_marker_at_startup():
    from backend import main
    assert main.permission_marker.prepared


def test_a_route_without_a_policy_is_refused_at_runtime():
    """policy.py:376: no runtime default-deny; an anonymous request reached an undeclared route."""
    router = APIRouter()
    reached = []

    @router.post("/{team_id}/probe-no-policy")
    async def undeclared(team_id: int):
        reached.append(team_id)
        return {"reached": True}

    probe = FastAPI(dependencies=[Depends(PermissionMarker())])
    probe.include_router(router)
    response = TestClient(probe, raise_server_exceptions=False).post("/1/probe-no-policy")
    assert response.status_code == 500 and "access policy" in response.json()["detail"]
    assert reached == []


def test_team_ids_under_other_names_need_a_team_permission():
    """coverage.py:70: only the literal {team_id} was recognised."""
    from pydantic import BaseModel

    class Body(BaseModel):
        teamId: int

    access = Access(_engine_getter)
    router = APIRouter()

    @router.get("/teams/{teamId}/renamed", dependencies=[access.authenticated()])
    async def renamed(teamId: int):
        return {}

    @router.get("/team/{id}", dependencies=[access.authenticated()])
    async def by_id(id: int):
        return {}

    @router.get("/query", dependencies=[access.authenticated()])
    async def by_query(team_id: int):
        return {}

    @router.post("/body", dependencies=[access.authenticated()])
    async def by_body(body: Body):
        return {}

    @router.post("/admin/teams/{target_team_id}/owner", dependencies=[access.platform_admin()])
    async def superuser(target_team_id: int):
        return {}

    @router.get("/sso/{team}/start", dependencies=[public("starts a sign-in", team_in_path="the team whose IdP signs in")])
    async def sso_start(team: int):
        return {}

    probe = FastAPI()
    probe.include_router(router)
    problems = "\n".join(coverage.violations(probe))
    for label in ("GET /teams/{teamId}/renamed", "GET /team/{id}", "GET /query", "POST /body"):
        assert f"{label}: names a team" in problems, (label, problems)
    assert "/admin/teams/{target_team_id}/owner" not in problems  # superusers are not team-scoped
    assert "/sso/{team}/start" not in problems  # public on purpose, and says why


def test_the_cbom_discovery_sweep_is_declared_admin_like_its_handler():
    """Review 5869356370 (cbom_sources.py:1109): declared cbom.write (member) while the handler is admin-only."""
    rows = {(r["methods"], r["path"]): r for r in coverage.inventory(app)}
    sweep = rows[("POST", "/{team_id}/cbom/sources/discovery")]
    assert sweep["permission"] == "cbom.settings" and sweep["min_role"] == "admin"
