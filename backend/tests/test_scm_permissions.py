"""F3 routes and F4's permission matrix (round-6 cross-track decision: F4 owns the matrix).

Every team route of the repositories API declares its permission as ``openapi_extra={"x-zs-permission": name}``
(F4 enforces such markers app-wide without F3 importing F4 code). The names must be ones F4's matrix holds
(``backend/utilities/rbac/permissions.py`` on feat/f4-rbac): ``repos.read`` (viewer) and ``repos.manage`` (admin).
An unknown name makes F4's enforcer fail every request to the route (500) and its route-coverage test fail.

The public webhook route carries no marker: it is not a team route (its credential is the connection's webhook
secret), and F4 declares such routes with its own ``public(...)`` policy once F4 (PR #42) and F3 are both on dev.

    cd backend && PYTHONPATH=.. uv run --with pytest python -m pytest tests/test_scm_permissions.py -q
"""
from __future__ import annotations

import importlib
import os
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))
os.environ.setdefault("JWT_SECRET_KEY", "scm-permissions-test-secret")
os.environ.setdefault("JWT_REFRESH_SECRET_KEY", "scm-permissions-test-refresh")

from fastapi.routing import APIRoute  # noqa: E402

from backend.routers import scm as scm_router  # noqa: E402

# F4's matrix (feat/f4-rbac b2933fc): the names F3 uses and the lowest role that holds each
F4_NAMES = {"repos.read": "viewer", "repos.manage": "admin"}
WEBHOOK = "/scm/webhooks/{provider}/{webhook_uid}"


def _routes() -> list[APIRoute]:
    return [r for r in scm_router.router.routes if isinstance(r, APIRoute)]


def _marker(route: APIRoute) -> str | None:
    extra = route.openapi_extra or {}
    return extra.get("x-zs-permission")


def test_every_team_route_names_a_permission_of_f4s_matrix():
    seen = set()
    for route in _routes():
        label = f"{','.join(sorted(route.methods))} {route.path}"
        if route.path == WEBHOOK:
            continue
        assert "{team_id}" in route.path, label
        name = _marker(route)
        assert name in F4_NAMES, f"{label}: x-zs-permission {name!r} is not in F4's matrix"
        seen.add(name)
    assert seen == set(F4_NAMES)


def test_reads_are_repos_read_and_every_change_is_repos_manage():
    for route in _routes():
        if route.path == WEBHOOK:
            continue
        name = _marker(route)
        # estimates and previews are POSTs that change nothing: they are reads
        read_only = route.methods == {"GET"} or route.path.endswith(("/preview", "/runs/estimate"))
        assert name == ("repos.read" if read_only else "repos.manage"), f"{route.methods} {route.path}: {name}"


def test_the_public_webhook_carries_no_team_permission():
    hooks = [r for r in _routes() if r.path == WEBHOOK]
    assert len(hooks) == 1 and _marker(hooks[0]) is None


def test_names_exist_in_f4s_matrix_when_it_is_present():
    """After F4 is merged the matrix module exists: the names must be in it with the same lowest role."""
    try:
        permissions = importlib.import_module("backend.utilities.rbac.permissions")
    except ModuleNotFoundError:
        return  # F4 not on this branch yet: F4_NAMES above mirrors feat/f4-rbac
    for name, role in F4_NAMES.items():
        assert permissions.PERMISSIONS[name].min_role == role, name
