"""Route coverage: every route of the app declares exactly one access policy, and the policy fits the path.

``violations(app)`` lists what is wrong (tests/test_rbac_route_coverage.py asserts it is empty); ``inventory(app)``
is the table the security review reads (scripts/rbac_route_inventory.py writes it to
docs/security/route-inventory.md).
"""
from __future__ import annotations

import re

from fastapi.routing import APIRoute, APIWebSocketRoute
from starlette.routing import Mount, Route

from backend.utilities.rbac.policy import (
    PERMISSION_MARKER, AccessPolicy, PermissionMarker, PlatformAdmin, Public, TeamPermission, declared_policies,
    marker_of, policy_from_marker,
)

# Routes FastAPI adds itself (API docs).  Anything else that is not an API route is a violation.
FRAMEWORK_PATHS = frozenset({"/openapi.json", "/docs", "/docs/oauth2-redirect", "/redoc"})


def _policies(route) -> list[AccessPolicy]:
    return declared_policies(route)


def _has_marker_enforcer(route) -> bool:
    return any(isinstance(d.call, PermissionMarker) for d in route.dependant.dependencies)


def _marker_problem(label: str, route, marker: str, policies: list[AccessPolicy]) -> str | None:
    try:
        declared_by_marker = policy_from_marker(marker, lambda: None)
    except ValueError as exc:
        return f"{label}: {exc}"
    if not isinstance(declared_by_marker, TeamPermission):  # public:<reason> / machine:<credential>
        if policies:
            return f"{label}: {PERMISSION_MARKER} {marker!r} and a declared policy: keep one"
        return None if _has_marker_enforcer(route) else (
            f"{label}: {PERMISSION_MARKER} is not enforced: the app has no rbac PermissionMarker dependency")
    if policies:
        declared = getattr(getattr(policies[0], "permission", None), "name", None)
        if len(policies) == 1 and declared != marker:
            return f"{label}: {PERMISSION_MARKER} {marker!r} disagrees with its policy ({policies[0].describe()})"
        return None
    if "{team_id}" not in route.path:
        return f"{label}: {PERMISSION_MARKER} is a team permission and needs {{team_id}} in the path"
    if not _has_marker_enforcer(route):
        return f"{label}: {PERMISSION_MARKER} is not enforced: the app has no rbac PermissionMarker dependency"
    return None


_TEAM_PARAM = re.compile(r"^team$|team.*id", re.IGNORECASE)
_TEAM_SEGMENT = re.compile(r"/teams?/\{(?!team_id\})[^}]+\}")


def _names_a_team(route) -> list[str]:
    """Team-like inputs under another name than {team_id}: a path, query or body parameter called team / teamId /
    *team*id, a body model field so named, or a /team/{x} or /teams/{x} segment (coverage.py:70 review)."""
    found = []
    dependant = getattr(route, "dependant", None)
    if dependant is not None:
        for param in [*dependant.path_params, *dependant.query_params]:
            if _TEAM_PARAM.search(param.name):
                found.append(param.name)
        for param in dependant.body_params:
            if _TEAM_PARAM.search(param.name):
                found.append(param.name)
            fields = getattr(getattr(param, "type_", None) or getattr(param.field_info, "annotation", None),
                             "model_fields", None) or {}
            found += [f"body.{name}" for name in fields if _TEAM_PARAM.search(name)]
    for match in _TEAM_SEGMENT.finditer(route.path):
        found.append(match.group(0))
    return sorted(set(found))


def _team_param_allowed(policy) -> bool:
    if isinstance(policy, PlatformAdmin):  # superusers are not team-scoped (/admin/audit?team_id=, owner recovery)
        return True
    return isinstance(policy, Public) and bool(policy.team_in_path)


def _methods(route) -> str:
    methods = getattr(route, "methods", None)
    return ",".join(sorted(methods)) if methods else "WS"


def violations(app) -> list[str]:
    problems: list[str] = []
    for route in app.routes:
        if isinstance(route, (APIRoute, APIWebSocketRoute)):
            label = f"{_methods(route)} {route.path}"
            policies = _policies(route)
            marker = marker_of(route)
            if marker is not None:
                problem = _marker_problem(label, route, marker, policies)
                if problem:
                    problems.append(problem)
                if not policies:
                    continue  # a marker route is a team route enforced by PermissionMarker
            if not policies:
                problems.append(f"{label}: declares no access policy (add access.team(...), "
                                "access.authenticated(), access.platform_admin(), public(...) or machine(...))")
                continue
            if len(policies) > 1:
                problems.append(f"{label}: declares {len(policies)} access policies; exactly one is allowed")
                continue
            policy = policies[0]
            team_path = "{team_id}" in route.path
            if team_path and not isinstance(policy, TeamPermission):
                problems.append(f"{label}: has {{team_id}} in its path but its policy is {policy.kind}, not a team "
                                "permission")
            elif not team_path and _names_a_team(route) and not _team_param_allowed(policy):
                problems.append(f"{label}: names a team ({', '.join(_names_a_team(route))}) but its policy is "
                                f"{policy.kind}: use {{team_id}} and access.team(...), or say why "
                                "(public(..., team_in_path=...))")
            if isinstance(policy, TeamPermission) and not team_path:
                problems.append(f"{label}: a team permission needs {{team_id}} in the path")
        elif isinstance(route, Mount):
            problems.append(f"MOUNT {route.path}: mounted apps are not covered by access policies")
        elif isinstance(route, Route):
            if route.path not in FRAMEWORK_PATHS:
                problems.append(f"{_methods(route)} {route.path}: a plain Starlette route has no access policy")
        else:
            problems.append(f"{type(route).__name__} {getattr(route, 'path', '?')}: unknown route type")
    return problems


def inventory(app) -> list[dict]:
    rows = []
    for route in app.routes:
        if not isinstance(route, (APIRoute, APIWebSocketRoute)):
            continue
        policies = _policies(route)
        policy = policies[0] if len(policies) == 1 else None
        if policy is None and marker_of(route) is not None:
            try:
                policy = policy_from_marker(marker_of(route), lambda: None)  # what PermissionMarker enforces
            except ValueError:
                policy = None
        rows.append({
            "methods": _methods(route),
            "path": route.path,
            "handler": f"{route.endpoint.__module__.replace('backend.routers.', '')}.{route.endpoint.__name__}",
            "kind": policy.kind if policy else "MISSING",
            "permission": getattr(getattr(policy, "permission", None), "name", None),
            "min_role": getattr(getattr(policy, "permission", None), "min_role", None),
            "audited": bool(getattr(policy, "audited", False)) if policy else False,
            "policy": policy.describe() if policy else "MISSING",
        })
    return rows
