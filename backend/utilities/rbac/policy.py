"""Access policies: the FastAPI dependency every route declares, and the only place a team role is checked.

Every route lists exactly one policy in ``dependencies=[...]`` (after its rate limiter); the route-coverage test
(tests/test_rbac_route_coverage.py, ``coverage.violations``) fails otherwise.

* ``access.team("scan.create")``   a member of the path's ``team_id`` whose role holds the permission
* ``access.authenticated()``       any signed-in account (no team in the path)
* ``access.platform_admin()``      a superuser (the admin console)
* ``public(reason)``               no account: sign-in, sign-up, codes, links that carry their own credential
* ``machine(credential, reason)``  a non-person credential the handler checks: scan-node token, API key

A team check is: Bearer token -> signature, type, expiry, token version -> account (session active) -> membership
of ``team_id`` -> role >= the permission's lowest role.  It reads only (no ``last_active`` write): the handler
still authenticates as before (defence in depth).  The roles are read from the database on every request (never
from the token), so a role change or removal applies to the next request.

Answers: 401 no or bad token; 403 "Session not active" (the frontend signs out on that one only); 403 "User is
not in team" (unchanged); 403 "Your role (viewer) cannot ..." for a role that is too low.  A refused team write is
written to the audit log (outcome "denied").
"""
# no "from __future__ import annotations": FastAPI reads the dependencies' annotations (request: Request) at runtime

import logging
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from fastapi import HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from sqlalchemy.engine import Engine
from sqlmodel import Session, select
from starlette.concurrency import run_in_threadpool

from backend.new_models import TeamMembership, User
from backend.utilities.rbac.permissions import Permission, ROLE_LABELS, get_permission, role_has

log = logging.getLogger("backend.rbac")

MAX_TEAM_ID = 2_147_483_647
EngineGetter = Callable[[], Engine]

NOT_IN_TEAM = "User is not in team"
SESSION_NOT_ACTIVE = "Session not active"
SUPERUSER_REQUIRED = "Access denied. Superuser privileges required."


@dataclass(frozen=True)
class Principal:
    user_id: int
    email: str
    is_superuser: bool
    team_id: Optional[int] = None
    role: Optional[str] = None


@dataclass
class AccessContext:
    """What the policy decided, kept on ``request.state.access`` for the handler and the audit middleware."""
    policy: "AccessPolicy"
    engine_getter: Optional[EngineGetter] = None
    principal: Optional[Principal] = None
    team_id: Optional[int] = None
    route_path: str = ""
    path_params: dict = field(default_factory=dict)


def role_denied_detail(role: str, permission: Permission) -> str:
    return f"Your role ({ROLE_LABELS.get(role, role).lower()}) cannot {permission.description}. Ask a team admin for access."


def _unauthorized(detail: str = "Could not validate credentials") -> HTTPException:
    return HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=detail, headers={"WWW-Authenticate": "Bearer"})


def bearer_token(request: Request) -> str:
    header = request.headers.get("authorization")
    if not header:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")
    parts = header.split(" ")
    if len(parts) != 2 or parts[0].lower() != "bearer" or not parts[1]:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid Authorization header format")
    return parts[1]


def team_id_from_path(request: Request) -> int:
    raw = request.path_params.get("team_id")
    try:
        value = int(str(raw), 10)
    except (TypeError, ValueError):
        value = None
    if value is None or not 1 <= value <= MAX_TEAM_ID or str(raw).strip() != str(raw):
        raise RequestValidationError([{
            "type": "int_parsing", "loc": ("path", "team_id"),
            "msg": f"Input should be a whole number from 1 to {MAX_TEAM_ID}", "input": None,
        }])
    return value


def _load_principal(engine: Engine, claims: dict, team_id: Optional[int], allow_inactive: bool
                    ) -> tuple[Optional[Principal], Optional[str]]:
    """(principal, problem): problem is "token" (unknown account or revoked token) or "session"."""
    with Session(engine) as session:
        user = session.exec(select(User).where(User.email == claims["sub"])).first()
        if user is None:
            return None, "token"
        if claims.get("ver", 0) < (user.token_version or 0):
            return None, "token"
        if not user.session_active and not allow_inactive:
            return None, "session"
        role = None
        if team_id is not None:
            role = session.exec(select(TeamMembership.role).where(
                TeamMembership.team_id == team_id, TeamMembership.user_id == user.id)).first()
        return Principal(user_id=user.id, email=user.email, is_superuser=bool(user.is_superuser),
                         team_id=team_id, role=role), None


ACCESS_CHECK_FAILED = "Could not check your access, please try again later"


def _engine(getter: EngineGetter) -> Engine:
    try:
        return getter()
    except Exception as exc:  # an unreachable database: a generic 500, never the driver's text (host, port)
        log.error("access check: database unavailable (%s)", type(exc).__name__)
        raise HTTPException(status_code=500, detail=ACCESS_CHECK_FAILED) from None


async def resolve_principal(request: Request, engine: Engine, team_id: Optional[int] = None,
                            allow_inactive: bool = False) -> Principal:
    from backend.utilities.auth import auth_utils  # at call time: tests may stand a stub module in for it

    claims = auth_utils.access_token_claims(bearer_token(request))
    if claims is None:
        raise _unauthorized()
    try:
        principal, problem = await run_in_threadpool(_load_principal, engine, claims, team_id, allow_inactive)
    except HTTPException:
        raise
    except Exception as exc:
        log.error("access check failed (%s)", type(exc).__name__)
        raise HTTPException(status_code=500, detail=ACCESS_CHECK_FAILED) from None
    if problem == "session":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=SESSION_NOT_ACTIVE)
    if problem is not None or principal is None:
        log.info("access refused: unknown account or revoked token")
        raise _unauthorized()
    return principal


class AccessPolicy:
    """Base class: a route's access declaration (a FastAPI dependency)."""
    kind = "abstract"
    audited = False  # a successful request is written to the audit log by the middleware

    def describe(self) -> str:  # pragma: no cover - overridden
        raise NotImplementedError

    def _context(self, request: Request, **values: Any) -> AccessContext:
        route = request.scope.get("route")
        ctx = AccessContext(policy=self, route_path=getattr(route, "path", "") or "",
                            path_params=dict(request.path_params), **values)
        request.state.access = ctx
        return ctx

    def __repr__(self) -> str:
        return f"<{type(self).__name__} {self.describe()}>"


class Public(AccessPolicy):
    kind = "public"

    def __init__(self, reason: str):
        if not reason.strip():
            raise ValueError("a public route needs a reason")
        self.reason = reason

    def describe(self) -> str:
        return f"public: {self.reason}"

    async def __call__(self, request: Request) -> None:
        self._context(request)


class Machine(AccessPolicy):
    """A credential that is not a person's session, checked by the handler (node token, API key)."""
    kind = "machine"

    def __init__(self, credential: str, reason: str):
        self.credential, self.reason = credential, reason

    def describe(self) -> str:
        return f"machine ({self.credential}): {self.reason}"

    async def __call__(self, request: Request) -> None:
        self._context(request)


class Authenticated(AccessPolicy):
    kind = "authenticated"

    def __init__(self, engine_getter: EngineGetter, *, allow_inactive_session: bool = False, audited: bool = False):
        self.engine_getter = engine_getter
        self.allow_inactive_session = allow_inactive_session
        self.audited = audited

    def describe(self) -> str:
        return "any signed-in account" + (" (also a closed session)" if self.allow_inactive_session else "")

    async def __call__(self, request: Request) -> Principal:
        principal = await resolve_principal(request, _engine(self.engine_getter),
                                            allow_inactive=self.allow_inactive_session)
        self._context(request, engine_getter=self.engine_getter, principal=principal)
        return principal


class PlatformAdmin(AccessPolicy):
    kind = "platform_admin"

    def __init__(self, engine_getter: EngineGetter, *, audited: bool = False):
        self.engine_getter = engine_getter
        self.audited = audited

    def describe(self) -> str:
        return "superuser (admin console)"

    async def __call__(self, request: Request) -> Principal:
        engine = _engine(self.engine_getter)
        principal = await resolve_principal(request, engine)
        ctx = self._context(request, engine_getter=self.engine_getter, principal=principal)
        if not principal.is_superuser:
            if self.audited:
                await _audit_denial(request, ctx, engine, action=f"platform.{request.method.lower()}",
                                    reason="not a superuser")
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=SUPERUSER_REQUIRED)
        return principal


class TeamPermission(AccessPolicy):
    kind = "team"

    def __init__(self, permission: str, engine_getter: EngineGetter):
        self.permission = get_permission(permission)  # an unknown name fails at import time
        self.engine_getter = engine_getter
        self.audited = self.permission.audited

    def describe(self) -> str:
        return f"team role >= {self.permission.min_role} ({self.permission.name})"

    async def __call__(self, request: Request) -> Principal:
        team_id = team_id_from_path(request)
        engine = _engine(self.engine_getter)
        principal = await resolve_principal(request, engine, team_id=team_id)
        ctx = self._context(request, engine_getter=self.engine_getter, principal=principal, team_id=team_id)
        if principal.role is None:
            if self.audited:
                await _audit_denial(request, ctx, engine, action=self.permission.name, reason="not a member")
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=NOT_IN_TEAM)
        if not role_has(principal.role, self.permission.name):
            await _audit_denial(request, ctx, engine, action=self.permission.name,
                                reason=f"role {principal.role} below {self.permission.min_role}")
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                                detail=role_denied_detail(principal.role, self.permission))
        return principal


async def _audit_denial(request: Request, ctx: AccessContext, engine: Engine, *, action: str, reason: str) -> None:
    from backend.utilities.rbac import audit  # import here: audit imports this module's types

    request.state.audit_denied = True  # the middleware does not record this refusal a second time
    try:
        await run_in_threadpool(audit.record_from_context, engine, ctx, request_meta(request), action=action,
                                outcome="denied", extra={"reason": reason})
    except Exception as exc:  # never turn a refusal into a 500; the log keeps the failure
        log.error("audit: could not record a refused request (%s)", type(exc).__name__)


def request_meta(request: Request) -> dict:
    """The client as the audit log records it: ``request.client.host`` only (uvicorn applies X-Forwarded-For when,
    and only when, the proxy is in FORWARDED_ALLOW_IPS; the header itself is client-controlled and never read)."""
    return {
        "ip": (request.client.host if request.client else "")[:64] or None,
        "user_agent": (request.headers.get("user-agent") or "")[:200] or None,
        "method": request.method,
    }


class Access:
    """The policies of one router, bound to how that router reaches the database (its own ``get_db``, which the
    tests replace per module)."""

    def __init__(self, engine_getter: EngineGetter):
        self.engine_getter = engine_getter

    def team(self, permission: str):
        from fastapi import Depends
        return Depends(TeamPermission(permission, self.engine_getter))

    def authenticated(self, *, allow_inactive_session: bool = False, audited: bool = False):
        from fastapi import Depends
        return Depends(Authenticated(self.engine_getter, allow_inactive_session=allow_inactive_session,
                                     audited=audited))

    def platform_admin(self, *, audited: bool = False):
        from fastapi import Depends
        return Depends(PlatformAdmin(self.engine_getter, audited=audited))


def public(reason: str):
    from fastapi import Depends
    return Depends(Public(reason))


def machine(credential: str, reason: str):
    from fastapi import Depends
    return Depends(Machine(credential, reason))


def context(request: Request) -> Optional[AccessContext]:
    return getattr(request.state, "access", None)


# ------------------------------------------------------------------------------------------- permission markers
# Parallel tracks (F1, F3) may declare a route's permission without importing this module:
#     @router.get(BASE + "/fleet/...", openapi_extra={"x-zs-permission": "cbom.fleet.read"})
# ``PermissionMarker`` is an app-level dependency (backend/main.py) that enforces such a marker exactly like
# ``access.team(name)`` on every route that declares no AccessPolicy of its own.  The coverage check accepts a marker
# only on a {team_id} route, with a permission that exists in the matrix, on an app that has the enforcer.

PERMISSION_MARKER = "x-zs-permission"


def marker_of(route) -> Optional[str]:
    extra = getattr(route, "openapi_extra", None) or {}
    value = extra.get(PERMISSION_MARKER) if isinstance(extra, dict) else None
    return value if isinstance(value, str) else None


def declared_policies(route) -> list:
    dependant = getattr(route, "dependant", None)
    return [d.call for d in (dependant.dependencies if dependant else []) if isinstance(d.call, AccessPolicy)]


def _engine_for(route) -> EngineGetter:
    """The database the route's own handler uses: its module's ``get_db`` (the CBOM Sources routers reach it through
    ``cbom_sources.http``), looked up on every call so a test that replaces it is honoured."""
    import sys

    module_name = getattr(getattr(route, "endpoint", None), "__module__", "")

    def getter() -> Engine:
        module = sys.modules.get(module_name)
        if module is not None and callable(getattr(module, "get_db", None)):
            return module.get_db()
        if "cbom" in module_name or "integrations" in module_name:
            from backend.utilities.cbom_sources import http as cbom_http
            return cbom_http.get_db()
        from backend import get_db as get_db_module
        return get_db_module.get_db()

    return getter


class PermissionMarker:
    """App-level dependency: enforces ``x-zs-permission`` on routes without an AccessPolicy (see above)."""

    def __init__(self):
        self._policies: dict[int, Optional[TeamPermission]] = {}

    def _policy_for(self, route) -> Optional[TeamPermission]:
        key = id(route)
        if key not in self._policies:
            name = marker_of(route)
            self._policies[key] = (TeamPermission(name, _engine_for(route))
                                   if name and not declared_policies(route) else None)
        return self._policies[key]

    async def __call__(self, request: Request) -> None:
        policy = self._policy_for(request.scope.get("route"))
        if policy is not None:
            await policy(request)
