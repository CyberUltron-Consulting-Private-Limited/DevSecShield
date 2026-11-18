"""Team-scoped CBOM API keys (issue #226): long-lived, scoped credentials for scripted onboarding.

* A team admin creates a named key with one or more scopes and an optional expiry.  The secret
  (``zsk_`` + 43 URL-safe characters, 256 random bits) is returned once; only its SHA-256 is stored, with its last
  four characters as a hint.  The ``zsk_`` prefix lets secret scanners find a leaked key
  (``zsk_[A-Za-z0-9_-]{43}``).  There is no plaintext fallback lookup (issue #146).
* ``Authorization: Bearer zsk_...`` is accepted only by ``http.authorize`` on the routes listed in ``ROUTE_SCOPES``
  (CBOM Sources items, runs and their exports), only for the key's own team and only with the scope the route needs.
  Every other route refuses it: the CBOM routes that call ``authorize`` with 403 (deny by default: a route missing
  from ``ROUTE_SCOPES`` is refused), every other route with 401 (a key is not a JWT, so
  ``get_user_from_header_or_raise_exception`` never accepts it): account settings, team and billing, the key
  management routes themselves, other products.
* A key acts as the admin who created it (sources and runs it creates are theirs), and only while that person is
  still an admin of the team (aligned with PR #42: a key works only while its creator still holds the role that
  made it).  Its writes are marked in the CBOM audit log as ``actor_type="api_key"``, ``actor_id=<key id>``.
* Every use is rate-limited per key (``ratelimit.user_key`` charges a verified key to ``("apikey", id)``) and
  audited (``api_key.use`` with the route; ``api_key.refused`` with the reason, under the key's own team), and
  updates ``last_used_at``.  Nothing here logs the secret, any part of it, or its hash.

Alembic sees ``cbomapikey`` because ``prod_database_migrations/migrations/env.py`` imports this module (migration
``cb226apikey001``).
"""
from __future__ import annotations

import contextvars
import datetime as _dt
import re
import secrets
from typing import Any

from fastapi import HTTPException, Request
from sqlalchemy import Index
from sqlmodel import JSON, Column, DateTime, Field, Session, SQLModel, select

from backend.get_db import get_db
from backend.new_models import TeamMembership, User, _cbom_utcnow
from backend.utilities.cbom_sources.common import iso_z, log, sha256_hex, utcnow

PREFIX = "zsk_"
SECRET_RE = re.compile(r"^zsk_[A-Za-z0-9_-]{43}$")
MAX_ACTIVE_KEYS = 25
MAX_EXPIRY_DAYS = 730
ADMIN_ROLES = ("admin", "owner")  # owners hold every admin right (PR #42, utilities/rbac)

READ = "cbom.read"
SOURCES_WRITE = "cbom.sources:write"
RUNS_WRITE = "cbom.runs:write"
SCOPES: dict[str, str] = {
    READ: "Read sources, scan nodes, runs, run results and exports (CycloneDX CBOM).",
    SOURCES_WRITE: "Add, change, test and remove sources. Includes cbom.read.",
    RUNS_WRITE: "Price, start and cancel runs. Includes cbom.read.",
}
# a write scope includes reading (a sync job that adds sources needs to read them back)
IMPLIED: dict[str, frozenset[str]] = {
    READ: frozenset({READ}),
    SOURCES_WRITE: frozenset({READ, SOURCES_WRITE}),
    RUNS_WRITE: frozenset({READ, RUNS_WRITE}),
}

_S = "/{team_id}/cbom/sources"
# The ONLY routes a key may call: (method, route path) -> scope.  Anything else that calls ``authorize`` refuses a
# key (deny by default).  Not here on purpose: settings and stop-all, node create / change / registration tokens
# (enrolment secrets), evidence and vendor links, discovery, templates, the audit log, ticketing, AI, fleet.
ROUTE_SCOPES: dict[tuple[str, str], str] = {
    ("GET", _S + "/overview"): READ,
    ("GET", _S + "/nodes"): READ,
    ("GET", _S + "/nodes/{node_id}"): READ,
    ("GET", _S + "/items"): READ,
    ("GET", _S + "/items/{source_id}"): READ,
    ("POST", _S + "/items"): SOURCES_WRITE,
    ("PATCH", _S + "/items/{source_id}"): SOURCES_WRITE,
    ("DELETE", _S + "/items/{source_id}"): SOURCES_WRITE,
    ("POST", _S + "/items/{source_id}/test"): SOURCES_WRITE,
    ("POST", _S + "/targets/count"): READ,
    ("GET", _S + "/jobs/{job_id}"): READ,
    ("GET", _S + "/jobs/{job_id}/assets"): READ,
    ("POST", _S + "/estimate"): READ,
    ("POST", _S + "/runs"): RUNS_WRITE,
    ("GET", _S + "/runs"): READ,
    ("GET", _S + "/runs/{run_id}"): READ,
    ("POST", _S + "/runs/{run_id}/cancel"): RUNS_WRITE,
    ("GET", _S + "/runs/{run_id}/assets"): READ,
    ("GET", _S + "/runs/{run_id}/results"): READ,
    ("GET", _S + "/runs/{run_id}/posture"): READ,
    ("GET", _S + "/runs/{run_id}/cbom"): READ,
    ("GET", _S + "/runs/{run_id}/oscal"): READ,
    ("GET", _S + "/runs/{run_id}/diff"): READ,
    ("GET", _S + "/runs/{run_id}/changes"): READ,
    ("GET", _S + "/runs/{run_id}/heatmap"): READ,
}

# Key management answers a key as "not a session" (401), like every route outside the CBOM routers: a key never
# lists, creates or revokes keys.
SESSION_ONLY_PREFIXES: tuple[str, ...] = ("/{team_id}/cbom/api-keys",)


def checked_by_authorize(request: Request) -> bool:
    """Would this route's handler hand a ``zsk_`` key to ``authorize`` (which answers 200 or an audited 403)?  True for
    a ``CbomRoute`` route outside ``SESSION_ONLY_PREFIXES``; every other route treats the key as a bad session token
    (401).  The F4 route policy (utilities/rbac/policy.py) uses this to answer exactly as the handler would."""
    from backend.utilities.cbom_sources.http import CbomRoute  # http imports this module

    route = request.scope.get("route")
    path = getattr(route, "path", "") or ""
    return isinstance(route, CbomRoute) and not path.startswith(SESSION_ONLY_PREFIXES)


# The request being served by a ``CbomRoute`` (set by its route handler) and the key it was authenticated with.
_REQUEST: contextvars.ContextVar[Request | None] = contextvars.ContextVar("cbom_api_key_request", default=None)
_ACTIVE_KEY: contextvars.ContextVar[int | None] = contextvars.ContextVar("cbom_api_key_active", default=None)


class CbomApiKey(SQLModel, table=True):
    """A team's CBOM API key.  ``key_hash`` is the SHA-256 of the secret; the secret itself is never stored."""
    __tablename__ = "cbomapikey"
    __table_args__ = (Index("ix_cbomapikey_team_created", "team_id", "created_at"),)
    id: int | None = Field(default=None, primary_key=True)
    team_id: int = Field(foreign_key="team.id", index=True)
    name: str = Field(max_length=64)
    scopes: list | None = Field(default_factory=list, sa_column=Column(JSON))
    key_hash: str = Field(max_length=64, unique=True)
    hint: str = Field(max_length=4)  # the secret's last four characters, to tell keys apart
    # a plain int like ``CbomCollectionSchedule.owner_user_id``: deleting the account must not be blocked by its keys
    # (a key whose creator is gone, or no longer a team admin, is refused on use)
    created_by_user_id: int
    created_at: _dt.datetime | None = Field(default_factory=_cbom_utcnow, sa_type=DateTime)
    expires_at: _dt.datetime | None = Field(default=None, sa_type=DateTime)
    revoked_at: _dt.datetime | None = Field(default=None, sa_type=DateTime)
    revoked_by_user_id: int | None = Field(default=None)
    last_used_at: _dt.datetime | None = Field(default=None, sa_type=DateTime)


# ----------------------------------------------------------------------------- secrets
def new_secret() -> str:
    return f"{PREFIX}{secrets.token_urlsafe(32)}"


def looks_like_key(token: str | None) -> bool:
    return bool(token) and token.startswith(PREFIX)  # type: ignore[union-attr]


def status_of(row: CbomApiKey, now: _dt.datetime) -> str:
    if row.revoked_at is not None:
        return "revoked"
    if row.expires_at is not None and row.expires_at <= now:
        return "expired"
    return "active"


def public_key(row: CbomApiKey, now: _dt.datetime, creator_email: str | None = None) -> dict[str, Any]:
    """What the API returns about a key: never the secret and never its hash."""
    return {"id": row.id, "name": row.name, "scopes": list(row.scopes or []), "hint": row.hint,
            "status": status_of(row, now), "created_at": iso_z(row.created_at), "created_by": creator_email,
            "expires_at": iso_z(row.expires_at), "revoked_at": iso_z(row.revoked_at),
            "last_used_at": iso_z(row.last_used_at)}


def _lookup(session: Session, token: str) -> CbomApiKey | None:
    if not SECRET_RE.match(token):
        return None
    return session.exec(select(CbomApiKey).where(CbomApiKey.key_hash == sha256_hex(token))).first()


def verified_key_id(token: str) -> int | None:
    """The id of a live (not revoked, not expired) key, for the rate limiter; None otherwise."""
    if not looks_like_key(token) or len(token) > 128:
        return None
    with Session(get_db()) as session:
        row = _lookup(session, token)
        return row.id if row is not None and status_of(row, utcnow()) == "active" else None


# ----------------------------------------------------------------------------- request context
def enter_request(request: Request) -> tuple[contextvars.Token, contextvars.Token]:
    return _REQUEST.set(request), _ACTIVE_KEY.set(None)


def leave_request(tokens: tuple[contextvars.Token, contextvars.Token]) -> None:
    _REQUEST.reset(tokens[0])
    _ACTIVE_KEY.reset(tokens[1])


def active_key_id() -> int | None:
    """The key the current request was authenticated with, else None (``common.audit`` marks machine writes)."""
    return _ACTIVE_KEY.get()


def _route_of(request: Request | None) -> tuple[str, str] | None:
    if request is None:
        return None
    route = request.scope.get("route")
    path = getattr(route, "path", None)
    return (request.method.upper(), path) if path else None


# ----------------------------------------------------------------------------- authentication
def _audit_key(session: Session, row: CbomApiKey, action: str, fields: list[str]) -> None:
    from backend.new_models import CbomCollectionAuditEvent  # one table with the rest of the CBOM audit log
    session.add(CbomCollectionAuditEvent(team_id=row.team_id, actor_type="api_key", actor_id=row.id, action=action,
                                         object_type="api_key", object_id=row.id,
                                         changed_fields=[f[:64] for f in fields]))


def _refuse(session: Session, row: CbomApiKey, reason: str, route: tuple[str, str] | None, status: int,
            detail: str) -> HTTPException:
    _audit_key(session, row, "api_key.refused", [reason] + ([f"{route[0]} {route[1]}"] if route else []))
    session.commit()
    log("api key refused", team=row.team_id, key=row.id, reason=reason,
        route=f"{route[0]} {route[1]}" if route else None)
    return HTTPException(status_code=status, detail=detail)


def remember_verified(request: Request, team_id: int, token: str, user: User, key_id: int) -> None:
    """The route's access policy (utilities/rbac/policy.py) verified this key for this request: ``authorize`` then
    reuses the result instead of checking (and auditing) the key a second time."""
    request.state.cbom_api_key = (team_id, sha256_hex(token), user, key_id)


def verified_for(team_id: int, token: str) -> tuple[User, int] | None:
    """(user, key id) when the access policy already verified exactly this key for this team in this request."""
    request = _REQUEST.get()
    held = getattr(getattr(request, "state", None), "cbom_api_key", None) if request is not None else None
    if held and held[0] == team_id and held[1] == sha256_hex(token):
        return held[2], held[3]
    return None


def mark_active(key_id: int) -> None:
    """Called in the request's own (async) context: a value set inside ``run_in_threadpool`` would not come back."""
    _ACTIVE_KEY.set(key_id)


def authenticate(engine, team_id: int, token: str) -> tuple[User, int]:
    """Check a ``zsk_`` key for the current request on ``team_id``; return (the user it acts as, the key id).

    401: unknown, malformed, revoked or expired.  403: another team, a route keys may not call, a missing scope, or
    a creator who is no longer a team admin.  Every outcome on a known key is audited under the key's own team."""
    now = utcnow()
    route = _route_of(_REQUEST.get())
    with Session(engine) as session:
        row = _lookup(session, token) if len(token) <= 128 else None
        if row is None:
            log("api key refused", reason="unknown")
            raise HTTPException(status_code=401, detail="Invalid API key")
        state = status_of(row, now)
        if state == "revoked":
            raise _refuse(session, row, "revoked", route, 401, "This API key was revoked")
        if state == "expired":
            raise _refuse(session, row, "expired", route, 401,
                          f"This API key expired at {iso_z(row.expires_at)}; ask a team admin for a new one")
        if row.team_id != team_id:
            raise _refuse(session, row, "team", route, 403, "This API key belongs to another team")
        scope = ROUTE_SCOPES.get(route) if route else None
        if scope is None:
            raise _refuse(session, row, "route", route, 403,
                          "API keys cannot call this route; it needs a signed-in team member")
        granted = set().union(*(IMPLIED.get(s, frozenset()) for s in (row.scopes or [])))
        if scope not in granted:
            raise _refuse(session, row, "scope", route, 403, f"This API key lacks the {scope} scope")
        membership = session.exec(select(TeamMembership).where(TeamMembership.team_id == row.team_id,
                                                                TeamMembership.user_id == row.created_by_user_id)).first()
        user = session.get(User, row.created_by_user_id)
        if user is None or membership is None or membership.role not in ADMIN_ROLES:
            raise _refuse(session, row, "creator", route, 403,
                          "The admin who created this API key is no longer a team admin; create a new key")
        row.last_used_at = now
        session.add(row)
        _audit_key(session, row, "api_key.use", [f"{route[0]} {route[1]}"])  # type: ignore[index]
        session.commit()
        session.refresh(user)
        session.expunge(user)
        return user, row.id  # type: ignore[return-value]
