"""HTTP helpers shared by the fleet routers (contract section 3, common rules).

* **Authentication is a dependency, never only a call in the handler body.**  Every team route under ``FLEET`` takes
  ``ctx: Member``: ``require_member`` runs ``authorize()`` (bearer token -> user -> member of the path's team; 401 /
  the existing 403 for a non-member) and returns ``(engine, user)``.  A route that forgets it fails
  ``test_cbom_fleet_scaffold`` (every route the app serves under ``FLEET``, whichever router registered it, and every
  route of the aggregator, checked with every flag on).  Declare the rate limiter in the decorator
  (``dependencies=READ`` / ``WRITE``) and ``ctx: Member`` as the first handler parameter after the path ids: nothing
  but the rate limiter may run before authentication (the guard reports any other dependency before
  ``require_member``, such as a body reader).  Do not put ``require_member`` on the router
  (``APIRouter(dependencies=...)``): router dependencies run before the route's, so requests over the limit would
  still reach the database.
* **Bodies.**  A pydantic body parameter (a model or ``dict``) is read and JSON-decoded by FastAPI before any
  dependency runs, the limiter and authentication included.  Small bodies may do that.  A route that accepts a large
  body (an inventory import, say) takes ``request: Request`` after ``ctx: Member`` and reads it in the handler with
  ``read_capped_json(request, LIMIT)`` (``backend/utilities/cbom_sources/http.py``; ``cbom_node.py`` does the same
  with ``read_capped_body``), so an anonymous or over-limit caller never gets the body read.
* Each route declares the permission F4's route-coverage test reads, ``openapi_extra=permission(...)``, and enforces
  it today with the existing CBOM Sources helpers (``require_admin`` for writes: a 400 inside the team, never a 403).
"""
from __future__ import annotations

from typing import Annotated, Any

from fastapi import Depends, Header

from backend.utilities.cbom_sources.http import TeamId, authorize

FLEET = "/{team_id}/cbom/sources/fleet"
AuthHeader = Annotated[str | None, Header()]

# permission -> today's check (contract section 3)
PERMISSIONS = {
    "cbom.fleet.read": "member",
    "cbom.inventory.write": "admin",
    "cbom.policies.write": "admin",
    "cbom.credentials.write": "admin",
    "cbom.transports.write": "admin",
    "cbom.sshca.admin": "admin",
}


def permission(name: str) -> dict[str, Any]:
    """``openapi_extra`` for a route; an unknown permission name is a KeyError at import time."""
    PERMISSIONS[name]  # noqa: B018 - validate the name
    return {"x-zs-permission": name}


async def require_member(team_id: TeamId, Authorization: AuthHeader = None) -> tuple:
    """The caller is a member of the path's team: ``(engine, user)``.  401 without a valid token; the existing 403
    for someone who is not a member (raised by ``check_if_user_is_in_team``)."""
    return await authorize(team_id, Authorization)


Member = Annotated[tuple, Depends(require_member)]
