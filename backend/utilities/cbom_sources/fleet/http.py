"""HTTP helpers shared by the fleet routers (contract section 3, common rules).

Each fleet route declares the permission F4's route-coverage test reads, ``openapi_extra={"x-zs-permission": ...}``,
and enforces it today with the existing CBOM Sources helpers (member check in ``authorize``; ``require_admin`` for
writes, a 400 inside the team, never a 403).
"""
from __future__ import annotations

from typing import Any

FLEET = "/{team_id}/cbom/sources/fleet"

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
