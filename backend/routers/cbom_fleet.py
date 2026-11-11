"""CBOM fleet onboarding: the one router ``backend/main.py`` includes for every F1 part (contract section 5).

All routes are ``/{team_id}/cbom/sources/fleet/...`` (plus F1.4's node route) and follow the CBOM Sources
conventions (``backend/utilities/cbom_sources/http.py``): members only, another team's or a missing record is a 404,
in-team refusals are a 400 (never a 403, which signs the user out of the frontend), stale forms get a 409, validation
errors are a 400 that never echoes input.  Every route declares ``openapi_extra={"x-zs-permission": ...}``.

Each part's routes sit behind its feature flag (``fleet/flags.py``, section 6): a route whose flag is off does not
exist (404).  ``GET /fleet/status`` is always there, so the frontend can hide what is off.

F1.3 and F1.4 add their ``router.include_router(...)`` lines under their marker below and nowhere else.
"""
from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Header
from fastapi.responses import JSONResponse

from backend.utilities.cbom_sources.fleet import flags as FLAGS
from backend.utilities.cbom_sources.fleet.http import FLEET, permission
from backend.utilities.cbom_sources.http import PRIVATE, CbomRoute, TeamId, authorize, read_limiter

router = APIRouter(tags=["cbom-fleet"], route_class=CbomRoute)
AuthHeader = Annotated[str | None, Header()]
READ = [Depends(read_limiter)]


@router.get(FLEET + "/status", dependencies=READ, openapi_extra=permission("cbom.fleet.read"),
            summary="Which fleet features are turned on in this deployment")
async def fleet_status(team_id: TeamId, Authorization: AuthHeader = None):
    await authorize(team_id, Authorization)
    return JSONResponse(FLAGS.status(), headers=PRIVATE)


# F1.2 routers
from backend.routers.cbom_fleet_inventory import router as _inventory_router  # noqa: E402
from backend.routers.cbom_fleet_policies import router as _policies_router  # noqa: E402

router.include_router(_inventory_router)  # /fleet/inventory/* (CBOM_FLEET_INVENTORY)
router.include_router(_policies_router)  # /fleet/policies*, /fleet/credentials*, /fleet/reconcile (CBOM_FLEET_POLICIES)

# F1.3 routers

# F1.4 routers
