"""CBOM fleet onboarding: the one router ``backend/main.py`` includes for every F1 part (contract section 5).

All routes are ``/{team_id}/cbom/sources/fleet/...`` (plus F1.4's node route) and follow the CBOM Sources
conventions (``backend/utilities/cbom_sources/http.py``): members only, another team's or a missing record is a 404,
in-team refusals are a 400 (never a 403, which signs the user out of the frontend), stale forms get a 409, validation
errors are a 400 that never echoes input.  Every route declares ``openapi_extra={"x-zs-permission": ...}``.

Rules every part's router follows (``test_cbom_fleet_scaffold`` checks every route of this aggregator, flags on):
* team routes take ``ctx: Member`` (``fleet/http.py``): authentication is a dependency that runs after the rate
  limiter, never only an ``authorize()`` call in the handler body;
* the route class is a ``CbomRoute`` behind the part's flag (``fleet/flags.py``, ``flagged_route(...)``), so a route
  whose flag is off does not exist (404) and a bad body is a readable 400, never a 422 that echoes the input.
  ``GET /fleet/status`` is the one unflagged route, so the frontend can hide what is off.

F1.3 and F1.4 add their import under their ``imports`` marker and their ``router.include_router(...)`` line under their
``routers`` marker, and nowhere else.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse

from backend.utilities.cbom_sources.fleet import flags as FLAGS
from backend.utilities.cbom_sources.fleet.http import FLEET, Member, permission
from backend.utilities.cbom_sources.http import PRIVATE, CbomRoute, TeamId, read_limiter

# F1.2 imports
from backend.routers.cbom_fleet_inventory import router as inventory_router
from backend.routers.cbom_fleet_policies import router as policies_router
# F1.3 imports
# F1.4 imports

router = APIRouter(tags=["cbom-fleet"], route_class=CbomRoute)
READ = [Depends(read_limiter)]


@router.get(FLEET + "/status", dependencies=READ, openapi_extra=permission("cbom.fleet.read"),
            summary="Which fleet features are turned on in this deployment")
async def fleet_status(team_id: TeamId, ctx: Member):
    return JSONResponse(FLAGS.status(), headers=PRIVATE)


# F1.2 routers
router.include_router(inventory_router)  # /fleet/inventory/* (CBOM_FLEET_INVENTORY)
router.include_router(policies_router)  # /fleet/policies*, /fleet/credentials*, /fleet/reconcile (CBOM_FLEET_POLICIES)

# F1.3 routers

# F1.4 routers
