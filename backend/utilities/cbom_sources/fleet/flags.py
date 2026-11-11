"""Feature flags of the fleet routes (F1 contract, section 6).  Every flag is an environment variable, default off, read
on every request (no restart, and tests can switch it).

A route behind a flag that is off does not exist: its route class reports "no match" to the router, so the request
gets the router's own 404 ``Not Found`` (or another route's answer), before authentication, before the body is read,
and with no 405 for a wrong method.  The flagged route class is a ``CbomRoute``, so with the flag on, validation
errors are the usual readable 400.

Other parts guard their routes the same way with their own variable, e.g.
``APIRouter(route_class=flagged_route("CBOM_FLEET_TRANSPORTS"))``.
"""
from __future__ import annotations

import functools
import os
import re

from starlette.routing import Match
from starlette.types import Scope

from backend.utilities.cbom_sources.http import CbomRoute

# F1.2's own flags.  CBOM_FLEET_TRANSPORTS (F1.3, transports/flags.py) and CBOM_SSH_CA (F1.4, sshca/flags.py) belong to
# the other parts; /fleet/status reads all four variables directly (contract section 3).
ENV = {
    "inventory": "CBOM_FLEET_INVENTORY",
    "policies": "CBOM_FLEET_POLICIES",
    "materialize": "CBOM_FLEET_MATERIALIZE",
}
STATUS_ENV = {
    "inventory": "CBOM_FLEET_INVENTORY",
    "policies": "CBOM_FLEET_POLICIES",
    "transports": "CBOM_FLEET_TRANSPORTS",
    "ssh_ca": "CBOM_SSH_CA",
}
_ON = frozenset({"1", "true", "yes", "on"})
_NAME = re.compile(r"^CBOM_[A-Z0-9_]{1,60}$")


def env_flag(name: str) -> bool:
    """True when the variable is 1 / true / yes / on (any case, surrounding spaces ignored)."""
    return os.environ.get(name, "").strip().lower() in _ON


def inventory_enabled() -> bool:
    return env_flag(ENV["inventory"])


def policies_enabled() -> bool:
    return env_flag(ENV["policies"])


def materialize_enabled() -> bool:
    """Policies may write managed sources and schedules (otherwise they evaluate and preview only)."""
    return env_flag(ENV["materialize"])


def status() -> dict[str, bool]:
    return {key: env_flag(name) for key, name in STATUS_ENV.items()}


@functools.cache
def flagged_route(env_name: str) -> type[CbomRoute]:
    """A ``CbomRoute`` class whose routes exist only while ``env_name`` is on.  One class per variable."""
    if not _NAME.match(env_name):
        raise ValueError(f"not a CBOM feature flag: {env_name!r}")

    class FlaggedRoute(CbomRoute):
        flag_env = env_name

        def matches(self, scope: Scope) -> tuple[Match, Scope]:
            if not env_flag(env_name):
                return Match.NONE, {}
            return super().matches(scope)

    FlaggedRoute.__name__ = FlaggedRoute.__qualname__ = f"FlaggedRoute_{env_name}"
    return FlaggedRoute


def route_class(flag: str) -> type[CbomRoute]:
    """The route class for one of F1.2's flags (``inventory`` / ``policies``); an unknown name is a KeyError."""
    return flagged_route(ENV[flag])
