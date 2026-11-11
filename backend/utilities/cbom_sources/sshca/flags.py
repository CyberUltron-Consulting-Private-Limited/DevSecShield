"""``CBOM_SSH_CA`` (F1 contract, section 6), default off, read on every request (no restart; tests switch it).

Off: the SSH CA routes and the node certificate route do not exist (404), ``credential_type: ssh_ca`` is refused when a
source is saved, and the claim plugin does nothing.
"""
from __future__ import annotations

import os

ENV = "CBOM_SSH_CA"
_ON = frozenset({"1", "true", "yes", "on"})
OFF_MESSAGE = "SSH CA certificates are turned off in this deployment"


def enabled() -> bool:
    return os.environ.get(ENV, "").strip().lower() in _ON


def route_class():
    """The route class of every SSH CA route: a ``CbomRoute`` that exists only while the flag is on.

    F1.2's ``fleet.flags.flagged_route`` is the shared implementation once it is on dev; until then (optional-import
    seam, removed in the F1 integration PR) an equivalent local class is used."""
    try:
        from backend.utilities.cbom_sources.fleet.flags import flagged_route  # type: ignore[import-not-found]
    except ImportError:
        return _local_flagged_route()
    return flagged_route(ENV)


_LOCAL = None


def _local_flagged_route():
    global _LOCAL
    if _LOCAL is not None:
        return _LOCAL
    from starlette.routing import Match

    from backend.utilities.cbom_sources.http import CbomRoute

    class SshCaRoute(CbomRoute):
        flag_env = ENV

        def matches(self, scope):  # type: ignore[override]
            if not enabled():
                return Match.NONE, {}
            return super().matches(scope)

    _LOCAL = SshCaRoute
    return _LOCAL
