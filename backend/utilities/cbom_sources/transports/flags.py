"""F1.3 feature flag (contract section 6): ``CBOM_FLEET_TRANSPORTS``, default off, read on every call.

Off: the transport routes do not exist (404, through ``fleet.flags.flagged_route``), fleet source kinds are refused at
save, ``collectable()`` is false, and the claim plugin gives no transport.  The value rule is the fleet flags' rule
(1 / true / yes / on, any case); it is repeated here so that ``kinds.py`` -> ``kinds_fleet.py`` -> this module does
not import the HTTP stack.
"""
from __future__ import annotations

import os

ENV = "CBOM_FLEET_TRANSPORTS"
_ON = frozenset({"1", "true", "yes", "on"})


def transports_enabled() -> bool:
    return os.environ.get(ENV, "").strip().lower() in _ON


def route_class():
    from backend.utilities.cbom_sources.fleet.flags import flagged_route  # F1.2-a0 (#34)

    return flagged_route(ENV)
