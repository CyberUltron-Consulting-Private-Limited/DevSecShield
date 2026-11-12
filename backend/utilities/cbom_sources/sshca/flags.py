"""``CBOM_SSH_CA`` (F1 contract, section 6), default off, read on every request (no restart; tests switch it).

Off: the SSH CA routes and the node certificate route do not exist (404, F1.2's ``fleet.flags.flagged_route``),
``credential_type: ssh_ca`` is refused when a source is saved, and the claim plugin does nothing.
"""
from __future__ import annotations

from backend.utilities.cbom_sources.fleet.flags import env_flag, flagged_route

ENV = "CBOM_SSH_CA"
OFF_MESSAGE = "SSH CA certificates are turned off in this deployment"


def enabled() -> bool:
    return env_flag(ENV)


def route_class():
    """The route class of every SSH CA route: a ``CbomRoute`` that exists only while the flag is on."""
    return flagged_route(ENV)
