"""F1.3 source kinds (contract section 2): hosts collected through the customer's own automation, never over SSH by
ZeroShield.  Registered into ``kinds.KINDS`` by two lines at the end of ``kinds.py``.

* ``awx_hosts`` / ``salt_hosts``: run by a scan node (it reaches the customer's AWX/AAP or salt-api inside the network);
  the node needs the ``transport_awx`` / ``transport_salt`` capability (F1.1 ``capabilities.py``).
* ``ssm_hosts``: node-less, run by the cloud worker through AWS Systems Manager.
Same group (``servers``) and therefore the same credits as Linux servers: 0.2 per target per run, from ``RATES_C``.
A source holds at most ``transports.limits.MAX_FLEET_TARGETS_PER_SOURCE`` (200) hosts, so one job's assets fit the
per-attempt cap (see that module).
The transport's secrets are stored on the transport, not here, so a fleet source has no secret of its own.
"""
from __future__ import annotations

import re
from typing import Literal

from pydantic import Field, field_validator, model_validator

from backend.utilities.cbom_sources import targets as T
from backend.utilities.cbom_sources.kinds import KindSpec, _Source, _always, _never, check_window_grid
from backend.utilities.cbom_sources.transports.flags import transports_enabled
from backend.utilities.cbom_sources.transports.limits import MAX_FLEET_TARGETS_PER_SOURCE

MAX_HANDLE = 255
_HANDLE_RE = {
    "awx_hosts": re.compile(r"^[A-Za-z0-9._-]{1,255}$"),        # an Ansible host name (no limit-pattern characters)
    "salt_hosts": re.compile(r"^[A-Za-z0-9._@:-]{1,255}$"),     # a minion id / roster entry
    "ssm_hosts": re.compile(r"^(i-[0-9a-f]{8}([0-9a-f]{9})?|mi-[0-9a-f]{17})$"),  # an EC2 or hybrid managed instance
}


class FleetHostsConfig(_Source):
    transport_id: int = Field(ge=1)
    targets: list[str] = Field(default_factory=list, max_length=T.MAX_LINES)
    handles: dict[str, str] = Field(default_factory=dict)
    addresses: dict[str, list[str]] = Field(default_factory=dict)
    exclusions: list[str] = Field(default_factory=list, max_length=2000)
    tier: Literal[1, 2] = 1
    timeout_s: int = Field(default=300, ge=10, le=3600)
    window: Literal["network", "any", "custom"] = "network"
    custom_window: list[list[bool]] | None = None

    @field_validator("targets")
    @classmethod
    def _targets(cls, v: list[str]) -> list[str]:
        if len(T.clean_lines(v)) > MAX_FLEET_TARGETS_PER_SOURCE:
            raise ValueError(f"at most {MAX_FLEET_TARGETS_PER_SOURCE} hosts per fleet source (one run keeps at most "
                             "50,000 assets); split the hosts over several sources")
        return v

    @field_validator("handles")
    @classmethod
    def _handles(cls, v: dict[str, str]) -> dict[str, str]:
        if len(v) > MAX_FLEET_TARGETS_PER_SOURCE:
            raise ValueError(f"at most {MAX_FLEET_TARGETS_PER_SOURCE} handles")
        return {str(k).strip(): str(h).strip() for k, h in v.items()}

    @field_validator("addresses")
    @classmethod
    def _addresses(cls, v: dict[str, list[str]]) -> dict[str, list[str]]:
        if len(v) > MAX_FLEET_TARGETS_PER_SOURCE:
            raise ValueError(f"at most {MAX_FLEET_TARGETS_PER_SOURCE} address lists")
        out = {}
        for k, values in v.items():
            if len(values) > 16:
                raise ValueError("at most 16 addresses per target")
            out[str(k).strip()] = [str(a).strip() for a in values if str(a).strip()]
        return out

    @model_validator(mode="after")
    def _check(self) -> "FleetHostsConfig":
        if not transports_enabled():  # contract section 6: fleet kinds are refused while the flag is off
            raise ValueError("Transports are turned off in this deployment")
        # every target is one host (an address or a name): a transport addresses hosts, never ranges
        normalized = []
        for number, line in enumerate(T.clean_lines(self.targets), start=1):
            kind, value, canonical = T.parse_line(line)
            if kind == "net" and value[1] != value[2]:
                raise ValueError(f"Line {number}: {line!r} is a range; list each host of a fleet source")
            normalized.append(canonical)
        if not normalized:
            raise ValueError("Add at least one host")
        if len(set(normalized)) != len(normalized):
            raise ValueError("a host is listed twice")
        self.targets = normalized
        unknown = sorted(set(self.handles) - set(normalized))
        if unknown:
            raise ValueError(f"handles: {unknown[0]!r} is not one of the targets")
        unknown = sorted(set(self.addresses) - set(normalized))
        if unknown:
            raise ValueError(f"addresses: {unknown[0]!r} is not one of the targets")
        self.exclusions = T.parse_exclusions(self.exclusions).normalized
        if self.window == "custom":
            self.custom_window = check_window_grid(self.custom_window, allow_empty=False)
        else:
            self.custom_window = None
        return self


def _model(kind: str) -> type[FleetHostsConfig]:
    pattern = _HANDLE_RE[kind]

    class Config(FleetHostsConfig):
        @model_validator(mode="after")
        def _handle_shape(self) -> "Config":
            for target in self.targets:
                handle = self.handles.get(target, target)
                if not pattern.match(handle):
                    what = {"awx_hosts": "an AWX host name", "salt_hosts": "a minion id",
                            "ssm_hosts": "an instance id (i-... or mi-...)"}[kind]
                    raise ValueError(f"handles: {handle[:40]!r} (for {target}) is not {what}")
            return self

    Config.__name__ = Config.__qualname__ = f"FleetHostsConfig_{kind}"
    return Config


def _collectable(_cfg) -> bool:
    return transports_enabled()


_WHERE = ("transport_id", "targets", "handles")

FLEET_KINDS: dict[str, KindSpec] = {
    "awx_hosts": KindSpec("awx_hosts", "servers", "Hosts through AWX/AAP", _model("awx_hosts"), lambda c: set(),
                          frozenset(), _always, _collectable, _WHERE),
    "salt_hosts": KindSpec("salt_hosts", "servers", "Hosts through Salt", _model("salt_hosts"), lambda c: set(),
                           frozenset(), _always, _collectable, _WHERE),
    "ssm_hosts": KindSpec("ssm_hosts", "servers", "Hosts through AWS SSM", _model("ssm_hosts"), lambda c: set(),
                          frozenset(), _never, _collectable, _WHERE, node_less=True),
}
