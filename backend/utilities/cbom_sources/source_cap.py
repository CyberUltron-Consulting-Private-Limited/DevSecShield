"""How many sources a team may have (issue #224): one deployment-wide cap with an optional per-team override.

* ``CBOM_MAX_SOURCES`` (default 10,000; 1 - 1,000,000): the cap for every team. The same variable name as PR #41's
  limits module, so both read one setting.
* ``CBOM_MAX_SOURCES_TEAMS``: per-team overrides, ``<team id>:<cap>`` pairs separated by commas, for example
  ``12:25000, 40:800``. A team not listed uses ``CBOM_MAX_SOURCES``.

Both are read when used (an operator sets them once per deployment; tests set them per test). A missing, non-numeric or
out-of-range value falls back to the default and is logged once, never raising.

Every source of the team counts (hand-made, CMDB-imported and fleet-managed), as before. Why 10,000 by default (it was
500, hard-coded twice): the per-team paths that read every source stay well under a second at that size (timed in
``tests/test_cbom_source_cap_224.py::test_default_cap_is_backed_by_a_timing_at_that_many_sources``), and a CMDB file of
5,000 hosts in 500 owner/application groups, or 3,000 single-host databases, fits with room to spare.
"""
from __future__ import annotations

import os
from typing import Any

from sqlalchemy import func
from sqlmodel import Session, select

from backend.new_models import CbomCollectionSource
from backend.utilities.cbom_sources.common import log

ENV = "CBOM_MAX_SOURCES"
ENV_TEAMS = "CBOM_MAX_SOURCES_TEAMS"
DEFAULT = 10_000
LOW, HIGH = 1, 1_000_000
_warned: set[str] = set()


def _warn(name: str, raw: str) -> None:
    key = f"{name}={raw}"
    if key not in _warned:
        _warned.add(key)
        log("source cap setting ignored", name=name, value=raw[:64], default=DEFAULT, allowed=f"{LOW}-{HIGH}")


def _parse(raw: str) -> int | None:
    try:
        value = int(raw.strip().replace("_", ""))
    except ValueError:
        return None
    return value if LOW <= value <= HIGH else None


def deployment_cap() -> int:
    raw = os.environ.get(ENV, "").strip()
    if not raw:
        return DEFAULT
    value = _parse(raw)
    if value is None:
        _warn(ENV, raw)
        return DEFAULT
    return value


def team_overrides() -> dict[int, int]:
    raw = os.environ.get(ENV_TEAMS, "").strip()
    out: dict[int, int] = {}
    if not raw:
        return out
    for part in raw.split(","):
        if not part.strip():
            continue
        team, sep, cap = part.partition(":")
        value = _parse(cap) if sep else None
        if not team.strip().isdigit() or value is None:
            _warn(ENV_TEAMS, part.strip())
            continue
        out[int(team.strip())] = value
    return out


def max_sources(team_id: int) -> int:
    return team_overrides().get(int(team_id), deployment_cap())


def setting_name(team_id: int) -> str:
    """The variable an operator changes to raise this team's cap."""
    return ENV_TEAMS if int(team_id) in team_overrides() else ENV


def used(session: Session, team_id: int) -> int:
    return int(session.exec(select(func.count()).select_from(CbomCollectionSource)
                            .where(CbomCollectionSource.team_id == team_id)).one() or 0)


def usage(session: Session, team_id: int, *, count: int | None = None) -> dict[str, Any]:
    """``{"used", "max", "remaining", "setting"}`` for the Sources pages, the source form and the CMDB preview."""
    n = used(session, team_id) if count is None else count
    cap = max_sources(team_id)
    return {"used": n, "max": cap, "remaining": max(0, cap - n), "setting": setting_name(team_id)}


def refusal(usage_: dict[str, Any], adding: int = 1) -> str:
    """The message shown when ``adding`` more sources would pass the cap (safe to show; names the setting)."""
    what = "this source" if adding == 1 else f"these {adding:,} sources"
    return (f"A team can have at most {usage_['max']:,} sources and this team has {usage_['used']:,}, so {what} "
            f"cannot be added. Delete unused sources, or ask your operator to raise {usage_['setting']}.")
