"""Where the hosted CBOM gate finds its policy: the integration's override, else the team's policy, else the default.

Rows are ``cbom_gate_models.CbomGatePolicy`` (``scope`` = ``team`` or ``integration:<id>``). A stored policy was
validated when it was saved; it is validated again on read (``for_save=False``: an exception that has expired since
then simply waives nothing). A row that no longer validates (a later format change) is never ignored silently: the
gate then uses the strict ``cnsa-2.0`` preset and says so in the verdict's source, so it fails closed rather than open.
"""
from __future__ import annotations

from typing import Any

from sqlmodel import Session, select

from backend.cbom_gate_models import CbomGatePolicy
from backend.utilities.cicd import gate_policy as GP

TEAM_SCOPE = "team"


def integration_scope(integration_id: int) -> str:
    return f"integration:{int(integration_id)}"


def row_for(session: Session, team_id: int, scope: str) -> CbomGatePolicy | None:
    return session.exec(select(CbomGatePolicy).where(CbomGatePolicy.team_id == team_id,
                                                     CbomGatePolicy.scope == scope)).first()


def effective_policy(session: Session, team_id: int, integration_id: int | None) -> tuple[dict[str, Any], str, int | None]:
    """(policy, source, version): source is ``integration``, ``team``, ``default`` or ``unreadable``."""
    rows: list[tuple[str, CbomGatePolicy | None]] = []
    if integration_id is not None:
        rows.append(("integration", row_for(session, team_id, integration_scope(integration_id))))
    rows.append(("team", row_for(session, team_id, TEAM_SCOPE)))
    for source, row in rows:
        if row is None:
            continue
        try:
            return GP.validate_policy(row.policy), source, row.row_version
        except GP.PolicyError:
            return GP.PRESETS["cnsa-2.0"], "unreadable", row.row_version
    return GP.DEFAULT_POLICY, "default", None
