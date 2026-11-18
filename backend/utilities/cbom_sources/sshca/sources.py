"""Who may save a source that logs in with the team's SSH CA (``credential_type: ssh_ca``), and who approved it.

The CA is a team-wide login credential: whoever writes an ``ssh_ca`` source chooses which servers (targets), which
groups (principals) and which addresses the team's CA certifies the scan node for.  So, like the vault credential
(``routers/cbom_sources.py``), only a team admin writes one:

* creating an ``ssh_ca`` source, switching a source to or from ``ssh_ca``, and ANY save of an ``ssh_ca`` source (a
  rename, a new node, turning it back on, or a save with no change) needs a team admin;
* turning it off is open to whoever may edit the source (stopping collection is always allowed);
* principals must be this team's (``zs-<team>-<group>``), checked here because the config model does not know the team.

An enabled ``ssh_ca`` source is therefore always last saved by someone who was an admin at that moment.  The mint
(``issue._check``) still requires that the last saver IS an admin, so an offboarded or demoted admin's sources stop;
``needing_admin_save`` lists them for the team, and an admin's save (even with no change) approves one again: it
counts as a change (``ssh_ca.approved`` in the ``source.update`` audit row, ``updated_by_user_id``, ``row_version``).
"""
from __future__ import annotations

from typing import Any

from fastapi import HTTPException
from sqlmodel import Session, select

from backend.new_models import CbomCollectionSource, TeamMembership
from backend.utilities.cbom_sources.http import is_team_admin, require_admin
from backend.utilities.cbom_sources.sshca import certs as C

ADMIN_WHAT = "sources that log in with the team's SSH CA"
APPROVED = "ssh_ca.approved"
KINDS_WITH_CA = ("linux_servers",)
MAX_LISTED = 50


def uses_ca(cfg: Any) -> bool:
    return getattr(cfg, "credential_type", None) == "ssh_ca"


def _check_principals(cfg: Any, team_id: int) -> None:
    for principal in getattr(cfg, "ssh_principals", None) or []:
        problem = C.principal_problem(principal, team_id)
        if problem:
            raise HTTPException(status_code=400, detail=f"ssh_principals: {problem}")


def check_create(session: Session, team_id: int, user_id: int, cfg: Any) -> None:
    """Called by ``_create_source`` (raises the usual 400)."""
    if not uses_ca(cfg):
        return
    require_admin(session, user_id, team_id, ADMIN_WHAT)
    _check_principals(cfg, team_id)


def check_update(session: Session, team_id: int, user_id: int, source: CbomCollectionSource, old_cfg: Any, cfg: Any,
                 *, relevant: bool, name: str | None, enabled: bool | None) -> None:
    """Called by ``_update_source`` once it knows what the request changes (``relevant``: the config, the node or
    the secrets).  Only turning the source off is open to a member."""
    if not (uses_ca(cfg) or uses_ca(old_cfg)):
        return
    renaming = name is not None and name != source.name
    turning_off_only = enabled is False and not relevant and not renaming
    if not turning_off_only:
        require_admin(session, user_id, team_id, ADMIN_WHAT)
    if uses_ca(cfg) and relevant:
        _check_principals(cfg, team_id)


def saved_by(source: CbomCollectionSource) -> int | None:
    return source.updated_by_user_id or source.owner_user_id


def needs_admin_save(session: Session, source: CbomCollectionSource) -> bool:
    who = saved_by(source)
    return not who or not is_team_admin(session, who, source.team_id)


def approval(session: Session, team_id: int, user_id: int, source: CbomCollectionSource, cfg: Any) -> set[str]:
    """``{"ssh_ca.approved"}`` when this save (by an admin, ``check_update`` ran) approves an ``ssh_ca`` source whose
    last saver is no longer an admin; the caller then records it as a change."""
    if uses_ca(cfg) and needs_admin_save(session, source) and is_team_admin(session, user_id, team_id):
        return {APPROVED}
    return set()


def needing_admin_save(session: Session, team_id: int) -> tuple[list[dict[str, Any]], int]:
    """Enabled ``ssh_ca`` sources whose last saver is no longer a team admin (offboarding): they get no certificate
    until an admin saves them.  (first ``MAX_LISTED`` of them, total)."""
    admins = set(session.exec(select(TeamMembership.user_id).where(TeamMembership.team_id == team_id,
                                                                   TeamMembership.role == "admin")).all())
    rows = session.exec(select(CbomCollectionSource).where(
        CbomCollectionSource.team_id == team_id, CbomCollectionSource.kind.in_(KINDS_WITH_CA),  # type: ignore[attr-defined]
        CbomCollectionSource.enabled.is_(True)).order_by(CbomCollectionSource.id)).all()  # type: ignore[attr-defined]
    found = [{"id": r.id, "name": r.name} for r in rows
             if isinstance(r.config, dict) and r.config.get("credential_type") == "ssh_ca" and saved_by(r) not in admins]
    return found[:MAX_LISTED], len(found)
