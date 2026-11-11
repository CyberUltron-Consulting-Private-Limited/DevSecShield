"""The permission matrix: every team permission, the lowest role that holds it, and what it lets a person do.

This file is the one place that says who may do what inside a team.  Routes name a permission
(``access.team("scan.create")``, see ``policy.py``); the route-coverage test (tests/test_rbac_route_coverage.py)
fails when a route names none.  Roles are ordered: each role holds every permission of the roles below it.

    viewer  < member  < admin  < owner

* viewer: reads the team's scans, findings, reports, CBOM data and settings; changes nothing.
* member: runs the products (scans, DAST profiles, CBOM sources, CI/CD keys); the objects they create stay
  theirs (handlers keep the "creator or admin" rules).
* admin: runs the team: name, Jira and outbound integrations, CBOM network scope, members and invitations
  (member and viewer roles), the audit log.
* owner: everything, including admins' and owners' roles, deleting the team, SSO and SCIM.

Superusers (``User.is_superuser``, the platform operators of the admin console) hold no team role by being
superusers: they see a team only as one of its members.
"""
from __future__ import annotations

from dataclasses import dataclass

ROLES: tuple[str, ...] = ("viewer", "member", "admin", "owner")
ROLE_RANK = {role: rank for rank, role in enumerate(ROLES)}
ADMIN_ROLES: tuple[str, ...] = ("admin", "owner")
DEFAULT_INVITE_ROLE = "member"
ROLE_LABELS = {"viewer": "Viewer", "member": "Member", "admin": "Admin", "owner": "Owner"}


@dataclass(frozen=True)
class Permission:
    name: str
    min_role: str
    description: str  # completes "Your role (viewer) cannot ..."
    audited: bool  # a successful use is written to the audit log (every change; reads are not)


_ALL = (
    # the team itself
    Permission("team.read", "viewer", "view this team", False),
    Permission("team.update", "admin", "change the team's name or description", True),
    Permission("team.integrations.manage", "admin", "change the team's integrations (Jira, ServiceNow, SIEM, webhooks, OSCAL, CMDB)", True),
    Permission("integrations.read", "viewer", "view the team's integrations", False),
    Permission("team.members.invite", "admin", "invite people or manage invitations", True),
    Permission("team.members.remove", "admin", "remove members", True),
    Permission("team.members.role", "admin", "change members' roles", True),
    Permission("team.ownership.claim", "admin", "claim ownership of this team", True),
    Permission("team.delete", "owner", "delete the team", True),
    Permission("team.audit.read", "admin", "read the team's audit log", False),
    Permission("team.sso.manage", "owner", "change single sign-on", True),
    Permission("team.scim.manage", "owner", "change SCIM provisioning", True),
    # scans of every product (SAST, IaC, SBOM/SCA, LLM, MCP, leakage, discovery, DAST, CBOM, AI-BOM)
    Permission("scan.read", "viewer", "view scans and their reports", False),
    Permission("scan.create", "member", "create scans", True),
    Permission("scan.update", "member", "change or delete scans", True),
    Permission("scan.run", "member", "start, estimate or cancel scans", True),
    Permission("finding.triage", "member", "change findings or create tickets", True),
    Permission("finding.remediate", "member", "generate remediations", True),
    Permission("certin.write", "member", "add attestations or sign BOMs", True),
    # DAST saved profiles
    Permission("dast.read", "viewer", "view DAST profiles", False),
    Permission("dast.manage", "member", "change DAST profiles", True),
    Permission("dast.run", "member", "run DAST profiles", True),
    # CI/CD and (deprecated) guardrails API keys
    Permission("cicd.read", "viewer", "view CI/CD integrations", False),
    Permission("cicd.manage", "member", "change CI/CD integrations", True),
    Permission("guardrails.read", "viewer", "view guardrails integrations", False),
    Permission("guardrails.manage", "member", "change guardrails integrations", True),
    # CBOM Sources (scan nodes, sources, runs, evidence, schedules, remediation plan)
    Permission("cbom.read", "viewer", "view CBOM sources and runs", False),
    Permission("cbom.write", "member", "change CBOM sources, nodes, runs or evidence", True),
    Permission("cbom.settings", "admin", "change the team's CBOM network scope and settings", True),
    # F1 fleet onboarding (round6/f1/CONTRACT.md section 3): inventory, tag policies, transports, SSH CA
    Permission("cbom.fleet.read", "viewer", "view the fleet inventory, policies, transports and SSH CA", False),
    Permission("cbom.inventory.write", "admin", "change the fleet inventory", True),
    Permission("cbom.policies.write", "admin", "change tag policies", True),
    Permission("cbom.credentials.write", "admin", "change fleet credentials", True),
    Permission("cbom.transports.write", "admin", "change transports", True),
    Permission("cbom.sshca.admin", "admin", "manage the SSH certificate authority", True),
    # F3 repositories at scale: connected Git organisations (installations, tokens, filters) and their repositories
    Permission("repos.read", "viewer", "view connected repositories", False),
    Permission("repos.manage", "admin", "connect Git organisations or change their tokens and filters", True),
)

PERMISSIONS: dict[str, Permission] = {p.name: p for p in _ALL}
if len(PERMISSIONS) != len(_ALL):  # pragma: no cover - a duplicate name is a programming error
    raise RuntimeError("duplicate permission name in the RBAC matrix")
for _p in _ALL:
    if _p.min_role not in ROLE_RANK:  # pragma: no cover
        raise RuntimeError(f"permission {_p.name}: unknown role {_p.min_role}")


def is_role(value: object) -> bool:
    return isinstance(value, str) and value in ROLE_RANK


def get_permission(name: str) -> Permission:
    try:
        return PERMISSIONS[name]
    except KeyError:
        raise ValueError(f"unknown permission {name!r}: add it to backend/utilities/rbac/permissions.py") from None


def role_has(role: str | None, permission: str) -> bool:
    """True when ``role`` holds ``permission``.  An unknown or missing role holds nothing."""
    if not is_role(role):
        return False
    return ROLE_RANK[role] >= ROLE_RANK[get_permission(permission).min_role]  # type: ignore[index]


def permissions_for(role: str | None) -> list[str]:
    return sorted(p.name for p in _ALL if role_has(role, p.name))


def matrix() -> dict:
    """The matrix as data (GET /rbac/matrix, the UI and the docs)."""
    return {
        "roles": list(ROLES),
        "permissions": [
            {"name": p.name, "min_role": p.min_role, "description": p.description, "audited": p.audited,
             "roles": [r for r in ROLES if role_has(r, p.name)]}
            for p in _ALL
        ],
    }


def is_admin_role(role: str | None) -> bool:
    return role in ADMIN_ROLES


# -------------------------------------------------------------------------------- who may give which role

def assignable_roles(actor_role: str | None) -> tuple[str, ...]:
    """Roles ``actor_role`` may give (invitation, role change).  Owners give any role; admins member and viewer."""
    if actor_role == "owner":
        return ROLES
    if actor_role == "admin":
        return ("member", "viewer")
    return ()


def invitable_roles(actor_role: str | None) -> tuple[str, ...]:
    """Roles an invitation may carry: owner is never given by an invitation (promote after joining)."""
    return tuple(r for r in assignable_roles(actor_role) if r != "owner")


def can_manage_member(actor_role: str | None, target_role: str | None) -> bool:
    """May the actor change or remove a member who holds ``target_role``?  Admins manage members and viewers;
    owners manage everybody."""
    if actor_role == "owner":
        return is_role(target_role)
    if actor_role == "admin":
        return target_role in ("member", "viewer")
    return False


def role_change_problem(actor_role: str | None, target_role: str | None, new_role: str, *, self_change: bool,
                        owners: int) -> str | None:
    """Why the actor may not move a member from ``target_role`` to ``new_role``, or None.

    ``owners`` is the team's current number of owners (the caller counts it with the team row locked)."""
    if not is_role(new_role):
        return f"Unknown role {new_role!r}: choose one of {', '.join(ROLES)}"
    if not can_manage_member(actor_role, target_role):
        return "Only an owner can change the role of an admin or owner"
    if new_role not in assignable_roles(actor_role):
        return f"Your role ({actor_role}) cannot give the {new_role} role"
    if self_change and actor_role != "owner":
        return "Ask an owner to change your role"
    if target_role == "owner" and new_role != "owner" and owners <= 1:
        return "A team needs at least one owner: make someone else an owner first"
    return None


def removal_problem(actor_role: str | None, target_role: str | None, *, owners: int) -> str | None:
    if not can_manage_member(actor_role, target_role):
        return "Only an owner can remove an admin or owner"
    if target_role == "owner" and owners <= 1:
        return "A team needs at least one owner: make someone else an owner first"
    return None
