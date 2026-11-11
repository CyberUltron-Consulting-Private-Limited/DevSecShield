"""The permission matrix (F4 RBAC): roles are ordered, every permission names a real role, the role-change and
removal rules hold.

    cd backend && PYTHON_DOTENV_DISABLED=1 PYTHONPATH=.. JWT_SECRET_KEY=t JWT_REFRESH_SECRET_KEY=r \
      python -m pytest tests/test_rbac_matrix.py -q -p no:cacheprovider
"""
import os
import sys
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))
os.environ.setdefault("JWT_SECRET_KEY", "rbac-matrix-test-access-secret")
os.environ.setdefault("JWT_REFRESH_SECRET_KEY", "rbac-matrix-test-refresh-secret")

from backend.utilities.rbac import permissions as P  # noqa: E402


def test_roles_are_ordered_and_each_holds_everything_below_it():
    assert P.ROLES == ("viewer", "member", "admin", "owner")
    for lower, higher in zip(P.ROLES, P.ROLES[1:]):
        assert set(P.permissions_for(lower)) < set(P.permissions_for(higher)), (lower, higher)


def test_every_permission_names_a_known_role_and_a_description():
    for perm in P.PERMISSIONS.values():
        assert perm.min_role in P.ROLES
        assert perm.description and not perm.description.endswith(".")


def test_viewer_reads_only():
    for name in P.permissions_for("viewer"):
        assert not P.PERMISSIONS[name].audited, f"viewer holds a write permission: {name}"
    for name in ("scan.read", "team.read", "cbom.read", "dast.read", "cicd.read", "integrations.read"):
        assert P.role_has("viewer", name)


def test_key_rows_of_the_matrix():
    assert not P.role_has("viewer", "scan.create") and P.role_has("member", "scan.create")
    assert not P.role_has("member", "team.update") and P.role_has("admin", "team.update")
    assert not P.role_has("member", "team.integrations.manage")  # the Jira rule: members read Jira, admins change it
    assert not P.role_has("admin", "team.delete") and P.role_has("owner", "team.delete")
    assert not P.role_has("admin", "team.sso.manage") and P.role_has("owner", "team.scim.manage")
    assert P.role_has("admin", "team.audit.read") and not P.role_has("member", "team.audit.read")


@pytest.mark.parametrize("role", [None, "", "superuser", "Admin", "OWNER", 1, "member "])
def test_an_unknown_role_holds_nothing(role):
    assert P.permissions_for(role) == []
    assert not P.role_has(role, "team.read")


def test_an_unknown_permission_is_refused():
    with pytest.raises(ValueError):
        P.get_permission("team.everything")
    with pytest.raises(ValueError):
        P.role_has("owner", "scan.reed")


def test_who_may_give_which_role():
    assert P.assignable_roles("owner") == P.ROLES
    assert P.assignable_roles("admin") == ("member", "viewer")
    assert P.assignable_roles("member") == () and P.assignable_roles("viewer") == ()
    assert "owner" not in P.invitable_roles("owner") and "admin" in P.invitable_roles("owner")
    assert P.invitable_roles("admin") == ("member", "viewer")


@pytest.mark.parametrize("actor,target,new,self_change,owners,ok", [
    ("admin", "member", "viewer", False, 1, True),
    ("admin", "viewer", "member", False, 1, True),
    ("admin", "member", "admin", False, 1, False),     # admins cannot make admins
    ("admin", "member", "owner", False, 1, False),     # nor owners
    ("admin", "admin", "member", False, 1, False),     # nor touch other admins
    ("admin", "owner", "member", False, 2, False),     # nor owners
    ("admin", "admin", "member", True, 1, False),      # nor change their own role
    ("owner", "admin", "member", False, 1, True),
    ("owner", "member", "owner", False, 1, True),
    ("owner", "owner", "admin", False, 1, False),      # the last owner stays
    ("owner", "owner", "admin", True, 1, False),       # also when it is oneself
    ("owner", "owner", "admin", True, 2, True),        # another owner remains
    ("member", "viewer", "member", False, 1, False),
    ("viewer", "viewer", "member", True, 1, False),
    ("owner", "member", "superuser", False, 1, False),  # not a role
])
def test_role_change_rules(actor, target, new, self_change, owners, ok):
    problem = P.role_change_problem(actor, target, new, self_change=self_change, owners=owners)
    assert (problem is None) is ok, problem


@pytest.mark.parametrize("actor,target,owners,ok", [
    ("admin", "member", 1, True), ("admin", "viewer", 1, True), ("admin", "admin", 1, False),
    ("admin", "owner", 2, False), ("owner", "admin", 1, True), ("owner", "owner", 2, True),
    ("owner", "owner", 1, False), ("member", "viewer", 1, False),
])
def test_removal_rules(actor, target, owners, ok):
    assert (P.removal_problem(actor, target, owners=owners) is None) is ok


def test_the_matrix_as_data_matches_role_has():
    data = P.matrix()
    assert data["roles"] == list(P.ROLES)
    for row in data["permissions"]:
        assert row["roles"] == [r for r in P.ROLES if P.role_has(r, row["name"])]
        assert row["roles"][0] == row["min_role"]
