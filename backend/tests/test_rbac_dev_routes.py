"""F4 RBAC revival (PR #42 after merging dev on 2026-11-15): every route dev added since 12 Nov carries a policy.

* ``test_every_route_dev_added_since_12_nov_holds_its_policy``: the 88 routes added to ``dev`` between 3399452 (the
  base #42 was written on) and 9fdd67c, each pinned to the permission (or machine / marker policy) it is served
  with.  A route that loses its policy, or whose permission changes, fails here with the route named; a route that
  dev adds later without a policy fails ``test_rbac_route_coverage`` (declaration check and runtime default-deny).
* Team-scoped CBOM API keys (``zsk_``, #226) pass the route policy exactly where their handler takes them, act as
  their creator's role, and are checked (and audited) once per request, not twice.
* The node-artifact download (signed link or node install ticket, no session) keeps working under the policy, and
  without a ticket it is refused before the handler.
* Owners hold every admin right in the code dev added (CI/CD key rotation, SSH CA approval).
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest
from fastapi.routing import APIRoute
from sqlmodel import Session, select

sys.path.insert(0, str(Path(__file__).parent))

from test_cbom_api_keys import USERS, api, audit_rows, make_key, world  # noqa: E402,F401  (fixtures)

from backend.main import app  # noqa: E402
from backend.new_models import TeamMembership  # noqa: E402
from backend.utilities.rbac.policy import (  # noqa: E402
    Machine, Public, TeamPermission, TeamPermissionOrTicket, declared_policies, marker_of,
)

# (method, path) -> the permission it is served with; "machine" for a non-person credential the handler checks,
# "marker:<name>" for an F1 route declared with x-zs-permission (PermissionMarker enforces it like access.team).
DEV_ROUTES_SINCE_12_NOV: dict[tuple[str, str], str] = {
    ("GET", "/version"): "authenticated",
    ("GET", "/cbom/ops/metrics"): "machine",
    ("POST", "/{team_id}/cicd/integration/{integration_id}/api-key/rotate"): "cicd.manage",
    ("DELETE", "/{team_id}/cicd/integration/{integration_id}/api-key"): "cicd.manage",
    ("POST", "/{team_id}/cbom/sources/items/{source_id}/host-key-resets"): "cbom.settings",
    ("GET", "/{team_id}/cbom/sources/items/{source_id}/host-key-resets"): "cbom.read",
    ("GET", "/{team_id}/cbom/sources/runs/{run_id}/results"): "cbom.read",
    ("GET", "/{team_id}/cbom/sources/runs/{run_id}/parity"): "cbom.read",
    ("GET", "/{team_id}/cbom/sources/runs/{run_id}/assets/{asset_id}/remediation"): "cbom.read",
    ("GET", "/{team_id}/cbom/sources/runs/{run_id}/heatmap/cell"): "cbom.read",
    ("GET", "/{team_id}/cbom/sources/grade-model"): "cbom.read",
    ("GET", "/{team_id}/cbom/sources/agility-model"): "cbom.read",
    ("GET", "/{team_id}/cbom/agility"): "cbom.read",
    ("GET", "/{team_id}/cbom/agility/subjects"): "cbom.read",
    ("GET", "/{team_id}/cbom/agility/history"): "cbom.read",
    ("GET", "/{team_id}/cbom/api-keys"): "cbom.read",
    ("POST", "/{team_id}/cbom/api-keys"): "cbom.api_keys.manage",
    ("POST", "/{team_id}/cbom/api-keys/{key_id}/revoke"): "cbom.api_keys.manage",
    ("GET", "/{team_id}/cbom/ai/status"): "cbom.read",
    ("POST", "/{team_id}/cbom/ai/assist"): "finding.remediate",
    ("GET", "/{team_id}/cbom/sources/runs/{run_id}/vex"): "cbom.read",
    ("GET", "/{team_id}/cbom/sources/runs/{run_id}/signature"): "cbom.read",
    ("POST", "/{team_id}/cbom/sources/runs/{run_id}/signature/verify"): "cbom.read",
    ("GET", "/{team_id}/cbom/sources/runs/{run_id}/report.pdf"): "cbom.read",
    ("GET", "/{team_id}/cbom/sources/runs/{run_id}/evidence-pack"): "cbom.read",
    ("GET", "/{team_id}/cbom/register/q0"): "cbom.read",
    ("GET", "/{team_id}/cbom/register"): "cbom.read",
    ("GET", "/{team_id}/cbom/register/summary"): "cbom.read",
    ("GET", "/{team_id}/cbom/register/heatmap"): "cbom.read",
    ("GET", "/{team_id}/cbom/register/items/{item_key}"): "cbom.read",
    ("GET", "/{team_id}/cbom/register.csv"): "cbom.read",
    ("GET", "/{team_id}/cbom/certificates/hygiene"): "cbom.read",
    ("GET", "/{team_id}/cbom/certificates/hygiene.csv"): "cbom.read",
    ("GET", "/{team_id}/cbom/sources/ticketing"): "cbom.read",
    ("PUT", "/{team_id}/cbom/sources/ticketing"): "team.integrations.manage",
    ("POST", "/{team_id}/cbom/sources/runs/{run_id}/tickets"): "finding.triage",
    ("GET", "/{team_id}/cbom/estate"): "cbom.read",
    ("GET", "/{team_id}/cbom/estate/{asset_key}"): "cbom.read",
    ("GET", "/{team_id}/cbom/estate-export"): "cbom.read",
    ("GET", "/{team_id}/cbom/node-artifacts"): "cbom.read",
    ("POST", "/{team_id}/cbom/node-artifacts/{kind}/link"): "cbom.read",
    ("GET", "/{team_id}/cbom/node-artifacts/{kind}"): "cbom.read+ticket",
    # F1.2 / F1.3 / F1.4 fleet routers (x-zs-permission markers, enforced by PermissionMarker)
    ("GET", "/{team_id}/cbom/sources/fleet/status"): "marker:cbom.fleet.read",
    ("GET", "/{team_id}/cbom/sources/fleet/inventory/targets"): "marker:cbom.fleet.read",
    ("GET", "/{team_id}/cbom/sources/fleet/inventory/targets/{target_id}"): "marker:cbom.fleet.read",
    ("POST", "/{team_id}/cbom/sources/fleet/inventory/import"): "marker:cbom.inventory.write",
    ("PUT", "/{team_id}/cbom/sources/fleet/inventory/targets"): "marker:cbom.inventory.write",
    ("DELETE", "/{team_id}/cbom/sources/fleet/inventory/targets/{target_id}"): "marker:cbom.inventory.write",
    ("GET", "/{team_id}/cbom/sources/fleet/inventory/sources"): "marker:cbom.fleet.read",
    ("POST", "/{team_id}/cbom/sources/fleet/inventory/sources"): "marker:cbom.inventory.write",
    ("PATCH", "/{team_id}/cbom/sources/fleet/inventory/sources/{source_id}"): "marker:cbom.inventory.write",
    ("DELETE", "/{team_id}/cbom/sources/fleet/inventory/sources/{source_id}"): "marker:cbom.inventory.write",
    ("POST", "/{team_id}/cbom/sources/fleet/inventory/sources/{source_id}/sync"): "marker:cbom.inventory.write",
    ("GET", "/{team_id}/cbom/sources/fleet/policies"): "marker:cbom.fleet.read",
    ("POST", "/{team_id}/cbom/sources/fleet/policies"): "marker:cbom.policies.write",
    ("PATCH", "/{team_id}/cbom/sources/fleet/policies/{policy_id}"): "marker:cbom.policies.write",
    ("DELETE", "/{team_id}/cbom/sources/fleet/policies/{policy_id}"): "marker:cbom.policies.write",
    ("POST", "/{team_id}/cbom/sources/fleet/policies/preview"): "marker:cbom.fleet.read",
    ("POST", "/{team_id}/cbom/sources/fleet/reconcile"): "marker:cbom.policies.write",
    ("GET", "/{team_id}/cbom/sources/fleet/credentials"): "marker:cbom.fleet.read",
    ("POST", "/{team_id}/cbom/sources/fleet/credentials"): "marker:cbom.credentials.write",
    ("PATCH", "/{team_id}/cbom/sources/fleet/credentials/{credential_id}"): "marker:cbom.credentials.write",
    ("DELETE", "/{team_id}/cbom/sources/fleet/credentials/{credential_id}"): "marker:cbom.credentials.write",
    ("GET", "/{team_id}/cbom/sources/fleet/transports"): "marker:cbom.fleet.read",
    ("POST", "/{team_id}/cbom/sources/fleet/transports"): "marker:cbom.transports.write",
    ("PATCH", "/{team_id}/cbom/sources/fleet/transports/{transport_id}"): "marker:cbom.transports.write",
    ("DELETE", "/{team_id}/cbom/sources/fleet/transports/{transport_id}"): "marker:cbom.transports.write",
    ("POST", "/{team_id}/cbom/sources/fleet/transports/{transport_id}/validate"): "marker:cbom.transports.write",
    ("GET", "/{team_id}/cbom/sources/fleet/transports/artifacts/{name}"): "marker:cbom.fleet.read",
    ("GET", "/{team_id}/cbom/sources/fleet/ssh-ca"): "marker:cbom.fleet.read",
    ("GET", "/{team_id}/cbom/sources/fleet/ssh-ca/trusted-keys"): "marker:cbom.fleet.read",
    ("GET", "/{team_id}/cbom/sources/fleet/ssh-ca/revoked"): "marker:cbom.fleet.read",
    ("GET", "/{team_id}/cbom/sources/fleet/ssh-ca/certificates"): "marker:cbom.fleet.read",
    ("GET", "/{team_id}/cbom/sources/fleet/ssh-ca/templates/{name}"): "marker:cbom.fleet.read",
    ("POST", "/{team_id}/cbom/sources/fleet/ssh-ca/certificates/{cert_id}/revoke"): "marker:cbom.sshca.admin",
    ("GET", "/{team_id}/cbom/sources/fleet/ssh-ca/trust-tokens"): "marker:cbom.fleet.read",
    ("POST", "/{team_id}/cbom/sources/fleet/ssh-ca/trust-tokens"): "marker:cbom.sshca.admin",
    ("POST", "/{team_id}/cbom/sources/fleet/ssh-ca/trust-tokens/{token_id}/revoke"): "marker:cbom.sshca.admin",
    ("POST", "/{team_id}/cbom/sources/fleet/ssh-ca"): "marker:cbom.sshca.admin",
    ("GET", "/{team_id}/cbom/sources/fleet/ssh-ca/{ca_id}"): "marker:cbom.fleet.read",
    ("POST", "/{team_id}/cbom/sources/fleet/ssh-ca/{ca_id}/rotate"): "marker:cbom.sshca.admin",
    ("POST", "/{team_id}/cbom/sources/fleet/ssh-ca/{ca_id}/promote"): "marker:cbom.sshca.admin",
    ("POST", "/{team_id}/cbom/sources/fleet/ssh-ca/{ca_id}/revoke"): "marker:cbom.sshca.admin",
    ("POST", "/cbom/node/jobs/{job_id}/ssh-cert/report"): "marker:machine:scan-node token",
    ("POST", "/cbom/node/jobs/{job_id}/ssh-cert"): "marker:machine:scan-node token",
    ("GET", "/cbom/ssh-ca-trust/trusted-keys"): "marker:machine:ssh-ca trust token",
    ("GET", "/cbom/ssh-ca-trust/revoked"): "marker:machine:ssh-ca trust token",
    ("GET", "/cbom/ssh-ca-trust/principals"): "marker:machine:ssh-ca trust token",
}


def _served_with(route) -> str:
    policies = declared_policies(route)
    if not policies:
        marker = marker_of(route)
        return f"marker:{marker}" if marker else "MISSING"
    policy = policies[0]
    if isinstance(policy, TeamPermissionOrTicket):
        return f"{policy.permission.name}+ticket"
    if isinstance(policy, TeamPermission):
        return policy.permission.name
    if isinstance(policy, (Machine, Public)):
        return policy.kind
    return policy.kind


def _app_routes() -> dict[tuple[str, str], APIRoute]:
    return {(m, r.path): r for r in app.routes if isinstance(r, APIRoute) for m in r.methods}


def test_every_route_dev_added_since_12_nov_holds_its_policy():
    routes = _app_routes()
    assert len(DEV_ROUTES_SINCE_12_NOV) == 88
    missing = sorted(k for k in DEV_ROUTES_SINCE_12_NOV if k not in routes)
    assert not missing, f"routes no longer served (update this table): {missing}"
    wrong = {k: (_served_with(routes[k]), want) for k, want in DEV_ROUTES_SINCE_12_NOV.items()
             if _served_with(routes[k]) != want}
    assert not wrong, f"(method, path): (served with, expected): {wrong}"


def test_every_team_route_dev_added_is_refused_to_a_viewer_where_it_changes_something():
    """No write route dev added is open to viewers: every non-GET team route needs member or above (or a ticket)."""
    from backend.utilities.rbac.permissions import role_has

    routes = _app_routes()
    for (method, path), want in DEV_ROUTES_SINCE_12_NOV.items():
        if method == "GET" or "{team_id}" not in path:
            continue
        name = want.removeprefix("marker:")
        if name in ("cbom.read", "cbom.fleet.read"):  # read-only POSTs: signature verify, link, preview
            assert path.endswith(("/signature/verify", "/link", "/policies/preview")), (method, path)
            continue
        assert not role_has("viewer", name), (method, path, name)
        assert routes[(method, path)] is not None


# ----------------------------------------------------------------------------- zsk_ keys under the route policy
def test_a_cbom_api_key_passes_the_policy_as_its_creator_and_is_checked_once(api, world):
    engine, _ids, _db = world
    _meta, key = make_key(api, ["cbom.read"], name="reader")
    before = [r for r in audit_rows(engine, 1) if r.action == "api_key.use"]
    r = api("GET", "/1/cbom/sources/items", key=key)
    assert r.status_code == 200, r.text
    uses = [r for r in audit_rows(engine, 1) if r.action == "api_key.use"]
    assert len(uses) - len(before) == 1  # the policy verified it; the handler's authorize reused that, once

    # a route that takes no key: refused by the policy with the handler's own answer (403 API key / 401 session)
    refused = api("GET", "/1/cbom/sources/settings", key=key)
    assert refused.status_code == 403 and "API key" in refused.json()["detail"]
    assert api("GET", "/1/cbom/api-keys", key=key).status_code == 401
    assert api("GET", "/team/1", key=key).status_code == 401


def test_a_key_stops_at_the_policy_when_its_creator_is_demoted_to_member(api, world):
    engine, _ids, _db = world
    _meta, key = make_key(api, ["cbom.read"], name="reader")
    assert api("GET", "/1/cbom/sources/runs", key=key).status_code == 200
    with Session(engine) as s:
        member = s.exec(select(TeamMembership).where(TeamMembership.team_id == 1)).all()
        alice = next(m for m in member if m.role == "admin")
        alice.role = "member"
        s.add(alice)
        s.commit()
    refused = api("GET", "/1/cbom/sources/runs", key=key)
    assert refused.status_code == 403 and "no longer a team admin" in refused.json()["detail"]


def test_a_key_created_by_an_owner_works(api, world):
    """Owners hold every admin right: a key an owner made acts for them (ADMIN_ROLES includes owner)."""
    engine, _ids, _db = world
    with Session(engine) as s:
        alice = next(m for m in s.exec(select(TeamMembership).where(TeamMembership.team_id == 1)).all()
                     if m.role == "admin")
        alice.role = "owner"
        s.add(alice)
        s.commit()
    _meta, key = make_key(api, ["cbom.read"], name="owners-key")
    assert api("GET", "/1/cbom/sources/runs", key=key).status_code == 200


# ----------------------------------------------------------------------------- signed download links
def test_the_node_artifact_download_takes_a_ticket_without_a_session_and_nothing_else(api, world):
    anonymous = api("GET", "/1/cbom/node-artifacts/image", None)
    assert anonymous.status_code == 401  # no session, no ticket: the policy refuses before the handler
    forged = api("GET", "/1/cbom/node-artifacts/image?ticket=forged", None)
    assert forged.status_code in (401, 403, 404) and forged.status_code != 200  # the handler's ticket check
    outsider = api("GET", "/1/cbom/node-artifacts/image", "carol")  # an admin of team 2
    assert outsider.status_code == 403 and outsider.json()["detail"] == "User is not in team"
    # a session AND a ticket: the session is what the policy checks
    assert api("GET", "/1/cbom/node-artifacts/image?ticket=forged", "carol").status_code == 403


# ----------------------------------------------------------------------------- owners in dev's admin checks
@pytest.mark.parametrize("role, admin", [("owner", True), ("admin", True), ("member", False), ("viewer", False)])
def test_owners_count_as_admins_in_the_ssh_ca_approval_list(world, role, admin):
    from backend.utilities.cbom_sources.http import is_team_admin as cbom_is_admin
    from backend.utilities.cicd.api_keys import is_team_admin as cicd_is_admin

    engine, _ids, _db = world
    with Session(engine) as s:
        row = next(m for m in s.exec(select(TeamMembership).where(TeamMembership.team_id == 1)).all()
                   if m.role == "admin")
        row.role = role
        s.add(row)
        s.commit()
        uid = row.user_id
        assert cbom_is_admin(s, uid, 1) is admin
    assert cicd_is_admin(uid, 1, engine) is admin
    import inspect

    from backend.utilities.cbom_sources.sshca import sources as SSHCA_SOURCES
    # needing_admin_save lists ssh_ca sources whose last saver is not an admin: its admin set includes owners
    assert '"owner"' in inspect.getsource(SSHCA_SOURCES.needing_admin_save)
    with Session(engine) as s:
        assert SSHCA_SOURCES.needing_admin_save(s, 1) == ([], 0)  # the owner-aware query runs
