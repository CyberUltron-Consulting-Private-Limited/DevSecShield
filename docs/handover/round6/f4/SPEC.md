# F4: access management (RBAC, SSO, SCIM) — spec

Track F4, three PRs into `dev`, in order: `feat/f4-rbac`, `feat/f4-sso`, `feat/f4-scim`.
Acceptance criteria: PARALLEL-PLAN.md "F4" plus the coordinator's brief (quoted per PR below).

## For other tracks (F1.2, F1.3, F1.4, F3): how to declare a permission — STABLE, published Nov 11

**Roles** (per team): `viewer < member < admin < owner`; each holds everything below it. Superusers get no team
access by being superusers.

**Permission names** you may use (the whole matrix: `backend/utilities/rbac/permissions.py` on `feat/f4-rbac`):

| Name | Lowest role | For |
|---|---|---|
| `cbom.fleet.read` | viewer | F1: every fleet GET (inventory, policies, credentials list, transports, SSH CA) |
| `cbom.inventory.write` | admin | F1.2: import, upsert, delete target, inventory-source CRUD, sync |
| `cbom.policies.write` | admin | F1.2: tag policy CRUD, reconcile |
| `cbom.credentials.write` | admin | F1.2: credential CRUD |
| `cbom.transports.write` | admin | F1.3: transport CRUD, validate |
| `cbom.sshca.admin` | admin | F1.4: CA create, rotate, promote, revoke |
| `repos.read` | viewer | F3: list connected orgs / repositories |
| `repos.manage` | admin | F3: connect an org (app installation or token), filters, tokens |
| `scan.read` / `scan.create` / `scan.run` | viewer / member / member | F3: repository scans (existing scan routes) |
| `cbom.read` / `cbom.write` / `cbom.settings` | viewer / member / admin | existing CBOM Sources routes |

Need another name? Ask F4 (one line in `permissions.py`); an unknown name fails at import / in the coverage test.

**How to declare it.** Either form passes the route-coverage test (`backend/tests/test_rbac_route_coverage.py`):

1. *Now, without importing F4 code* (works before and after F4 PR 1 merges):
   `@router.get(BASE + "/fleet/inventory", ..., openapi_extra={"x-zs-permission": "cbom.fleet.read"})`
   Before F4 is on dev the marker is inert and your existing helpers enforce (400 in-team convention). Once F4 PR 1
   is on dev an app-level dependency (`rbac.policy.PermissionMarker`, installed in `main.py`) enforces the marker on
   every `{team_id}` route that declares no other policy: a role below the permission gets **403**
   `"Your role (member) cannot ..."` before your handler runs; a non-member gets 403 `"User is not in team"`.
   Your handler's own checks (object-level "creator or admin" 400s) keep working behind it.
2. *After F4 PR 1 is on dev* (explicit, preferred for new routers):
   ```python
   from backend.utilities.rbac.policy import Access, public, machine
   access = Access(lambda: get_db())          # bound to YOUR module's get_db (tests patch it per module)
   @router.get(path, dependencies=[Depends(read_limiter), access.team("repos.read")])
   ```
   Non-team routes: `access.authenticated()`, `access.platform_admin()`, `public("why")`, `machine("node token", "why")`.

Rules the coverage test enforces: exactly one declaration per route; a `{team_id}` path needs a team permission;
a team permission needs `{team_id}`; a marker must name a known permission; a marker and an explicit policy on the
same route must agree. Tests that call team routes need a real `TeamMembership` row with a role and a real access
token (helper: `backend/tests/support/rbac.py`: `patch_all_get_db`, `make_user`, `join`, `bearer`).
**Audit:** successful requests on audited permissions (every write) are logged automatically by the middleware;
you do not need to call anything. Keep `common.audit(...)` for CBOM's own audit table as the contract says.
**Migrations:** F4 uses prefixes `r6f4rbac`, `r6f4sso`, `r6f4scim`; F4's new tables live in `backend/access_models.py`.

## 0. What `dev` (3399452) does today (evidence: code read + `tools/inventory.py` over `backend.main.app`)

* **Identity.** `User` rows (email, Argon2id hash with bcrypt fallback, `token_version`, `session_active`,
  `is_superuser`, `must_change_password`). Sign-in = email + password + mailed 6-digit code. Tokens: HS256 JWTs
  (access 30 min, refresh 8 h) with `typ` and `ver`; bumping `user.token_version` revokes every token (logout,
  reset, password change). **No cookies**: the SPA keeps both tokens in `localStorage` and sends
  `Authorization: Bearer`. CORS has `allow_credentials=False`. So the JSON API has no ambient credential and is not
  CSRF-able today; anything this track adds that uses a cookie (the SSO round trip) must bring its own CSRF defence.
* **Tenancy.** There is no organisation object: the tenant is the **team** (`Team`, `TeamMembership(team_id,
  user_id, role)`). Roles today: `admin` | `member` (string column). Every user has a default team (role admin).
* **Platform roles.** Only `User.is_superuser` (the admin console, `/admin/*`). There is **no "operator" role in
  code** (grep over backend, frontend, migrations): "operator" in the brief maps to the superuser.
* **Admin vs member today.** Admin-only: PUT/PATCH/DELETE `/team/{id}` (rename, Jira settings, invite/remove,
  delete), invitations list/resend/revoke, CBOM settings, integrations (WP11) save/delete/test/retry, CMDB
  preview/apply, vault-credential sources. The Jira rule: members see Jira read-only (`readOnly={!is_team_admin}`),
  the API refuses their PUT. Everything else in a team is open to any member; object-level rules (scan owner,
  "creator or admin" for CBOM nodes/sources/schedules/pools) live inside handlers.
* **Checks are hand-written in every handler** (`get_user_from_header_or_raise_exception` +
  `check_if_user_is_in_team` / `check_if_user_is_admin_of_team` / `authorize` / `is_superuser`). Nothing enforces
  that a new route does any check. Route inventory: `ROUTE-INVENTORY.md` (151 routes, 120 team-scoped).
* **Bugs found on the way** (fixed in PR 1, each with a test):
  1. `PATCH /team/{id}` with `intent=remove` removes **admins too**, including the caller (UI hides it, API
     allows it). With several admins one admin can evict the others.
  2. CBOM `http.py` still says "no 403: the frontend logs out on a 403"; the frontend was fixed (only
     "Session not active" logs out, `utils/error-handler.ts`), so a 403 is now the right answer for a role denial.

## 1. PR 1 — `feat/f4-rbac`: roles, permissions, audit log

### Roles (per team) and the matrix
`viewer < member < admin < owner`. One table, `backend/utilities/rbac/permissions.py`:
`PERMISSIONS: dict[name, Permission(min_role, description, audited)]`; `ROLE_PERMISSIONS` (role → set) is derived
from it. `GET /rbac/matrix` serves it; `GET /team/{id}` returns the caller's `role` and `permissions`.

| Permission | Min role | Routes |
|---|---|---|
| team.read | viewer | GET team, dashboard |
| team.update | admin | PUT team (name, description) |
| team.integrations.manage | admin | Jira in PUT team; integrations PUT/DELETE/test/retry; CMDB preview/apply |
| integrations.read | viewer | GET integrations, deliveries |
| team.members.invite | admin | PATCH team add; invitations list/resend/revoke |
| team.members.remove | admin | PATCH team remove (admins/owners only by an owner; never the last owner) |
| team.members.role | admin | PATCH team/{id}/members/role (admin: member↔viewer; owner: any; last owner kept) |
| team.ownership.claim | admin | POST team/{id}/ownership/claim (only while the team has **no** owner) |
| team.delete | owner | DELETE team |
| team.audit.read | admin | GET team/{id}/audit |
| scan.read | viewer | list/get/export scans, attestations GET, VEX, BOM, evidence pack, deliverables |
| scan.create / scan.update / scan.run | member | create; update/delete/message; start/estimate/reinitialize/cancel |
| finding.triage / finding.remediate | member | finding state, create ticket; remediation |
| certin.write | member | attestation upload/delete, sign |
| dast.read / dast.manage / dast.run | viewer / member / member | DAST profiles |
| cicd.read / cicd.manage | viewer / member | CI/CD integrations (keys are shown masked only) |
| guardrails.read / guardrails.manage | viewer / member | deprecated guardrails |
| cbom.read / cbom.write / cbom.settings | viewer / member / admin | CBOM Sources, ops, node pools, OSCAL |
| team.sso.manage, team.scim.manage | owner | PR 2 / PR 3 |

Non-team routes declare a policy too: `public(reason)` (sign-in, sign-up, codes, reset, refresh, health,
invitation link, vendor questionnaire), `authenticated` (get_user, logout, account password, teams list, create
team, accept invitation), `platform_admin` (superuser, `/admin/*`), `machine(kind)` (scan-node token, CI/CD and
guardrails API keys). Superusers get **no** implicit team access (unchanged).

### Enforcement
* `backend/utilities/rbac/policy.py`: `AccessPolicy` dependency classes. Every route lists exactly one in
  `dependencies=` (after its rate limiter). `TeamPermission(p)`: Bearer → claims (signature, `typ`, `exp`, `ver`
  vs `token_version`) → user (`session_active`) → membership of the path's `team_id` → `role ≥ min_role`.
  401 bad token, 403 "Session not active" (frontend logs out), 403 "User is not in team" (unchanged text), 403
  role denial `"Your role (viewer) cannot <description>"`. Read-only: no `last_active` write.
  The engine comes from a getter bound to each router's own `get_db` (existing tests patch it per module).
* Handlers keep their own checks (defence in depth); `check_if_user_is_admin_of_team`, `is_team_admin`,
  `require_admin` accept owner as admin.
* **Coverage test** (`tests/test_rbac_route_coverage.py`): every APIRoute/WebSocket route has exactly one
  AccessPolicy; every path with `{team_id}` has a team permission and no team permission on a path without one;
  every permission named exists in the matrix; plus the full matrix over HTTP: each team route × {non-member,
  viewer, member, admin, owner} → denied roles get the RBAC 403 before the handler runs (handler replaced by a
  sentinel that fails the test if reached); allowed roles reach the sentinel.

### Audit log (append-only)
* Table `auditevent`: id, at (UTC), team_id (plain int, no FK: survives team deletion), actor_user_id,
  actor_email (snapshot), actor_type (user | superuser | scim | sso | system), action, object_type, object_id,
  outcome (success | denied), ip (`request.client.host`, uvicorn's trusted-proxy handling; never the raw
  `X-Forwarded-For`), user_agent (≤200), details (JSON, field names / old→new roles, never secrets), prev_hash,
  hash (SHA-256 chain).
* Append-only: no update/delete code path; ORM `before_update`/`before_delete` raise; on PostgreSQL the migration
  adds `BEFORE UPDATE OR DELETE` and `BEFORE TRUNCATE` triggers that raise. Writes take
  `pg_advisory_xact_lock` so the hash chain never forks; `GET /admin/audit/verify` walks it.
* What is recorded: every successful request whose permission is `audited` (all team writes, platform-admin
  writes) by an ASGI middleware after the response (status < 400), with the route's path params as the object;
  role denials (member of the team, role too low) and non-member denials on write routes, written by the
  dependency; domain events written **in the same transaction** as the change: role change (old → new), member
  removal, ownership claim, invitation create/resend/revoke/accept, team create/delete; auth events (login ok /
  refused, logout, password change/reset, sign-up).
* Read: `GET /team/{id}/audit` (team.audit.read; filters action/actor, cursor `before_id`, limit ≤ 200),
  `GET /admin/audit` (superuser, platform-wide).

### Data model and migration `r6f4rbac001` (down_revision = dev head `rv6p1nodename001`)
* `teammembership.role`: values `owner|admin|member|viewer`; CHECK constraint `ck_teammembership_role`.
* `teaminvitation.role` (default `member`): the invite carries the role (admin invites member/viewer, owner may
  invite admin); accept/register joins with it.
* `auditevent` + indexes (team_id, at), (actor_user_id), + triggers (PostgreSQL).
* Data: admin → admin, member → member (identity; no owners invented), superusers unchanged. New teams (sign-up,
  POST /team, invitation register, admin console) give their creator **owner**. Legacy teams have no owner until
  an admin claims it (audited; refused once an owner exists).
* Downgrade: owner → admin, viewer → member (keeps access, never loses it), drop CHECK and `teaminvitation.role`,
  drop triggers, rename `auditevent` → `auditevent_archive` (evidence kept; upgrade renames it back).
  Proof: upgrade → downgrade → upgrade on PostgreSQL 15 with rows in every state.

### UI
* `TeamAccessProvider` in `app/[team_id]/layout.tsx` (role + permissions from GET /team), `useCan()`.
* Viewer: banner "View-only access" on every team page; scan-creation sidebars and run/delete/cancel controls
  disabled with the reason (a `<ReadOnlyGate>`), CBOM Sources write controls hidden.
* Settings: role column with a role selector per member (only roles the caller may assign), invite with role,
  "claim ownership" when the team has none, delete team for owners only, an Audit log page
  (`/[team_id]/settings/audit`) for admins.
* Server refuses anyway: tests call every hidden action as a viewer and assert 403.

### PR 1 acceptance → proof
| Criterion | Proof |
|---|---|
| Roles owner/admin/member/viewer per team, matrix in one place | `permissions.py`; test_rbac_matrix (matrix is monotone, every permission used) |
| Enforced server-side on every route via a dependency | test_rbac_route_coverage (declaration + HTTP matrix 120 routes × 5 actors) |
| Coverage test fails if a route lacks a permission | the same test, plus a self-test that adds an undeclared route and sees it fail |
| Audit log: who, what, which object, IP, when; append-only | test_audit_log (middleware rows, denials, domain events, ORM refusal, chain verify); PostgreSQL trigger test (CI `AUTH_TEST_PG_URL`) |
| UI hides/disables, server 403 | frontend rbac tests (tsx) + backend viewer tests; browser QA by QA agent |
| Migration admin→admin, member→member, superusers unchanged, reversible | test_rbac_migration on PostgreSQL: up/down/up, row-by-row comparison |
| IDOR / escalation | tests: member of team A on team B ids; admin promoting self to owner; admin removing owner; last owner; role values outside the enum; invitation with role above inviter |

## 2. PR 2 — `feat/f4-sso`: OIDC + SAML per team
* Config per team (`teamsso`): protocol, OIDC issuer/client_id/client_secret (Fernet, write-only), SAML IdP entity
  id / SSO URL / signing certs, default JIT role (viewer|member), `enforced` flag, verified domains
  (`teamssodomain`: DNS TXT `devsecshield-verify=<token>`; superuser override for air-gapped, audited).
  Managed by owners (`team.sso.manage`).
* OIDC: authorization code + PKCE S256, `state` + `nonce`, discovery + JWKS via python-jose (already a
  dependency; no new crypto), `iss`/`aud`/`azp`/`exp`/`iat`/`nonce` checks, `email_verified` required.
* SAML 2.0: SP-initiated, `signxml` (pure Python, lxml + cryptography) verifies the signature and only the
  element it returns is read (signature wrapping), Response and/or Assertion must be signed, `Audience` = our SP
  entity id, `Recipient`/`Destination` = our ACS URL, `InResponseTo` = the request we sent, `NotBefore` /
  `NotOnOrAfter` with 120 s skew, replay cache of assertion ids (DB table, unique), XXE off (lxml
  `resolve_entities=False`, no network).
* Browser binding: the round trip state lives in a server-side row keyed by a random id, sent as an HttpOnly,
  Secure, SameSite=Lax cookie (`__Host-` prefix in production) — login CSRF and session fixation are refused
  when the cookie does not match. The callback never puts tokens in a URL: it redirects to `/sso/complete` with a
  one-time code (60 s, single use) that the SPA exchanges for tokens. Redirect targets are relative paths only
  (open redirect).
* JIT: an assertion for an email in one of the team's verified domains creates the account (no password usable,
  random hash) and the membership with the default role; an email outside them is refused. Domain capture: a
  verified domain belongs to one team; sign-in for that domain is routed to its IdP. Enforced SSO: password
  sign-in refused for captured domains, except the break-glass path: owners keep password + code sign-in, every
  use audited and mailed.
* Tests: unit (forged signature, wrapped assertion, wrong audience/recipient, expired, replayed, unsolicited,
  open redirect, state mismatch); live: Keycloak in docker under `flock stack.lock`, realms `zs-oidc` and
  `zs-saml`, scripted browser-less flows.

## 3. PR 3 — `feat/f4-scim`: SCIM 2.0
* `/scim/v2/Users`, `/scim/v2/Groups` (+ ServiceProviderConfig, ResourceTypes, Schemas). Users: create, get,
  list with `filter=userName eq "..."` (only that filter; others 400 `invalidFilter`), PATCH (RFC 7644 §3.5.2:
  `replace active`, names, emails), PUT, DELETE = deactivate. Groups: create/get/list/PATCH members/DELETE,
  each group mapped to a role (`teamscimgroup.role`).
* Auth: per-team bearer token (`scim_` + 256 bits), stored as SHA-256, shown once, rotate/revoke, rate limited.
  A token reaches only its team's users: IDs are scoped, a user of another team is a 404.
* Deprovisioning (active=false or DELETE): membership removed or marked inactive, `token_version` bumped (every
  session signed out), audited (actor_type scim).
* Tests: scripted RFC 7644 client (Users + Groups lifecycle, filter, PATCH ops, errors `scimType`), Keycloak if a
  SCIM plugin is available, otherwise the scripted client against the running stack.

## Risks
* Every team route gains a dependency: two extra indexed SELECTs per request (measured in PR 1).
* 403 for role denials where some CBOM routes answered 400: the frontend no longer logs out on 403; tests updated.
* Shared files touched (main.py, new_models.py, team settings page, layout): changes kept additive.
* One alembic head: PR 1 chains on `rv6p1nodename001`; PR 2/3 chain on PR 1.
