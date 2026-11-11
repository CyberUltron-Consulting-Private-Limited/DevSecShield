/**
 * F4 RBAC in the browser: the role helpers, and the guards the pages must keep (the server refuses anyway).
 * Run: npx --yes tsx utils/rbac.test.ts
 */
import assert from "node:assert/strict"
import fs from "node:fs"
import path from "node:path"

import { auditActionLabel, auditDetailText, auditObjectText } from "./auditLog"
import { accessFrom, can, canManageMember, isReadOnly, isRoleRefusal, lastOwnerProblem, roleChoices, roleLabel } from "./rbac"

const viewer = accessFrom({ role: "viewer", permissions: ["team.read", "scan.read"], assignable_roles: [], invitable_roles: [], has_owner: true })
const admin = accessFrom({
  role: "admin", permissions: ["team.read", "scan.read", "scan.create", "team.members.role", "team.audit.read"],
  assignable_roles: ["member", "viewer"], invitable_roles: ["viewer", "member"], has_owner: false,
})
const owner = accessFrom({
  role: "owner", permissions: ["team.delete", "scan.create"], assignable_roles: ["viewer", "member", "admin", "owner"],
  invitable_roles: ["viewer", "member", "admin"], has_owner: true,
})

// --- what GET /team says, read defensively (an older server sends none of it)
assert.deepEqual(accessFrom(undefined), { role: null, permissions: [], assignable_roles: [], invitable_roles: [], has_owner: true })
assert.equal(accessFrom({ role: "superuser", permissions: "all" }).role, null)
assert.deepEqual(accessFrom({ permissions: ["a", 1, null] }).permissions, ["a"])
assert.deepEqual(accessFrom({ assignable_roles: ["owner", "root"] }).assignable_roles, ["owner"])

// --- can / read-only
assert.ok(can(admin, "scan.create") && !can(viewer, "scan.create") && !can(null, "scan.read"))
assert.ok(isReadOnly(viewer) && !isReadOnly(admin) && !isReadOnly(null))
assert.equal(roleLabel("owner"), "Owner")
assert.equal(roleLabel("root"), "Unknown")

// --- who manages whom (mirrors backend/utilities/rbac/permissions.py)
assert.ok(canManageMember(admin, "member") && canManageMember(admin, "viewer"))
assert.ok(!canManageMember(admin, "admin") && !canManageMember(admin, "owner"))
assert.ok(canManageMember(owner, "owner") && !canManageMember(viewer, "viewer"))
assert.deepEqual(roleChoices(admin, "member"), ["viewer", "member"])
assert.deepEqual(roleChoices(admin, "admin"), [])
assert.deepEqual(roleChoices(owner, "admin"), ["viewer", "member", "admin", "owner"])
assert.deepEqual(roleChoices(viewer, "viewer"), [])

// --- a team keeps one owner
const members = [{ role: "owner" }, { role: "admin" }]
assert.ok(lastOwnerProblem(members, "owner", "admin"))
assert.equal(lastOwnerProblem([...members, { role: "owner" }], "owner", "admin"), null)
assert.equal(lastOwnerProblem(members, "admin", "member"), null)

// --- the server's refusal text
assert.ok(isRoleRefusal("Your role (viewer) cannot create scans. Ask a team admin for access."))
assert.ok(!isRoleRefusal("User is not in team") && !isRoleRefusal(undefined))

// --- audit log wording
assert.equal(auditActionLabel("team.members.role"), "Changed a role")
assert.equal(auditActionLabel("team.update", "denied"), "Refused: changed team settings")
assert.equal(auditActionLabel("something.new"), "something.new")
assert.equal(auditObjectText({ object_type: "member", object_id: "7", details: { email: "a@b.c" } }), "member a@b.c")
assert.equal(auditObjectText({ object_type: "scan", object_id: "12", details: {} }), "scan 12")
assert.equal(auditDetailText({ details: { from: "member", to: "viewer", method: "PATCH", route: "/team/{team_id}/members/role" }, outcome: "success" }),
  "member → viewer · PATCH /team/{team_id}/members/role")
assert.equal(auditDetailText({ details: { reason: "role viewer below member" }, outcome: "denied" }), "refused: role viewer below member")

// --- the pages keep their guards
const root = path.resolve(__dirname, "..")
const read = (p: string) => fs.readFileSync(path.join(root, p), "utf8")
const layout = read("app/[team_id]/layout.tsx")
assert.ok(layout.includes("<TeamAccessProvider teamId={team_id}>") && layout.includes("<ReadOnlyBanner />"), "layout provides the role")
const settings = read("app/[team_id]/settings/page.tsx")
assert.ok(settings.includes('can(access, "team.delete")'), "only owners see Delete team")
assert.ok(settings.includes("roleChoices(access, member.role)"), "role selector offers only roles the caller may give")
assert.ok(settings.includes("canManageMember(access, member.role)"), "remove checkbox only for members the caller may remove")
assert.ok(settings.includes('data-testid="invite-role"') && settings.includes("access.invitable_roles"), "invite with a role")
assert.ok(settings.includes('can(access, "team.ownership.claim")'), "claim ownership of a legacy team")
assert.ok(settings.includes("settings/audit"), "audit log link")
for (const product of ["sast", "sbom_sca", "cbom", "ai_bom", "mcp", "llm", "iac", "dast"]) {
  const list = read(`app/[team_id]/${product}/page.tsx`)
  assert.equal((list.match(/<IfAllowed permission="scan.create">/g) ?? []).length, 2, `${product}: New Scan buttons gated`)
  assert.equal((list.match(/<IfAllowed permission="scan.update">/g) ?? []).length, 2, `${product}: rename / delete gated`)
}
for (const page of ["sast/[scan_id]", "sbom_sca/[scan_id]", "cbom/[scan_id]", "ai_bom/[scan_id]", "mcp/[conversation_id]",
  "llm/[conversation_id]", "iac/[scan_id]", "dast/[scan_id]"]) {
  assert.ok(read(`app/[team_id]/${page}/page.tsx`).includes('<ReadOnlyGate permission="scan.run"'), `${page}: options sidebar gated`)
}
const sources = read("app/[team_id]/cbom/sources/page.tsx")
assert.equal((sources.match(/<ReadOnlyGate permission="cbom.write"/g) ?? []).length, 7, "CBOM Sources tabs gated")
assert.ok(fs.existsSync(path.join(root, "app/[team_id]/settings/audit/page.tsx")), "audit log page")

console.log("rbac: all assertions passed")
