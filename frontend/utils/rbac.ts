/**
 * F4 RBAC in the browser: what the signed-in person may do in a team, so the UI can hide or disable it.
 *
 * The server is the authority: every route refuses (403) what a role does not hold, whatever the UI shows
 * (backend/utilities/rbac/permissions.py holds the matrix). GET /team/{id} returns the caller's `role` and the
 * `permissions` it holds; these helpers only read that answer, they never decide on their own.
 */

export type TeamRole = "viewer" | "member" | "admin" | "owner"

export const ROLES: TeamRole[] = ["viewer", "member", "admin", "owner"]

export const ROLE_LABELS: Record<TeamRole, string> = {
  viewer: "Viewer",
  member: "Member",
  admin: "Admin",
  owner: "Owner",
}

export const ROLE_HELP: Record<TeamRole, string> = {
  viewer: "Sees scans, findings and reports; changes nothing.",
  member: "Runs scans and manages what they create.",
  admin: "Also manages members, invitations, integrations and team settings.",
  owner: "Also manages admins and owners, and can delete the team.",
}

export const READ_ONLY_TITLE = "View-only access"
export const READ_ONLY_TEXT =
  "Your role in this team is Viewer: you can see scans, findings and reports, but not start, change or delete anything. Ask a team admin for the Member role."

export function isRole(value: unknown): value is TeamRole {
  return typeof value === "string" && (ROLES as string[]).includes(value)
}

export function roleLabel(role: unknown): string {
  return isRole(role) ? ROLE_LABELS[role] : "Unknown"
}

/** The caller's access as GET /team/{id} reports it. Missing fields (an older server) mean "no permission". */
export interface TeamAccess {
  role: TeamRole | null
  permissions: string[]
  assignable_roles: TeamRole[]
  invitable_roles: TeamRole[]
  has_owner: boolean
}

export function accessFrom(team: unknown): TeamAccess {
  const t = (team && typeof team === "object" ? team : {}) as Record<string, unknown>
  const list = (value: unknown): string[] => (Array.isArray(value) ? value.filter((v): v is string => typeof v === "string") : [])
  return {
    role: isRole(t.role) ? t.role : null,
    permissions: list(t.permissions),
    assignable_roles: list(t.assignable_roles).filter(isRole),
    invitable_roles: list(t.invitable_roles).filter(isRole),
    has_owner: t.has_owner !== false,
  }
}

export function can(access: TeamAccess | null | undefined, permission: string): boolean {
  return !!access && access.permissions.includes(permission)
}

export function isReadOnly(access: TeamAccess | null | undefined): boolean {
  return !!access && access.role === "viewer"
}

/**
 * Whether the caller may change or remove a member holding `targetRole` (the server applies the same rule):
 * owners manage everybody, admins manage members and viewers.
 */
export function canManageMember(access: TeamAccess | null | undefined, targetRole: unknown): boolean {
  if (!access || !isRole(targetRole)) return false
  if (access.role === "owner") return true
  if (access.role === "admin") return targetRole === "member" || targetRole === "viewer"
  return false
}

/** The roles to offer in a member's role selector (always including the member's current role). */
export function roleChoices(access: TeamAccess | null | undefined, targetRole: unknown): TeamRole[] {
  if (!canManageMember(access, targetRole) || !access) return []
  const choices = new Set<TeamRole>(access.assignable_roles)
  if (isRole(targetRole)) choices.add(targetRole)
  return ROLES.filter((r) => choices.has(r))
}

/** Why a change would be refused before asking the server (the last owner), or null. */
export function lastOwnerProblem(members: { role: string }[], targetRole: unknown, newRole: TeamRole | "remove"): string | null {
  const owners = members.filter((m) => m.role === "owner").length
  if (targetRole === "owner" && newRole !== "owner" && owners <= 1) {
    return "A team needs at least one owner: make someone else an owner first."
  }
  return null
}

/** The text of a 403 role refusal, for a toast ("Your role (viewer) cannot create scans. Ask a team admin ..."). */
export function isRoleRefusal(detail: unknown): boolean {
  return typeof detail === "string" && /^Your role \((viewer|member|admin|owner)\) cannot /.test(detail)
}
