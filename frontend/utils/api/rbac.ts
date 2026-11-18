// F4 RBAC: member roles, ownership, invitations with a role, and the team's audit log.
// Errors propagate to React Query; callers show them (showErrorToast keeps a 403's reason, utils/error-handler.ts).

import api from "@/utils/interceptors"
import type { TeamRole } from "@/utils/rbac"

export async function changeMemberRole(teamId: number, email: string, role: TeamRole) {
  const response = await api.patch(`/team/${teamId}/members/role`, { email, role })
  return response.data as { email: string; role: TeamRole; changed: { email: string; from: TeamRole; to: TeamRole }[] }
}

export async function claimTeamOwnership(teamId: number) {
  const response = await api.post(`/team/${teamId}/ownership/claim`)
  return response.data as { role: "owner" }
}

export async function inviteMembers(teamId: number, emails: string[], role: TeamRole) {
  const response = await api.patch(`/team/${teamId}`, { intent: "add", email_ids: emails, role })
  return response.data as { message: string; invited: string[]; role: TeamRole }
}

export interface AuditEventItem {
  id: number
  at: string | null
  team_id: number | null
  actor_user_id: number | null
  actor_email: string | null
  actor_type: string
  action: string
  object_type: string | null
  object_id: string | null
  outcome: "success" | "denied"
  ip: string | null
  user_agent: string | null
  details: Record<string, unknown>
}

export interface AuditPage {
  events: AuditEventItem[]
  next_before_id: number | null
}

export interface AuditQuery {
  limit?: number
  before_id?: number | null
  action?: string
  actor_email?: string
  outcome?: "success" | "denied" | ""
}

export async function getTeamAudit(teamId: number, query: AuditQuery = {}): Promise<AuditPage> {
  const params: Record<string, string | number> = { limit: query.limit ?? 50 }
  if (query.before_id) params.before_id = query.before_id
  if (query.action) params.action = query.action
  if (query.actor_email) params.actor_email = query.actor_email
  if (query.outcome) params.outcome = query.outcome
  const response = await api.get(`/team/${teamId}/audit`, { params })
  return response.data as AuditPage
}
