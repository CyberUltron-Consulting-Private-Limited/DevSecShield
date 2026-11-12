/**
 * F4 RBAC: how the audit log page words an event. Actions are permission names (team.update, scan.create, ...) or
 * domain events (team.members.role, auth.login, ...); unknown ones are shown as they are.
 */
import type { AuditEventItem } from "@/utils/api/rbac"

const ACTION_LABELS: Record<string, string> = {
  "team.create": "Created the team",
  "team.update": "Changed team settings",
  "team.delete": "Deleted the team",
  "team.integrations.manage": "Changed an integration",
  "team.members.invite": "Invited someone",
  "team.members.invite.resend": "Re-sent an invitation",
  "team.members.invite.revoke": "Revoked an invitation",
  "team.members.join": "Joined the team",
  "team.members.remove": "Removed a member",
  "team.members.role": "Changed a role",
  "team.ownership.claim": "Became the owner",
  "scan.create": "Created a scan",
  "scan.update": "Changed or deleted a scan",
  "scan.run": "Started, estimated or cancelled a scan",
  "finding.triage": "Changed a finding or created a ticket",
  "finding.remediate": "Generated a remediation",
  "certin.write": "Changed an attestation or signature",
  "dast.manage": "Changed a DAST profile",
  "dast.run": "Ran a DAST profile",
  "cicd.manage": "Changed a CI/CD integration",
  "guardrails.manage": "Changed a guardrails integration",
  "cbom.write": "Changed CBOM sources",
  "cbom.settings": "Changed CBOM network settings",
  "auth.login": "Signed in",
  "auth.logout": "Signed out",
  "auth.signup": "Signed up",
  "auth.password.change": "Changed their password",
  "auth.password.reset": "Reset their password",
}

export function auditActionLabel(action: string, outcome?: string): string {
  const label = ACTION_LABELS[action] ?? action
  return outcome === "denied" ? `Refused: ${label.charAt(0).toLowerCase()}${label.slice(1)}` : label
}

export function auditObjectText(event: Pick<AuditEventItem, "object_type" | "object_id" | "details">): string {
  const details = event.details ?? {}
  const email = typeof details.email === "string" ? details.email : null
  if (event.object_type === "member" && email) return `member ${email}`
  if (event.object_type === "invitation" && email) return `invitation for ${email}`
  if (!event.object_type) return "-"
  return event.object_id ? `${event.object_type} ${event.object_id}` : event.object_type
}

export function auditDetailText(event: Pick<AuditEventItem, "details" | "outcome">): string {
  const d = event.details ?? {}
  const parts: string[] = []
  if (typeof d.from === "string" && typeof d.to === "string") parts.push(`${d.from} → ${d.to}`)
  if (typeof d.role === "string" && d.from === undefined) parts.push(`role ${d.role}`)
  if (typeof d.reason === "string") parts.push(event.outcome === "denied" ? `refused: ${d.reason}` : d.reason)
  if (typeof d.product === "string") parts.push(String(d.product))
  if (typeof d.method === "string" && typeof d.route === "string") parts.push(`${d.method} ${d.route}`)
  return parts.join(" · ") || "-"
}
