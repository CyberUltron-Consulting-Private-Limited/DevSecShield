// Integrations (WP11): ServiceNow, syslog and Splunk HEC (SIEM), signed webhooks, OSCAL push; the delivery log and
// dead-letter list; OSCAL exports of a run or a code scan; and the CMDB import (CSV or ServiceNow pull).
// Secrets are write-only: the API returns the names of stored secrets (secrets_set), never their values.

import api from "@/utils/interceptors"
import { showErrorToast } from "@/utils/error-handler"
import { saveBlob } from "@/utils/download"

export type IntegrationKind = "servicenow" | "syslog" | "splunk_hec" | "webhook" | "oscal"
export type IntegrationEventKind =
  | "opened" | "resolved" | "new_asset" | "removed_asset" | "cert_renewed" | "cert_expiring" | "schedule_skipped"
  | "scan_finished" | "q0_closed" | "agility_asset_moved" | "agility_system_changed"

export interface Integration {
  kind: IntegrationKind
  label: string
  configured: boolean
  allowed_events: IntegrationEventKind[]
  default_events: IntegrationEventKind[]
  id?: number
  enabled: boolean
  config: Record<string, unknown> | null
  secrets_set: string[]
  secrets_required?: string[]
  row_version: number | null
  queue: Partial<Record<"pending" | "delivered" | "dead", number>>
  /** unconfirmed: sent, but the destination cannot acknowledge it (syslog over UDP) */
  last_test: { status: "never" | "ok" | "failed" | "unconfirmed"; at: string | null; message: string | null } | null
  failures?: number
  next_attempt_at?: string | null
  last_delivery_at?: string | null
  last_error?: string | null
  updated_at?: string | null
}

export interface IntegrationsList {
  integrations: Integration[]
  event_types: Record<IntegrationEventKind, string>
  schema: string
  webhook_verify_snippet: string
  private_destinations: { env: string; configured: boolean }
}

export interface IntegrationSave {
  enabled: boolean
  config: Record<string, unknown>
  secrets?: Record<string, string>
  clear_secrets?: string[]
  expected_version?: number | null
}

export interface Delivery {
  id: number
  kind: IntegrationKind
  event_id: string
  event_type: string
  status: "pending" | "delivered" | "dead"
  attempts: number
  queued_at: string | null
  last_attempt_at: string | null
  delivered_at: string | null
  result: string | null
  external_ref: string | null
  code: string | null
  asset: string | null
  source: string | null
  run_id: number | null
  scan_id: number | null
}

export const integrationKeys = {
  all: (teamId: number) => ["integrations", teamId] as const,
  list: (teamId: number) => ["integrations", teamId, "list"] as const,
  deliveries: (teamId: number, kind: string, status: string) => ["integrations", teamId, "deliveries", kind, status] as const,
}

export async function listIntegrations(teamId: number): Promise<IntegrationsList> {
  return (await api.get(`/${teamId}/integrations`)).data
}

export async function saveIntegration(teamId: number, kind: IntegrationKind, body: IntegrationSave): Promise<Integration> {
  return (await api.put(`/${teamId}/integrations/${kind}`, body)).data.integration
}

export async function deleteIntegration(teamId: number, kind: IntegrationKind): Promise<void> {
  await api.delete(`/${teamId}/integrations/${kind}`)
}

export async function testIntegration(teamId: number, kind: IntegrationKind):
  Promise<{ ok: boolean; confirmed?: boolean; status?: "ok" | "failed" | "unconfirmed"; message: string; at: string }> {
  return (await api.post(`/${teamId}/integrations/${kind}/test`)).data
}

export async function listDeliveries(teamId: number, params: { kind?: string; status?: string; before_id?: number; limit?: number }):
  Promise<{ deliveries: Delivery[]; next_before_id: number | null }> {
  const clean = Object.fromEntries(Object.entries(params).filter(([, v]) => v !== undefined && v !== ""))
  return (await api.get(`/${teamId}/integrations/deliveries`, { params: clean })).data
}

export async function retryDeliveries(teamId: number, body: { ids?: number[]; kind?: string; all_dead?: boolean }):
  Promise<{ requeued: number }> {
  return (await api.post(`/${teamId}/integrations/deliveries/retry`, body)).data
}

// ---------------------------------------------------------------- ticketing (SOW S2): Jira and test tickets
export type TicketingKind = "jira" | "servicenow"

/** A "Raise test ticket" result: created (with its key and link), failed, or uncertain (the next click looks it up). */
export interface TestTicket {
  kind: TicketingKind
  status: "pending" | "created" | "failed" | "uncertain"
  ticket_key: string | null
  ticket_url: string | null
  message: string | null
  at: string | null
  click_id: string
  ok?: boolean
  repeated?: boolean
}

/** The team's Jira as Settings > Integrations shows it; the API token is never returned (api_token_set only). */
export interface JiraIntegration {
  kind: "jira"
  label: string
  configured: boolean
  url: string | null
  email: string | null
  api_token_set: boolean
  project_key: string | null
  issue_type: string
  issue_type_default: string
  row_version: number
  last_test: { status: "ok" | "failed"; at: string | null; message: string | null } | null
  last_test_ticket: TestTicket | null
  is_admin: boolean
}

export interface JiraSave {
  url: string
  email: string
  api_token?: string
  project_key?: string | null
  issue_type?: string | null
  expected_version?: number | null
}

export const ticketingKeys = {
  jira: (teamId: number) => ["integrations", teamId, "jira"] as const,
  testTickets: (teamId: number) => ["integrations", teamId, "test-tickets"] as const,
}

export async function getJira(teamId: number): Promise<JiraIntegration> {
  return (await api.get(`/${teamId}/integrations/jira`)).data.jira
}

export async function saveJira(teamId: number, body: JiraSave): Promise<JiraIntegration> {
  return (await api.put(`/${teamId}/integrations/jira`, body)).data.jira
}

export async function deleteJira(teamId: number): Promise<void> {
  await api.delete(`/${teamId}/integrations/jira`)
}

export async function testJira(teamId: number): Promise<{ ok: boolean; status: "ok" | "failed"; message: string; at: string }> {
  return (await api.post(`/${teamId}/integrations/jira/test`)).data
}

/** One clearly labelled test ticket; the same clickId always answers with the same ticket (idempotent per click). */
export async function raiseTestTicket(teamId: number, kind: TicketingKind, clickId: string): Promise<TestTicket> {
  return (await api.post(`/${teamId}/integrations/${kind}/test-ticket`, { click_id: clickId })).data
}

export async function listTestTickets(teamId: number): Promise<{ test_tickets: TestTicket[] }> {
  return (await api.get(`/${teamId}/integrations/test-tickets`)).data
}

/** A fresh id per click (crypto.randomUUID where available). */
export function newClickId(): string {
  if (typeof crypto !== "undefined" && typeof crypto.randomUUID === "function") return crypto.randomUUID()
  const b = new Uint8Array(16)
  crypto.getRandomValues(b)
  b[6] = (b[6] & 0x0f) | 0x40
  b[8] = (b[8] & 0x3f) | 0x80
  const h = Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("")
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`
}

/** OSCAL 1.2.3 assessment results (schema-validated on the server) of a finished run or a CBOM code scan. */
export async function downloadOscal(teamId: number | string, what: { runId?: number; scanId?: number | string }) {
  const path = what.runId != null
    ? `/${teamId}/cbom/sources/runs/${what.runId}/oscal`
    : `/${teamId}/cbom/code-scans/${what.scanId}/oscal`
  try {
    const response = await api.get(path, { responseType: "blob" })
    const name = what.runId != null ? `run-${what.runId}` : `scan-${what.scanId}`
    saveBlob(response.data as Blob, `zeroshield-cbom-${name}-oscal-assessment-results.json`)
  } catch (error) {
    showErrorToast(error, "Error downloading the OSCAL assessment results")
    throw error
  }
}

// ----------------------------------------------------------------------------- CMDB import
export type CmdbVaultProvider = "hashicorp" | "cyberark" | "aws_secrets_manager" | "azure_key_vault"

export interface CmdbPlanCreate {
  kind: "linux_servers" | "windows_servers" | "network_range" | "database" | "kubernetes" | "key_manager"
  name: string
  targets?: string[]
  cidr?: string
  // #225: connection settings of Windows, database, cluster and HSM sources (never a secret)
  config?: Record<string, unknown>
  metadata: Record<string, string>
  lines: number[]
  // #225: the row's scan node (null: the import's node, named in node_name when chosen) and its segment
  node_id?: number | null
  node_name?: string | null
  segment?: string | null
}

export interface CmdbPlan {
  rows: number
  digest: string
  unchanged: number
  counts: { create: number; update: number; conflict: number; skipped: number; new_targets: number; over_limit?: number; merged?: number }
  // #224: the team's source cap, and the new sources past it (never created), each with its reason
  limit?: { used: number; max: number; remaining: number; setting: string }
  warnings?: string[]
  over_limit?: (CmdbPlanCreate & { reason: string })[]
  creates: CmdbPlanCreate[]
  updates: { source_id: number; source: string; kind: string; changes: Record<string, [unknown, unknown]> }[]
  // a conflict on an existing source (source_id, source) or, #362, between rows of the file for one new host (host)
  conflicts: { source_id: number | null; source: string | null; host?: string | null; field: string; values: Record<string, number[]> }[]
  // #362: rows naming the same host merged into one planned source
  merged?: { label: string | null; kind: string; lines: number[]; notes: string[] }[]
  // #367: existing sources the file matched without a change, with their lines; the segments the file's rows use
  unchanged_items?: { source_id: number; source: string; kind: string; lines: number[] }[]
  segments?: { segment: string; rows: number; nodes: { id: number; name: string }[]; chosen: number | null }[]
  skipped: { line?: number; label?: string | null; reason: string; partial?: boolean }[]
  truncated: boolean
}

export interface CmdbRequest {
  source: "csv" | "servicenow"
  csv?: string
  node_id?: number | null
  segment_nodes?: Record<string, number>
  vault_provider?: CmdbVaultProvider | null
  windows_vault?: { provider: CmdbVaultProvider; path: string } | null
  // #363: engine ("mysql", "mssql", "oracle", "mongodb", "redis", or "*" for all of them) -> CA certificate PEM
  database_ca?: Record<string, string>
  create_missing?: boolean
  digest?: string
}

export async function previewCmdbImport(teamId: number, body: CmdbRequest):
  Promise<{ source: string; source_truncated: boolean; plan: CmdbPlan }> {
  return (await api.post(`/${teamId}/cbom/sources/cmdb/preview`, body)).data
}

export async function applyCmdbImport(teamId: number, body: CmdbRequest):
  Promise<{ result: { created: number; updated: number; conflicts: number; skipped: number; over_limit?: number }; plan: CmdbPlan }> {
  return (await api.post(`/${teamId}/cbom/sources/cmdb/apply`, body)).data
}
