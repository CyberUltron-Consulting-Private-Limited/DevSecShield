// Integrations (WP11): ServiceNow, syslog and Splunk HEC (SIEM), signed webhooks, OSCAL push; the delivery log and
// dead-letter list; OSCAL exports of a run or a code scan; and the CMDB import (CSV or ServiceNow pull).
// Secrets are write-only: the API returns the names of stored secrets (secrets_set), never their values.

import api from "@/utils/interceptors"
import { showErrorToast } from "@/utils/error-handler"

export type IntegrationKind = "servicenow" | "syslog" | "splunk_hec" | "webhook" | "oscal"
export type IntegrationEventKind =
  | "opened" | "resolved" | "new_asset" | "removed_asset" | "cert_renewed" | "cert_expiring" | "schedule_skipped"
  | "scan_finished"

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
  last_test: { status: "never" | "ok" | "failed"; at: string | null; message: string | null } | null
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

export async function testIntegration(teamId: number, kind: IntegrationKind): Promise<{ ok: boolean; message: string; at: string }> {
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

function saveBlob(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob)
  const link = document.createElement("a")
  link.href = url
  link.download = filename
  document.body.appendChild(link)
  link.click()
  link.remove()
  setTimeout(() => URL.revokeObjectURL(url), 1000)
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
export interface CmdbPlanCreate {
  kind: "linux_servers" | "network_range"
  name: string
  targets?: string[]
  cidr?: string
  metadata: Record<string, string>
  lines: number[]
}

export interface CmdbPlan {
  rows: number
  digest: string
  unchanged: number
  counts: { create: number; update: number; conflict: number; skipped: number; new_targets: number }
  creates: CmdbPlanCreate[]
  updates: { source_id: number; source: string; kind: string; changes: Record<string, [unknown, unknown]> }[]
  conflicts: { source_id: number; source: string; field: string; values: Record<string, number[]> }[]
  skipped: { line?: number; label?: string | null; reason: string; partial?: boolean }[]
  truncated: boolean
}

export interface CmdbRequest {
  source: "csv" | "servicenow"
  csv?: string
  node_id?: number | null
  create_missing?: boolean
  digest?: string
}

export async function previewCmdbImport(teamId: number, body: CmdbRequest):
  Promise<{ source: string; source_truncated: boolean; plan: CmdbPlan }> {
  return (await api.post(`/${teamId}/cbom/sources/cmdb/preview`, body)).data
}

export async function applyCmdbImport(teamId: number, body: CmdbRequest):
  Promise<{ result: { created: number; updated: number; conflicts: number; skipped: number }; plan: CmdbPlan }> {
  return (await api.post(`/${teamId}/cbom/sources/cmdb/apply`, body)).data
}
