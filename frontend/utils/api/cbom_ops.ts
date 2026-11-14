// CBOM outputs B: compare runs and code scans, drift events ("Changes"), schedules, remediation waves, the heat-map
// and certificate calendar of a run, and SBOM links. Errors propagate to React Query (the cards show them inline).

import api from "@/utils/interceptors"

export type CbomImpactLevel = "Critical" | "High" | "Medium" | "Low"

export interface CbomDiffAsset {
  key: string
  label: string
  type: string
  impact: CbomImpactLevel | null
  finding_codes: string[]
  quantum_vulnerable: boolean | null
  asset_id?: number | null
  source_name?: string | null
  code?: string
  renewed?: boolean
  changes?: Record<string, [unknown, unknown]>
  asset_removed?: boolean
  new_asset?: boolean
  rule_change?: string
  /** not_read only: the findings that could not be confirmed, and why (the coverage row's detail) */
  codes?: string[]
  reason?: string | null
}

export interface CbomDiffSource {
  source_ref: string
  name: string | null
  status: "compared" | "not_compared"
  reason: string | null
  counts?: Record<string, number>
}

export interface CbomDiff {
  run_id?: number
  against_run_id?: number | null
  scan_id?: number
  against_scan_id?: number | null
  message?: string
  versions?: { before: unknown; after: unknown; rules_changed: boolean; reclassified: boolean }
  sources?: CbomDiffSource[]
  added?: CbomDiffAsset[]
  removed?: CbomDiffAsset[]
  changed?: CbomDiffAsset[]
  opened?: CbomDiffAsset[]
  resolved?: CbomDiffAsset[]
  /** assets of a compared source that the later run did not read (a coverage gap): neither removed nor resolved */
  not_read?: CbomDiffAsset[]
  rule_changes?: { key: string; label: string; code: string; direction: string; label_change: string }[]
  /** findings that vanished only because a collector started sending a new fact (CB-33): not drift, no event */
  collector_changes?: { key: string; label: string; code: string; direction: string; label_change: string }[]
  readiness?: { before: number | null; after: number | null; delta: number | null }
  counts?: Record<string, number>
  truncated?: boolean
}

export type CbomDriftKind =
  | "opened" | "resolved" | "new_asset" | "removed_asset" | "cert_renewed" | "cert_expiring" | "schedule_skipped"

export interface CbomDriftEvent {
  id: number
  at: string
  scope: "node" | "code"
  kind: CbomDriftKind
  run_id: number | null
  baseline_run_id: number | null
  scan_id: number | null
  source_name: string | null
  asset_label: string | null
  code: string | null
  severity: string | null
  detail: Record<string, unknown>
}

export interface CbomRunChanges {
  run_id: number
  status: string
  recorded: boolean
  counts: Partial<Record<CbomDriftKind, number>>
  events: CbomDriftEvent[]
  /** not read again under a coverage gap (no event: neither removed nor resolved), with the reason */
  not_read?: CbomDiffAsset[]
  not_read_count?: number
}

export interface CbomHeatCell {
  row: string
  column: string
  count: number
  worst: CbomImpactLevel | "none"
  by_impact: Record<string, number>
}

export interface CbomCalendarCert {
  name?: string | null
  not_after: string
  days_left?: number
  subject?: string | null
  issuer?: string | null
  target?: string | null
  location?: string | null
  source_name?: string | null
}

export interface CbomRunHeatmap {
  by: "source" | "type"
  rows: string[]
  columns: string[]
  cells: CbomHeatCell[]
  certificates: CbomCalendarCert[]
}

export type CbomFrequency = "daily" | "weekly" | "monthly"

export interface CbomSchedule {
  id: number
  name: string
  enabled: boolean
  frequency: CbomFrequency
  time_of_day: string
  weekday: number | null
  monthday: number | null
  include: Record<string, boolean>
  source_ids: number[]
  min_criticality: string | null
  soc_ack: boolean
  next_run_at: string | null
  last_slot: string | null
  last_run_id: number | null
  last_status: string | null
  last_message: string | null
  row_version: number
}

export type CbomScheduleWrite = Partial<Omit<CbomSchedule, "id" | "next_run_at" | "last_slot" | "last_run_id" |
  "last_status" | "last_message" | "row_version">> & { expected_version?: number }

export type CbomWaveStatus = "open" | "in_progress" | "done" | "accepted_risk"

export interface CbomRemediationItem {
  asset_key: string
  asset_id?: number
  row_index?: number
  bom_ref?: string | null
  scope: "node" | "code"
  label: string
  type: string | null
  impact: CbomImpactLevel | null
  finding_codes: string[]
  quantum_vulnerable: boolean | null
  exposure: string
  hndl: boolean
  owner_hint?: string | null
  source_name?: string | null
  suggested_wave: number | null
  wave: number | null
  wave_source: "assigned" | "suggested"
  assignment: null | { wave: number | null; owner: string | null; target_date: string | null; status: CbomWaveStatus;
    note: string | null }
}

export interface CbomRemediation {
  items: CbomRemediationItem[]
  by_wave: Record<string, number>
  labels: Record<string, string>
}

export interface CbomAssignmentPatch {
  asset_key: string
  wave?: number | null
  owner?: string | null
  target_date?: string | null
  status?: CbomWaveStatus
  note?: string | null
}

export interface CbomSbomMatch { scan_id: number; scan_title: string; match: "purl" | "name_version" | "name"; component: string; purl: string | null }

const src = (teamId: number) => `/${teamId}/cbom/sources`

export async function getCbomRunDiff(teamId: number, runId: number, against?: number): Promise<CbomDiff> {
  return (await api.get(`${src(teamId)}/runs/${runId}/diff`, { params: against ? { against } : {} })).data
}

export async function getCbomRunChanges(teamId: number, runId: number): Promise<CbomRunChanges> {
  return (await api.get(`${src(teamId)}/runs/${runId}/changes`)).data
}

export async function getCbomRunHeatmap(teamId: number, runId: number, by: "source" | "type" = "source"): Promise<CbomRunHeatmap> {
  return (await api.get(`${src(teamId)}/runs/${runId}/heatmap`, { params: { by } })).data
}

export async function getCbomCodeDiff(teamId: number, scanId: number, against?: number): Promise<CbomDiff> {
  return (await api.get(`/${teamId}/cbom/code-scans/${scanId}/diff`, { params: against ? { against } : {} })).data
}

export async function listCbomSchedules(teamId: number): Promise<{ schedules: CbomSchedule[]; timezone: string }> {
  return (await api.get(`${src(teamId)}/schedules`)).data
}

export async function createCbomSchedule(teamId: number, body: CbomScheduleWrite): Promise<{ schedule: CbomSchedule }> {
  return (await api.post(`${src(teamId)}/schedules`, body)).data
}

export async function updateCbomSchedule(teamId: number, id: number, body: CbomScheduleWrite): Promise<{ schedule: CbomSchedule }> {
  return (await api.patch(`${src(teamId)}/schedules/${id}`, body)).data
}

export async function deleteCbomSchedule(teamId: number, id: number): Promise<void> {
  await api.delete(`${src(teamId)}/schedules/${id}`)
}

export async function getCbomRunRemediation(teamId: number, runId: number): Promise<CbomRemediation> {
  return (await api.get(`${src(teamId)}/runs/${runId}/remediation`)).data
}

export async function getCbomCodeRemediation(teamId: number, scanId: number): Promise<CbomRemediation> {
  return (await api.get(`/${teamId}/cbom/code-scans/${scanId}/remediation`)).data
}

export async function putCbomRemediation(
  teamId: number, body: { run_id?: number; scan_id?: number; items: CbomAssignmentPatch[] },
): Promise<{ updated: number }> {
  return (await api.put(`/${teamId}/cbom/remediation`, body)).data
}

export async function getCbomAssetSbom(teamId: number, assetId: number): Promise<{ purl: string | null; matches: CbomSbomMatch[] }> {
  return (await api.get(`${src(teamId)}/assets/${assetId}/sbom`)).data
}

export async function getCbomCodeSbomLinks(teamId: number, scanId: number): Promise<{
  libraries: { bom_ref: string | null; name: string; version: string | null; purl: string | null; matches: CbomSbomMatch[] }[]
}> {
  return (await api.get(`/${teamId}/cbom/code-scans/${scanId}/sbom-links`)).data
}

/** Query keys (under the CBOM Sources prefix so a mutation's invalidation refreshes them). */
export const cbomOpsKeys = {
  diff: (teamId: number, runId: number, against?: number) => ["cbom-sources", teamId, "run", runId, "diff", against ?? "prev"] as const,
  changes: (teamId: number, runId: number) => ["cbom-sources", teamId, "run", runId, "changes"] as const,
  heatmap: (teamId: number, runId: number, by: string) => ["cbom-sources", teamId, "run", runId, "heatmap", by] as const,
  schedules: (teamId: number) => ["cbom-sources", teamId, "schedules"] as const,
  runRemediation: (teamId: number, runId: number) => ["cbom-sources", teamId, "run", runId, "remediation"] as const,
  codeRemediation: (teamId: number, scanId: number) => ["cbom-sources", teamId, "code", scanId, "remediation"] as const,
  codeDiff: (teamId: number, scanId: number) => ["cbom-sources", teamId, "code", scanId, "diff"] as const,
  assetSbom: (teamId: number, assetId: number) => ["cbom-sources", teamId, "asset", assetId, "sbom"] as const,
  codeSbom: (teamId: number, scanId: number) => ["cbom-sources", teamId, "code", scanId, "sbom"] as const,
}
