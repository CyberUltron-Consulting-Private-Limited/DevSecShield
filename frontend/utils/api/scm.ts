// Code repositories at scale (F3): SCM connections, the repository inventory, scan policies, bulk runs and the
// cross-repository roll-up (backend/routers/scm.py). Credentials are write-only: the API answers `secrets_set`, and a
// connection's webhook secret is returned once, at creation or rotation. Errors propagate to React Query; the pages
// show the server's sentence (refusalReason).

import api from "@/utils/interceptors"

export type ScmProvider = "github" | "gitlab" | "bitbucket"
export type ScmAuthKind = "github_app" | "token"
export type ScmScopeKind = "installation" | "org" | "user" | "group" | "workspace"
export type ScmProduct = "sast" | "iac" | "sbom_sca" | "cbom" | "ai_bom"
export type ScmVisibility = "public" | "private" | "internal"

export interface ScmFilters {
  include_names: string[]
  exclude_names: string[]
  topics_any: string[]
  exclude_topics: string[]
  languages: string[]
  include_archived: boolean
  include_forks: boolean
  visibility: ScmVisibility[]
  max_size_mb: number | null
}

export interface ScmSyncSummary {
  status?: string
  discovered?: number
  in_scope?: number
  added?: number
  updated?: number
  removed?: number
  restored?: number
  api_calls?: number
  pages?: number
  retries?: number
  waits?: number
  waited_s?: number
  rate_limit?: number | null
  rate_remaining?: number | null
  duration_s?: number
  at?: string
}

export interface ScmConnection {
  id: number
  name: string
  provider: ScmProvider
  auth_kind: ScmAuthKind
  api_base: string
  scope_kind: ScmScopeKind
  scope_name: string
  config: { app_id?: string | null; installation_id?: string | null; include_subgroups?: boolean }
  filters: Partial<ScmFilters>
  secrets_set: string[]
  enabled: boolean
  webhook_path: string
  webhook_secret_set: boolean
  sync_interval_min: number
  sync: { status: string; last_at: string | null; next_at: string | null; requested_at: string | null; summary: ScmSyncSummary; error: string | null }
  last_test: { status: string; at: string | null; message: string | null }
  row_version: number
  created_at: string | null
  updated_at: string | null
  repos?: number
  repos_in_scope?: number
}

export interface ScmConnectionCreate {
  name: string
  provider: ScmProvider
  auth_kind: ScmAuthKind
  api_base?: string | null
  scope_kind: ScmScopeKind
  scope_name: string
  config?: { app_id?: string | null; installation_id?: string | null; include_subgroups?: boolean }
  secrets: Record<string, string>
  filters?: Partial<ScmFilters>
  sync_interval_min?: number
}

export interface ScmWebhookOnce {
  path: string
  secret: string
}

export interface ScmPreview {
  discovered: number
  in_scope: number
  reasons: Record<string, number>
  sample_in: string[]
  sample_out: { full_name: string; reason: string }[]
  estimate: { per_product: Partial<Record<ScmProduct, number>>; credits: number; formula: string }
  sync: { status: string; last_at: string | null }
}

export interface ScmRepoScan {
  scan_id: number
  status: string
  at: string
  branch?: string
  findings?: number
}

export interface ScmRepository {
  id: number
  connection_id: number
  connection: string | null
  full_name: string
  name: string
  web_url: string
  default_branch: string
  visibility: string
  archived: boolean
  fork: boolean
  language: string | null
  topics: string[]
  size_kb: number
  pushed_at: string | null
  in_scope: boolean
  scope_reason: string
  manual_state: "include" | "exclude" | null
  pinned_policy_id: number | null
  policy: { id: number; name: string; why: string; products: ScmProduct[]; on_push: boolean } | null
  removed_at: string | null
  last_scan_at: string | null
  last_scans: Partial<Record<ScmProduct, ScmRepoScan>>
  first_seen_at: string | null
}

export interface ScmRepositoryPage {
  items: ScmRepository[]
  total: number
  page: number
  page_size: number
  facets: { languages: Record<string, number>; reasons: Record<string, number>; in_scope: number }
}

export interface ScmRepositoryQuery {
  connection_id?: number
  q?: string
  scope?: "in" | "out" | "all" | "removed"
  language?: string
  reason?: string
  policy_id?: number
  scanned?: "never" | "yes"
  page?: number
  page_size?: number
}

export interface ScmSchedule {
  frequency: "off" | "daily" | "weekly" | "monthly"
  time_of_day: string
  weekday?: number | null
  monthday?: number | null
  timezone: string
}

export interface ScmPolicyOptions {
  iac_modes?: string[]
  environment?: "production" | "staging" | "development"
  cbom_scan_binaries?: boolean
  cbom_include_vendored?: boolean
  cbom_scan_history?: boolean
}

export interface ScmPolicy {
  id: number
  name: string
  position: number
  enabled: boolean
  selector: Partial<ScmFilters>
  products: ScmProduct[]
  branch: string
  on_push: boolean
  schedule: ScmSchedule
  options: ScmPolicyOptions
  next_run_at: string | null
  last_fired_at: string | null
  last_status: string | null
  last_message: string | null
  last_run_id: number | null
  row_version: number
  repos_matched: number | null
}

export interface ScmPolicyBody {
  name: string
  position: number
  enabled: boolean
  selector: ScmFilters
  products: ScmProduct[]
  branch: string
  on_push: boolean
  schedule: ScmSchedule
  options: ScmPolicyOptions
  expected_version?: number | null
}

export interface ScmPolicyPreview {
  repos: number
  sample: string[]
  taken_by_other_policies: Record<string, number>
  credits_per_run: number
  formula: string
}

export interface ScmEstimate {
  scans: number
  repos: number
  credits: number
  per_product: Partial<Record<ScmProduct, { scans: number; credits: number }>>
  skipped: { repo_id: number; product: string; reason: string }[]
  skipped_counts: Record<string, number>
  balance: number
  affordable: boolean
  formula: string
}

export interface ScmRunBody {
  repo_ids?: number[]
  policy_id?: number
  products?: ScmProduct[]
  branch?: string
  expected_credits?: number
  client_request_id?: string
}

export interface ScmRunSummary {
  run_id: number
  status: string
  trigger: string
  policy_id: number | null
  queued: number
  credits: number
  refunded: number
  skipped_counts: Record<string, number>
}

export interface ScmRun {
  id: number
  trigger: "manual" | "schedule" | "push"
  policy_id: number | null
  status: "queued" | "running" | "done" | "cancelled"
  totals: { scans?: number; repos?: number; skipped_counts?: Record<string, number>; commit?: string }
  credits: number
  refunded: number
  requests: Record<string, number>
  created_at: string | null
  finished_at: string | null
}

export interface ScmQueueStats {
  by_status: Record<string, number>
  queued_by_trigger: Record<string, number>
  max_inflight: number
  team_max_inflight: number
  teams_waiting: number
}

export interface ScmRunRequest {
  id: number
  repo_id: number
  repo: string
  product: ScmProduct
  branch: string
  status: string
  priority: number
  scan_id: number | null
  credits: number
  refunded: boolean
  error: string | null
  enqueued_at: string | null
  dispatched_at: string | null
  finished_at: string | null
}

export interface ScmFinding {
  id: number
  product: ScmProduct
  title: string
  severity: "critical" | "high" | "medium" | "low" | "info"
  repo_count: number
  occurrence_count: number
  key_fields: Record<string, unknown>
  first_seen_at: string | null
  last_seen_at: string | null
  resolved_at: string | null
}

export interface ScmRollup {
  products: Partial<Record<ScmProduct, { findings_total: number; occurrences: number; findings_open: number; repos_affected: number; dedup_ratio: number | null }>>
  repos_in_scope: number
  repos_scanned: number
  by_severity: Record<string, number>
  top: { id: number; product: ScmProduct; title: string; severity: string; repo_count: number }[]
}

const base = (teamId: number) => `/${teamId}/scm`

export async function listScmConnections(teamId: number): Promise<{ connections: ScmConnection[]; default_api: Record<ScmProvider, string> }> {
  return (await api.get(`${base(teamId)}/connections`)).data
}
export async function createScmConnection(teamId: number, body: ScmConnectionCreate): Promise<{ connection: ScmConnection; webhook: ScmWebhookOnce }> {
  return (await api.post(`${base(teamId)}/connections`, body)).data
}
export async function getScmConnection(teamId: number, id: number): Promise<{ connection: ScmConnection }> {
  return (await api.get(`${base(teamId)}/connections/${id}`)).data
}
export async function updateScmConnection(teamId: number, id: number, body: Record<string, unknown>): Promise<{ connection: ScmConnection }> {
  return (await api.patch(`${base(teamId)}/connections/${id}`, body)).data
}
export async function deleteScmConnection(teamId: number, id: number): Promise<{ deleted: number; repositories: number; refunded: number }> {
  return (await api.delete(`${base(teamId)}/connections/${id}`)).data
}
export async function testScmConnection(teamId: number, id: number): Promise<{ ok: boolean; message: string }> {
  return (await api.post(`${base(teamId)}/connections/${id}/test`)).data
}
export async function syncScmConnection(teamId: number, id: number): Promise<{ status: string; connection: ScmConnection }> {
  return (await api.post(`${base(teamId)}/connections/${id}/sync`)).data
}
export async function rotateScmWebhookSecret(teamId: number, id: number): Promise<{ webhook: ScmWebhookOnce }> {
  return (await api.post(`${base(teamId)}/connections/${id}/webhook-secret`)).data
}
export async function previewScmFilters(teamId: number, id: number, filters: ScmFilters, products: ScmProduct[]): Promise<ScmPreview> {
  return (await api.post(`${base(teamId)}/connections/${id}/preview`, { filters, products })).data
}
export async function applyScmFilters(teamId: number, id: number, filters: ScmFilters, expectedVersion?: number): Promise<{ changed: number; in_scope: number; connection: ScmConnection }> {
  return (await api.put(`${base(teamId)}/connections/${id}/filters`, { filters, expected_version: expectedVersion ?? null })).data
}

export async function listScmRepositories(teamId: number, query: ScmRepositoryQuery): Promise<ScmRepositoryPage> {
  const params = Object.fromEntries(Object.entries(query).filter(([, v]) => v !== undefined && v !== null && v !== ""))
  return (await api.get(`${base(teamId)}/repositories`, { params })).data
}
export async function bulkScmRepositories(
  teamId: number,
  body: { repo_ids: number[]; action: "include" | "exclude" | "reset" | "pin_policy" | "unpin_policy"; policy_id?: number },
): Promise<{ changed: number }> {
  return (await api.post(`${base(teamId)}/repositories/bulk`, body)).data
}

export async function listScmPolicies(teamId: number): Promise<{ policies: ScmPolicy[]; products: ScmProduct[]; iac_modes: string[] }> {
  return (await api.get(`${base(teamId)}/policies`)).data
}
export async function createScmPolicy(teamId: number, body: ScmPolicyBody): Promise<{ policy: ScmPolicy }> {
  return (await api.post(`${base(teamId)}/policies`, body)).data
}
export async function updateScmPolicy(teamId: number, id: number, body: ScmPolicyBody): Promise<{ policy: ScmPolicy }> {
  return (await api.put(`${base(teamId)}/policies/${id}`, body)).data
}
export async function deleteScmPolicy(teamId: number, id: number): Promise<{ deleted: number }> {
  return (await api.delete(`${base(teamId)}/policies/${id}`)).data
}
export async function previewScmPolicy(
  teamId: number,
  body: { selector: ScmFilters; products: ScmProduct[]; position: number; policy_id?: number | null },
): Promise<ScmPolicyPreview> {
  return (await api.post(`${base(teamId)}/policies/preview`, body)).data
}

export async function estimateScmRun(teamId: number, body: ScmRunBody): Promise<ScmEstimate> {
  return (await api.post(`${base(teamId)}/runs/estimate`, body)).data
}
export async function createScmRun(teamId: number, body: ScmRunBody): Promise<{ run: ScmRunSummary }> {
  return (await api.post(`${base(teamId)}/runs`, body)).data
}
export async function listScmRuns(teamId: number, limit = 25): Promise<{ runs: ScmRun[]; queue: ScmQueueStats }> {
  return (await api.get(`${base(teamId)}/runs`, { params: { limit } })).data
}
export async function getScmRun(teamId: number, id: number, page = 1, status?: string): Promise<{ run: ScmRun; requests: ScmRunRequest[]; page: number; page_size: number }> {
  return (await api.get(`${base(teamId)}/runs/${id}`, { params: { page, page_size: 50, ...(status ? { status } : {}) } })).data
}
export async function cancelScmRun(teamId: number, id: number): Promise<{ refunded: number }> {
  return (await api.post(`${base(teamId)}/runs/${id}/cancel`)).data
}

export async function listScmFindings(
  teamId: number,
  query: { product?: ScmProduct; severity?: string; q?: string; min_repos?: number; include_resolved?: boolean; page?: number },
): Promise<{ items: ScmFinding[]; total: number; page: number; page_size: number }> {
  const params = Object.fromEntries(Object.entries(query).filter(([, v]) => v !== undefined && v !== null && v !== ""))
  return (await api.get(`${base(teamId)}/findings`, { params })).data
}
export async function getScmFinding(teamId: number, id: number): Promise<{
  finding: ScmFinding
  repositories: { repo_id: number; repo: string; web_url: string; scan_id: number | null; count: number; locations: string[]; last_seen_at: string | null }[]
}> {
  return (await api.get(`${base(teamId)}/findings/${id}`)).data
}
export async function getScmRollup(teamId: number): Promise<ScmRollup> {
  return (await api.get(`${base(teamId)}/rollup`)).data
}
