// CBOM fleet onboarding (F1): which fleet features this deployment has turned on, and F1.2's inventory, policies and
// credentials. Each feature is a server-side flag (CBOM_FLEET_INVENTORY, CBOM_FLEET_POLICIES, CBOM_FLEET_TRANSPORTS,
// CBOM_SSH_CA; all off by default); a route whose flag is off answers 404. The Fleet tab and each of its sections show
// only what is on. Errors propagate to React Query (the forms show the server's reason inline).

import api from "@/utils/interceptors"

export interface CbomFleetStatus {
  inventory: boolean
  policies: boolean
  transports: boolean
  ssh_ca: boolean
}

export async function getCbomFleetStatus(teamId: number): Promise<CbomFleetStatus> {
  const response = await api.get(`/${teamId}/cbom/sources/fleet/status`)
  return response.data
}

const base = (teamId: number) => `/${teamId}/cbom/sources/fleet`

// ---------------------------------------------------------------------------- inventory
export type CbomTargetKind =
  | "linux_host" | "windows_host" | "database" | "k8s_cluster" | "load_balancer" | "certificate" | "kms_key" | "secret" | "other"
export type CbomDecisionAction = "collect" | "never_scan" | "unmanaged"

export interface CbomDecision {
  action: CbomDecisionAction
  policy_id: number | null
  matched_policy_ids: number[]
  transport: "ssh" | "awx" | "salt" | "ssm" | null
  transport_id: number | null
  credential_id: number | null
  node_id: number | null
  node_segment: string | null
  tier: number
  schedule: CbomPolicySchedule | null
  batch_size: number
  reason: string
}

export interface CbomInventoryTarget {
  id: number
  inventory_source_id: number
  external_id: string
  kind: CbomTargetKind
  address: string | null
  addresses: string[]
  hostname: string | null
  tags: Record<string, string>
  account_id: string | null
  region: string | null
  platform: string | null
  handles: Record<string, string>
  attributes: Record<string, unknown>
  first_seen_at: string | null
  last_seen_at: string | null
  missing_since: string | null
  /** removed from the inventory by a person (deleted, or its inventory source deleted): never collected again */
  deleted_at: string | null
  managed_source_id: number | null
  /** its managed source has a job running: the change waits for it (the fleet worker retries every minute) */
  pending: boolean
  pending_since: string | null
  decision: CbomDecision
}

/** Whether the stored decisions and counts are current. A write to a large inventory is evaluated by the fleet
 * worker within seconds; until then the lists serve the previous decisions with ``stale``. */
export interface CbomFleetEvaluation {
  evaluated_at: string | null
  stale: boolean
  evaluation_requested: boolean
  reconcile_requested: boolean
  last_reconcile: Partial<CbomReconcileResult> & { at?: string }
}

/** What a write answers about the decisions: evaluated in the request ("done"), or by the fleet worker ("queued"). */
export interface CbomWriteEvaluation {
  evaluation: "done" | "queued"
  decisions_changed: number | null
}

export interface CbomPolicyRef {
  name: string
  priority: number
  enabled: boolean
  deleted: boolean
}

export interface CbomTargetPage {
  targets: CbomInventoryTarget[]
  next_cursor: number | null
  total: number
  policies: Record<string, CbomPolicyRef>
  evaluation: CbomFleetEvaluation
}

export interface CbomTargetFilters {
  kind?: string
  /** a tag key (it may contain colons, as AWS system tags do); with tag_value, that value only */
  tag_key?: string
  tag_value?: string
  q?: string
  missing?: "yes" | "no" | "all"
  source_id?: number
  decision?: CbomDecisionAction
  cursor?: number
  limit?: number
}

export async function listCbomInventoryTargets(teamId: number, filters: CbomTargetFilters): Promise<CbomTargetPage> {
  const params = Object.fromEntries(Object.entries(filters).filter(([, v]) => v !== undefined && v !== ""))
  const response = await api.get(`${base(teamId)}/inventory/targets`, { params })
  return response.data
}

export interface CbomTargetDetail {
  target: CbomInventoryTarget
  decision: CbomDecision
  matched_policies: { id: number; name: string; priority: number; won: boolean }[]
  managed_source: { id: number; name: string } | null
}

export async function getCbomInventoryTarget(teamId: number, targetId: number): Promise<CbomTargetDetail> {
  const response = await api.get(`${base(teamId)}/inventory/targets/${targetId}`)
  return response.data
}

export interface CbomImportResult {
  created: number
  updated: number
  unchanged: number
  missing: number
  /** rows another inventory source already lists: that source owns them */
  skipped: number
  /** a row's problem (``row``), or a target's (``external_id``) such as which source owns it */
  errors: { row?: number; external_id?: string; error: string }[]
  error_count: number
  rows: number
  digest: string
  dry_run: boolean
  inventory_source_id: number
  missing_skipped: boolean
}

export async function importCbomInventory(
  teamId: number,
  body: { format: "csv" | "json"; content: string; inventory_source_id?: number | null; dry_run?: boolean },
): Promise<CbomImportResult> {
  const response = await api.post(`${base(teamId)}/inventory/import`, body)
  return response.data
}

export async function deleteCbomInventoryTarget(teamId: number, targetId: number): Promise<{ deleted: number } & CbomWriteEvaluation> {
  const response = await api.delete(`${base(teamId)}/inventory/targets/${targetId}`)
  return response.data
}

export interface CbomInventorySource {
  id: number
  kind: "aws" | "csv" | "json" | "api"
  name: string
  config: { aws_account_source_id?: number; regions?: string[]; services?: string[] }
  enabled: boolean
  sync_every_min: number
  last_sync_at: string | null
  last_sync_status: "never" | "queued" | "running" | "ok" | "partial" | "failed"
  last_sync_summary: Record<string, unknown> & { error?: string; created?: number; updated?: number; missing?: number }
  coverage: Record<string, Record<string, string>>
  syncing: boolean
  target_count: number | null
  row_version: number
  created_at: string | null
  last_updated: string | null
}

export async function listCbomInventorySources(teamId: number): Promise<{
  sources: CbomInventorySource[]
  aws_accounts: { id: number; name: string; validated: boolean }[]
}> {
  const response = await api.get(`${base(teamId)}/inventory/sources`)
  return response.data
}

export async function createCbomInventorySource(
  teamId: number,
  body: { kind: "aws" | "csv" | "json" | "api"; name: string; config?: Record<string, unknown>; sync_every_min?: number },
): Promise<{ source: CbomInventorySource }> {
  const response = await api.post(`${base(teamId)}/inventory/sources`, body)
  return response.data
}

export async function updateCbomInventorySource(
  teamId: number,
  sourceId: number,
  body: { name?: string; config?: Record<string, unknown>; sync_every_min?: number; enabled?: boolean; expected_version?: number },
): Promise<{ source: CbomInventorySource }> {
  const response = await api.patch(`${base(teamId)}/inventory/sources/${sourceId}`, body)
  return response.data
}

export async function deleteCbomInventorySource(
  teamId: number,
  sourceId: number,
): Promise<{ deleted: number; targets_removed: number } & CbomWriteEvaluation> {
  const response = await api.delete(`${base(teamId)}/inventory/sources/${sourceId}`)
  return response.data
}

export async function syncCbomInventorySource(teamId: number, sourceId: number): Promise<{ sync_id: string; status: string }> {
  const response = await api.post(`${base(teamId)}/inventory/sources/${sourceId}/sync`)
  return response.data
}

// ---------------------------------------------------------------------------- policies
export interface CbomPolicySchedule {
  frequency: "daily" | "weekly" | "monthly"
  time_of_day: string
  weekday: number | null
  monthday: number | null
}

export type CbomSelector = Record<string, unknown>

export interface CbomPolicyAction {
  never_scan?: boolean
  transport?: "ssh" | "awx" | "salt" | "ssm"
  transport_id?: number | null
  credential_id?: number | null
  node_id?: number | null
  node_segment?: string | null
  tier?: 1 | 2
  batch_size?: number
  schedule?: CbomPolicySchedule | null
}

export interface CbomFleetPolicy {
  id: number
  name: string
  enabled: boolean
  priority: number
  selector: CbomSelector
  action: CbomPolicyAction
  row_version: number
  matched_targets: number | null
  won_targets?: number
  precedence?: number | null
  created_at: string | null
  last_updated: string | null
}

export interface CbomPolicyWrite {
  name: string
  enabled?: boolean
  priority: number
  selector: CbomSelector
  action: CbomPolicyAction
}

export async function listCbomPolicies(
  teamId: number,
): Promise<{ policies: CbomFleetPolicy[]; materialize: boolean; order: string; evaluation: CbomFleetEvaluation }> {
  const response = await api.get(`${base(teamId)}/policies`)
  return response.data
}

export async function createCbomPolicy(teamId: number, body: CbomPolicyWrite): Promise<{ policy: CbomFleetPolicy } & CbomWriteEvaluation> {
  const response = await api.post(`${base(teamId)}/policies`, body)
  return response.data
}

export async function updateCbomPolicy(
  teamId: number,
  policyId: number,
  body: Partial<CbomPolicyWrite> & { expected_version?: number },
): Promise<{ policy: CbomFleetPolicy } & CbomWriteEvaluation> {
  const response = await api.patch(`${base(teamId)}/policies/${policyId}`, body)
  return response.data
}

export async function deleteCbomPolicy(teamId: number, policyId: number): Promise<{ deleted: number } & CbomWriteEvaluation> {
  const response = await api.delete(`${base(teamId)}/policies/${policyId}`)
  return response.data
}

export interface CbomPolicyPreview {
  matched: number
  would_collect: number
  never_scan: number
  conflicts: { winner_policy_id: number | null; winner: string | null; loser_policy_id: number | null; loser: string | null; targets: number }[]
  sample: (CbomInventoryTarget & { won: boolean })[]
  /** the draft as it will be saved; a disabled one matches nothing */
  enabled: boolean
  /** with ``enabled`` false: what it would match once enabled */
  matched_if_enabled?: number
}

export async function previewCbomPolicy(
  teamId: number,
  // a draft, a saved policy, or both: an edit previewed in place of the saved policy
  body: { policy: CbomPolicyWrite; policy_id?: number } | { policy_id: number },
): Promise<CbomPolicyPreview> {
  const response = await api.post(`${base(teamId)}/policies/preview`, body)
  return response.data
}

export interface CbomReconcileResult {
  materialize: boolean
  sources_created: number
  sources_updated: number
  sources_removed: number
  deferred: number
  targets_assigned: number
  targets_unassigned: number
  schedules_created: number
  schedules_updated: number
  schedules_removed: number
  decisions_changed: number
  problems: string[]
}

export async function reconcileCbomFleet(teamId: number): Promise<CbomReconcileResult> {
  const response = await api.post(`${base(teamId)}/reconcile`)
  return response.data
}

// ---------------------------------------------------------------------------- credentials
export type CbomCredentialType = "node_key" | "password" | "ssh_cert" | "vault" | "ssh_ca"

export interface CbomCredential {
  id: number
  name: string
  credential_type: CbomCredentialType
  config: Record<string, unknown>
  secrets_set: string[]
  managed_sources?: number
  row_version: number
}

export async function listCbomCredentials(teamId: number): Promise<{ credentials: CbomCredential[] }> {
  const response = await api.get(`${base(teamId)}/credentials`)
  return response.data
}

export async function createCbomCredential(
  teamId: number,
  body: { name: string; credential_type: CbomCredentialType; config: Record<string, unknown>; secrets?: Record<string, string> },
): Promise<{ credential: CbomCredential }> {
  const response = await api.post(`${base(teamId)}/credentials`, body)
  return response.data
}

export async function updateCbomCredential(
  teamId: number,
  credentialId: number,
  body: { name?: string; config?: Record<string, unknown>; secrets?: Record<string, string>; expected_version?: number },
): Promise<{ credential: CbomCredential } & CbomWriteEvaluation> {
  const response = await api.patch(`${base(teamId)}/credentials/${credentialId}`, body)
  return response.data
}

export async function deleteCbomCredential(teamId: number, credentialId: number): Promise<{ deleted: number }> {
  const response = await api.delete(`${base(teamId)}/credentials/${credentialId}`)
  return response.data
}
