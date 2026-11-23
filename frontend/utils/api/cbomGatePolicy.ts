// CBOM CI/CD gate policy (SOW S1): the team's policy and per-integration overrides that POST /cicd/cbom/scan applies,
// in the same JSON format as the offline `aibom cbom --policy` file (backend/utilities/cicd/gate_policy.py).

import api from "@/utils/interceptors"

export type GateMode = "off" | "warn" | "fail"
export type GateRule = "finding_code" | "banned_algorithm" | "min_key_size" | "deprecated_algorithm" | "quantum_vulnerable"
export type KeyFamily = "rsa" | "dsa" | "dh" | "ec" | "symmetric"
export const KEY_FAMILIES: KeyFamily[] = ["rsa", "dsa", "dh", "ec", "symmetric"]

export interface GateException {
  id?: string
  rule: GateRule | null
  algorithm: string | null
  location: string | null
  reason: string
  expires: string
}

export interface GatePolicy {
  version: 1
  name: string
  block_codes: string[]
  banned_algorithms: string[]
  min_key_bits: Record<KeyFamily, number>
  quantum_vulnerable: GateMode
  deprecated: GateMode
  exceptions: GateException[]
}

export interface StoredGatePolicy {
  policy: GatePolicy
  valid: boolean
  row_version: number
  updated_at: string | null
  digest: string
}

export interface GatePolicyView {
  team: StoredGatePolicy | null
  default: GatePolicy
  default_digest: string
  presets: Record<string, GatePolicy>
  rules: GateRule[]
  key_limits: Record<KeyFamily, [number, number]>
  max_exception_days: number
  file_kind: string
  integrations: { id: number; title: string; override: StoredGatePolicy | null }[]
  is_admin: boolean
}

export const gatePolicyKey = (teamId: number) => ["cbom-gate-policy", teamId] as const

export async function getGatePolicy(teamId: number): Promise<GatePolicyView> {
  return (await api.get(`/${teamId}/cbom/gate-policy`)).data
}

export async function saveGatePolicy(teamId: number, policy: GatePolicy, expectedVersion: number | null,
                                     integrationId?: number): Promise<StoredGatePolicy & { saved: boolean }> {
  const url = integrationId ? `/${teamId}/cbom/gate-policy/integrations/${integrationId}` : `/${teamId}/cbom/gate-policy`
  return (await api.put(url, { policy, expected_version: expectedVersion })).data
}

export async function resetGatePolicy(teamId: number, integrationId?: number): Promise<{ deleted: boolean }> {
  const url = integrationId ? `/${teamId}/cbom/gate-policy/integrations/${integrationId}` : `/${teamId}/cbom/gate-policy`
  return (await api.delete(url)).data
}

export const RULE_LABEL: Record<GateRule, string> = {
  finding_code: "Blocked finding code",
  banned_algorithm: "Banned algorithm",
  min_key_size: "Key below the minimum size",
  deprecated_algorithm: "Deprecated (SP 800-131A)",
  quantum_vulnerable: "Quantum-vulnerable",
}

/** The policy file for the offline gate (`aibom cbom --policy <file>`), same format as the server stores. */
export function policyFileText(policy: GatePolicy, fileKind: string): string {
  return JSON.stringify({ kind: fileKind, ...policy }, null, 2) + "\n"
}

/** "MD5, 3DES\nRC4" -> ["MD5", "3DES", "RC4"] (trimmed, blanks and repeats dropped, order kept). */
export function splitList(text: string): string[] {
  const out: string[] = []
  for (const part of text.split(/[,\n]/)) {
    const v = part.trim()
    if (v && !out.some((x) => x.toUpperCase() === v.toUpperCase())) out.push(v)
  }
  return out
}

/** The exception as the API takes it: empty strings become null (an empty rule means "every rule"). */
export function cleanException(e: GateException): GateException {
  const blank = (v: string | null | undefined) => (v && v.trim() ? v.trim() : null)
  return { ...(e.id ? { id: e.id } : {}), rule: e.rule || null, algorithm: blank(e.algorithm), location: blank(e.location),
           reason: (e.reason ?? "").trim(), expires: (e.expires ?? "").trim() }
}
