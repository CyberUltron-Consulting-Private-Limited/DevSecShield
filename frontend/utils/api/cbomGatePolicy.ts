// CBOM CI/CD gate policy (SOW S1): the team's policy and per-integration overrides that POST /cicd/cbom/scan applies,
// in the same JSON format as the offline `aibom cbom --policy` file (backend/utilities/cicd/gate_policy.py).

import api from "@/utils/interceptors"

export type GateMode = "off" | "warn" | "fail"
export type GateRule = "finding_code" | "banned_algorithm" | "min_key_size" | "deprecated_algorithm" | "quantum_vulnerable"
export type KeyFamily = "rsa" | "dsa" | "dh" | "ec" | "symmetric"
export const KEY_FAMILIES: KeyFamily[] = ["rsa", "dsa", "dh", "ec", "symmetric"]

/** One narrow allow-list entry: ONE rule, the finding code (rule finding_code) or the algorithm (other rules) it waives,
 * and a bounded location (a glob with at least one literal path segment; "*" or "**" are refused by the API). */
export interface GateException {
  id?: string
  rule: GateRule
  code?: string | null
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

/** The exception as the API takes it: empty strings become null; the code goes only with the finding_code rule and the
 * algorithm only with the other rules. */
export function cleanException(e: GateException): GateException {
  const blank = (v: string | null | undefined) => (v && v.trim() ? v.trim() : null)
  const byCode = e.rule === "finding_code"
  return { ...(e.id ? { id: e.id } : {}), rule: e.rule, code: byCode ? blank(e.code)?.toUpperCase() ?? null : null,
           algorithm: byCode ? null : blank(e.algorithm), location: blank(e.location),
           reason: (e.reason ?? "").trim(), expires: (e.expires ?? "").trim() }
}

/** False for a glob that matches (nearly) everything ("*", "**", "/*", a wildcard in every segment): the API refuses those. */
export function boundedLocation(glob: string): boolean {
  return glob.replace(/\\/g, "/").split("/").some((seg) => seg !== "" && seg !== "." && seg !== ".." && !/[*?[\]!]/.test(seg))
}

/** The preset a policy's rules equal (its name and exceptions aside), else null ("custom"): the gate page's preset
 * dropdown starts there, so after saving a CNSA 2.0 policy it still reads CNSA 2.0 (staging QA2 m9). */
export function matchingPreset(policy: GatePolicy | null | undefined, presets: Record<string, GatePolicy>): string | null {
  if (!policy) return null
  const rules = (p: GatePolicy) => JSON.stringify({
    block_codes: [...(p.block_codes ?? [])].sort(),
    banned_algorithms: [...(p.banned_algorithms ?? [])].map((a) => a.toUpperCase()).sort(),
    min_key_bits: KEY_FAMILIES.map((f) => Number(p.min_key_bits?.[f])),
    quantum_vulnerable: p.quantum_vulnerable,
    deprecated: p.deprecated,
  })
  const mine = rules(policy)
  for (const [key, preset] of Object.entries(presets)) {
    if (rules(preset) === mine) return key
  }
  return null
}
