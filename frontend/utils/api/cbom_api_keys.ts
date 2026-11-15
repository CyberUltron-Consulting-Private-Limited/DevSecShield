// CBOM API keys of a team (issue #226): list, create (the secret is in the create response only), revoke.
// Keys work only on the CBOM Sources, runs and export routes (backend/utilities/cbom_sources/api_keys.py);
// guide: docs/cbom/api-keys.md.

import api from "@/utils/interceptors"

export type CbomApiKeyScope = "cbom.read" | "cbom.sources:write" | "cbom.runs:write"
export type CbomApiKeyStatus = "active" | "expired" | "revoked"

export interface CbomApiKey {
  id: number
  name: string
  scopes: CbomApiKeyScope[]
  /** the secret's last four characters, to tell keys apart (never the secret, never its hash) */
  hint: string
  status: CbomApiKeyStatus
  created_at: string | null
  created_by: string | null
  expires_at: string | null
  revoked_at: string | null
  last_used_at: string | null
}

export interface CbomApiKeyList {
  api_keys: CbomApiKey[]
  scopes: { name: CbomApiKeyScope; description: string }[]
  can_manage: boolean
  prefix: string
  max_expiry_days: number
  server_time: string
}

export interface CbomApiKeyCreate {
  name: string
  scopes: CbomApiKeyScope[]
  expires_in_days: number | null
}

export const cbomApiKeyKeys = {
  list: (teamId: number) => ["cbom-api-keys", teamId] as const,
}

export async function listCbomApiKeys(teamId: number): Promise<CbomApiKeyList> {
  return (await api.get(`/${teamId}/cbom/api-keys`)).data
}

export async function createCbomApiKey(teamId: number, body: CbomApiKeyCreate): Promise<{ api_key: CbomApiKey; secret: string }> {
  return (await api.post(`/${teamId}/cbom/api-keys`, body)).data
}

export async function revokeCbomApiKey(teamId: number, keyId: number): Promise<CbomApiKey> {
  return (await api.post(`/${teamId}/cbom/api-keys/${keyId}/revoke`)).data.api_key
}

// ----------------------------------------------------------------------------- pure helpers (tested)
export const EXPIRY_CHOICES: { value: string; label: string; days: number | null }[] = [
  { value: "30", label: "30 days", days: 30 },
  { value: "90", label: "90 days", days: 90 },
  { value: "365", label: "1 year", days: 365 },
  { value: "never", label: "No expiry", days: null },
]

const NAME_RE = /^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$/

/** Why the create form cannot be sent yet, or null (the server checks the same rules). */
export function createFormProblem(name: string, scopes: string[]): string | null {
  const trimmed = name.trim()
  if (!trimmed) return "Enter a name"
  if (!NAME_RE.test(trimmed)) return "Use 1-64 letters, digits, spaces, dots, dashes or underscores, starting with a letter or digit"
  if (scopes.length === 0) return "Choose at least one scope"
  return null
}

export function statusLabel(key: Pick<CbomApiKey, "status" | "expires_at">): string {
  if (key.status === "revoked") return "Revoked"
  if (key.status === "expired") return "Expired"
  return key.expires_at ? "Active" : "Active, no expiry"
}

/** A key shown in the list: its prefix and last four characters, never more of the secret. */
export function maskedKey(prefix: string, hint: string): string {
  return `${prefix}…${hint}`
}
