// CBOM fleet (F1.4): the team's SSH certificate authority. It signs the scan node's own public key into a short-lived
// OpenSSH user certificate per job, so Linux servers trust the CA instead of each node key. Private keys and Vault
// tokens are never returned; public keys and fingerprints are public by nature. Routes 404 while CBOM_SSH_CA is off.

import api from "@/utils/interceptors"

export type SshCaState = "next" | "active" | "retired" | "revoked"
export type SshCaProvider = "builtin" | "vault"
export type SshCaKeyWrap = "fernet" | "aws_kms"

export interface SshCa {
  id: number
  name: string
  provider: SshCaProvider
  key_alg: string
  public_key: string
  fingerprint: string
  key_wrap: SshCaKeyWrap | null
  kms_key_ref: string | null
  vault_config: { addr: string; mount: string; role: string; namespace: string | null; ca_pem_set?: boolean } | null
  secrets_set: string[]
  state: SshCaState
  trusted: boolean
  default_ttl_s: number
  rotated_from_id: number | null
  lineage_id: number
  retired_at: string | null
  revoked_at: string | null
  revoked_reason: string | null
  issued_count: number | null
  row_version: number
  created_at: string | null
  last_updated: string | null
}

export interface SshCaList {
  server_time: string
  cas: SshCa[]
  kms_keys: string[]
  default_key_wrap: SshCaKeyWrap
}

export interface SshCaCreate {
  name: string
  provider: SshCaProvider
  key_alg?: "ed25519" | "ecdsa-p256"
  key_wrap?: SshCaKeyWrap
  kms_key_ref?: string
  vault_config?: { addr: string; mount?: string; role: string; namespace?: string; ca_pem?: string }
  secrets?: { token?: string; role_id?: string; secret_id?: string }
  default_ttl_s?: number
}

export interface SshCertIssued {
  id: number
  ca_id: number
  serial: number
  key_id: string
  principals: string[]
  source_addresses: string[]
  valid_after: string | null
  valid_before: string | null
  status: "valid" | "expired" | "revoked"
  cert_public_key_sha256: string
  node_id: number | null
  job_id: number | null
  source_id: number | null
  via: "claim" | "refresh"
  issued_at: string | null
  revoked_at: string | null
  revoked_reason: string | null
}

const base = (teamId: number) => `/${teamId}/cbom/sources/fleet/ssh-ca`

export async function listSshCas(teamId: number): Promise<SshCaList> {
  return (await api.get(base(teamId))).data
}

export async function createSshCa(teamId: number, body: SshCaCreate): Promise<{ ca: SshCa }> {
  return (await api.post(base(teamId), body)).data
}

export async function rotateSshCa(teamId: number, caId: number, expectedVersion?: number): Promise<{ ca: SshCa }> {
  return (await api.post(`${base(teamId)}/${caId}/rotate`, { expected_version: expectedVersion })).data
}

export async function promoteSshCa(teamId: number, caId: number, expectedVersion?: number): Promise<{ ca: SshCa }> {
  return (await api.post(`${base(teamId)}/${caId}/promote`, { expected_version: expectedVersion })).data
}

export async function revokeSshCa(teamId: number, caId: number, reason: string, expectedVersion?: number): Promise<{ ca: SshCa }> {
  return (await api.post(`${base(teamId)}/${caId}/revoke`, { reason, expected_version: expectedVersion })).data
}

export async function listSshCertificates(
  teamId: number,
  params: { ca_id?: number; node_id?: number; job_id?: number; before_id?: number; limit?: number } = {},
): Promise<{ server_time: string; certificates: SshCertIssued[]; next_before_id: number | null }> {
  return (await api.get(`${base(teamId)}/certificates`, { params })).data
}

export async function revokeSshCertificate(teamId: number, certId: number, reason: string): Promise<{ certificate: SshCertIssued }> {
  return (await api.post(`${base(teamId)}/certificates/${certId}/revoke`, { reason })).data
}

/** Text files for the servers: TrustedUserCAKeys, the sshd snippet and the principals file. */
export async function getSshCaText(
  teamId: number,
  what: "trusted-keys" | "templates/sshd-config" | "templates/principals" | "revoked-keys",
  group?: string,
): Promise<string> {
  const path = what === "revoked-keys" ? "revoked" : what
  const params: Record<string, string> = {}
  if (what === "revoked-keys") params.format = "keys"
  if (group) params.group = group
  return (await api.get(`${base(teamId)}/${path}`, { params, responseType: "text", transformResponse: (d) => d })).data
}

/** The OpenSSH key revocation list (binary) for sshd's RevokedKeys. */
export async function getSshCaKrl(teamId: number): Promise<Blob> {
  return (await api.get(`${base(teamId)}/revoked`, { responseType: "blob" })).data
}
