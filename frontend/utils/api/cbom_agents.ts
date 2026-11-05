// CBOM agent mode (WP8b): agent pool registration tokens for the Helm DaemonSet. Each pod enrolls as its own
// agent-mode scan node, named after its Kubernetes node, and only ever collects its own host (never a credential).
// The token is returned once, at creation. Errors propagate to React Query (the dialogs show them inline).

import api from "@/utils/interceptors"

export type CbomPoolStatus = "active" | "expired" | "revoked" | "full"

export interface CbomNodePool {
  id: number
  team_id: number
  owner_user_id: number
  name: string
  segment: string
  status: CbomPoolStatus
  expires_at: string | null
  max_enrollments: number
  enrollments: number
  revoked_at: string | null
  last_enrolled_at: string | null
  created_at: string | null
  nodes: { id: number; name: string }[]
}

export interface CbomNodePoolCreate {
  name: string
  segment?: string
  expires_in_hours: number
  max_enrollments: number
}

export async function listCbomNodePools(teamId: number): Promise<{ server_time: string; pools: CbomNodePool[] }> {
  const response = await api.get(`/${teamId}/cbom/sources/node-pools`)
  return response.data
}

export async function createCbomNodePool(
  teamId: number,
  body: CbomNodePoolCreate,
): Promise<{ pool: CbomNodePool; registration_token: string }> {
  const response = await api.post(`/${teamId}/cbom/sources/node-pools`, body)
  return response.data
}

export async function revokeCbomNodePool(teamId: number, poolId: number): Promise<{ pool: CbomNodePool }> {
  const response = await api.post(`/${teamId}/cbom/sources/node-pools/${poolId}/revoke`)
  return response.data
}
