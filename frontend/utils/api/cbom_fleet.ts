// CBOM fleet onboarding (F1): which fleet features this deployment has turned on. Each feature is a server-side flag
// (CBOM_FLEET_INVENTORY, CBOM_FLEET_POLICIES, CBOM_FLEET_TRANSPORTS, CBOM_SSH_CA; all off by default); a route whose
// flag is off answers 404. The Fleet tab and each of its sections show only what is on.

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
