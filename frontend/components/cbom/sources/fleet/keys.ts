// Query keys of the Fleet tab. They sit under the CBOM Sources prefix, so the page's Refresh (which invalidates
// ["cbom-sources", teamId]) refreshes the Fleet tab too, and a fleet mutation can refresh just the fleet keys.
import { cbomSourcesKeys } from "../keys";

export const cbomFleetKeys = {
  all: (teamId: number) => [...cbomSourcesKeys.all(teamId), "fleet"] as const,
  status: (teamId: number) => [...cbomSourcesKeys.all(teamId), "fleet", "status"] as const,
  targets: (teamId: number, filters: string) => [...cbomSourcesKeys.all(teamId), "fleet", "targets", filters] as const,
  target: (teamId: number, targetId: number) => [...cbomSourcesKeys.all(teamId), "fleet", "target", targetId] as const,
  inventorySources: (teamId: number) => [...cbomSourcesKeys.all(teamId), "fleet", "inventory-sources"] as const,
  policies: (teamId: number) => [...cbomSourcesKeys.all(teamId), "fleet", "policies"] as const,
  credentials: (teamId: number) => [...cbomSourcesKeys.all(teamId), "fleet", "credentials"] as const,
};
