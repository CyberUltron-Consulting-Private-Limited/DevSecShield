// Query keys of the Fleet tab. They sit under the CBOM Sources prefix, so the page's Refresh (which invalidates
// ["cbom-sources", teamId]) refreshes the Fleet tab too, and a fleet mutation can refresh just the fleet keys.
import { cbomSourcesKeys } from "../keys";

export const cbomFleetKeys = {
  all: (teamId: number) => [...cbomSourcesKeys.all(teamId), "fleet"] as const,
  status: (teamId: number) => [...cbomSourcesKeys.all(teamId), "fleet", "status"] as const,
};
