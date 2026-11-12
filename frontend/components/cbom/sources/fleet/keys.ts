// Query keys of the Fleet tab. They sit under the CBOM Sources prefix, so the page's Refresh (which invalidates
// ["cbom-sources", teamId]) refreshes the Fleet tab too. A fleet write refreshes only what it changes (refreshFleet),
// not every fleet query: pausing a source or adding a credential does not refetch the policies or the targets.
import type { QueryClient } from "@tanstack/react-query";

import { cbomSourcesKeys } from "../keys";

export const cbomFleetKeys = {
  all: (teamId: number) => [...cbomSourcesKeys.all(teamId), "fleet"] as const,
  status: (teamId: number) => [...cbomSourcesKeys.all(teamId), "fleet", "status"] as const,
  targets: (teamId: number, filters: string) => [...cbomSourcesKeys.all(teamId), "fleet", "targets", filters] as const,
  targetPages: (teamId: number) => [...cbomSourcesKeys.all(teamId), "fleet", "targets"] as const,
  target: (teamId: number, targetId: number) => [...cbomSourcesKeys.all(teamId), "fleet", "target", targetId] as const,
  targetDetails: (teamId: number) => [...cbomSourcesKeys.all(teamId), "fleet", "target"] as const,
  inventorySources: (teamId: number) => [...cbomSourcesKeys.all(teamId), "fleet", "inventory-sources"] as const,
  policies: (teamId: number) => [...cbomSourcesKeys.all(teamId), "fleet", "policies"] as const,
  credentials: (teamId: number) => [...cbomSourcesKeys.all(teamId), "fleet", "credentials"] as const,
};

/** What a write changed:
 * - "targets": the targets and their decisions (pages and the open detail);
 * - "sources": the inventory sources (counts, sync status);
 * - "policies": the policies and their matched / won counts;
 * - "credentials": the credentials. */
export type FleetPart = "targets" | "sources" | "policies" | "credentials";

export function refreshFleet(queryClient: QueryClient, teamId: number, parts: readonly FleetPart[]): Promise<void[]> {
  const keys: Record<FleetPart, readonly (readonly unknown[])[]> = {
    targets: [cbomFleetKeys.targetPages(teamId), cbomFleetKeys.targetDetails(teamId)],
    sources: [cbomFleetKeys.inventorySources(teamId)],
    policies: [cbomFleetKeys.policies(teamId)],
    credentials: [cbomFleetKeys.credentials(teamId)],
  };
  return Promise.all(parts.flatMap((p) => keys[p]).map((queryKey) => queryClient.invalidateQueries({ queryKey })));
}
