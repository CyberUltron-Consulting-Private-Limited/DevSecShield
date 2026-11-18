// The deployment's fleet flags (GET /fleet/status), as one cached query shared by the page's tab bar, the Fleet tab
// and the Servers tab. Its own module so a tab that only needs the flags does not import the Fleet UI.
import { useQuery } from "@tanstack/react-query";

import { getCbomFleetStatus } from "@/utils/api/cbom_fleet";
import { queryRetry } from "@/utils/query_client";

import { isNotFound } from "./fleetLogic";
import { cbomFleetKeys } from "./keys";

/** The deployment's fleet flags. A server without the fleet routes answers 404: that is not retried (the tab stays
 * hidden); anything else keeps the app's policy (a 429 waits for Retry-After, other errors retry 3 times). */
export function useFleetStatus(teamId: number) {
  return useQuery({
    queryKey: cbomFleetKeys.status(teamId),
    queryFn: () => getCbomFleetStatus(teamId),
    staleTime: 60_000,
    retry: (failureCount, error) => !isNotFound(error) && queryRetry(failureCount, error),
    enabled: Number.isFinite(teamId) && teamId > 0,
  });
}
