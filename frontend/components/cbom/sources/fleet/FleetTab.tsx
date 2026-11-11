"use client";

// Fleet: onboard servers, databases and clusters from an inventory (AWS discovery, CSV/JSON import, API) and let tag
// policies decide how each one is collected. Every part is behind a server flag; the tab and each section show only
// what this deployment has turned on.

import { useQuery } from "@tanstack/react-query";

import { getCbomFleetStatus } from "@/utils/api/cbom_fleet";

import { EmptyState, ErrorBlock, LoadingBlock } from "../shared";
import { visibleSections } from "./fleetLogic";
import { cbomFleetKeys } from "./keys";
import { FLEET_SECTIONS } from "./sections";

/** The deployment's fleet flags. Not retried: a server without the fleet routes answers 404, and the tab stays hidden. */
export function useFleetStatus(teamId: number) {
  return useQuery({
    queryKey: cbomFleetKeys.status(teamId),
    queryFn: () => getCbomFleetStatus(teamId),
    staleTime: 60_000,
    retry: false,
    enabled: Number.isFinite(teamId) && teamId > 0,
  });
}

export default function FleetTab({ teamId }: { teamId: number; onNavigate?: (tab: string) => void }) {
  const status = useFleetStatus(teamId);
  if (status.isLoading) return <LoadingBlock />;
  if (status.isError || !status.data) return <ErrorBlock error={status.error} onRetry={() => status.refetch()} />;
  const sections = visibleSections(FLEET_SECTIONS, status.data);
  if (sections.length === 0) {
    return (
      <EmptyState
        title="Nothing to show yet"
        body="Fleet onboarding is turned on for this deployment, but none of its sections is available in this version."
      />
    );
  }
  return (
    <div className="space-y-6">
      {sections.map(({ id, Component }) => (
        <Component key={id} teamId={teamId} status={status.data} />
      ))}
    </div>
  );
}
