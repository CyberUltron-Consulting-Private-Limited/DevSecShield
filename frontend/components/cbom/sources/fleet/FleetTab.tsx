"use client";

// Fleet: onboard servers, databases and clusters from an inventory (AWS discovery, CSV/JSON import, API) and let tag
// policies decide how each one is collected. Every part is behind a server flag; the tab and each section show only
// what the server has turned on.

import { EmptyState, ErrorBlock, LoadingBlock } from "../shared";
import { fleetTabState, visibleSections } from "./fleetLogic";
import { FLEET_SECTIONS } from "./sections";
import { useFleetStatus } from "./useFleetStatus";

export { useFleetStatus };

export default function FleetTab({ teamId }: { teamId: number; onNavigate?: (tab: string) => void }) {
  const status = useFleetStatus(teamId);
  const state = fleetTabState(status);
  if (state === "loading") return <LoadingBlock />;
  if (state === "error" || !status.data) return <ErrorBlock error={status.error} onRetry={() => status.refetch()} />;
  // A failed background refetch keeps the last flags (TanStack keeps data): the sections stay mounted, so unsaved
  // input in their forms survives a 429 or a network blip.
  const sections = visibleSections(FLEET_SECTIONS, status.data);
  if (sections.length === 0) {
    // The page hides the tab in this case (fleetTabMode); this only shows if the flags change while the tab is open.
    return (
      <EmptyState
        title="Fleet onboarding isn't available yet"
        body="Ask your administrator if you expected to see it here."
      />
    );
  }
  return (
    <div className="space-y-6">
      {state === "stale" && (
        <p className="text-xs text-amber-700 dark:text-amber-400" role="status">
          Could not refresh the fleet settings; showing the last ones loaded.
        </p>
      )}
      {sections.map(({ id, Component }) => (
        <Component key={id} teamId={teamId} status={status.data} />
      ))}
    </div>
  );
}
