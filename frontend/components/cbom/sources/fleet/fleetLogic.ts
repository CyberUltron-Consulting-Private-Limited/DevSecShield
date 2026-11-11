// Pure helpers of the Fleet tab (no React), so they can be tested with tsx.
import type { CbomFleetStatus } from "@/utils/api/cbom_fleet";

export const ALL_OFF: CbomFleetStatus = { inventory: false, policies: false, transports: false, ssh_ca: false };

/** The Fleet tab shows when at least one fleet feature is on. While the status loads, or when it failed (a server
 * without the fleet routes answers 404), the tab stays hidden. */
export function fleetTabVisible(status: CbomFleetStatus | undefined): boolean {
  if (!status) return false;
  return Object.values({ ...ALL_OFF, ...status }).some(Boolean);
}

/** The sections whose flag is on, in registry order. */
export function visibleSections<T extends { flag: keyof CbomFleetStatus }>(sections: readonly T[], status: CbomFleetStatus | undefined): T[] {
  if (!status) return [];
  return sections.filter((s) => status[s.flag] === true);
}

/** The tab to show for ``?tab=``: the requested one when it exists and is shown, otherwise the first tab. */
export function pickTab<T extends string>(requested: string | null, tabs: readonly T[], shown: (tab: T) => boolean): T {
  const hit = tabs.find((t) => t === requested);
  return hit !== undefined && shown(hit) ? hit : tabs[0];
}
