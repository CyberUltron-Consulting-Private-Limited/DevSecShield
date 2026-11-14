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

/** What the Fleet tab renders for its status query. Data wins: after a failed background refetch TanStack keeps the
 * last data and sets isError, and the sections must stay mounted ("stale"); the error block is only for a first load
 * that failed. */
export function fleetTabState(q: { data?: unknown; isError: boolean; isLoading?: boolean }): "loading" | "error" | "stale" | "ok" {
  if (q.data !== undefined && q.data !== null) return q.isError ? "stale" : "ok";
  return q.isError ? "error" : "loading";
}

/** CB36-BUG-03: whether the Servers tab may ask for the team's SSH CAs. Only when GET /fleet/status reports the SSH CA
 * on: its routes answer 404 while CBOM_SSH_CA is off (by design), and a 404 is a failed request in the browser console.
 * While the status loads, or when it failed (an older server without the fleet routes), the option stays off. */
export function sshCaListEnabled(teamId: number, isLinux: boolean, status: CbomFleetStatus | undefined): boolean {
  return Number.isFinite(teamId) && isLinux && status?.ssh_ca === true;
}

/** A 404 from the API (an older server without the fleet routes): not worth retrying. */
export function isNotFound(error: unknown): boolean {
  return (error as { response?: { status?: number } } | null)?.response?.status === 404;
}
