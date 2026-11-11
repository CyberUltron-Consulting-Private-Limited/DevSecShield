/**
 * Where a CBOM result came from: a code scan, or a CBOM Sources run (M1x, X1 Nov 11).
 *
 * The CBOM landing page counts each Sources source's latest completed collection next to the code scans
 * (backend collections_view). Every row says where it came from, and the Table tab is empty only when there is
 * neither a code scan nor a completed Sources run.
 */

export type CbomResultOrigin =
  | { kind: "code_scan"; scan_id?: number | null; scan_title?: string | null }
  | { kind: "sources_run"; run_id: number; job_id?: number; source_name?: string | null; observed_at?: string };

export interface CbomSourcesRun {
  run_id: number;
  job_id: number;
  source_name: string;
  source_kind: string;
  finished_at: string;
  asset_count: number;
  endpoints_probed: number;
}

/** "Code scan: <title>" or "Sources run #<id>: <source>" (the backend's collections_view.origin_label). */
export function originLabel(origin: CbomResultOrigin | null | undefined): string {
  if (origin && origin.kind === "sources_run") {
    return `Sources run #${origin.run_id}: ${origin.source_name || "source"}`;
  }
  const title = origin && origin.kind === "code_scan" ? origin.scan_title : null;
  return title ? `Code scan: ${title}` : "Code scan";
}

/** The CBOM Sources page's Review & Run tab, which lists the runs and opens each run's results. */
export function sourcesRunsHref(teamId: string | number): string {
  return `/${teamId}/cbom/sources?tab=review`;
}

/** The Table tab's empty state: no code scan AND no completed Sources run. */
export function hasCbomResults(scans: readonly unknown[] | null | undefined,
                               runs: readonly CbomSourcesRun[] | null | undefined): boolean {
  return (scans?.length ?? 0) > 0 || (runs?.length ?? 0) > 0;
}

/** Runs are listed once per run (a run can collect several sources): sources joined, assets and probes summed. */
export function groupSourcesRuns(runs: readonly CbomSourcesRun[] | null | undefined): Array<{
  run_id: number; sources: string[]; finished_at: string; asset_count: number; endpoints_probed: number;
}> {
  const byRun = new Map<number, { run_id: number; sources: string[]; finished_at: string; asset_count: number;
                                  endpoints_probed: number }>();
  for (const r of runs ?? []) {
    const held = byRun.get(r.run_id);
    if (!held) {
      byRun.set(r.run_id, { run_id: r.run_id, sources: [r.source_name], finished_at: r.finished_at,
                            asset_count: r.asset_count, endpoints_probed: r.endpoints_probed });
      continue;
    }
    if (!held.sources.includes(r.source_name)) held.sources.push(r.source_name);
    held.asset_count += r.asset_count;
    held.endpoints_probed += r.endpoints_probed;
    if (r.finished_at > held.finished_at) held.finished_at = r.finished_at;
  }
  return [...byRun.values()]
    .map((g) => ({ ...g, sources: [...g.sources].sort((a, b) => a.localeCompare(b)) }))
    .sort((a, b) => (b.finished_at.localeCompare(a.finished_at)) || b.run_id - a.run_id);
}
