/**
 * Where a CBOM result came from: a code scan, or a CBOM Sources run (M1x, X1 Nov 11).
 *
 * The CBOM landing page counts each Sources source's latest completed collection next to the code scans
 * (backend collections_view) and every top-risk row says where it came from. The Table tab lists code scans and
 * Sources runs in one table (CB-38, components/cbom/results/resultRows.ts).
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
