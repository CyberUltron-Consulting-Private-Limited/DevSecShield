/**
 * CB-38: where a row of the CBOM Scans table opens.
 *
 * A Sources run opens its results page at every status (a queued or running run shows live progress there, a
 * partial, failed or cancelled run shows what was collected). A code scan opens its results once it succeeded and
 * its scan page (progress, upload, chat) before that.
 *
 * Runs and code scans share one address shape, `/{team}/cbom/<id>/results`, under the dynamic `[scan_id]` segment:
 * a plain number is a code scan (`/cbom/5/results` is scan #5) and `run-<n>` is a Sources run (`/cbom/run-5/results`
 * is run #5). The older `/cbom/runs/<n>/results` redirects to the `run-<n>` form.
 */

export interface ResultsHrefRow {
  kind: "scan" | "run";
  id: number;
  scan_status?: string | null;
}

export type CbomResultsId = { kind: "scan"; id: number } | { kind: "run"; id: number };

const POSITIVE_INT = /^[1-9]\d*$/;
const RUN_ID = /^run-([1-9]\d*)$/;

/** The `[scan_id]` route segment as a code scan (`12`) or a Sources run (`run-12`); anything else is null (not found). */
export function parseCbomResultsId(raw: unknown): CbomResultsId | null {
  const s = typeof raw === "string" ? raw : "";
  if (POSITIVE_INT.test(s)) return { kind: "scan", id: Number(s) };
  const run = RUN_ID.exec(s);
  return run ? { kind: "run", id: Number(run[1]) } : null;
}

export function runResultsHref(teamId: string | number, runId: number): string {
  return `/${teamId}/cbom/run-${runId}/results`;
}

export function resultsHref(teamId: string | number, row: ResultsHrefRow): string {
  if (row.kind === "run") return runResultsHref(teamId, row.id);
  return (row.scan_status ?? "").toLowerCase() === "success"
    ? `/${teamId}/cbom/${row.id}/results`
    : `/${teamId}/cbom/${row.id}`;
}

/** Where the older `/{team}/cbom/runs/{run}/results?<query>` now lives, query string kept; null when an id is not a
 * positive integer (the ids the old page accepted, `012` included). */
export function legacyRunResultsTarget(teamId: unknown, runId: unknown, query: string): string | null {
  const num = (raw: unknown) => (typeof raw === "string" && /^\d+$/.test(raw) && Number(raw) > 0 ? Number(raw) : null);
  const team = num(teamId);
  const run = num(runId);
  if (!team || !run) return null;
  const qs = query.replace(/^\?/, "");
  return `${runResultsHref(team, run)}${qs ? `?${qs}` : ""}`;
}
