/**
 * CB-38: where a row of the CBOM Scans table opens.
 *
 * A Sources run opens its results page at every status (a queued or running run shows live progress there, a
 * partial, failed or cancelled run shows what was collected). A code scan opens its results once it succeeded and
 * its scan page (progress, upload, chat) before that.
 *
 * Both open the same results template at `/{team}/cbom/<id>/results`. A code scan is the plain path. A Sources run
 * is that same path with `?run=1`: scan ids and run ids are separate sequences, so `/cbom/1/results` stays code
 * scan 1 when both exist (team 2 on staging). `/cbom/run-<id>/results` and `/cbom/runs/<id>/results` only redirect
 * here.
 */

export interface ResultsHrefRow {
  kind: "scan" | "run";
  id: number;
  scan_status?: string | null;
}

export type CbomResultsId = { kind: "scan"; id: number } | { kind: "run"; id: number };

const POSITIVE_INT = /^[1-9]\d*$/;
const RUN_ID = /^run-([1-9]\d*)$/;

/** The `[scan_id]` route segment as a number (`12`) or a legacy Sources-run prefix (`run-12`); anything else is null. */
export function parseCbomResultsId(raw: unknown): CbomResultsId | null {
  const s = typeof raw === "string" ? raw : "";
  if (POSITIVE_INT.test(s)) return { kind: "scan", id: Number(s) };
  const run = RUN_ID.exec(s);
  return run ? { kind: "run", id: Number(run[1]) } : null;
}

/** True when the results query asks for the Sources run (`?run=1`), not the code scan that may share the id. */
export function asksForRun(query: string): boolean {
  return new URLSearchParams(query.replace(/^\?/, "")).get("run") === "1";
}

/** The one results template for Sources run `runId`. `query` is kept (`view=all`); `run=1` is set. */
export function runResultsHref(teamId: string | number, runId: number, query = ""): string {
  const params = new URLSearchParams(query.replace(/^\?/, ""));
  params.set("run", "1");
  return `/${teamId}/cbom/${runId}/results?${params.toString()}`;
}

export function resultsHref(teamId: string | number, row: ResultsHrefRow): string {
  if (row.kind === "run") return runResultsHref(teamId, row.id);
  return (row.scan_status ?? "").toLowerCase() === "success"
    ? `/${teamId}/cbom/${row.id}/results`
    : `/${teamId}/cbom/${row.id}`;
}

/** Where `/{team}/cbom/runs/{run}/results` and `/{team}/cbom/run-{run}/results` now live. Null when an id is not a
 * positive integer (the ids the old page accepted, `012` included). */
export function legacyRunResultsTarget(teamId: unknown, runId: unknown, query: string): string | null {
  const num = (raw: unknown) => (typeof raw === "string" && /^\d+$/.test(raw) && Number(raw) > 0 ? Number(raw) : null);
  const team = num(teamId);
  const run = num(runId);
  if (!team || !run) return null;
  return runResultsHref(team, run, query);
}
