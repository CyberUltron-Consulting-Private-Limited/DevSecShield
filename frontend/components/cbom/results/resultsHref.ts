/**
 * CB-38: where a row of the CBOM Scans table opens.
 *
 * A Sources run opens its results page at every status (a queued or running run shows live progress there, a
 * partial, failed or cancelled run shows what was collected). A code scan opens its results once it succeeded and
 * its scan page (progress, upload, chat) before that.
 *
 * `/cbom/runs/<id>/results` is a static `runs` segment beside the dynamic `[scan_id]` segment, so `/cbom/5/results`
 * stays scan #5 and `/cbom/runs/5/results` is run #5.
 */

export interface ResultsHrefRow {
  kind: "scan" | "run";
  id: number;
  scan_status?: string | null;
}

export function runResultsHref(teamId: string | number, runId: number): string {
  return `/${teamId}/cbom/runs/${runId}/results`;
}

export function resultsHref(teamId: string | number, row: ResultsHrefRow): string {
  if (row.kind === "run") return runResultsHref(teamId, row.id);
  return (row.scan_status ?? "").toLowerCase() === "success"
    ? `/${teamId}/cbom/${row.id}/results`
    : `/${teamId}/cbom/${row.id}`;
}
