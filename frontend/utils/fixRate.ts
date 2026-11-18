/**
 * The SAST dashboard's Fix rate (#36; it was the hard-coded text "0% Fix Rate"): the findings marked Fixed as a whole
 * percent of all stored findings of the team's SAST scans. The list dashboard sends both counts
 * (backend/utilities/dashboard/scan_list.py: fixed_findings, total_findings). A SAST finding is fixed only when
 * someone marks it Fixed on its scan's results page (routers/scans.py); Ignored and In progress findings are not.
 */

const WHAT_COUNTS = "A finding counts as fixed once it is marked Fixed on its scan's results page; Ignored and In progress findings do not count.";

/** "33%" for 2 of 6 findings; a dash when there is no finding (or the server sent no counts). */
export function fixRateText(fixed: number | undefined, total: number | undefined): string {
  if (typeof fixed !== "number" || typeof total !== "number" || !(total > 0)) return "—";
  return `${Math.max(0, Math.min(100, Math.round((fixed / total) * 100)))}%`;
}

/** The tooltip: the two counts, and what counts as fixed. */
export function fixRateTitle(fixed: number | undefined, total: number | undefined): string {
  if (typeof fixed !== "number" || typeof total !== "number" || !(total > 0)) return `No findings yet. ${WHAT_COUNTS}`;
  return `${fixed} of ${total} ${total === 1 ? "finding is" : "findings are"} marked Fixed. ${WHAT_COUNTS}`;
}
