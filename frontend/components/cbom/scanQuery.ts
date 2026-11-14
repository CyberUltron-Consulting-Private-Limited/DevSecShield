// The CBOM scan query (GET /{team}/cbom/scan/{id}) on the scan page and the results page: a 403 or 404 is an answer,
// not a failure, so it is not retried (four 404s held a spinner for 12 s and stacked toasts) and the page says what
// it means instead of "try again later". Dependency-free so its test runs with plain tsx.

function statusOf(error: unknown): number | undefined {
  return (error as { response?: { status?: number } } | null)?.response?.status;
}

/** The scan does not exist (404) or is not this user's (403): retrying cannot change the answer. */
export function isScanGone(error: unknown): boolean {
  const status = statusOf(error);
  return status === 403 || status === 404;
}

/** What the scan pages say when the scan query failed. */
export function scanErrorText(error: unknown): string {
  const status = statusOf(error);
  if (status === 404) return "CBOM scan not found. It may have been deleted, or the link is wrong.";
  if (status === 403) return "You do not have access to this CBOM scan.";
  return "Error fetching CBOM results. Please try again later.";
}
