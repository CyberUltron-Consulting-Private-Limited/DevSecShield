/**
 * CB-38: one error toast per outage of the CBOM Scans list.
 *
 * A failed refetch keeps the last good rows on screen (the page shows a "couldn't refresh" note instead of the
 * error screen); the toast is shown for the first failure only, and again only after a success ended the outage.
 */
export interface OutageGate {
  /** a fetch failed: true when this is the first failure since the last success (toast it) */
  failed(): boolean;
  /** a fetch succeeded: the next failure starts a new outage */
  succeeded(): void;
}

export function createOutageGate(): OutageGate {
  let down = false;
  return {
    failed() {
      if (down) return false;
      down = true;
      return true;
    },
    succeeded() {
      down = false;
    },
  };
}

/** Which body the page shows: the error screen only when there is nothing loaded to show. */
export function listView(q: { isLoading: boolean; isError: boolean; hasData: boolean }): "loading" | "error" | "rows" {
  if (q.isLoading && !q.hasData) return "loading";
  if (q.isError && !q.hasData) return "error";
  return "rows";
}
