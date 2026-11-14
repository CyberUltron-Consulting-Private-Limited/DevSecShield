/**
 * The credit balance in the app sidebar (#13, #28). The team switcher (app/[team_id]/layout.tsx) shows each team's
 * balance from GET /teams, cached under ["teams"]. Two kinds of change keep it current:
 * - a user action that charges or refunds (a scan start or cancel, a chat message, a CBOM sources run, deleting or
 *   re-pointing a source, ...) calls refreshCreditBalance when its mutation settles (utils/creditBalance.test.ts lists
 *   every such API helper and checks every use);
 * - credits the server moves on its own (a failed scan's refund, a CBOM sources run's refunded jobs) are seen in the
 *   responses that report them: makeQueryClient (utils/query_client.ts) runs creditBalanceWatcher on every response.
 */
import type { Query, QueryClient } from "@tanstack/react-query";

/** The query the sidebar's balance reads (GET /teams). */
export const CREDIT_BALANCE_QUERY_KEY = ["teams"] as const;

/** Refetch the balance now. Call it from onSettled, not onSuccess: a refused start or cancel still shows the
 * current balance (another tab may have spent credits), and the refetch is one small GET. */
export function refreshCreditBalance(queryClient: QueryClient): Promise<void> {
  return queryClient.invalidateQueries({ queryKey: CREDIT_BALANCE_QUERY_KEY });
}

/** For a caller that also invalidates every other query: leave the balance to refreshCreditBalance, otherwise
 * GET /teams is sent twice (the second invalidation cancels the first fetch and starts another). */
export function isCreditBalanceQuery(query: Pick<Query, "queryKey">): boolean {
  return query.queryKey[0] === CREDIT_BALANCE_QUERY_KEY[0];
}

/** The records in a response whose state says the server moved credits: a scan's status ("failure" was refunded) and a
 * CBOM sources run's refunded total. Keyed per record; "" means nothing was refunded. A response is a record, a list of
 * them, or an object holding one ({ run }) or a list ({ runs }, { scans }); nested results are not searched. */
export function refundMarks(data: unknown): Map<string, string> {
  const marks = new Map<string, string>();
  const visit = (value: unknown, top: boolean) => {
    if (Array.isArray(value)) {
      for (const item of value) visit(item, false);
      return;
    }
    if (!value || typeof value !== "object") return;
    const record = value as Record<string, unknown>;
    if (typeof record.scan_status === "string") {
      marks.set(`scan:${String(record.id ?? "")}`, record.scan_status === "failure" ? "failure" : "");
    }
    const credits = record.credits as { refunded?: unknown } | null | undefined;
    if (typeof record.status === "string" && typeof credits?.refunded === "number") {
      marks.set(`run:${String(record.id ?? "")}`, credits.refunded > 0 ? String(credits.refunded) : "");
    }
    if (top) for (const inner of Object.values(record)) if (inner && typeof inner === "object") visit(inner, false);
  };
  visit(data, true);
  return marks;
}

/** The query cache's onSuccess (utils/query_client.ts): refresh the balance when a response shows a refund this client
 * has not seen yet: a scan that is now "failure" (backend utilities/celery/celery_connection.py refunds it in the
 * status poll that sees it fail, or in the scan list's background update), or a CBOM sources run whose refunded total
 * changed (utilities/cbom_sources/jobs.py refund_job, as its jobs fail, expire or are cancelled). A scan already failed
 * when first seen also counts: that first read may be the poll that refunded it. One GET /teams per change.
 * The marks of a query are merged, not replaced: a record that leaves a response (another page or filter of a list) and
 * comes back unchanged is not a new refund, while a record that changes (a re-run scan that fails again) still is.
 * No second GET /teams while one is on its way: that one is nearly always the onSettled refresh of the action that moved
 * the credits, sent after the server answered it, whose refetched list then shows the refund (a CBOM "Cancel run" sent
 * GET /teams twice). The marks are recorded either way, so the same refund does not refresh later. */
export function creditBalanceWatcher(getClient: () => QueryClient) {
  const seen = new WeakMap<Pick<Query, "queryKey">, Map<string, string>>();
  return (data: unknown, query: Pick<Query, "queryKey">): void => {
    if (isCreditBalanceQuery(query)) return;
    const marks = refundMarks(data);
    const before = seen.get(query) ?? new Map<string, string>();
    const changed = [...marks].some(([key, refunded]) => refunded !== "" && before.get(key) !== refunded);
    for (const [key, refunded] of marks) before.set(key, refunded);
    seen.set(query, before);
    if (!changed) return;
    const client = getClient();
    if (client.isFetching({ queryKey: CREDIT_BALANCE_QUERY_KEY }) === 0) void refreshCreditBalance(client);
  };
}
