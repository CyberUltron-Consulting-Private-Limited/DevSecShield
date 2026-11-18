/**
 * The credit balance in the team sidebar (#13, #28). TeamSwitcher (app/[team_id]/layout.tsx) shows each team's balance
 * from GET /teams, cached under ["teams"]. A scan start or re-run (charged), a cancel (refunded), a saved DAST
 * profile run and a scan chat message (charged) call refreshCredits when they settle. A failed scan's refund is the
 * query-cache watcher (creditBalanceWatcher): a status effect that also refreshes sends GET /teams a second time.
 * utils/creditRefresh.test.ts lists the call sites.
 */
import type { Query, QueryClient } from "@tanstack/react-query";

import { refreshCreditBalance } from "./creditBalance";

/** The query the balance in the team sidebar reads (GET /teams). */
export const CREDITS_QUERY_KEY = ["teams"] as const;

/** Read the balance again. Call it when the action settles, not only when it succeeds: a refused start still shows the
 * server's balance, which another tab may have changed. Same refetch as refreshCreditBalance: a second call while
 * that GET /teams is in flight joins it. */
export function refreshCredits(queryClient: QueryClient): Promise<void> {
  return refreshCreditBalance(queryClient);
}

/** For a caller that also refreshes every other query: leave the balance to refreshCredits, or GET /teams is sent twice
 * (a second invalidation cancels the first fetch and starts another). */
export function isCreditsQuery(query: Pick<Query, "queryKey">): boolean {
  return query.queryKey[0] === CREDITS_QUERY_KEY[0];
}
