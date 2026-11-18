/**
 * The credit balance in the team sidebar (#13, #28). TeamSwitcher (app/[team_id]/layout.tsx) shows each team's balance
 * from GET /teams, cached under ["teams"]. Every action that moves credits calls refreshCredits when it settles: a scan
 * start or re-run (charged), a cancel (refunded), a failed scan (refunded by the status check that saw it fail), a
 * saved DAST profile run and a scan chat message (charged). utils/creditRefresh.test.ts lists them.
 */
import type { Query, QueryClient } from "@tanstack/react-query";

/** The query the balance in the team sidebar reads (GET /teams). */
export const CREDITS_QUERY_KEY = ["teams"] as const;

/** Read the balance again. Call it when the action settles, not only when it succeeds: a refused start still shows the
 * server's balance, which another tab may have changed. */
export function refreshCredits(queryClient: QueryClient): Promise<void> {
  return queryClient.invalidateQueries({ queryKey: CREDITS_QUERY_KEY });
}

/** For a caller that also refreshes every other query: leave the balance to refreshCredits, or GET /teams is sent twice
 * (a second invalidation cancels the first fetch and starts another). */
export function isCreditsQuery(query: Pick<Query, "queryKey">): boolean {
  return query.queryKey[0] === CREDITS_QUERY_KEY[0];
}
