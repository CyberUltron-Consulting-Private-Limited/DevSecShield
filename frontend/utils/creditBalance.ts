/**
 * The credit balance in the app sidebar (#13). The team switcher (app/[team_id]/layout.tsx) shows each team's balance
 * from GET /teams, cached under ["teams"]. Starting a scan charges credits and cancelling one refunds them, so every
 * scan start and cancel calls refreshCreditBalance when it settles. Before, only CBOM did, and after a SAST, AI BOM or
 * IaC start the balance stayed stale until a reload.
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
