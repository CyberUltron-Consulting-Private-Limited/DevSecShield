/**
 * "Try again" in a scan sidebar's error view (X1, Nov 11). It used to call window.location.reload(): the page reloaded
 * and every typed input was lost (target, repository URL, token, options), and on a failed scan it reloaded into the
 * same error. A refused estimate or start now keeps the form and says why under the estimate button (as X1's DAST fix
 * 37d808f); the error view is left for the remaining requests (export, reinitialise), and its "Try again" returns to
 * the view that matches the scan's status, with the form still filled in, and refetches the scan. A failed scan offers
 * "Run again" instead.
 */
export type RecoveredState = "ready" | "scanning" | "done";

export function stateAfterError(status: unknown): RecoveredState;
export function stateAfterError(status: unknown, cancelledView: true): RecoveredState | "cancelled";
export function stateAfterError(status: unknown, cancelledView = false): RecoveredState | "cancelled" {
  if (status === "success") return "done";
  if (status === "pending" || status === "started") return "scanning";
  if (status === "cancelled" && cancelledView) return "cancelled";
  return "ready";
}
