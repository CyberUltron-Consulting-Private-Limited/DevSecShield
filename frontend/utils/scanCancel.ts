/**
 * Cancelling a code scan (SAST, IaC, SCA + SBOM, CBOM, AI BOM). The server (POST /{team}/{type}/scan/{id}/cancel,
 * backend utilities/scan/cancel_scan.py) cancels a pending or running scan, refunds its charge in full and keeps no
 * results; a finished, failed or already-cancelled scan answers 409 with a reason. A cancelled scan stores
 * `info = { cancelled: true, refunded_credits: N }` and offers Run again (utils/scanRerun.ts).
 */

export type ScanSidebarState = "ready" | "scanning" | "done" | "error" | "cancelled";

/** The sidebar state for a scan status the server returned, or null to leave the current state alone. */
export function sidebarStateFor(status: unknown): ScanSidebarState | null {
  switch (status) {
    case "success":
      return "done";
    case "pending":
    case "started":
    case "retry":
      return "scanning";
    case "failure":
      return "error";
    case "cancelled":
      return "cancelled";
    case "unknown":
      return "ready";
    default:
      return null;
  }
}

/** Cancel is offered while the scan is waiting for a worker or running. */
export function canCancel(status: unknown): boolean {
  return status === "pending" || status === "started" || status === "retry";
}

function record(value: unknown): Record<string, unknown> | null {
  if (typeof value === "string") {
    try {
      value = JSON.parse(value);
    } catch {
      return null;
    }
  }
  return value && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : null;
}

export function formatCredits(amount: number): string {
  const value = Math.round(amount * 100) / 100;
  return `${value} credit${value === 1 ? "" : "s"}`;
}

/** What the scan was charged (GET scan returns `credit_charged`), or null when unknown. */
export function chargedCredits(scan: unknown): number | null {
  const value = record(scan)?.credit_charged;
  return typeof value === "number" && Number.isFinite(value) && value >= 0 ? value : null;
}

/** The confirmation shown before cancelling: it states the refund. */
export function cancelConfirmText(scan: unknown): string {
  const charged = chargedCredits(scan);
  const refund = charged === null ? "the credits it was charged are" : `the ${formatCredits(charged)} it was charged ${charged === 1 ? "is" : "are"}`;
  return `The scan stops and no results are kept. ${refund[0].toUpperCase()}${refund.slice(1)} refunded in full.`;
}

/** "Cancelled — N credits refunded", from the scan's stored info. */
export function cancelledSummary(scan: unknown): string {
  const info = record(record(scan)?.info);
  const refunded = info?.refunded_credits;
  if (typeof refunded === "number" && Number.isFinite(refunded)) {
    return `Cancelled — ${formatCredits(refunded)} refunded`;
  }
  return "Cancelled — the scan's credits were refunded";
}

/** A 409 "already_cancelled" means the scan is cancelled (a second click or another tab): not an error. */
export function isAlreadyCancelled(error: unknown): boolean {
  const response = record(record(error)?.response);
  const data = record(response?.data);
  return response?.status === 409 && data?.code === "already_cancelled";
}

/** Label for a scan status in the scan lists. */
export function scanStatusLabel(status: unknown): string {
  return status === "cancelled" ? "Cancelled" : typeof status === "string" ? status : "";
}
