/**
 * CB-38: one status vocabulary for code scans and CBOM Sources runs.
 *
 * The mapping is the shared contract `contracts/cbom/status_buckets.json` (read by a backend pytest and by
 * statusBuckets.test.ts, so the browser and the server cannot drift). It is copied here rather than imported because
 * the frontend image is built from `frontend/` alone; the test fails if the two ever differ.
 */

export type RunStatus = "queued" | "running" | "done" | "partial" | "failed" | "cancelled";
export type UnifiedStatus =
  | "not_started" | "pending" | "started" | "retry" | "success" | "partial" | "failure" | "cancelled";
export type AssignmentStatus = "open" | "in_progress" | "done" | "accepted_risk";
export type FindingStatus = "not_started" | "in_progress" | "fixed" | "ignored";

export const STATUS_BUCKETS = {
  run_to_unified: {
    queued: "pending",
    running: "started",
    done: "success",
    partial: "partial",
    failed: "failure",
    cancelled: "cancelled",
  },
  assignment_to_finding: {
    open: "not_started",
    in_progress: "in_progress",
    done: "fixed",
    accepted_risk: "ignored",
  },
} as const satisfies {
  run_to_unified: Record<RunStatus, UnifiedStatus>;
  assignment_to_finding: Record<AssignmentStatus, FindingStatus>;
};

const UNIFIED = new Set<string>(["not_started", "pending", "started", "retry", "success", "partial", "failure", "cancelled"]);

/** A run status as the table shows it; an unknown value is returned unchanged (never guessed). */
export function runToUnified(status: string | null | undefined): string {
  if (!status) return "not_started";
  return (STATUS_BUCKETS.run_to_unified as Record<string, string>)[status] ?? status;
}

export function isUnifiedStatus(status: string | null | undefined): status is UnifiedStatus {
  return !!status && UNIFIED.has(status);
}

/** Still collecting: the row shows live progress (jobs done / total). */
export function isActiveStatus(status: string | null | undefined): boolean {
  return status === "pending" || status === "started" || status === "retry";
}
