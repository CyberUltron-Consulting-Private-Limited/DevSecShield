// Pure logic of the Sources run Ticketing tab (CB-38 PR-4): which rows can be ticketed, what the tab shows for the
// team's Jira state, the project-key rule (the API's rule, so the form refuses what the API would refuse), batching
// and the per-asset outcome of a request. No React, no network: unit-tested in runTicketing.test.ts.

import type {
  CbomRunTicketAsset,
  CbomRunTicketsResult,
  CbomSourcesTicketing,
} from "@/utils/backend_api";

/** The API's per-request cap (run_tickets.MAX_ASSETS): larger selections are sent in batches. */
export const MAX_TICKETS_PER_REQUEST = 50;

/** Jira project key (SEC, PAY_OPS) or numeric project id, as backend run_tickets._PROJECT (after upper-casing). */
const PROJECT_RE = /^(?:[A-Z][A-Z0-9_]{1,31}|[1-9][0-9]{0,17})$/;

export type TicketingState = "loading" | "not_connected" | "no_project" | "ready";

export function ticketingState(t: CbomSourcesTicketing | undefined | null): TicketingState {
  if (!t) return "loading";
  if (!t.connected) return "not_connected";
  if (!t.jira_project_key) return "no_project";
  return "ready";
}

export function normalizeProjectKey(raw: string): { value: string | null; error: string | null } {
  const text = raw.trim().toUpperCase();
  if (!text) return { value: null, error: null };
  if (!PROJECT_RE.test(text)) {
    return { value: null, error: "Use the Jira project key (such as SEC) or the numeric project id." };
  }
  return { value: text, error: null };
}

/** A finding: an impact, or quantum-vulnerable crypto to migrate. Clean inventory and "not collected" coverage notes
 * are listed in the CBOM but never ticketed (the API reports them as failed if sent anyway). */
export function isTicketable(asset: Pick<CbomRunTicketAsset, "type" | "impact" | "quantum_vulnerable">): boolean {
  if (asset.type === "coverage") return false;
  return asset.impact != null || asset.quantum_vulnerable === true;
}

export function hasTicket(asset: Pick<CbomRunTicketAsset, "ticket_key">): boolean {
  return typeof asset.ticket_key === "string" && asset.ticket_key.length > 0;
}

/** Rows the user can select: findings without a ticket yet. */
export function selectableIds(items: CbomRunTicketAsset[]): number[] {
  return items.filter((a) => isTicketable(a) && !hasTicket(a)).map((a) => a.id);
}

export function batches<T>(values: T[], size = MAX_TICKETS_PER_REQUEST): T[][] {
  const out: T[][] = [];
  for (let i = 0; i < values.length; i += size) out.push(values.slice(i, i + size));
  return out;
}

export function mergeResults(results: CbomRunTicketsResult[]): CbomRunTicketsResult {
  return {
    created: results.flatMap((r) => r.created),
    existing: results.flatMap((r) => r.existing),
    failed: results.flatMap((r) => r.failed),
  };
}

export type TicketOutcome = {
  asset_id: number;
  label: string;
  state: "created" | "existing" | "failed";
  ticket_key: string | null;
  ticket_url: string | null;
  error: string | null;
};

/** One line per asset sent, in the order the API answered (created, then existing, then failed). */
export function outcomes(result: CbomRunTicketsResult, items: CbomRunTicketAsset[]): TicketOutcome[] {
  const byId = new Map(items.map((a) => [a.id, a]));
  const label = (id: number) => {
    const a = byId.get(id);
    if (!a) return `Asset #${id}`;
    const what = a.algorithm ?? a.name ?? a.type;
    return `${what} · ${a.location}`;
  };
  return [
    ...result.created.map((r) => ({ asset_id: r.asset_id, label: label(r.asset_id), state: "created" as const,
      ticket_key: r.ticket_key, ticket_url: r.ticket_url, error: null })),
    ...result.existing.map((r) => ({ asset_id: r.asset_id, label: label(r.asset_id), state: "existing" as const,
      ticket_key: r.ticket_key, ticket_url: r.ticket_url, error: null })),
    ...result.failed.map((r) => ({ asset_id: r.asset_id, label: label(r.asset_id), state: "failed" as const,
      ticket_key: null, ticket_url: null, error: r.error })),
  ];
}

export function resultSummary(result: CbomRunTicketsResult): string {
  const parts: string[] = [];
  if (result.created.length) parts.push(`${result.created.length} Jira ${result.created.length === 1 ? "issue" : "issues"} created`);
  if (result.existing.length) parts.push(`${result.existing.length} already had one`);
  if (result.failed.length) parts.push(`${result.failed.length} failed`);
  return parts.join(", ") || "Nothing to create";
}

/** Only http(s) links are rendered (the URL is built by the API from the team's Jira site). */
export function safeTicketUrl(url: string | null | undefined): string | null {
  if (!url) return null;
  try {
    const parsed = new URL(url);
    return parsed.protocol === "https:" || parsed.protocol === "http:" ? parsed.toString() : null;
  } catch {
    return null;
  }
}
