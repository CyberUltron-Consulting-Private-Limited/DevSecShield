// Quantum risk register: the Q0 gap list (CB-23 PR-A). GET /{team}/cbom/register/q0 returns one row per opening of a
// Q0 Unknown item (evidence area or vendor at E0, unread scope, asset of unknown class, missing Mosca input) with its
// lifecycle: opened, last seen, closed, the cause and the grade it closed to. Pure helpers here (tested with tsx);
// the component is Q0Gaps.tsx.
import { useInfiniteQuery } from "@tanstack/react-query";

import api from "@/utils/interceptors";

export type Q0GapStatus = "open" | "closed";
export type Q0GapKind = "evidence" | "scope" | "asset" | "inputs";
export type Q0CloseCause = "evidence" | "removed" | "observation" | "inputs" | "model_change";

export interface Q0Gap {
  id: number;
  item_kind: Q0GapKind | string;
  item_key: string;
  reason: string;
  reason_text: string | null;
  sub_reason: string | null;
  title: string;
  source_id: number | null;
  source_name: string | null;
  detail: Record<string, unknown>;
  status: Q0GapStatus;
  opened_at: string | null;
  as_of: string | null;
  last_seen_at: string | null;
  closed_at: string | null;
  close_cause: Q0CloseCause | string | null;
  closed_grade: string | null;
  /** closed rows: whether the closure was sent to integrations (false for a grade-model change) */
  forwarded: boolean | null;
  age_days: number;
  run_id: number | null;
}

export interface Q0GapPage {
  status: Q0GapStatus;
  items: Q0Gap[];
  next_after: string | null;
  by_reason: Record<string, number>;
  counts: Record<Q0GapStatus, number>;
  server_time: string;
  source: string;
}

export const q0GapKeys = {
  list: (teamId: number, status: Q0GapStatus) => ["cbom-sources", teamId, "register-q0", status] as const,
};

export async function getCbomQ0Gaps(teamId: number, params: {
  status: Q0GapStatus; kind?: Q0GapKind; reason?: string; after?: string | null; limit?: number;
}): Promise<Q0GapPage> {
  const query: Record<string, string | number> = { status: params.status, limit: params.limit ?? 200 };
  if (params.kind) query.kind = params.kind;
  if (params.reason) query.reason = params.reason;
  if (params.after) query.after = params.after;
  const response = await api.get(`/${teamId}/cbom/register/q0`, { params: query });
  return response.data as Q0GapPage;
}

export function useQ0Gaps(teamId: number | undefined, status: Q0GapStatus) {
  return useInfiniteQuery({
    queryKey: q0GapKeys.list(teamId ?? NaN, status),
    queryFn: ({ pageParam }) => getCbomQ0Gaps(teamId as number, { status, after: pageParam }),
    initialPageParam: null as string | null,
    getNextPageParam: (last) => last.next_after,
    enabled: Number.isFinite(teamId),
    retry: 1,
  });
}

/** Why each evidence item is at E0 (CB-18's codes; the same words as the Evidence tab). */
export const SUB_REASON_TEXT: Record<string, string> = {
  no_answer: "Unanswered",
  rated_unknown: "Answered, rated E0 Unknown",
  evidence_expired: "Evidence older than 12 months",
  vendor_not_asked: "Vendor not asked yet",
  vendor_no_response: "Vendor has not answered",
  vendor_link_expired: "Vendor link expired unanswered",
};

export const CAUSE_TEXT: Record<string, string> = {
  evidence: "Evidence answered or renewed",
  removed: "Removed (vendor or source deleted)",
  observation: "Read again in a later collection",
  inputs: "Mosca inputs set",
  model_change: "Grade model changed (not sent to integrations)",
};

export const KIND_TEXT: Record<string, string> = {
  evidence: "Evidence", scope: "Unread scope", asset: "Asset", inputs: "Inputs",
};

export function causeText(cause: string | null | undefined): string {
  if (!cause) return "—";
  return CAUSE_TEXT[cause] ?? cause;
}

export function subReasonText(code: string | null | undefined): string | null {
  if (!code) return null;
  return SUB_REASON_TEXT[code] ?? code;
}

export function ageText(days: number | null | undefined): string {
  const d = Math.max(0, Math.floor(Number(days) || 0));
  if (d === 0) return "today";
  if (d === 1) return "1 day";
  return `${d} days`;
}

export interface Q0GapGroup {
  reason: string;
  items: Q0Gap[];
  /** the server's count for this reason (all pages), or the loaded rows when the server sent none */
  total: number;
}

/** Rows grouped by reason, largest group first (then by code); rows keep the server's order (newest opening first). */
export function groupByReason(items: Q0Gap[], byReason?: Record<string, number>): Q0GapGroup[] {
  const groups = new Map<string, Q0Gap[]>();
  for (const item of items) {
    const list = groups.get(item.reason) ?? [];
    list.push(item);
    groups.set(item.reason, list);
  }
  for (const reason of Object.keys(byReason ?? {})) {
    if (!groups.has(reason) && (byReason?.[reason] ?? 0) > 0) groups.set(reason, []);
  }
  return [...groups.entries()]
    .map(([reason, rows]) => ({ reason, items: rows, total: Math.max(rows.length, Number(byReason?.[reason]) || 0) }))
    .sort((a, b) => b.total - a.total || a.reason.localeCompare(b.reason));
}

/** All loaded pages as one list, without a row twice (a page boundary can move while new gaps open). */
export function flattenPages(pages: Q0GapPage[] | undefined): Q0Gap[] {
  const seen = new Set<number>();
  const out: Q0Gap[] = [];
  for (const page of pages ?? []) {
    for (const item of page.items ?? []) {
      if (seen.has(item.id)) continue;
      seen.add(item.id);
      out.push(item);
    }
  }
  return out;
}
