// Server-side search, filters and keyset paging for the source tables (issue #225). Pure helpers, so they are tested
// without a browser: the request parameters, the filter choices and the "showing N of M" line.

export const SOURCE_PAGE_SIZE = 100;

export type SourceStatusFilter =
  | "" | "enabled" | "disabled" | "never" | "pending" | "passed" | "partial" | "failed" | "error" | "not_available";

export interface SourceFilters {
  q: string
  kind: string // "" = every kind the table shows
  segment: string
  status: SourceStatusFilter
}

export const EMPTY_FILTERS: SourceFilters = { q: "", kind: "", segment: "", status: "" };

export const STATUS_OPTIONS: { value: SourceStatusFilter; label: string }[] = [
  { value: "", label: "Any status" },
  { value: "enabled", label: "Enabled" },
  { value: "disabled", label: "Disabled" },
  { value: "passed", label: "Test passed" },
  { value: "partial", label: "Test partly passed" },
  { value: "failed", label: "Test failed" },
  { value: "error", label: "Test error" },
  { value: "pending", label: "Test running" },
  { value: "never", label: "Never tested" },
];

/** The query parameters of one page. ``kinds`` are the kinds the table shows when no kind is chosen. */
export function sourceListParams(group: string | undefined, kinds: string[], filters: SourceFilters,
                                 after: number | null, pageSize = SOURCE_PAGE_SIZE): Record<string, string | number> {
  const params: Record<string, string | number> = { limit: pageSize };
  if (group) params.group = group;
  const kind = filters.kind || kinds.join(",");
  if (kind) params.kind = kind;
  const q = filters.q.trim().slice(0, 128);
  if (q) params.q = q;
  if (filters.segment) params.segment = filters.segment;
  if (filters.status) params.status = filters.status;
  if (after !== null && after !== undefined) params.after = after;
  return params;
}

/** The segments a table can filter by: every non-empty segment of the team's agentless scan nodes, sorted. */
export function segmentOptions(nodes: { segment?: string | null; mode?: string | null }[]): string[] {
  const seen = new Map<string, string>();
  for (const n of nodes) {
    const seg = (n.segment ?? "").trim();
    if (seg && n.mode !== "agent" && !seen.has(seg.toLowerCase())) seen.set(seg.toLowerCase(), seg);
  }
  return Array.from(seen.values()).sort((a, b) => a.localeCompare(b));
}

export function filtersActive(filters: SourceFilters): boolean {
  return !!(filters.q.trim() || filters.kind || filters.segment || filters.status);
}

export function shownLine(shown: number, total: number, filters: SourceFilters): string {
  const n = (v: number) => v.toLocaleString("en-US");
  const what = filtersActive(filters) ? `matching source${total === 1 ? "" : "s"}` : `source${total === 1 ? "" : "s"}`;
  return shown >= total ? `${n(total)} ${what}` : `Showing ${n(shown)} of ${n(total)} ${what}`;
}
