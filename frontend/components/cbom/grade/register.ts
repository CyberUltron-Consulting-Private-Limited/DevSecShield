// Quantum risk register (CB-23 PR-B): one row per asset (estate key) with its current grade. GET /{team}/cbom/register
// (keyset, filters), …/register/summary, …/register/items/{key}, …/register.csv. Pure helpers here (tested with tsx);
// the components are in RiskRegister.tsx.
import { useInfiniteQuery, useQuery } from "@tanstack/react-query";

import api from "@/utils/interceptors";

export interface RegisterRow {
  item_key: string;
  item_kind: string;
  q_grade: string | null;
  q_label: string | null;
  q_reason: string;
  label: string | null;
  asset_type: string | null;
  family: string | null;
  source_ref: string | null;
  source_name: string | null;
  application: string | null;
  exposure: string | null;
  presence: string;
  sources: number;
  last_run_id: number | null;
  last_observed_at: string | null;
  model_version: string;
  updated_at: string | null;
}

export interface RegisterPage {
  items: RegisterRow[];
  total: number;
  next_after: string | null;
}

export interface RegisterSummary {
  total: number;
  q_grades: Record<string, number>;
  q0_reasons: Record<string, number>;
  q0_gaps_open: Record<string, number>;
  families: Record<string, Record<string, number>>;
  closures_by_week: { week: string; total: number; by_cause: Record<string, number> }[];
  pending_regrade: number;
  estate: { stale: boolean; stale_reason?: string | null } | null;
  model_version: string;
  server_time: string;
}

export interface RegisterFilters {
  grade?: string;
  reason?: string;
  family?: string;
  exposure?: string;
  source?: string;
}

export const registerKeys = {
  list: (teamId: number, f: RegisterFilters) => ["cbom-sources", teamId, "register", "list", f] as const,
  summary: (teamId: number) => ["cbom-sources", teamId, "register", "summary"] as const,
};

/** The query parameters of a filter set: empty values dropped (the API treats a missing filter as "any"). */
export function filterParams(f: RegisterFilters): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(f)) if (typeof v === "string" && v.trim()) out[k] = v.trim();
  return out;
}

export async function getRegisterPage(teamId: number, f: RegisterFilters, after: string | null, limit = 100
): Promise<RegisterPage> {
  const params: Record<string, string | number> = { ...filterParams(f), limit };
  if (after) params.after = after;
  const response = await api.get(`/${teamId}/cbom/register`, { params });
  return response.data as RegisterPage;
}

export async function getRegisterSummary(teamId: number): Promise<RegisterSummary> {
  const response = await api.get(`/${teamId}/cbom/register/summary`);
  return response.data as RegisterSummary;
}

/** The filtered register as a CSV file the browser saves (authenticated request, so not a plain link). */
export async function downloadRegisterCsv(teamId: number, f: RegisterFilters, now = new Date()): Promise<void> {
  const response = await api.get(`/${teamId}/cbom/register.csv`, { params: filterParams(f), responseType: "blob" });
  const url = URL.createObjectURL(response.data as Blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = csvFileName(teamId, now);
  a.click();
  URL.revokeObjectURL(url);
}

export function csvFileName(teamId: number, now: Date): string {
  return `quantum-risk-register-team${teamId}-${now.toISOString().slice(0, 10)}.csv`;
}

export function useRegister(teamId: number | undefined, f: RegisterFilters) {
  return useInfiniteQuery({
    queryKey: registerKeys.list(teamId ?? NaN, f),
    queryFn: ({ pageParam }) => getRegisterPage(teamId as number, f, pageParam),
    initialPageParam: null as string | null,
    getNextPageParam: (last) => last.next_after,
    enabled: Number.isFinite(teamId),
    retry: 1,
  });
}

export function useRegisterSummary(teamId: number | undefined) {
  return useQuery({
    queryKey: registerKeys.summary(teamId ?? NaN),
    queryFn: () => getRegisterSummary(teamId as number),
    enabled: Number.isFinite(teamId),
    retry: 1,
  });
}

/** All loaded pages as one list, without a row twice. */
export function registerRows(pages: RegisterPage[] | undefined): RegisterRow[] {
  const seen = new Set<string>();
  const out: RegisterRow[] = [];
  for (const page of pages ?? []) {
    for (const row of page.items ?? []) {
      if (seen.has(row.item_key)) continue;
      seen.add(row.item_key);
      out.push(row);
    }
  }
  return out;
}

/** Closures of the last weeks as "week: n" lines, newest last (the trend line next to the distribution). */
export function closureTrend(s: RegisterSummary | undefined): { week: string; total: number }[] {
  return (s?.closures_by_week ?? []).map((w) => ({ week: w.week, total: Number(w.total) || 0 }));
}
