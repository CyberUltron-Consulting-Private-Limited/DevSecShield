// Orphaned and unmanaged certificates of the team's estate (diagram output 04): GET /{team}/cbom/certificates/hygiene
// (keyset pages, filters flag / source / q / all / stale_runs) and …/hygiene.csv. Pure helpers here (tested with tsx).
import { useInfiniteQuery } from "@tanstack/react-query";

import api from "@/utils/interceptors";

export const HYGIENE_FLAGS = ["unmanaged", "prober_only", "orphaned", "no_owner", "expired_served", "stale"] as const;
export type HygieneFlag = (typeof HYGIENE_FLAGS)[number];

export const FLAG_LABEL: Record<HygieneFlag, string> = {
  unmanaged: "Unmanaged",
  prober_only: "Seen only by a probe",
  orphaned: "Orphaned",
  no_owner: "No owner",
  expired_served: "Expired, still served",
  stale: "Not seen lately",
};

export const FLAG_TONE: Record<HygieneFlag, string> = {
  unmanaged: "border-amber-500/50 text-amber-800 dark:text-amber-300",
  prober_only: "border-zinc-400 text-zinc-700 dark:text-zinc-300",
  orphaned: "border-amber-500/50 text-amber-800 dark:text-amber-300",
  no_owner: "border-zinc-400 text-zinc-700 dark:text-zinc-300",
  expired_served: "border-red-500/60 text-red-700 dark:text-red-400",
  stale: "border-zinc-400 text-zinc-700 dark:text-zinc-300",
};

export interface HygieneObservation {
  source_name: string;
  source_kind: string | null;
  location: string;
  presence: string;
  served: boolean;
  managing: boolean;
  seen_at: string | null;
  not_seen_runs: number;
}

export interface HygieneCert {
  key: string;
  label: string;
  key_kind: string;
  subject: string | null;
  issuer: string | null;
  serial: string | null;
  not_after: string | null;
  days_left: number | null;
  expired: boolean;
  flags: string[];
  not_seen_runs: number;
  owners: string[];
  applications: string[];
  sources: string[];
  observations: HygieneObservation[];
}

export interface HygienePage {
  as_of: string;
  state: "ready" | "pending" | "stale" | string;
  probed: boolean;
  stale_runs: number;
  flags: Record<string, string>;
  counts: { certificates: number; flagged: number; by_flag: Record<string, number> };
  total: number;
  next: string | null;
  items: HygieneCert[];
}

export interface HygieneFilters {
  flag: HygieneFlag | null;
  q: string;
  all: boolean;
}

export function filterParams(f: HygieneFilters): Record<string, string> {
  return {
    ...(f.flag ? { flag: f.flag } : {}),
    ...(f.q.trim() ? { q: f.q.trim().slice(0, 128) } : {}),
    ...(f.all ? { all: "true" } : {}),
  };
}

export function flagLabel(flag: string): string {
  return (FLAG_LABEL as Record<string, string>)[flag] ?? flag;
}

/** "Expired 5 days ago", "Expires in 12 days", "—". */
export function expiryText(c: Pick<HygieneCert, "days_left">): string {
  if (c.days_left == null) return "—";
  if (c.days_left < 0) return `Expired ${-c.days_left} day${c.days_left === -1 ? "" : "s"} ago`;
  if (c.days_left === 0) return "Expires today";
  return `Expires in ${c.days_left} day${c.days_left === 1 ? "" : "s"}`;
}

/** Why the page may be incomplete, in one sentence (null when the store is current). */
export function stateNote(p: Pick<HygienePage, "state" | "probed">): string | null {
  if (p.state === "pending") return "The latest collections are still being written to the estate; this list may lag by a few minutes.";
  if (p.state === "stale") return "The estate store missed a run and is being repaired; this list may be incomplete.";
  if (!p.probed) return "No endpoint is probed yet, so no certificate can be called orphaned: add a network range to see which ones are served.";
  return null;
}

export const hygieneKeys = {
  list: (teamId: number, f: HygieneFilters) => ["cbom-sources", teamId, "cert-hygiene", f.flag ?? "", f.q.trim(), f.all] as const,
};

export async function getHygienePage(teamId: number, f: HygieneFilters, after: string | null, limit = 50): Promise<HygienePage> {
  const response = await api.get(`/${teamId}/cbom/certificates/hygiene`, {
    params: { ...filterParams(f), limit, ...(after ? { after } : {}) },
  });
  return response.data as HygienePage;
}

export function csvFileName(teamId: number, now: Date): string {
  return `certificate-hygiene-team${teamId}-${now.toISOString().slice(0, 10)}.csv`;
}

/** The filtered list as a CSV file the browser saves (authenticated request, so not a plain link). */
export async function downloadHygieneCsv(teamId: number, f: HygieneFilters, now = new Date()): Promise<void> {
  const response = await api.get(`/${teamId}/cbom/certificates/hygiene.csv`, { params: filterParams(f), responseType: "blob" });
  const url = URL.createObjectURL(response.data as Blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = csvFileName(teamId, now);
  a.click();
  URL.revokeObjectURL(url);
}

export function useHygiene(teamId: number, f: HygieneFilters) {
  return useInfiniteQuery({
    queryKey: hygieneKeys.list(teamId, f),
    queryFn: ({ pageParam }) => getHygienePage(teamId, f, pageParam),
    initialPageParam: null as string | null,
    getNextPageParam: (last) => last.next,
    enabled: Number.isFinite(teamId),
    staleTime: 60_000,
  });
}
