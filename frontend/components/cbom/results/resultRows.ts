/**
 * CB-38: one CBOM Scans table for code scans AND CBOM Sources runs.
 *
 * `mergeResultRows` turns the list response's code scans (`scans_list_data`) and runs (`runs_list_data`) into one
 * array of rows with the same fields, so every column, the search, the status / risk filters and the sorts work
 * across both kinds. Keys are prefixed (`scan-<id>` / `run-<id>`): a scan and a run may share an id.
 *
 * Deploy skew: a backend without `runs_list_data` still sends `sources_runs` (each source's latest completed
 * collection); those are grouped into one row per run with the fields they carry and "—" elsewhere, so the runs never
 * disappear from the table.
 */
import type { CbomSourcesRun } from "@/components/cbom/resultOrigin";
import type { CBOMConversation, RunListRow } from "@/utils/backend_api";
import { isUnifiedStatus, runToUnified } from "./statusBuckets";

export type ResultKind = "scan" | "run";

export interface RiskCounts {
  total_critical: number;
  total_high: number;
  total_medium: number;
  total_low: number;
  total_quantum_vulnerable?: number | null;
}

interface ResultRowBase {
  kind: ResultKind;
  /** "scan-<id>" | "run-<id>": React keys, selection and test ids */
  key: string;
  id: number;
  title: string;
  created_at: string | null;
  last_updated: string | null;
  /** unified status (scan status as is; run status mapped through status_buckets.json) */
  scan_status: string;
  risk_data: RiskCounts | null;
  average_risk_score: number | null;
  estimated_credits: number | null;
  owner_user_email: string | null;
  owner_user_full_name: string | null;
  repo_url: string | null;
  branch: string | null;
}

export interface ScanResultRow extends ResultRowBase {
  kind: "scan";
  scan: CBOMConversation;
}

export interface RunResultRow extends ResultRowBase {
  kind: "run";
  /** the backend row; null when the row was built from `sources_runs` (older backend) */
  run: RunListRow | null;
  sources: { name: string; kind: string }[];
  jobs_total: number | null;
  jobs_done: number | null;
  asset_count: number | null;
  endpoints_probed: number | null;
  /** true when built from `sources_runs`: fewer fields, the rest shows "—" */
  limited: boolean;
}

export type ResultRow = ScanResultRow | RunResultRow;

export type RiskScoreFilter = "all" | "critical" | "high" | "medium" | "low";
export type TableSortBy =
  | "none" | "created_asc" | "created_desc" | "risk_desc" | "risk_asc" | "credits_desc" | "credits_asc";

export interface ResultFilters {
  search: string;
  status: string;
  risk: RiskScoreFilter;
  sort: TableSortBy;
}

export const NO_FILTERS: ResultFilters = { search: "", status: "all", risk: "all", sort: "none" };

function num(v: unknown): number | null {
  if (v == null || v === "") return null;
  const n = Number(v);
  return Number.isFinite(n) ? n : null;
}

function time(iso: string | null | undefined): number {
  if (!iso) return Number.NEGATIVE_INFINITY;
  const t = Date.parse(iso);
  return Number.isNaN(t) ? Number.NEGATIVE_INFINITY : t;
}

export function scanRow(scan: CBOMConversation): ScanResultRow {
  return {
    kind: "scan",
    key: `scan-${scan.id}`,
    id: scan.id,
    title: scan.title ?? "",
    created_at: scan.created_at ?? null,
    last_updated: scan.last_updated ?? null,
    scan_status: (scan.scan_status ?? "").toLowerCase(),
    risk_data: scan.risk_data ?? null,
    average_risk_score: num(scan.average_risk_score),
    estimated_credits: num(scan.estimated_credits),
    owner_user_email: scan.owner_user_email ?? null,
    owner_user_full_name: scan.owner_user_full_name ?? null,
    repo_url: scan.repo_url ?? null,
    branch: scan.branch ?? null,
    scan,
  };
}

export function runRow(run: RunListRow): RunResultRow {
  // the backend sends the mapped status; map the raw run status only if it did not
  const status = isUnifiedStatus(run.scan_status) ? run.scan_status : runToUnified(run.run_status);
  const sources = (run.sources ?? []).map((s) => ({ name: s.name, kind: s.kind }));
  return {
    kind: "run",
    key: `run-${run.id}`,
    id: run.id,
    title: run.title || runTitle(run.id, sources.map((s) => s.name)),
    created_at: run.created_at ?? null,
    last_updated: run.last_updated ?? run.finished_at ?? null,
    scan_status: status,
    risk_data: run.risk_data ?? null,
    average_risk_score: num(run.average_risk_score),
    estimated_credits: num(run.estimated_credits),
    owner_user_email: run.owner_user_email ?? null,
    owner_user_full_name: run.owner_user_full_name ?? null,
    repo_url: null,
    branch: null,
    run,
    sources,
    jobs_total: num(run.jobs_total),
    jobs_done: num(run.jobs_done),
    asset_count: num(run.asset_count),
    endpoints_probed: num(run.endpoints_probed),
    limited: false,
  };
}

export function runTitle(id: number, sourceNames: readonly string[]): string {
  return sourceNames.length > 0 ? `Sources run #${id} · ${sourceNames.join(", ")}` : `Sources run #${id}`;
}

/**
 * Older backend (no `runs_list_data`): one row per run from `sources_runs`. Those entries are completed collections,
 * so the run has results (status success); risk counts, score, credits and owner are not in them and show "—".
 */
export function runRowsFromSourcesRuns(entries: readonly CbomSourcesRun[] | null | undefined): RunResultRow[] {
  const byRun = new Map<number, { sources: { name: string; kind: string }[]; finished: string; assets: number;
                                  probed: number }>();
  for (const e of entries ?? []) {
    const held = byRun.get(e.run_id);
    if (!held) {
      byRun.set(e.run_id, { sources: [{ name: e.source_name, kind: e.source_kind }], finished: e.finished_at,
                            assets: e.asset_count ?? 0, probed: e.endpoints_probed ?? 0 });
      continue;
    }
    if (!held.sources.some((s) => s.name === e.source_name)) held.sources.push({ name: e.source_name, kind: e.source_kind });
    held.assets += e.asset_count ?? 0;
    held.probed += e.endpoints_probed ?? 0;
    if ((e.finished_at ?? "") > held.finished) held.finished = e.finished_at;
  }
  return [...byRun.entries()].map(([id, g]) => {
    const sources = [...g.sources].sort((a, b) => a.name.localeCompare(b.name));
    return {
      kind: "run" as const,
      key: `run-${id}`,
      id,
      title: runTitle(id, sources.map((s) => s.name)),
      created_at: g.finished || null,
      last_updated: g.finished || null,
      scan_status: "success",
      risk_data: null,
      average_risk_score: null,
      estimated_credits: null,
      owner_user_email: null,
      owner_user_full_name: null,
      repo_url: null,
      branch: null,
      run: null,
      sources,
      jobs_total: null,
      jobs_done: null,
      asset_count: g.assets,
      endpoints_probed: g.probed,
      limited: true,
    };
  });
}

/** Newest first: created_at descending, then runs before scans, then id descending (a stable, total order). */
function newestFirst(a: ResultRow, b: ResultRow): number {
  const d = time(b.created_at) - time(a.created_at);
  if (d !== 0 && !Number.isNaN(d)) return d > 0 ? 1 : -1;
  if (a.kind !== b.kind) return a.kind === "run" ? -1 : 1;
  return b.id - a.id;
}

/**
 * One list for the table. `runs` is `runs_list_data` when the backend sends it (even empty); when it is absent
 * (`undefined`/`null`), run rows are built from `sourcesRuns`.
 */
export function mergeResultRows(
  scans: readonly CBOMConversation[] | null | undefined,
  runs: readonly RunListRow[] | null | undefined,
  sourcesRuns?: readonly CbomSourcesRun[] | null,
): ResultRow[] {
  const runRows: RunResultRow[] = runs != null ? runs.map(runRow) : runRowsFromSourcesRuns(sourcesRuns);
  const rows: ResultRow[] = [...(scans ?? []).map(scanRow), ...runRows];
  return rows.sort(newestFirst);
}

/** Risk score shown in the table: clamped to 0-10, one decimal. */
export function displayRiskScore(row: Pick<ResultRow, "average_risk_score">): number | null {
  if (row.average_risk_score == null) return null;
  return Math.round(Math.min(10, Math.max(0, row.average_risk_score)) * 10) / 10;
}

/** Risk tiers: Critical >= 9, High 7-9, Medium 5-7, Low < 5; a row without a score matches only "all". */
export function matchesRiskTier(score: number | null, tier: RiskScoreFilter): boolean {
  if (tier === "all") return true;
  if (score == null) return false;
  if (tier === "critical") return score >= 9;
  if (tier === "high") return score >= 7 && score < 9;
  if (tier === "medium") return score >= 5 && score < 7;
  return score < 5;
}

/** Search: scans by title, repository and branch; runs by title, source names and run number ("#5", "5"). */
export function matchesSearch(row: ResultRow, query: string): boolean {
  const q = query.trim().toLowerCase();
  if (!q) return true;
  const hay: string[] = [row.title];
  if (row.kind === "scan") {
    if (row.repo_url) hay.push(row.repo_url);
    if (row.branch) hay.push(row.branch);
  } else {
    for (const s of row.sources) hay.push(s.name);
    hay.push(`#${row.id}`, `run #${row.id}`, String(row.id));
  }
  return hay.some((h) => h.toLowerCase().includes(q));
}

export function filterAndSortRows(rows: readonly ResultRow[], f: ResultFilters): ResultRow[] {
  const out = rows.filter((r) => {
    if (!matchesSearch(r, f.search)) return false;
    if (f.status !== "all" && r.scan_status !== f.status) return false;
    return matchesRiskTier(displayRiskScore(r), f.risk);
  });
  if (f.sort === "none") return out;
  const score = (r: ResultRow) => displayRiskScore(r) ?? -1;
  const credits = (r: ResultRow) => r.estimated_credits ?? -1;
  const cmp: Record<Exclude<TableSortBy, "none">, (a: ResultRow, b: ResultRow) => number> = {
    created_asc: (a, b) => -newestFirst(a, b),
    created_desc: newestFirst,
    risk_desc: (a, b) => score(b) - score(a),
    risk_asc: (a, b) => score(a) - score(b),
    credits_desc: (a, b) => credits(b) - credits(a),
    credits_asc: (a, b) => credits(a) - credits(b),
  };
  return [...out].sort(cmp[f.sort]);
}

/** Live progress of an active run: jobs done / total (null when unknown or nothing to show). */
export function runProgress(row: RunResultRow): { done: number; total: number; pct: number } | null {
  if (row.jobs_total == null || row.jobs_total <= 0 || row.jobs_done == null) return null;
  const done = Math.min(row.jobs_done, row.jobs_total);
  return { done, total: row.jobs_total, pct: Math.round((done / row.jobs_total) * 100) };
}

/** Footer note when the backend loaded fewer runs than the team has. */
export function runsLoadedNote(loaded: number, total: number | null | undefined): string | null {
  if (total == null || total <= loaded) return null;
  return `${loaded} newest runs loaded · ${total} runs in total`;
}
