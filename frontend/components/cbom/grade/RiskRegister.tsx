"use client";

// Quantum risk -> Register (CB-23 PR-B, the CISO view): the team's distribution (one row per asset across sources),
// what is still to re-grade, closures per week, and the register table worst first, filtered, keyset-paged, with a
// CSV of the filtered rows. Fed only by the register API. Hooks: register-row-<key> (data-q), register-total.
import { useMemo, useState, type ChangeEvent } from "react";

import { formatDateTime } from "@/components/cbom/sources/logic";

import { QDistributionBar, QGradeChip } from "./QGrade";
import { GRADE_TEXT, humanize } from "./model";
import {
  closureTrend,
  downloadRegisterCsv,
  registerRows,
  useRegister,
  useRegisterSummary,
  type RegisterFilters,
  type RegisterRow,
  type RegisterSummary,
} from "./register";

const GRADE_OPTIONS = [...GRADE_TEXT.map((t) => ({ value: t.split(" ")[0], label: t })), { value: "none", label: "No grade" }];

export function RegisterSummaryCard({ summary }: { summary: RegisterSummary }) {
  const trend = closureTrend(summary);
  const reasons = Object.entries(summary.q0_reasons ?? {}).sort((a, b) => b[1] - a[1]);
  return (
    <div className="space-y-3" data-testid="register-summary">
      <p className="text-sm text-zinc-700 dark:text-zinc-300" data-testid="register-total" data-total={summary.total}>
        {summary.total} assets, one row per asset however many sources see it.
      </p>
      <QDistributionBar posture={{ q_grades: summary.q_grades, assets: summary.total }} />
      {reasons.length > 0 && (
        <p className="text-xs text-zinc-500 dark:text-zinc-400">
          Q0 Unknown assets: {reasons.map(([code, n]) => `${humanize(code)} ${n}`).join(" · ")}
        </p>
      )}
      {summary.pending_regrade > 0 && (
        <p className="text-xs text-amber-700 dark:text-amber-300" data-testid="register-pending" role="status">
          {summary.pending_regrade} assets are being re-graded after an input or grade-model change; their grades update shortly.
        </p>
      )}
      {summary.estate?.stale && (
        <p className="text-xs text-amber-700 dark:text-amber-300" role="status">
          The estate store missed a run and is being repaired; some rows may be behind.
        </p>
      )}
      {trend.some((w) => w.total > 0) && (
        <p className="text-xs text-zinc-500 dark:text-zinc-400" data-testid="register-closures">
          Q0 gaps closed per week: {trend.map((w) => `${w.week.slice(5)} ${w.total}`).join(" · ")}
        </p>
      )}
    </div>
  );
}

export function RegisterTable({ rows }: { rows: RegisterRow[] }) {
  if (!rows.length) return <p className="text-sm text-zinc-500" data-testid="register-empty">No assets match.</p>;
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="text-left text-xs text-zinc-500 dark:text-zinc-400">
            <th className="py-1 pr-3 font-medium">Grade</th>
            <th className="py-1 pr-3 font-medium">Asset</th>
            <th className="py-1 pr-3 font-medium">Family</th>
            <th className="py-1 pr-3 font-medium">Exposure</th>
            <th className="py-1 pr-3 font-medium">Source</th>
            <th className="py-1 font-medium">Last observed</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r.item_key} className="border-t border-zinc-100 align-top dark:border-zinc-800"
                data-testid={`register-row-${r.item_key}`} data-q={r.q_grade ?? "none"}>
              <td className="py-1.5 pr-3"><QGradeChip item={r} /></td>
              <td className="py-1.5 pr-3">
                <div className="font-medium text-zinc-900 dark:text-zinc-100">{r.label || r.item_key}</div>
                <div className="text-xs text-zinc-500 dark:text-zinc-400">
                  {humanize(r.asset_type ?? "asset")} · {humanize(r.q_reason)}
                  {r.presence !== "present" ? " · not read in the latest collection" : ""}
                </div>
              </td>
              <td className="py-1.5 pr-3 text-xs">{r.family ?? "—"}</td>
              <td className="py-1.5 pr-3 text-xs">{r.exposure ? humanize(r.exposure) : "—"}</td>
              <td className="py-1.5 pr-3 text-xs">
                {r.source_name ?? "—"}{r.sources > 1 ? ` (+${r.sources - 1} more)` : ""}
                {r.application ? <div className="text-zinc-500">{r.application}</div> : null}
              </td>
              <td className="py-1.5 whitespace-nowrap text-xs">{formatDateTime(r.last_observed_at)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/** The CISO view: summary, filters, table, CSV. */
export function RiskRegister({ teamId }: { teamId: number }) {
  const [filters, setFilters] = useState<RegisterFilters>({});
  const [downloading, setDownloading] = useState(false);
  const summary = useRegisterSummary(teamId);
  const list = useRegister(teamId, filters);
  const rows = useMemo(() => registerRows(list.data?.pages), [list.data?.pages]);
  const total = list.data?.pages?.[0]?.total;
  const families = Object.keys(summary.data?.families ?? {});
  const set = (k: keyof RegisterFilters) => (e: ChangeEvent<HTMLSelectElement>) =>
    setFilters((f) => ({ ...f, [k]: e.target.value || undefined }));
  return (
    <div className="space-y-4" data-testid="risk-register">
      {summary.data && <RegisterSummaryCard summary={summary.data} />}
      {summary.isError && <p className="text-sm text-red-600" role="alert">Could not load the register summary.</p>}
      <div className="flex flex-wrap items-end gap-2">
        <label className="text-xs text-zinc-600 dark:text-zinc-400">Grade{" "}
          <select className="rounded border border-zinc-300 bg-transparent px-1.5 py-1 text-xs dark:border-zinc-700"
                  value={filters.grade ?? ""} onChange={set("grade")} data-testid="register-filter-grade">
            <option value="">Any</option>
            {GRADE_OPTIONS.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
          </select>
        </label>
        <label className="text-xs text-zinc-600 dark:text-zinc-400">Family{" "}
          <select className="rounded border border-zinc-300 bg-transparent px-1.5 py-1 text-xs dark:border-zinc-700"
                  value={filters.family ?? ""} onChange={set("family")} data-testid="register-filter-family">
            <option value="">Any</option>
            {families.map((f) => <option key={f} value={f}>{f}</option>)}
          </select>
        </label>
        <label className="text-xs text-zinc-600 dark:text-zinc-400">Exposure{" "}
          <select className="rounded border border-zinc-300 bg-transparent px-1.5 py-1 text-xs dark:border-zinc-700"
                  value={filters.exposure ?? ""} onChange={set("exposure")} data-testid="register-filter-exposure">
            <option value="">Any</option>
            {["internet", "internal", "unknown"].map((x) => <option key={x} value={x}>{humanize(x)}</option>)}
          </select>
        </label>
        <button type="button" data-testid="register-csv" disabled={downloading}
                className="rounded-md border border-zinc-300 px-2.5 py-1 text-xs font-medium dark:border-zinc-700"
                onClick={async () => {
                  setDownloading(true);
                  try { await downloadRegisterCsv(teamId, filters); } finally { setDownloading(false); }
                }}>
          {downloading ? "Preparing CSV…" : "Download CSV"}
        </button>
        {typeof total === "number" && <span className="text-xs text-zinc-500">{total} rows</span>}
      </div>
      {list.isLoading && <p className="text-sm text-zinc-500">Loading the register…</p>}
      {list.isError && (
        <p className="text-sm text-red-600" role="alert">
          Could not load the register. <button type="button" className="underline" onClick={() => list.refetch()}>Retry</button>
        </p>
      )}
      {list.data && <RegisterTable rows={rows} />}
      {list.hasNextPage && (
        <button type="button" className="text-xs underline" disabled={list.isFetchingNextPage}
                onClick={() => list.fetchNextPage()}>
          {list.isFetchingNextPage ? "Loading…" : "Load more"}
        </button>
      )}
    </div>
  );
}
