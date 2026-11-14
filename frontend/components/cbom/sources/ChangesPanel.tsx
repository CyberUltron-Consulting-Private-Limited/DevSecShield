"use client";

// "Changes" of a run (drift events against each source's previous complete collection), the run comparison dialog,
// and the heat-map + certificate calendar of a run. Only complete collections are compared: a partial or failed job
// shows as "not compared" with its reason, never as everything removed.

import { useQuery } from "@tanstack/react-query";
import { useState } from "react";

import CertCalendar from "@/components/cbom/CertCalendar";
import CryptoHeatmap from "@/components/cbom/CryptoHeatmap";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import {
  cbomOpsKeys,
  getCbomCodeDiff,
  getCbomRunChanges,
  getCbomRunDiff,
  getCbomRunHeatmap,
  type CbomDiff,
  type CbomDiffAsset,
  type CbomDriftKind,
} from "@/utils/api/cbom_ops";

import { ASSET_TYPE_LABEL } from "./RunResults";
import { formatDateTime, groupNotRead, pluralize } from "./logic";
import { ErrorBlock, LoadingBlock, StatusBadge, type Tone } from "./shared";

export const DRIFT_LABEL: Record<CbomDriftKind, [string, Tone]> = {
  opened: ["Finding opened", "red"],
  resolved: ["Finding resolved", "green"],
  new_asset: ["New asset", "blue"],
  removed_asset: ["Asset removed", "zinc"],
  cert_renewed: ["Certificate renewed", "green"],
  cert_expiring: ["Certificate expiring", "amber"],
  schedule_skipped: ["Scheduled run skipped", "amber"],
};

export function RunChanges({ teamId, runId, finished }: { teamId: number; runId: number; finished: boolean }) {
  const [all, setAll] = useState(false);
  const q = useQuery({
    queryKey: cbomOpsKeys.changes(teamId, runId),
    queryFn: () => getCbomRunChanges(teamId, runId),
    enabled: finished,
    retry: 1,
  });
  if (!finished) return <p className="text-xs text-zinc-500">Changes are listed when the run has finished.</p>;
  if (q.isLoading) return <LoadingBlock />;
  if (q.isError || !q.data) return <ErrorBlock error={q.error} onRetry={() => q.refetch()} />;
  const events = q.data.events;
  const shown = all ? events : events.slice(0, 25);
  return (
    <div className="space-y-2" data-testid="run-changes">
      <div className="flex flex-wrap gap-2">
        {(Object.keys(DRIFT_LABEL) as CbomDriftKind[]).filter((k) => q.data.counts[k]).map((k) => (
          <StatusBadge key={k} tone={DRIFT_LABEL[k][1]}>{DRIFT_LABEL[k][0]}: {q.data.counts[k]}</StatusBadge>
        ))}
        {!!q.data.not_read_count && <StatusBadge tone="amber">Not read: {q.data.not_read_count}</StatusBadge>}
        {events.length === 0 && !q.data.not_read?.length && (
          <p className="text-xs text-zinc-500">
            No changes: either nothing changed since each source&apos;s previous complete collection, or this is the first one.
          </p>
        )}
      </div>
      {events.length > 0 && (
        <ul className="divide-y divide-zinc-200 dark:divide-zinc-800 text-xs">
          {shown.map((e) => (
            <li key={e.id} className="py-1.5 flex flex-wrap gap-x-2 gap-y-0.5" data-testid={`drift-${e.kind}`}>
              <StatusBadge tone={DRIFT_LABEL[e.kind]?.[1] ?? "zinc"}>{DRIFT_LABEL[e.kind]?.[0] ?? e.kind}</StatusBadge>
              {e.code && <span className="font-mono text-zinc-700 dark:text-zinc-300">{e.code}</span>}
              <span className="text-zinc-800 dark:text-zinc-200 break-all">{e.asset_label}</span>
              <span className="text-zinc-500">{e.source_name}</span>
              {typeof e.detail?.cause === "string" && <span className="text-amber-700 dark:text-amber-400">({e.detail.cause})</span>}
            </li>
          ))}
        </ul>
      )}
      {events.length > 25 && (
        <button type="button" className="text-xs text-blue-600 dark:text-blue-400 cursor-pointer" onClick={() => setAll(!all)}>
          {all ? "Show fewer" : `Show all ${events.length}`}
        </button>
      )}
      <NotReadList items={q.data.not_read} total={q.data.not_read_count} testId="run-changes-not-read" />
    </div>
  );
}

function AssetList({ title, items, tone, testId }: { title: string; items: CbomDiffAsset[] | undefined; tone: Tone; testId: string }) {
  if (!items?.length) return null;
  return (
    <div data-testid={testId}>
      <p className="text-xs font-semibold uppercase tracking-wide text-zinc-500 mb-1">
        <StatusBadge tone={tone}>{items.length}</StatusBadge> {title}
      </p>
      <ul className="space-y-0.5 text-xs text-zinc-700 dark:text-zinc-300 max-h-48 overflow-y-auto">
        {items.slice(0, 200).map((a, i) => (
          <li key={`${a.key}-${a.code ?? ""}-${i}`} className="[overflow-wrap:anywhere]">
            {a.code && <span className="font-mono mr-1.5">{a.code}</span>}
            {a.label}
            <span className="text-zinc-500"> · {ASSET_TYPE_LABEL[a.type] ?? a.type}{a.source_name ? ` · ${a.source_name}` : ""}</span>
            {a.renewed && <span className="ml-1 text-green-700 dark:text-green-400">(renewed)</span>}
            {a.asset_removed && <span className="ml-1 text-zinc-500">(asset gone)</span>}
            {a.rule_change && <span className="ml-1 text-amber-700 dark:text-amber-400">(rule change possible)</span>}
          </li>
        ))}
      </ul>
    </div>
  );
}

/** What the later run did not read (a coverage gap: a stopped target, a denied check). Not removed, findings not
 * resolved: never listed with "resolved" (lab UI r1 F2: the Compare dialog left these out entirely). */
export function NotReadList({ items, total, testId }: { items: CbomDiffAsset[] | undefined; total?: number; testId: string }) {
  if (!items?.length) return null;
  const count = Math.max(total ?? 0, items.length);
  return (
    <div data-testid={testId} className="rounded-md border border-dashed border-amber-500/70 dark:border-amber-500/50 bg-amber-50/60 dark:bg-amber-950/20 p-3">
      <p className="text-xs font-semibold uppercase tracking-wide text-amber-800 dark:text-amber-300 mb-1">
        <StatusBadge tone="amber">{count}</StatusBadge> not read in this run
      </p>
      <p className="text-xs text-zinc-600 dark:text-zinc-400 mb-2">
        Not confirmed either way: these are not counted as removed, and their findings stay open until a run reads them again.
      </p>
      <div className="space-y-2 max-h-56 overflow-y-auto">
        {groupNotRead(items.slice(0, 200)).map((g) => (
          <div key={`${g.source ?? ""}-${g.reason}`}>
            <p className="text-xs text-amber-800 dark:text-amber-300 [overflow-wrap:anywhere]" data-testid={`${testId}-reason`}>
              {g.source ? <span className="font-medium">{g.source}: </span> : null}{g.reason}
            </p>
            <ul className="mt-0.5 space-y-0.5 text-xs text-zinc-700 dark:text-zinc-300">
              {g.items.map((a, i) => (
                <li key={`${a.key}-${i}`} className="[overflow-wrap:anywhere]">
                  {a.label}
                  <span className="text-zinc-500"> · {ASSET_TYPE_LABEL[a.type] ?? a.type}</span>
                  <span className="ml-1 text-zinc-500">
                    {a.asset_removed ? "(not seen in this run" : "(listed, some facts not read"}
                    {a.codes?.length ? `; findings not confirmed: ${a.codes.join(", ")})` : ")"}
                  </span>
                </li>
              ))}
            </ul>
          </div>
        ))}
      </div>
      {count > Math.min(items.length, 200) && <p className="mt-1 text-xs text-zinc-500">Showing {Math.min(items.length, 200)} of {count}.</p>}
    </div>
  );
}

export function DiffView({ diff }: { diff: CbomDiff }) {
  if (diff.message) return <p className="text-sm text-zinc-600 dark:text-zinc-400" data-testid="diff-message">{diff.message}</p>;
  const r = diff.readiness;
  return (
    <div className="space-y-3" data-testid="diff-view">
      <div className="flex flex-wrap gap-3 text-sm">
        <span>PQC readiness: <strong>{r?.before ?? "—"}%</strong> → <strong>{r?.after ?? "—"}%</strong>
          {r?.delta != null && <span className={r.delta >= 0 ? "text-green-700 dark:text-green-400" : "text-red-600"}> ({r.delta >= 0 ? "+" : ""}{r.delta})</span>}
        </span>
        {diff.versions && (diff.versions.rules_changed || diff.versions.reclassified) && (
          <StatusBadge tone="amber">
            {!diff.versions.reclassified ? "Engine version changed"
              : diff.versions.rules_changed ? "Rules changed: both runs re-judged with the current rules"
              : "Judged by older rules: both runs re-judged with the current rules"}
          </StatusBadge>
        )}
      </div>
      {diff.sources && (
        <ul className="text-xs space-y-0.5" data-testid="diff-sources">
          {diff.sources.map((s) => (
            <li key={s.source_ref} className="flex flex-wrap gap-2">
              <StatusBadge tone={s.status === "compared" ? "green" : "zinc"}>{s.status === "compared" ? "Compared" : "Not compared"}</StatusBadge>
              <span className="text-zinc-800 dark:text-zinc-200">{s.name}</span>
              {s.reason && <span className="text-zinc-500">{s.reason}</span>}
            </li>
          ))}
        </ul>
      )}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        <AssetList title="findings resolved" items={diff.resolved} tone="green" testId="diff-resolved" />
        <AssetList title="findings opened" items={diff.opened} tone="red" testId="diff-opened" />
        <AssetList title="assets added" items={diff.added} tone="blue" testId="diff-added" />
        <AssetList title="assets removed" items={diff.removed} tone="zinc" testId="diff-removed" />
        <AssetList title="assets changed" items={diff.changed} tone="amber" testId="diff-changed" />
        {!!diff.rule_changes?.length && (
          <div data-testid="diff-rule-changes">
            <p className="text-xs font-semibold uppercase tracking-wide text-zinc-500 mb-1">
              <StatusBadge tone="amber">{diff.rule_changes.length}</StatusBadge> rule changes (not drift)
            </p>
            <ul className="space-y-0.5 text-xs text-zinc-700 dark:text-zinc-300 max-h-48 overflow-y-auto">
              {diff.rule_changes.map((x, i) => (
                <li key={i} className="break-all"><span className="font-mono mr-1.5">{x.code}</span>{x.direction} · {x.label}</li>
              ))}
            </ul>
          </div>
        )}
      </div>
      <NotReadList items={diff.not_read} total={diff.counts?.not_read} testId="diff-not-read" />
      {diff.truncated && <p className="text-xs text-zinc-500">Lists are cut at 500 entries each.</p>}
    </div>
  );
}

export function CompareDialog({ teamId, runId, runs, onClose }: {
  teamId: number;
  runId: number;
  runs: { id: number; created_at: string | null }[];
  onClose: () => void;
}) {
  const [against, setAgainst] = useState<number | undefined>(undefined);
  const q = useQuery({
    queryKey: cbomOpsKeys.diff(teamId, runId, against),
    queryFn: () => getCbomRunDiff(teamId, runId, against),
    retry: 1,
  });
  const others = runs.filter((r) => r.id !== runId);
  return (
    <Dialog open onOpenChange={(v) => !v && onClose()}>
      <DialogContent className="sm:max-w-4xl max-h-[90vh] overflow-y-auto" data-testid="compare-dialog">
        <DialogHeader>
          <DialogTitle>Compare run #{runId}</DialogTitle>
          <DialogDescription>
            Against {q.data?.against_run_id ? `run #${q.data.against_run_id}` : "the previous complete run"}. Sources not complete in
            both runs are listed as not compared.
          </DialogDescription>
        </DialogHeader>
        <div className="flex items-center gap-2 text-sm">
          <span className="text-zinc-600 dark:text-zinc-400">Compare with</span>
          <Select value={against ? String(against) : "prev"} onValueChange={(v) => setAgainst(v === "prev" ? undefined : Number(v))}>
            <SelectTrigger className="w-[220px] cursor-pointer" aria-label="Run to compare with" data-testid="compare-against">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="prev" className="cursor-pointer">Previous complete run</SelectItem>
              {others.map((r) => (
                <SelectItem key={r.id} value={String(r.id)} className="cursor-pointer">#{r.id} · {formatDateTime(r.created_at)}</SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
        {q.isLoading ? <LoadingBlock /> : q.isError || !q.data ? <ErrorBlock error={q.error} onRetry={() => q.refetch()} /> : <DiffView diff={q.data} />}
        <DialogFooter>
          <Button variant="outline" className="cursor-pointer" onClick={onClose}>Close</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

/** A code scan against the previous completed scan of the same repository and branch (line-independent). */
export function CodeChanges({ teamId, scanId }: { teamId: number; scanId: number }) {
  const [open, setOpen] = useState(false);
  const q = useQuery({
    queryKey: cbomOpsKeys.codeDiff(teamId, scanId),
    queryFn: () => getCbomCodeDiff(teamId, scanId),
    enabled: open,
    retry: 1,
  });
  return (
    <details className="rounded-lg border border-zinc-200 dark:border-zinc-800 p-4" data-testid="code-changes"
             onToggle={(e) => setOpen((e.target as HTMLDetailsElement).open)}>
      <summary className="cursor-pointer text-sm font-medium text-zinc-900 dark:text-white">
        Changes since the previous scan of this repository and branch
      </summary>
      <div className="mt-3">
        {!open ? null : q.isLoading ? <LoadingBlock /> : q.isError || !q.data ? <ErrorBlock error={q.error} onRetry={() => q.refetch()} /> : (
          <>
            {q.data.against_scan_id && <p className="text-xs text-zinc-500 mb-2">Compared with scan #{q.data.against_scan_id}. Fixed findings of that scan are marked fixed and their Jira tickets closed.</p>}
            <DiffView diff={q.data} />
          </>
        )}
      </div>
    </details>
  );
}

/** Heat-map (family x source, or x asset type) and the certificate calendar of one run. */
export function RunInsights({ teamId, runId, active }: { teamId: number; runId: number; active: boolean }) {
  const [by, setBy] = useState<"source" | "type">("source");
  const q = useQuery({
    queryKey: cbomOpsKeys.heatmap(teamId, runId, by),
    queryFn: () => getCbomRunHeatmap(teamId, runId, by),
    retry: 1,
    refetchInterval: active ? 20000 : false,
  });
  if (q.isLoading) return <LoadingBlock />;
  if (q.isError || !q.data) return <ErrorBlock error={q.error} onRetry={() => q.refetch()} />;
  if (q.data.rows.length === 0) return null;
  return (
    <div className="grid grid-cols-1 xl:grid-cols-2 gap-4 rounded-lg border border-zinc-200 dark:border-zinc-800 p-4" data-testid="run-insights">
      <div className="space-y-2 min-w-0">
        <div className="flex gap-2 text-xs" role="group" aria-label="Heat-map columns">
          {(["source", "type"] as const).map((v) => (
            <button key={v} type="button" aria-pressed={by === v} onClick={() => setBy(v)}
                    className={`rounded px-2 py-0.5 cursor-pointer border ${by === v ? "bg-zinc-900 text-white dark:bg-white dark:text-zinc-900" : "border-zinc-300 dark:border-zinc-700"}`}>
              By {v === "source" ? "source" : "asset type"}
            </button>
          ))}
        </div>
        <CryptoHeatmap data={q.data} title={`Algorithm family × ${by === "source" ? "source" : "asset type"}`}
                       columnLabel={by === "type" ? (c) => ASSET_TYPE_LABEL[c] ?? c : undefined} testId="run-heatmap" />
      </div>
      <div className="min-w-0">
        {q.data.certificates.length > 0 ? (
          <CertCalendar certs={q.data.certificates} testId="run-cert-calendar" />
        ) : (
          <p className="text-xs text-zinc-500">No certificates with an expiry date in this run.</p>
        )}
        {q.data.certificates.length > 0 && (
          <p className="text-xs text-zinc-500 mt-1">{pluralize(q.data.certificates.length, "certificate")} with an expiry date.</p>
        )}
      </div>
    </div>
  );
}
