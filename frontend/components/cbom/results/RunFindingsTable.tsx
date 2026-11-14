"use client";

// S12: the run's one findings table, in the code page's look (CbomResults "Cryptographic findings"): select, Impact,
// Algorithm, Type, Where, Finding, Strength, Quantum, Risk score, Source, Wave, Status, [Quantum risk], [Fix class],
// Actions. Paged and filtered by the server (GET /runs/{id}/assets: view, type, impact, quantum, q, source_id, status);
// the page never filters or counts rows itself. #267: a row click (or Enter / Space on a focused row) opens the finding
// dialog (S14), the Actions column (Action + Details) is pinned right, and only the essential columns show by default
// (the rest are in the Columns chooser, remembered per user).
// Test ids kept for the gate: run-results, run-asset-<id> with data-* attributes (data-type-label too; the gate reads
// rows from these, not by column position, since columns can be hidden), every cell's data-col="<column id>",
// run-results-total ("N assets found" in All assets), run-results-page, button "Next", run-results-empty.

import { CheckCircle, Circle, Eye, EyeOff, Loader2, Pencil, Search, ShieldAlert } from "lucide-react";
import { Fragment, useRef, useState } from "react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Checkbox } from "@/components/ui/checkbox";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from "@/components/ui/dropdown-menu";
import { Input } from "@/components/ui/input";
import { ScrollArea, ScrollBar } from "@/components/ui/scroll-area";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import FindingSelectionMenu from "@/components/finding-selection-menu";
import { FixClassChip, QGradeChip, type FixClassFields, type QGradeFields } from "@/components/cbom/grade";
import type { CbomFindingStatus, CbomImpact, CbomRunAssetItem, CbomRunAssetPage } from "@/utils/backend_api";
import type { CbomRemediationItem } from "@/utils/api/cbom_ops";

import { pluralize } from "@/components/cbom/sources/logic";
import { ASSET_TYPE_LABEL, factsRows } from "@/components/cbom/sources/RunResults";
import { BulkAssignBar, WaveBadge } from "@/components/cbom/sources/WavesControls";
import { ErrorBlock, LoadingBlock, StatusBadge, Truncate } from "@/components/cbom/sources/shared";

import { getFindingStatusBadgeClass, getImpactBadgeClass, getRiskScoreBoxClass, getStrengthBadgeClass } from "./badgeClasses";
import {
  assetRowAttrs,
  FINDING_STATUS_LABEL,
  FINDING_STATUSES,
  findingStatusOf,
  hasActiveFilters,
  optionalColumns,
  pageCount,
  serverSupportsFindingsView,
  tableTotal,
  viewCounts,
  type RunTableFilters,
} from "./model";
import { InfoTip } from "@/components/ui/info-tip";
import { ColumnChooser, useColumnPrefs } from "./ColumnChooser";
import { rowOpenProps, RUN_TABLE_COLUMNS, STICKY_ACTIONS, type RunColumnId } from "./findingTable";

const IMPACTS: CbomImpact[] = ["Critical", "High", "Medium", "Low"];
const IMPACT_TONE = { Critical: "red", High: "red", Medium: "amber", Low: "blue" } as const;
const STATUS_ICON: Record<CbomFindingStatus, typeof CheckCircle> = { fixed: CheckCircle, ignored: EyeOff, in_progress: Loader2, not_started: Circle };

/** Bounds the Radix viewport (on the root the limit does not stop the table painting over the next section). */
export const VIEWPORT_MAX_H_TABLE = "[&>[data-slot=scroll-area-viewport]]:max-h-[640px]";
/** The shadcn Table wraps <table> in its own `overflow-auto` div, which never scrolls inside the ScrollArea but becomes
 * the sticky cells' scroll container, so they never stuck: make that wrapper visible (R-qa, PR #120). */
export const TABLE_WRAPPER_VISIBLE = "[&_div:has(>table[data-slot=table])]:overflow-visible";
/** Below 768 px the select and name columns stay on screen while the table scrolls sideways (PLAN §4.5). */
const STICKY_SELECT = "max-md:sticky max-md:left-0 max-md:z-10 max-md:bg-white max-md:dark:bg-zinc-900";
const STICKY_NAME = "max-md:sticky max-md:left-12 max-md:z-10 max-md:bg-white max-md:dark:bg-zinc-900";
const SEARCH_DEBOUNCE_MS = 400;

export interface RunTableSelection {
  /** asset id -> stable asset key (what PUT /cbom/remediation takes) */
  keys: Map<number, string>;
}

function QuantumCell({ item }: { item: CbomRunAssetItem }) {
  if (item.quantum_vulnerable === true) return <Badge variant="outline" className="border-red-500/50 text-red-600 dark:text-red-400">Vulnerable</Badge>;
  if (item.quantum_vulnerable === false) return <Badge variant="outline" className="border-emerald-500/50 text-emerald-600 dark:text-emerald-400">Safe</Badge>;
  return <span className="text-zinc-500 dark:text-zinc-400 text-xs" title="Not applicable to this kind of asset">—</span>;
}

export function AsOfRunNote({ item }: { item: CbomRunAssetItem }) {
  if (!item.as_of_run) return null;
  return (
    <p className="text-xs text-amber-700 dark:text-amber-400" data-testid="asset-as-of-run">
      Judged today ({item.as_of_run.judged_on}): a certificate expiry or library end-of-life date passed after this run. The run on{" "}
      {item.as_of_run.date} recorded {item.as_of_run.impact ? `${item.as_of_run.impact}` : "no finding"}
      {item.as_of_run.finding_codes.length > 0 ? ` (${item.as_of_run.finding_codes.join(", ")})` : ""}.
    </p>
  );
}

export function CollectedFacts({ item }: { item: CbomRunAssetItem }) {
  const rows = factsRows(item);
  if (rows.length === 0) return null;
  return (
    <details className="text-xs">
      <summary className="cursor-pointer text-zinc-500">Collected facts</summary>
      <dl className="mt-2 grid grid-cols-1 sm:grid-cols-[180px_1fr] gap-x-4 gap-y-1 text-xs">
        {rows.map(([key, value]) => (
          <Fragment key={key}>
            <dt className="text-zinc-500">{key}</dt>
            <dd className="text-zinc-800 dark:text-zinc-200 break-all font-mono">{value}</dd>
          </Fragment>
        ))}
      </dl>
    </details>
  );
}

export function assetName(item: CbomRunAssetItem): string {
  return item.algorithm_name ?? item.algorithm ?? item.protocol ?? item.name ?? item.location;
}

export function RunFindingsTable({
  teamId, runId, active, page, isLoading, error, onRetry, filters, onFilters, sources, waveOf, selection, onSelection,
  onOpenDetails, onSetStatus, statusPending,
}: {
  teamId: number;
  runId: number;
  active: boolean;
  page: CbomRunAssetPage | undefined;
  isLoading: boolean;
  error: unknown;
  onRetry: () => void;
  filters: RunTableFilters;
  onFilters: (patch: Partial<RunTableFilters>) => void;
  sources: { id: number | null; name: string }[];
  /** the wave entry of a row: the API item's own `wave`, else the run remediation list's (older backend) */
  waveOf: (item: CbomRunAssetItem) => CbomRemediationItem | undefined;
  selection: Map<number, string>;
  onSelection: (next: Map<number, string>) => void;
  onOpenDetails: (item: CbomRunAssetItem) => void;
  onSetStatus: (keys: string[], status: CbomFindingStatus) => void;
  statusPending: boolean;
}) {
  const [search, setSearch] = useState(filters.q ?? "");
  const columns = useColumnPrefs("run", RUN_TABLE_COLUMNS);
  const typing = useRef<ReturnType<typeof setTimeout> | null>(null);
  // the search applies as you type (debounced), like the code page's table; Enter applies at once
  const applySearch = (value: string, delay: number) => {
    if (typing.current) clearTimeout(typing.current);
    typing.current = setTimeout(() => {
      const q = value.trim() || undefined;
      if (q !== filters.q) onFilters({ q, page: 1 });
    }, delay);
  };

  const supportsView = serverSupportsFindingsView(page);
  const counts = viewCounts(page);
  // An older server lists every asset whatever `view` says: the table then says so and labels it as All assets.
  const effectiveView = supportsView ? filters.view : "all";
  const items = page?.items ?? [];
  const pages = pageCount(page);
  const cols = optionalColumns(items);
  const types = Object.entries(page?.facets.type ?? {}).sort((a, b) => b[1] - a[1]);
  const keyOf = (item: CbomRunAssetItem): string | null => item.asset_key ?? waveOf(item)?.asset_key ?? null;
  const selectable = items.filter((i) => !!keyOf(i));
  const allSelected = selectable.length > 0 && selectable.every((i) => selection.has(i.id));
  // Quantum risk / Fix class are offered only once the server sends them (#113 / #114)
  const offered = RUN_TABLE_COLUMNS.filter((c) => (c.id !== "qgrade" || cols.qGrade) && (c.id !== "fixclass" || cols.fixClass));
  const show = (id: RunColumnId) => columns.isVisible(id) && offered.some((c) => c.id === id);

  const toggle = (item: CbomRunAssetItem) => {
    const key = keyOf(item);
    if (!key) return;
    const next = new Map(selection);
    if (next.has(item.id)) next.delete(item.id);
    else next.set(item.id, key);
    onSelection(next);
  };

  return (
    <Card id="bom-findings" data-testid="run-results" className="min-w-0">
      <CardHeader>
        <CardTitle>Cryptographic findings <InfoTip id="cbom.run.findings" /></CardTitle>
        <CardDescription>
          {effectiveView === "findings"
            ? "Assets of this run with a finding. Select rows to change their status or plan a remediation wave; click a row for its explanation."
            : "Every asset this run collected, including clean ones and parts it could not read (Not collected)."}
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4 min-w-0">
        <div className="flex flex-wrap items-center gap-2">
          <div className="inline-flex rounded-md border border-zinc-200 dark:border-zinc-700 p-0.5" role="group" aria-label="Rows to show">
            {(["findings", "all"] as const).map((v) => (
              <button key={v} type="button" aria-pressed={effectiveView === v} disabled={v === "findings" && !supportsView && !!page}
                      data-testid={`run-results-view-${v}`}
                      onClick={() => onFilters({ view: v, page: 1 })}
                      className={`px-3 py-1 text-sm rounded cursor-pointer disabled:cursor-not-allowed disabled:opacity-50 ${effectiveView === v ? "bg-zinc-900 text-white dark:bg-white dark:text-zinc-900" : "text-zinc-600 dark:text-zinc-400"}`}>
                {v === "findings" ? `Findings (${counts.findings ?? "—"})` : `All assets (${counts.all ?? "—"})`}
              </button>
            ))}
          </div>
          <InfoTip id="cbom.run.view" />
          {page && (
            <p className="text-sm font-medium text-zinc-900 dark:text-white" data-testid="run-results-total">
              {effectiveView === "all"
                ? `${pluralize(tableTotal(page, "all", hasActiveFilters(filters)), "asset")} found`
                : pluralize(tableTotal(page, "findings", hasActiveFilters(filters)), "finding")}
            </p>
          )}
          {page && IMPACTS.map((impact) =>
            page.facets.impact[impact] ? (
              <button key={impact} type="button" className="cursor-pointer" data-testid={`run-results-impact-${impact}`}
                      onClick={() => onFilters({ impact: filters.impact === impact ? undefined : impact, page: 1 })}>
                <StatusBadge tone={filters.impact === impact ? "blue" : IMPACT_TONE[impact]}>{impact} {page.facets.impact[impact]}</StatusBadge>
              </button>
            ) : null,
          )}
          {page && page.facets.quantum_vulnerable > 0 && (
            <button type="button" className="cursor-pointer" onClick={() => onFilters({ quantum: filters.quantum ? undefined : true, page: 1 })}>
              <StatusBadge tone={filters.quantum ? "blue" : "zinc"}>
                <ShieldAlert className="h-3 w-3" /> Quantum-vulnerable {page.facets.quantum_vulnerable}
              </StatusBadge>
            </button>
          )}
        </div>
        {page && !supportsView && (
          <p className="text-xs text-zinc-500" data-testid="run-results-view-note">
            This server lists every asset of the run (the Findings view and the status filter come with the backend update).
          </p>
        )}

        <div className="flex flex-wrap items-center gap-3">
          <div className="relative flex-1 min-w-[200px] max-w-sm">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-zinc-400" />
            <Input type="search" placeholder="Search location, algorithm or finding" value={search} className="pl-9 h-9"
                   aria-label="Search findings table" data-testid="run-results-search"
                   onChange={(e) => { setSearch(e.target.value); applySearch(e.target.value, SEARCH_DEBOUNCE_MS); }}
                   onKeyDown={(e) => e.key === "Enter" && applySearch(search, 0)} />
          </div>
          <InfoTip id="cbom.run.search" className="-ml-1" />
          <Select value={filters.impact ?? "all"} onValueChange={(v) => onFilters({ impact: v === "all" ? undefined : (v as CbomImpact), page: 1 })}>
            <SelectTrigger className="h-9 min-w-[140px] cursor-pointer" aria-label="Impact" data-testid="run-results-impact"><SelectValue /></SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All impacts</SelectItem>
              {IMPACTS.map((i) => <SelectItem key={i} value={i}>{i}</SelectItem>)}
            </SelectContent>
          </Select>
          <InfoTip id="cbom.run.filter.impact" className="-ml-1" />
          <Select value={filters.type ?? "all"} onValueChange={(v) => onFilters({ type: v === "all" ? undefined : v, page: 1 })}>
            <SelectTrigger className="h-9 min-w-[180px] cursor-pointer" aria-label="Type" data-testid="run-results-type"><SelectValue /></SelectTrigger>
            <SelectContent>
              <SelectItem value="all" className="cursor-pointer">All types</SelectItem>
              {types.map(([type, count]) => (
                <SelectItem key={type} value={type} className="cursor-pointer">{ASSET_TYPE_LABEL[type] ?? type} ({count})</SelectItem>
              ))}
            </SelectContent>
          </Select>
          <InfoTip id="cbom.run.filter.type" className="-ml-1" />
          <Select value={filters.quantum ? "vulnerable" : "all"} onValueChange={(v) => onFilters({ quantum: v === "vulnerable" ? true : undefined, page: 1 })}>
            <SelectTrigger className="h-9 min-w-[150px] cursor-pointer" aria-label="Quantum" data-testid="run-results-quantum"><SelectValue /></SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All</SelectItem>
              <SelectItem value="vulnerable">Quantum-vulnerable</SelectItem>
            </SelectContent>
          </Select>
          <InfoTip id="cbom.run.filter.quantum" className="-ml-1" />
          {sources.some((s) => s.id != null) && (
            <>
              <Select value={filters.source_id != null ? String(filters.source_id) : "all"}
                      onValueChange={(v) => onFilters({ source_id: v === "all" ? undefined : Number(v), page: 1 })}>
                <SelectTrigger className="h-9 min-w-[160px] cursor-pointer" aria-label="Source" data-testid="run-results-source"><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All sources</SelectItem>
                  {sources.filter((s) => s.id != null).map((s) => <SelectItem key={s.id} value={String(s.id)}>{s.name}</SelectItem>)}
                </SelectContent>
              </Select>
              <InfoTip id="cbom.run.filter.source" className="-ml-1" />
            </>
          )}
          {supportsView && (
            <>
              <Select value={filters.status ?? "all"} onValueChange={(v) => onFilters({ status: v === "all" ? undefined : (v as CbomFindingStatus), page: 1 })}>
                <SelectTrigger className="h-9 min-w-[140px] cursor-pointer" aria-label="Status" data-testid="run-results-status-filter"><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All statuses</SelectItem>
                  {FINDING_STATUSES.map((s) => <SelectItem key={s} value={s}>{FINDING_STATUS_LABEL[s]}</SelectItem>)}
                </SelectContent>
              </Select>
              <InfoTip id="cbom.run.filter.status" className="-ml-1" />
            </>
          )}
          {hasActiveFilters(filters) && (
            <Button variant="ghost" size="sm" className="cursor-pointer" onClick={() => {
              if (typing.current) clearTimeout(typing.current);
              setSearch("");
              onFilters({ type: undefined, impact: undefined, quantum: undefined, q: undefined, source_id: undefined, status: undefined,
                          codes: undefined, asset_ids: undefined, drill_label: undefined, page: 1 });
            }}>
              Clear filters
            </Button>
          )}
          <div className="ml-auto">
            <ColumnChooser defs={offered} visible={columns.visible} onToggle={columns.toggle} onReset={columns.reset} testId="run-results-columns" />
          </div>
        </div>
        {(filters.codes?.length || filters.asset_ids?.length) ? (
          // #270: the compliance mapping's "N assets" drill-down
          <p className="text-sm text-zinc-600 dark:text-zinc-400 flex flex-wrap items-center gap-2" data-testid="run-results-drill">
            <StatusBadge tone="blue">Compliance: {filters.drill_label ?? "selected clause"}</StatusBadge>
            <button type="button" className="text-blue-600 dark:text-blue-400 hover:underline cursor-pointer" data-testid="run-results-drill-clear"
                    onClick={() => onFilters({ codes: undefined, asset_ids: undefined, drill_label: undefined, page: 1 })}>
              Show every asset
            </button>
          </p>
        ) : null}

        <FindingSelectionMenu
          selectedCount={selection.size}
          onClearSelection={() => onSelection(new Map())}
          ticketType={null}
          onBulkStatusChange={(status) => onSetStatus([...selection.values()], status)}
          isBulkStatusChanging={statusPending}
        />
        <BulkAssignBar teamId={teamId} target={{ run_id: runId }} keys={[...new Set(selection.values())]} onDone={() => onSelection(new Map())} />

        {isLoading && !page ? (
          <LoadingBlock />
        ) : error && !page ? (
          <ErrorBlock error={error} onRetry={onRetry} />
        ) : !page ? null : items.length === 0 ? (
          <p className="text-sm text-zinc-500" data-testid="run-results-empty">
            {page.all_total === 0
              ? active ? "Nothing collected yet." : "This run collected no assets."
              : hasActiveFilters(filters) ? "No assets match these filters." : effectiveView === "findings" ? "No findings in this run." : "No assets match these filters."}
          </p>
        ) : (
          <ScrollArea className={`w-full rounded-md border border-zinc-200 dark:border-zinc-800 ${VIEWPORT_MAX_H_TABLE} ${TABLE_WRAPPER_VISIBLE}`} data-testid="run-results-scroll">
            <Table className="min-w-max">
              <TableHeader>
                <TableRow>
                  <TableHead data-col="select" className={`w-[48px] ${STICKY_SELECT}`}>
                    {/* infotip-shared: the select column stays 48 px (the sticky name column sits at left-12); the
                        Cryptographic findings title's tip explains selecting rows */}
                    <Checkbox checked={allSelected} aria-label="Select all rows" className="cursor-pointer" disabled={selectable.length === 0}
                              onCheckedChange={() => {
                                const next = new Map(selection);
                                if (allSelected) selectable.forEach((i) => next.delete(i.id));
                                else selectable.forEach((i) => next.set(i.id, keyOf(i)!));
                                onSelection(next);
                              }} />
                  </TableHead>
                  {show("impact") && <TableHead data-col="impact" className="min-w-[90px]">Impact <InfoTip id="results.table.impact" /></TableHead>}
                  {show("algorithm") && <TableHead data-col="algorithm" className={`min-w-[160px] ${STICKY_NAME}`}>Algorithm <InfoTip id="cbom.res.col.algorithm" /></TableHead>}
                  {show("type") && <TableHead data-col="type" className="min-w-[120px]">Type <InfoTip id="cbom.res.col.type" /></TableHead>}
                  {show("where") && <TableHead data-col="where" className="min-w-[200px]">Where <InfoTip id="cbom.run.col.where" /></TableHead>}
                  {show("finding") && <TableHead data-col="finding" className="min-w-[220px]">Finding <InfoTip id="cbom.run.col.finding" /></TableHead>}
                  {show("strength") && <TableHead data-col="strength" className="min-w-[100px]">Strength <InfoTip id="cbom.res.col.strength" /></TableHead>}
                  {show("quantum") && <TableHead data-col="quantum" className="min-w-[100px]">Quantum <InfoTip id="cbom.res.col.quantum" /></TableHead>}
                  {show("risk") && <TableHead data-col="risk" className="min-w-[90px] text-center">Risk score <InfoTip id="cbom.run.f.risk" /></TableHead>}
                  {show("source") && <TableHead data-col="source" className="min-w-[120px]">Source <InfoTip id="cbom.run.col.source" /></TableHead>}
                  {show("wave") && <TableHead data-col="wave" className="min-w-[110px]">Wave <InfoTip id="cbom.run.col.wave" /></TableHead>}
                  {show("status") && <TableHead data-col="status" className="min-w-[100px]">Status <InfoTip id="cbom.run.col.status" /></TableHead>}
                  {show("qgrade") && <TableHead data-col="qgrade" className="min-w-[100px]">Quantum risk <InfoTip id="cbom.run.col.qgrade" /></TableHead>}
                  {show("fixclass") && <TableHead data-col="fixclass" className="min-w-[110px]">Fix class <InfoTip id="cbom.res.col.fix_class" /></TableHead>}
                  <TableHead data-col="actions" className={`min-w-[150px] text-right ${STICKY_ACTIONS}`}><span className="inline-flex items-center gap-1">Actions <InfoTip id="results.finding.action" /></span></TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {items.map((item) => {
                  const wave = item.wave ?? waveOf(item);
                  const status = findingStatusOf(item, wave);
                  const key = keyOf(item);
                  const coverage = item.type === "coverage";
                  return (
                      <TableRow key={item.id} data-testid={`run-asset-${item.id}`} {...assetRowAttrs(item, wave)}
                                data-type-label={item.type_label ?? ASSET_TYPE_LABEL[item.type] ?? item.type}
                                {...rowOpenProps(() => onOpenDetails(item), `Open details of ${assetName(item)} at ${item.location}`)}
                                className={`cursor-pointer hover:bg-zinc-50 dark:hover:bg-zinc-800/50 focus-visible:outline-none focus-visible:bg-blue-50 dark:focus-visible:bg-blue-950/40 ${selection.has(item.id) ? "bg-zinc-100 dark:bg-zinc-800/70" : ""}`}>
                        <TableCell data-col="select" onClick={(e) => e.stopPropagation()} className={`w-[48px] ${STICKY_SELECT}`}>
                          {/* infotip-shared: one row of the selection; the Select all tip in the header explains it */}
                          <Checkbox checked={selection.has(item.id)} disabled={!key} className="cursor-pointer"
                                    aria-label={`Select ${item.location}`} data-testid={`run-asset-select-${item.id}`}
                                    title={key ? undefined : "This row has no stable key to plan or track"}
                                    onCheckedChange={() => toggle(item)} />
                        </TableCell>
                        {show("impact") && (
                        <TableCell data-col="impact">
                          {item.impact
                            ? <Badge variant="outline" className={getImpactBadgeClass(item.impact)}>{item.impact}</Badge>
                            : <span className="text-xs text-zinc-500">Info</span>}
                        </TableCell>
                        )}
                        {show("algorithm") && (
                        <TableCell data-col="algorithm" className={`font-medium whitespace-nowrap ${STICKY_NAME}`}>
                          <button type="button" className="text-left text-blue-600 hover:text-blue-700 dark:text-blue-400 dark:hover:text-blue-300 hover:underline cursor-pointer font-medium max-w-[180px] truncate inline-block align-bottom"
                                  title={assetName(item)} onClick={(e) => { e.stopPropagation(); onOpenDetails(item); }}>
                            {assetName(item)}
                          </button>
                          {item.key_size ? <span className="text-zinc-500 text-xs ml-1">{item.key_size}</span> : null}
                        </TableCell>
                        )}
                        {show("type") && <TableCell data-col="type" className="text-sm text-zinc-600 dark:text-zinc-400">{item.type_label ?? ASSET_TYPE_LABEL[item.type] ?? item.type}</TableCell>}
                        {show("where") && (
                        <TableCell data-col="where" className="max-w-[280px]">
                          <Truncate text={item.location} className="font-mono text-xs text-zinc-900 dark:text-white" />
                          {item.target && item.target !== item.location && <Truncate text={item.target} className="text-xs text-zinc-500" />}
                        </TableCell>
                        )}
                        {show("finding") && <TableCell data-col="finding" className="max-w-[320px]"><Truncate text={item.finding} className="text-sm text-zinc-600 dark:text-zinc-400" /></TableCell>}
                        {show("strength") && (
                        <TableCell data-col="strength">
                          {item.crypto_strength
                            ? <Badge variant="outline" className={getStrengthBadgeClass(item.crypto_strength)}>{item.crypto_strength}</Badge>
                            : <span className="text-xs text-zinc-500">—</span>}
                        </TableCell>
                        )}
                        {show("quantum") && <TableCell data-col="quantum"><QuantumCell item={item} /></TableCell>}
                        {show("risk") && (
                        <TableCell data-col="risk" className="text-center">
                          <span className={`inline-flex items-center justify-center min-w-9 px-2 py-1 rounded-md text-xs font-semibold tabular-nums ${typeof item.risk_score === "number" ? getRiskScoreBoxClass(item.risk_score) : "text-zinc-500"}`}
                                title="Risk score (0-10, the same score as code findings)">
                            {typeof item.risk_score === "number" ? item.risk_score.toFixed(1) : "—"}
                          </span>
                        </TableCell>
                        )}
                        {show("source") && <TableCell data-col="source" className="max-w-[160px]"><Truncate text={item.source_name} className="text-sm text-zinc-600 dark:text-zinc-400" /></TableCell>}
                        {show("wave") && <TableCell data-col="wave"><WaveBadge item={wave ?? undefined} /></TableCell>}
                        {show("status") && (
                        <TableCell data-col="status">
                          {coverage ? (
                            <span className="text-xs text-zinc-500" title="A part the run could not read: nothing to plan or track">—</span>
                          ) : (
                            <span className={`inline-flex items-center justify-center px-2.5 py-1 rounded-md text-xs font-medium capitalize ${getFindingStatusBadgeClass(status)}`}>
                              {status.replace(/_/g, " ")}
                            </span>
                          )}
                        </TableCell>
                        )}
                        {show("qgrade") && (
                          <TableCell data-col="qgrade"><QGradeChip item={item as QGradeFields} assetId={item.id} /></TableCell>
                        )}
                        {show("fixclass") && (
                          <TableCell data-col="fixclass"><FixClassChip item={item as FixClassFields} assetId={item.id} /></TableCell>
                        )}
                        <TableCell data-col="actions" className={`text-right whitespace-nowrap ${STICKY_ACTIONS}`} onClick={(e) => e.stopPropagation()}
                                   data-testid={`run-asset-actions-${item.id}`}>
                          <div className="inline-flex items-center gap-1.5">
                            <DropdownMenu>
                              {/* infotip-shared: explained by the (i) on the Actions column header */}
                              <DropdownMenuTrigger asChild>
                                <Button variant="outline" size="sm" className="cursor-pointer gap-1.5 h-8" aria-label="Finding actions"
                                        disabled={!key} title={key ? undefined : "This row has no stable key to track a status"}
                                        data-testid={`run-asset-action-${item.id}`}>
                                  <Pencil className="h-3.5 w-3.5 opacity-70" /> Action
                                </Button>
                              </DropdownMenuTrigger>
                              <DropdownMenuContent align="end">
                                {FINDING_STATUSES.map((s) => {
                                  const Icon = STATUS_ICON[s];
                                  return (
                                    <DropdownMenuItem key={s} className="cursor-pointer gap-2" disabled={statusPending}
                                                      data-testid={`run-asset-status-${item.id}-${s}`}
                                                      onClick={() => key && onSetStatus([key], s)}>
                                      <Icon className="h-4 w-4" /> Mark as {FINDING_STATUS_LABEL[s]}
                                    </DropdownMenuItem>
                                  );
                                })}
                              </DropdownMenuContent>
                            </DropdownMenu>
                            <Button variant="ghost" size="sm" className="cursor-pointer h-8 gap-1" data-testid={`run-asset-details-${item.id}`}
                                    aria-label={`Details of ${item.location}`} onClick={() => onOpenDetails(item)}>
                              <Eye className="h-3.5 w-3.5" /> Details
                            </Button>
                          </div>
                        </TableCell>
                      </TableRow>
                  );
                })}
              </TableBody>
            </Table>
            <ScrollBar orientation="horizontal" />
          </ScrollArea>
        )}

        {pages > 1 && (
          <div className="flex items-center justify-end gap-2 text-sm text-zinc-600 dark:text-zinc-400">
            <Button size="sm" variant="outline" className="cursor-pointer" disabled={filters.page <= 1} onClick={() => onFilters({ page: filters.page - 1 })}>
              Previous
            </Button>
            <span data-testid="run-results-page">Page {filters.page} of {pages}</span>
            <Button size="sm" variant="outline" className="cursor-pointer" disabled={filters.page >= pages} onClick={() => onFilters({ page: filters.page + 1 })}>
              Next
            </Button>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
