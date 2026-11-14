"use client";

// The data sources of the one CBOM results template (components/CbomResults.tsx). Owner decision (CB-38): a code scan
// and a CBOM Sources run use the SAME results page; only the adapter that feeds it differs.
//
//   codeScanSource(props)          today's code page data (GET /{t}/cbom/scan/{id}: data, dashboard, findings, metadata)
//   useSourcesRunSource(team, run) a run, from GET /runs/{id}, /results, /assets (paged), /posture, /heatmap,
//                                  /changes, /diff, /remediation, /tickets (Ticketing tab) and the run downloads
//
// Each section of the template reads what it needs from the source; a section a source has no data for is hidden or
// says so in one line. Rule P (PLAN §2.5): every readiness, PQC-class and severity total of a run comes from /posture
// (model.ts runDashboardModel / applyPostureToDistributions), never from counting rows.

import { keepPreviousData, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { toast } from "@/utils/toast";

import {
  getCbomRun,
  getCbomRunAssetPage,
  getCbomRunPosture,
  getCbomRunResults,
  listCbomRuns,
  type CbomFinding,
  type CbomFindingStatus,
  type CbomRun,
  type CbomRunAssetItem,
  type CbomRunAssetPage,
  type CbomRunResults,
  type CbomScanDashboardData,
  type CbomScanMetadata,
} from "@/utils/backend_api";
import { putCbomRemediation, type CbomRemediation, type CbomRemediationItem } from "@/utils/api/cbom_ops";
import type { CbomPostureWithExposure } from "@/utils/api/cbom_outputs";
import { showErrorToast } from "@/utils/error-handler";

import { cbomSourcesKeys, TERMINAL_RUN } from "@/components/cbom/sources/keys";
import { pluralize } from "@/components/cbom/sources/logic";
import { useRunRemediation } from "@/components/cbom/sources/WavesControls";

import {
  DEFAULT_FILTERS,
  filtersToParams,
  isActiveRunStatus,
  isNotFoundStatus,
  needsRunRemediationList,
  resultsPollInterval,
  riskScoreRows,
  runDashboardModel,
  runNodes,
  runPollInterval,
  runSectionPlan,
  runSources,
  statusRequestBodies,
  type ResultsState,
  type RunDashboardModel,
  type RunSectionId,
  type RunTableFilters,
  type SectionView,
} from "./model";
import type { DialogSubject } from "./RunFindingDialog";

function httpStatus(err: unknown): number | undefined {
  return (err as { response?: { status?: number } } | null)?.response?.status;
}

/** Query key of /runs/{id}/results: under the run's key, so invalidating ["cbom-sources", team] refreshes it. */
export const runResultsKey = (teamId: number, runId: number) => [...cbomSourcesKeys.run(teamId, runId), "results"] as const;

// ---------------------------------------------------------------------------- code scan

/** A code scan: the props the code page has always passed (GET /{t}/cbom/scan/{id}). */
export interface CodeScanSource {
  kind: "scan";
  data: unknown;
  conversationId?: number;
  teamId?: string;
  dashboard?: CbomScanDashboardData | null;
  findings?: CbomFinding[] | null;
  scanMetadata?: CbomScanMetadata | Record<string, unknown> | null;
  integrationSettings?: Record<string, unknown> | null;
  onIntegrationSettingsUpdated?: () => void;
  onFindingsUpdated?: () => void;
  backHref?: string;
}

export function codeScanSource(props: Omit<CodeScanSource, "kind">): CodeScanSource {
  return { kind: "scan", ...props };
}

// ---------------------------------------------------------------------------- Sources run

export interface SourcesRunSource {
  kind: "run";
  teamId: number;
  runId: number;
  state: "loading" | "not_found" | "error" | "ready";
  run: CbomRun | undefined;
  active: boolean;
  now: number;
  canCompare: boolean;
  sources: { id: number | null; name: string }[];
  nodes: string[];
  /** /results (W2): dashboard, distributions, compliance, certificates, provenance (+ parity: graph, roll-ups) */
  results: CbomRunResults | null;
  resultsState: ResultsState;
  posture: CbomPostureWithExposure | null;
  plan: Record<RunSectionId, SectionView>;
  dashboardModel: RunDashboardModel;
  riskRows: CbomFinding[];
  /** the findings table: one server page, its filters and selection */
  page: CbomRunAssetPage | undefined;
  pageLoading: boolean;
  pageError: unknown;
  refetchPage: () => void;
  filters: RunTableFilters;
  onFilters: (patch: Partial<RunTableFilters>) => void;
  selection: Map<number, string>;
  setSelection: (next: Map<number, string>) => void;
  setStatus: (keys: string[], status: CbomFindingStatus) => void;
  statusPending: boolean;
  /** remediation waves: the run plan (older backend, or a finished run's chips) */
  waves: { data: CbomRemediation | undefined; loading: boolean; wanted: boolean };
  waveOf: (item: CbomRunAssetItem) => CbomRemediationItem | undefined;
  /** the finding dialog and the Compare dialog */
  dialog: DialogSubject | null;
  setDialog: (d: DialogSubject | null) => void;
  openAsset: (assetId: number, label?: string) => void;
  compareOpen: boolean;
  setCompareOpen: (open: boolean) => void;
  compareRuns: { id: number; created_at: string | null }[];
}

export type ResultsSource = CodeScanSource | SourcesRunSource;

export function useSourcesRunSource(teamId: number, runId: number, { initialView = "findings", onViewChange }: {
  initialView?: "findings" | "all";
  onViewChange?: (view: "findings" | "all") => void;
} = {}): SourcesRunSource {
  const queryClient = useQueryClient();
  const [filters, setFilters] = useState<RunTableFilters>({ ...DEFAULT_FILTERS, view: initialView });
  const [selection, setSelection] = useState<Map<number, string>>(new Map());
  const [dialog, setDialog] = useState<DialogSubject | null>(null);
  const [compareOpen, setCompareOpen] = useState(false);
  const [now, setNow] = useState(() => Date.now());

  // the run (jobs, status, credits); a 4xx is an answer (no retry) and any error stops the polling
  const runQ = useQuery({
    queryKey: cbomSourcesKeys.run(teamId, runId),
    queryFn: () => getCbomRun(teamId, runId),
    retry: (count, err) => (httpStatus(err) ?? 500) >= 500 && count < 1,
    refetchInterval: (query) => runPollInterval(query.state.data?.status, !!query.state.error && !query.state.data),
    refetchIntervalInBackground: false,
  });
  const run = runQ.data;
  const active = isActiveRunStatus(run?.status);

  // when the run finishes, every live section is read once more (they all sit under the run's query key)
  const wasActive = useRef(active);
  useEffect(() => {
    if (wasActive.current && !active && run) {
      queryClient.invalidateQueries({ queryKey: cbomSourcesKeys.run(teamId, runId) });
      queryClient.invalidateQueries({ queryKey: ["cbom-results-list", teamId] });
    }
    wasActive.current = active;
  }, [active, run, queryClient, teamId, runId]);

  useEffect(() => {
    if (!active) return;
    const t = setInterval(() => setNow(Date.now()), 10_000);
    return () => clearInterval(t);
  }, [active]);

  // the findings table page (server-side filters and paging); live every 8 s while the run is active
  const params = filtersToParams(filters);
  const assetsQ = useQuery({
    queryKey: cbomSourcesKeys.runAssets(teamId, runId, JSON.stringify(params)),
    queryFn: () => getCbomRunAssetPage(teamId, runId, params),
    enabled: !!run,
    retry: 1,
    placeholderData: keepPreviousData,
    refetchInterval: active ? 8000 : false,
    refetchIntervalInBackground: false,
  });
  const page = assetsQ.data;

  // /results: every 30 s for an active run of ≤ 5,000 assets, else once and again when it finishes; 5 s while computing
  const resultsQ = useQuery({
    queryKey: runResultsKey(teamId, runId),
    queryFn: () => getCbomRunResults(teamId, runId),
    enabled: !!run,
    retry: (count, err) => (httpStatus(err) ?? 500) >= 500 && count < 1,
    refetchInterval: (query) => {
      if (query.state.error) return false;
      if (query.state.data?.state === "computing") return 5000;
      return resultsPollInterval(active, page?.all_total);
    },
    refetchIntervalInBackground: false,
  });
  const resultsState: ResultsState = resultsQ.data
    ? { kind: "ok", data: resultsQ.data }
    : resultsQ.isError
      ? httpStatus(resultsQ.error) === 404 ? { kind: "missing" } : { kind: "error" }
      : { kind: "loading" };
  const results = resultsQ.data ?? null;

  // /posture: the same query (key and fetcher) RunPostureCard uses, so both read one cache entry
  const postureQ = useQuery({
    queryKey: cbomSourcesKeys.runPosture(teamId, runId),
    queryFn: async () => (await getCbomRunPosture(teamId, runId)) as unknown as CbomPostureWithExposure,
    enabled: !!run,
    retry: 1,
    refetchInterval: active ? 15000 : false,
    refetchIntervalInBackground: false,
  });
  const posture = postureQ.data ?? null;

  // the whole-run wave plan: only for an older backend (rows without wave / key) or once for a finished run's chips
  const wantRemediation = !!run && needsRunRemediationList(page, active);
  const waves = useRunRemediation(teamId, runId, active && wantRemediation, wantRemediation);
  const waveOf = useCallback((item: CbomRunAssetItem) => waves.byAsset.get(item.id), [waves.byAsset]);

  const runsQ = useQuery({ queryKey: cbomSourcesKeys.runs(teamId), queryFn: () => listCbomRuns(teamId), enabled: compareOpen, retry: 1 });

  const statusMutation = useMutation({
    mutationFn: async ({ keys, status }: { keys: string[]; status: CbomFindingStatus }) => {
      let updated = 0;
      try {
        for (const body of statusRequestBodies(runId, keys, status)) updated += (await putCbomRemediation(teamId, body)).updated;
      } catch (err) {
        throw Object.assign(err instanceof Error ? err : new Error(String(err)), { updatedBeforeError: updated });
      }
      return { updated, status };
    },
    onSuccess: ({ updated }) => {
      toast.success(`Updated ${pluralize(updated, "finding")}`);
      setSelection(new Map());
    },
    onError: (err) => {
      const done = (err as { updatedBeforeError?: number }).updatedBeforeError ?? 0;
      showErrorToast(err, done > 0 ? `${pluralize(done, "finding")} updated, then an error stopped the rest` : "Error updating finding status");
    },
    onSettled: () => {
      queryClient.invalidateQueries({ queryKey: cbomSourcesKeys.all(teamId) });
      queryClient.invalidateQueries({ queryKey: ["cbom-results-list", teamId] });
    },
  });

  const onFilters = useCallback((patch: Partial<RunTableFilters>) => {
    if (patch.view && patch.view !== filters.view) onViewChange?.(patch.view);
    setFilters((f) => ({ ...f, ...patch, page: patch.page ?? 1 }));
  }, [filters.view, onViewChange]);

  const plan = runSectionPlan({ results: resultsState, posture });
  const dashboardModel = useMemo(() => runDashboardModel(results?.dashboard, posture), [results?.dashboard, posture]);
  // the per-finding risk chart plots the API's 0-10 score of the rows on this table page (and is titled so)
  const riskRows = useMemo(() => riskScoreRows(page?.items ?? []) as unknown as CbomFinding[], [page?.items]);

  const state: SourcesRunSource["state"] = runQ.isLoading
    ? "loading"
    : runQ.isError && !run
      ? isNotFoundStatus(httpStatus(runQ.error)) ? "not_found" : "error"
      : run ? "ready" : "loading";

  return {
    kind: "run",
    teamId,
    runId,
    state,
    run,
    active,
    now,
    canCompare: !!run && TERMINAL_RUN.has(run.status),
    sources: run ? runSources(run, results?.provenance) : [],
    nodes: run ? runNodes(run, results?.provenance) : [],
    results,
    resultsState,
    posture,
    plan,
    dashboardModel,
    riskRows,
    page,
    pageLoading: assetsQ.isLoading,
    pageError: assetsQ.error,
    refetchPage: () => void assetsQ.refetch(),
    filters,
    onFilters,
    selection,
    setSelection,
    setStatus: (keys, status) => statusMutation.mutate({ keys, status }),
    statusPending: statusMutation.isPending,
    waves: { data: waves.query.data, loading: wantRemediation && waves.query.isLoading, wanted: wantRemediation },
    waveOf,
    dialog,
    setDialog,
    openAsset: (assetId, label) => {
      const item = page?.items.find((i) => i.id === assetId);
      setDialog(item ? { item } : { assetId, label });
    },
    compareOpen,
    setCompareOpen,
    compareRuns: (runsQ.data?.runs ?? []).map((r) => ({ id: r.id, created_at: r.created_at })),
  };
}
