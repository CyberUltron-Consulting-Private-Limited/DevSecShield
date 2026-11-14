"use client";

// The results page of a CBOM Sources run (CB-38 PR-1c): the code-scan results page (components/CbomResults.tsx) in
// the same order and look, fed by the run APIs, plus the run views of the architecture diagram.
//
//   S0 header · S1 what was covered · S2 Results / Ticketing tabs · S3 metadata cards · S4 post-quantum and risk
//   posture · S5 algorithm family × source / asset type + certificate calendar · S6 orphaned / unmanaged certificates ·
//   S7 crypto charts · S8 changes · S9 remediation waves · S10 compliance mapping · S11 dashboard charts ·
//   S12 findings table · S13 top cryptographic risks · S14 finding dialog
//
// Rule P (PLAN §2.5): readiness, PQC classes, quantum-vulnerable and severity totals come from /posture (and the
// /results dashboard W2 builds from it); nothing on this page counts table rows for a total.

import { keepPreviousData, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { BarChart3 } from "lucide-react";
import { toast } from "@/utils/toast";

import {
  getCbomRun,
  getCbomRunAssetPage,
  getCbomRunPosture,
  getCbomRunResults,
  listCbomRuns,
  type CbomFinding,
  type CbomFindingStatus,
  type CbomRunAssetItem,
} from "@/utils/backend_api";
import { putCbomRemediation } from "@/utils/api/cbom_ops";
import type { CbomPostureWithExposure } from "@/utils/api/cbom_outputs";
import { showErrorToast } from "@/utils/error-handler";

import { CompareDialog, RunInsights } from "@/components/cbom/sources/ChangesPanel";
import { cbomSourcesKeys, TERMINAL_RUN } from "@/components/cbom/sources/keys";
import { pluralize } from "@/components/cbom/sources/logic";
import { RunPostureCard } from "@/components/cbom/sources/RunPosture";
import { useRunRemediation } from "@/components/cbom/sources/WavesControls";

import {
  DEFAULT_FILTERS,
  endpointsProbed,
  filtersToParams,
  isActiveRunStatus,
  isNotFoundStatus,
  needsRunRemediationList,
  resultsPollInterval,
  riskScoreRows,
  runPollInterval,
  runDashboardModel,
  runDurationSeconds,
  runNodes,
  runSectionPlan,
  runSources,
  statusRequestBodies,
  type ResultsState,
  type RunTableFilters,
} from "./model";
import { RunFindingDialog, type DialogSubject } from "./RunFindingDialog";
import { RunFindingsTable } from "./RunFindingsTable";
import { RunHeader } from "./RunHeader";
import {
  PostureDistributions,
  RunCertificatesSection,
  RunChangesSection,
  RunComplianceSection,
  RunCoverageSection,
  RunCryptoChartsSection,
  RunDashboardSection,
  RunMetaCards,
  RunTopRisks,
  RunWavesSection,
} from "./RunSections";

function httpStatus(err: unknown): number | undefined {
  return (err as { response?: { status?: number } } | null)?.response?.status;
}

/** Query key of /runs/{id}/results: under the run's key, so invalidating ["cbom-sources", team] refreshes it. */
export const runResultsKey = (teamId: number, runId: number) => [...cbomSourcesKeys.run(teamId, runId), "results"] as const;

export function RunNotFound({ teamId }: { teamId: number }) {
  return (
    <div className="flex min-h-[60vh] w-full flex-col items-center justify-center gap-3 px-6 text-center" data-testid="run-results-not-found">
      <p className="text-lg font-semibold text-zinc-900 dark:text-white">Run not found</p>
      <p className="text-sm text-zinc-600 dark:text-zinc-400 max-w-md">
        This CBOM Sources run does not exist or belongs to another team.
      </p>
      <a href={`/${teamId}/cbom`} className="text-sm text-blue-600 dark:text-blue-400 hover:underline">Back to CBOM scans</a>
    </div>
  );
}

export default function RunResultsView({ teamId, runId, initialView = "findings", onViewChange }: {
  teamId: number;
  runId: number;
  initialView?: "findings" | "all";
  /** called when the Findings / All assets toggle changes (the page mirrors it in ?view=) */
  onViewChange?: (view: "findings" | "all") => void;
}) {
  const queryClient = useQueryClient();
  const [filters, setFilters] = useState<RunTableFilters>({ ...DEFAULT_FILTERS, view: initialView });
  const [selection, setSelection] = useState<Map<number, string>>(new Map());
  const [dialog, setDialog] = useState<DialogSubject | null>(null);
  const [compareOpen, setCompareOpen] = useState(false);
  const [now, setNow] = useState(() => Date.now());

  // -- the run (jobs, status, credits); 404 = another team's or a deleted run
  const runQ = useQuery({
    queryKey: cbomSourcesKeys.run(teamId, runId),
    queryFn: () => getCbomRun(teamId, runId),
    // a 4xx is an answer (not found, not allowed, bad id): no retry; any error stops the polling (m1)
    retry: (count, err) => (httpStatus(err) ?? 500) >= 500 && count < 1,
    refetchInterval: (query) => runPollInterval(query.state.data?.status, !!query.state.error && !query.state.data),
    refetchIntervalInBackground: false,
  });
  const run = runQ.data;
  const active = isActiveRunStatus(run?.status);

  // When the run finishes, every live section is read once more (polling stops with `active`): posture, /results,
  // the table, the heat-map and the wave plan all sit under the run's query key.
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

  // -- the findings table page (server-side filters and paging); live every 8 s while the run is active
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

  // -- /results (W2): dashboard, distributions, compliance, certificates, provenance. 404 = older backend.
  // Recomputed per request while the run is active: every 30 s for runs of ≤ 5,000 assets, else once (and again when
  // the run finishes); every 5 s while a large run's summary says "computing".
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

  // -- /posture: the same query (key and fetcher) RunPostureCard uses, so the cache is shared and both agree.
  const postureQ = useQuery({
    queryKey: cbomSourcesKeys.runPosture(teamId, runId),
    queryFn: async () => (await getCbomRunPosture(teamId, runId)) as unknown as CbomPostureWithExposure,
    enabled: !!run,
    retry: 1,
    refetchInterval: active ? 15000 : false,
    refetchIntervalInBackground: false,
  });
  const posture = postureQ.data ?? null;

  // -- waves: the whole-run plan is loaded only for an older backend (its rows carry no wave or key) and, once, for
  // the S9 chips of a finished run; a newer backend's rows carry their own page-scoped wave.
  const wantRemediation = !!run && needsRunRemediationList(page, active);
  const waves = useRunRemediation(teamId, runId, active && wantRemediation, wantRemediation);
  const waveOf = useCallback((item: CbomRunAssetItem) => waves.byAsset.get(item.id), [waves.byAsset]);

  // -- runs for Compare… (loaded when the dialog opens)
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
  // The per-finding risk chart plots the API's 0-10 score of the rows on this table page (and is titled so, m9).
  const riskRows = useMemo(() => riskScoreRows(page?.items ?? []) as unknown as CbomFinding[], [page?.items]);

  if (runQ.isLoading) {
    return <div className="container mx-auto p-6"><p className="text-sm text-zinc-500" data-testid="run-results-loading">Loading the run…</p></div>;
  }
  if (runQ.isError && !run) {
    if (isNotFoundStatus(httpStatus(runQ.error))) return <RunNotFound teamId={teamId} />;
    return (
      <div className="container mx-auto p-6" role="alert">
        <p className="text-zinc-600 dark:text-zinc-400">Error fetching the run results. Please try again later.</p>
      </div>
    );
  }
  if (!run) return null;

  const sources = runSources(run, results?.provenance);
  const nodes = runNodes(run, results?.provenance);
  const canCompare = TERMINAL_RUN.has(run.status);
  const openAsset = (assetId: number, label?: string) => {
    const item = page?.items.find((i) => i.id === assetId);
    setDialog(item ? { item } : { assetId, label });
  };

  return (
    <div className="container mx-auto p-4 sm:p-6 space-y-6 min-w-0" data-testid="run-results-page-root">
      {/* S0 */}
      <RunHeader teamId={teamId} run={run} sources={sources} assetTotal={page?.all_total ?? null}
                 canCompare={canCompare} onCompare={() => setCompareOpen(true)} />

      {/* S1 */}
      <RunCoverageSection run={run} targets={page?.targets ?? null} provenance={results?.provenance} />

      {/* S2: Results / Ticketing tabs. Ticketing mount point (lane W6): when components/cbom/results/RunTicketingTab.tsx
          exists, set RUN_TICKETING_TAB_AVAILABLE in model.ts and render <RunTicketingTab teamId={teamId} runId={runId} />
          as the second tab, exactly like the code page's "Ticketing integrations" tab. Until then: Results only. */}
      <div className="flex gap-2 border-b border-zinc-200 dark:border-zinc-800" role="tablist" data-testid="run-results-tabs">
        <button type="button" role="tab" aria-selected className="px-4 py-2 font-medium text-sm border-b-2 border-blue-600 text-blue-600 dark:text-blue-400">
          <span className="flex items-center gap-2"><BarChart3 className="w-4 h-4" /> Results</span>
        </button>
      </div>

      {/* S3 */}
      <RunMetaCards sources={sources.length} nodes={nodes} endpoints={endpointsProbed(results)} duration={runDurationSeconds(run, now)} />

      {/* S4: posture card unchanged (ids run-posture, posture-*, mosca-*) + CB-19 / CB-24 distributions when present */}
      <div className="space-y-3" data-testid="run-section-posture">
        <RunPostureCard teamId={teamId} runId={runId} active={active} />
        <PostureDistributions posture={posture as unknown as Record<string, unknown> | null} />
      </div>

      {/* S5 (ids run-insights, run-heatmap, run-cert-calendar) */}
      <RunInsights teamId={teamId} runId={runId} active={active} />

      {/* S6 */}
      <RunCertificatesSection view={plan.certificates} results={results} onOpenAsset={(id) => openAsset(id)} />

      {/* S7 */}
      <RunCryptoChartsSection view={plan.cryptoCharts} results={results} posture={posture} />

      {/* S8 */}
      <RunChangesSection teamId={teamId} run={run} canCompare={canCompare} onCompare={() => setCompareOpen(true)} />

      {/* S9 */}
      <RunWavesSection byWave={waves.query.data?.by_wave} labels={waves.query.data?.labels} loading={wantRemediation && waves.query.isLoading}
                       deferred={!wantRemediation && active} selected={selection.size} />

      {/* S10 */}
      <RunComplianceSection view={plan.compliance} results={results} posture={posture} />

      {/* S11 */}
      <RunDashboardSection view={plan.dashboard} model={dashboardModel} riskRows={riskRows} pageRows={page?.items.length ?? 0} results={results} />

      {/* S12 */}
      <RunFindingsTable
        teamId={teamId}
        runId={runId}
        active={active}
        page={page}
        isLoading={assetsQ.isLoading}
        error={assetsQ.error}
        onRetry={() => assetsQ.refetch()}
        filters={filters}
        onFilters={onFilters}
        sources={sources}
        waveOf={waveOf}
        selection={selection}
        onSelection={setSelection}
        onOpenDetails={(item) => setDialog({ item })}
        onSetStatus={(keys, status) => statusMutation.mutate({ keys, status })}
        statusPending={statusMutation.isPending}
      />

      {/* S13 */}
      {plan.topRisks.show && posture && <RunTopRisks posture={posture} onOpenAsset={(id) => openAsset(id)} />}

      {/* S14 */}
      <RunFindingDialog teamId={teamId} subject={dialog} jobs={run.jobs ?? []} waveOf={waveOf} onClose={() => setDialog(null)} />

      {compareOpen && (
        <CompareDialog teamId={teamId} runId={runId}
                       runs={(runsQ.data?.runs ?? []).map((r) => ({ id: r.id, created_at: r.created_at }))}
                       onClose={() => setCompareOpen(false)} />
      )}
    </div>
  );
}
