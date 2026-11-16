"use client";

// The run results summary (results redesign F1, §2): answer first, then drill down. Run status (banner, coverage and
// import notes, the jobs line), the run summary (readiness gauge, KPI tiles, metadata cards), the post-quantum and risk
// posture with its explanation panel, the top cryptographic risks, one tile per detail view, and the findings table.

import { RunFindingsTable } from "../RunFindingsTable";
import { RunMetaCards } from "../RunSections";
import { endpointsProbed, runDurationSeconds } from "../model";
import { readinessDrillFilters } from "../readinessExplain";
import type { SourcesRunSource } from "../source";
import { DrillTiles } from "./DrillTiles";
import { ExplainPanel } from "./ExplainPanel";
import { PostureSummary } from "./PostureSummary";
import { RunStatusBanner } from "./RunStatusBanner";
import { tileFigures } from "./selectors";
import { SummaryKpis } from "./SummaryKpis";
import { TopRisksSummary } from "./TopRisksSummary";
import type { RunViewCtx } from "./types";

/** The run's findings table (#bom-findings): on the summary, and under the remediation waves. */
export function RunFindingsTableMount({ run }: { run: SourcesRunSource }) {
  return (
    <RunFindingsTable
      teamId={run.teamId}
      runId={run.runId}
      active={run.active}
      page={run.page}
      isLoading={run.pageLoading}
      error={run.pageError}
      onRetry={run.refetchPage}
      filters={run.filters}
      onFilters={run.onFilters}
      sources={run.sources}
      waveOf={run.waveOf}
      selection={run.selection}
      onSelection={run.setSelection}
      onOpenDetails={(item) => run.setDialog({ item })}
      onSetStatus={run.setStatus}
      statusPending={run.statusPending}
    />
  );
}

export function SummaryView({ ctx }: { ctx: RunViewCtx }) {
  const { run } = ctx;
  if (!run.run) return null;
  const figures = tileFigures({
    run: run.run,
    posture: run.posture,
    plan: run.plan,
    resultsPending: run.resultsState.kind === "loading",
    dashboardModel: run.dashboardModel,
    distributions: ctx.distributions,
    frameworks: ctx.complianceMapping.frameworks,
    waves: { byWave: run.waves.data?.by_wave, loading: run.waves.loading, deferred: !run.waves.wanted && run.active },
  });
  return (
    <div className="space-y-8 min-w-0" data-testid="results-summary">
      <RunStatusBanner run={run.run} assets={run.posture?.assets ?? null} targets={run.page?.targets ?? null}
                       coverageReport={ctx.coverageReport} importReport={ctx.importReport}
                       onOpenCollection={() => ctx.goSection("collection")} />
      <SummaryKpis posture={run.posture} model={run.dashboardModel} view={run.plan.dashboard}
                   meta={<RunMetaCards sources={run.sources.length} nodes={run.nodes} endpoints={endpointsProbed(run.results)}
                                       duration={runDurationSeconds(run.run, run.now)} />} />
      <div className="space-y-3">
        {/* Post-quantum and risk posture (ids run-posture, posture-*, mosca-*); its explanation (issue #271) under it */}
        <PostureSummary teamId={run.teamId} runId={run.runId} active={run.active} onDrill={ctx.drill}
                        onOpenQuantum={() => ctx.goSection("quantum")} />
        <ExplainPanel posture={run.posture} onShowAssets={(action) => ctx.drill(readinessDrillFilters(action))} />
      </div>
      {/* Top Cryptographic Risks: the posture's ranked risks, once */}
      {run.plan.topRisks.show && run.posture && <TopRisksSummary posture={run.posture} onOpenAsset={(id) => run.openAsset(id)} />}
      <DrillTiles figures={figures} onOpen={(s) => ctx.goSection(s)} />
      <RunFindingsTableMount run={run} />
    </div>
  );
}
