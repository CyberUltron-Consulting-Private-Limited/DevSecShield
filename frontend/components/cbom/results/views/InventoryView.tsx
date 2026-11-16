"use client";

// Inventory & certificates (results redesign 08-A + 10-A + 11-A): the crypto inventory charts (algorithms, weak
// crypto, PQC readiness, asset types, protocols, the dependency graph) and the dashboard charts but their KPI tiles
// (those are on the summary) in one card grid, the "As of" line, the certificates card (expiry list with keys and
// keystores, calendar, orphaned and unmanaged), the algorithm family × source heat-map, and each section's one-line
// note when the run has no data.

import { CbomCryptoCharts } from "@/components/cbom/CbomCryptoCharts";
import { RunInsights } from "@/components/cbom/sources/ChangesPanel";

import { RunDashboardSection, SectionNote } from "../RunSections";
import { CertificatesCard } from "./CertificatesCard";
import type { RunViewCtx } from "./types";

/** CbomCryptoCharts parts of this view (the quantum-vulnerable list and roadmap are the migration view's, the
 * compliance matrix the compliance view's, the certificate expiry list CertificatesCard's). */
export const INVENTORY_CHART_PARTS = ["algorithms", "weak", "readiness", "assetTypes", "protocols", "graph"];
/** CbomDashboardCharts parts of this view: all but the KPI tiles (SummaryKpis). */
export const INVENTORY_DASHBOARD_PARTS = ["progress", "owasp", "risk", "controls", "algoTypes", "strength", "quantum", "riskScores", "metrics"];

export function InventoryView({ ctx }: { ctx: RunViewCtx }) {
  const { run } = ctx;
  return (
    <div className="space-y-6 min-w-0">
      {/* variant "run" renders the graph from its own data when /results has no distributions */}
      <CbomCryptoCharts
        parts={INVENTORY_CHART_PARTS}
        variant="run"
        distributions={ctx.distributions}
        graph={ctx.graph}
        graphCompact={ctx.graphCompact}
        graphExpanded={ctx.graphExpanded}
        compliance={ctx.compliance}
        findings={[]}
        inventory={[]}
        onOpenFinding={ctx.onOpenPqcFinding}
        showCodeHeatmap={false}
        readinessScope="run"
      />
      {/* one line where the run has no data for a chart: distributions from /results, the dependency graph from /parity */}
      {run.plan.cryptoCharts.note && <SectionNote testId="run-crypto-charts-note">{run.plan.cryptoCharts.note}</SectionNote>}
      {ctx.parityNotes?.graph && <SectionNote testId="run-graph-note">{ctx.parityNotes.graph}</SectionNote>}
      <RunDashboardSection view={run.plan.dashboard} model={run.dashboardModel} riskRows={run.riskRows}
                           pageRows={run.page?.items.length ?? 0} results={run.results} parts={INVENTORY_DASHBOARD_PARTS} variant="run" />
      <CertificatesCard teamId={run.teamId} runId={run.runId} active={run.active} distributions={ctx.distributions} graph={ctx.graph}
                        chartsView={run.plan.cryptoCharts} certificatesView={run.plan.certificates} results={run.results}
                        onOpenAsset={(id) => run.openAsset(id)} />
      {/* Algorithm family x source (or asset type), from the run API; the calendar is CertificatesCard's tab */}
      <RunInsights teamId={run.teamId} runId={run.runId} active={run.active} calendar={false} />
    </div>
  );
}
