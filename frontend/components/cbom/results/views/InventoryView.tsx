"use client";

// Inventory & certificates (results redesign 08-A + 10-A + 11-A): the crypto inventory charts (algorithms, weak
// crypto, PQC readiness, asset types, certificates and keys, protocols, the dependency graph), the dashboard charts but
// their KPI tiles (those are on the summary), the "As of" line, the orphaned and unmanaged certificates, the algorithm
// family × source heat-map with the certificate calendar, and each section's one-line note when the run has no data.

import { CbomCryptoCharts } from "@/components/cbom/CbomCryptoCharts";
import { RunInsights } from "@/components/cbom/sources/ChangesPanel";

import { RunCertificatesSection, RunDashboardSection, SectionNote } from "../RunSections";
import type { RunViewCtx } from "./types";

/** CbomCryptoCharts parts of this view (the quantum-vulnerable list and roadmap are the migration view's, the
 * compliance matrix the compliance view's). */
export const INVENTORY_CHART_PARTS = ["algorithms", "weak", "readiness", "assetTypes", "certExpiry", "protocols", "graph"];
/** CbomDashboardCharts parts of this view: all but the KPI tiles (SummaryKpis). */
export const INVENTORY_DASHBOARD_PARTS = ["progress", "owasp", "risk", "controls", "algoTypes", "strength", "quantum", "riskScores", "metrics"];

export function InventoryView({ ctx }: { ctx: RunViewCtx }) {
  const { run } = ctx;
  return (
    <div className="space-y-6 min-w-0">
      {ctx.distributions && (
        <CbomCryptoCharts
          parts={INVENTORY_CHART_PARTS}
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
      )}
      {/* one line where the run has no data for a chart: distributions from /results, the dependency graph from /parity */}
      {run.plan.cryptoCharts.note && <SectionNote testId="run-crypto-charts-note">{run.plan.cryptoCharts.note}</SectionNote>}
      {ctx.parityNotes?.graph && <SectionNote testId="run-graph-note">{ctx.parityNotes.graph}</SectionNote>}
      <RunDashboardSection view={run.plan.dashboard} model={run.dashboardModel} riskRows={run.riskRows}
                           pageRows={run.page?.items.length ?? 0} results={run.results} parts={INVENTORY_DASHBOARD_PARTS} />
      <RunCertificatesSection view={run.plan.certificates} results={run.results} onOpenAsset={(id) => run.openAsset(id)} />
      {/* Algorithm family x source (or asset type) and the certificate calendar, from the run API */}
      <RunInsights teamId={run.teamId} runId={run.runId} active={run.active} />
    </div>
  );
}
