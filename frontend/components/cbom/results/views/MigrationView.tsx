"use client";

// PQC migration plan (results redesign 09-A): the quantum-vulnerable algorithms grouped with their distinct fixes,
// the migration roadmap against CNSA 2.0 and the recommended replacements (CbomCryptoCharts' "qv" and "roadmap"
// parts); an item opens the run's finding dialog for its asset.

import { CbomCryptoCharts } from "@/components/cbom/CbomCryptoCharts";

import { SectionNote } from "../RunSections";
import type { RunViewCtx } from "./types";

export const MIGRATION_CHART_PARTS = ["qv", "roadmap"];

export function MigrationView({ ctx }: { ctx: RunViewCtx }) {
  const { run } = ctx;
  return (
    <div className="space-y-6 min-w-0">
      {ctx.distributions && (
        <CbomCryptoCharts
          parts={MIGRATION_CHART_PARTS}
          distributions={ctx.distributions}
          findings={[]}
          inventory={[]}
          onOpenFinding={ctx.onOpenPqcFinding}
          showCodeHeatmap={false}
          readinessScope="run"
        />
      )}
      {run.plan.cryptoCharts.note && <SectionNote testId="run-migration-note">{run.plan.cryptoCharts.note}</SectionNote>}
    </div>
  );
}
