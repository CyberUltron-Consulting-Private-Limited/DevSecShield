"use client";

// Run summary (results redesign 02-B): the PQC readiness gauge (the run posture's figure, Rule P), the seven KPI tiles
// the dashboard showed on top of its charts (same labels, values and tips: CbomDashboardCharts' "kpis" part, so the
// inventory view's charts leave them out) and the run's four metadata cards (sources, scan nodes, endpoints, duration).

import type { LucideIcon } from "lucide-react";
import type { ReactNode } from "react";

import { InfoTip } from "@/components/ui/info-tip";
import type { InfoTipId } from "@/content/infotips";
import type { CbomPostureWithExposure } from "@/utils/api/cbom_outputs";
import { KPI_TILES } from "../CbomDashboardCharts";

import { pqcGaugeCopy } from "../readinessExplain";
import type { RunDashboardModel, SectionView } from "../model";
import { SectionNote } from "../RunSections";

export function KpiTile({ label, value, icon: Icon, box, infoId, testId }: {
  label: string; value: ReactNode; icon: LucideIcon; box: string; infoId: InfoTipId; testId: string;
}) {
  return (
    <div className="flex items-center gap-3 rounded-xl border border-zinc-200 bg-white p-4 dark:border-zinc-800 dark:bg-zinc-900 min-w-0" data-testid={testId}>
      <div className={`flex h-10 w-10 shrink-0 items-center justify-center rounded-lg ${box}`}>
        <Icon className="h-5 w-5" />
      </div>
      <div className="min-w-0">
        <p className="text-xs font-medium text-zinc-500 dark:text-zinc-400 flex items-center gap-0.5">
          {label}
          <InfoTip id={infoId} />
        </p>
        <p className="text-lg font-semibold text-zinc-900 dark:text-zinc-100 tabular-nums truncate">{value}</p>
      </div>
    </div>
  );
}

/** The seven tiles, with CbomDashboardCharts' labels, tips and values ("—" until the run's dashboard is there). */
export function kpiTiles(model: RunDashboardModel): { label: string; value: string; icon: LucideIcon; box: string; tip: InfoTipId; key: string }[] {
  const c = model.dashboard?.card_data;
  return KPI_TILES.map((t) => {
    const v = c ? t.value(c) : null;
    return { key: t.key, label: t.label, icon: t.icon, box: t.box, tip: t.tip,
             value: v == null ? "—" : typeof v === "number" ? v.toLocaleString() : v };
  });
}

/** Semicircle gauge of the posture's readiness; a withheld or missing figure draws an empty arc, never 0 %. */
function ReadinessGauge({ posture }: { posture: CbomPostureWithExposure | null }) {
  const copy = pqcGaugeCopy("run", posture?.pqc_readiness_pct ?? null, posture?.readiness_basis);
  const pct = typeof posture?.pqc_readiness_pct === "number" ? Math.max(0, Math.min(100, posture.pqc_readiness_pct)) : null;
  const b = posture?.readiness_basis;
  // the arc: a half circle of radius 80 (length π·80); dasharray draws pct of it
  const L = Math.PI * 80;
  return (
    <div className="flex flex-col items-center justify-center gap-2 rounded-xl border border-zinc-200 bg-white p-4 text-center dark:border-zinc-800 dark:bg-zinc-900 min-w-0"
         data-testid="run-kpi-readiness">
      <svg viewBox="0 0 200 120" className="h-28 w-48" role="img" aria-label={`PQC readiness ${copy.value}`}>
        <path d="M20 110 A80 80 0 0 1 180 110" fill="none" strokeWidth="16" strokeLinecap="round" className="stroke-zinc-200 dark:stroke-zinc-800" />
        {pct != null && pct > 0 && (
          <path d="M20 110 A80 80 0 0 1 180 110" fill="none" strokeWidth="16" strokeLinecap="round" className="stroke-teal-500"
                strokeDasharray={`${(pct / 100) * L} ${L}`} />
        )}
        <text x="100" y="98" textAnchor="middle" fontSize={copy.value.length > 6 ? 22 : 32} fontWeight="700" className="fill-zinc-900 dark:fill-white">
          {copy.value}
        </text>
      </svg>
      <p className="text-sm font-medium text-zinc-900 dark:text-white">PQC readiness <InfoTip id="cbom.run.readiness" /></p>
      <p className="text-xs text-zinc-500 dark:text-zinc-400" data-testid="run-kpi-readiness-basis">
        {copy.withheld ?? (b && pct != null ? `${b.ready} of ${b.judged} judged assets resist a quantum computer` : copy.description)}
      </p>
    </div>
  );
}

export function SummaryKpis({ posture, model, view, meta }: {
  posture: CbomPostureWithExposure | null;
  model: RunDashboardModel;
  /** the dashboard's plan: its note when the run's dashboard is not there */
  view: SectionView;
  /** the run's four metadata cards (RunMetaCards) */
  meta: ReactNode;
}) {
  return (
    <section className="space-y-3 min-w-0" data-testid="run-summary-kpis">
      <h2 className="text-base font-semibold text-zinc-900 dark:text-white">Run summary <InfoTip id="cbom.run.summary" /></h2>
      <div className="grid grid-cols-1 lg:grid-cols-[16rem_minmax(0,1fr)] gap-4">
        <ReadinessGauge posture={posture} />
        <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-3 content-start" data-testid="run-kpi-tiles">
          {kpiTiles(model).map((t) => (
            <KpiTile key={t.key} label={t.label} value={t.value} icon={t.icon} box={t.box} infoId={t.tip} testId={`run-kpi-${t.key}`} />
          ))}
        </div>
      </div>
      {!model.dashboard && view.note && <SectionNote testId="run-kpis-note">{view.note}</SectionNote>}
      {meta}
    </section>
  );
}
