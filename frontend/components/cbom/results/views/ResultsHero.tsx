"use client";

// The run results header (results redesign 01-B), on every view: Back, the code scan's title ("CBOM Scan Results",
// test id cbom-results-title), the run's status line (RunHeaderMeta: status, start / finish, credits, linked scan,
// sources, the live-run note), three headline figures from the run posture, every header action (RunHeaderActions:
// CycloneDX JSON / XML / OSCAL, the deliverables, Verify file…, Compare…, Open in CBOM Sources), the Explanations
// drawer button and, on every view but
// Collection (whose jobs card carries it), the lab-mode note.

import { ArrowLeft, ShieldCheck } from "lucide-react";

import { Button } from "@/components/ui/button";
import { InfoTip } from "@/components/ui/info-tip";
import type { InfoTipId } from "@/content/infotips";
import type { CbomJobTargets, CbomRun } from "@/utils/backend_api";
import type { CbomPostureWithExposure } from "@/utils/api/cbom_outputs";
import { LabModeBanner } from "@/components/cbom/sources/LabModeBanner";
import { ExplanationsButton } from "@/components/ui/info-tip-drawer";

import { pqcGaugeCopy } from "../readinessExplain";
import { RunHeaderActions, RunHeaderMeta } from "../RunSections";

export function heroFigures(posture: CbomPostureWithExposure | null): { key: string; label: string; value: string; tip: InfoTipId; tone: string }[] {
  const p = posture;
  return [
    { key: "ready", label: "PQC ready", value: p ? pqcGaugeCopy("run", p.pqc_readiness_pct, p.readiness_basis).value : "—", tip: "cbom.run.readiness",
      tone: "text-teal-700 dark:text-teal-300" },
    { key: "crit-high", label: "Critical / High", value: p ? `${p.impacts.Critical ?? 0} / ${p.impacts.High ?? 0}` : "—", tip: "cbom.res.severity",
      tone: "text-red-700 dark:text-red-300" },
    { key: "assets", label: "Assets", value: p ? p.assets.toLocaleString() : "—", tip: "cbom.res.kpi.assets", tone: "text-zinc-900 dark:text-white" },
  ];
}

export function ResultsHero({ teamId, run, sources, posture, assetTotal, canCompare, onCompare, onBack, targets, showLabBanner }: {
  teamId: number;
  run: CbomRun;
  sources: { id: number | null; name: string }[];
  posture: CbomPostureWithExposure | null;
  assetTotal: number | null;
  canCompare: boolean;
  onCompare: () => void;
  onBack: (() => void) | null;
  targets: CbomJobTargets[] | null;
  /** false on the Collection view: its jobs card shows the lab-mode note */
  showLabBanner: boolean;
}) {
  return (
    <header className="space-y-4" data-testid="results-hero">
      <div className="grid grid-cols-1 xl:grid-cols-[minmax(0,1.4fr)_minmax(0,1fr)] gap-6 items-start">
        <div className="flex items-start gap-4 min-w-0">
          {onBack && (
            <Button variant="outline" size="icon" aria-label="Back" onClick={onBack} className="cursor-pointer shrink-0">
              <ArrowLeft className="h-4 w-4" />
            </Button>
          )}
          <div className="min-w-0 space-y-2">
            <h1 className="text-3xl font-bold text-zinc-900 dark:text-white flex items-center gap-2" data-testid="cbom-results-title">
              <ShieldCheck className="h-7 w-7 text-blue-600 dark:text-blue-400" />
              CBOM Scan Results
            </h1>
            <div className="flex flex-wrap items-center gap-3 text-sm text-zinc-600 dark:text-zinc-400">
              <RunHeaderMeta teamId={teamId} run={run} sources={sources} />
            </div>
          </div>
        </div>
        <dl className="grid grid-cols-3 gap-3" data-testid="results-hero-figures">
          {heroFigures(posture).map((f) => (
            <div key={f.key} className="rounded-xl border border-zinc-200 bg-zinc-50 p-3 dark:border-zinc-800 dark:bg-zinc-950 min-w-0"
                 data-testid={`results-hero-${f.key}`}>
              <dt className="text-[11px] font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400 flex items-center gap-0.5">
                {f.label} <InfoTip id={f.tip} />
              </dt>
              <dd className={`text-2xl font-bold tabular-nums truncate ${f.tone}`} title={f.value}>{f.value}</dd>
            </div>
          ))}
        </dl>
      </div>
      <div className="flex flex-wrap items-center gap-2">
        <RunHeaderActions teamId={teamId} run={run} assetTotal={assetTotal} canCompare={canCompare} onCompare={onCompare} />
        {/* the page's Explanations drawer (every tip of this view); nothing without its provider */}
        <ExplanationsButton className="h-9" />
      </div>
      {showLabBanner && targets?.some((job) => job.lab_mode) && (
        <LabModeBanner testId="run-lab-mode" detail="An AWS source in this run was read from the deployment's own AWS account." />
      )}
    </header>
  );
}
