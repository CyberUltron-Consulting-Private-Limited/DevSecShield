"use client";

// Remediation waves & changes (results redesign 13-A): the wave plan (chips, legend, the deferred note of an active
// run), the run's changes (the diff against the previous complete run, its drift events, "Compare with another run…")
// and, because the waves card says "Select findings in the table below…", the findings table under them (the only
// view other than the summary that mounts it, so #bom-findings stays unique).

import { RunChangesSection, RunWavesSection } from "../RunSections";
import { RunFindingsTableMount } from "./SummaryView";
import type { RunViewCtx } from "./types";

export function RemediationView({ ctx }: { ctx: RunViewCtx }) {
  const { run } = ctx;
  return (
    <div className="space-y-6 min-w-0">
      <RunWavesSection byWave={run.waves.data?.by_wave} labels={run.waves.data?.labels} rules={run.waves.data?.rules} loading={run.waves.loading}
                       deferred={!run.waves.wanted && run.active} selected={run.selection.size}
                       items={run.waves.data?.items} onOpenAsset={(id) => run.openAsset(id)} />
      {run.run && <RunChangesSection teamId={run.teamId} run={run.run} canCompare={run.canCompare} onCompare={() => run.setCompareOpen(true)} />}
      <RunFindingsTableMount run={run} onOpenDetails={ctx.openFromTable} />
    </div>
  );
}
