// What each remediation wave holds and why one can be empty (issue #271), shared by the run page's "Remediation waves"
// section and the code scan's (staging QA round 4, finding D): one legend for the one results template. Counts are the
// wave plan's (by_wave), never recounted; while the plan is not loaded the legend gives the rules only.

import { waveLegend } from "./readinessExplain";

export function WaveLegend({ byWave, rules, scope = "run" }: {
  byWave: Record<string, number> | null | undefined;
  rules?: Record<string, string>;
  /** "code": worded for a code scan (no exposure is known there, so the rules never suggest wave 1) */
  scope?: "run" | "code";
}) {
  const rows = waveLegend(byWave, rules, scope);
  return (
    <details className="text-xs text-zinc-600 dark:text-zinc-400" data-testid="run-wave-legend" open>
      <summary className="cursor-pointer text-zinc-700 dark:text-zinc-300">What goes in each wave</summary>
      <ul className="mt-1.5 space-y-1">
        {rows.map((r) => (
          <li key={r.key} data-testid={`run-wave-legend-${r.key}`} data-count={byWave ? r.count : undefined}>
            <span className="font-semibold text-zinc-800 dark:text-zinc-200">{r.label}</span>
            {byWave ? <span className="text-zinc-500"> ({r.count})</span> : null}: {r.rule}.
            {byWave && r.empty ? <span className="text-zinc-500"> {r.empty}</span> : null}
          </li>
        ))}
      </ul>
      <p className="mt-1">An asset gets the first wave whose rule it meets; you can move it to another wave in the table below.</p>
    </details>
  );
}
