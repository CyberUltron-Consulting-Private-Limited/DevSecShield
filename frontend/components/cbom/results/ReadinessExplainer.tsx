"use client";

// Issue #271: "PQC readiness N%" in plain words, under the run's posture card: what "judged" means, the formula with this
// run's numbers, how symmetric assets are treated, which assets are left out and why, and the top actions that would
// raise the score, each with a link that filters the findings table to those assets. Every number is the API's
// (posture.readiness_basis / pqc_classes / readiness_actions / readiness_excluded; Rule P): see readinessExplain.ts.

import { InfoTip } from "@/components/ui/info-tip";

import { readinessExplanation, type ReadinessPostureLike } from "./readinessExplain";

export function ReadinessExplainer({ posture, onShowAssets }: {
  posture: ReadinessPostureLike | null | undefined;
  /** filter the findings table below to the quantum-vulnerable assets (of one asset type when given) */
  onShowAssets?: (assetType?: string) => void;
}) {
  if (!posture) return null;
  const e = readinessExplanation(posture);
  const link = "cursor-pointer text-blue-600 hover:underline dark:text-blue-400";
  return (
    <div className="space-y-2 rounded-lg border border-zinc-200 p-4 text-xs text-zinc-700 dark:border-zinc-800 dark:text-zinc-300"
         data-testid="pqc-readiness-explained">
      <p className="text-sm font-medium text-zinc-900 dark:text-white">
        What PQC readiness {e.value} means <InfoTip id="cbom.run.readiness" />
      </p>
      <p data-testid="pqc-readiness-formula"><span className="font-semibold">Formula:</span> {e.formula}</p>
      {e.judged && <p data-testid="pqc-readiness-judged">{e.judged}</p>}
      {e.counts.length > 0 && (
        <ul className="list-disc space-y-0.5 pl-5" data-testid="pqc-readiness-counts">
          {e.counts.map((c) => <li key={c}>{c}</li>)}
        </ul>
      )}
      {e.excluded.length > 0 && (
        <ul className="list-disc space-y-0.5 pl-5 text-zinc-600 dark:text-zinc-400" data-testid="pqc-readiness-excluded">
          {e.excluded.map((c) => <li key={c}>{c}</li>)}
        </ul>
      )}
      <p className="text-zinc-600 dark:text-zinc-400" data-testid="pqc-readiness-symmetric">{e.symmetric}</p>
      <p className="text-zinc-600 dark:text-zinc-400">{e.target}</p>
      {e.actions.length > 0 && (
        <div data-testid="pqc-readiness-actions">
          <p className="font-medium text-zinc-900 dark:text-white">
            What would raise it <InfoTip id="cbom.run.readiness_actions" />
          </p>
          <ol className="mt-1 list-decimal space-y-1.5 pl-5">
            {e.actions.map((a) => (
              <li key={a.key} data-testid="pqc-readiness-action" data-assets={a.assets}>
                <span className="font-semibold">{a.text}</span>
                {a.effect && <span className="text-emerald-700 dark:text-emerald-400"> · {a.effect}</span>}
                {a.fix && <span className="block text-zinc-600 dark:text-zinc-400 [overflow-wrap:anywhere]">{a.fix}</span>}
                {onShowAssets && (
                  <button type="button" className={link} onClick={() => onShowAssets(a.assetType)}
                          data-testid="pqc-readiness-action-show">
                    Show these {a.assets}
                  </button>
                )}
              </li>
            ))}
          </ol>
        </div>
      )}
      {onShowAssets && e.vulnerable > 0 && (
        <button type="button" className={link} onClick={() => onShowAssets()} data-testid="pqc-readiness-show-vulnerable">
          Show the {e.vulnerable} quantum-vulnerable assets in the findings table
        </button>
      )}
    </div>
  );
}
