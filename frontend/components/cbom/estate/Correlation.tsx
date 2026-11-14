"use client";

// The drawer section "Ownership and code" (engine step 3): owners, applications, data classification of the systems
// the asset sits in, and the SBOM / code scan components that use it. Renders nothing on an older backend.
import Link from "next/link";

import { classificationText, gaps, linkText, scanHref, type Correlation } from "./correlation";

export function CorrelationSection({ teamId, correlation }: { teamId?: number | string; correlation: Correlation | null | undefined }) {
  if (correlation === undefined) return null;
  return (
    <div className="rounded-md border border-zinc-200 dark:border-zinc-700 p-3 space-y-2 min-w-0" data-testid="asset-correlation"
         data-estate-key={correlation?.estate_key ?? ""}>
      <p className="text-xs font-semibold text-zinc-800 dark:text-zinc-200">Ownership and code that uses it</p>
      {correlation === null ? (
        <p className="text-xs text-zinc-500 dark:text-zinc-400">
          Not in the team estate yet: it appears a few minutes after its run finishes.
        </p>
      ) : (
        <>
          <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 text-xs">
            <dt className="text-zinc-500">Owner</dt>
            <dd data-testid="asset-correlation-owners" className="break-words">{correlation.owners.join(", ") || "Not set"}</dd>
            <dt className="text-zinc-500">Application</dt>
            <dd className="break-words">{correlation.applications.join(", ") || "Not set"}</dd>
            <dt className="text-zinc-500">Data classification</dt>
            <dd data-testid="asset-correlation-class" data-class={correlation.data_classification ?? ""}>{classificationText(correlation)}</dd>
          </dl>
          {gaps(correlation).map((g) => <p key={g} className="text-xs text-amber-700 dark:text-amber-400">{g}</p>)}
          {correlation.links.length === 0 ? (
            <p className="text-xs text-zinc-500 dark:text-zinc-400">No SBOM or code scan lists it.</p>
          ) : (
            <ul className="space-y-0.5 text-xs" data-testid="asset-correlation-links">
              {correlation.links.map((l) => (
                <li key={`${l.kind}-${l.scan_id}-${l.component}`} className="break-words">
                  {teamId != null ? <Link className="text-blue-600 dark:text-blue-400" href={scanHref(teamId, l)}>{linkText(l)}</Link> : linkText(l)}
                </li>
              ))}
            </ul>
          )}
        </>
      )}
    </div>
  );
}
