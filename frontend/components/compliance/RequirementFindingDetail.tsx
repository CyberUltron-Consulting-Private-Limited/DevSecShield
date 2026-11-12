"use client";

/**
 * Inline finding/issue snippets for posture requirement drilldowns
 * (RBI CSF + CERT-In). Prefer matched findings; fall back to graph aliases.
 */

import {
  filterFindingsByRelatedRefs,
  type RelatedFindingFields,
} from "@/utils/relatedFindingMatch";

const SAMPLE_CAP = 3;
const ALIAS_CAP = 5;

export function RequirementFindingDetail({
  verdict,
  evidence,
  refs,
  findings,
  refAliases,
}: {
  verdict: string;
  evidence?: string;
  refs: string[];
  findings?: RelatedFindingFields[] | null;
  refAliases?: Record<string, string>;
}) {
  const v = (verdict || "").toLowerCase();
  const isGap = v === "fail" || v === "not_bom_evidenceable";
  const isOos = v === "out_of_scope" || v === "na";

  const matched =
    findings != null && refs.length > 0
      ? filterFindingsByRelatedRefs(findings, refs, { aliases: refAliases })
      : [];
  const samples = matched.slice(0, SAMPLE_CAP);

  const aliasLabels: string[] = [];
  if (samples.length === 0 && refs.length > 0 && refAliases) {
    for (const ref of refs) {
      const label = (refAliases[ref] || "").trim();
      if (label && !aliasLabels.includes(label)) {
        aliasLabels.push(label);
        if (aliasLabels.length >= ALIAS_CAP) break;
      }
    }
  }

  return (
    <div className="space-y-1.5" data-testid="requirement-finding-detail">
      {evidence && (
        <div className="text-xs text-zinc-600 dark:text-zinc-400">
          <span className="font-medium text-zinc-700 dark:text-zinc-300">
            {isGap ? "Issue: " : "Why: "}
          </span>
          {evidence}
        </div>
      )}
      {samples.map((f, i) => {
        const title = (f.title || f.component_name || f.name || "").trim();
        const desc = (f.description || "").trim();
        if (!title && !desc) return null;
        return (
          <div
            key={`${f.bom_ref || f.id || title}-${i}`}
            className="text-xs text-zinc-600 dark:text-zinc-400 rounded border border-zinc-100 dark:border-zinc-800 px-2 py-1.5"
            data-testid="requirement-finding-sample"
          >
            {title && (
              <div className="font-medium text-zinc-800 dark:text-zinc-200">
                {title}
              </div>
            )}
            {desc && <div className="mt-0.5">{desc}</div>}
          </div>
        );
      })}
      {aliasLabels.length > 0 && (
        <div className="text-xs text-zinc-500">
          <span className="font-medium text-zinc-700 dark:text-zinc-300">
            Related assets:{" "}
          </span>
          {aliasLabels.join(", ")}
          {refs.length > aliasLabels.length ? "…" : ""}
        </div>
      )}
      {isOos && (findings?.length ?? 0) > 0 && (
        <div className="text-xs text-zinc-500 italic">
          This scan has inventoried findings, but they are not AI models covered
          by this requirement.
        </div>
      )}
    </div>
  );
}

export default RequirementFindingDetail;
