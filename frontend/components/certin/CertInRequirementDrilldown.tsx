"use client";

/**
 * Shared CERT-In posture requirement drilldown — why / how / related assets /
 * attest. Used by CertInLanePosture and CertInRollup.
 */

import { useState } from "react";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import type { AttestHandler } from "@/components/compliance/ComplianceMatrix";
import {
  CERTIN_DIM_LABELS,
  type CertInRequirement,
} from "@/components/certin/certinShared";
import {
  countRelatedFindings,
  type RelatedFindingFields,
} from "@/utils/relatedFindingMatch";

function verdictBadge(v: string) {
  const map: Record<string, string> = {
    pass: "bg-emerald-100 text-emerald-800 dark:bg-emerald-900/30 dark:text-emerald-300",
    pass_with_evidence:
      "bg-teal-100 text-teal-800 dark:bg-teal-900/30 dark:text-teal-300",
    fail: "bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-300",
    out_of_scope:
      "bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-300",
    not_bom_evidenceable:
      "bg-violet-100 text-violet-800 dark:bg-violet-900/30 dark:text-violet-300",
    na: "bg-zinc-100 text-zinc-600 dark:bg-zinc-800 dark:text-zinc-400",
  };
  return (
    <Badge variant="outline" className={map[v] ?? ""}>
      {v.replace(/_/g, " ")}
    </Badge>
  );
}

export function CertInRequirementDrilldown({
  dimKey,
  requirements,
  onClose,
  onAttest,
  onViewFindings,
  findings,
  refAliases,
}: {
  dimKey: string;
  requirements: CertInRequirement[];
  onClose?: () => void;
  onAttest?: AttestHandler;
  onViewFindings?: (refs: string[]) => void;
  /** Persisted findings — required for an honest related-findings count. */
  findings?: RelatedFindingFields[] | null;
  /** bom-ref → label map from ai_bom_graph / cbom_graph nodes. */
  refAliases?: Record<string, string>;
}) {
  const [pending, setPending] = useState<Record<string, string>>({});
  const [busyKey, setBusyKey] = useState<string | null>(null);

  if (requirements.length === 0) return null;

  return (
    <div
      className="mt-4 rounded-lg border border-zinc-200 dark:border-zinc-800"
      data-testid="certin-requirement-drilldown"
    >
      <div className="px-3 py-2 text-sm font-medium border-b border-zinc-200 dark:border-zinc-800 flex items-center justify-between gap-2">
        <span>
          {CERTIN_DIM_LABELS[dimKey] ?? dimKey} — contributing requirements
        </span>
        {onClose && (
          <button
            type="button"
            className="text-xs text-zinc-500 hover:text-zinc-700 dark:hover:text-zinc-300 cursor-pointer"
            onClick={onClose}
          >
            Close
          </button>
        )}
      </div>
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead className="w-28">Verdict</TableHead>
            <TableHead className="w-28">ID</TableHead>
            <TableHead>Requirement</TableHead>
            <TableHead className="w-28">Source</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {requirements.map((r) => {
            const pKey = `${r.framework}:${r.id}`;
            const pendingName = pending[pKey];
            const refs = Array.isArray(r.refs) ? r.refs : [];
            const showAttach =
              !!onAttest &&
              (r.verdict === "not_bom_evidenceable" || r.attestable) &&
              r.verdict !== "pass_with_evidence" &&
              !pendingName;
            return (
              <TableRow key={`${r.framework}-${r.id}`}>
                <TableCell className="align-top">
                  {verdictBadge(r.verdict)}
                </TableCell>
                <TableCell className="font-mono text-xs align-top">
                  {r.id}
                </TableCell>
                <TableCell className="text-sm align-top space-y-1.5">
                  <div className="font-medium text-zinc-900 dark:text-zinc-100">
                    {r.title || r.id}
                  </div>
                  {r.source && (
                    <div className="text-xs text-zinc-500">Cite: {r.source}</div>
                  )}
                  {r.evidence && (
                    <div className="text-xs text-zinc-600 dark:text-zinc-400">
                      <span className="font-medium text-zinc-700 dark:text-zinc-300">
                        Why:{" "}
                      </span>
                      {r.evidence}
                    </div>
                  )}
                  {r.resolve_hint && (
                    <div className="text-xs text-zinc-600 dark:text-zinc-400">
                      <span className="font-medium text-zinc-700 dark:text-zinc-300">
                        How to resolve:{" "}
                      </span>
                      {r.resolve_hint}
                    </div>
                  )}
                  {refs.length > 0 && (() => {
                    const relatedCount =
                      findings != null
                        ? countRelatedFindings(findings, refs, {
                            aliases: refAliases,
                          })
                        : null;
                    // When findings are available, only surface rows that the
                    // findings table can actually show (never claim refs.length).
                    if (relatedCount === 0) return null;
                    return (
                      <div className="flex flex-wrap items-center gap-2 pt-0.5">
                        {relatedCount != null ? (
                          <span
                            className="text-xs text-zinc-500"
                            data-testid="related-findings-count"
                          >
                            {relatedCount} related finding
                            {relatedCount === 1 ? "" : "s"}
                          </span>
                        ) : null}
                        {onViewFindings && (relatedCount == null || relatedCount > 0) && (
                          <Button
                            type="button"
                            variant="outline"
                            size="sm"
                            className="h-7 text-xs cursor-pointer"
                            onClick={() => onViewFindings(refs)}
                          >
                            View related findings
                          </Button>
                        )}
                      </div>
                    );
                  })()}
                  {pendingName && (
                    <div className="text-xs text-teal-600 dark:text-teal-400">
                      attested: {pendingName}
                      {busyKey === pKey
                        ? " (uploading…)"
                        : " (pending re-evaluation)"}
                    </div>
                  )}
                  {showAttach && (
                    <label className="mt-1 inline-flex cursor-pointer items-center gap-1 text-xs text-violet-600 dark:text-violet-400 hover:underline">
                      <input
                        type="file"
                        className="hidden"
                        accept=".pdf,.png,.jpg,.jpeg,.txt,.md,.json"
                        disabled={busyKey === pKey}
                        onChange={async (e) => {
                          const file = e.target.files?.[0];
                          e.target.value = "";
                          if (!file || !onAttest) return;
                          setBusyKey(pKey);
                          setPending((p) => ({ ...p, [pKey]: file.name }));
                          try {
                            await onAttest(r.framework, r.id, file);
                          } catch {
                            setPending((p) => {
                              const next = { ...p };
                              delete next[pKey];
                              return next;
                            });
                          } finally {
                            setBusyKey(null);
                          }
                        }}
                      />
                      + Attach attestation
                    </label>
                  )}
                </TableCell>
                <TableCell className="text-xs text-zinc-500 align-top">
                  {r.framework}
                </TableCell>
              </TableRow>
            );
          })}
        </TableBody>
      </Table>
    </div>
  );
}

export default CertInRequirementDrilldown;
