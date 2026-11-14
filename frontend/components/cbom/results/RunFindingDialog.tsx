"use client";

// S14: a run asset's finding dialog, in the code page's dialog layout (metadata grid, location, description), with the
// run's own explanation: AssetDetailPanel (PQC class, exposure, library EOL / CVEs, SBOM links, KB details with fix
// steps and read-only verify commands), the as-of-run note, the collected facts and where it came from (source, scan
// node, job). Full-screen below 640 px (PLAN §4.5).

import type { ReactNode } from "react";

import { Badge } from "@/components/ui/badge";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { ScrollArea } from "@/components/ui/scroll-area";
import type { CbomJob, CbomRunAssetItem } from "@/utils/backend_api";
import type { CbomRemediationItem } from "@/utils/api/cbom_ops";

import { AssetDetailPanel } from "@/components/cbom/sources/RunPosture";
import { ASSET_TYPE_LABEL } from "@/components/cbom/sources/RunResults";

import { getFindingStatusBadgeClass, getImpactBadgeClass, getRiskScoreBoxClass, getStrengthBadgeClass } from "./badgeClasses";
import { findingStatusOf } from "./model";
import { assetName, AsOfRunNote, CollectedFacts } from "./RunFindingsTable";

function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="min-w-0">
      <div className="text-xs font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400 mb-1">{label}</div>
      {children}
    </div>
  );
}

/** What the dialog shows for an asset: a table row, or (from top risks / certificates) only its id. */
export type DialogSubject = { item: CbomRunAssetItem } | { assetId: number; label?: string };

export function RunFindingDialog({ teamId, subject, jobs, waveOf, onClose }: {
  teamId: number;
  subject: DialogSubject | null;
  jobs: CbomJob[];
  /** the row's wave entry from the run plan (an older backend's rows carry no status of their own) */
  waveOf?: (item: CbomRunAssetItem) => CbomRemediationItem | undefined;
  onClose: () => void;
}) {
  const item = subject && "item" in subject ? subject.item : null;
  const assetId = item ? item.id : subject && "assetId" in subject ? subject.assetId : null;
  const job = item ? jobs.find((j) => j.id === item.job_id) : undefined;
  const title = item ? assetName(item) : subject && "assetId" in subject ? subject.label ?? `Asset ${subject.assetId}` : "Finding details";
  const status = item && item.type !== "coverage" ? findingStatusOf(item, item.wave ?? waveOf?.(item)) : null;
  return (
    <Dialog open={!!subject} onOpenChange={(open) => !open && onClose()}>
      <DialogContent
        className="sm:max-w-3xl max-h-[90vh] flex flex-col p-0 gap-0 overflow-hidden bg-white dark:bg-zinc-900 max-sm:max-w-none max-sm:w-screen max-sm:h-[100dvh] max-sm:max-h-[100dvh] max-sm:rounded-none max-sm:border-0"
        data-testid="run-finding-dialog">
        <DialogHeader className="px-6 pt-6 pb-2 shrink-0">
          <DialogTitle className="pr-8 break-all">{title}</DialogTitle>
          <DialogDescription className="sr-only">Explanation, fix and provenance of this asset</DialogDescription>
        </DialogHeader>
        {assetId != null && (
          <div className="flex-1 min-h-0 sm:h-[70vh] px-6 pb-6">
            <ScrollArea className="h-full w-full rounded-md [&_[data-slot=scroll-area-viewport]>div]:!block" data-testid="run-finding-scroll">
              <div className="space-y-4 pt-2 pr-4">
                {item && (
                  <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
                    <Field label="Type"><p className="text-sm text-zinc-700 dark:text-zinc-300">{item.type_label ?? ASSET_TYPE_LABEL[item.type] ?? item.type}</p></Field>
                    <Field label="Crypto strength">
                      {item.crypto_strength ? <Badge variant="outline" className={getStrengthBadgeClass(item.crypto_strength)}>{item.crypto_strength}</Badge> : <p className="text-sm">—</p>}
                    </Field>
                    <Field label="Key size"><p className="text-sm text-zinc-700 dark:text-zinc-300">{item.key_size ? `${item.key_size} bits` : "—"}</p></Field>
                    <Field label="Quantum">
                      <p className="text-sm text-zinc-700 dark:text-zinc-300">
                        {item.quantum_vulnerable === true ? "Vulnerable" : item.quantum_vulnerable === false ? "Safe" : "Not applicable"}
                      </p>
                    </Field>
                    <Field label="Impact">
                      {item.impact ? <Badge variant="outline" className={getImpactBadgeClass(item.impact)}>{item.impact}</Badge> : <p className="text-sm">Info</p>}
                    </Field>
                    <Field label="Risk score">
                      <span className={`inline-flex items-center justify-center min-w-9 px-2 py-1 rounded-md text-xs font-semibold tabular-nums ${typeof item.risk_score === "number" ? getRiskScoreBoxClass(item.risk_score) : ""}`}>
                        {typeof item.risk_score === "number" ? item.risk_score.toFixed(1) : "—"}
                      </span>
                    </Field>
                    <Field label="Status">
                      {status
                        ? <span className={`inline-flex px-2.5 py-1 rounded-md text-xs font-medium capitalize ${getFindingStatusBadgeClass(status)}`}>{status.replace(/_/g, " ")}</span>
                        : <p className="text-sm">—</p>}
                    </Field>
                    {item.q_grade != null && <Field label="Quantum risk"><p className="text-sm" title={item.q_label ?? undefined}>{item.q_grade}{item.q_label ? ` · ${item.q_label}` : ""}</p></Field>}
                    {item.fix_class != null && <Field label="Fix class"><p className="text-sm">{item.fix_class.replace(/_/g, " ")}</p></Field>}
                    {item.ticket_key && (
                      <Field label="Ticket">
                        {item.ticket_url
                          ? <a href={item.ticket_url} target="_blank" rel="noreferrer noopener" className="text-sm text-blue-600 dark:text-blue-400">{item.ticket_key}</a>
                          : <p className="text-sm">{item.ticket_key}</p>}
                      </Field>
                    )}
                  </div>
                )}

                {item && (
                  <Field label="Location">
                    <p className="text-sm font-mono text-zinc-700 dark:text-zinc-300 bg-zinc-100 dark:bg-zinc-800 px-3 py-2 rounded-md border border-zinc-200 dark:border-zinc-700 break-all"
                       data-testid="run-finding-location">
                      {item.location}
                      {item.target && item.target !== item.location ? <span className="block text-xs text-zinc-500 font-sans mt-1">Target: {item.target}</span> : null}
                    </p>
                  </Field>
                )}

                {item?.finding && (
                  <Field label="Finding"><p className="text-sm text-zinc-700 dark:text-zinc-300 whitespace-pre-wrap">{item.finding}</p></Field>
                )}
                {item?.description && item.description !== item.finding && (
                  <Field label="Description"><p className="text-sm text-zinc-700 dark:text-zinc-300 whitespace-pre-wrap">{item.description}</p></Field>
                )}
                {item && <AsOfRunNote item={item} />}

                {item && (
                  <Field label="Where it came from">
                    <p className="text-sm text-zinc-700 dark:text-zinc-300" data-testid="run-finding-provenance">
                      Source {item.source_name ?? "—"}
                      {" · "}{job ? (job.runner === "cloud" ? "ZeroShield cloud" : `scan node ${job.node_name ?? "—"}`) : "scan node —"}
                      {" · "}job #{item.job_id}
                      {item.finding_codes.length > 0 ? ` · ${item.finding_codes.join(", ")}` : ""}
                    </p>
                  </Field>
                )}

                <AssetDetailPanel teamId={teamId} assetId={assetId} />

                {item && <CollectedFacts item={item} />}

                {/* AI remediation mount point (lane W5): components/cbom/results/AiRemediationPanel.tsx, default export,
                    props {teamId, subject: {kind: "run_asset", assetId}}; renders nothing when the assistant is off.
                    Mount it here, below the knowledge-base fix: <AiRemediationPanel teamId={teamId} subject={{ kind: "run_asset", assetId }} /> */}
              </div>
            </ScrollArea>
          </div>
        )}
      </DialogContent>
    </Dialog>
  );
}
