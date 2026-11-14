"use client";

// S14: a run asset's finding dialog, in the code page's dialog layout (metadata grid, location, description), with the
// run's own explanation: AssetDetailPanel (PQC class, exposure, library EOL / CVEs, SBOM links, KB details with fix
// steps and read-only verify commands), the as-of-run note, the collected facts and where it came from (source, scan
// node, job). Full-screen below 640 px (PLAN §4.5). #266: the dialog body is its one scroll container (wheel, touch,
// keyboard), and the knowledge-base details (with "Standards and regulations") show once: AssetDetailPanel's, so the
// remediation panel below drops its Standards tab.

import type { ReactNode } from "react";

import { Badge } from "@/components/ui/badge";
import { COMPLIANCE_KEY_TO_LABEL, OWASP_KEY_TO_LABEL } from "@/lib/owasp-compliance-labels";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import type { CbomJob, CbomRunAssetItem } from "@/utils/backend_api";
import type { CbomRemediationItem } from "@/utils/api/cbom_ops";

import { AssetDetailPanel } from "@/components/cbom/sources/RunPosture";
import { ASSET_TYPE_LABEL } from "@/components/cbom/sources/RunResults";

import { getFindingStatusBadgeClass, getImpactBadgeClass, getRiskScoreBoxClass, getStrengthBadgeClass } from "./badgeClasses";
import RemediationPanel from "@/components/RemediationPanel";
import AiRemediationPanel from "./AiRemediationPanel";
import { dialogItem, findingChips, findingStatusOf } from "./model";
import { useQuery } from "@tanstack/react-query";
import { getCbomAssetDetail } from "@/utils/backend_api";
import type { CbomAssetDetailWithExposure } from "@/utils/api/cbom_outputs";
import { cbomSourcesKeys } from "@/components/cbom/sources/keys";
import { assetName, AsOfRunNote, CollectedFacts } from "./RunFindingsTable";
import { InfoTip } from "@/components/ui/info-tip";
import { FINDING_DIALOG_BODY, FINDING_DIALOG_CONTENT, FINDING_DIALOG_FULLSCREEN_SM } from "./findingTable";
import type { InfoTipId } from "@/content/infotips";

function Field({ label, children, infoId }: { label: string; children: ReactNode; infoId: InfoTipId }) {
  return (
    <div className="min-w-0">
      <div className="text-xs font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400 mb-1 flex items-center gap-0.5">
        {label}
        <InfoTip id={infoId} />
      </div>
      {children}
    </div>
  );
}

/** What the dialog was opened with: a table row, or (from top risks / certificates) its id; the dialog then renders the
 * asset detail's copy of the row (dialogItem). */
export type DialogSubject = { item: CbomRunAssetItem } | { assetId: number; label?: string };

export function RunFindingDialog({ teamId, runId, subject, jobs, waveOf, onClose }: {
  teamId: number;
  runId: number;
  subject: DialogSubject | null;
  jobs: CbomJob[];
  /** the row's wave entry from the run plan (an older backend's rows carry no status of their own) */
  waveOf?: (item: CbomRunAssetItem) => CbomRemediationItem | undefined;
  onClose: () => void;
}) {
  const assetId = subject ? ("item" in subject ? subject.item.id : subject.assetId) : null;
  // the asset detail (the same query AssetDetailPanel runs, so one request): its KB entries are the chips' fallback,
  // and for an asset opened by id (Top risks, Certificates: not on the findings page) its copy of the table row
  const detailQ = useQuery({
    queryKey: cbomSourcesKeys.asset(teamId, assetId ?? 0),
    queryFn: async () => (await getCbomAssetDetail(teamId, assetId as number)) as unknown as CbomAssetDetailWithExposure,
    enabled: assetId != null,
    retry: 1,
    staleTime: 60_000,
  });
  // the row every block below renders: the table's row, else the detail's copy of it (staging QA B7 bug 1)
  const item = dialogItem(subject, detailQ.data);
  const job = item ? jobs.find((j) => j.id === item.job_id) : undefined;
  const title = item ? assetName(item) : subject && "assetId" in subject ? subject.label ?? `Asset ${subject.assetId}` : "Finding details";
  const chips = findingChips(item, detailQ.data?.details, detailQ.data);
  const status = item && item.type !== "coverage" ? findingStatusOf(item, item.wave ?? waveOf?.(item)) : null;
  return (
    <Dialog open={!!subject} onOpenChange={(open) => !open && onClose()}>
      <DialogContent className={`${FINDING_DIALOG_CONTENT} ${FINDING_DIALOG_FULLSCREEN_SM}`} data-testid="run-finding-dialog">
        <DialogHeader className="px-6 pt-6 pb-2 shrink-0">
          <DialogTitle className="pr-8 break-all">{title}</DialogTitle>
          <DialogDescription className="sr-only">Explanation, fix and provenance of this asset</DialogDescription>
        </DialogHeader>
        {assetId != null && (
          <div className={FINDING_DIALOG_BODY} tabIndex={0} role="region" aria-label="Finding details" data-testid="run-finding-scroll">
              <div className="space-y-4 pt-2">
                {item && (
                  <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
                    <Field infoId="cbom.run.f.type" label="Type"><p className="text-sm text-zinc-700 dark:text-zinc-300">{item.type_label ?? ASSET_TYPE_LABEL[item.type] ?? item.type}</p></Field>
                    <Field infoId="cbom.run.f.strength" label="Crypto strength">
                      {item.crypto_strength ? <Badge variant="outline" className={getStrengthBadgeClass(item.crypto_strength)}>{item.crypto_strength}</Badge> : <p className="text-sm">—</p>}
                    </Field>
                    <Field infoId="cbom.run.f.key_size" label="Key size"><p className="text-sm text-zinc-700 dark:text-zinc-300">{item.key_size ? `${item.key_size} bits` : "—"}</p></Field>
                    <Field infoId="cbom.run.f.quantum" label="Quantum">
                      <p className="text-sm text-zinc-700 dark:text-zinc-300">
                        {item.quantum_vulnerable === true ? "Vulnerable" : item.quantum_vulnerable === false ? "Safe" : "Not applicable"}
                      </p>
                    </Field>
                    <Field infoId="cbom.run.f.impact" label="Impact">
                      {item.impact ? <Badge variant="outline" className={getImpactBadgeClass(item.impact)}>{item.impact}</Badge> : <p className="text-sm">Info</p>}
                    </Field>
                    <Field infoId="cbom.run.f.risk" label="Risk score">
                      <span className={`inline-flex items-center justify-center min-w-9 px-2 py-1 rounded-md text-xs font-semibold tabular-nums ${typeof item.risk_score === "number" ? getRiskScoreBoxClass(item.risk_score) : ""}`}>
                        {typeof item.risk_score === "number" ? item.risk_score.toFixed(1) : "—"}
                      </span>
                    </Field>
                    <Field infoId="cbom.run.f.status" label="Status">
                      {status
                        ? <span className={`inline-flex px-2.5 py-1 rounded-md text-xs font-medium capitalize ${getFindingStatusBadgeClass(status)}`}>{status.replace(/_/g, " ")}</span>
                        : <p className="text-sm">—</p>}
                    </Field>
                    {item.q_grade != null && <Field infoId="cbom.run.col.qgrade" label="Quantum risk"><p className="text-sm" title={item.q_label ?? undefined}>{item.q_grade}{item.q_label ? ` · ${item.q_label}` : ""}</p></Field>}
                    {item.fix_class != null && <Field infoId="cbom.res.col.fix_class" label="Fix class"><p className="text-sm">{item.fix_class.replace(/_/g, " ")}</p></Field>}
                    {item.ticket_key && (
                      <Field infoId="cbom.run.f.ticket" label="Ticket">
                        {item.ticket_url
                          ? <a href={item.ticket_url} target="_blank" rel="noreferrer noopener" className="text-sm text-blue-600 dark:text-blue-400">{item.ticket_key}</a>
                          : <p className="text-sm">{item.ticket_key}</p>}
                      </Field>
                    )}
                  </div>
                )}

                {item && (
                  <Field infoId="cbom.run.f.location" label="Location">
                    <p className="text-sm font-mono text-zinc-700 dark:text-zinc-300 bg-zinc-100 dark:bg-zinc-800 px-3 py-2 rounded-md border border-zinc-200 dark:border-zinc-700 break-all"
                       data-testid="run-finding-location">
                      {item.location}
                      {item.target && item.target !== item.location ? <span className="block text-xs text-zinc-500 font-sans mt-1">Target: {item.target}</span> : null}
                    </p>
                  </Field>
                )}

                {item?.finding && (
                  <Field infoId="cbom.run.f.finding" label="Finding"><p className="text-sm text-zinc-700 dark:text-zinc-300 whitespace-pre-wrap">{item.finding}</p></Field>
                )}
                {item?.description && item.description !== item.finding && (
                  <Field infoId="cbom.run.f.description" label="Description"><p className="text-sm text-zinc-700 dark:text-zinc-300 whitespace-pre-wrap">{item.description}</p></Field>
                )}
                {item && <AsOfRunNote item={item} />}

                {/* the code dialog's OWASP Top 10 / Compliance controls / Suggested fix: the /assets item's fields (W2b),
                    else the same facts from the asset's knowledge-base entries */}
                {chips.owasp.length > 0 && (
                  <Field infoId="cbom.run.f.owasp" label="OWASP Top 10">
                    <div className="flex flex-wrap gap-1" data-testid="run-finding-owasp">
                      {chips.owasp.map(([key, value]) => (
                        <Badge key={key} variant="secondary" className="text-xs whitespace-normal max-w-full text-left bg-purple-100 dark:bg-purple-900/40 text-purple-800 dark:text-purple-200">
                          {OWASP_KEY_TO_LABEL[key] ?? value}
                        </Badge>
                      ))}
                    </div>
                  </Field>
                )}
                {chips.controls.length > 0 && (
                  <Field infoId="cbom.run.f.compliance" label="Compliance controls">
                    <div className="flex flex-wrap gap-1" data-testid="run-finding-controls">
                      {chips.controls.map(([key, value]) => (
                        <Badge key={key} variant="outline" className="text-xs whitespace-normal max-w-full text-left">{COMPLIANCE_KEY_TO_LABEL[key] ?? value}</Badge>
                      ))}
                    </div>
                  </Field>
                )}
                {chips.suggestedFix && (
                  <Field infoId="cbom.run.f.suggested_fix" label="Suggested fix">
                    <p className="text-sm text-zinc-700 dark:text-zinc-300 whitespace-pre-wrap" data-testid="run-finding-suggested-fix">{chips.suggestedFix}</p>
                  </Field>
                )}

                {item && (
                  <Field infoId="cbom.run.f.origin" label="Where it came from">
                    <p className="text-sm text-zinc-700 dark:text-zinc-300" data-testid="run-finding-provenance">
                      Source {item.source_name ?? "—"}
                      {" · "}{job ? (job.runner === "cloud" ? "ZeroShield cloud" : `scan node ${job.node_name ?? "—"}`) : "scan node —"}
                      {" · "}job #{item.job_id}
                      {item.finding_codes.length > 0 ? ` · ${item.finding_codes.join(", ")}` : ""}
                    </p>
                  </Field>
                )}

                <AssetDetailPanel teamId={teamId} assetId={assetId} />

                {/* the code page's "Remediation, fix code and exploit demo" panel (Fix code / Diff / Exploit demo), from
                    GET /runs/{id}/assets/{asset}/remediation; hidden on an older backend. Its Standards tab would repeat
                    the KB details AssetDetailPanel shows above (#266) */}
                <RemediationPanel key={`rem-${assetId}`} teamId={String(teamId)} scanType="cbom" scanId={0} findingId={String(assetId)}
                                  runAsset={{ runId, assetId }} standardsTab={false} />

                {/* AI remediation assistant (CB-38 PR-6), below the knowledge-base fix; renders nothing when it is off */}
                <AiRemediationPanel teamId={teamId} subject={{ kind: "run_asset", assetId }} />

                {item && <CollectedFacts item={item} />}
              </div>
          </div>
        )}
      </DialogContent>
    </Dialog>
  );
}
