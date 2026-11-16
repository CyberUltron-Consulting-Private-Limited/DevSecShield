"use client";

// A Sources-run asset's finding dialog (results redesign F7–F10; before it S14 / #266). Frame 16-A with a severity-
// tinted edge, header 17-B (risk ring, title, visible subtitle, solid chips) and six tabs (26-A):
//   Overview          facts 4×2, location table and the stored string, finding issues, description + as-of-run note,
//                     numbered suggested fix, OWASP Top 10 and compliance-control framework cards, where it came from
//   Issues N          the knowledge-base issues as five-step stories, CVE cards, platform commands, ONE verify block
//   Quantum & effort  class chips + PQC basis, Q grade, crypto agility, standards, correlation, library, SBOM links
//   Standards         "Standards and regulations", once, as regulator tabs (#266)
//   Fix & demo        the code page's remediation panel (Fix code / Diff / Exploit demo) as status cards
//   AI                opens the AI assistant (and the collected facts it is given) in a panel on the right
// Every tab is mounted at once and hidden when inactive (forceMount), so the remediation panel's request, an AI answer
// and an open Diff survive a tab switch; the body is keyed by asset, so Previous / Next start at the top of the same tab.
// The AI panel and the Explanations drawer are panels INSIDE the dialog (not portaled layers): focus stays in the
// dialog, a click in them never closes it, and Escape closes them first. Full screen below 640 px (PLAN §4.5); the
// dialog body is its one scroll container (#266).

import { useEffect, useRef, useState, type KeyboardEvent, type ReactNode } from "react";
import { useQuery } from "@tanstack/react-query";
import { ChevronLeft, ChevronRight, Pencil, Sparkles, X, XCircle } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from "@/components/ui/dropdown-menu";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { InfoTip } from "@/components/ui/info-tip";
import { ExplanationsButton, InfoTipDrawerProvider, useInfoTipDrawer, type InfoTipDrawerApi } from "@/components/ui/info-tip-drawer";
import { COMPLIANCE_KEY_TO_LABEL, OWASP_KEY_TO_LABEL } from "@/lib/owasp-compliance-labels";
import { getCbomAiStatus, getCbomAssetDetail, type CbomFindingStatus, type CbomJob, type CbomRunAssetItem } from "@/utils/backend_api";
import type { CbomRemediationItem } from "@/utils/api/cbom_ops";
import type { CbomAssetDetailWithExposure } from "@/utils/api/cbom_outputs";
import type { InfoTipId } from "@/content/infotips";
import type { DrawerView } from "@/content/infotips/drawerManifest";

import KbFindingDetails, { StandardsTabs } from "@/components/cbom/KbFindingDetails";
import RemediationPanel from "@/components/RemediationPanel";
import { AssetClassChips, AssetQuantumParts } from "@/components/cbom/sources/RunPosture";
import { ASSET_TYPE_LABEL } from "@/components/cbom/sources/RunResults";
import { ErrorBlock, LoadingBlock } from "@/components/cbom/sources/shared";
import { cbomSourcesKeys } from "@/components/cbom/sources/keys";

import AiRemediationPanel from "./AiRemediationPanel";
import { aiPanelVisible } from "./aiPanelLogic";
import { getFindingStatusBadgeClass, getImpactBadgeClass, getRiskScoreBoxClass, getStrengthBadgeClass } from "./badgeClasses";
import { arrowKeysMove, canGo, positionLabel, removedFromView, type DialogNav } from "./dialogNav";
import {
  FRAME_CLASS,
  IMPACT_CHIP_CLASS,
  NEUTRAL_CHIP_CLASS,
  controlGroups,
  evidenceCodes,
  fixSteps,
  issueRows,
  locationRows,
  riskRingClass,
  riskRingFraction,
  severityTone,
} from "./findingDialogModel";
import { FINDING_DIALOG_BODY, FINDING_DIALOG_CONTENT, FINDING_DIALOG_FULLSCREEN_SM } from "./findingTable";
import { FINDING_STATUS_LABEL, FINDING_STATUSES, dialogItem, findingChips, findingStatusOf } from "./model";
import { assetName, AsOfRunNote, CollectedFacts } from "./RunFindingsTable";

export type { DialogNav } from "./dialogNav";

/** What the dialog shows: an asset id (and a label for the title while its row loads). The row itself is resolved
 * live: the table page's row, else the asset detail's copy (dialogItem). */
export type DialogSubject = { assetId: number; label?: string };

export type FindingTab = "overview" | "issues" | "quantum" | "standards" | "fix" | "ai";
const TAB_VIEW: Record<FindingTab, DrawerView> = {
  overview: "dialog.overview", issues: "dialog.issues", quantum: "dialog.quantum", standards: "dialog.standards",
  fix: "dialog.fix", ai: "dialog.ai",
};
/** Wider than the code dialog from 1024 px: the overview has two columns there. */
const FINDING_DIALOG_WIDE = "lg:max-w-5xl";

function Field({ label, children, infoId, className = "" }: { label: string; children: ReactNode; infoId: InfoTipId; className?: string }) {
  return (
    <div className={`min-w-0 ${className}`}>
      <div className="text-xs font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400 mb-1 flex items-center gap-0.5">
        {label}
        <InfoTip id={infoId} />
      </div>
      {children}
    </div>
  );
}

/** One fact box of the 4×2 grid (18-A). */
function Fact({ label, infoId, children }: { label: string; infoId: InfoTipId; children: ReactNode }) {
  return (
    <div className="rounded-lg border border-zinc-200 dark:border-zinc-800 bg-zinc-50 dark:bg-zinc-950/60 px-3 py-2 min-w-0">
      <Field label={label} infoId={infoId}>{children}</Field>
    </div>
  );
}

function RiskRing({ score }: { score: number | null | undefined }) {
  const r = 22;
  const c = 2 * Math.PI * r;
  const filled = riskRingFraction(score) * c;
  const text = typeof score === "number" ? score.toFixed(1) : "—";
  return (
    <div className="relative size-14 shrink-0" role="img" aria-label={typeof score === "number" ? `Risk score ${text} of 10` : "No risk score"}
         data-testid="run-finding-ring">
      <svg viewBox="0 0 56 56" className="size-14 -rotate-90" aria-hidden="true">
        <circle cx="28" cy="28" r={r} fill="none" strokeWidth="6" className="stroke-zinc-200 dark:stroke-zinc-800" />
        <circle cx="28" cy="28" r={r} fill="none" strokeWidth="6" strokeLinecap="round" className={riskRingClass(score)}
                strokeDasharray={`${filled} ${c}`} />
      </svg>
      <span className="absolute inset-0 flex items-center justify-center text-sm font-bold tabular-nums text-zinc-900 dark:text-zinc-50">{text}</span>
    </div>
  );
}

/** Loading / error-with-retry of the asset detail, for the tabs built from it (AssetDetailPanel's states). */
function WithDetail({ q, children }: {
  q: { isLoading: boolean; isError: boolean; data?: CbomAssetDetailWithExposure; error: unknown; refetch: () => unknown };
  children: (a: CbomAssetDetailWithExposure) => ReactNode;
}) {
  if (q.isLoading) return <LoadingBlock />;
  if (q.isError || !q.data) return <ErrorBlock error={q.error} onRetry={() => q.refetch()} />;
  return <>{children(q.data)}</>;
}

/** Gives the dialog (outside the drawer's provider) the drawer's open state and close(), for Escape and ←/→. */
function DrawerBridge({ apiRef }: { apiRef: { current: InfoTipDrawerApi | null } }) {
  const api = useInfoTipDrawer();
  useEffect(() => {
    apiRef.current = api;
  }, [api, apiRef]);
  return null;
}

export function RunFindingDialog({ teamId, runId, subject, jobs, waveOf, onClose, pageItems, nav, onSetStatus, statusPending = false, priorityOf }: {
  teamId: number;
  runId: number;
  subject: DialogSubject | null;
  jobs: CbomJob[];
  /** the row's wave entry from the run plan (an older backend's rows carry no status of their own) */
  waveOf?: (item: CbomRunAssetItem) => CbomRemediationItem | undefined;
  onClose: () => void;
  /** the live findings-table page: the dialog's row is read from it (fresh after a refresh), else from the detail */
  pageItems?: readonly CbomRunAssetItem[];
  /** Previous / Next over the findings table (opened from the table only); no footer navigation without it */
  nav?: DialogNav;
  /** the table's status action (PUT /cbom/remediation by asset key); no status control without it */
  onSetStatus?: (keys: string[], status: CbomFindingStatus) => void;
  statusPending?: boolean;
  /** the posture's priority (impact × business criticality × internet exposure) when the asset is a top risk */
  priorityOf?: (assetId: number) => number | null | undefined;
}) {
  const assetId = subject ? subject.assetId : null;
  // the asset detail (the same query the Quantum / Issues / Standards parts read, so one request): its KB entries are
  // the chips' fallback, and for an asset not on the table page its copy of the table row
  const detailQ = useQuery({
    queryKey: cbomSourcesKeys.asset(teamId, assetId ?? 0),
    queryFn: async () => (await getCbomAssetDetail(teamId, assetId as number)) as unknown as CbomAssetDetailWithExposure,
    enabled: assetId != null,
    retry: 1,
    staleTime: 60_000,
  });
  const aiStatus = useQuery({
    queryKey: ["cbom-ai-status", teamId],
    queryFn: () => getCbomAiStatus(teamId),
    enabled: assetId != null && Number.isInteger(teamId) && teamId > 0,
    staleTime: 60_000,
    retry: false,
  });
  // the row every block below renders: the table page's row, else the detail's copy of it (staging QA B7 bug 1)
  const item = dialogItem(subject, detailQ.data, pageItems);
  const details = detailQ.data && detailQ.data.id === assetId ? detailQ.data.details : undefined;
  const job = item ? jobs.find((j) => j.id === item.job_id) : undefined;
  const title = item ? assetName(item) : subject ? subject.label ?? `Asset ${subject.assetId}` : "Finding details";
  const chips = findingChips(item, detailQ.data?.details, detailQ.data);
  const status = item && item.type !== "coverage" ? findingStatusOf(item, item.wave ?? waveOf?.(item)) : null;
  const statusKey = item ? item.asset_key ?? waveOf?.(item)?.asset_key ?? null : null;
  const tone = severityTone(item?.impact);
  const priority = assetId != null ? priorityOf?.(assetId) ?? null : null;
  const issues = issueRows(details);
  const steps = fixSteps(details, chips.suggestedFix);
  const groups = controlGroups(chips.controls, COMPLIANCE_KEY_TO_LABEL);
  const aiOn = aiPanelVisible(aiStatus.data);

  // the active tab persists across Previous / Next; a dialog opened anew starts on Overview
  const [tab, setTab] = useState<FindingTab>("overview");
  const [aiOpen, setAiOpen] = useState(false);
  const [shown, setShown] = useState(!!subject);
  if (shown !== !!subject) {
    // adjusted while rendering (no effect): a closed dialog forgets its tab and AI panel
    setShown(!!subject);
    if (!subject) {
      setTab("overview");
      setAiOpen(false);
    }
  }
  const drawerRef = useRef<InfoTipDrawerApi | null>(null);
  const aiButton = useRef<HTMLButtonElement | null>(null);
  const aiClose = useRef<HTMLButtonElement | null>(null);
  const bodyRef = useRef<HTMLDivElement | null>(null);
  const closeAi = () => {
    setAiOpen(false);
    queueMicrotask(() => aiButton.current?.focus());
  };
  useEffect(() => {
    if (aiOpen) aiClose.current?.focus();
  }, [aiOpen]);
  // a new asset starts at the top of the same tab (the body is keyed by asset; this covers a kept scroll position)
  useEffect(() => {
    bodyRef.current?.scrollTo?.({ top: 0 });
  }, [assetId]);

  const go = (dir: -1 | 1) => {
    if (nav && canGo(nav, dir)) nav.onGo(nav.index + dir);
  };
  const onKeyDown = (e: KeyboardEvent<HTMLDivElement>) => {
    if (!nav || e.defaultPrevented || e.altKey || e.ctrlKey || e.metaKey || e.shiftKey) return;
    if (e.key !== "ArrowLeft" && e.key !== "ArrowRight") return;
    if (!arrowKeysMove(e.target as HTMLElement, aiOpen || !!drawerRef.current?.isOpen)) return;
    e.preventDefault();
    go(e.key === "ArrowLeft" ? -1 : 1);
  };
  const removed = nav && assetId != null && removedFromView(assetId, pageItems?.map((i) => i.id));
  const position = nav ? positionLabel(nav.index, nav.total) : null;

  return (
    <Dialog open={!!subject} onOpenChange={(open) => !open && onClose()}>
      <DialogContent className={`${FINDING_DIALOG_CONTENT} ${FINDING_DIALOG_FULLSCREEN_SM} ${FINDING_DIALOG_WIDE} ${FRAME_CLASS[tone]}`} data-testid="run-finding-dialog"
                     data-severity={tone} onKeyDown={onKeyDown}
                     onEscapeKeyDown={(e) => {
                       // nested panels first: the AI panel, then the Explanations drawer; then the dialog
                       if (aiOpen) {
                         e.preventDefault();
                         closeAi();
                       } else if (drawerRef.current?.isOpen) {
                         e.preventDefault();
                         drawerRef.current.close();
                       }
                     }}>
        <InfoTipDrawerProvider view={TAB_VIEW[tab]} mode="inline">
          <DrawerBridge apiRef={drawerRef} />
          <Tabs value={tab} onValueChange={(v) => setTab(v as FindingTab)} className="flex min-h-0 min-w-0 flex-1 flex-col gap-0">
            <DialogHeader className="px-4 sm:px-6 pt-5 pb-0 shrink-0 gap-3 text-left">
              <div className="flex items-start gap-3 pr-8 min-w-0">
                <RiskRing score={item?.risk_score} />
                <div className="min-w-0 flex-1">
                  <DialogTitle className="break-all text-lg leading-snug">{title}</DialogTitle>
                  <DialogDescription className="text-sm text-zinc-500 dark:text-zinc-400">Explanation, fix and provenance of this asset</DialogDescription>
                  <div className="mt-2 flex flex-wrap items-center gap-1.5" data-testid="run-finding-chips">
                    {item && (
                      <span className={`inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-semibold ${IMPACT_CHIP_CLASS[tone]}`} data-testid="run-finding-chip-impact">
                        {item.impact ?? "Info"}
                      </span>
                    )}
                    {priority != null && (
                      <span className={`inline-flex items-center gap-0.5 rounded-full pl-2.5 pr-1 py-0.5 text-xs font-medium ${NEUTRAL_CHIP_CLASS}`} data-testid="run-finding-chip-priority">
                        Priority {priority}
                        <InfoTip id="cbom.run.col.priority" className="text-zinc-200 hover:text-white dark:text-zinc-300" />
                      </span>
                    )}
                    {status && (
                      <span className={`inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium capitalize ${NEUTRAL_CHIP_CLASS}`} data-testid="run-finding-chip-status">
                        {status.replace(/_/g, " ")}
                      </span>
                    )}
                  </div>
                </div>
                <ExplanationsButton className="hidden sm:inline-flex shrink-0" testId="run-finding-explanations" />
              </div>
              <div className="flex items-center gap-2 min-w-0">
                <TabsList className="h-auto min-w-0 flex-1 justify-start overflow-x-auto overflow-y-hidden rounded-none border-b border-zinc-200 dark:border-zinc-800 bg-transparent p-0 [scrollbar-width:thin]"
                          aria-label="Finding sections" data-testid="run-finding-tabs">
                  {([
                    ["overview", "Overview"],
                    ["issues", `Issues ${details ? details.length : item ? item.finding_codes.length : ""}`.trim()],
                    ["quantum", "Quantum & effort"],
                    ["standards", "Standards"],
                    ["fix", "Fix & demo"],
                    ["ai", "AI"],
                  ] as [FindingTab, string][]).map(([id, label]) => (
                    <TabsTrigger key={id} value={id} data-testid={`run-finding-tab-${id}`}
                                 className="shrink-0 cursor-pointer rounded-none border-b-2 border-transparent px-3 py-2 text-sm text-zinc-500 dark:text-zinc-400 shadow-none data-[state=active]:border-blue-600 data-[state=active]:bg-transparent data-[state=active]:text-zinc-900 dark:data-[state=active]:text-zinc-50 data-[state=active]:shadow-none">
                      {label}
                    </TabsTrigger>
                  ))}
                </TabsList>
                <ExplanationsButton className="sm:hidden shrink-0" testId="run-finding-explanations-sm" />
              </div>
            </DialogHeader>
            {assetId != null && (
              <div className={FINDING_DIALOG_BODY} key={assetId} ref={bodyRef} tabIndex={0} role="region" aria-label="Finding details" data-testid="run-finding-scroll">
                <div className="pt-4 min-w-0">
                  {removed && (
                    <p className="mb-3 rounded-md border border-amber-300 bg-amber-50 px-3 py-2 text-xs text-amber-900 dark:border-amber-700 dark:bg-amber-900/20 dark:text-amber-300"
                       role="status" data-testid="run-finding-removed">
                      Removed from view: this finding is no longer on the table&apos;s current page (a filter or a status change); it keeps its place for Previous and Next.
                    </p>
                  )}

                  {/* ------------------------------------------------------------------ Overview */}
                  <TabsContent value="overview" forceMount className="mt-0 data-[state=inactive]:hidden" data-testid="run-finding-overview">
                    {!item && detailQ.isLoading && <LoadingBlock />}
                    {!item && detailQ.isError && <ErrorBlock error={detailQ.error} onRetry={() => detailQ.refetch()} />}
                    <div className="grid grid-cols-1 lg:grid-cols-[minmax(0,1.15fr)_minmax(0,1fr)] gap-5">
                      <div className="space-y-4 min-w-0">
                        {item && (
                          <div className="grid grid-cols-2 md:grid-cols-4 gap-2" data-testid="run-finding-facts">
                            <Fact infoId="cbom.run.f.type" label="Type"><p className="text-sm font-semibold text-zinc-800 dark:text-zinc-200 break-words">{item.type_label ?? ASSET_TYPE_LABEL[item.type] ?? item.type}</p></Fact>
                            <Fact infoId="cbom.run.f.strength" label="Crypto strength">
                              {item.crypto_strength ? <Badge variant="outline" className={getStrengthBadgeClass(item.crypto_strength)}>{item.crypto_strength}</Badge> : <p className="text-sm">—</p>}
                            </Fact>
                            <Fact infoId="cbom.run.f.key_size" label="Key size"><p className="text-sm font-semibold text-zinc-800 dark:text-zinc-200">{item.key_size ? `${item.key_size} bits` : "—"}</p></Fact>
                            <Fact infoId="cbom.run.f.quantum" label="Quantum">
                              <p className="text-sm font-semibold text-zinc-800 dark:text-zinc-200">
                                {item.quantum_vulnerable === true ? "Vulnerable" : item.quantum_vulnerable === false ? "Safe" : "Not applicable"}
                              </p>
                            </Fact>
                            <Fact infoId="cbom.run.f.impact" label="Impact">
                              {item.impact ? <Badge variant="outline" className={getImpactBadgeClass(item.impact)}>{item.impact}</Badge> : <p className="text-sm">Info</p>}
                            </Fact>
                            <Fact infoId="cbom.run.f.risk" label="Risk score">
                              <span className={`inline-flex items-center justify-center min-w-9 px-2 py-1 rounded-md text-xs font-semibold tabular-nums ${typeof item.risk_score === "number" ? getRiskScoreBoxClass(item.risk_score) : ""}`}>
                                {typeof item.risk_score === "number" ? item.risk_score.toFixed(1) : "—"}
                              </span>
                            </Fact>
                            <Fact infoId="cbom.run.f.status" label="Status">
                              {status
                                ? <span className={`inline-flex px-2.5 py-1 rounded-md text-xs font-medium capitalize ${getFindingStatusBadgeClass(status)}`}>{status.replace(/_/g, " ")}</span>
                                : <p className="text-sm">—</p>}
                            </Fact>
                            <Fact infoId="cbom.res.col.fix_class" label="Fix class"><p className="text-sm font-semibold text-zinc-800 dark:text-zinc-200">{item.fix_class != null ? item.fix_class.replace(/_/g, " ") : "—"}</p></Fact>
                            {item.q_grade != null && <Fact infoId="cbom.run.col.qgrade" label="Quantum risk"><p className="text-sm" title={item.q_label ?? undefined}>{item.q_grade}{item.q_label ? ` · ${item.q_label}` : ""}</p></Fact>}
                            {item.ticket_key && (
                              <Fact infoId="cbom.run.f.ticket" label="Ticket">
                                {item.ticket_url
                                  ? <a href={item.ticket_url} target="_blank" rel="noreferrer noopener" className="text-sm text-blue-600 dark:text-blue-400">{item.ticket_key}</a>
                                  : <p className="text-sm">{item.ticket_key}</p>}
                              </Fact>
                            )}
                          </div>
                        )}

                        {item && (
                          <Field infoId="cbom.run.f.location" label="Location">
                            <div data-testid="run-finding-location-table">
                              {locationRows(item).length > 0 && (
                                <dl className="grid grid-cols-[max-content_minmax(0,1fr)] gap-x-4 rounded-md border border-zinc-200 dark:border-zinc-800 text-sm">
                                  {locationRows(item).map(([k, v]) => (
                                    <div key={k} className="contents">
                                      <dt className="px-3 py-1.5 text-zinc-500 dark:text-zinc-400 border-b border-zinc-100 dark:border-zinc-800/70">{k}</dt>
                                      <dd className="px-3 py-1.5 font-mono text-xs text-zinc-800 dark:text-zinc-200 break-all border-b border-zinc-100 dark:border-zinc-800/70">{v}</dd>
                                    </div>
                                  ))}
                                </dl>
                              )}
                              <p className="mt-1.5 text-sm font-mono text-zinc-700 dark:text-zinc-300 bg-zinc-100 dark:bg-zinc-800 px-3 py-2 rounded-md border border-zinc-200 dark:border-zinc-700 break-all"
                                 data-testid="run-finding-location">
                                <span className="block text-[11px] font-sans text-zinc-500">Stored as</span>
                                {item.location}
                                {item.target && item.target !== item.location ? <span className="block text-xs text-zinc-500 font-sans mt-1">Target: {item.target}</span> : null}
                              </p>
                            </div>
                          </Field>
                        )}

                        {(item?.finding || issues.length > 0) && (
                          <Field infoId="cbom.run.f.finding" label={issues.length > 0 ? `Finding · ${issues.length} ${issues.length === 1 ? "issue" : "issues"}` : "Finding"}>
                            {item?.finding && <p className="text-sm text-zinc-700 dark:text-zinc-300 whitespace-pre-wrap">{item.finding}</p>}
                            {issues.length > 0 && (
                              <ul className="mt-2 space-y-1.5" data-testid="run-finding-issues">
                                {issues.map((iss) => (
                                  <li key={iss.code} className="flex items-start gap-2 rounded-lg border border-zinc-200 dark:border-zinc-800 bg-zinc-50 dark:bg-zinc-950/60 px-3 py-2">
                                    <XCircle className="mt-0.5 h-4 w-4 shrink-0 text-red-500" aria-hidden="true" />
                                    <span className="min-w-0">
                                      <span className="block text-sm font-semibold text-zinc-800 dark:text-zinc-200">{iss.title}</span>
                                      {iss.observed && <span className="block text-xs text-zinc-500 dark:text-zinc-400 break-words">{iss.observed}</span>}
                                    </span>
                                  </li>
                                ))}
                              </ul>
                            )}
                          </Field>
                        )}
                        {item?.description && item.description !== item.finding && (
                          <Field infoId="cbom.run.f.description" label="Description"><p className="text-sm text-zinc-700 dark:text-zinc-300 whitespace-pre-wrap">{item.description}</p></Field>
                        )}
                        {item && <AsOfRunNote item={item} />}
                      </div>

                      <div className="space-y-4 min-w-0">
                        {/* the code dialog's Suggested fix / OWASP Top 10 / Compliance controls: the /assets item's fields
                            (W2b), else the same facts from the asset's knowledge-base entries */}
                        {steps.length > 0 && (
                          <div className="rounded-xl border border-blue-200 bg-blue-50/60 p-3 dark:border-blue-900 dark:bg-blue-950/30">
                            <Field infoId="cbom.run.f.suggested_fix" label={steps.length > 1 ? `Suggested fix · ${steps.length} steps` : "Suggested fix"}>
                              <ol className="list-decimal space-y-1 pl-5 text-sm text-zinc-700 dark:text-zinc-300" data-testid="run-finding-suggested-fix">
                                {steps.map((s) => <li key={s} className="whitespace-pre-wrap break-words">{s}</li>)}
                              </ol>
                              {issues.length > 0 && <p className="mt-1.5 text-[11px] text-zinc-500">Each step is an issue&apos;s stored fix; platform commands are in the Issues tab.</p>}
                            </Field>
                          </div>
                        )}
                        {(chips.owasp.length > 0 || groups.length > 0) && (
                          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                            {chips.owasp.length > 0 && (
                              <div className="rounded-lg border border-zinc-200 dark:border-zinc-800 p-2.5 min-w-0">
                                <Field infoId="cbom.run.f.owasp" label="OWASP Top 10">
                                  <div className="flex flex-wrap gap-1" data-testid="run-finding-owasp">
                                    {chips.owasp.map(([key, value]) => (
                                      <Badge key={key} variant="secondary" className="text-xs whitespace-normal max-w-full text-left bg-purple-100 dark:bg-purple-900/40 text-purple-800 dark:text-purple-200">
                                        {OWASP_KEY_TO_LABEL[key] ?? value}
                                      </Badge>
                                    ))}
                                  </div>
                                </Field>
                              </div>
                            )}
                            {groups.length > 0 && (
                              <div className="rounded-lg border border-zinc-200 dark:border-zinc-800 p-2.5 min-w-0">
                                <Field infoId="cbom.run.f.compliance" label="Compliance controls">
                                  <div className="space-y-2" data-testid="run-finding-controls">
                                    {groups.map((g) => (
                                      <div key={g.framework}>
                                        <div className="text-[11px] text-zinc-500 dark:text-zinc-400">{g.framework}</div>
                                        <div className="flex flex-wrap gap-1">
                                          {g.items.map((c) => (
                                            <Badge key={c.key} variant="outline" className="text-xs whitespace-normal max-w-full text-left">{c.label}</Badge>
                                          ))}
                                        </div>
                                      </div>
                                    ))}
                                  </div>
                                </Field>
                              </div>
                            )}
                          </div>
                        )}
                        {item && (
                          <Field infoId="cbom.run.f.origin" label="Where it came from">
                            {evidenceCodes(item.finding_codes, details).length > 0 && (
                              <ul className="mb-1.5 space-y-1" data-testid="run-finding-evidence">
                                {evidenceCodes(item.finding_codes, details).map((c) => (
                                  <li key={c.code} className="flex items-center justify-between gap-2 rounded-md border border-zinc-200 dark:border-zinc-800 px-2.5 py-1.5 text-xs">
                                    <span className="text-zinc-700 dark:text-zinc-300 min-w-0 break-words">{c.title ?? "Finding code"}</span>
                                    <Badge variant="outline" className="font-mono text-[10px] shrink-0">{c.code}</Badge>
                                  </li>
                                ))}
                              </ul>
                            )}
                            <p className="text-sm text-zinc-700 dark:text-zinc-300" data-testid="run-finding-provenance">
                              Source {item.source_name ?? "—"}
                              {" · "}{job ? (job.runner === "cloud" ? "ZeroShield cloud" : `scan node ${job.node_name ?? "—"}`) : "scan node —"}
                              {" · "}job #{item.job_id}
                              {item.finding_codes.length > 0 ? ` · ${item.finding_codes.join(", ")}` : ""}
                            </p>
                          </Field>
                        )}
                        {item && <CollectedFacts item={item} />}
                      </div>
                    </div>
                  </TabsContent>

                  {/* ------------------------------------------------------------------ Issues */}
                  <TabsContent value="issues" forceMount className="mt-0 data-[state=inactive]:hidden space-y-3" data-testid="run-finding-issues-tab">
                    <h3 className="flex items-center gap-1 text-sm font-semibold text-zinc-800 dark:text-zinc-200">Issues the knowledge base explains <InfoTip id="cbom.run.f.finding" /></h3>
                    <WithDetail q={detailQ}>{(a) => <KbFindingDetails details={a.details} variant="steps" />}</WithDetail>
                  </TabsContent>

                  {/* ------------------------------------------------------------------ Quantum & effort */}
                  <TabsContent value="quantum" forceMount className="mt-0 data-[state=inactive]:hidden" data-testid="run-finding-quantum-tab">
                    <WithDetail q={detailQ}>
                      {(a) => (
                        <div className="space-y-3" data-testid={`asset-detail-${a.id}`}>
                          <AssetClassChips a={a} />
                          <AssetQuantumParts teamId={teamId} a={a} />
                        </div>
                      )}
                    </WithDetail>
                  </TabsContent>

                  {/* ------------------------------------------------------------------ Standards (once, #266) */}
                  <TabsContent value="standards" forceMount className="mt-0 data-[state=inactive]:hidden space-y-3" data-testid="run-finding-standards-tab">
                    <h3 className="flex items-center gap-1 text-sm font-semibold text-zinc-800 dark:text-zinc-200">Clauses and standards these issues map to <InfoTip id="cbom.run.f.compliance" /></h3>
                    <WithDetail q={detailQ}>{(a) => <StandardsTabs details={a.details} />}</WithDetail>
                  </TabsContent>

                  {/* ------------------------------------------------------------------ Fix & demo */}
                  <TabsContent value="fix" forceMount className="mt-0 data-[state=inactive]:hidden space-y-2" data-testid="run-finding-fix-tab">
                    <h3 className="flex items-center gap-1 text-sm font-semibold text-zinc-800 dark:text-zinc-200">Fix code, diff and exploit demo <InfoTip id="cbom.run.f.suggested_fix" /></h3>
                    {/* the code page's "Remediation, fix code and exploit demo" panel (Fix code / Diff / Exploit demo), from
                        GET /runs/{id}/assets/{asset}/remediation; on an older backend a one-line note. Its Standards tab
                        would repeat this dialog's Standards tab (#266) */}
                    <RemediationPanel key={`rem-${assetId}`} teamId={String(teamId)} scanType="cbom" scanId={0} findingId={String(assetId)}
                                      runAsset={{ runId, assetId }} standardsTab={false} layout="cards"
                                      missingNote={<p className="text-xs text-zinc-500" data-testid="run-finding-fix-missing">This server does not provide fix code or an exploit demo for collected assets yet; the fix steps and verify commands are in the Issues tab.</p>} />
                  </TabsContent>

                  {/* ------------------------------------------------------------------ AI */}
                  <TabsContent value="ai" forceMount className="mt-0 data-[state=inactive]:hidden" data-testid="run-finding-ai-tab">
                    <div className="rounded-xl border border-violet-200 dark:border-violet-900 bg-violet-50/50 dark:bg-violet-950/20 p-4 space-y-2">
                      <h3 className="flex items-center gap-1.5 text-sm font-semibold text-zinc-800 dark:text-zinc-200">
                        <Sparkles className="h-4 w-4 text-violet-600 dark:text-violet-400" aria-hidden="true" /> AI assistant <InfoTip id="cbom.ai.panel" />
                      </h3>
                      {aiOn ? (
                        <>
                          <p className="text-xs text-zinc-600 dark:text-zinc-400">Explain this finding, plan the fix or ask a question; answers are checked against the knowledge base.</p>
                          <Button ref={aiButton} type="button" size="sm" className="gap-1.5 cursor-pointer" aria-expanded={aiOpen}
                                  aria-controls="run-finding-ai-sheet" data-testid="run-finding-ai-open" onClick={() => setAiOpen(true)}>
                            <Sparkles className="h-3.5 w-3.5" aria-hidden="true" /> Open AI assistant
                          </Button>
                        </>
                      ) : (
                        <p className="text-xs text-zinc-500" data-testid="run-finding-ai-off">
                          {aiStatus.isLoading ? "Checking whether the AI assistant is available…" : "The AI assistant is not available on this deployment; the knowledge-base fix in the other tabs needs no model."}
                        </p>
                      )}
                    </div>
                  </TabsContent>
                </div>
              </div>
            )}

            {/* ------------------------------------------------------------------ footer (24-C) */}
            <div className="flex shrink-0 flex-wrap items-center justify-between gap-2 border-t border-zinc-200 dark:border-zinc-800 px-4 sm:px-6 py-2.5"
                 data-testid="run-finding-footer">
              <div className="flex flex-wrap items-center gap-2">
                {nav && (
                  <>
                    <Button type="button" variant="outline" size="sm" className="h-8 gap-1 cursor-pointer" disabled={!canGo(nav, -1)}
                            onClick={() => go(-1)} data-testid="run-finding-prev" aria-label="Previous finding">
                      <ChevronLeft className="h-4 w-4" aria-hidden="true" /> Previous
                    </Button>
                    <Button type="button" variant="outline" size="sm" className="h-8 gap-1 cursor-pointer" disabled={!canGo(nav, 1)}
                            onClick={() => go(1)} data-testid="run-finding-next" aria-label="Next finding">
                      Next <ChevronRight className="h-4 w-4" aria-hidden="true" />
                    </Button>
                    <span className="text-xs text-zinc-500 dark:text-zinc-400" data-testid="run-finding-position" aria-live="polite">
                      {nav.pageEdge ? `Loading the ${nav.pageEdge === "next" ? "next" : "previous"} page…` : position ?? ""}
                      <span className="hidden md:inline">{" · "}← → to move · Esc to close</span>
                    </span>
                  </>
                )}
              </div>
              <div className="flex flex-wrap items-center gap-2">
                {onSetStatus && item && item.type !== "coverage" && (
                  <span className="inline-flex items-center gap-0.5">
                    <DropdownMenu>
                      {/* infotip-shared: the Status fact's (i) in the Overview explains the finding status */}
                      <DropdownMenuTrigger asChild>
                        <Button type="button" variant="outline" size="sm" className="h-8 gap-1.5 cursor-pointer" disabled={!statusKey}
                                title={statusKey ? undefined : "This row has no stable key to track a status"}
                                data-testid="run-finding-status-action" aria-label="Set finding status">
                          <Pencil className="h-3.5 w-3.5 opacity-70" aria-hidden="true" /> Set status
                        </Button>
                      </DropdownMenuTrigger>
                      <DropdownMenuContent align="end">
                        {FINDING_STATUSES.map((s) => (
                          <DropdownMenuItem key={s} className="cursor-pointer" disabled={statusPending || s === status}
                                            data-testid={`run-finding-status-${s}`}
                                            onClick={() => statusKey && onSetStatus([statusKey], s)}>
                            Mark as {FINDING_STATUS_LABEL[s]}
                          </DropdownMenuItem>
                        ))}
                      </DropdownMenuContent>
                    </DropdownMenu>
                  </span>
                )}
                <Button type="button" variant="ghost" size="sm" className="h-8 cursor-pointer" onClick={onClose} data-testid="run-finding-close">Close</Button>
              </div>
            </div>
          </Tabs>

          {/* AI assistant panel (35-B): inside the dialog, mounted while the dialog is open (answers survive closing it
              and switching tabs), keyed by asset */}
          {assetId != null && aiOn && (
            <aside id="run-finding-ai-sheet" hidden={!aiOpen} aria-label="AI assistant" data-testid="run-finding-ai-sheet"
                   className="absolute inset-y-0 right-0 z-30 flex w-full sm:w-[400px] flex-col border-l border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-950 shadow-2xl">
              <div className="flex items-center justify-between gap-2 border-b border-zinc-200 dark:border-zinc-800 px-4 py-3">
                <span className="text-sm font-semibold text-zinc-900 dark:text-zinc-100 truncate">AI assistant · {title}</span>
                <Button ref={aiClose} type="button" variant="ghost" size="sm" className="h-7 w-7 p-0 cursor-pointer" aria-label="Close AI assistant"
                        onClick={closeAi} data-testid="run-finding-ai-close">
                  <X className="h-4 w-4" />
                </Button>
              </div>
              <div className="min-h-0 flex-1 overflow-y-auto overscroll-contain p-4 space-y-3">
                {/* AI remediation assistant (CB-38 PR-6), an addition to the knowledge-base fix; nothing when it is off */}
                <AiRemediationPanel key={`ai-${assetId}`} teamId={teamId} subject={{ kind: "run_asset", assetId }} />
                {item && <CollectedFacts item={item} />}
              </div>
            </aside>
          )}
        </InfoTipDrawerProvider>
      </DialogContent>
    </Dialog>
  );
}
