"use client";

// Sections of the Sources run results page (CB-38 PR-1c) that are not the header, the findings table or the finding
// dialog. Each takes API payloads as they are; a section without data says so in one line (`SectionNote`).
// Rule P: no section here counts rows. Figures come from /runs/{id} (jobs), /posture, /results and /remediation.

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useEffect, useId, useRef, useState, type ReactNode } from "react";
import { BadgeCheck, ChevronDown, ChevronRight, Download, GitCompare, Info, Loader2, Network, Server, SlidersHorizontal, Timer, Waypoints } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { ScrollArea, ScrollBar } from "@/components/ui/scroll-area";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { downloadCbomRunCbom, verifyCbomRunSignature, type CbomCertRef, type CbomJobTargets, type CbomRun, type CbomRunResults } from "@/utils/backend_api";
import { downloadCbomRunBom } from "@/utils/api/cbom_outputs";
import { downloadOscal } from "@/utils/api/integrations";

import { DiffView, RunChanges } from "@/components/cbom/sources/ChangesPanel";
import { cbomOpsKeys, getCbomRunDiff, type CbomRemediationItem } from "@/utils/api/cbom_ops";
import { useQuery } from "@tanstack/react-query";
import { TERMINAL_RUN } from "@/components/cbom/sources/keys";
import { credits, formatDateTime, formatDay, pluralize } from "@/components/cbom/sources/logic";
import { LabModeBanner } from "@/components/cbom/sources/LabModeBanner";
import { TargetsBlock } from "@/components/cbom/sources/RunResults";
import { EmptyState, RunStatusBadge, RunStatusReason, StatusBadge, Truncate, type Tone } from "@/components/cbom/sources/shared";

import { CbomDashboardCharts, type DashboardChartPart } from "./CbomDashboardCharts";
import { WaveLegend } from "./WaveLegend";
import { waveLegend } from "./readinessExplain";
import {
  certCountText,
  certListView,
  formatDuration,
  isActiveRunStatus,
  verifyResultText,
  waveChips,
  type RunDashboardModel,
  type SectionView,
} from "./model";
import RunDeliverablesMenu from "./RunDeliverablesMenu";
import { runTriggerLabel } from "./resultRows";
import { RunJobsTable, SkippedAtStart } from "./RunJobsTable";
import { RunSourceCards } from "./RunSourceCards";
import { toast } from "@/utils/toast";
import { showErrorToast } from "@/utils/error-handler";
import { Badge } from "@/components/ui/badge";
import { InfoTip } from "@/components/ui/info-tip";
import type { InfoTipId } from "@/content/infotips";

/** Bounds the Radix viewport (not the root, which grows with its content). Read by results/scrollBounds.test.ts. */
export const VIEWPORT_MAX_H_72 = "[&>[data-slot=scroll-area-viewport]]:max-h-72";

export function SectionNote({ children, testId }: { children: ReactNode; testId?: string }) {
  return (
    <p className="text-sm text-zinc-500 dark:text-zinc-400 flex items-start gap-1.5" data-testid={testId}>
      <Info className="h-4 w-4 shrink-0 mt-0.5" /> <span>{children}</span>
    </p>
  );
}

function SectionShell({ title, description, testId, children, actions, infoId }: {
  title: ReactNode; description?: ReactNode; testId: string; children: ReactNode; actions?: ReactNode;
  /** the (i) tip beside the title (required: the coverage test pairs every section title with a tip) */
  infoId: InfoTipId;
}) {
  return (
    <Card className="border-zinc-200 dark:border-zinc-800 min-w-0" data-testid={testId}>
      <CardHeader className="flex flex-row flex-wrap items-start justify-between gap-3">
        <div className="space-y-1.5 min-w-0">
          <CardTitle className="text-base">{title} <InfoTip id={infoId} /></CardTitle>
          {description && <CardDescription>{description}</CardDescription>}
        </div>
        {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
      </CardHeader>
      <CardContent className="min-w-0 space-y-4">{children}</CardContent>
    </Card>
  );
}

// ---------------------------------------------------------------------------- S0 header (in the code page's header)

/** The line under the title: run status, start / finish, credits, linked scan, sources, live note. */
export function RunHeaderMeta({ teamId, run, sources }: { teamId: number; run: CbomRun; sources: { id: number | null; name: string }[] }) {
  const active = isActiveRunStatus(run.status);
  return (
    <>
      <span data-testid="run-results-status"><RunStatusBadge status={run.status} reason={run.status_reason} /></span>
      <span>Started {formatDateTime(run.created_at)}</span>
      {/* the badge says queued or running; no second state word beside it (staging QA2 Q1-13) */}
      {run.finished_at ? <span>Finished {formatDateTime(run.finished_at)}</span> : null}
      <span data-testid="run-results-credits">{credits(run.credits?.charged)} credits charged, {credits(run.credits?.refunded)} refunded</span>
      {runTriggerLabel(run) && (
        <span data-testid="run-results-trigger" className="inline-flex items-center gap-1">
          {run.trigger === "scheduled" ? <Timer className="h-3.5 w-3.5" aria-hidden /> : null}
          {runTriggerLabel(run)}
        </span>
      )}
      {run.scan_id != null && (
        <Link href={`/${teamId}/cbom/${run.scan_id}`} className="text-blue-600 dark:text-blue-400 hover:underline" data-testid="run-results-linked-scan">
          Linked scan #{run.scan_id}
        </Link>
      )}
      {sources.length > 0 && (
        <span className="flex flex-wrap gap-1.5 basis-full" data-testid="run-results-sources">
          {sources.map((s) => (
            <Badge key={`${s.id ?? "x"}-${s.name}`} variant="outline" className="border-zinc-300 text-zinc-600 dark:border-zinc-700 dark:text-zinc-400 max-w-[260px] truncate">
              <Network className="h-3 w-3 mr-1" /> {s.name}
            </Badge>
          ))}
        </span>
      )}
      {run.status_reason && (
        <span className="basis-full" data-testid="run-results-status-reason-line">
          <RunStatusReason reason={run.status_reason} testId="run-results-status-reason" />
        </span>
      )}
      {active && (
        <span className="basis-full text-xs text-zinc-500" data-testid="run-results-live">
          The run is still collecting: this page updates every few seconds and the downloads hold what was collected so far.
        </span>
      )}
    </>
  );
}

/** The run's buttons in the code page's header row: its CycloneDX JSON / XML and OSCAL (test ids kept for the gate),
 * Compare…, and "Open in CBOM Sources" where a code scan has "Scan settings". */
export function RunHeaderActions({ teamId, run, assetTotal, canCompare, onCompare, children }: {
  teamId: number; run: CbomRun; assetTotal: number | null; canCompare: boolean; onCompare: () => void;
  /** more download buttons (the run deliverables) */
  children?: ReactNode;
}) {
  const router = useRouter();
  const [busy, setBusy] = useState<string | null>(null);
  const active = isActiveRunStatus(run.status);
  const empty = assetTotal === 0;
  const go = (id: string, fn: () => Promise<unknown>) => async () => {
    setBusy(id);
    try { await fn(); } catch { /* the download helpers showed the error */ } finally { setBusy(null); }
  };
  const downloads = [
    { id: "run-results-download", label: `CycloneDX JSON${active ? " (so far)" : ""}`, title: "The run's CycloneDX 1.6 CBOM as JSON",
      disabled: empty, run: go("run-results-download", () => downloadCbomRunCbom(teamId, run.id)) },
    { id: "run-results-download-xml", label: "CycloneDX XML", title: "The same CycloneDX 1.6 CBOM as XML, valid against the official schema",
      disabled: empty, run: go("run-results-download-xml", () => downloadCbomRunBom(teamId, run.id, "xml")) },
    { id: "run-results-download-oscal", label: "OSCAL", title: active ? "Available when the run has finished" : "OSCAL 1.2.3 assessment results for a GRC tool (validated against the official schema)",
      disabled: active, run: go("run-results-download-oscal", () => downloadOscal(teamId, { runId: run.id })) },
  ];
  return (
    <div className="flex items-center gap-2 flex-wrap lg:justify-end" data-testid="run-results-header-actions">
      {/* mockup F1: one "Export" menu holds the seven downloads (each keeps its own hover text); both tips stay beside it */}
      <ExportMenu tips={<><InfoTip id="cbom.run.downloads" /><InfoTip id="cbom.run.deliverables" /></>}>
        {downloads.map((d) => (
          <Button key={d.id} variant="outline" className="cursor-pointer" title={d.title} disabled={d.disabled || busy === d.id}
                  data-testid={d.id} onClick={() => void d.run()}>
            {busy === d.id ? <Loader2 className="h-4 w-4 mr-2 animate-spin" /> : <Download className="h-4 w-4 mr-2" />}
            {d.label}
          </Button>
        ))}
        {/* VEX, Signature, Evidence pack, PDF Report (CB-38 PR-8), as on the code page's header */}
        <RunDeliverablesMenu teamId={teamId} runId={run.id} active={active} tip={false} />
      </ExportMenu>
      <RunVerifyButton teamId={teamId} runId={run.id} />
      {children}
      {canCompare && (
        <Button variant="outline" className="cursor-pointer" onClick={onCompare} data-testid="run-results-compare">
          <GitCompare className="h-4 w-4 mr-2" /> Compare…
        </Button>
      )}
      <Button variant="default" className="cursor-pointer bg-blue-600 hover:bg-blue-700 text-white"
              onClick={() => router.push(`/${teamId}/cbom/sources?tab=review`)} data-testid="run-results-open-sources">
        <SlidersHorizontal className="h-4 w-4 mr-2" /> Open in CBOM Sources
      </Button>
    </div>
  );
}

/** "Export ▾": a disclosure (not a Radix menu) so the download buttons stay mounted and keep their test ids, titles and
 * order; it closes on Escape, an outside click and after a download is started. */
function ExportMenu({ children, tips }: { children: ReactNode; tips: ReactNode }) {
  const ref = useRef<HTMLDetailsElement>(null);
  useEffect(() => {
    const close = (e: Event) => {
      const el = ref.current;
      if (!el?.open) return;
      if (e instanceof KeyboardEvent ? e.key === "Escape" : !el.contains(e.target as Node)) {
        el.open = false;
        if (e instanceof KeyboardEvent) el.querySelector("summary")?.focus();
      }
    };
    document.addEventListener("pointerdown", close);
    document.addEventListener("keydown", close);
    return () => {
      document.removeEventListener("pointerdown", close);
      document.removeEventListener("keydown", close);
    };
  }, []);
  return (
    <span className="inline-flex items-center gap-1">
      <details ref={ref} className="relative group" data-testid="run-results-export">
        <summary className="list-none [&::-webkit-details-marker]:hidden inline-flex h-9 items-center gap-2 rounded-md border border-zinc-200 dark:border-zinc-700 bg-white dark:bg-zinc-900 px-4 text-sm font-medium cursor-pointer hover:bg-zinc-50 dark:hover:bg-zinc-800 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500">
          <Download className="h-4 w-4" aria-hidden /> Export <ChevronDown className="h-4 w-4 transition-transform group-open:rotate-180" aria-hidden />
        </summary>
        <div className="absolute left-0 z-40 mt-1 flex w-64 flex-col gap-1 rounded-lg border border-zinc-200 dark:border-zinc-700 bg-white dark:bg-zinc-900 p-1.5 shadow-lg [&>button]:w-full [&>button]:justify-start [&>button]:border-0 [&>button]:shadow-none"
             onClick={(e) => { if ((e.target as HTMLElement).closest("button")) ref.current?.removeAttribute("open"); }}>
          {children}
        </div>
      </details>
      {tips}
    </span>
  );
}

/** "Verify file…": checks a downloaded CycloneDX JSON of this run against its signature (ES256 with the published key;
 * files signed earlier with the HMAC key are checked on the server). */
export function RunVerifyButton({ teamId, runId }: { teamId: number; runId: number }) {
  const input = useRef<HTMLInputElement>(null);
  const [busy, setBusy] = useState(false);
  const verify = async (file: File | undefined) => {
    if (!file) return;
    setBusy(true);
    try {
      const out = await verifyCbomRunSignature(teamId, runId, file);
      if (out.valid) toast.success(verifyResultText(out));
      else toast.error(verifyResultText(out));
    } catch (err) {
      showErrorToast(err, "Could not verify the file");
    } finally {
      setBusy(false);
      if (input.current) input.current.value = "";
    }
  };
  return (
    <>
      <input ref={input} type="file" accept=".json,application/json" className="hidden" data-testid="run-verify-signature-file"
             onChange={(e) => void verify(e.target.files?.[0])} />
      <Button variant="outline" className="cursor-pointer" disabled={busy} data-testid="run-verify-signature"
              title="Check a downloaded CycloneDX JSON of this run against its signature (also verifiable offline with the published key)"
              onClick={() => input.current?.click()}>
        {busy ? <Loader2 className="h-4 w-4 mr-2 animate-spin" /> : <BadgeCheck className="h-4 w-4 mr-2" />}
        Verify file…
      </Button>
      <InfoTip id="cbom.run.verify" />
    </>
  );
}

export function RunNotFound({ teamId }: { teamId: number }) {
  return (
    <div className="flex min-h-[60vh] w-full flex-col items-center justify-center gap-3 px-6 text-center" data-testid="run-results-not-found">
      <p className="text-lg font-semibold text-zinc-900 dark:text-white">Run not found</p>
      <p className="text-sm text-zinc-600 dark:text-zinc-400 max-w-md">This CBOM Sources run does not exist or belongs to another team.</p>
      <a href={`/${teamId}/cbom`} className="text-sm text-blue-600 dark:text-blue-400 hover:underline">Back to CBOM scans</a>
    </div>
  );
}

// ---------------------------------------------------------------------------- S1 what was covered
/** 03-B: one card per source (RunSourceCards), the sources skipped at the start and each target's outcome; the full
 * jobs and provenance tables (every column and tip as before) behind "Show the full jobs and provenance tables". */
export function RunCoverageSection({ run, targets, provenance }: {
  run: CbomRun;
  targets: CbomJobTargets[] | null;
  provenance: CbomRunResults["provenance"] | null | undefined;
}) {
  const jobs = run.jobs ?? [];
  const skipped = run.breakdown?.skipped ?? [];
  const [tables, setTables] = useState(false);
  const tablesId = useId();
  return (
    <SectionShell infoId="cbom.run.covered" title="Jobs by source" testId="run-section-coverage"
                  description="Every job of the run with where it ran and how it ended, the sources skipped at the start, and each target's outcome">
      {/* lab mode (test deployments): the run-level note, the same component as the AWS form's; each job keeps its badge */}
      {targets?.some((job) => job.lab_mode) && (
        <LabModeBanner testId="run-lab-mode" detail="An AWS source in this run was read from the deployment's own AWS account." />
      )}
      {jobs.length === 0 ? <EmptyState title="No jobs in this run" /> : <RunSourceCards jobs={jobs} provenance={provenance} targets={targets} />}
      <SkippedAtStart items={skipped} />
      {targets ? <TargetsBlock jobs={targets} /> : null}
      {(jobs.length > 0 || (provenance && provenance.length > 0)) && (
        <div className="space-y-3">
          <button type="button" className="inline-flex items-center gap-1 text-sm text-blue-600 dark:text-blue-400 cursor-pointer hover:underline"
                  aria-expanded={tables} aria-controls={tablesId} onClick={() => setTables(!tables)} data-testid="run-coverage-tables-toggle">
            {tables ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
            {tables ? "Hide" : "Show"} the full jobs and provenance tables
          </button>
          <div id={tablesId} className="space-y-4" hidden={!tables} data-testid="run-coverage-tables">
            {tables && (
              <>
                {jobs.length > 0 && <RunJobsTable jobs={jobs} testIdPrefix="run-job" />}
                {provenance && provenance.length > 0 && (
                  <div className="space-y-1.5" data-testid="run-provenance">
                    <p className="text-sm font-medium text-zinc-900 dark:text-white">Provenance per source <InfoTip id="cbom.run.provenance" /></p>
                    <ScrollArea className="w-full border rounded-lg">
                      <div className="min-w-max">
                        <Table>
                          <TableHeader>
                            <TableRow>
                              <TableHead>Source <InfoTip id="cbsrc.rr.job.source" /></TableHead>
                              <TableHead>Kind <InfoTip id="cbom.run.col.kind" /></TableHead>
                              <TableHead>Runs on <InfoTip id="cbsrc.rr.job.runs_on" /></TableHead>
                              <TableHead>Outcome <InfoTip id="cbom.run.col.outcome" /></TableHead>
                              <TableHead className="text-right" title="Collected assets; the jobs table above also counts the Not collected rows">Assets (excl. not collected) <InfoTip id="cbom.run.col.assets_collected" /></TableHead>
                              <TableHead className="text-right">Endpoints probed <InfoTip id="cbom.run.col.endpoints" /></TableHead>
                              <TableHead className="text-right">Duration <InfoTip id="cbom.run.col.duration" /></TableHead>
                              <TableHead className="text-right">Credits <InfoTip id="cbom.run.col.credits" /></TableHead>
                            </TableRow>
                          </TableHeader>
                          <TableBody>
                            {provenance.map((p, i) => (
                              <TableRow key={`${p.source_id ?? "x"}-${i}`} data-testid={`run-provenance-${p.source_id ?? i}`}>
                                <TableCell className="max-w-[220px]"><Truncate text={p.source ?? (p.source_id != null ? `Source ${p.source_id}` : "—")} /></TableCell>
                                <TableCell className="text-zinc-600 dark:text-zinc-400">{p.kind ?? "—"}</TableCell>
                                <TableCell className="text-zinc-600 dark:text-zinc-400 max-w-[180px]">
                                  <Truncate text={p.runner === "cloud" ? "ZeroShield cloud" : p.node ?? "—"} />
                                </TableCell>
                                <TableCell className="text-zinc-600 dark:text-zinc-400">{p.outcome ?? "—"}</TableCell>
                                <TableCell className="text-right tabular-nums">{p.assets}</TableCell>
                                <TableCell className="text-right tabular-nums">{p.endpoints_probed}</TableCell>
                                <TableCell className="text-right tabular-nums">{formatDuration(p.duration_s)}</TableCell>
                                <TableCell className="text-right tabular-nums">{p.credits ?? "—"}</TableCell>
                              </TableRow>
                            ))}
                          </TableBody>
                        </Table>
                      </div>
                      <ScrollBar orientation="horizontal" />
                    </ScrollArea>
                  </div>
                )}
              </>
            )}
          </div>
        </div>
      )}
    </SectionShell>
  );
}

// ---------------------------------------------------------------------------- S3 metadata cards
export function RunMetaCards({ sources, nodes, endpoints, duration }: {
  sources: number; nodes: string[]; endpoints: number | null; duration: number | null;
}) {
  const cards = [
    { label: "Sources", value: String(sources), icon: Waypoints, box: "bg-violet-100 dark:bg-violet-900/30 text-violet-600 dark:text-violet-400", testId: "run-meta-sources" },
    { label: "Scan nodes", value: nodes.length ? nodes.join(", ") : "—", icon: Server, box: "bg-amber-100 dark:bg-amber-900/30 text-amber-600 dark:text-amber-400", testId: "run-meta-nodes" },
    { label: "Endpoints probed", value: endpoints == null ? "—" : endpoints.toLocaleString(), icon: Network, box: "bg-blue-100 dark:bg-blue-900/30 text-blue-600 dark:text-blue-400", testId: "run-meta-endpoints" },
    { label: "Duration", value: formatDuration(duration), icon: Timer, box: "bg-teal-100 dark:bg-teal-900/30 text-teal-600 dark:text-teal-400", testId: "run-meta-duration" },
  ];
  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4" data-testid="run-meta-cards">
      {cards.map(({ label, value, icon: Icon, box, testId }) => (
        <Card key={label} className="border-zinc-200 dark:border-zinc-800" data-testid={testId}>
          <CardContent className="pt-4 pb-4 flex items-center gap-3">
            <div className={`flex h-10 w-10 shrink-0 items-center justify-center rounded-lg ${box}`}>
              <Icon className="h-5 w-5" />
            </div>
            <div className="min-w-0">
              <p className="text-xs font-medium text-zinc-500 dark:text-zinc-400">{label}</p>
              <p className="text-lg font-semibold text-zinc-900 dark:text-zinc-100 truncate" title={value}>{value}</p>
            </div>
          </CardContent>
        </Card>
      ))}
    </div>
  );
}

// ---------------------------------------------------------------------------- S6 orphaned / unmanaged certificates
function CertTable({ title, label, count, certs, testId, onOpenAsset, infoId }: {
  title: string; label: string | null; count: string; certs: CbomCertRef[]; testId: string; onOpenAsset: (id: number) => void; infoId: InfoTipId;
}) {
  return (
    <div className="space-y-1.5 min-w-0" data-testid={testId}>
      <p className="text-sm font-medium text-zinc-900 dark:text-white">
        {title} <span className="text-zinc-500 font-normal" data-testid={`${testId}-count`}>({count})</span> <InfoTip id={infoId} />
      </p>
      {label && <p className="text-xs text-zinc-500">{label}</p>}
      {certs.length === 0 ? (
        <p className="text-xs text-zinc-500">None in this run.</p>
      ) : (
        // The height limit goes on the Radix viewport: on the root it does not bound the scrolling box (R-qa).
        <ScrollArea className={`w-full border rounded-lg ${VIEWPORT_MAX_H_72}`} data-testid={`${testId}-scroll`}>
          <div className="min-w-max">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Subject <InfoTip id="cbom.run.cert.subject" /></TableHead>
                  <TableHead>Issuer <InfoTip id="cbom.run.cert.issuer" /></TableHead>
                  <TableHead>Expires <InfoTip id="cbom.run.cert.expires" /></TableHead>
                  <TableHead>Location <InfoTip id="cbom.run.cert.location" /></TableHead>
                  <TableHead>Source <InfoTip id="cbom.run.cert.source" /></TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {certs.map((c) => (
                  <TableRow key={c.asset_id} data-testid={`${testId}-${c.asset_id}`}>
                    <TableCell className="max-w-[240px]">
                      <button type="button" className="text-left text-blue-600 dark:text-blue-400 hover:underline cursor-pointer max-w-[240px] truncate block"
                              title={c.subject ?? undefined} onClick={() => onOpenAsset(c.asset_id)}>
                        {c.subject ?? `Asset ${c.asset_id}`}
                      </button>
                    </TableCell>
                    <TableCell className="max-w-[200px]"><Truncate text={c.issuer} className="text-zinc-600 dark:text-zinc-400" /></TableCell>
                    <TableCell className="whitespace-nowrap text-zinc-600 dark:text-zinc-400">{c.not_after ? formatDay(c.not_after.slice(0, 10)) : "—"}</TableCell>
                    <TableCell className="max-w-[260px]"><Truncate text={c.location} className="font-mono text-xs" /></TableCell>
                    <TableCell className="max-w-[180px]"><Truncate text={c.source} className="text-zinc-600 dark:text-zinc-400" /></TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
          <ScrollBar orientation="horizontal" />
        </ScrollArea>
      )}
    </div>
  );
}

const CERTS_DESCRIPTION = "Within this run's scope: orphaned = stored but presented by no endpoint the run read; unmanaged = held by no managing system the run saw (ACM, cert-manager, AD CS, Key Vault, Certificate Manager)";

/** `bare`: without its own card (the run page's CertificatesCard tab): the title with its tip, the description and the
 * same lists, notes and hooks. */
export function RunCertificatesSection({ view, results, onOpenAsset, bare }: {
  view: SectionView; results: CbomRunResults | null; onOpenAsset: (id: number) => void; bare?: boolean;
}) {
  if (!view.show) return null;
  const orphaned = results?.certificates_orphaned ?? null;
  const unmanaged = results?.certificates_unmanaged ?? null;
  const o = certListView(results, "orphaned");
  const u = certListView(results, "unmanaged");
  const body = (
    <>
      {view.note && <SectionNote testId="run-certificates-note">{view.note}</SectionNote>}
      {(orphaned?.length || unmanaged?.length) ? (
        <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
          <CertTable infoId="cbom.run.certs.orphaned" title="Orphaned certificates" label={o.label} count={certCountText(o)} certs={orphaned ?? []} testId="run-certs-orphaned" onOpenAsset={onOpenAsset} />
          <CertTable infoId="cbom.run.certs.unmanaged" title="Unmanaged certificates" label={u.label} count={certCountText(u)} certs={unmanaged ?? []} testId="run-certs-unmanaged" onOpenAsset={onOpenAsset} />
        </div>
      ) : null}
    </>
  );
  if (bare) {
    return (
      <div className="space-y-4 min-w-0" data-testid="run-section-certificates" data-bare="true">
        <div className="space-y-1">
          <p className="text-sm font-semibold text-zinc-900 dark:text-white">Orphaned and unmanaged certificates <InfoTip id="cbom.run.certs" /></p>
          <p className="text-sm text-zinc-500 dark:text-zinc-400">{CERTS_DESCRIPTION}</p>
        </div>
        {body}
      </div>
    );
  }
  return (
    <SectionShell infoId="cbom.run.certs" title="Orphaned and unmanaged certificates" testId="run-section-certificates"
                  description={CERTS_DESCRIPTION}>
      {body}
    </SectionShell>
  );
}

// ---------------------------------------------------------------------------- S8 changes
export function RunChangesSection({ teamId, run, canCompare, onCompare }: { teamId: number; run: CbomRun; canCompare: boolean; onCompare: () => void }) {
  return (
    <SectionShell infoId="cbom.run.changes" title="Changes" testId="run-section-changes"
                  description="Drift against each source's previous complete collection"
                  actions={canCompare ? (
                    <button type="button" className="text-sm text-blue-600 dark:text-blue-400 cursor-pointer hover:underline" onClick={onCompare}>
                      Compare with another run…
                    </button>
                  ) : undefined}>
      <RunDiffBlock teamId={teamId} runId={run.id} />
      <RunChanges teamId={teamId} runId={run.id} finished={TERMINAL_RUN.has(run.status)} />
    </SectionShell>
  );
}

/** The code page's CodeChanges block for a run: the same collapsible DiffView (resolved / opened / added / removed /
 * changed, readiness delta, rule changes, not read), over GET /runs/{id}/diff against the previous complete run. The
 * run's drift events (opened, resolved, renewed, expiring ...) are listed below it from /changes, which the run page
 * has always used and which W2b's /diff ``events`` duplicate. */
export function RunDiffBlock({ teamId, runId }: { teamId: number; runId: number }) {
  const [open, setOpen] = useState(false);
  const q = useQuery({ queryKey: cbomOpsKeys.diff(teamId, runId, undefined), queryFn: () => getCbomRunDiff(teamId, runId), enabled: open, retry: 1 });
  return (
    <details className="rounded-lg border border-zinc-200 dark:border-zinc-800 p-4" data-testid="run-diff"
             onToggle={(e) => setOpen((e.target as HTMLDetailsElement).open)}>
      <summary className="cursor-pointer text-sm font-medium text-zinc-900 dark:text-white">
        Changes since the previous complete run of these sources
      </summary>
      <div className="mt-3">
        {!open ? null : q.isLoading ? <p className="text-xs text-zinc-500">Loading…</p> : q.isError || !q.data ? (
          <p className="text-xs text-zinc-500">The comparison could not be loaded.</p>
        ) : (
          <>
            {q.data.against_run_id && <p className="text-xs text-zinc-500 mb-2">Compared with run #{q.data.against_run_id}.</p>}
            <DiffView diff={q.data} />
          </>
        )}
      </div>
    </details>
  );
}

// ---------------------------------------------------------------------------- S9 remediation waves
const WAVE_TONE: Record<number, Tone> = { 1: "red", 2: "amber", 3: "blue", 4: "zinc" };
const WAVE_BAR: Record<string, string> = {
  "1": "bg-red-500", "2": "bg-amber-500", "3": "bg-blue-500", "4": "bg-zinc-400", none: "bg-emerald-500",
};
const WAVE_ITEMS_SHOWN = 3;

/** 13-A: one column per wave (Wave 1 to 4 and No action, in the legend's order, then any other wave the plan names)
 * with its count from the wave plan (by_wave, never recounted), its rule and, when the plan's items are given, the first
 * few assets in it. */
function WaveBoard({ byWave, labels, rules, items, onOpenAsset }: {
  byWave: Record<string, number>; labels?: Record<string, string>; rules?: Record<string, string>;
  items?: CbomRemediationItem[] | null; onOpenAsset?: (id: number) => void;
}) {
  const legend = waveLegend(byWave, rules, "run");
  const chips = waveChips(byWave);
  const columns = [
    ...legend.map((r) => ({ key: r.key, label: r.label, count: r.count, rule: r.rule as string | null, empty: r.empty,
                            wave: r.key === "none" ? null : Number(r.key) })),
    ...chips.filter((c) => !legend.some((r) => r.key === c.key))
      .map((c) => ({ key: c.key, label: c.label, count: c.count, rule: null, empty: "", wave: c.wave })),
  ];
  return (
    <ul className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 2xl:grid-cols-5 gap-3" data-testid="run-wave-board">
      {columns.map((c) => {
        const inWave = (items ?? []).filter((it) => (c.wave == null ? it.wave == null : it.wave === c.wave));
        const shown = inWave.slice(0, WAVE_ITEMS_SHOWN);
        const more = Math.max(0, c.count - shown.length);
        return (
          <li key={c.key} className="flex flex-col gap-2 rounded-xl border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 p-3 min-w-0"
              data-testid={`run-wave-column-${c.key}`} data-count={c.count}>
            <span className={`h-1 rounded-full ${WAVE_BAR[c.key] ?? "bg-zinc-300"}`} aria-hidden="true" />
            <div className="flex items-center justify-between gap-2" title={c.wave != null ? labels?.[String(c.wave)] : undefined}
                 data-testid={`run-wave-chip-${c.key}`}>
              <StatusBadge tone={c.wave != null ? WAVE_TONE[c.wave] ?? "zinc" : "zinc"} className="text-sm">{c.label}: {c.count}</StatusBadge>
            </div>
            {c.rule && <p className="text-xs text-zinc-600 dark:text-zinc-400">{c.rule}.</p>}
            {c.count === 0 ? (
              c.empty ? <p className="text-xs text-zinc-500 dark:text-zinc-400">{c.empty}</p> : null
            ) : shown.length > 0 ? (
              <ul className="space-y-1.5">
                {shown.map((it) => (
                  <li key={it.asset_key} className="rounded-md border border-zinc-200 dark:border-zinc-800 bg-zinc-50 dark:bg-zinc-950/60 px-2 py-1.5 text-xs min-w-0"
                      data-testid={`run-wave-item-${it.asset_id ?? it.asset_key}`}>
                    {it.asset_id != null && onOpenAsset ? (
                      <button type="button" className="text-left text-blue-600 dark:text-blue-400 hover:underline cursor-pointer break-all"
                              onClick={() => onOpenAsset(it.asset_id as number)}>
                        {it.label}
                      </button>
                    ) : (
                      <span className="text-zinc-800 dark:text-zinc-200 break-all">{it.label}</span>
                    )}
                    {it.impact && <span className="text-zinc-500 dark:text-zinc-400"> · {it.impact}</span>}
                  </li>
                ))}
              </ul>
            ) : null}
            {c.count > 0 && more > 0 && (
              <p className="text-xs text-zinc-500 dark:text-zinc-400" data-testid={`run-wave-more-${c.key}`}>
                {shown.length > 0 ? `+${more.toLocaleString()} more` : pluralize(c.count, "asset")}
              </p>
            )}
          </li>
        );
      })}
    </ul>
  );
}

export function RunWavesSection({ byWave, labels, rules, loading, deferred, selected, items, onOpenAsset }: {
  byWave: Record<string, number> | null | undefined; labels?: Record<string, string>; loading: boolean;
  /** what puts an asset in each wave (the backend's suggested_wave rules; issue #271) */
  rules?: Record<string, string>;
  /** an active run on a newer backend: the whole-run plan is not polled; each row shows its own wave */
  deferred: boolean;
  selected: number;
  /** the wave plan's items (GET …/remediation `items`): the board lists the first few assets of each wave */
  items?: CbomRemediationItem[] | null;
  /** opens an asset of the board in the finding dialog */
  onOpenAsset?: (id: number) => void;
}) {
  const chips = waveChips(byWave);
  return (
    <SectionShell infoId="cbom.run.waves" title="Remediation waves" testId="run-section-waves"
                  description="Who fixes what, by when. Plans follow each asset's stable identity, so they carry over to later runs">
      {deferred ? <SectionNote testId="run-waves-deferred">Wave counts for the whole run appear when it has finished; each row below shows its own wave meanwhile.</SectionNote>
        : loading ? <p className="text-xs text-zinc-500">Loading the wave plan…</p> : chips.length === 0 ? (
        <SectionNote>No asset of this run needs a remediation wave.</SectionNote>
      ) : (
        <WaveBoard byWave={byWave ?? {}} labels={labels} rules={rules} items={items} onOpenAsset={onOpenAsset} />
      )}
      <WaveLegend byWave={deferred || loading ? null : byWave} rules={rules} />
      <p className="text-xs text-zinc-500">
        {selected > 0
          ? `${pluralize(selected, "finding")} selected in the table below: set wave, owner, target date or status there.`
          : "Select findings in the table below to assign a wave, owner, target date or status."}
      </p>
    </SectionShell>
  );
}

// WaveLegend lives in WaveLegend.tsx (shared with the code scan's waves panel); re-exported for older imports
export { WaveLegend };
// the summary view's compact jobs line (gate hooks run-results-job-<id>) lives beside the source cards
export { RunJobsStatusLine } from "./RunSourceCards";

// S10 compliance mapping: ComplianceSummary.tsx (#270), on code scans and runs alike

// ---------------------------------------------------------------------------- S11 dashboard charts
export function RunDashboardSection({ view, model, riskRows, pageRows, results, parts, variant }: {
  view: SectionView;
  model: RunDashboardModel;
  riskRows: Parameters<typeof CbomDashboardCharts>[0]["findingsList"];
  /** rows on the findings table's current page (the per-finding chart plots those, and says so) */
  pageRows: number;
  results: CbomRunResults | null;
  /** passed to CbomDashboardCharts: the cards to render (default all) and the run layout (08-A uniform grid) */
  parts?: readonly DashboardChartPart[];
  variant?: "run";
}) {
  if (!view.show) return null;
  return (
    <div className="space-y-3" data-testid="run-section-dashboard">
      {model.dashboard && (
        <CbomDashboardCharts dashboard={model.dashboard} findingsList={riskRows} parts={parts} variant={variant}
                             riskScoresTitle={`Risk scores on this table page (${pageRows} rows)`} riskScoresTip="cbom.run.risk_scores" quantumTip="cbom.run.quantum"
                             riskScoresDescription="Risk score (0-10) of the rows on the findings table's current page and filter, top 24, descending" />
      )}
      {view.note && <SectionNote testId="run-dashboard-note">{view.note}</SectionNote>}
      {model.dashboard && results?.computed_at && (
        <p className="text-xs text-zinc-500" data-testid="run-dashboard-asof">
          As of {formatDateTime(results.computed_at)}{results.judged_on ? ` · judged on ${results.judged_on}` : ""}
          {results.stale ? " · refreshing" : ""}. Readiness, quantum-vulnerable and severity figures are the run posture&apos;s.
        </p>
      )}
    </div>
  );
}

// S13 top risks: views/TopRisksSummary.tsx (results redesign: the posture's ranked risks once, cards then a table)
