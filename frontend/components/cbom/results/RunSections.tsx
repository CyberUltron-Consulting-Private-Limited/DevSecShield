"use client";

// Sections of the Sources run results page (CB-38 PR-1c) that are not the header, the findings table or the finding
// dialog. Each takes API payloads as they are; a section without data says so in one line (`SectionNote`).
// Rule P: no section here counts rows. Figures come from /runs/{id} (jobs), /posture, /results and /remediation.

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState, type ReactNode } from "react";
import { Download, ExternalLink, GitCompare, Info, Loader2, Network, Server, SlidersHorizontal, Timer, Waypoints } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { ScrollArea, ScrollBar } from "@/components/ui/scroll-area";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { downloadCbomRunCbom, type CbomCertRef, type CbomJobTargets, type CbomRun, type CbomRunResults } from "@/utils/backend_api";
import { downloadCbomRunBom, EXPOSURE_LABEL, type CbomPostureWithExposure } from "@/utils/api/cbom_outputs";
import { downloadOscal } from "@/utils/api/integrations";

import { RunChanges } from "@/components/cbom/sources/ChangesPanel";
import { TERMINAL_RUN } from "@/components/cbom/sources/keys";
import { credits, formatDateTime, formatDay, pluralize } from "@/components/cbom/sources/logic";
import { TargetsBlock } from "@/components/cbom/sources/RunResults";
import { EmptyState, RunStatusBadge, StatusBadge, Truncate, type Tone } from "@/components/cbom/sources/shared";

import { CbomDashboardCharts } from "./CbomDashboardCharts";
import { getImpactBadgeClass } from "./badgeClasses";
import {
  certCountText,
  certListView,
  complianceRows,
  formatDuration,
  isActiveRunStatus,
  waveChips,
  type RunDashboardModel,
  type SectionView,
} from "./model";
import { RunJobsTable, SkippedAtStart } from "./RunJobsTable";
import { Badge } from "@/components/ui/badge";

/** Bounds the Radix viewport (not the root, which grows with its content). Read by results/scrollBounds.test.ts. */
export const VIEWPORT_MAX_H_72 = "[&>[data-slot=scroll-area-viewport]]:max-h-72";

export function SectionNote({ children, testId }: { children: ReactNode; testId?: string }) {
  return (
    <p className="text-sm text-zinc-500 dark:text-zinc-400 flex items-start gap-1.5" data-testid={testId}>
      <Info className="h-4 w-4 shrink-0 mt-0.5" /> <span>{children}</span>
    </p>
  );
}

function SectionShell({ title, description, testId, children, actions }: {
  title: ReactNode; description?: ReactNode; testId: string; children: ReactNode; actions?: ReactNode;
}) {
  return (
    <Card className="border-zinc-200 dark:border-zinc-800 min-w-0" data-testid={testId}>
      <CardHeader className="flex flex-row flex-wrap items-start justify-between gap-3">
        <div className="space-y-1.5 min-w-0">
          <CardTitle className="text-base">{title}</CardTitle>
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
      <span data-testid="run-results-status"><RunStatusBadge status={run.status} /></span>
      <span>Started {formatDateTime(run.created_at)}</span>
      {run.finished_at ? <span>Finished {formatDateTime(run.finished_at)}</span> : active ? <span>Running</span> : null}
      <span data-testid="run-results-credits">{credits(run.credits?.charged)} credits charged, {credits(run.credits?.refunded)} refunded</span>
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
      {downloads.map((d) => (
        <Button key={d.id} variant="outline" className="cursor-pointer" title={d.title} disabled={d.disabled || busy === d.id}
                data-testid={d.id} onClick={() => void d.run()}>
          {busy === d.id ? <Loader2 className="h-4 w-4 mr-2 animate-spin" /> : <Download className="h-4 w-4 mr-2" />}
          {d.label}
        </Button>
      ))}
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
export function RunCoverageSection({ run, targets, provenance }: {
  run: CbomRun;
  targets: CbomJobTargets[] | null;
  provenance: CbomRunResults["provenance"] | null | undefined;
}) {
  const jobs = run.jobs ?? [];
  const skipped = run.breakdown?.skipped ?? [];
  return (
    <SectionShell title="What this run covered" testId="run-section-coverage"
                  description="Every job of the run with where it ran and how it ended, the sources skipped at the start, and each target's outcome">
      {jobs.length === 0 ? <EmptyState title="No jobs in this run" /> : <RunJobsTable jobs={jobs} testIdPrefix="run-job" />}
      <SkippedAtStart items={skipped} />
      {provenance && provenance.length > 0 && (
        <div className="space-y-1.5" data-testid="run-provenance">
          <p className="text-sm font-medium text-zinc-900 dark:text-white">Provenance per source</p>
          <ScrollArea className="w-full border rounded-lg">
            <div className="min-w-max">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Source</TableHead>
                    <TableHead>Kind</TableHead>
                    <TableHead>Runs on</TableHead>
                    <TableHead>Outcome</TableHead>
                    <TableHead className="text-right" title="Collected assets; the jobs table above also counts the Not collected rows">Assets (excl. not collected)</TableHead>
                    <TableHead className="text-right">Endpoints probed</TableHead>
                    <TableHead className="text-right">Duration</TableHead>
                    <TableHead className="text-right">Credits</TableHead>
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
      {targets ? <TargetsBlock jobs={targets} /> : null}
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
function CertTable({ title, label, count, certs, testId, onOpenAsset }: {
  title: string; label: string | null; count: string; certs: CbomCertRef[]; testId: string; onOpenAsset: (id: number) => void;
}) {
  return (
    <div className="space-y-1.5 min-w-0" data-testid={testId}>
      <p className="text-sm font-medium text-zinc-900 dark:text-white">
        {title} <span className="text-zinc-500 font-normal" data-testid={`${testId}-count`}>({count})</span>
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
                  <TableHead>Subject</TableHead>
                  <TableHead>Issuer</TableHead>
                  <TableHead>Expires</TableHead>
                  <TableHead>Location</TableHead>
                  <TableHead>Source</TableHead>
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

export function RunCertificatesSection({ view, results, onOpenAsset }: {
  view: SectionView; results: CbomRunResults | null; onOpenAsset: (id: number) => void;
}) {
  if (!view.show) return null;
  const orphaned = results?.certificates_orphaned ?? null;
  const unmanaged = results?.certificates_unmanaged ?? null;
  const o = certListView(results, "orphaned");
  const u = certListView(results, "unmanaged");
  return (
    <SectionShell title="Orphaned and unmanaged certificates" testId="run-section-certificates"
                  description="Within this run's scope: orphaned = stored but presented by no endpoint the run read; unmanaged = held by no managing system the run saw (ACM, cert-manager, AD CS, Key Vault, Certificate Manager)">
      {view.note && <SectionNote testId="run-certificates-note">{view.note}</SectionNote>}
      {(orphaned?.length || unmanaged?.length) ? (
        <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
          <CertTable title="Orphaned certificates" label={o.label} count={certCountText(o)} certs={orphaned ?? []} testId="run-certs-orphaned" onOpenAsset={onOpenAsset} />
          <CertTable title="Unmanaged certificates" label={u.label} count={certCountText(u)} certs={unmanaged ?? []} testId="run-certs-unmanaged" onOpenAsset={onOpenAsset} />
        </div>
      ) : null}
    </SectionShell>
  );
}

// ---------------------------------------------------------------------------- S8 changes
export function RunChangesSection({ teamId, run, canCompare, onCompare }: { teamId: number; run: CbomRun; canCompare: boolean; onCompare: () => void }) {
  return (
    <SectionShell title="Changes" testId="run-section-changes"
                  description="Drift against each source's previous complete collection"
                  actions={canCompare ? (
                    <button type="button" className="text-sm text-blue-600 dark:text-blue-400 cursor-pointer hover:underline" onClick={onCompare}>
                      Compare with another run…
                    </button>
                  ) : undefined}>
      <RunChanges teamId={teamId} runId={run.id} finished={TERMINAL_RUN.has(run.status)} />
    </SectionShell>
  );
}

// ---------------------------------------------------------------------------- S9 remediation waves
const WAVE_TONE: Record<number, Tone> = { 1: "red", 2: "amber", 3: "blue", 4: "zinc" };

export function RunWavesSection({ byWave, labels, loading, deferred, selected }: {
  byWave: Record<string, number> | null | undefined; labels?: Record<string, string>; loading: boolean;
  /** an active run on a newer backend: the whole-run plan is not polled; each row shows its own wave */
  deferred: boolean;
  selected: number;
}) {
  const chips = waveChips(byWave);
  return (
    <SectionShell title="Remediation waves" testId="run-section-waves"
                  description="Who fixes what, by when. Plans follow each asset's stable identity, so they carry over to later runs">
      {deferred ? <SectionNote testId="run-waves-deferred">Wave counts for the whole run appear when it has finished; each row below shows its own wave meanwhile.</SectionNote>
        : loading ? <p className="text-xs text-zinc-500">Loading the wave plan…</p> : chips.length === 0 ? (
        <SectionNote>No asset of this run needs a remediation wave.</SectionNote>
      ) : (
        <div className="flex flex-wrap gap-2" data-testid="run-wave-chips">
          {chips.map((c) => (
            <span key={c.key} title={c.wave != null ? labels?.[String(c.wave)] : undefined} data-testid={`run-wave-chip-${c.key}`}>
              <StatusBadge tone={c.wave != null ? WAVE_TONE[c.wave] ?? "zinc" : "zinc"}>{c.label}: {c.count}</StatusBadge>
            </span>
          ))}
        </div>
      )}
      <p className="text-xs text-zinc-500">
        {selected > 0
          ? `${pluralize(selected, "finding")} selected in the table below: set wave, owner, target date or status there.`
          : "Select findings in the table below to assign a wave, owner, target date or status."}
      </p>
    </SectionShell>
  );
}

// ---------------------------------------------------------------------------- S10 compliance mapping
export function RunComplianceSection({ view, results, posture }: {
  view: SectionView; results: CbomRunResults | null; posture: CbomPostureWithExposure | null | undefined;
}) {
  if (!view.show) return null;
  const { rows, basis } = complianceRows(results, posture);
  return (
    <SectionShell title="Compliance mapping" testId="run-section-compliance"
                  description="Regulatory clauses the run's findings touch: CERT-In, RBI, SEBI CSCRF, NIST and CNSA 2.0 (knowledge-base mapping, no AI)">
      {view.note && <SectionNote>{view.note}</SectionNote>}
      {rows.length > 0 && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {rows.map((fw) => (
            <div key={fw.framework} className="rounded-lg border border-zinc-200 dark:border-zinc-800 p-3 min-w-0" data-testid={`run-compliance-${fw.framework.replace(/\s+/g, "-")}`}>
              <p className="text-sm font-semibold text-zinc-900 dark:text-white mb-2">
                {fw.framework} <span className="text-xs font-normal text-zinc-500">· {pluralize(fw.clauses.length, "clause")}</span>
              </p>
              <ul className="space-y-1.5">
                {fw.clauses.map((c) => (
                  <li key={c.clause} className="text-xs text-zinc-600 dark:text-zinc-400 [overflow-wrap:anywhere]">
                    {c.source ? (
                      <a href={c.source} target="_blank" rel="noreferrer noopener" className="font-medium text-blue-600 dark:text-blue-400 inline-flex items-center gap-1">
                        {c.clause} <ExternalLink className="h-3 w-3" />
                      </a>
                    ) : (
                      <span className="font-medium text-zinc-800 dark:text-zinc-200">{c.clause}</span>
                    )}
                    {c.title ? <span> · {c.title}</span> : null}
                    <span className="block text-zinc-500">{pluralize(c.assets, "asset")}{c.codes.length ? ` · ${c.codes.join(", ")}` : ""}</span>
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </div>
      )}
      {basis === "posture" && <p className="text-xs text-zinc-500">From the run posture (this server does not send the run results summary yet).</p>}
    </SectionShell>
  );
}

// ---------------------------------------------------------------------------- S11 dashboard charts
export function RunDashboardSection({ view, model, riskRows, pageRows, results }: {
  view: SectionView;
  model: RunDashboardModel;
  riskRows: Parameters<typeof CbomDashboardCharts>[0]["findingsList"];
  /** rows on the findings table's current page (the per-finding chart plots those, and says so) */
  pageRows: number;
  results: CbomRunResults | null;
}) {
  if (!view.show) return null;
  return (
    <div className="space-y-3" data-testid="run-section-dashboard">
      {model.dashboard && (
        <CbomDashboardCharts dashboard={model.dashboard} findingsList={riskRows}
                             riskScoresTitle={`Risk scores on this table page (${pageRows} rows)`}
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

// ---------------------------------------------------------------------------- S13 top risks
export function RunTopRisks({ posture, onOpenAsset }: { posture: CbomPostureWithExposure; onOpenAsset: (id: number) => void }) {
  const risks = posture.top_risks ?? [];
  if (risks.length === 0) return null;
  return (
    <Card className="border-zinc-200 dark:border-zinc-800" data-testid="run-top-risks">
      <CardHeader>
        <CardTitle className="text-base">Top cryptographic risks</CardTitle>
        <CardDescription>Priority = impact × business criticality × internet exposure, from the run posture</CardDescription>
      </CardHeader>
      <CardContent>
        <ScrollArea className="h-[320px] w-full rounded-md border border-zinc-200 dark:border-zinc-800">
          <Table className="min-w-max">
            <TableHeader>
              <TableRow>
                <TableHead className="min-w-[80px]">Priority</TableHead>
                <TableHead className="min-w-[200px]">Asset</TableHead>
                <TableHead className="min-w-[90px]">Impact</TableHead>
                <TableHead className="min-w-[140px]">Source</TableHead>
                <TableHead className="min-w-[100px]">Criticality</TableHead>
                <TableHead className="min-w-[130px]">Exposure</TableHead>
                <TableHead className="min-w-[70px]">HNDL</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {risks.map((r) => (
                <TableRow key={r.id} className="hover:bg-zinc-50 dark:hover:bg-zinc-800/50" data-testid={`run-top-risk-${r.id}`}>
                  <TableCell className="font-mono tabular-nums">{r.score}</TableCell>
                  <TableCell className="max-w-[320px]">
                    <button type="button" className="text-left text-blue-600 dark:text-blue-400 hover:underline cursor-pointer max-w-[300px] truncate block font-mono text-xs"
                            title={r.location} onClick={() => onOpenAsset(r.id)}>
                      {r.name}
                    </button>
                    {r.finding && <span className="block text-xs text-zinc-500 max-w-[300px] truncate" title={r.finding}>{r.finding}</span>}
                  </TableCell>
                  <TableCell><Badge variant="outline" className={getImpactBadgeClass(r.impact)}>{r.impact}</Badge></TableCell>
                  <TableCell className="text-sm text-zinc-600 dark:text-zinc-400">{r.source_name ?? "—"}</TableCell>
                  <TableCell className="text-sm text-zinc-600 dark:text-zinc-400 capitalize">{r.criticality}</TableCell>
                  <TableCell className="text-sm text-zinc-600 dark:text-zinc-400" title={r.exposure_basis}>{r.exposure ? EXPOSURE_LABEL[r.exposure] : "—"}</TableCell>
                  <TableCell className="text-sm">{r.hndl ? <StatusBadge tone="red">HNDL</StatusBadge> : "—"}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
          <ScrollBar orientation="horizontal" />
        </ScrollArea>
      </CardContent>
    </Card>
  );
}
