"use client";

// Sections of the Sources run results page (CB-38 PR-1c) that are not the header, the findings table or the finding
// dialog. Each takes API payloads as they are; a section without data says so in one line (`SectionNote`).
// Rule P: no section here counts rows. Figures come from /runs/{id} (jobs), /posture, /results and /remediation.

import { ExternalLink, Info, Network, Server, Timer, Waypoints } from "lucide-react";
import type { ReactNode } from "react";

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { ScrollArea, ScrollBar } from "@/components/ui/scroll-area";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { CbomCryptoCharts } from "@/components/cbom/CbomCryptoCharts";
import type { CbomCertRef, CbomJobTargets, CbomRun, CbomRunResults } from "@/utils/backend_api";
import { EXPOSURE_LABEL, type CbomPostureWithExposure } from "@/utils/api/cbom_outputs";

import { RunChanges } from "@/components/cbom/sources/ChangesPanel";
import { TERMINAL_RUN } from "@/components/cbom/sources/keys";
import { formatDateTime, formatDay, pluralize } from "@/components/cbom/sources/logic";
import { TargetsBlock } from "@/components/cbom/sources/RunResults";
import { EmptyState, StatusBadge, Truncate, type Tone } from "@/components/cbom/sources/shared";

import { CbomDashboardCharts } from "./CbomDashboardCharts";
import { getImpactBadgeClass } from "./badgeClasses";
import {
  applyPostureToDistributions,
  complianceRows,
  formatDuration,
  postureDistribution,
  waveChips,
  type RunDashboardModel,
  type SectionView,
} from "./model";
import { RunJobsTable, SkippedAtStart } from "./RunJobsTable";
import { Badge } from "@/components/ui/badge";

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

// ---------------------------------------------------------------------------- S1 what was covered
export function RunCoverageSection({ run, targets, provenance }: {
  run: CbomRun;
  targets: CbomJobTargets[] | null;
  provenance: CbomRunResults["provenance"] | null | undefined;
}) {
  const jobs = run.jobs ?? [];
  const skipped = run.breakdown?.skipped ?? [];
  return (
    <SectionShell title="What was covered" testId="run-section-coverage"
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
                    <TableHead className="text-right">Assets</TableHead>
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

// ---------------------------------------------------------------------------- S4 posture passthrough distributions
/** CB-19 `q_grades` and CB-24 `fix_classes` from the posture payload, shown as they are (Rule P). Nothing when absent. */
export function PostureDistributions({ posture }: { posture: Record<string, unknown> | null | undefined }) {
  const q = postureDistribution(posture?.q_grades);
  const fix = postureDistribution(posture?.fix_classes);
  if (q.length === 0 && fix.length === 0) return null;
  const row = (title: string, entries: [string, number][], testId: string) => (
    <div className="space-y-1" data-testid={testId}>
      <p className="text-xs font-semibold uppercase tracking-wide text-zinc-500">{title}</p>
      <div className="flex flex-wrap gap-1.5">
        {entries.map(([k, n]) => (
          <span key={k} data-testid={`${testId}-${k}`}><StatusBadge tone="zinc">{k.replace(/_/g, " ")}: {n}</StatusBadge></span>
        ))}
      </div>
    </div>
  );
  return (
    <div className="grid grid-cols-1 md:grid-cols-2 gap-4 rounded-lg border border-zinc-200 dark:border-zinc-800 p-4" data-testid="run-posture-distributions">
      {q.length > 0 && row("Quantum risk grade (per asset)", q, "posture-q-grades")}
      {fix.length > 0 && row("Fix class (crypto agility)", fix, "posture-fix-classes")}
    </div>
  );
}

// ---------------------------------------------------------------------------- S6 orphaned / unmanaged certificates
function CertTable({ title, certs, testId, onOpenAsset }: { title: string; certs: CbomCertRef[]; testId: string; onOpenAsset: (id: number) => void }) {
  return (
    <div className="space-y-1.5 min-w-0" data-testid={testId}>
      <p className="text-sm font-medium text-zinc-900 dark:text-white">{title} <span className="text-zinc-500 font-normal">({certs.length})</span></p>
      {certs.length === 0 ? (
        <p className="text-xs text-zinc-500">None in this run.</p>
      ) : (
        <ScrollArea className="w-full max-h-72 border rounded-lg">
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
  return (
    <SectionShell title="Orphaned and unmanaged certificates" testId="run-section-certificates"
                  description="Within this run's scope: orphaned = stored but presented by no endpoint the run read; unmanaged = held by no managing system the run saw (ACM, cert-manager, AD CS, Key Vault, Certificate Manager)">
      {view.note && <SectionNote testId="run-certificates-note">{view.note}</SectionNote>}
      {(orphaned?.length || unmanaged?.length) ? (
        <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
          <CertTable title="Orphaned certificates" certs={orphaned ?? []} testId="run-certs-orphaned" onOpenAsset={onOpenAsset} />
          <CertTable title="Unmanaged certificates" certs={unmanaged ?? []} testId="run-certs-unmanaged" onOpenAsset={onOpenAsset} />
        </div>
      ) : null}
    </SectionShell>
  );
}

// ---------------------------------------------------------------------------- S7 crypto charts
export function RunCryptoChartsSection({ view, results, posture }: {
  view: SectionView; results: CbomRunResults | null; posture: CbomPostureWithExposure | null | undefined;
}) {
  if (!view.show) return null;
  const dist = results?.distributions ?? null;
  return (
    <div className="space-y-3" data-testid="run-section-crypto-charts">
      {dist ? (
        // Rows are not passed (findings / inventory empty): the PQC gauge reads the run's posture figures, never a
        // recount of the table (Rule P). The heat-map and calendar come from RunInsights (S5).
        <CbomCryptoCharts distributions={applyPostureToDistributions(dist, posture)} findings={[]} inventory={[]} showCodeHeatmap={false} />
      ) : null}
      {view.note && <SectionNote testId="run-crypto-charts-note">{view.note}</SectionNote>}
    </div>
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

export function RunWavesSection({ byWave, labels, loading, selected }: {
  byWave: Record<string, number> | null | undefined; labels?: Record<string, string>; loading: boolean; selected: number;
}) {
  const chips = waveChips(byWave);
  return (
    <SectionShell title="Remediation waves" testId="run-section-waves"
                  description="Who fixes what, by when. Plans follow each asset's stable identity, so they carry over to later runs">
      {loading ? <p className="text-xs text-zinc-500">Loading the wave plan…</p> : chips.length === 0 ? (
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
export function RunDashboardSection({ view, model, riskRows, results }: {
  view: SectionView;
  model: RunDashboardModel;
  riskRows: Parameters<typeof CbomDashboardCharts>[0]["findingsList"];
  results: CbomRunResults | null;
}) {
  if (!view.show) return null;
  return (
    <div className="space-y-3" data-testid="run-section-dashboard">
      {model.dashboard && <CbomDashboardCharts dashboard={model.dashboard} findingsList={riskRows} />}
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
