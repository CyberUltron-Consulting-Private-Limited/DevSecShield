"use client";

// 03-B (run results redesign): the run's collection jobs as one card per source, and a compact status line of the
// jobs for the summary view. Fed by the payloads the page already has: /runs/{id} (jobs), /results (provenance per
// source) and the targets of each job. Nothing here counts rows: every figure is a field of those payloads.

import type { ReactNode } from "react";

import { refundLabel } from "@/components/cbom/results/refundLabel";
import { jobReadLabel, jobTargetsLine } from "@/components/cbom/sources/jobReadLabel";
import { addressProgress, credits } from "@/components/cbom/sources/logic";
import { JobStatusBadge, StatusBadge, type Tone } from "@/components/cbom/sources/shared";
import { InfoTip } from "@/components/ui/info-tip";
import type { InfoTipId } from "@/content/infotips";
import type { CbomJob, CbomJobTargets, CbomRunProvenance } from "@/utils/backend_api";

import { formatDuration } from "./model";

/** The fields of a source card, each with the tip of the jobs / provenance table column it comes from. */
export const SOURCE_CARD_FIELDS: { key: string; label: string; tip: InfoTipId }[] = [
  { key: "status", label: "Status", tip: "cbsrc.rr.job.status" },
  { key: "runs_on", label: "Runs on", tip: "cbsrc.rr.job.runs_on" },
  { key: "kind", label: "Kind", tip: "cbom.run.col.kind" },
  { key: "outcome", label: "Outcome", tip: "cbom.run.col.outcome" },
  { key: "assets", label: "Assets", tip: "cbsrc.rr.job.assets" },
  { key: "collected", label: "Assets (excl. not collected)", tip: "cbom.run.col.assets_collected" },
  { key: "endpoints", label: "Endpoints probed", tip: "cbom.run.col.endpoints" },
  { key: "duration", label: "Duration", tip: "cbom.run.col.duration" },
  { key: "credits", label: "Credits", tip: "cbsrc.rr.job.credits" },
  { key: "attempts", label: "Attempts", tip: "cbsrc.rr.job.attempts" },
  { key: "error", label: "Error", tip: "cbsrc.rr.job.error" },
];

/** One card's data: a job of the run with its source's provenance row and its targets (either may be missing), or a
 * provenance row no job of the run names (it still gets a card, nothing is dropped). */
export interface SourceCardModel {
  key: string;
  job: CbomJob | null;
  provenance: CbomRunProvenance | null;
  targets: CbomJobTargets | null;
}

/** Pairs each job with its source's provenance row (by source id) and its targets (by job id); provenance rows no job
 * names follow the jobs, in the server's order. */
export function sourceCardModels(jobs: CbomJob[], provenance: CbomRunProvenance[] | null | undefined,
                                 targets: CbomJobTargets[] | null | undefined): SourceCardModel[] {
  const prov = provenance ?? [];
  const used = new Set<number>();
  const out: SourceCardModel[] = jobs.map((job) => {
    const i = prov.findIndex((p, idx) => !used.has(idx) && p.source_id != null && p.source_id === job.source_id);
    if (i >= 0) used.add(i);
    return { key: `job-${job.id}`, job, provenance: i >= 0 ? prov[i] : null,
             targets: (targets ?? []).find((t) => t.job_id === job.id) ?? null };
  });
  prov.forEach((p, i) => {
    if (!used.has(i)) out.push({ key: `prov-${p.source_id ?? "x"}-${i}`, job: null, provenance: p, targets: null });
  });
  return out;
}

function Stat({ label, children, testId }: { label: string; children: ReactNode; testId?: string }) {
  return (
    <div className="min-w-0" data-testid={testId}>
      <dt className="text-[11px] leading-tight text-zinc-500 dark:text-zinc-400 break-words">{label}</dt>
      <dd className="text-sm font-semibold tabular-nums text-zinc-900 dark:text-zinc-100 break-words">{children}</dd>
    </div>
  );
}

function SourceCard({ m }: { m: SourceCardModel }) {
  const { job, provenance: p, targets: t } = m;
  const id = job?.id ?? m.key;
  const name = job ? job.source_name ?? `Source ${job.source_id ?? "—"}` : p?.source ?? (p?.source_id != null ? `Source ${p.source_id}` : "—");
  const runner = job ? (job.runner === "cloud" ? "ZeroShield cloud" : job.node_name ?? "—") : p?.runner === "cloud" ? "ZeroShield cloud" : p?.node ?? "—";
  const progress = job ? addressProgress(job) : null;
  const refund = job ? refundLabel(job) : null;
  const targetsLine = t ? jobTargetsLine(t) : null;
  const duration = p?.duration_s ?? t?.duration_s ?? null;
  return (
    <li className="flex flex-col gap-3 rounded-xl border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 p-4 min-w-0"
        data-testid={`run-source-card-${id}`} data-source-id={job?.source_id ?? p?.source_id ?? undefined}>
      <div className="flex items-start justify-between gap-2 min-w-0">
        <div className="min-w-0">
          <p className="text-sm font-semibold text-zinc-900 dark:text-white break-all">{name}</p>
          <p className="text-xs text-zinc-500 dark:text-zinc-400 break-words">
            {[p?.kind, runner].filter(Boolean).join(" · ")}
          </p>
        </div>
        <div className="flex shrink-0 flex-wrap justify-end gap-1">
          {job ? <JobStatusBadge status={job.status} title={job.waiting_reason} /> : <StatusBadge tone="zinc">No job</StatusBadge>}
        </div>
      </div>
      {job?.waiting_reason && <p className="text-xs text-zinc-500 dark:text-zinc-400 break-words">{job.waiting_reason}</p>}
      {progress && (
        <p className="text-xs text-zinc-700 dark:text-zinc-300" data-testid={`run-source-card-progress-${id}`}>{progress}</p>
      )}
      <dl className="grid grid-cols-2 sm:grid-cols-4 gap-x-3 gap-y-2 items-end">
        <Stat label="Assets">{job ? job.asset_count ?? 0 : "—"}</Stat>
        <Stat label="Assets (excl. not collected)">{p ? p.assets : "—"}</Stat>
        <Stat label="Endpoints probed">{p ? p.endpoints_probed : "—"}</Stat>
        <Stat label="Duration">{formatDuration(duration)}</Stat>
        <Stat label="Credits">
          {job ? credits(job.credits) : p?.credits ?? "—"}
          {refund && (
            <span className="ml-1 text-xs font-normal text-green-600 dark:text-green-400" data-testid={`run-source-card-refund-${id}`}>{refund}</span>
          )}
        </Stat>
        <Stat label="Attempts">{job ? job.attempts : "—"}</Stat>
        <Stat label="Outcome">{p?.outcome ?? "—"}</Stat>
      </dl>
      {targetsLine && <p className="text-xs text-zinc-500 dark:text-zinc-400">{targetsLine}</p>}
      {job?.error && (
        <p className="text-xs text-red-600 dark:text-red-400 break-words" data-testid={`run-source-card-error-${id}`}>
          <span className="font-semibold">Error: </span>{job.error}
        </p>
      )}
    </li>
  );
}

/** The cards, with one key line above them naming every field with its tip (a tip per field, not per card). */
export function RunSourceCards({ jobs, provenance, targets }: {
  jobs: CbomJob[];
  provenance: CbomRunProvenance[] | null | undefined;
  targets: CbomJobTargets[] | null | undefined;
}) {
  const models = sourceCardModels(jobs, provenance, targets);
  if (models.length === 0) return null;
  return (
    <div className="space-y-3" data-testid="run-source-cards">
      <p className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-zinc-500 dark:text-zinc-400" data-testid="run-source-card-key">
        <span className="font-semibold text-zinc-700 dark:text-zinc-300">On each card:</span>
        {SOURCE_CARD_FIELDS.map((f) => (
          <span key={f.key} className="inline-flex items-center gap-0.5">{f.label} <InfoTip id={f.tip} /></span>
        ))}
      </p>
      <ul className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-3">
        {models.map((m) => <SourceCard key={m.key} m={m} />)}
      </ul>
    </div>
  );
}

/** A compact line of the run's jobs for the summary view: per job its source, how it read (the same label as the
 * targets list) and, unless it finished, its job status. Carries the gate hooks `run-results-job-<job id>` (e2e G11
 * reads them on the default page): mount it on a view without the full targets list (TargetsBlock), never beside it. */
export function RunJobsStatusLine({ targets, onOpen }: {
  targets: CbomJobTargets[] | null | undefined;
  /** "Collection jobs and targets": opens the collection view (optional) */
  onOpen?: () => void;
}) {
  if (!targets || targets.length === 0) return null;
  return (
    <div className="flex flex-wrap items-center gap-x-3 gap-y-1.5 text-xs" data-testid="run-jobs-status-line">
      <span className="inline-flex items-center gap-0.5 font-medium text-zinc-700 dark:text-zinc-300">
        Jobs <InfoTip id="cbsrc.rr.job.status" />
      </span>
      <ul className="flex flex-wrap gap-1.5 min-w-0">
        {targets.map((job) => {
          const [tone, label] = jobReadLabel(job);
          return (
            <li key={job.job_id} className="inline-flex max-w-full flex-wrap items-center gap-1 rounded-md border border-zinc-200 dark:border-zinc-800 px-2 py-0.5"
                data-testid={`run-results-job-${job.job_id}`}>
              <span className="text-zinc-800 dark:text-zinc-200 break-all">{job.source_name ?? `Source ${job.source_id ?? "—"}`}</span>
              <StatusBadge tone={tone as Tone}>{label}</StatusBadge>
              {job.status !== "success" && <JobStatusBadge status={job.status} />}
              {job.lab_mode && <StatusBadge tone="amber" title="Lab mode: same-account collection — not for production">Lab mode</StatusBadge>}
            </li>
          );
        })}
      </ul>
      {onOpen && (
        <button type="button" className="text-blue-600 dark:text-blue-400 hover:underline cursor-pointer" onClick={onOpen}
                data-testid="run-jobs-status-open">
          Collection jobs and targets ›
        </button>
      )}
    </div>
  );
}
