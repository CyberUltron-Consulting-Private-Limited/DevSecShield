"use client";

// The summary's run status area (results redesign §2.2): a banner when the run did not read everything (failed,
// cancelled or partial, a job or target with an error, a source skipped at the start, no asset read) with a link to
// the Collection view; the scan's coverage and import notes (from /parity's scan_metadata); and one compact line per
// job with its read label (the jobs' test ids run-results-job-<id>, as on the Collection view's targets list, which
// the user-flow gate reads on the default page).

import { AlertTriangle, ChevronRight } from "lucide-react";

import { InfoTip } from "@/components/ui/info-tip";
import type { CbomCoverageReport, CbomImportReport } from "@/utils/api/cbom_outputs";
import type { CbomJobTargets, CbomRun } from "@/utils/backend_api";
import { jobReadLabel } from "@/components/cbom/sources/jobReadLabel";
import { StatusBadge, type Tone } from "@/components/cbom/sources/shared";

import { CoverageNotesCard, ImportNotesCard } from "./ScanNotes";
import { runProblem } from "./selectors";

const JOB_STATUS_WORD: Record<string, string> = { failure: "failure", expired: "expired", cancelled: "cancelled" };

export function RunJobsLine({ targets }: { targets: CbomJobTargets[] | null }) {
  if (!targets || targets.length === 0) return null;
  return (
    <ul className="flex flex-wrap gap-2" data-testid="run-jobs-line" aria-label="Collection jobs">
      {targets.map((job) => {
        const [tone, label] = jobReadLabel(job);
        return (
          <li key={job.job_id} data-testid={`run-results-job-${job.job_id}`}
              className="inline-flex max-w-full items-center gap-1.5 rounded-full border border-zinc-200 px-2.5 py-1 text-xs dark:border-zinc-800">
            <span className="truncate max-w-[14rem] font-medium text-zinc-800 dark:text-zinc-200" title={job.source_name ?? undefined}>
              {job.source_name ?? `Source ${job.source_id ?? "—"}`}
            </span>
            <StatusBadge tone={tone as Tone}>{label}</StatusBadge>
            {JOB_STATUS_WORD[job.status] && <span className="text-zinc-500">({JOB_STATUS_WORD[job.status]})</span>}
          </li>
        );
      })}
    </ul>
  );
}

export function RunStatusBanner({ run, assets, targets, coverageReport, importReport, onOpenCollection }: {
  run: CbomRun;
  /** the posture's asset count (null while it loads) */
  assets: number | null;
  targets: CbomJobTargets[] | null;
  coverageReport: CbomCoverageReport | null;
  importReport: CbomImportReport | null;
  onOpenCollection: () => void;
}) {
  const problem = runProblem(run, { assets, targets });
  return (
    <section className="space-y-3 min-w-0" data-testid="run-status-area">
      {problem && (
        <div role="alert" data-testid="run-status-banner"
             className="flex flex-col gap-2 rounded-xl border border-amber-300 bg-amber-50/60 p-4 text-sm text-amber-900 dark:border-amber-700 dark:bg-amber-950/20 dark:text-amber-200 sm:flex-row sm:items-start sm:justify-between">
          <div className="flex gap-2 min-w-0">
            <AlertTriangle className="h-4 w-4 shrink-0 mt-0.5" aria-hidden />
            <div className="min-w-0">
              <p className="font-medium">This run did not read everything <InfoTip id="cbom.run.covered" /></p>
              <ul className="mt-1 space-y-0.5">
                {problem.lines.map((l) => <li key={l}>{l}</li>)}
              </ul>
            </div>
          </div>
          <button type="button" onClick={onOpenCollection} data-testid="run-status-open-collection"
                  className="inline-flex shrink-0 items-center gap-0.5 self-start font-medium text-blue-700 hover:underline dark:text-blue-300 cursor-pointer">
            See jobs and targets <ChevronRight className="h-4 w-4" aria-hidden />
          </button>
        </div>
      )}
      <CoverageNotesCard report={coverageReport} />
      <ImportNotesCard report={importReport} />
      <RunJobsLine targets={targets} />
    </section>
  );
}
