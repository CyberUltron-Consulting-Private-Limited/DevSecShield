"use client";

// A run's jobs (source, where it ran, status with waiting reason and address progress, assets, credits, attempts,
// error) and the sources skipped when the run started. Moved out of ReviewRunTab's run dialog (CB-38) so the dialog
// and the run results page render the same table.

import { ScrollArea, ScrollBar } from "@/components/ui/scroll-area";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import type { CbomJob, CbomPlanItem } from "@/utils/backend_api";

import { addressProgress, credits } from "@/components/cbom/sources/logic";
import { JobStatusBadge, Truncate } from "@/components/cbom/sources/shared";

export function skipText(item: CbomPlanItem): string {
  const reason = item.reason ?? "Skipped";
  return item.name && !reason.includes(item.name) ? `${item.name}: ${reason}` : reason;
}

export function RunJobsTable({ jobs, testIdPrefix = "review-job" }: { jobs: CbomJob[]; testIdPrefix?: string }) {
  return (
    <ScrollArea className="w-full border rounded-lg">
      <div className="min-w-max">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Source</TableHead>
              <TableHead>Runs on</TableHead>
              <TableHead>Status</TableHead>
              <TableHead className="text-right">Assets</TableHead>
              <TableHead className="text-right">Credits</TableHead>
              <TableHead className="text-right">Attempts</TableHead>
              <TableHead>Error</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {jobs.map((job) => (
              <TableRow key={job.id} data-testid={`${testIdPrefix}-${job.id}`}>
                <TableCell className="font-medium text-zinc-900 dark:text-white max-w-[220px]">
                  <Truncate text={job.source_name ?? `Source ${job.source_id ?? "—"}`} />
                </TableCell>
                <TableCell className="text-zinc-600 dark:text-zinc-400 max-w-[180px]">
                  <Truncate text={job.runner === "cloud" ? "ZeroShield cloud" : job.node_name ?? "—"} />
                </TableCell>
                <TableCell className="max-w-[260px]">
                  <JobStatusBadge status={job.status} title={job.waiting_reason} />
                  {job.waiting_reason && (
                    <p className="mt-1 whitespace-normal text-xs text-zinc-500">{job.waiting_reason}</p>
                  )}
                  {addressProgress(job) && (
                    <p className="mt-0.5 whitespace-normal text-xs text-zinc-700 dark:text-zinc-300" data-testid={`${testIdPrefix}-progress-${job.id}`}>
                      {addressProgress(job)}
                    </p>
                  )}
                </TableCell>
                <TableCell className="text-right text-zinc-600 dark:text-zinc-400">{job.asset_count ?? 0}</TableCell>
                <TableCell className="text-right text-zinc-600 dark:text-zinc-400 whitespace-nowrap">
                  {credits(job.credits)}
                  {job.refunded && <span className="ml-1 text-xs text-green-600 dark:text-green-400">refunded</span>}
                </TableCell>
                <TableCell className="text-right text-zinc-600 dark:text-zinc-400">{job.attempts}</TableCell>
                <TableCell className="max-w-[260px] text-zinc-600 dark:text-zinc-400">
                  {job.error ? <Truncate text={job.error} className="text-red-600 dark:text-red-400" /> : "—"}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>
      <ScrollBar orientation="horizontal" />
    </ScrollArea>
  );
}

export function SkippedAtStart({ items }: { items: CbomPlanItem[] }) {
  if (items.length === 0) return null;
  return (
    <div className="space-y-1.5" data-testid="run-skipped-at-start">
      <p className="text-sm font-medium text-zinc-900 dark:text-white">Skipped when the run started</p>
      <ul className="list-disc pl-5 space-y-1 text-sm text-zinc-600 dark:text-zinc-400">
        {items.map((item, index) => (
          <li key={`${item.source_id ?? item.name}-${index}`} className="break-words">
            {skipText(item)}
          </li>
        ))}
      </ul>
    </div>
  );
}
