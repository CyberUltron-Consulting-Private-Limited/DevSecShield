"use client";

// BRIDGE until CB-38 PR #120 lands; delete when #120 merges (issue #158). #120 adds this same file with the new run
// results page: on merge, take #120's version of this file and drop this one.
//
// Results of a CBOM Sources run at /{team_id}/cbom/runs/{run_id}/results, where the Scans table and the Review & Run
// "Results" links point (resultsHref.ts). It renders the existing run results UI (RunResults, with its posture card,
// asset detail panel, Q-grade and fix-class chips) so those links never 404. The static `runs` segment sits beside the
// dynamic `[scan_id]`, so /cbom/5/results stays scan #5.

import { useQuery } from "@tanstack/react-query";
import { ArrowLeft } from "lucide-react";
import Link from "next/link";
import { useParams } from "next/navigation";

import { cbomSourcesKeys } from "@/components/cbom/sources/keys";
import { credits, formatDateTime } from "@/components/cbom/sources/logic";
import RunResults from "@/components/cbom/sources/RunResults";
import { ErrorBlock, LoadingBlock, RunStatusBadge } from "@/components/cbom/sources/shared";
import { getCbomRun } from "@/utils/backend_api";

function parseId(raw: unknown): number | null {
  const s = typeof raw === "string" ? raw : "";
  return /^\d+$/.test(s) && Number(s) > 0 ? Number(s) : null;
}

function httpStatus(err: unknown): number | undefined {
  return (err as { response?: { status?: number } } | null)?.response?.status;
}

const isActive = (status: string | undefined) => status === "queued" || status === "running";

export default function RunResultsPage() {
  const params = useParams();
  const teamId = parseId(params?.team_id);
  const runId = parseId(params?.run_id);
  const runQuery = useQuery({
    queryKey: cbomSourcesKeys.run(teamId ?? 0, runId ?? 0),
    queryFn: () => getCbomRun(teamId as number, runId as number),
    enabled: teamId !== null && runId !== null,
    retry: 1,
    refetchInterval: (query) => {
      if (httpStatus(query.state.error) === 404) return false;
      const status = query.state.data?.status;
      return !status || isActive(status) ? 6000 : false;
    },
  });
  const run = runQuery.data;
  const notFound = teamId === null || runId === null || httpStatus(runQuery.error) === 404;

  return (
    <div className="min-h-screen bg-white dark:bg-zinc-900 min-w-0 p-4 sm:p-8" data-testid="run-results-page">
      <div className="max-w-7xl mx-auto space-y-4 min-w-0">
        <div className="flex flex-wrap gap-4 text-sm">
          <Link href={`/${teamId ?? ""}/cbom`} className="inline-flex items-center gap-1.5 text-zinc-600 dark:text-zinc-400 hover:text-zinc-900 dark:hover:text-white">
            <ArrowLeft className="h-4 w-4" />
            CBOM scans
          </Link>
          <Link href={`/${teamId ?? ""}/cbom/sources?tab=review`} className="text-zinc-600 dark:text-zinc-400 hover:text-zinc-900 dark:hover:text-white">
            CBOM Sources · Review &amp; Run
          </Link>
        </div>
        <div>
          <h1 className="text-3xl font-bold text-zinc-900 dark:text-white mb-1">Sources run #{runId ?? "?"}</h1>
          {run && (
            <p className="text-sm text-zinc-600 dark:text-zinc-400">
              <RunStatusBadge status={run.status} /> · started {formatDateTime(run.created_at)} · {credits(run.credits.charged)} charged,{" "}
              {credits(run.credits.refunded)} refunded
            </p>
          )}
        </div>
        {notFound ? (
          <ErrorBlock message="This run does not exist or is not in this team." />
        ) : runQuery.isLoading ? (
          <LoadingBlock />
        ) : runQuery.isError && !run ? (
          <ErrorBlock error={runQuery.error} onRetry={() => runQuery.refetch()} />
        ) : (
          <RunResults teamId={teamId as number} runId={runId as number} active={isActive(run?.status)} />
        )}
        {run && isActive(run.status) && <p className="text-xs text-zinc-500">Updates every few seconds while the run is active.</p>}
      </div>
    </div>
  );
}
