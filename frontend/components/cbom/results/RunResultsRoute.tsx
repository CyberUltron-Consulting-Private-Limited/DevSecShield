"use client";

// Sources-run data for the one results template (components/CbomResults.tsx), mounted by
// /{team_id}/cbom/{run_id}/results?run=1. The run adapter is useSourcesRunSource. `?view=findings|all` keeps the
// findings table's toggle across reloads and `?section=` the view (views/url.ts). The heading is the code scan's
// ("CBOM Scan Results").

import { useSearchParams } from "next/navigation";
import { Suspense, useCallback } from "react";
import { Loader2 } from "lucide-react";

import CbomResults from "@/components/CbomResults";
import { RunNotFound } from "@/components/cbom/results/RunSections";
import { useSourcesRunSource } from "@/components/cbom/results/source";
import { useResultsUrl } from "@/components/cbom/results/views/url";

function RunResults({ teamId, runId, view }: { teamId: number; runId: number; view: "findings" | "all" }) {
  // the table toggle goes through the page's one URL writer (views/url.ts), which the section switch uses too: it
  // merges into the URL as it is, so a drill that changes both in one tick keeps both
  const { patch } = useResultsUrl();
  const onViewChange = useCallback((next: "findings" | "all") => patch({ view: next }), [patch]);
  const source = useSourcesRunSource(teamId, runId, { initialView: view, onViewChange });

  if (source.state === "not_found") return <RunNotFound teamId={teamId} />;
  if (source.state === "error") {
    return (
      <div className="flex h-screen w-full items-center justify-center" role="alert">
        <p className="text-zinc-600 dark:text-zinc-400 mb-4">Error fetching the run results. Please try again later.</p>
      </div>
    );
  }
  if (source.state === "loading") {
    return (
      <div className="flex h-screen w-full items-center justify-center" data-testid="run-results-loading">
        <Loader2 className="size-10 animate-spin text-blue-600" />
      </div>
    );
  }
  return (
    <div className="min-h-screen bg-white dark:bg-zinc-900 min-w-0">
      <CbomResults data={undefined} teamId={String(teamId)} source={source} />
    </div>
  );
}

function RunResultsWithView({ teamId, runId }: { teamId: number; runId: number }) {
  const search = useSearchParams();
  const view = search.get("view") === "all" ? "all" : "findings";
  return <RunResults key={`${teamId}-${runId}`} teamId={teamId} runId={runId} view={view} />;
}

export default function RunResultsRoute({ teamId, runId }: { teamId: number; runId: number }) {
  return (
    <Suspense
      fallback={
        <div className="flex h-screen w-full items-center justify-center">
          <Loader2 className="size-10 animate-spin text-blue-600" />
        </div>
      }
    >
      <RunResultsWithView teamId={teamId} runId={runId} />
    </Suspense>
  );
}
