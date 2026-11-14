"use client";

// Results page of a CBOM Sources run: /{team_id}/cbom/runs/{run_id}/results. Owner decision (CB-38): the SAME results
// template as a code scan (components/CbomResults.tsx), fed by the run adapter (useSourcesRunSource). The static `runs`
// segment is matched before the code scans' dynamic `[scan_id]`, so /cbom/5/results stays scan #5 and
// /cbom/runs/5/results is run #5. `?view=findings|all` keeps the findings table's toggle across reloads.

import { useParams, usePathname, useRouter, useSearchParams } from "next/navigation";
import { Suspense, useCallback } from "react";
import { Loader2 } from "lucide-react";

import CbomResults from "@/components/CbomResults";
import { RunNotFound } from "@/components/cbom/results/RunSections";
import { useSourcesRunSource } from "@/components/cbom/results/source";

function parseId(raw: unknown): number | null {
  const s = typeof raw === "string" ? raw : "";
  return /^\d+$/.test(s) && Number(s) > 0 ? Number(s) : null;
}

function RunResults({ teamId, runId, view }: { teamId: number; runId: number; view: "findings" | "all" }) {
  const search = useSearchParams();
  const router = useRouter();
  const pathname = usePathname();
  const onViewChange = useCallback((next: "findings" | "all") => {
    const qs = new URLSearchParams(search.toString());
    qs.set("view", next);
    router.replace(`${pathname}?${qs.toString()}`, { scroll: false });
  }, [pathname, router, search]);
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

function RunResultsPage() {
  const params = useParams();
  const search = useSearchParams();
  const teamId = parseId(params?.team_id);
  const runId = parseId(params?.run_id);
  const view = search.get("view") === "all" ? "all" : "findings";
  if (!teamId || !runId) return <RunNotFound teamId={teamId ?? 0} />;
  return <RunResults key={`${teamId}-${runId}`} teamId={teamId} runId={runId} view={view} />;
}

export default function Page() {
  return (
    <Suspense
      fallback={
        <div className="flex h-screen w-full items-center justify-center">
          <Loader2 className="size-10 animate-spin text-blue-600" />
        </div>
      }
    >
      <RunResultsPage />
    </Suspense>
  );
}
