"use client";

// Results page of a CBOM Sources run: /{team_id}/cbom/runs/{run_id}/results (CB-38). The static `runs` segment is
// matched before the code scans' dynamic `[scan_id]`, so /cbom/5/results stays scan #5 and /cbom/runs/5/results is
// run #5. `?view=findings|all` keeps the findings table's toggle across reloads.

import { useParams, usePathname, useRouter, useSearchParams } from "next/navigation";
import { Suspense, useCallback } from "react";
import { Loader2 } from "lucide-react";

import RunResultsView, { RunNotFound } from "@/components/cbom/results/RunResultsView";

function parseId(raw: unknown): number | null {
  const s = typeof raw === "string" ? raw : "";
  return /^\d+$/.test(s) && Number(s) > 0 ? Number(s) : null;
}

function RunResultsPage() {
  const params = useParams();
  const search = useSearchParams();
  const router = useRouter();
  const pathname = usePathname();
  const teamId = parseId(params?.team_id);
  const runId = parseId(params?.run_id);
  const view = search.get("view") === "all" ? "all" : "findings";

  const onViewChange = useCallback((next: "findings" | "all") => {
    const qs = new URLSearchParams(search.toString());
    qs.set("view", next);
    router.replace(`${pathname}?${qs.toString()}`, { scroll: false });
  }, [pathname, router, search]);

  if (!teamId || !runId) return <RunNotFound teamId={teamId ?? 0} />;
  return (
    <div className="min-h-screen bg-white dark:bg-zinc-900 overflow-x-hidden">
      <RunResultsView key={`${teamId}-${runId}`} teamId={teamId} runId={runId} initialView={view} onViewChange={onViewChange} />
    </div>
  );
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
