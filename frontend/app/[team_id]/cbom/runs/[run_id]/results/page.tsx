"use client";

// The older address of a CBOM Sources run's results: /{team_id}/cbom/runs/{run_id}/results. Runs now open on the
// code-scan results template at /{team_id}/cbom/{run_id}/results?run=1. This page replaces the URL with that one,
// query string (`?view=all`) included.

import { useParams, useRouter, useSearchParams } from "next/navigation";
import { Suspense, useEffect } from "react";
import { Loader2 } from "lucide-react";

import { RunNotFound } from "@/components/cbom/results/RunSections";
import { legacyRunResultsTarget } from "@/components/cbom/results/resultsHref";

const spinner = (
  <div className="flex h-screen w-full items-center justify-center">
    <Loader2 className="size-10 animate-spin text-blue-600" />
  </div>
);

function RunResultsRedirect() {
  const params = useParams();
  const search = useSearchParams();
  const router = useRouter();
  const target = legacyRunResultsTarget(params?.team_id, params?.run_id, search.toString());

  useEffect(() => {
    if (target) router.replace(target);
  }, [router, target]);

  if (!target) return <RunNotFound teamId={Number(params?.team_id) || 0} />;
  return spinner;
}

export default function Page() {
  return (
    <Suspense fallback={spinner}>
      <RunResultsRedirect />
    </Suspense>
  );
}
