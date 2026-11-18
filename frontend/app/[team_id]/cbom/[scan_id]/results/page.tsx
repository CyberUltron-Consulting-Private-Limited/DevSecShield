"use client";

import { useParams, useRouter, useSearchParams } from "next/navigation";
import { Suspense, useEffect } from "react";
import { useQuery } from "@tanstack/react-query";
import { Loader2 } from "lucide-react";
import { toast } from "@/utils/toast";
import CbomResults from "@/components/CbomResults";
import { getCBOMScanData } from "@/utils/backend_api";
import { isScanGone, scanErrorText } from "@/components/cbom/scanQuery";
import { queryRetry } from "@/utils/query_client";
import { asksForRun, parseCbomResultsId, runResultsHref } from "@/components/cbom/results/resultsHref";
import RunResultsRoute from "@/components/cbom/results/RunResultsRoute";

const spinner = (
  <div className="flex h-screen w-full items-center justify-center">
    <Loader2 className="size-10 animate-spin text-blue-600" />
  </div>
);

// /{team_id}/cbom/<id>/results is the one results template. `?run=1` opens Sources run <id>
// (scan ids and run ids overlap, so the plain path stays the code scan). `run-<id>` only redirects there.
export default function CbomResultsPage() {
  const params = useParams();
  const team_id = parseInt((params?.team_id as string) ?? "0", 10);
  const id = parseCbomResultsId(params?.scan_id);

  if (!team_id || !id) {
    toast.error("Team or scan id not found");
    return (
      <div className="flex h-screen w-full items-center justify-center">
        <p className="text-zinc-600 dark:text-zinc-400 mb-4">
          Team or scan id not found
        </p>
      </div>
    );
  }
  if (id.kind === "run") {
    return (
      <Suspense fallback={spinner}>
        <RunPrefixRedirect teamId={team_id} runId={id.id} />
      </Suspense>
    );
  }
  return (
    <Suspense fallback={spinner}>
      <NumericResults teamId={team_id} scanId={id.id} />
    </Suspense>
  );
}

function RunPrefixRedirect({ teamId, runId }: { teamId: number; runId: number }) {
  const search = useSearchParams();
  const router = useRouter();
  const target = runResultsHref(teamId, runId, search.toString());

  useEffect(() => {
    router.replace(target);
  }, [router, target]);

  return spinner;
}

function NumericResults({ teamId, scanId }: { teamId: number; scanId: number }) {
  const search = useSearchParams();
  if (asksForRun(search.toString())) return <RunResultsRoute teamId={teamId} runId={scanId} />;
  return <ScanResults team_id={teamId} scan_id={scanId} />;
}

function ScanResults({ team_id, scan_id }: { team_id: number; scan_id: number }) {
  const query = useQuery({
    queryKey: ["cbom-conversation-data", team_id, scan_id],
    queryFn: getCBOMScanData,
    retry: (failureCount, error) => !isScanGone(error) && queryRetry(failureCount, error),
  });

  if (query.isError) {
    return (
      <div className="flex h-screen w-full items-center justify-center">
        <p className="text-zinc-600 dark:text-zinc-400 mb-4" data-testid="cbom-scan-error">
          {scanErrorText(query.error)}
        </p>
      </div>
    );
  }

  if (query.isLoading) {
    return (
      <div className="flex h-screen w-full items-center justify-center">
        <Loader2 className="size-10 animate-spin text-blue-600" />
      </div>
    );
  }

  const scanData = query.data?.data;
  const dashboard = query.data?.dashboard ?? null;
  const findings = query.data?.findings ?? null;
  const scanMetadata = query.data?.scan_metadata ?? null;
  const integrationSettings = query.data?.integration_settings ?? undefined;

  return (
    <div className="min-h-screen bg-white dark:bg-zinc-900">
      <CbomResults
        data={scanData}
        dashboard={dashboard}
        findings={findings}
        scanMetadata={scanMetadata}
        conversationId={scan_id}
        teamId={String(team_id)}
        integrationSettings={integrationSettings}
        onIntegrationSettingsUpdated={() => query.refetch()}
        onFindingsUpdated={() => query.refetch()}
      />
    </div>
  );
}
