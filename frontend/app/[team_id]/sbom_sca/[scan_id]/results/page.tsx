"use client";

import { useParams } from "next/navigation";
import { useQuery } from "@tanstack/react-query";
import { Loader2 } from "lucide-react";
import { toast } from "@/utils/toast";
import SbomResults from "@/components/SbomResults";
import { getSBOMSCAScanData } from "@/utils/backend_api";

export default function SbomResultsPage() {
  const params = useParams();
  const team_id = parseInt((params?.team_id as string) ?? "0", 10);
  const scan_id = parseInt((params?.scan_id as string) ?? "0", 10);

  if (!team_id || !scan_id) {
    toast.error("Team or scan id not found");
    return (
      <div className="flex h-screen w-full items-center justify-center">
        <p className="text-zinc-600 dark:text-zinc-400 mb-4">
          Team or scan id not found
        </p>
      </div>
    );
  }

  const query = useQuery({
    queryKey: ["sbom_sca-conversation-data", team_id, scan_id],
    queryFn: getSBOMSCAScanData,
  });

  if (query.isError) {
    return (
      <div className="flex h-screen w-full items-center justify-center">
        <p className="text-zinc-600 dark:text-zinc-400 mb-4">
          Error fetching SBOM results. Please try again later.
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
      <SbomResults
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
