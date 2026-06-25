"use client";

import { useParams } from "next/navigation";
import { useQuery } from "@tanstack/react-query";
import { Loader2 } from "lucide-react";
import { toast } from "sonner";
import CbomResults from "@/components/CbomResults";
import { getCBOMScanData } from "@/utils/backend_api";

export default function CbomResultsPage() {
  const params = useParams();
  const team_id = parseInt((params?.team_id as string) ?? "0", 10);
  const scan_id = parseInt((params?.scan_id as string) ?? "0", 10);
  const hasValidIds = !!team_id && !!scan_id;

  const query = useQuery({
    queryKey: ["cbom-conversation-data", team_id, scan_id],
    queryFn: getCBOMScanData,
    enabled: hasValidIds,
  });

  if (!hasValidIds) {
    toast.error("Team or scan id not found");
    return (
      <div className="flex h-screen w-full items-center justify-center">
        <p className="text-zinc-600 dark:text-zinc-400 mb-4">
          Team or scan id not found
        </p>
      </div>
    );
  }

  if (query.isError) {
    return (
      <div className="flex h-screen w-full items-center justify-center">
        <p className="text-zinc-600 dark:text-zinc-400 mb-4">
          Error fetching CBOM results. Please try again later.
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
