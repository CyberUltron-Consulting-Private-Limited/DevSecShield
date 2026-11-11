"use client";

import { useParams } from "next/navigation";
import { useQuery } from "@tanstack/react-query";
import { Loader2 } from "lucide-react";
import { toast } from "@/utils/toast";
import SASTResults from "@/components/SASTResults";
import { getSastConversationMessages } from "@/utils/backend_api";

export default function SASTResultsPage() {
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
    queryKey: ['sast-conversation-data', team_id, scan_id],
    queryFn: getSastConversationMessages,
  });

  if (query.isError) {
    return (
      <div className="flex h-screen w-full items-center justify-center">
        <p className="text-zinc-600 dark:text-zinc-400 mb-4">
          Error fetching SAST results. Please try again later.
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

  const dashboard = query.data?.dashboard;
  const findings = query.data?.findings ?? undefined;
  const scanMetadata = query.data?.scan_metadata ?? undefined;
  const integrationSettings = query.data?.integration_settings ?? undefined;

  const hasFindings = Array.isArray(findings) && findings.length > 0;
  const hasDashboard = dashboard != null;
  const hasResults = hasFindings || hasDashboard;
  if (!hasResults) {
    return (
      <div className="flex h-screen w-full items-center justify-center">
        <p className="text-zinc-600 dark:text-zinc-400 mb-4">
          No SAST results found for this scan.
        </p>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-white dark:bg-zinc-900">
      <SASTResults
        conversationId={scan_id}
        dashboard={dashboard}
        findings={findings}
        teamId={String(team_id)}
        scanMetadata={scanMetadata}
        integrationSettings={integrationSettings}
        onIntegrationSettingsUpdated={() => query.refetch()}
        onFindingsUpdated={() => query.refetch()}
      />
    </div>
  );
}

