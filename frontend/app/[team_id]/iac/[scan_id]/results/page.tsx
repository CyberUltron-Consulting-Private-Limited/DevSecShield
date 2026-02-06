"use client";

import { useParams } from "next/navigation";
import { useQuery } from "@tanstack/react-query";
import { Loader2 } from "lucide-react";
import { toast } from "sonner";
import IACResults from "@/components/IACResults";
import { getIACConversationMessages } from "@/utils/backend_api";

export default function IACResultsPage() {
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
    queryKey: ["iac-conversation-data", team_id, scan_id],
    queryFn: getIACConversationMessages,
  });

  if (query.isError) {
    return (
      <div className="flex h-screen w-full items-center justify-center">
        <p className="text-zinc-600 dark:text-zinc-400 mb-4">
          Error fetching IAC results. Please try again later.
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

  // IAC scan data: backend returns query.data.data as array of vulnerabilities (worker_iac_agent format)
  const iacData = query.data?.data;
  const dashboard = query.data?.dashboard;
  const integrationSettings = query.data?.integration_settings ?? undefined;

  // Normalize: accept either direct array or legacy { results: [] }
  const dataArray = Array.isArray(iacData)
    ? iacData
    : iacData && Array.isArray((iacData as { results?: unknown[] }).results)
      ? (iacData as { results: unknown[] }).results
      : null;

  return (
    <div className="min-h-screen bg-white dark:bg-zinc-900">
      <IACResults
        data={dataArray ?? undefined}
        conversationId={scan_id}
        dashboard={dashboard}
        teamId={String(team_id)}
        integrationSettings={integrationSettings}
        onIntegrationSettingsUpdated={() => query.refetch()}
      />
    </div>
  );
}

