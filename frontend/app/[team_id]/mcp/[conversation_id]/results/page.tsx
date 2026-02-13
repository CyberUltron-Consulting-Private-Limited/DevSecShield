"use client";

import { useParams, usePathname } from "next/navigation";
import { useQuery, useQueryClient, useMutation } from "@tanstack/react-query";
import { Loader2 } from "lucide-react";
import { toast } from "sonner";
import MCPResults from "@/components/MCPResults";
import { getMCPConversationMessages, getMCPExportResults } from "@/utils/backend_api";
import { showErrorToast } from "@/utils/error-handler";

export default function MCPResultsPage() {
  const params = useParams();
  const pathname = usePathname();
  const queryClient = useQueryClient();
  const team_id = parseInt((params?.team_id as string) ?? "0", 10);
  const conversation_id = parseInt((params?.conversation_id as string) ?? pathname?.split("/").filter(Boolean)[2] ?? "0", 10);

  if (!team_id || !conversation_id) {
    toast.error("Conversation id not found");
    return (
      <div className="flex h-screen w-full items-center justify-center">
        <p className="text-zinc-600 dark:text-zinc-400 mb-4">
          Conversation id not found
        </p>
      </div>
    );
  }

  const query = useQuery({
    queryKey: ['mcp-conversation-data', team_id, conversation_id],
    queryFn: getMCPConversationMessages,
    enabled: team_id > 0 && conversation_id > 0,
  });

  const exportMutation = useMutation({
    mutationFn: () => getMCPExportResults(team_id, conversation_id),
    onSuccess: (blob) => {
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `mcp_scan_${conversation_id}_report.pdf`;
      a.click();
      URL.revokeObjectURL(url);
    },
    onError: (err) => showErrorToast(err, "Failed to download scan report"),
  });

  if (query.isError) {
    return (
      <div className="flex h-screen w-full items-center justify-center">
        <p className="text-zinc-600 dark:text-zinc-400 mb-4">
          Error fetching MCP results. Please try again later.
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

  const mcpData = query.data?.data;
  const dashboard = query.data?.dashboard ?? null;

  if (!mcpData) {
    return (
      <div className="flex h-screen w-full items-center justify-center">
        <p className="text-zinc-600 dark:text-zinc-400 mb-4">
          No MCP results found for this conversation.
        </p>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-white dark:bg-zinc-900">
      <MCPResults
        data={mcpData}
        conversationId={conversation_id}
        teamId={params?.team_id as string}
        dashboard={dashboard}
        integrationSettings={query.data?.integration_settings ?? null}
        onIntegrationSettingsUpdated={() => queryClient.invalidateQueries({ queryKey: ['mcp-conversation-data', team_id, conversation_id] })}
        onRefresh={() => queryClient.invalidateQueries({ queryKey: ['mcp-conversation-data', team_id, conversation_id] })}
        onDownloadReport={() => exportMutation.mutate()}
        isExporting={exportMutation.isPending}
      />
    </div>
  );
}

