"use client";

import { useParams, usePathname } from "next/navigation";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Loader2 } from "lucide-react";
import { toast } from "@/utils/toast";
import { useExportPdf } from "@/components/reports/ExportPdfDialog";
import LLMResults from "@/components/LLMResults";
import { getLLMConversationMessages, type LLMDashboardData } from "@/utils/backend_api";

export default function LLMResultsPage() {
  const params = useParams();
  const pathname = usePathname();
  const queryClient = useQueryClient();
  const team_id = parseInt((params?.team_id as string) ?? "0", 10);
  const conversation_id = parseInt((params?.conversation_id as string) ?? pathname?.split("/").filter(Boolean)[2] ?? "0", 10);

  // The PDF report: its options in a dialog that shows a refused build itself and says the outcome once
  // (components/reports/ExportPdfDialog.tsx). The file keeps its name.
  const pdf = useExportPdf({
    teamId: team_id,
    target: { family: "scan", type: "llm", scanId: conversation_id },
    fileName: `llm_scan_${conversation_id}_report.pdf`,
    successText: "LLM report downloaded",
  });

  if (!team_id || !conversation_id) {
    toast.error("Scan id not found");
    return (
      <div className="flex h-screen w-full items-center justify-center">
        <p className="text-zinc-600 dark:text-zinc-400 mb-4">
          Scan id not found
        </p>
      </div>
    );
  }

  const query = useQuery({
    queryKey: ['llm-conversation-data', team_id, conversation_id],
    queryFn: getLLMConversationMessages,
    enabled: team_id > 0 && conversation_id > 0,
  });

  if (query.isError) {
    return (
      <div className="flex h-screen w-full items-center justify-center">
        <p className="text-zinc-600 dark:text-zinc-400 mb-4">
          Error fetching LLM results. Please try again later.
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

  const llmData = query.data?.data;
  const hasData = llmData != null;
  const hasFindings = Array.isArray(query.data?.findings) && query.data.findings.length > 0;

  if (!hasData && !hasFindings) {
    return (
      <div className="flex h-screen w-full items-center justify-center">
        <p className="text-zinc-600 dark:text-zinc-400 mb-4">
          No LLM results found for this scan.
        </p>
      </div>
    );
  }

  const dashboard = (query.data?.dashboard ?? null) as LLMDashboardData | null;

  return (
    <div className="min-h-screen bg-white dark:bg-zinc-900">
      <LLMResults
        data={llmData ?? null}
        dashboard={dashboard}
        findings={query.data?.findings ?? null}
        scanMetadata={query.data?.scan_metadata ?? null}
        conversationId={conversation_id}
        teamId={params?.team_id as string}
        integrationSettings={query.data?.integration_settings ?? null}
        onIntegrationSettingsUpdated={() => queryClient.invalidateQueries({ queryKey: ['llm-conversation-data', team_id, conversation_id] })}
        onFindingsUpdated={() => queryClient.invalidateQueries({ queryKey: ['llm-conversation-data', team_id, conversation_id] })}
        onRefresh={() => queryClient.invalidateQueries({ queryKey: ['llm-conversation-data', team_id, conversation_id] })}
        onDownloadReport={pdf.open}
        isExporting={pdf.pending}
      />
      {pdf.dialog}
    </div>
  );
}

