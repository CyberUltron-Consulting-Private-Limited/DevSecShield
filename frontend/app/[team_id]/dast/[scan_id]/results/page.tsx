"use client";

import { useParams } from "next/navigation";
import { useQuery, useQueryClient, useMutation } from "@tanstack/react-query";
import { Loader2 } from "lucide-react";
import { toast } from "sonner";
import DASTResults from "@/components/DASTResults";
import { getDASTScan, getDASTExportResults } from "@/utils/backend_api";
import { showErrorToast } from "@/utils/error-handler";

export default function DASTResultsPage() {
  const params = useParams();
  const queryClient = useQueryClient();
  const team_id = parseInt((params?.team_id as string) ?? "0", 10);
  const scan_id = parseInt((params?.scan_id as string) ?? "0", 10);

  const exportMutation = useMutation({
    mutationFn: () => getDASTExportResults(team_id, scan_id),
    onSuccess: (data) => {
      const blob = new Blob([data], { type: "application/pdf" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `dast_scan_${scan_id}_report.pdf`;
      a.click();
      URL.revokeObjectURL(url);
      toast.success("Report downloaded");
    },
    onError: (err) => showErrorToast(err, "Failed to download report"),
  });

  if (!team_id || !scan_id) {
    toast.error("Team or scan id not found");
    return (
      <div className="flex h-screen w-full items-center justify-center">
        <p className="text-zinc-600 dark:text-zinc-400 mb-4">Team or scan id not found</p>
      </div>
    );
  }

  const query = useQuery({
    queryKey: ["dast-scan", team_id, scan_id],
    queryFn: () => getDASTScan(team_id, scan_id),
  });

  if (query.isError) {
    return (
      <div className="flex h-screen w-full items-center justify-center">
        <p className="text-zinc-600 dark:text-zinc-400 mb-4">Error fetching DAST results. Please try again later.</p>
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

  const dashboard = query.data?.dashboard ?? null;
  const findings = query.data?.findings ?? null;
  const hasResults = dashboard != null || (Array.isArray(findings) && findings.length > 0);

  if (!hasResults) {
    return (
      <div className="flex h-screen w-full items-center justify-center">
        <p className="text-zinc-600 dark:text-zinc-400 mb-4">No DAST results found for this scan.</p>
      </div>
    );
  }

  return (
    <DASTResults
      teamId={String(team_id)}
      scanId={scan_id}
      title={query.data?.title}
      scanStatus={query.data?.scan_status}
      dashboard={dashboard}
      findings={findings}
      scanMetadata={query.data?.scan_metadata ?? null}
      integrationSettings={query.data?.integration_settings ?? null}
      onIntegrationSettingsUpdated={() => queryClient.invalidateQueries({ queryKey: ["dast-scan", team_id, scan_id] })}
      onDownloadReport={() => exportMutation.mutate()}
      isExporting={exportMutation.isPending}
    />
  );
}
