"use client";

import { useParams } from "next/navigation";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Loader2 } from "lucide-react";
import { toast } from "@/utils/toast";
import { useExportPdf } from "@/components/reports/ExportPdfDialog";
import DASTResults from "@/components/DASTResults";
import { getDASTScan } from "@/utils/backend_api";

export default function DASTResultsPage() {
  const params = useParams();
  const queryClient = useQueryClient();
  const team_id = parseInt((params?.team_id as string) ?? "0", 10);
  const scan_id = parseInt((params?.scan_id as string) ?? "0", 10);

  // The PDF report: its options in a dialog that shows a refused build itself and says the outcome once
  // (components/reports/ExportPdfDialog.tsx). The file keeps its name.
  const pdf = useExportPdf({
    teamId: team_id,
    target: { family: "scan", type: "dast", scanId: scan_id },
    fileName: `dast_scan_${scan_id}_report.pdf`,
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
    <>
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
        onDownloadReport={pdf.open}
        isExporting={pdf.pending}
      />
      {pdf.dialog}
    </>
  );
}
