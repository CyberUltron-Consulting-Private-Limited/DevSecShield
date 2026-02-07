"use client";

import { usePathname, useSearchParams } from "next/navigation";
import { useQuery } from "@tanstack/react-query";
import { Loader2 } from "lucide-react";
import { toast } from "sonner";
import CicdSastResults from "@/components/cicd-sast-results";
import { getCicdIntegrationDashboard } from "@/utils/backend_api";

export default function CicdSastResultsPage() {
  const pathname = usePathname();
  const searchParams = useSearchParams();
  
  // Path format: /[team_id]/ci_cd/[integration_id]/sast/results?log_id=...
  const pathParts = pathname.split('/').filter(Boolean);
  const team_id = pathParts[0] ?? '';
  const integration_id = pathParts[2] ?? '';
  const log_id = searchParams.get('log_id');

  if (!integration_id) {
    toast.error("Integration id not found");
    return (
      <div className="flex h-screen w-full items-center justify-center">
        <p className="text-zinc-600 dark:text-zinc-400 mb-4">
          Integration id not found
        </p>
      </div>
    );
  }

  if (!log_id) {
    toast.error("Log id not found");
    return (
      <div className="flex h-screen w-full items-center justify-center">
        <p className="text-zinc-600 dark:text-zinc-400 mb-4">
          Log id not found. Please select a log from the dashboard.
        </p>
      </div>
    );
  }

  const query = useQuery({
    queryKey: ['cicd-integration-dashboard', team_id, integration_id, 100, 0],
    queryFn: getCicdIntegrationDashboard,
    enabled: !!team_id && !!integration_id,
  });

  if (query.isError) {
    return (
      <div className="flex h-screen w-full items-center justify-center">
        <p className="text-zinc-600 dark:text-zinc-400 mb-4">
          Error fetching CI/CD integration data. Please try again later.
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

  // Find the specific log by ID
  const dashboardData = query.data;
  if (!dashboardData) {
    return (
      <div className="flex h-screen w-full items-center justify-center">
        <p className="text-zinc-600 dark:text-zinc-400 mb-4">
          No dashboard data found.
        </p>
      </div>
    );
  }

  // Find the log - handle both string and ObjectId cases
  const log = dashboardData.logs.find(
    (l) => l.id.toString() === log_id.toString()
  );

  if (!log) {
    return (
      <div className="flex h-screen w-full items-center justify-center">
        <p className="text-zinc-600 dark:text-zinc-400 mb-4">
          Log not found. It may have been deleted or the ID is invalid.
        </p>
      </div>
    );
  }

  // Extract SAST results from the log's results field
  const sastData = log.results;

  if (!sastData) {
    return (
      <div className="flex h-screen w-full items-center justify-center">
        <p className="text-zinc-600 dark:text-zinc-400 mb-4">
          No SAST results found for this log. The scan may not have completed successfully.
        </p>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-white dark:bg-zinc-900">
      <CicdSastResults
        data={sastData}
        dashboard={log.dashboard ?? undefined}
        integrationId={integration_id}
      />
    </div>
  );
}

