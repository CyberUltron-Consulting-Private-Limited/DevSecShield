"use client";

import { Loader2 } from "lucide-react";
import { DASTOptionsSidebar } from "@/components/dast-options-sidebar";
import ChatWindow from "@/components/ai/ChatWindow";
import { useEffect } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { getDASTScan, type DASTScanResponse } from "@/utils/backend_api";
import { useParams } from "next/navigation";
import { toast } from "@/utils/toast";
import { ReadOnlyGate } from "@/components/rbac/team-access";

export default function DASTPage() {
  const params = useParams();
  const team_id = Number(params?.team_id ?? 0);
  const scan_id = Number(params?.scan_id ?? 0);

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

  const queryClient = useQueryClient();
  const query = useQuery<DASTScanResponse>({
    queryKey: ["dast-scan", team_id, scan_id],
    queryFn: () => getDASTScan(team_id, scan_id),
  });

  useEffect(() => {
    if (query.data?.scan_status === "pending" || query.data?.scan_status === "started") {
      const t = setTimeout(() => {
        queryClient.invalidateQueries({ queryKey: ["dast-scan", team_id, scan_id] });
      }, 6 * 1000);
      return () => clearTimeout(t);
    }
  }, [query.data?.scan_status, query.dataUpdatedAt, queryClient, team_id, scan_id]);

  if (query.isError) {
    return (
      <div className="flex h-screen w-full items-center justify-center">
        <p className="text-zinc-600 dark:text-zinc-400 mb-4">
          Error fetching scan data. Please try again later.
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

  const scan_status = query.data?.scan_status ?? "";
  const scanInfo = query.data?.info;
  const isInProgress = scan_status === "pending" || scan_status === "started";
  const progress =
    isInProgress && scanInfo?.current != null ? { current: scanInfo.current } : undefined;

  return (
    <div className="flex flex-col md:flex-row h-screen overflow-y-auto md:overflow-hidden">
      <div className="flex-1 min-h-[75vh] md:min-h-0 min-w-0 bg-white dark:bg-zinc-900 overflow-auto">
        <div className="mx-auto">
          <ChatWindow query={query} progress={progress} />
        </div>
      </div>
      <ReadOnlyGate permission="scan.run" className="contents">
      <DASTOptionsSidebar team_id={team_id} scan_id={scan_id} query={query} />
      </ReadOnlyGate>
    </div>
  );
}
