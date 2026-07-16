"use client";

import { Loader2 } from "lucide-react";
import { useEffect } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useParams } from "next/navigation";
import { toast } from "sonner";
import ChatWindow from "@/components/ai/ChatWindow";
import { MobileOptionsSidebar } from "@/components/mobile-options-sidebar";
import { getMobileScanData } from "@/utils/backend_api";

export default function MobileScanPage() {
  const params = useParams();
  const team_id = parseInt((params?.team_id as string) ?? "0", 10);
  const scan_id = parseInt((params?.scan_id as string) ?? "0", 10);
  const hasValidIds = !!team_id && !!scan_id;
  const queryClient = useQueryClient();

  const query = useQuery({
    queryKey: ["mobile-conversation-data", team_id, scan_id],
    queryFn: getMobileScanData,
    enabled: hasValidIds,
  });

  useEffect(() => {
    if (query.data?.scan_status === "pending" || query.data?.scan_status === "started") {
      const t = setTimeout(() => {
        queryClient.invalidateQueries({ queryKey: ["mobile-conversation-data", team_id, scan_id] });
      }, 6000);
      return () => clearTimeout(t);
    }
  }, [query.dataUpdatedAt, scan_id, team_id, queryClient, query.data?.scan_status]);

  if (!hasValidIds) {
    toast.error("Team or scan id not found");
    return (
      <div className="flex h-screen w-full items-center justify-center">
        <p className="text-zinc-600 dark:text-zinc-400">Team or scan id not found</p>
      </div>
    );
  }

  if (query.isError) {
    return (
      <div className="flex h-screen w-full items-center justify-center">
        <p className="text-zinc-600 dark:text-zinc-400">Error loading scan</p>
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

  const scanInfo = query.data?.info;
  const isInProgress =
    query.data?.scan_status === "pending" || query.data?.scan_status === "started";

  return (
    <div className="flex h-screen">
      <div className="flex-1 bg-white dark:bg-zinc-900 overflow-auto">
        <ChatWindow
          query={query as never}
          progress={
            isInProgress && scanInfo?.current != null
              ? { current: scanInfo.current }
              : undefined
          }
        />
      </div>
      <MobileOptionsSidebar query={query} />
    </div>
  );
}
