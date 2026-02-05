"use client";

import { useParams } from "next/navigation";
import { useQuery } from "@tanstack/react-query";
import { Loader2 } from "lucide-react";
import { toast } from "sonner";
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

  // Extract SAST results and dashboard from the conversation data
  const sastData = query.data?.data;
  const dashboard = query.data?.dashboard;

  if (!sastData) {
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
      <SASTResults data={sastData} conversationId={scan_id} dashboard={dashboard} />
    </div>
  );
}

