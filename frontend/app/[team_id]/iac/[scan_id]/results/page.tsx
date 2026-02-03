"use client";

import { useParams } from "next/navigation";
import { useQuery } from "@tanstack/react-query";
import { Loader2 } from "lucide-react";
import { toast } from "sonner";
import IACResults from "@/components/IACResults";
import { getIACConversationMessages } from "@/utils/backend_api";

export default function IACResultsPage() {
  const params = useParams();
  const scan_id = parseInt((params?.scan_id as string) ?? "0", 10);

  if (!scan_id) {
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
    queryKey: ['iac-conversation-data', scan_id],
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

  // Extract IAC results from the conversation data
  // The IAC results should be in query.data.data
  const iacData = query.data?.data;

  if (!iacData || !iacData.results) {
    return (
      <div className="flex h-screen w-full items-center justify-center">
        <p className="text-zinc-600 dark:text-zinc-400 mb-4">
          No IAC results found for this scan.
        </p>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-white dark:bg-zinc-900">
      <IACResults data={iacData} conversationId={scan_id} />
    </div>
  );
}

