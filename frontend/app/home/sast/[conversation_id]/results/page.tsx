"use client";

import { usePathname } from "next/navigation";
import { useQuery } from "@tanstack/react-query";
import { Loader2 } from "lucide-react";
import { toast } from "sonner";
import SASTResults from "@/components/SASTResults";
import { getSastConversationMessages } from "@/utils/backend_api";

export default function SASTResultsPage() {
  const pathname = usePathname();
  // Path format: /home/sast/[conversation_id]/results
  const pathParts = pathname.split('/').filter(Boolean);
  const conversation_id = parseInt(pathParts[2] || '0');
  
  if (!conversation_id) {
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
    queryKey: ['sast-conversation-data', conversation_id],
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
        <Loader2 className="size-10 animate-spin text-teal-600" />
      </div>
    );
  }

  // Extract SAST results from the conversation data
  // The SAST results should be in query.data.data
  const sastData = query.data?.data;

  if (!sastData) {
    return (
      <div className="flex h-screen w-full items-center justify-center">
        <p className="text-zinc-600 dark:text-zinc-400 mb-4">
          No SAST results found for this conversation.
        </p>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-white dark:bg-zinc-900">
      <SASTResults data={sastData} conversationId={conversation_id} />
    </div>
  );
}

