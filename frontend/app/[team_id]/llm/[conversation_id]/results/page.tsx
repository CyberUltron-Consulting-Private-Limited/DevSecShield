"use client";

import { usePathname } from "next/navigation";
import { useQuery } from "@tanstack/react-query";
import { Loader2 } from "lucide-react";
import { toast } from "sonner";
import LLMResults from "@/components/LLMResults";
import { getLLMConversationMessages } from "@/utils/backend_api";

export default function LLMResultsPage() {
  const pathname = usePathname();
  // Path format: /home/llm/[conversation_id]/results
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
    queryKey: ['llm-conversation-data', conversation_id],
    queryFn: getLLMConversationMessages,
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

  // Extract LLM results from the conversation data
  // The LLM results should be in query.data.data
  const llmData = query.data?.data;

  if (!llmData) {
    return (
      <div className="flex h-screen w-full items-center justify-center">
        <p className="text-zinc-600 dark:text-zinc-400 mb-4">
          No LLM results found for this conversation.
        </p>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-white dark:bg-zinc-900">
      <LLMResults data={llmData} conversationId={conversation_id} />
    </div>
  );
}

