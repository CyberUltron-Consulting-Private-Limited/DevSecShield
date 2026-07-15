"use client";

import { Loader2 } from "lucide-react";
import { Progress } from "@/components/ui/progress";
import { MCPOptionsSidebar } from "@/components/mcp-options-sidebar";
import ChatWindow, { ChatMessage } from "@/components/ai/ChatWindow";
import { useEffect, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useParams, usePathname } from "next/navigation";
import { toast } from "sonner";
import { getMCPConversationMessages } from "@/utils/backend_api";

export default function MCPPage() {
  const params = useParams();
  const pathname = usePathname();
  const team_id = parseInt((params?.team_id as string) ?? "0", 10);
  const conversation_id = parseInt((params?.conversation_id as string) ?? pathname?.split("/").pop() ?? "0", 10);
  const [scan_status, setScanStatus] = useState<string>("unknown");
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const queryClient = useQueryClient();

  const query = useQuery({
    queryKey: ['mcp-conversation-data', team_id, conversation_id],
    queryFn: getMCPConversationMessages,
    enabled: team_id > 0 && conversation_id > 0,
  });

  if (team_id <= 0 || conversation_id <= 0) {
    toast.error("Conversation id not found");
    return (
      <div className="flex h-screen w-full items-center justify-center">
        <p className="text-zinc-600 dark:text-zinc-400 mb-4">Conversation id not found</p>
      </div>
    );
  }

  useEffect(() => {
    if (query.data?.scan_status === "pending" || query.data?.scan_status === "started") {
      const t = setTimeout(() => {
        queryClient.invalidateQueries({ queryKey: ['mcp-conversation-data', team_id, conversation_id] });
      }, 6 * 1000);
      return () => clearTimeout(t);
    }
  }, [query.data?.scan_status, query.dataUpdatedAt, team_id, conversation_id, queryClient]);

  useEffect(() => {
    setScanStatus(query.data?.scan_status || "unknown");
    setMessages(query.data?.messages || []);
  }, [query.data]);

  if (query.isError) {
    return (
      <div className="flex h-screen w-full items-center justify-center">
        <p className="text-zinc-600 dark:text-zinc-400 mb-4">
          Error in fetching conversation data, please try again later
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

  const scanInfo = query.data?.info;
  const isInProgress = scan_status === "pending" || scan_status === "started";

  return (
    <div className="flex h-screen">
      {/* Main Content Area */}
      <div className="flex-1 bg-white dark:bg-zinc-900 overflow-auto">
        <div className="mx-auto">
          <ChatWindow
            query={query}
            progress={isInProgress && scanInfo?.current != null ? { current: scanInfo.current } : undefined}
          />
        </div>
      </div>

      {/* Right Sidebar - MCP Options */}
      <MCPOptionsSidebar query={query} team_id={team_id} scan_id={conversation_id} />
    </div>
  );
}
