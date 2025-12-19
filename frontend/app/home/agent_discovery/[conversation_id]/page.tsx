"use client";

import {
  Loader2,
} from "lucide-react";
import { DiscoveryOptionsSidebar } from "@/components/discovery-options-sidebar";
import ChatWindow, { ChatMessage } from "@/components/ai/ChatWindow";
import { useEffect, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { getDiscoveryConversationMessages } from "@/utils/backend_api";
import { usePathname } from "next/navigation";
import { toast } from "sonner";
import { Mode } from "@/app/home/sast/[conversation_id]/page";

export default function DiscoveryPage() {
  const [mode, setMode] = useState<Mode>("unknown");
  const [repo_url, setRepoUrl] = useState<string>("");
  const [PAT, setPAT] = useState<string>("");
  const [scan_status, setScanStatus] = useState<string>("unknown");
  const [messages, setMessages] = useState<ChatMessage[]>([]);

  const conversation_id = parseInt(usePathname().split('/').pop() || '0');
  if (!conversation_id) {
    toast.error("Conversation id not found");
    return
  } 
  const queryClient = useQueryClient();
  const query = useQuery({queryKey: ['discovery-conversation-data', conversation_id] , queryFn : getDiscoveryConversationMessages});

  useEffect(() => {
    if (query.data?.scan_status === "pending" || query.data?.scan_status === "started") {
      setTimeout(()=>{
        queryClient.invalidateQueries({ queryKey: ['discovery-conversation-data', conversation_id] });
      }, 6 * 1000);
    }
  }, [query.dataUpdatedAt, conversation_id]);

  useEffect(() => {
    setScanStatus(query.data?.scan_status || "unknown");
    setMessages(query.data?.messages || []);
  }, [query.data]);

  if (query.isError) {
    return <div className="flex h-screen w-full items-center justify-center">
      <p className="text-zinc-600 dark:text-zinc-400 mb-4">
        Error in fetching conversation data , please try again later
      </p>
    </div>
  }
  if (query.isLoading) {
    return <div className="flex h-screen w-full items-center justify-center">
      <Loader2 className="size-10 animate-spin text-teal-600" />
    </div>;
  }
  return (
    <div className="flex h-screen">
      <div className="flex-1 bg-white dark:bg-zinc-900  overflow-auto">
        <div className="mx-auto">
          <ChatWindow query={query}/>
        </div>
      </div>
      <DiscoveryOptionsSidebar query={query} mode={mode} setMode={setMode} repo_url={repo_url} setRepoUrl={setRepoUrl} PAT={PAT} setPAT={setPAT} />
    </div>
  );
}
