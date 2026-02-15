"use client";

import { Loader2 } from "lucide-react";
import { Progress } from "@/components/ui/progress";
import { IACOptionsSidebar } from "@/components/iac-options-sidebar";
import ChatWindow, { ChatMessage } from "@/components/ai/ChatWindow";
import { useEffect, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { getIACConversationMessages } from "@/utils/backend_api";
import { useParams } from "next/navigation";
import { toast } from "sonner";
import { Mode } from "@/app/[team_id]/sast/[scan_id]/page";

export default function IACPage() {
  const [mode, setMode] = useState<Mode>("unknown");
  const [repo_url, setRepoUrl] = useState<string>("");
  const [PAT, setPAT] = useState<string>("");
  const [scan_status, setScanStatus] = useState<string>("unknown");
  const [messages, setMessages] = useState<ChatMessage[]>([]);

  const params = useParams();
  const team_id = parseInt((params?.team_id as string) ?? "0", 10);
  const scan_id = parseInt((params?.scan_id as string) ?? "0", 10);
  if (!team_id || !scan_id) {
    toast.error("Team or scan id not found");
    return (
      <div className="flex h-screen w-full items-center justify-center">
        <p className="text-zinc-600 dark:text-zinc-400 mb-4">Team or scan id not found</p>
      </div>
    );
  }
  const queryClient = useQueryClient();
  const query = useQuery({
    queryKey: ["iac-conversation-data", team_id, scan_id],
    queryFn: getIACConversationMessages,
  });

  useEffect(() => {
    if (query.data?.scan_status === "pending" || query.data?.scan_status === "started") {
      setTimeout(() => {
        queryClient.invalidateQueries({ queryKey: ["iac-conversation-data", team_id, scan_id] });
      }, 6 * 1000);
    }
  }, [query.dataUpdatedAt, scan_id, team_id, queryClient]);

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
      <Loader2 className="size-10 animate-spin text-blue-600" />
    </div>;
  }
  const scanInfo = query.data?.info;
  const isInProgress = scan_status === "pending" || scan_status === "started";

  return (
    <div className="flex h-screen">
      <div className="flex-1 bg-white dark:bg-zinc-900 overflow-auto flex flex-col">
        {/* Progress bar */}
        {isInProgress && scanInfo?.current != null && (
          <div className="px-6 pt-4 pb-2">
            <div className="flex items-center gap-3">
              <Loader2 className="h-4 w-4 animate-spin text-blue-600 shrink-0" />
              <div className="flex-1">
                <div className="flex items-center justify-between mb-1">
                  <span className="text-sm font-medium text-zinc-700 dark:text-zinc-300">Scan in progress</span>
                  <span className="text-sm tabular-nums text-zinc-500">{scanInfo.current}%</span>
                </div>
                <Progress value={scanInfo.current} className="h-2" />
              </div>
            </div>
          </div>
        )}
        <div className="mx-auto flex-1 w-full">
          <ChatWindow query={query}/>
        </div>
      </div>
      <IACOptionsSidebar query={query} mode={mode} setMode={setMode} repo_url={repo_url} setRepoUrl={setRepoUrl} PAT={PAT} setPAT={setPAT} />
    </div>
  );
}
