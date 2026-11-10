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
  const [branch, setBranch] = useState<string>("");
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
      const t = setTimeout(() => {
        queryClient.invalidateQueries({ queryKey: ["iac-conversation-data", team_id, scan_id] });
      }, 6 * 1000);
      return () => clearTimeout(t);
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
    <div className="flex flex-col md:flex-row h-screen overflow-y-auto md:overflow-hidden">
      <div className="flex-1 min-h-[75vh] md:min-h-0 min-w-0 bg-white dark:bg-zinc-900 overflow-auto flex flex-col">
        <div className="mx-auto flex-1 w-full">
          <ChatWindow
            query={query}
            progress={isInProgress && scanInfo?.current != null ? { current: scanInfo.current } : undefined}
          />
        </div>
      </div>
      <IACOptionsSidebar query={query} mode={mode} setMode={setMode} repo_url={repo_url} setRepoUrl={setRepoUrl} PAT={PAT} setPAT={setPAT} branch={branch} setBranch={setBranch} />
    </div>
  );
}
