"use client";

import {
  Loader2,
} from "lucide-react";
import { SCASBOMOptionsSidebar } from "@/components/sca-sbom-options-sidebar";
import ChatWindow from "@/components/ai/ChatWindow";
import { useEffect, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { getSBOMSCAScanData } from "@/utils/backend_api";
import { useParams } from "next/navigation";
import { toast } from "sonner";
import { Mode } from "@/app/[team_id]/sast/[scan_id]/page";

export default function SCASBOMPage() {
  const [mode, setMode] = useState<Mode>("unknown");
  const [repo_url, setRepoUrl] = useState<string>("");
  const [PAT, setPAT] = useState<string>("");
  const [branch, setBranch] = useState<string>("");
  const [scan_status, setScanStatus] = useState<string>("unknown");
  const [messages, setMessages] = useState<{ id: number; content: string; role: "user" | "assistant"; timestamp: string; is_streaming: boolean }[]>([]);

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
  const queryClient = useQueryClient();
  const query = useQuery({
    queryKey: ["sbom_sca-conversation-data", team_id, scan_id],
    queryFn: getSBOMSCAScanData,
  });

  useEffect(() => {
    if (query.data?.scan_status === "pending" || query.data?.scan_status === "started") {
      setTimeout(() => {
        queryClient.invalidateQueries({ queryKey: ["sbom_sca-conversation-data", team_id, scan_id] });
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
  return (
    <div className="flex h-screen">
      <div className="flex-1 bg-white dark:bg-zinc-900 overflow-auto">
        <div className="mx-auto">
          <ChatWindow query={query} />
        </div>
      </div>
      <SCASBOMOptionsSidebar
        query={query}
        mode={mode}
        setMode={setMode}
        repo_url={repo_url}
        setRepoUrl={setRepoUrl}
        PAT={PAT}
        setPAT={setPAT}
        branch={branch}
        setBranch={setBranch}
      />
    </div>
  );
}
