"use client";

import {
  Loader2,
} from "lucide-react";
import { CBOMOptionsSidebar } from "@/components/cbom-options-sidebar";
import ChatWindow from "@/components/ai/ChatWindow";
import { useEffect, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { getCBOMScanData } from "@/utils/backend_api";
import { useParams } from "next/navigation";
import { toast } from "sonner";
import { Mode } from "@/app/[team_id]/sast/[scan_id]/page";

export default function CBOMScanPage() {
  const [mode, setMode] = useState<Mode>("unknown");
  const [repo_url, setRepoUrl] = useState<string>("");
  const [PAT, setPAT] = useState<string>("");
  const [branch, setBranch] = useState<string>("");
  const [scan_binaries, setScanBinaries] = useState<boolean>(false);
  const [scan_status, setScanStatus] = useState<string>("unknown");
  const [messages, setMessages] = useState<{ id: number; content: string; role: "user" | "assistant"; timestamp: string; is_streaming: boolean }[]>([]);

  const params = useParams();
  const team_id = parseInt((params?.team_id as string) ?? "0", 10);
  const scan_id = parseInt((params?.scan_id as string) ?? "0", 10);
  const hasValidIds = !!team_id && !!scan_id;
  const queryClient = useQueryClient();
  const query = useQuery({
    queryKey: ["cbom-conversation-data", team_id, scan_id],
    queryFn: getCBOMScanData,
    enabled: hasValidIds,
  });

  useEffect(() => {
    if (query.data?.scan_status === "pending" || query.data?.scan_status === "started") {
      const t = setTimeout(() => {
        queryClient.invalidateQueries({ queryKey: ["cbom-conversation-data", team_id, scan_id] });
      }, 6 * 1000);
      return () => clearTimeout(t);
    }
  }, [query.dataUpdatedAt, scan_id, team_id, queryClient]);

  useEffect(() => {
    setScanStatus(query.data?.scan_status || "unknown");
    setMessages(query.data?.messages || []);
    // Restore scan_binaries from the previous scan's metadata on first load
    if (query.data?.scan_metadata?.scan_binaries === true || query.data?.scan_metadata?.scan_binaries === false) {
      setScanBinaries(query.data.scan_metadata.scan_binaries);
    }
  }, [query.data]);

  if (!hasValidIds) {
    toast.error("Team or scan id not found");
    return (
      <div className="flex h-screen w-full items-center justify-center">
        <p className="text-zinc-600 dark:text-zinc-400 mb-4">
          Team or scan id not found
        </p>
      </div>
    );
  }

  if (query.isError) {
    return <div className="flex h-screen w-full items-center justify-center">
      <p className="text-zinc-600 dark:text-zinc-400 mb-4">
        Error in fetching scan data, please try again later
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
      <div className="flex-1 bg-white dark:bg-zinc-900 overflow-auto">
        <div className="mx-auto">
          <ChatWindow
            query={query}
            progress={isInProgress && scanInfo?.current != null ? { current: scanInfo.current } : undefined}
          />
        </div>
      </div>
      <CBOMOptionsSidebar
        query={query}
        mode={mode}
        setMode={setMode}
        repo_url={repo_url}
        setRepoUrl={setRepoUrl}
        PAT={PAT}
        setPAT={setPAT}
        branch={branch}
        setBranch={setBranch}
        scan_binaries={scan_binaries}
        setScanBinaries={setScanBinaries}
      />
    </div>
  );
}
