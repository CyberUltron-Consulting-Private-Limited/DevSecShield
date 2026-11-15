"use client";

import {
  Loader2,
} from "lucide-react";
import { CBOMOptionsSidebar } from "@/components/cbom-options-sidebar";
import ChatWindow from "@/components/ai/ChatWindow";
import { useEffect, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { getCBOMScanData } from "@/utils/backend_api";
import { isScanGone, scanErrorText } from "@/components/cbom/scanQuery";
import { queryRetry } from "@/utils/query_client";
import { useParams } from "next/navigation";
import { toast } from "@/utils/toast";
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
    retry: (failureCount, error) => !isScanGone(error) && queryRetry(failureCount, error),
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
      <p className="text-zinc-600 dark:text-zinc-400 mb-4" data-testid="cbom-scan-error">
        {scanErrorText(query.error)}
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
      <div className="flex-1 min-h-[75vh] md:min-h-0 min-w-0 bg-white dark:bg-zinc-900 overflow-auto">
        <div className="mx-auto">
          <ChatWindow
            query={query}
            progress={isInProgress && scanInfo?.current != null ? { current: scanInfo.current } : undefined}
            chatDisabledNotice="CBOM runs without any AI model, so there is no chat. Open the results to see each finding's explanation, CVE / CWE / OWASP mapping, remediation steps and proof commands."
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
