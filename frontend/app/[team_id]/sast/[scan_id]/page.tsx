"use client";

import {
  Triangle,
  Calendar,
  Shield,
  TrendingUp,
  Search,
  Loader2,
} from "lucide-react";
import { SASTOptionsSidebar } from "@/components/sast-options-sidebar";
import ChatWindow, { ChatMessage } from "@/components/ai/ChatWindow";
import { useEffect, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { getSastConversationMessages } from "@/utils/backend_api";
import { useParams } from "next/navigation";
import { toast } from "sonner";
import { Skeleton } from "@/components/ui/skeleton";

const dashboardCards = [
  {
    title: "List down 10 vulnerabilities",
    description: "Displays top 10 discovered vulnerabilities.",
    icon: Triangle,
    iconColor: "text-blue-400",
    bgColor: "bg-blue-50 dark:bg-blue-950/20",
  },
  {
    title: "List down last month vulnerabilities",
    description: "Shows vulnerabilities from last month's scan.",
    icon: Calendar,
    iconColor: "text-green-400",
    bgColor: "bg-green-50 dark:bg-green-950/20",
  },
  {
    title: "List down 10 critical vulnerabilities",
    description: "Filters and displays 10 most severe vulnerabilities.",
    icon: Shield,
    iconColor: "text-blue-400",
    bgColor: "bg-blue-50 dark:bg-blue-950/20",
  },
  {
    title: "List down 10 medium vulnerabilities",
    description: "Filters and displays 10 medium-severity vulnerabilities.",
    icon: TrendingUp,
    iconColor: "text-green-400",
    bgColor: "bg-green-50 dark:bg-green-950/20",
  },
];

export type AppLang = "python" | "javascript" | "java" | "php" | "c" | "ruby" | "rust" | "swift" | "csharp" | "kotlin"  | "unknown"
export type Mode = "github" | "gitlab" | "bitbucket" | "unknown"

function parseId(value: string | undefined): number {
  if (value == null || value === "") return 0;
  const n = Number.parseInt(value, 10);
  return Number.isNaN(n) ? 0 : n;
}

export default function SASTPage() {
  const params = useParams();
  const team_id = parseId(params?.team_id as string | undefined);
  const scan_id = parseId(params?.scan_id as string | undefined);

  const [app_lang, setAppLang] = useState<AppLang>("unknown");
  const [mode, setMode] = useState<Mode>("unknown");
  const [repo_url, setRepoUrl] = useState<string>("");
  const [PAT, setPAT] = useState<string>("");
  const [branch, setBranch] = useState<string>("");
  const [scan_status, setScanStatus] = useState<string>("unknown");
  const [messages, setMessages] = useState<ChatMessage[]>([]);

  const queryClient = useQueryClient();
  const query = useQuery({
    queryKey: ["sast-conversation-data", team_id, scan_id],
    queryFn: getSastConversationMessages,
    enabled: team_id > 0 && scan_id > 0,
  });


  useEffect(() => {
    if (query.data?.scan_status === "pending" || query.data?.scan_status === "started") {
      setTimeout(()=>{
        queryClient.invalidateQueries({ queryKey: ['sast-conversation-data', team_id, scan_id] });
      }, 6 * 1000);
    }
  }, [query.dataUpdatedAt, team_id, scan_id]);

  useEffect(() => {
    setScanStatus(query.data?.scan_status || "unknown");
    setMessages(query.data?.messages || []);
  }, [query.data]);

  if (team_id <= 0 || scan_id <= 0) {
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
        Error in fetching conversation data , please try again later
      </p>
    </div>
  }
  if (query.isLoading || !query.data) {
    return <div className="flex h-screen w-full items-center justify-center">
      <Loader2 className="size-10 animate-spin text-blue-600" />
    </div>;
  }
  const scanInfo = query.data?.info;
  const isInProgress = scan_status === "pending" || scan_status === "started";

  return (
    <div className="flex h-screen">
      {/* Main Content Area */}
      <div className="flex-1 bg-white dark:bg-zinc-900 overflow-auto flex flex-col">
        <div className="mx-auto flex-1 w-full">
          <ChatWindow
            query={query}
            progress={isInProgress && scanInfo?.current != null ? { current: scanInfo.current } : undefined}
          />
        </div>
      </div>

      {/* Right Sidebar - SAST Options */}
      <SASTOptionsSidebar query={query} app_lang={app_lang} setAppLang={setAppLang} mode={mode} setMode={setMode} repo_url={repo_url} setRepoUrl={setRepoUrl} PAT={PAT} setPAT={setPAT} branch={branch} setBranch={setBranch} />
    </div>
  );
}

