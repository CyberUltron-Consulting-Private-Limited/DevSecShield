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
import { useParams, usePathname } from "next/navigation";
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

interface SASTPageProps {
  params: {
    conversation_id: string;
  };
}
export type AppLang = "python" | "javascript" | "java" | "php" | "c" | "ruby" | "rust" | "swift" | "csharp" | "kotlin"  | "unknown"
export type Mode = "github" | "gitlab" | "bitbucket" | "unknown"
export default function SASTPage({ params }: SASTPageProps) {
  const [app_lang, setAppLang] = useState<AppLang>("unknown");
  const [mode, setMode] = useState<Mode>("unknown");
  const [repo_url, setRepoUrl] = useState<string>("");
  const [PAT, setPAT] = useState<string>("");

  const [ scan_status, setScanStatus ] = useState<string>("unknown");
  const [ messages, setMessages ] = useState<ChatMessage[]>([]);

  const conversation_id = parseInt(usePathname().split('/').pop() || '0');
  if (!conversation_id) {
    toast.error("Conversation id not found");
    return
  } 
  const queryClient = useQueryClient();
  const query = useQuery({queryKey: ['sast-conversation-data', conversation_id] , queryFn : getSastConversationMessages});


  useEffect(() => {
    if (query.data?.scan_status === "pending" || query.data?.scan_status === "started") {
      setTimeout(()=>{
        queryClient.invalidateQueries({ queryKey: ['sast-conversation-data', conversation_id] });
      }, 6 * 1000);
    }
  }, [query.dataUpdatedAt, conversation_id, queryClient]);

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
      {/* Main Content Area */}
      <div className="flex-1 bg-white dark:bg-zinc-900  overflow-auto">
        <div className="mx-auto">
          <ChatWindow query={query}/>
        </div>
      </div>

      {/* Right Sidebar - SAST Options */}
      <SASTOptionsSidebar query={query} app_lang={app_lang} setAppLang={setAppLang} mode={mode} setMode={setMode} repo_url={repo_url} setRepoUrl={setRepoUrl} PAT={PAT} setPAT={setPAT} />
    </div>
  );
}

