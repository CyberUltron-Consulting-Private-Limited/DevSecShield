"use client";

import { Button } from "@/components/ui/button";
import { Card, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import {
  Triangle,
  Calendar,
  Shield,
  TrendingUp,
  Search,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { SASTOptionsSidebar } from "@/components/sast-options-sidebar";
import ChatWindow from "@/components/ai/ChatWindow";
import { useState } from "react";

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
export type Mode = "github" | "gitlab" | "bitbucket" | "not_initiated" | "unknown"
export default function SASTPage({ params }: SASTPageProps) {
  const [app_lang, setAppLang] = useState<AppLang>("unknown");
  const [mode, setMode] = useState<Mode>("unknown");
  const [repo_url, setRepoUrl] = useState<string>("");
  const [PAT, setPAT] = useState<string>("");
  return (
    <div className="flex h-screen">
      {/* Main Content Area */}
      <div className="flex-1 bg-white dark:bg-zinc-900  overflow-auto">
        <div className="mx-auto">
          <ChatWindow />
        </div>
      </div>

      {/* Right Sidebar - SAST Options */}
      <SASTOptionsSidebar app_lang={app_lang} setAppLang={setAppLang} mode={mode} setMode={setMode} repo_url={repo_url} setRepoUrl={setRepoUrl} PAT={PAT} setPAT={setPAT} />
    </div>
  );
}

