"use client";

import { useParams } from "next/navigation";
import { useState } from "react";
import { ArrowLeft, Loader2, Settings } from "lucide-react";
import { Button } from "@/components/ui/button";
import Link from "next/link";

const REDAMON_URL = process.env.NEXT_PUBLIC_REDAMON_URL || "http://localhost:3000";

export default function RedTeamProjectSettingsPage() {
  const params = useParams();
  const teamId = params?.team_id as string;
  const projectId = params?.projectId as string;
  const [loaded, setLoaded] = useState(false);

  const settingsUrl = `${REDAMON_URL}/projects/${projectId}/settings?embed=true&teamId=${teamId}`;

  return (
    <div className="flex flex-col h-screen">
      <div className="flex items-center gap-3 px-4 py-2.5 border-b border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-950 shrink-0">
        <Link
          href={`/${teamId}/redteam/${projectId}`}
          className="p-1.5 rounded-md text-zinc-400 hover:text-zinc-900 dark:hover:text-white hover:bg-zinc-100 dark:hover:bg-zinc-800 transition-colors"
        >
          <ArrowLeft className="h-4 w-4" />
        </Link>
        <Settings className="h-4 w-4 text-zinc-500" />
        <span className="font-semibold text-sm text-zinc-900 dark:text-white">
          Project Settings
        </span>
      </div>

      <div className="relative flex-1">
        {!loaded && (
          <div className="absolute inset-0 flex items-center justify-center z-10 bg-white dark:bg-zinc-950">
            <div className="flex flex-col items-center gap-3">
              <Loader2 className="h-8 w-8 animate-spin text-red-500" />
              <p className="text-sm text-zinc-400">Loading settings...</p>
            </div>
          </div>
        )}
        <iframe
          src={settingsUrl}
          className="w-full h-full border-0"
          onLoad={() => setLoaded(true)}
          allow="clipboard-read; clipboard-write"
        />
      </div>
    </div>
  );
}
