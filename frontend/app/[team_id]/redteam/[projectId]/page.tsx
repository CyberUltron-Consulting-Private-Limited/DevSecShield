"use client";

import { useParams, useRouter } from "next/navigation";
import { useQuery } from "@tanstack/react-query";
import { useState, useEffect, useRef } from "react";
import {
  ArrowLeft,
  Crosshair,
  Globe,
  Loader2,
  Maximize2,
  Minimize2,
  Settings,
  ExternalLink,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import Link from "next/link";

const REDAMON_URL = process.env.NEXT_PUBLIC_REDAMON_URL || "http://localhost:3000";

interface RedamonProject {
  id: string;
  name: string;
  targetDomain: string;
  description: string | null;
}

async function fetchProject(teamId: string, projectId: string): Promise<RedamonProject> {
  const res = await fetch(`/api/redteam/projects/${projectId}`, {
    headers: { "X-Team-Id": teamId },
  });
  if (!res.ok) throw new Error("Failed to fetch project");
  return res.json();
}

export default function RedTeamProjectPage() {
  const params = useParams();
  const router = useRouter();
  const teamId = params?.team_id as string;
  const projectId = params?.projectId as string;
  const iframeRef = useRef<HTMLIFrameElement>(null);
  const [isFullscreen, setIsFullscreen] = useState(false);
  const [iframeLoaded, setIframeLoaded] = useState(false);

  const { data: project, isLoading } = useQuery({
    queryKey: ["redamon-project", projectId],
    queryFn: () => fetchProject(teamId, projectId),
    enabled: !!projectId && !!teamId,
  });

  const graphUrl = `${REDAMON_URL}/graph?project=${projectId}&embed=true&teamId=${teamId}`;

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape" && isFullscreen) setIsFullscreen(false);
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [isFullscreen]);

  if (isLoading) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <Loader2 className="h-8 w-8 animate-spin text-red-500" />
      </div>
    );
  }

  return (
    <div className={`flex flex-col h-screen ${isFullscreen ? "fixed inset-0 z-50" : ""}`}>
      {/* Header bar */}
      <div className="flex items-center justify-between px-4 py-2.5 border-b border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-950 shrink-0">
        <div className="flex items-center gap-3 min-w-0">
          <Link
            href={`/${teamId}/redteam`}
            className="p-1.5 rounded-md text-zinc-400 hover:text-zinc-900 dark:hover:text-white hover:bg-zinc-100 dark:hover:bg-zinc-800 transition-colors shrink-0"
          >
            <ArrowLeft className="h-4 w-4" />
          </Link>

          <div className="flex items-center gap-2 min-w-0">
            <Crosshair className="h-4 w-4 text-red-500 shrink-0" />
            <span className="font-semibold text-sm text-zinc-900 dark:text-white truncate">
              {project?.name || "Project"}
            </span>
          </div>

          {project?.targetDomain && (
            <Badge variant="outline" className="gap-1 shrink-0 text-xs">
              <Globe className="h-3 w-3" />
              {project.targetDomain}
            </Badge>
          )}
        </div>

        <div className="flex items-center gap-1.5 shrink-0">
          <Button
            variant="ghost"
            size="sm"
            className="h-8 w-8 p-0"
            onClick={() => setIsFullscreen(!isFullscreen)}
            title={isFullscreen ? "Exit fullscreen (Esc)" : "Fullscreen"}
          >
            {isFullscreen ? (
              <Minimize2 className="h-4 w-4" />
            ) : (
              <Maximize2 className="h-4 w-4" />
            )}
          </Button>
          <Button
            variant="ghost"
            size="sm"
            className="h-8 w-8 p-0"
            onClick={() => router.push(`/${teamId}/redteam/${projectId}/settings`)}
            title="Project settings"
          >
            <Settings className="h-4 w-4" />
          </Button>
          <a
            href={graphUrl}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center justify-center h-8 w-8 rounded-md text-zinc-500 hover:text-zinc-900 dark:hover:text-white hover:bg-zinc-100 dark:hover:bg-zinc-800 transition-colors"
            title="Open in new tab"
          >
            <ExternalLink className="h-4 w-4" />
          </a>
        </div>
      </div>

      {/* Graph iframe */}
      <div className="relative flex-1 bg-zinc-950">
        {!iframeLoaded && (
          <div className="absolute inset-0 flex items-center justify-center z-10 bg-zinc-950">
            <div className="flex flex-col items-center gap-3">
              <Loader2 className="h-8 w-8 animate-spin text-red-500" />
              <p className="text-sm text-zinc-400">Loading attack surface graph...</p>
            </div>
          </div>
        )}
        <iframe
          ref={iframeRef}
          src={graphUrl}
          className="w-full h-full border-0"
          onLoad={() => setIframeLoaded(true)}
          allow="clipboard-read; clipboard-write"
        />
      </div>
    </div>
  );
}
