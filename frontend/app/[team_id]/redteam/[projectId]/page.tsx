"use client";

import { useParams, useRouter } from "next/navigation";
import { useQuery } from "@tanstack/react-query";
import { useState, useEffect, useRef, useMemo, useCallback } from "react";
import {
  ArrowLeft,
  Bot,
  ChevronDown,
  ExternalLink,
  Github,
  Globe,
  Loader2,
  Maximize2,
  Minimize2,
  Radar,
  Settings,
  Shield,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
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
  const redamonOrigin = useMemo(() => {
    try {
      return new URL(REDAMON_URL).origin;
    } catch {
      return "http://localhost:3000";
    }
  }, []);

  const { data: project, isLoading } = useQuery({
    queryKey: ["redamon-project", projectId],
    queryFn: () => fetchProject(teamId, projectId),
    enabled: !!projectId && !!teamId,
  });

  const graphUrl = `${REDAMON_URL}/graph?project=${projectId}&embed=true&teamId=${teamId}`;

  const sendGraphAction = useCallback(
    (action: "start-recon" | "start-gvm" | "start-github-hunt" | "toggle-ai") => {
      iframeRef.current?.contentWindow?.postMessage(
        { source: "devsecshield-redteam", action },
        redamonOrigin
      );
    },
    [redamonOrigin]
  );

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
      <div className="shrink-0 border-b border-zinc-800 bg-[#0a1220] text-white">
        <div className="flex items-center justify-between gap-4 px-4 py-3">
          <div className="flex min-w-0 items-center gap-3">
            <Link
              href={`/${teamId}/redteam`}
              className="inline-flex h-9 w-9 items-center justify-center rounded-xl border border-white/10 bg-white/5 text-zinc-300 transition hover:border-white/20 hover:bg-white/10 hover:text-white"
            >
              <ArrowLeft className="h-4 w-4" />
            </Link>

            <div className="flex h-10 w-10 items-center justify-center rounded-2xl bg-emerald-500/15 text-emerald-300 ring-1 ring-emerald-400/20">
              <Shield className="h-5 w-5" />
            </div>

            <div className="min-w-0">
              <div className="truncate text-sm font-semibold">DevSecShield Platform</div>
              <div className="mt-1 flex flex-wrap items-center gap-3 text-xs text-zinc-400">
                <span className="truncate">{project?.name || "Assessment"}</span>
                <span className="inline-flex items-center gap-1.5 text-emerald-400">
                  <span className="h-2 w-2 rounded-full bg-emerald-400 shadow-[0_0_12px_rgba(74,222,128,0.9)]" />
                  Assessment Workspace
                </span>
                {project?.targetDomain && (
                  <span className="inline-flex items-center gap-1 truncate">
                    <Globe className="h-3.5 w-3.5" />
                    {project.targetDomain}
                  </span>
                )}
              </div>
            </div>
          </div>

          <div className="flex shrink-0 items-center gap-2">
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button
                  disabled={!iframeLoaded}
                  className="h-10 rounded-xl bg-emerald-500 px-4 text-sm font-semibold text-black hover:bg-emerald-400"
                >
                  New Assessment
                  <ChevronDown className="h-4 w-4" />
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent
                align="end"
                className="w-64 rounded-xl border-zinc-800 bg-[#0f172a] text-zinc-100"
              >
                <DropdownMenuItem
                  className="cursor-pointer rounded-lg focus:bg-white/10 focus:text-white"
                  onClick={() => sendGraphAction("start-recon")}
                >
                  <Radar className="h-4 w-4 text-emerald-400" />
                  <div className="flex flex-col">
                    <span className="font-medium">Recon</span>
                    <span className="text-xs text-zinc-400">Run reconnaissance collection</span>
                  </div>
                </DropdownMenuItem>
                <DropdownMenuItem
                  className="cursor-pointer rounded-lg focus:bg-white/10 focus:text-white"
                  onClick={() => sendGraphAction("start-gvm")}
                >
                  <Shield className="h-4 w-4 text-amber-400" />
                  <div className="flex flex-col">
                    <span className="font-medium">GVM Scan</span>
                    <span className="text-xs text-zinc-400">Launch vulnerability assessment</span>
                  </div>
                </DropdownMenuItem>
                <DropdownMenuItem
                  className="cursor-pointer rounded-lg focus:bg-white/10 focus:text-white"
                  onClick={() => sendGraphAction("start-github-hunt")}
                >
                  <Github className="h-4 w-4 text-sky-400" />
                  <div className="flex flex-col">
                    <span className="font-medium">GitHub Hunt</span>
                    <span className="text-xs text-zinc-400">Search repository leaks and secrets</span>
                  </div>
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>

            <Button
              variant="outline"
              className="h-10 rounded-xl border-white/10 bg-white/5 px-4 text-zinc-100 hover:bg-white/10 hover:text-white"
              onClick={() => sendGraphAction("toggle-ai")}
              disabled={!iframeLoaded}
            >
              <Bot className="h-4 w-4 text-rose-300" />
              AI Assistant
            </Button>

            {project?.targetDomain && (
              <Badge
                variant="outline"
                className="hidden h-10 items-center gap-1 rounded-xl border-white/10 bg-white/5 px-3 text-zinc-300 md:inline-flex"
              >
                <Globe className="h-3.5 w-3.5" />
                {project.targetDomain}
              </Badge>
            )}

            <Button
              variant="ghost"
              size="sm"
              className="h-10 w-10 rounded-xl text-zinc-300 hover:bg-white/10 hover:text-white"
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
              className="h-10 w-10 rounded-xl text-zinc-300 hover:bg-white/10 hover:text-white"
              onClick={() => router.push(`/${teamId}/redteam/${projectId}/settings`)}
              title="Project settings"
            >
              <Settings className="h-4 w-4" />
            </Button>
            <a
              href={graphUrl}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex h-10 w-10 items-center justify-center rounded-xl text-zinc-300 transition hover:bg-white/10 hover:text-white"
              title="Open in new tab"
            >
              <ExternalLink className="h-4 w-4" />
            </a>
          </div>
        </div>
      </div>

      <div className="relative flex-1 bg-zinc-950">
        {!iframeLoaded && (
          <div className="absolute inset-0 z-10 flex items-center justify-center bg-zinc-950">
            <div className="flex flex-col items-center gap-3">
              <Loader2 className="h-8 w-8 animate-spin text-emerald-400" />
              <p className="text-sm text-zinc-400">Loading red team workspace...</p>
            </div>
          </div>
        )}

        <iframe
          ref={iframeRef}
          src={graphUrl}
          className="h-full w-full border-0"
          onLoad={() => setIframeLoaded(true)}
          allow="clipboard-read; clipboard-write"
        />
      </div>
    </div>
  );
}
