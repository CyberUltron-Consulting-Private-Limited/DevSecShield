"use client";

import { useState } from "react";
import { Loader2, ExternalLink, Maximize2, Minimize2 } from "lucide-react";

const REDAMON_URL = process.env.NEXT_PUBLIC_REDAMON_URL || "http://localhost:3000";

export default function RedTeamPage() {
  const [loading, setLoading] = useState(true);
  const [isFullscreen, setIsFullscreen] = useState(false);

  return (
    <div className={`flex flex-col h-full ${isFullscreen ? "fixed inset-0 z-50 bg-zinc-950" : ""}`}>
      <div className="flex items-center justify-between px-4 py-3 border-b border-zinc-800 bg-zinc-950/80 backdrop-blur-sm">
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2">
            <div className="h-2 w-2 rounded-full bg-red-500 animate-pulse" />
            <h1 className="text-lg font-semibold text-white">Red Team Console</h1>
          </div>
          <span className="text-xs text-zinc-500 font-mono">RedAmon</span>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => setIsFullscreen(!isFullscreen)}
            className="p-2 rounded-md text-zinc-400 hover:text-white hover:bg-zinc-800 transition-colors"
            title={isFullscreen ? "Exit fullscreen" : "Fullscreen"}
          >
            {isFullscreen ? <Minimize2 className="h-4 w-4" /> : <Maximize2 className="h-4 w-4" />}
          </button>
          <a
            href={REDAMON_URL}
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs text-zinc-400 hover:text-white hover:bg-zinc-800 transition-colors"
          >
            Open in new tab
            <ExternalLink className="h-3.5 w-3.5" />
          </a>
        </div>
      </div>

      <div className="relative flex-1">
        {loading && (
          <div className="absolute inset-0 flex items-center justify-center bg-zinc-950 z-10">
            <div className="flex flex-col items-center gap-3">
              <Loader2 className="h-8 w-8 animate-spin text-red-500" />
              <p className="text-sm text-zinc-400">Loading Red Team Console...</p>
            </div>
          </div>
        )}
        <iframe
          src={REDAMON_URL}
          className="w-full h-full border-0"
          onLoad={() => setLoading(false)}
          allow="clipboard-read; clipboard-write"
        />
      </div>
    </div>
  );
}
