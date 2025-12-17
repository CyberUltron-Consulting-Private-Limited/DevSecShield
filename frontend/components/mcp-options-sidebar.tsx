"use client";

import { useEffect, useState } from "react";
import { Button } from "@/components/ui/button";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Separator } from "@/components/ui/separator";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import {
  ScanIcon,
  Loader2,
  Download,
  AlertCircle,
  CheckCircle2,
} from "lucide-react";
import { useMutation, useQueryClient, UseQueryResult } from "@tanstack/react-query";
import { toast } from "sonner";
import { useParams } from "next/navigation";
import { startMCPScan, getMCPExportResults } from "@/utils/backend_api";
import { generateAndDownloadPDF } from "@/components/PDF_Report";

// Placeholder response type - replace with actual type when backend API is created
interface MCPConversationResponse {
  scan_status: string;
  messages: any[];
  server_config?: string;
  title?: string;
}


export function MCPOptionsSidebar({
  query,
}: {
  query: UseQueryResult<MCPConversationResponse>;
}) {
  const [optionsSidebarState, setOptionsSidebarState] = useState<"ready" | "scanning" | "error" | "done">("ready");
  const [serverConfigJson, setServerConfigJson] = useState<string>("");
  const [jsonError, setJsonError] = useState<string | null>(null);

  const queryClient = useQueryClient();
  const { conversation_id } = useParams();

  // Validate JSON as user types
  const validateJson = (value: string) => {
    setServerConfigJson(value);
    if (!value.trim()) {
      setJsonError(null);
      return;
    }
    try {
      JSON.parse(value);
      setJsonError(null);
    } catch (e) {
      setJsonError("Invalid JSON format");
    }
  };

  const handleStartScan = async ({
    conversation_id,
    server_config,
  }: {
    conversation_id: number;
    server_config: string;
  }) => {
    setOptionsSidebarState("scanning");

    if (!server_config.trim()) {
      toast.error("Please provide the MCP server configuration JSON");
      setOptionsSidebarState("error");
      throw new Error("Please provide the MCP server configuration JSON");
    }

    try {
      JSON.parse(server_config);
    } catch (e) {
      toast.error("Invalid JSON format in server configuration");
      setOptionsSidebarState("error");
      throw new Error("Invalid JSON format in server configuration");
    }

    return startMCPScan({ conversation_id, server_config });
  };

  const startScanMutation = useMutation({
    mutationFn: handleStartScan,
    onSuccess: () => {
      setOptionsSidebarState("scanning");
      queryClient.invalidateQueries({ queryKey: ['mcp-conversation-data', parseInt(conversation_id as string)] });
    },
    onError: () => {
      setOptionsSidebarState("error");
    }
  });

  const exportMutation = useMutation({
    mutationFn: getMCPExportResults,
    onSuccess: () => {
      toast.success("Export results fetched successfully");
    },
    onError: () => {
      toast.error("Failed to fetch export results");
    }
  });

  useEffect(() => {
    if (query.data?.scan_status === "success") {
      setOptionsSidebarState("done");
    }
    if (query.data?.scan_status === "pending" || query.data?.scan_status === "started") {
      setOptionsSidebarState("scanning");
    }
    if (query.data?.scan_status === "failure") {
      setOptionsSidebarState("error");
    }
    if (query.data?.scan_status === "not_started" || !query.data?.scan_status) {
      setOptionsSidebarState("ready");
    }
    // Load saved server config if available
    if (query.data?.server_config) {
      setServerConfigJson(query.data.server_config);
    }
  }, [query.data?.scan_status, query.data?.server_config]);

  const exampleConfig = `{
  "mcpServers": {
    "playwright": {
      "command": "npx",
      "args": ["@playwright/mcp@latest"]
    },
    "another-server": {
      "command": "npx",
      "args": ["-y", "server-package"]
    }
  }
}`;


  return (
    <ScrollArea className="w-80 h-screen bg-zinc-900 dark:bg-zinc-950 border-l border-zinc-800">
      <div className="p-6">
        <h2 className="text-xl font-bold text-white mb-2">MCP Options</h2>
        <p className="text-sm text-zinc-400">
          Configure your MCP server scanning options.
        </p>
      </div>

      <Separator className="bg-zinc-800" />

      {optionsSidebarState === "ready" && (
        <div className="p-6 space-y-6">
          {/* Server Configuration */}
          <div className="space-y-4">
            <div>
              <h3 className="text-lg font-semibold text-white mb-1">Server Configuration</h3>
              <p className="text-sm text-zinc-400">Paste your MCP server configuration JSON below</p>
            </div>

            {/* Info box */}
            <div className="bg-blue-500/10 border border-blue-500/50 rounded-lg p-3">
              <p className="text-sm font-medium text-blue-400">ℹ️ Configuration Format</p>
              <p className="text-xs text-blue-300 mt-1">
                Paste the JSON configuration containing your MCP servers. This should include the server names, commands, and arguments.
              </p>
            </div>

            <div className="space-y-2">
              <Label htmlFor="serverConfig" className="text-zinc-300">Server Config JSON *</Label>
              <Textarea
                className="cursor-pointer bg-zinc-700 border-zinc-600 text-white placeholder:text-zinc-500 font-mono text-sm min-h-[250px]"
                id="serverConfig"
                placeholder={exampleConfig}
                value={serverConfigJson}
                onChange={(e) => validateJson(e.target.value)}
              />
              {jsonError && (
                <div className="flex items-center gap-2 text-red-400 text-sm">
                  <AlertCircle className="h-4 w-4" />
                  {jsonError}
                </div>
              )}
              {serverConfigJson && !jsonError && (
                <div className="flex items-center gap-2 text-green-400 text-sm">
                  <CheckCircle2 className="h-4 w-4" />
                  Valid JSON
                </div>
              )}
            </div>

            {/* Example toggle */}
            <details className="text-sm">
              <summary className="text-zinc-400 cursor-pointer hover:text-zinc-300">
                Show example configuration
              </summary>
              <pre className="mt-2 p-3 bg-zinc-800 rounded-lg text-xs text-zinc-300 overflow-x-auto">
                {exampleConfig}
              </pre>
            </details>
          </div>

          {/* Warning */}
          <div className="bg-amber-500/10 border border-amber-500/50 rounded-lg p-3">
            <p className="text-sm font-medium text-amber-400">⚠️ Security Notice</p>
            <p className="text-xs text-amber-500 mt-1">
              MCP server scans will analyze the tools and capabilities exposed by your configured servers to identify potential security issues.
            </p>
          </div>

          <Button
            variant="ghost"
            size="icon-lg"
            onClick={() => {
              startScanMutation.mutate({
                conversation_id: parseInt(conversation_id as string),
                server_config: serverConfigJson
              });
              setOptionsSidebarState("scanning");
            }}
            disabled={!serverConfigJson.trim() || !!jsonError}
            className="w-full h-8 px-4 bg-teal-600 hover:bg-teal-700 text-white cursor-pointer hover:text-white disabled:opacity-50 disabled:cursor-not-allowed"
          >
            <ScanIcon className="size-4" />
            <span className="ml-1">Run Scan</span>
          </Button>
        </div>
      )}

      {optionsSidebarState === "scanning" && (
        <div className="p-6 flex flex-col items-center justify-center min-h-[400px]">
          <Loader2 className="h-8 w-8 text-teal-500 animate-spin mb-4" />
          <p className="text-zinc-300 text-center">
            Scan has started, this might take a while
          </p>
        </div>
      )}

      {optionsSidebarState === "done" && (
        <div className="p-6 space-y-4">
          <div className="flex flex-col items-center justify-center min-h-[200px] space-y-4">
            <p className="text-zinc-300 text-center">
              Scan has run successfully. You can now chat with your scan results
            </p>
            <Button
              variant="ghost"
              size="sm"
              onClick={async () => {
                const exportResults = await exportMutation.mutateAsync(parseInt(conversation_id as string));
                if (exportResults) {
                  generateAndDownloadPDF(
                    exportResults,
                    "MCP Security Scan",
                    query.data?.title || null,
                    new Date().toLocaleDateString()
                  );
                }
              }}
              className="w-full h-8 px-2 bg-teal-600 hover:bg-teal-700 text-white cursor-pointer hover:text-white"
            >
              <Download className="size-4" />
              <span className="ml-1">Download Scan Report</span>
            </Button>
          </div>
        </div>
      )}

      {optionsSidebarState === "error" && (
        <div className="p-6 flex flex-col items-center justify-center min-h-[200px] space-y-4">
          <p className="text-red-400 text-center">
            An error occurred during the scan. Please try again.
          </p>
          <Button
            variant="ghost"
            size="sm"
            onClick={() => setOptionsSidebarState("ready")}
            className="w-full h-8 px-2 bg-zinc-700 hover:bg-zinc-600 text-white cursor-pointer hover:text-white"
          >
            <span>Try Again</span>
          </Button>
        </div>
      )}
    </ScrollArea>
  );
}
