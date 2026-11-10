"use client";

import { useEffect, useState } from "react";
import { Button } from "@/components/ui/button";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Separator } from "@/components/ui/separator";
import { Label } from "@/components/ui/label";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  ScanIcon,
  Loader2,
  Download,
  AlertCircle,
  CheckCircle2,
  Eye,
  ScanLine,
} from "lucide-react";
import { useMutation, useQueryClient, UseQueryResult } from "@tanstack/react-query";
import { toast } from "sonner";
import { useRouter } from "next/navigation";
import {
  estimateCreditsForScan,
  startScan,
  getMCPExportResults,
  reinitializeMCPScan,
  type MCPConversationResponse,
} from "@/utils/backend_api";
import { handleApiError } from "@/utils/error-handler";

type ServerMode = "httpstreamable" | "sse";

type MCPEnvironment = "production" | "staging" | "development";

const MCP_ENVIRONMENTS: { value: MCPEnvironment; label: string }[] = [
  { value: "development", label: "Development" },
  { value: "staging", label: "Staging" },
  { value: "production", label: "Production" },
];

function buildPayloadString(
  serverUrl: string,
  serverMode: ServerMode,
  headersJson: string,
  environment: MCPEnvironment
): string {
  const headers =
    headersJson.trim() === ""
      ? undefined
      : (JSON.parse(headersJson) as Record<string, string>);
  return JSON.stringify({
    mcp: {
      server_url: serverUrl.trim(),
      server_mode: serverMode,
      headers: headers ?? null,
      environment,
    },
  });
}

export function MCPOptionsSidebar({
  query,
  team_id,
  scan_id,
}: {
  query: UseQueryResult<MCPConversationResponse>;
  team_id: number;
  scan_id: number;
}) {
  const [optionsSidebarState, setOptionsSidebarState] = useState<
    "ready" | "scanning" | "error" | "done"
  >("ready");
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [estimatedCredits, setEstimatedCredits] = useState<number | null>(null);
  const [estimationProcessDone, setEstimationProcessDone] = useState(false);

  const [serverUrl, setServerUrl] = useState("");
  const [serverMode, setServerMode] = useState<ServerMode>("sse");
  const [environment, setEnvironment] = useState<MCPEnvironment>("development");
  const [headersJson, setHeadersJson] = useState("");
  const [headersError, setHeadersError] = useState<string | null>(null);

  const queryClient = useQueryClient();
  const router = useRouter();

  const validateHeadersJson = (value: string) => {
    setHeadersJson(value);
    if (!value.trim()) {
      setHeadersError(null);
      return;
    }
    try {
      JSON.parse(value);
      setHeadersError(null);
    } catch {
      setHeadersError("Invalid JSON format");
    }
  };

  const validateScanInputs = (): { valid: true } | { valid: false; message: string } => {
    if (!serverUrl.trim()) {
      return { valid: false, message: "Please enter the MCP server URL." };
    }
    try {
      new URL(serverUrl.trim());
    } catch {
      return { valid: false, message: "Please enter a valid URL for the MCP server." };
    }
    if (headersJson.trim() && headersError) {
      return { valid: false, message: "Please fix the headers JSON or leave it empty." };
    }
    return { valid: true };
  };

  const buildPayloadStringSafe = (): string => {
    const validation = validateScanInputs();
    if (!validation.valid) throw new Error(validation.message);
    return buildPayloadString(serverUrl, serverMode, headersJson, environment);
  };

  const estimateCreditsMutation = useMutation({
    mutationFn: () =>
      estimateCreditsForScan(team_id, "mcp", scan_id, buildPayloadStringSafe()),
    onSuccess: (data) => {
      setEstimatedCredits(data.credits_required);
      setEstimationProcessDone(true);
      if (data.credits_required !== -1) {
        toast.success(`This scan will use ${data.credits_required} credits`);
      } else {
        toast.error("Invalid input from user");
      }
    },
    onError: (err) => {
      setErrorMessage(handleApiError(err).message);
      setOptionsSidebarState("error");
    },
  });

  const startScanMutation = useMutation({
    mutationFn: () => startScan(team_id, "mcp", scan_id, buildPayloadStringSafe()),
    onSuccess: () => {
      setEstimatedCredits(null);
      setEstimationProcessDone(false);
      setOptionsSidebarState("scanning");
      queryClient.invalidateQueries({ queryKey: ["mcp-conversation-data", team_id, scan_id] });
    },
    onError: (err) => {
      setErrorMessage(handleApiError(err).message);
      setOptionsSidebarState("error");
    },
  });

  const handleRunEstimate = () => {
    const validation = validateScanInputs();
    if (!validation.valid) {
      toast.error(validation.message);
      return;
    }
    estimateCreditsMutation.mutate();
  };

  const handleStartScanAfterEstimate = () => {
    const validation = validateScanInputs();
    if (!validation.valid) {
      toast.error(validation.message);
      return;
    }
    startScanMutation.mutate();
  };

  const scanInputsValid = validateScanInputs().valid;
  const displayCredits = estimatedCredits;
  const creditsInvalid = estimatedCredits === -1;
  const canRunScan = estimationProcessDone && !creditsInvalid;

  useEffect(() => {
    setEstimationProcessDone(false);
    setEstimatedCredits(null);
  }, [serverUrl, serverMode, environment, headersJson]);

  useEffect(() => {
    if (query.data?.scan_status === "success") {
      setOptionsSidebarState("done");
      setErrorMessage(null);
    }
    if (query.data?.scan_status === "pending" || query.data?.scan_status === "started") {
      setOptionsSidebarState("scanning");
      setErrorMessage(null);
    }
    if (query.data?.scan_status === "failure") {
      setErrorMessage(
        (query.data as { scan_metadata?: { error_message?: string } })?.scan_metadata
          ?.error_message ?? "The scan failed."
      );
      setOptionsSidebarState("error");
    }
    if (
      query.data?.scan_status === "not_started" ||
      query.data?.scan_status === "NOT_STARTED" ||
      !query.data?.scan_status
    ) {
      setOptionsSidebarState("ready");
      setErrorMessage(null);
    }
    const meta = query.data?.scan_metadata as {
      server_url?: string;
      server_mode?: string;
      headers?: Record<string, string>;
      environment?: string;
    } | null | undefined;
    if (meta?.server_url) {
      setServerUrl(meta.server_url);
    }
    if (meta?.server_mode === "httpstreamable" || meta?.server_mode === "sse") {
      setServerMode(meta.server_mode as ServerMode);
    }
    if (
      meta?.environment === "production" ||
      meta?.environment === "staging" ||
      meta?.environment === "development"
    ) {
      setEnvironment(meta.environment as MCPEnvironment);
    }
    if (meta?.headers && typeof meta.headers === "object") {
      setHeadersJson(JSON.stringify(meta.headers, null, 2));
    }
  }, [
    query.data?.scan_status,
    query.data?.scan_metadata,
  ]);

  const payloadString =
    scanInputsValid && !headersError
      ? buildPayloadString(serverUrl, serverMode, headersJson, environment)
      : "";

  const reinitializeScanMutation = useMutation({
    mutationFn: () =>
      reinitializeMCPScan({
        team_id,
        scan_id,
        start_scan_payload_string: payloadString,
      }),
    onSuccess: () => {
      setOptionsSidebarState("scanning");
      queryClient.invalidateQueries({ queryKey: ["mcp-conversation-data", team_id, scan_id] });
    },
    onError: (err) => {
      setErrorMessage(handleApiError(err).message);
      setOptionsSidebarState("error");
    },
  });

  const exportMutation = useMutation({
    mutationFn: () => getMCPExportResults(team_id, scan_id),
    onSuccess: (data) => {
      const blob = new Blob([data], { type: "application/pdf" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `${query.data?.title ?? "mcp"}_scan_report.pdf`;
      a.click();
      setOptionsSidebarState("done");
    },
    onError: (err) => {
      setErrorMessage(handleApiError(err).message);
      setOptionsSidebarState("error");
    },
  });

  return (
    <ScrollArea className="w-full md:w-96 shrink-0 md:h-screen bg-neutral-900/70 border-t md:border-t-0 md:border-l border-zinc-800">
      <div className="p-6">
        <div className="flex items-center gap-2 flex-row mb-2">
          <h2 className="text-xl font-bold text-white">MCP Configuration</h2>
          <ScanLine className="h-5 w-5 text-blue-400 shrink-0" />
        </div>
        <p className="text-sm text-zinc-400">
          Configure MCP server URL, mode, and optional headers to run a scan.
        </p>
      </div>

      <Separator className="bg-zinc-800" />

      {optionsSidebarState === "ready" && (
        <>
          <div className="p-6 space-y-4">
            <div className="space-y-2">
              <Label htmlFor="mcp-server-url" className="text-zinc-300">
                MCP server URL <span className="text-red-500">*</span>
              </Label>
              <Input
                id="mcp-server-url"
                type="url"
                placeholder="https://example.com/mcp"
                value={serverUrl}
                onChange={(e) => setServerUrl(e.target.value)}
                className="bg-zinc-800 border-zinc-700 text-white placeholder:text-zinc-500"
              />
            </div>

            <div className="space-y-2">
              <Label htmlFor="server-mode" className="text-zinc-300">
                Server mode <span className="text-red-500">*</span>
              </Label>
              <Select
                value={serverMode}
                onValueChange={(v) => setServerMode(v as ServerMode)}
              >
                <SelectTrigger
                  id="server-mode"
                  className="bg-zinc-800 border-zinc-700 text-white focus:text-white cursor-pointer"
                >
                  <SelectValue />
                </SelectTrigger>
                <SelectContent className="bg-zinc-800 border-zinc-700">
                  <SelectItem
                    value="httpstreamable"
                    className="text-white hover:bg-zinc-700 cursor-pointer"
                  >
                    httpstreamable
                  </SelectItem>
                  <SelectItem value="sse" className="text-white hover:bg-zinc-700 cursor-pointer">
                    sse
                  </SelectItem>
                </SelectContent>
              </Select>
            </div>

            <div className="space-y-2">
              <Label htmlFor="mcp-environment" className="text-zinc-300">
                Environment
              </Label>
              <Select
                value={environment}
                onValueChange={(v) => setEnvironment(v as MCPEnvironment)}
              >
                <SelectTrigger
                  id="mcp-environment"
                  className="bg-zinc-800 border-zinc-700 text-white focus:text-white cursor-pointer"
                >
                  <SelectValue />
                </SelectTrigger>
                <SelectContent className="bg-zinc-800 border-zinc-700">
                  {MCP_ENVIRONMENTS.map((e) => (
                    <SelectItem
                      key={e.value}
                      value={e.value}
                      className="text-white hover:bg-zinc-700 cursor-pointer"
                    >
                      {e.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            <div className="space-y-2">
              <Label htmlFor="headers-json" className="text-zinc-300">
                Headers (JSON, optional)
              </Label>
              <Textarea
                id="headers-json"
                placeholder='{"Authorization": "Bearer ...", "X-Custom": "value"}'
                value={headersJson}
                onChange={(e) => validateHeadersJson(e.target.value)}
                className="bg-zinc-800 border-zinc-700 text-white placeholder:text-zinc-500 font-mono text-sm min-h-[80px] resize-y"
              />
              {headersError && (
                <div className="flex items-center gap-2 text-red-400 text-sm">
                  <AlertCircle className="h-4 w-4" />
                  {headersError}
                </div>
              )}
              {headersJson.trim() && !headersError && (
                <div className="flex items-center gap-2 text-green-400 text-sm">
                  <CheckCircle2 className="h-4 w-4" />
                  Valid JSON
                </div>
              )}
            </div>

            <div className="text-sm text-amber-400/70">
              <span className="font-medium">⚠️</span> MCP server scans analyze tools and
              capabilities exposed by the server for potential security issues.
            </div>
          </div>

          <Separator className="bg-zinc-800" />

          <div className="p-6">
            <h3 className="text-sm font-semibold text-zinc-200 mb-2">Estimate scan credits</h3>
            <Button
              variant="ghost"
              size="sm"
              onClick={handleRunEstimate}
              disabled={!scanInputsValid || !!headersError || estimateCreditsMutation.isPending}
              className="w-full h-9 px-4 bg-zinc-700 hover:bg-zinc-600 text-white cursor-pointer disabled:opacity-50"
            >
              {estimateCreditsMutation.isPending ? (
                <>
                  <Loader2 className="size-4 animate-spin mr-2" />
                  Estimating...
                </>
              ) : (
                <>Estimate credits required</>
              )}
            </Button>
            {displayCredits != null && (
              <p className="text-sm text-zinc-300 mt-3">
                {creditsInvalid ? (
                  <span className="font-semibold text-amber-400">Invalid input from user</span>
                ) : (
                  <>
                    Credits required:{" "}
                    <span className="font-semibold text-blue-400">{displayCredits}</span>
                  </>
                )}
              </p>
            )}
          </div>

          <Separator className="bg-zinc-800" />

          <div className="p-6">
            <h3 className="text-sm font-semibold text-zinc-200 mb-2">Run scan</h3>
            {canRunScan ? (
              <div className="space-y-2">
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={handleStartScanAfterEstimate}
                  disabled={!scanInputsValid || startScanMutation.isPending}
                  className="w-full h-9 px-4 bg-blue-600 hover:bg-blue-700 text-white cursor-pointer disabled:opacity-50"
                >
                  {startScanMutation.isPending ? (
                    <>
                      <Loader2 className="size-4 animate-spin mr-2" />
                      Starting...
                    </>
                  ) : (
                    <>
                      <ScanIcon className="size-4 mr-2" />
                      Start scan
                    </>
                  )}
                </Button>
                {displayCredits != null && !creditsInvalid && (
                  <p className="text-xs text-zinc-500">Uses {displayCredits} credits.</p>
                )}
              </div>
            ) : creditsInvalid ? (
              <p className="text-sm text-amber-400">
                Credit estimation failed due to invalid inputs. Check the MCP server URL and
                connectivity.
              </p>
            ) : (
              <p className="text-sm text-zinc-500">Run estimate above to enable starting the scan.</p>
            )}
          </div>
        </>
      )}

      {optionsSidebarState === "scanning" && (
        <div className="p-6 flex flex-col items-center justify-center min-h-[400px]">
          <Loader2 className="h-8 w-8 text-blue-500 animate-spin mb-4" />
          <p className="text-zinc-300 text-center">Scan has started; this may take a while.</p>
        </div>
      )}

      {optionsSidebarState === "done" && (
        <div className="p-6 space-y-4">
          <div className="flex flex-col items-center justify-center min-h-[200px] space-y-4">
            <p className="text-zinc-300 text-center">
              Scan completed successfully. You can chat with your scan results.
            </p>
            <Button
              variant="ghost"
              size="sm"
              onClick={() => router.push(`/${team_id}/mcp/${scan_id}/results?origin=chat`)}
              className="w-full h-8 px-2 bg-blue-600 hover:bg-blue-700 text-white cursor-pointer hover:text-white"
            >
              <Eye className="size-4" />
              <span className="ml-1">View Results</span>
            </Button>
            <Button
              variant="ghost"
              size="sm"
              onClick={() => exportMutation.mutate()}
              className="w-full h-8 px-2 bg-zinc-700 hover:bg-zinc-600 text-white cursor-pointer hover:text-white"
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
            {errorMessage ?? "An error occurred during the scan. Please try again."}
          </p>
          <Button
            variant="ghost"
            size="sm"
            onClick={() => window.location.reload()}
            className="w-full h-8 px-2 bg-zinc-700 hover:bg-zinc-600 text-white cursor-pointer hover:text-white"
          >
            <span>Try Again</span>
          </Button>
        </div>
      )}

      {query.data?.scan_status === "pending" && (
        <div className="p-6 border-t border-zinc-800">
          <Button
            variant="ghost"
            size="sm"
            onClick={() => reinitializeScanMutation.mutate()}
            disabled={
              reinitializeScanMutation.isPending ||
              !scanInputsValid ||
              !!headersError ||
              !payloadString
            }
            className="w-full h-8 px-2 bg-yellow-600 hover:bg-yellow-700 text-white cursor-pointer hover:text-white disabled:opacity-50"
          >
            {reinitializeScanMutation.isPending ? (
              <>
                <Loader2 className="size-4 mr-2 animate-spin" />
                <span>Reinitializing...</span>
              </>
            ) : (
              <>
                <ScanIcon className="size-4 mr-2" />
                <span>Reinitialize Scan</span>
              </>
            )}
          </Button>
        </div>
      )}
    </ScrollArea>
  );
}
