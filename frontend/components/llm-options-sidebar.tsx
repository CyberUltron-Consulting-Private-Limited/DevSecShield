"use client";

import { Dispatch, SetStateAction, useEffect, useState } from "react";
import { Button } from "@/components/ui/button";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Separator } from "@/components/ui/separator";
import { Label } from "@/components/ui/label";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Select, SelectTrigger, SelectValue, SelectContent, SelectItem } from "@/components/ui/select";
import { Checkbox } from "@/components/ui/checkbox";
import {
  ScanIcon,
  Loader2,
  Download,
  Eye,
  ScanLine,
} from "lucide-react";
import { useMutation, useQueryClient, UseQueryResult } from "@tanstack/react-query";
import {
  LLMConversationResponse,
  estimateCreditsForScan,
  startScan,
  getLLMExportResults,
  reinitializeLLMScan,
} from "@/utils/backend_api";
import { handleApiError } from "@/utils/error-handler";
import { scanFailureMessage } from "@/utils/scanFailure";
import { readFormRerun } from "@/utils/formRerun";
import { NewScanRunAgainButton } from "@/components/scan-run-again";
import { stateAfterError } from "@/utils/scanErrorRecovery";
import { ScanRequestError } from "@/components/scan-request-error";
import { toast } from "@/utils/toast";
import { useRouter } from "next/navigation";
import ModelChoicePicker from "./ModelChoicePicker";
import probeDescription from "@/garak_probes.json";
import { AVAILABLE_PROBES } from "@/lib/llm-probes";
import { getProbeDisplayName } from "@/utils/probe-display-names";
// import { generateAndDownloadPDF } from "@/components/PDF_Report";

// LLM Scan creation data interface
type LLMScanCreateData = {
    model_type: string;
    model_name: string;
    probes: string[];
    api_key: string;
    generations: number;
    headers: string;
    request_template: string;
    response_json_field: string;
    model_uri: string;
}

/** Get probe description for tooltip; tries web_injection then xss alias for backward compat. */
function getProbeDescription(probe: string): string {
  const desc = (probeDescription as Record<string, string>)[probe];
  if (desc) return desc;
  if (probe.startsWith("web_injection.")) {
    const xssKey = "xss." + probe.slice("web_injection.".length);
    return (probeDescription as Record<string, string>)[xssKey] ?? "";
  }
  return "";
}

export function LLMOptionsSidebar({
  query,
  team_id,
  scan_id,
}: {
  query: UseQueryResult<LLMConversationResponse>;
  team_id: number;
  scan_id: number;
}) {
  const [optionsSidebarState, setOptionsSidebarState] = useState<"ready" | "scanning" | "error" | "done">("ready");
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [estimatedCredits, setEstimatedCredits] = useState<number | null>(null);
  const [estimationProcessDone, setEstimationProcessDone] = useState(false);

  // Unified state object conforming to LLMScanCreateData type
  const [creationData, setCreationData] = useState<LLMScanCreateData>({
      model_type: "",
      model_name: "",
      probes: [],
      api_key: "",
      generations: 1,
      headers: "",
      request_template: "",
      response_json_field: "",
      model_uri: ""
  });

  // a scan opened by "Run again" on a failed LLM scan: its model and probes (the API key and headers are typed again)
  useEffect(() => {
    const p = Number.isFinite(scan_id) ? readFormRerun("llm", scan_id) : null;
    if (!p) return;
    setCreationData((prev) => ({
      ...prev,
      ...(typeof p.model_type === "string" ? { model_type: p.model_type } : {}),
      ...(typeof p.model_name === "string" ? { model_name: p.model_name } : {}),
      ...(Array.isArray(p.probes) ? { probes: p.probes.filter((x): x is string => typeof x === "string") } : {}),
      ...(typeof p.generations === "number" ? { generations: p.generations } : {}),
      ...(typeof p.request_template === "string" ? { request_template: p.request_template } : {}),
      ...(typeof p.response_json_field === "string" ? { response_json_field: p.response_json_field } : {}),
      ...(typeof p.model_uri === "string" ? { model_uri: p.model_uri } : {}),
    }));
  }, [scan_id]);

  // Helper function to update creation data
  const updateCreationData =(field: keyof LLMScanCreateData, value: any) => {
      setCreationData(prev => ({
          ...prev,
          [field]: value
      }));
  };

  // Helper function to toggle benchmark selection
  const toggleProbe = (probe: string) => {
      setCreationData(prev => ({
          ...prev,
          probes: prev.probes.includes(probe)
              ? prev.probes.filter(p => p !== probe)
              : [...prev.probes, probe]
      }));
  };

  const queryClient = useQueryClient();
  const router = useRouter();

  /** Validate required inputs; return message for toast on invalid. */
  const validateScanInputs = (): { valid: true } | { valid: false; message: string } => {
    if (!creationData.model_type || !creationData.model_name) {
      return { valid: false, message: "Please select Model Type and Model Name." };
    }
    if (creationData.probes.length === 0) {
      return { valid: false, message: "Please select at least one Security Benchmark." };
    }
    if (creationData.model_type !== "custom" && !creationData.api_key?.trim()) {
      return { valid: false, message: "Please provide the API Key for the model." };
    }
    if (creationData.model_type === "custom") {
      if (!creationData.model_uri?.trim() || !creationData.request_template?.trim() || !creationData.response_json_field?.trim()) {
        return { valid: false, message: "Custom models require Model URI, Request Template, and Response JSON Field." };
      }
      try {
        if (creationData.headers?.trim()) {
          const h = JSON.parse(creationData.headers);
          if (typeof h !== "object") return { valid: false, message: "Headers must be a JSON object." };
        }
      } catch {
        return { valid: false, message: "Invalid JSON in Headers." };
      }
      try {
        const t = JSON.parse(creationData.request_template);
        if (!t || typeof t !== "object") return { valid: false, message: "Request Template must be a JSON object." };
      } catch {
        return { valid: false, message: "Invalid JSON in Request Template." };
      }
    }
    return { valid: true };
  };

  /** Build payload object for backend (matches StartLLMBenchmarkingData). */
  const buildLLMPayload = (): Record<string, unknown> => {
    const validation = validateScanInputs();
    if (!validation.valid) throw new Error(validation.message);
    const base = {
      model_type: creationData.model_type as "openai" | "anthropic" | "gemini" | "custom",
      model_name: creationData.model_name,
      generations: creationData.generations ?? 1,
      probes: creationData.probes,
      api_key: creationData.api_key?.trim() || null,
      method: "post" as const,
    };
    if (creationData.model_type === "custom") {
      const headers =
        creationData.headers?.trim() ? JSON.parse(creationData.headers) as Record<string, unknown> : null;
      const request_template =
        creationData.request_template?.trim() ? JSON.parse(creationData.request_template) as Record<string, unknown> : null;
      return {
        llm: {
          ...base,
          headers,
          request_template,
          response_json_field: creationData.response_json_field?.trim() || null,
          model_uri: creationData.model_uri?.trim() || null,
        },
      };
    }
    return { llm: { ...base, headers: null, request_template: null, response_json_field: null, model_uri: null } };
  };

  const buildPayloadStringSafe = (): string => JSON.stringify(buildLLMPayload());

  const scanInputsValid = validateScanInputs().valid;
  const displayCredits = estimatedCredits;
  const creditsInvalid = estimatedCredits === -1;
  const canRunScan = estimationProcessDone && !creditsInvalid;

  const estimateCreditsMutation = useMutation({
    mutationFn: () => estimateCreditsForScan(team_id, "llm", scan_id, buildPayloadStringSafe()),
    onSuccess: (data) => {
      setEstimatedCredits(data.credits_required);
      setEstimationProcessDone(true);
      if (data.credits_required !== -1) {
        toast.success(`This scan will use ${data.credits_required} credits`);
      } else {
        toast.error("These settings cannot be scanned. Check them and estimate again.");
      }
    },
    onError: (err) => {
      setErrorMessage(handleApiError(err).message);
    },
  });

  const startScanMutation = useMutation({
    mutationFn: () => startScan(team_id, "llm", scan_id, buildPayloadStringSafe()),
    onSuccess: () => {
      setEstimatedCredits(null);
      setEstimationProcessDone(false);
      setOptionsSidebarState("scanning");
      queryClient.invalidateQueries({ queryKey: ["llm-conversation-data", team_id, scan_id] });
    },
    onError: (err) => {
      setErrorMessage(handleApiError(err).message);
      setOptionsSidebarState("ready");
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

  useEffect(() => {
    setEstimationProcessDone(false);
    setEstimatedCredits(null);
    setErrorMessage(null);
  }, [
    creationData.model_type,
    creationData.model_name,
    creationData.probes,
    creationData.api_key,
    creationData.generations,
    creationData.headers,
    creationData.request_template,
    creationData.response_json_field,
    creationData.model_uri,
  ]);

  const exportMutation = useMutation({
    mutationFn: () => getLLMExportResults(team_id, scan_id),
    onSuccess: (data) => {
      const blob = new Blob([data], { type: "application/pdf" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `${query.data?.title ?? "llm"}_scan_report.pdf`;
      a.click();
      setOptionsSidebarState("done");
    },
    onError: (err) => {
      setErrorMessage(handleApiError(err).message);
      setOptionsSidebarState("error");
    },
  });

  const reinitializeScanMutation = useMutation({
    mutationFn: () => reinitializeLLMScan({ team_id, scan_id, start_scan_payload_string: buildPayloadStringSafe() }),
    onSuccess: () => {
      setOptionsSidebarState("scanning");
      queryClient.invalidateQueries({ queryKey: ["llm-conversation-data", team_id, scan_id] });
    },
    onError: (err) => {
      setErrorMessage(handleApiError(err).message);
      setOptionsSidebarState("error");
    },
  });

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
      const msg = scanFailureMessage(query.data); // the worker's reason (scan.info.error)
      setErrorMessage(msg);
      setOptionsSidebarState("error");
    }
    if (query.data?.scan_status === "not_started" || query.data?.scan_status === "NOT_STARTED" || !query.data?.scan_status) {
      setOptionsSidebarState("ready");
      setErrorMessage(null);
    }
  }, [query.data?.scan_status, query.data?.scan_metadata]);

  return (
    <ScrollArea className="w-full md:w-96 shrink-0 md:h-screen bg-neutral-900/70 border-t md:border-t-0 md:border-l border-zinc-800">
      <div className="p-6">
        <div className="flex items-center gap-2 flex-row mb-2">
          <h2 className="text-xl font-bold text-white">LLM Configuration</h2>
          <ScanLine className="h-5 w-5 text-blue-400 shrink-0" />
        </div>
        <p className="text-sm text-zinc-400">
          Configure model, benchmarks, and run estimate then scan.
        </p>
      </div>

      <Separator className="bg-zinc-800" />

      {optionsSidebarState === "ready" && (
        <div className="p-6 space-y-6">
          {/* Model Configuration */}
          <div className="space-y-4">
            <div>
              <h3 className="text-lg font-semibold text-white mb-1">Model Configuration</h3>
              <p className="text-sm text-zinc-400">Configure the LLM model and provider settings</p>
            </div>
            <div className="grid grid-cols-1 gap-4">
              <div className="space-y-2">
                <Label htmlFor="modelType" className="text-zinc-300">Model Type *</Label>
                <Select
                  value={creationData.model_type}
                  onValueChange={(value) => updateCreationData("model_type", value)}
                  required
                >
                  <SelectTrigger className="w-full cursor-pointer bg-zinc-700 border-zinc-600 text-white">
                    <SelectValue placeholder="Select model provider" />
                  </SelectTrigger>
                  <SelectContent className="bg-zinc-800 border-zinc-700">
                    <SelectItem value="openai" className="text-white hover:bg-zinc-700 cursor-pointer">OpenAI</SelectItem>
                    <SelectItem value="anthropic" className="text-white hover:bg-zinc-700 cursor-pointer">Anthropic</SelectItem>
                    <SelectItem value="gemini" className="text-white hover:bg-zinc-700 cursor-pointer">Google Gemini</SelectItem>
                    <SelectItem value="custom" className="text-white hover:bg-zinc-700 cursor-pointer">Custom Model</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              {creationData.model_type == "custom" && <div className="space-y-2">
                <Label htmlFor="modelName" className="text-zinc-300">Model Name *</Label>
                <Input 
                  className="w-full cursor-pointer bg-zinc-700 border-zinc-600 text-white placeholder:text-zinc-500"
                  id="modelName" 
                  placeholder="e.g., gpt-4o, claude-3-sonnet" 
                  value={creationData.model_name} 
                  onChange={(e) => updateCreationData("model_name", e.target.value)} 
                  required 
                />
              </div>}
              {creationData.model_type !== "custom" && creationData.model_type !== "" && <div className="space-y-2">
                <Label htmlFor="modelName" className="text-zinc-300">Model Name *</Label>
                 <div className="cursor-pointer">
                   <ModelChoicePicker creationData={creationData} updateCreationData={updateCreationData} />
                 </div>
              </div>}
            </div>
            <div className="grid grid-cols-1 gap-4">
              {creationData.model_type !== "custom" && <div className="space-y-2">
                <Label htmlFor="apiKey" className="text-zinc-300">API Key *</Label>
                <Input 
                  className="w-full cursor-pointer bg-zinc-700 border-zinc-600 text-white placeholder:text-zinc-500"
                  id="apiKey" 
                  type="password"
                  placeholder="Enter your API key" 
                  value={creationData.api_key} 
                  onChange={(e) => updateCreationData("api_key", e.target.value)} 
                />
              </div>}
              <div className="space-y-2">
                <Label htmlFor="generations" className="text-zinc-300">Generations per benchmark</Label>
                <Input 
                  className="w-full cursor-pointer bg-zinc-700 border-zinc-600 text-white placeholder:text-zinc-500"
                  id="generations" 
                  type="number"
                  min="1"
                  placeholder="1" 
                  value={creationData.generations} 
                  onChange={(e) => updateCreationData("generations", parseInt(e.target.value) || 1)} 
                />
                <p className="text-xs text-zinc-500">Higher values = more tokens consumed</p>
              </div>
            </div>
          </div>

          {/* Custom Model Configuration */}
          {creationData.model_type === "custom" && (
            <div className="space-y-4">
              <div>
                <h3 className="text-lg font-semibold text-white mb-1">Custom Model Configuration</h3>
                <p className="text-sm text-zinc-400">Configure custom model endpoint and request format</p>
              </div>
              <div className="space-y-2">
                <Label htmlFor="modelUri" className="text-zinc-300">Model URI *</Label>
                <Input 
                  className="w-full cursor-pointer bg-zinc-700 border-zinc-600 text-white placeholder:text-zinc-500"
                  id="modelUri" 
                  placeholder="https://api.example.com/v1/chat/completions" 
                  value={creationData.model_uri} 
                  onChange={(e) => updateCreationData("model_uri", e.target.value)} 
                  required 
                />
              </div>
              <div className="min-w-0 space-y-2">
                <Label htmlFor="headersJson" className="text-zinc-300">Headers (JSON)</Label>
                <div className="min-w-0 overflow-hidden">
                  <Textarea
                    className="w-full min-w-0 max-w-full cursor-pointer resize-none overflow-x-auto bg-zinc-700 border-zinc-600 text-white placeholder:text-zinc-500 field-sizing-fixed"
                    id="headersJson"
                    placeholder='{"Authorization": "Bearer <API_KEY>", "Content-Type": "application/json"}'
                    value={creationData.headers}
                    onChange={(e) => updateCreationData("headers", e.target.value)}
                  />
                </div>
              </div>
              <div className="min-w-0 space-y-2">
                <Label htmlFor="requestTemplate" className="text-zinc-300">Request Template *</Label>
                <div className="min-w-0 overflow-hidden">
                  <Textarea
                    className="w-full min-w-0 max-w-full cursor-pointer resize-none overflow-x-auto bg-zinc-700 border-zinc-600 text-white placeholder:text-zinc-500 field-sizing-fixed"
                    id="requestTemplate"
                    placeholder='{"model": "gpt-4o", "messages": [{"role": "user", "content": "$INPUT"}]}'
                    value={creationData.request_template}
                    onChange={(e) => updateCreationData("request_template", e.target.value)}
                    required
                  />
                </div>
              </div>
              <div className="space-y-2">
                <Label htmlFor="responseJsonField" className="text-zinc-300">Response JSON Field *</Label>
                <Input 
                  className="w-full cursor-pointer bg-zinc-700 border-zinc-600 text-white placeholder:text-zinc-500"
                  id="responseJsonField" 
                  placeholder="$.choices[0].message.content" 
                  value={creationData.response_json_field} 
                  onChange={(e) => updateCreationData("response_json_field", e.target.value)} 
                  required 
                />
              </div>
            </div>
          )}

          {/* Security benchmark selection */}
          <div className="space-y-4">
            <div>
              <h3 className="text-lg font-semibold text-white mb-1">Security Benchmarks *</h3>
              <p className="text-sm text-zinc-400">Select the security benchmarks to run against your LLM</p>
            </div>
            {/* Token usage warning */}
            <div className="bg-amber-500/10 border border-amber-500/50 rounded-lg p-3">
              <p className="text-sm font-medium text-amber-400">⚠️ High Token Usage Warning</p>
              <p className="text-xs text-amber-500 mt-1">
                LLM security scans consume significant API tokens. Each benchmark runs multiple tests, and costs can add up quickly. Consider starting with fewer benchmarks and increasing as needed using multiple scans.
              </p>
            </div>
            
            <ScrollArea className="h-60">
              <div className="grid grid-cols-1 gap-2 pr-4">
                {AVAILABLE_PROBES.map((probe) => (
                  <div key={probe} className="flex items-center space-x-2">
                    <Checkbox
                      className="cursor-pointer"
                      id={probe}
                      checked={creationData.probes.includes(probe)}
                      onCheckedChange={() => toggleProbe(probe)}
                    />
                    <Label title={getProbeDescription(probe)} htmlFor={probe} className="text-sm font-normal cursor-pointer text-zinc-300">
                      {getProbeDisplayName(probe)}
                    </Label>
                  </div>
                ))}
              </div>
            </ScrollArea>
            <div className="text-sm text-zinc-400">
              Selected: {creationData.probes.length} benchmark(s)
            </div>
          </div>

          <Separator className="bg-zinc-800" />

          <div className="p-6">
            <h3 className="text-sm font-semibold text-zinc-200 mb-2">Estimate scan credits</h3>
            <Button
              variant="ghost"
              size="sm"
              onClick={handleRunEstimate}
              disabled={!scanInputsValid || estimateCreditsMutation.isPending}
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
            {optionsSidebarState === "ready" && <ScanRequestError message={errorMessage} />}
            {displayCredits != null && (
              <p className="text-sm text-zinc-300 mt-3">
                {creditsInvalid ? (
                  <span className="font-semibold text-amber-400">These settings cannot be scanned. Check them and estimate again.</span>
                ) : (
                  <>
                    Credits required: <span className="font-semibold text-blue-400">{displayCredits}</span>
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
                Credit estimation failed due to invalid inputs. Check model and API key.
              </p>
            ) : (
              <p className="text-sm text-zinc-500">Run estimate above to enable starting the scan.</p>
            )}
          </div>
        </div>
      )}

      {optionsSidebarState === "scanning" && (
        <div className="p-6 flex flex-col items-center justify-center min-h-[400px]">
          <Loader2 className="h-8 w-8 text-blue-500 animate-spin mb-4" />
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
              onClick={() => {
                router.push(`/${team_id}/llm/${scan_id}/results?origin=chat`);
              }}
              className="w-full h-8 px-2 bg-blue-600 hover:bg-blue-700 text-white cursor-pointer hover:text-white"
            >
              <Eye className="size-4" />
              <span className="ml-1">View Results</span>
            </Button>
            <Button 
              variant="ghost" 
              size="sm"
              onClick={async () => {
                exportMutation.mutate();
              }}
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
            {query.data?.scan_status === "failure" ? scanFailureMessage(query.data) : (errorMessage ?? "The request failed. Try again.")}
          </p>
          {query.data?.scan_status === "failure" ? (
            <NewScanRunAgainButton type="llm" teamId={team_id} scan={query.data} settings={{
              model_type: creationData.model_type, model_name: creationData.model_name, probes: creationData.probes,
              generations: creationData.generations, request_template: creationData.request_template,
              response_json_field: creationData.response_json_field, model_uri: creationData.model_uri,
            }} />
          ) : (
            <Button
              variant="ghost"
              size="sm"
              data-testid="scan-try-again"
              onClick={() => {
                // back to the view that matches the scan, with the form still filled in (no reload)
                setErrorMessage(null);
                setOptionsSidebarState(stateAfterError(query.data?.scan_status));
                void query.refetch();
              }}
              className="w-full h-8 px-2 bg-zinc-700 hover:bg-zinc-600 text-white cursor-pointer hover:text-white"
            >
              <span>Try again</span>
            </Button>
          )}
        </div>
      )}

      {query.data?.scan_status === "pending" && (
        <div className="p-6 border-t border-zinc-800">
          <Button 
            variant="ghost" 
            size="sm"
            onClick={() => reinitializeScanMutation.mutate()}
            disabled={reinitializeScanMutation.isPending || !scanInputsValid}
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
