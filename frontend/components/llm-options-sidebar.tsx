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
} from "lucide-react";
import { useMutation, useQuery, useQueryClient, UseQueryResult } from "@tanstack/react-query";
import { LLMConversationResponse, startLLMScan, getLLMExportResults } from "@/utils/backend_api";
import { toast } from "sonner";
import { useParams } from "next/navigation";
import ModelChoicePicker from "./ModelChoicePicker";
import probeDescription from "@/garak_probes.json";
import { generateAndDownloadPDF } from "@/components/PDF_Report";

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

// Available probe categories and probes
const availableProbes = [
    "malwaregen.TopLevel",
    "malwaregen.Evasion", 
    "promptinject.HijackHateHumans",
    "promptinject.HijackKillHumans",
    "promptinject.HijackLongPrompt",
    "realtoxicityprompts.RTPBlank",
    "sata.MLM",
    "snowball.GraphConnectivity",
    "snowball.Primes",
    "snowball.Senators",
    "suffix.BEAST",
    "suffix.GCG",
    "suffix.GCGCached",
    "tap.PAIR",
    "tap.TAP",
    "tap.TAPCached",
    "test.Blank",
    "test.Test",
    "topic.WordnetAllowedWords",
    "topic.WordnetBlockedWords",
    "topic.WordnetControversial",
    "visual_jailbreak.FigStep",
    "xss.ColabAIDataLeakage",
    "xss.MarkdownImageExfil",
    "xss.MarkdownURIImageExfilExtended",
    "xss.MarkdownURINonImageExfilExtended",
    "xss.MdExfil20230929",
    "xss.StringAssemblyDataExfil"
];

// Display names mapping for probes
const probeDisplayNames: Record<string, string> = {
    "malwaregen.TopLevel": "Malware Generation - Top Level",
    "malwaregen.Evasion": "Malware Generation - Evasion Techniques",
    "promptinject.HijackHateHumans": "Prompt Injection - Hate Humans",
    "promptinject.HijackKillHumans": "Prompt Injection - Kill Humans",
    "promptinject.HijackLongPrompt": "Prompt Injection - Long Prompt",
    "realtoxicityprompts.RTPBlank": "Real Toxicity Prompts - Blank",
    "sata.MLM": "SATA - Masked Language Model",
    "snowball.GraphConnectivity": "Snowball - Graph Connectivity",
    "snowball.Primes": "Snowball - Prime Numbers",
    "snowball.Senators": "Snowball - Senators",
    "suffix.BEAST": "Suffix Attack - BEAST",
    "suffix.GCG": "Suffix Attack - GCG",
    "suffix.GCGCached": "Suffix Attack - GCG Cached",
    "tap.PAIR": "TAP - PAIR",
    "tap.TAP": "TAP - Tree of Attacks with Pruning",
    "tap.TAPCached": "TAP - Tree of Attacks (Cached)",
    "test.Blank": "Test - Blank Response",
    "test.Test": "Test - Basic Test",
    "topic.WordnetAllowedWords": "Topic - WordNet Allowed Words",
    "topic.WordnetBlockedWords": "Topic - WordNet Blocked Words",
    "topic.WordnetControversial": "Topic - WordNet Controversial",
    "visual_jailbreak.FigStep": "Visual Jailbreak - Figure Step",
    "xss.ColabAIDataLeakage": "XSS - Colab AI Data Leakage",
    "xss.MarkdownImageExfil": "XSS - Markdown Image Exfiltration",
    "xss.MarkdownURIImageExfilExtended": "XSS - Markdown URI Image Exfiltration",
    "xss.MarkdownURINonImageExfilExtended": "XSS - Markdown URI Non-Image Exfiltration",
    "xss.MdExfil20230929": "XSS - Markdown Exfiltration (2023-09-29)",
    "xss.StringAssemblyDataExfil": "XSS - String Assembly Data Exfiltration"
};

export function LLMOptionsSidebar({
  query,
}:{
  query: UseQueryResult<LLMConversationResponse>;
}) {
  const [ optionsSidebarState , setOptionsSidebarState ] = useState<"ready" | "scanning" | "error" | "done" >("ready");

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

  // Helper function to update creation data
  const updateCreationData = (field: keyof LLMScanCreateData, value: any) => {
      setCreationData(prev => ({
          ...prev,
          [field]: value
      }));
  };

  // Helper function to toggle probe selection
  const toggleProbe = (probe: string) => {
      setCreationData(prev => ({
          ...prev,
          probes: prev.probes.includes(probe)
              ? prev.probes.filter(p => p !== probe)
              : [...prev.probes, probe]
      }));
  };

  const queryClient = useQueryClient();
  const { conversation_id } = useParams();

  const handleStartScan = ({
    conversation_id,
    creationData
  }: {
    conversation_id: number;
    creationData: LLMScanCreateData;
  }) => {
    setOptionsSidebarState("scanning");
    
    // Validate required fields
    if (!creationData.api_key && creationData.model_type !== "custom"){
      toast.error("Please provide the API Key for the model");
      setOptionsSidebarState("error");
      throw new Error("Please provide the API Key for the model");
    }
    if(!creationData.model_type || !creationData.model_name || creationData.probes.length === 0){
      toast.error("Please fill in Model Type, Model Name, and at least one Probe");
      setOptionsSidebarState("error");
      throw new Error("Please fill in Model Type, Model Name, and at least one Probe");
    }

    // For custom models, validate additional required fields
    if(creationData.model_type === "custom"){
      if(!creationData.model_uri || !creationData.request_template || !creationData.response_json_field){
        toast.error("Custom models require Model URI, Request Template, and Response JSON Field");
        setOptionsSidebarState("error");
        throw new Error("Custom models require Model URI, Request Template, and Response JSON Field");
      }

      // Validate JSON for headers and request_template
      let parsedHeaders = null;
      let parsedTemplate = null;

      try {
        parsedHeaders = creationData.headers && creationData.headers.trim() !== "" ? JSON.parse(creationData.headers) : "";
        if(parsedHeaders && typeof parsedHeaders !== "object"){
          toast.error("Headers must be a JSON object");
          setOptionsSidebarState("error");
          throw new Error("Headers must be a JSON object");
        }
      } catch (e:any) {
        toast.error("Invalid JSON in Headers");
        setOptionsSidebarState("error");
        throw new Error("Invalid JSON in Headers");
      }

      try {
        parsedTemplate = creationData.request_template && creationData.request_template.trim() !== "" ? JSON.parse(creationData.request_template) : "";
        if(!parsedTemplate || typeof parsedTemplate !== "object"){
          toast.error("Request Template must be a JSON object");
          setOptionsSidebarState("error");
          throw new Error("Request Template must be a JSON object");
        }
      } catch (e:any) {
        toast.error("Invalid JSON in Request Template");
        setOptionsSidebarState("error");
        throw new Error("Invalid JSON in Request Template");
      }

      return startLLMScan({
        conversation_id,
        model_type: creationData.model_type as "openai" | "anthropic" | "gemini" | "custom",
        model_name: creationData.model_name,
        generations: creationData.generations,
        probes: creationData.probes,
        api_key: creationData.api_key || null,
        headers: parsedHeaders,
        request_template: parsedTemplate,
        response_json_field: creationData.response_json_field,
        model_uri: creationData.model_uri
      });
    }

    return startLLMScan({
      conversation_id,
      model_type: creationData.model_type as "openai" | "anthropic" | "gemini" | "custom",
      model_name: creationData.model_name,
      generations: creationData.generations,
      probes: creationData.probes,
      api_key: creationData.api_key || null,
      headers: null,
      request_template: null,
      response_json_field: null,
      model_uri: null
    });
  };

  const startScanMutation = useMutation({
    mutationFn: handleStartScan,
    onSuccess: () => {
      setOptionsSidebarState("scanning");
      queryClient.invalidateQueries({ queryKey: ['llm-conversation-data', parseInt(conversation_id as string)] });
    },
    onError: () => {
      setOptionsSidebarState("error");
    }
  });

  const exportMutation = useMutation({
    mutationFn: getLLMExportResults,
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
  }, [query.data?.scan_status]);

  return (
    <ScrollArea className="w-80 h-screen bg-zinc-900 dark:bg-zinc-950 border-l border-zinc-800">
      <div className="p-6">
        <h2 className="text-xl font-bold text-white mb-2">LLM Options</h2>
        <p className="text-sm text-zinc-400">
          Configure your LLM benchmark scanning options.
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
                  className="cursor-pointer bg-zinc-700 border-zinc-600 text-white placeholder:text-zinc-500"
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
                  className="cursor-pointer bg-zinc-700 border-zinc-600 text-white placeholder:text-zinc-500"
                  id="apiKey" 
                  type="password"
                  placeholder="Enter your API key" 
                  value={creationData.api_key} 
                  onChange={(e) => updateCreationData("api_key", e.target.value)} 
                />
              </div>}
              <div className="space-y-2">
                <Label htmlFor="generations" className="text-zinc-300">Generations per Probe</Label>
                <Input 
                  className="cursor-pointer bg-zinc-700 border-zinc-600 text-white placeholder:text-zinc-500"
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
                  className="cursor-pointer bg-zinc-700 border-zinc-600 text-white placeholder:text-zinc-500"
                  id="modelUri" 
                  placeholder="https://api.example.com/v1/chat/completions" 
                  value={creationData.model_uri} 
                  onChange={(e) => updateCreationData("model_uri", e.target.value)} 
                  required 
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="headersJson" className="text-zinc-300">Headers (JSON)</Label>
                <Textarea
                  className="cursor-pointer bg-zinc-700 border-zinc-600 text-white placeholder:text-zinc-500"
                  id="headersJson"
                  placeholder='{"Authorization": "Bearer <API_KEY>", "Content-Type": "application/json"}'
                  value={creationData.headers}
                  onChange={(e) => updateCreationData("headers", e.target.value)}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="requestTemplate" className="text-zinc-300">Request Template *</Label>
                <Textarea
                  className="cursor-pointer bg-zinc-700 border-zinc-600 text-white placeholder:text-zinc-500"
                  id="requestTemplate"
                  placeholder='{"model": "gpt-4o", "messages": [{"role": "user", "content": "$INPUT"}]}'
                  value={creationData.request_template}
                  onChange={(e) => updateCreationData("request_template", e.target.value)}
                  required
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="responseJsonField" className="text-zinc-300">Response JSON Field *</Label>
                <Input 
                  className="cursor-pointer bg-zinc-700 border-zinc-600 text-white placeholder:text-zinc-500"
                  id="responseJsonField" 
                  placeholder="$.choices[0].message.content" 
                  value={creationData.response_json_field} 
                  onChange={(e) => updateCreationData("response_json_field", e.target.value)} 
                  required 
                />
              </div>
            </div>
          )}

          {/* Probe Selection */}
          <div className="space-y-4">
            <div>
              <h3 className="text-lg font-semibold text-white mb-1">Security Probes *</h3>
              <p className="text-sm text-zinc-400">Select the security probes to test against your LLM</p>
            </div>
            {/* Token usage warning */}
            <div className="bg-amber-500/10 border border-amber-500/50 rounded-lg p-3">
              <p className="text-sm font-medium text-amber-400">⚠️ High Token Usage Warning</p>
              <p className="text-xs text-amber-500 mt-1">
                LLM security scans consume significant API tokens. Each probe runs multiple tests, and costs can add up quickly. Consider starting with fewer probes and increasing as needed using multiple scans.
              </p>
            </div>
            
            <ScrollArea className="h-60">
              <div className="grid grid-cols-1 gap-2 pr-4">
                {availableProbes.map((probe) => (
                  <div key={probe} className="flex items-center space-x-2">
                    <Checkbox
                      className="cursor-pointer"
                      id={probe}
                      checked={creationData.probes.includes(probe)}
                      onCheckedChange={() => toggleProbe(probe)}
                    />
                    <Label title={probeDescription[probe as keyof typeof probeDescription]} htmlFor={probe} className="text-sm font-normal cursor-pointer text-zinc-300">
                      {probeDisplayNames[probe] || probe}
                    </Label>
                  </div>
                ))}
              </div>
            </ScrollArea>
            <div className="text-sm text-zinc-400">
              Selected: {creationData.probes.length} probe(s)
            </div>
          </div>

          <Button 
            variant="ghost" 
            size="icon-lg"
            onClick={() =>{ 
              startScanMutation.mutate({
                conversation_id: parseInt(conversation_id as string),
                creationData
              });
              setOptionsSidebarState("scanning");
            }}
            className="w-full h-8 px-4 bg-teal-600 hover:bg-teal-700 text-white cursor-pointer hover:text-white"
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
                  const modelInfo = query.data?.model_name 
                    ? `${query.data.model_type || "LLM"}: ${query.data.model_name}`
                    : null;
                  generateAndDownloadPDF(
                    exportResults,
                    "LLM Security Scan",
                    modelInfo,
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
