"use client";

import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { generateFindingRemediation, type RemediationData } from "@/utils/backend_api";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { ScrollArea } from "@/components/ui/scroll-area";
import { showErrorToast } from "@/utils/error-handler";
import {
  Loader2,
  Shield,
  Copy,
  Check,
  AlertTriangle,
  Zap,
  CheckCircle,
} from "lucide-react";
import { toast } from "sonner";

interface RemediationPanelProps {
  teamId: string;
  scanType: "sast" | "iac" | "sbom_sca" | "mcp" | "llm" | "dast" | "cbom";
  scanId: number;
  findingId: string;
  existingRemediation?: RemediationData | null;
  onRemediationGenerated?: (data: RemediationData) => void;
}

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  const handleCopy = async () => {
    await navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };
  return (
    <Button variant="ghost" size="sm" onClick={handleCopy} className="h-7 gap-1.5 text-xs">
      {copied ? <Check className="h-3 w-3" /> : <Copy className="h-3 w-3" />}
      {copied ? "Copied" : "Copy"}
    </Button>
  );
}

function DiffLine({ line }: { line: string }) {
  if (line.startsWith("+") && !line.startsWith("+++")) {
    return <div className="bg-green-500/10 text-green-700 dark:text-green-400 px-2">{line}</div>;
  }
  if (line.startsWith("-") && !line.startsWith("---")) {
    return <div className="bg-red-500/10 text-red-700 dark:text-red-400 px-2">{line}</div>;
  }
  if (line.startsWith("@@")) {
    return <div className="bg-blue-500/10 text-blue-600 dark:text-blue-400 px-2">{line}</div>;
  }
  return <div className="px-2 text-zinc-600 dark:text-zinc-400">{line}</div>;
}

function DiffViewer({ diff }: { diff: string }) {
  if (!diff) return null;
  const lines = diff.split("\n");
  return (
    <div className="rounded-md border border-zinc-200 dark:border-zinc-700 overflow-hidden">
      <div className="flex items-center justify-between px-3 py-1.5 border-b border-zinc-200 dark:border-zinc-700 bg-zinc-50 dark:bg-zinc-900">
        <span className="text-xs font-medium text-zinc-500 dark:text-zinc-400">Diff View</span>
        <CopyButton text={diff} />
      </div>
      <ScrollArea className="max-h-[300px]">
        <pre className="text-xs font-mono leading-relaxed py-2">
          {lines.map((line, i) => (
            <DiffLine key={i} line={line} />
          ))}
        </pre>
      </ScrollArea>
    </div>
  );
}

function ConfidenceMeter({ confidence }: { confidence: number }) {
  const color =
    confidence >= 80 ? "bg-green-500" : confidence >= 50 ? "bg-yellow-500" : "bg-red-500";
  return (
    <div className="flex items-center gap-2">
      <div className="flex-1 h-2 bg-zinc-200 dark:bg-zinc-700 rounded-full overflow-hidden">
        <div className={`h-full ${color} rounded-full transition-all`} style={{ width: `${confidence}%` }} />
      </div>
      <span className="text-xs font-medium text-zinc-600 dark:text-zinc-400">{confidence}%</span>
    </div>
  );
}

const difficultyColors: Record<string, string> = {
  trivial: "bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400",
  easy: "bg-orange-100 text-orange-800 dark:bg-orange-900/30 dark:text-orange-400",
  moderate: "bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-400",
  hard: "bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-400",
  expert: "bg-purple-100 text-purple-800 dark:bg-purple-900/30 dark:text-purple-400",
};

export default function RemediationPanel({
  teamId,
  scanType,
  scanId,
  findingId,
  existingRemediation,
  onRemediationGenerated,
}: RemediationPanelProps) {
  const [remediation, setRemediation] = useState<RemediationData | null>(existingRemediation ?? null);
  const queryClient = useQueryClient();

  const generateMutation = useMutation({
    mutationFn: () =>
      generateFindingRemediation({
        team_id: parseInt(teamId, 10),
        type: scanType,
        scan_id: scanId,
        finding_id: findingId,
      }),
    onSuccess: (data) => {
      setRemediation(data);
      onRemediationGenerated?.(data);
      if (data.status === "completed") {
        queryClient.invalidateQueries({ queryKey: ["teams"] });
        queryClient.invalidateQueries({ queryKey: ["teams-dashboard"] });
        queryClient.invalidateQueries({ queryKey: ["team-dashboard"] });
        toast.success("AI remediation generated successfully");
      } else {
        toast.error("Remediation generation failed: " + (data.error || "Unknown error"));
      }
    },
    onError: (err) => {
      showErrorToast(err, "Failed to generate remediation");
    },
  });

  // Already has remediation — show results directly, no generate button
  if (remediation && remediation.status === "completed") {
    return (
      <div className="space-y-4 pt-2">
        <div className="flex items-center gap-2">
          <Shield className="h-4 w-4 text-green-600 dark:text-green-400" />
          <span className="text-sm font-semibold text-zinc-800 dark:text-zinc-200">AI Remediation</span>
          <Badge variant="outline" className="ml-auto text-xs gap-1 text-green-700 dark:text-green-400 border-green-300 dark:border-green-700">
            <CheckCircle className="h-3 w-3" /> Generated
          </Badge>
        </div>

        <Tabs defaultValue="fix" className="w-full">
          <TabsList className="w-full grid grid-cols-3">
            <TabsTrigger value="fix" className="text-xs">Fix Code</TabsTrigger>
            <TabsTrigger value="diff" className="text-xs">Diff</TabsTrigger>
            <TabsTrigger value="exploit" className="text-xs">Exploit Demo</TabsTrigger>
          </TabsList>

          {/* Fix Code Tab */}
          <TabsContent value="fix" className="space-y-3 pt-2">
            {remediation.fix && (
              <>
                <p className="text-sm text-zinc-700 dark:text-zinc-300">{remediation.fix.description}</p>

                <div className="flex items-center gap-3">
                  <div className="flex-1">
                    <span className="text-xs text-zinc-500 dark:text-zinc-400">Confidence</span>
                    <ConfidenceMeter confidence={remediation.fix.confidence} />
                  </div>
                  <Badge variant="secondary" className="text-xs">{remediation.fix.language}</Badge>
                </div>

                {/* Original code */}
                <div>
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-xs font-semibold uppercase tracking-wide text-red-600 dark:text-red-400">Vulnerable Code</span>
                    <CopyButton text={remediation.fix.original_code} />
                  </div>
                  <pre className="text-xs bg-red-50 dark:bg-red-900/10 p-3 rounded-md overflow-x-auto whitespace-pre-wrap font-mono text-zinc-800 dark:text-zinc-200 border border-red-200 dark:border-red-800">
                    {remediation.fix.original_code}
                  </pre>
                </div>

                {/* Fixed code */}
                <div>
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-xs font-semibold uppercase tracking-wide text-green-600 dark:text-green-400">Fixed Code</span>
                    <CopyButton text={remediation.fix.fixed_code} />
                  </div>
                  <pre className="text-xs bg-green-50 dark:bg-green-900/10 p-3 rounded-md overflow-x-auto whitespace-pre-wrap font-mono text-zinc-800 dark:text-zinc-200 border border-green-200 dark:border-green-800">
                    {remediation.fix.fixed_code}
                  </pre>
                </div>

                {remediation.fix.validation_notes && (
                  <div>
                    <span className="text-xs font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400">Validation Notes</span>
                    <p className="text-xs text-zinc-600 dark:text-zinc-400 mt-0.5">{remediation.fix.validation_notes}</p>
                  </div>
                )}

                {remediation.fix.references && remediation.fix.references.length > 0 && (
                  <div>
                    <span className="text-xs font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400">References</span>
                    <div className="flex flex-wrap gap-1 mt-1">
                      {remediation.fix.references.map((ref, i) => (
                        <a key={i} href={ref} target="_blank" rel="noopener noreferrer" className="text-xs text-blue-600 dark:text-blue-400 underline hover:no-underline truncate max-w-[250px]">
                          {ref}
                        </a>
                      ))}
                    </div>
                  </div>
                )}
              </>
            )}
          </TabsContent>

          {/* Diff Tab */}
          <TabsContent value="diff" className="pt-2">
            {remediation.diff ? (
              <DiffViewer diff={remediation.diff} />
            ) : (
              <p className="text-xs text-zinc-500 dark:text-zinc-400">No diff available for this remediation.</p>
            )}
          </TabsContent>

          {/* Exploit Payload Tab */}
          <TabsContent value="exploit" className="space-y-3 pt-2">
            {remediation.exploit_payload && (
              <>
                <div className="flex items-center gap-2 p-2 rounded-md bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-800">
                  <AlertTriangle className="h-4 w-4 text-amber-600 dark:text-amber-400 shrink-0" />
                  <span className="text-xs text-amber-800 dark:text-amber-300">For educational purposes only. Do not use against systems without authorization.</span>
                </div>

                <p className="text-sm text-zinc-700 dark:text-zinc-300">{remediation.exploit_payload.description}</p>

                <div className="flex items-center gap-2 flex-wrap">
                  <Badge className={difficultyColors[remediation.exploit_payload.difficulty] || "bg-zinc-100 text-zinc-800"}>
                    <Zap className="h-3 w-3 mr-1" />{remediation.exploit_payload.difficulty}
                  </Badge>
                  <Badge variant="outline" className="text-xs">
                    {remediation.exploit_payload.attack_vector}
                  </Badge>
                </div>

                <div>
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-xs font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400">Proof of Concept</span>
                    <CopyButton text={remediation.exploit_payload.payload} />
                  </div>
                  <pre className="text-xs bg-zinc-100 dark:bg-zinc-800 p-3 rounded-md overflow-x-auto whitespace-pre-wrap font-mono text-zinc-800 dark:text-zinc-200 border border-zinc-200 dark:border-zinc-700">
                    {remediation.exploit_payload.payload}
                  </pre>
                </div>

                <div>
                  <span className="text-xs font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400">Impact</span>
                  <p className="text-xs text-zinc-600 dark:text-zinc-400 mt-0.5">{remediation.exploit_payload.impact_demonstration}</p>
                </div>

                <div>
                  <span className="text-xs font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400">Prerequisites</span>
                  <p className="text-xs text-zinc-600 dark:text-zinc-400 mt-0.5">{remediation.exploit_payload.prerequisites}</p>
                </div>
              </>
            )}
          </TabsContent>
        </Tabs>
      </div>
    );
  }

  // No remediation yet — show generate button
  return (
    <div className="pt-2">
      <div className="flex items-center gap-2 mb-3">
        <Shield className="h-4 w-4 text-zinc-500 dark:text-zinc-400" />
        <span className="text-sm font-semibold text-zinc-800 dark:text-zinc-200">AI Remediation</span>
      </div>

      {remediation?.status === "failed" && (
        <div className="mb-3 p-2 rounded-md bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800">
          <p className="text-xs text-red-700 dark:text-red-400">Generation failed: {remediation.error || "Unknown error"}</p>
        </div>
      )}

      <Button
        onClick={() => generateMutation.mutate()}
        disabled={generateMutation.isPending}
        variant="outline"
        className="w-full gap-2"
      >
        {generateMutation.isPending ? (
          <>
            <Loader2 className="h-4 w-4 animate-spin" />
            Generating remediation...
          </>
        ) : (
          <>
            <Shield className="h-4 w-4" />
            Generate AI Remediation
          </>
        )}
      </Button>

      {!generateMutation.isPending && (
        <p className="text-xs text-zinc-500 dark:text-zinc-400 text-center mt-1.5">
          0.05 credits will be used
        </p>
      )}

      {generateMutation.isPending && (
        <p className="text-xs text-zinc-500 dark:text-zinc-400 text-center mt-2">
          This may take 15-30 seconds. Two AI calls are being made for fix code and exploit analysis.
        </p>
      )}
    </div>
  );
}
