"use client";

import { Dispatch, SetStateAction, useEffect, useState } from "react";
import { Button } from "@/components/ui/button";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Separator } from "@/components/ui/separator";
import { Label } from "@/components/ui/label";
import { Input } from "@/components/ui/input";
import {
  ScanIcon,
  Download,
  Loader2,
  Eye,
  ScanLine,
  FileJson,
  FolderGit2,
} from "lucide-react";
import {
  Accordion,
  AccordionContent,
  AccordionItem,
  AccordionTrigger,
} from "@/components/ui/accordion";
import { RepositoryCard } from "@/components/repository-card";
import { useMutation, useQueryClient, UseQueryResult } from "@tanstack/react-query";
import {
  AIBOMConversationResponse,
  getAIBOMExportResults,
  reinitializeAIBOMScanWithPayload,
  estimateCreditsForScan,
  startScan,
  type StartScanPayload,
  type RepoMode,
} from "@/utils/backend_api";
import { toast } from "sonner";
import { useParams, useRouter } from "next/navigation";
import { handleApiError } from "@/utils/error-handler";
import { scanFailureMessage } from "@/utils/scanFailure";

export type Mode = RepoMode | "unknown";

export function AiBomOptionsSidebar({
  query,
  mode,
  setMode,
  repo_url,
  setRepoUrl,
  PAT,
  setPAT,
  branch,
  setBranch,
}: {
  query: UseQueryResult<AIBOMConversationResponse>;
  mode: Mode;
  setMode: Dispatch<SetStateAction<Mode>>;
  repo_url: string;
  setRepoUrl: Dispatch<SetStateAction<string>>;
  PAT: string;
  setPAT: Dispatch<SetStateAction<string>>;
  branch: string;
  setBranch: Dispatch<SetStateAction<string>>;
}) {
  const [optionsSidebarState, setOptionsSidebarState] = useState<"ready" | "scanning" | "error" | "done">("ready");
  const [error_message, setErrorMessage] = useState<string | null>(null);
  const [estimatedCredits, setEstimatedCredits] = useState<number | null>(null);
  const [estimationProcessDone, setEstimationProcessDone] = useState(false);
  const [uploaded_file, setUploadedFile] = useState<File | null>(null);
  const [uploaded_ai_bom_file, setUploadedAiBomFile] = useState<File | null>(null);

  const zip_file_used = uploaded_file !== null;
  const ai_bom_file_used = uploaded_ai_bom_file !== null;

  const queryClient = useQueryClient();
  const router = useRouter();
  const params = useParams();
  const team_id = parseInt(params?.team_id as string, 10);
  const scan_id = parseInt(params?.scan_id as string, 10);

  const validateScanInputs = (): { valid: true } | { valid: false; message: string } => {
    if (uploaded_file) return { valid: true };
    if (uploaded_ai_bom_file) return { valid: true };
    if (mode === "unknown") {
      return { valid: false, message: "Please select a repository platform (GitHub, GitLab, or Bitbucket)." };
    }
    if (!repo_url?.trim()) {
      return { valid: false, message: "Please enter the repository URL." };
    }
    // GitHub public repos can clone without a PAT. GitLab/Bitbucket still need a token.
    if (mode !== "github" && !PAT?.trim()) {
      return { valid: false, message: "Please enter a Personal Access Token." };
    }
    if (PAT?.trim() && (/:\/\//.test(PAT) || /github\.com|gitlab\.com|bitbucket\.org/i.test(PAT))) {
      return { valid: false, message: "PAT looks like a URL. Paste a token (or leave blank for public GitHub repos)." };
    }
    return { valid: true };
  };

  const buildStartScanPayloadString = (): string => {
    const validation = validateScanInputs();
    if (!validation.valid) throw new Error(validation.message);
    const payload: StartScanPayload = {
      ai_bom: {
        repo_context:
          zip_file_used || ai_bom_file_used
            ? null
            : { mode: mode as RepoMode, repo_url: repo_url.trim(), PAT: (PAT || "").trim(), branch: (branch?.trim() || "main") },
        zip_file_used,
        ai_bom_file_used,
      },
    };
    return JSON.stringify(payload);
  };

  const getUploadedFileForApi = (): File | undefined => {
    if (zip_file_used && uploaded_file) return uploaded_file;
    if (ai_bom_file_used && uploaded_ai_bom_file) return uploaded_ai_bom_file;
    return undefined;
  };

  const estimateCreditsMutation = useMutation({
    mutationFn: () =>
      estimateCreditsForScan(team_id, "ai_bom", scan_id, buildStartScanPayloadString(), getUploadedFileForApi()),
    onSuccess: (data) => {
      setEstimatedCredits(data.credits_required);
      setEstimationProcessDone(true);
      if (data.credits_required !== -1) {
        toast.success(`This scan will use ${data.credits_required} credits`);
      } else {
        toast.error("Invalid Input from user");
      }
    },
    onError: (err) => {
      setErrorMessage(handleApiError(err).message);
      setOptionsSidebarState("error");
    },
  });

  const startScanMutation = useMutation({
    mutationFn: () =>
      startScan(team_id, "ai_bom", scan_id, buildStartScanPayloadString(), getUploadedFileForApi()),
    onSuccess: () => {
      setEstimatedCredits(null);
      setEstimationProcessDone(false);
      setOptionsSidebarState("scanning");
      queryClient.invalidateQueries({ queryKey: ["ai_bom-conversation-data", team_id, scan_id] });
    },
    onError: (err) => {
      setErrorMessage(handleApiError(err).message);
      setOptionsSidebarState("error");
    },
  });

  const handleRunScan = () => {
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

  useEffect(() => {
    setEstimationProcessDone(false);
    setEstimatedCredits(null);
  }, [mode, repo_url, PAT, uploaded_file, uploaded_ai_bom_file]);

  const displayCredits = estimatedCredits;
  const creditsInvalid = estimatedCredits === -1;
  const canRunScan = estimationProcessDone && !creditsInvalid;

  const failureMessage = scanFailureMessage(query.data);
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
      const msg = failureMessage;
      setErrorMessage(msg);
      setOptionsSidebarState("error");
    }
    if (query.data?.scan_status === "not_started" || query.data?.scan_status === "unknown") {
      setOptionsSidebarState("ready");
      setErrorMessage(null);
    }
  }, [query.data?.scan_status, query.data?.scan_metadata, failureMessage]);

  const exportMutation = useMutation({
    mutationFn: () => getAIBOMExportResults(team_id, scan_id),
    onSuccess: (data) => {
      const blob = new Blob([data], { type: "application/pdf" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `${query.data?.title ?? "ai_bom"}_scan_report.pdf`;
      a.click();
      URL.revokeObjectURL(url);
      setOptionsSidebarState("done");
    },
    onError: (err) => {
      setErrorMessage(handleApiError(err).message);
      setOptionsSidebarState("error");
    },
  });

  const reinitializeScanMutation = useMutation({
    mutationFn: () =>
      reinitializeAIBOMScanWithPayload(
        team_id,
        scan_id,
        buildStartScanPayloadString(),
        getUploadedFileForApi() ?? undefined
      ),
    onSuccess: () => {
      setOptionsSidebarState("scanning");
      queryClient.invalidateQueries({ queryKey: ["ai_bom-conversation-data", team_id, scan_id] });
    },
    onError: (err) => {
      setErrorMessage(handleApiError(err).message);
      setOptionsSidebarState("error");
    },
  });

  const onZipChange: Dispatch<SetStateAction<File | null>> = (value) => {
    setUploadedFile((prev) => {
      const next = typeof value === "function" ? value(prev) : value;
      if (next) setUploadedAiBomFile(null);
      return next;
    });
  };

  const onAiBomFileChange = (file: File | null) => {
    setUploadedAiBomFile(file);
    if (file) {
      setUploadedFile(null);
      setRepoUrl("");
      setPAT("");
      setMode("unknown");
    }
  };

  const setRepoUrlAndClearAiBom: Dispatch<SetStateAction<string>> = (value) => {
    setRepoUrl(value);
    setUploadedAiBomFile(null);
  };
  const setPATAndClearAiBom: Dispatch<SetStateAction<string>> = (value) => {
    setPAT(value);
    setUploadedAiBomFile(null);
  };

  return (
    <ScrollArea className="w-96 h-screen bg-neutral-900/70 border-l border-zinc-800">
      <div className="p-6">
        <div className="flex items-center gap-2 flex-row mb-2">
          <h2 className="text-xl font-bold text-white">AI BOM Configuration</h2>
          <ScanLine className="h-5 w-5 text-blue-400 shrink-0" />
        </div>
        <p className="text-sm text-zinc-400">
          Analyze AI assets: connect a repository (or upload zip) or upload an existing AI BOM file.
        </p>
      </div>

      <Separator className="bg-zinc-800" />

      {optionsSidebarState === "ready" && (
        <>
          <div className="p-6 pb-8">
            <Accordion type="single" collapsible className="w-full">
              <AccordionItem value="repository" className="border-zinc-700 border rounded-lg px-3 data-[state=open]:border-blue-500/50">
                <AccordionTrigger className="text-zinc-300 hover:text-white cursor-pointer py-4 hover:no-underline [&[data-state=open]>svg]:rotate-180">
                  <div className="flex items-center gap-2">
                    <FolderGit2 className="h-4 w-4 text-zinc-400 shrink-0" />
                    <span>Analyze Repository</span>
                  </div>
                </AccordionTrigger>
                <AccordionContent className="pb-5 pt-0">
                  <RepositoryCard
                    uploadedFile={uploaded_file}
                    setUploadedFile={onZipChange}
                    repoUrl={repo_url}
                    setRepoUrl={setRepoUrlAndClearAiBom}
                    pat={PAT}
                    setPat={setPATAndClearAiBom}
                    branch={branch}
                    setBranch={setBranch}
                    mode={mode}
                    setMode={setMode}
                  />
                </AccordionContent>
              </AccordionItem>
              <AccordionItem value="ai-bom-file" className="border-zinc-700 border rounded-lg px-3 mt-2 data-[state=open]:border-blue-500/50">
                <AccordionTrigger className="text-zinc-300 hover:text-white cursor-pointer py-4 hover:no-underline [&[data-state=open]>svg]:rotate-180">
                  <div className="flex items-center gap-2">
                    <FileJson className="h-4 w-4 text-zinc-400 shrink-0" />
                    <span>Analyze AI BOM file</span>
                    {uploaded_ai_bom_file && (
                      <span className="text-xs text-zinc-500 font-normal">({uploaded_ai_bom_file.name})</span>
                    )}
                  </div>
                </AccordionTrigger>
                <AccordionContent className="pb-6 pt-0">
                  <p className="text-xs text-zinc-500 mb-3">
                    Upload an existing AI BOM JSON file. This will clear any repository or zip selection.
                  </p>
                  <Label className="text-zinc-300 text-sm">AI BOM file</Label>
                  <Input
                    type="file"
                    accept=".json,application/json"
                    className="bg-zinc-800 h-fit p-2 border-zinc-700 text-white file:mr-2 file:rounded file:border-0 file:bg-blue-600 file:cursor-pointer file:px-3 file:py-1 file:text-sm file:text-white mt-1"
                    onChange={(e) => onAiBomFileChange(e.target.files?.[0] ?? null)}
                  />
                  {uploaded_ai_bom_file && (
                    <p className="text-xs text-zinc-500 mt-2 mb-2">{uploaded_ai_bom_file.name}</p>
                  )}
                </AccordionContent>
              </AccordionItem>
            </Accordion>
          </div>

          <Separator className="bg-zinc-800" />

          <div className="p-6">
            <h3 className="text-sm font-semibold text-zinc-200 mb-2">Estimate scan credits</h3>
            <Button
              variant="ghost"
              size="sm"
              onClick={handleRunScan}
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
            {displayCredits != null && (
              <p className="text-sm text-zinc-300 mt-3">
                {creditsInvalid ? (
                  <span className="font-semibold text-amber-400">Invalid Input from user</span>
                ) : (
                  <>Credits required: <span className="font-semibold text-blue-400">{displayCredits}</span></>
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
                    <>Start scan</>
                  )}
                </Button>
                {displayCredits != null && !creditsInvalid && (
                  <p className="text-xs text-zinc-500">Uses {displayCredits} credits.</p>
                )}
              </div>
            ) : creditsInvalid ? (
              <p className="text-sm text-amber-400">Credit Estimation failed due to invalid inputs from user. Ensure there are documents that match the include/exclude patterns.</p>
            ) : (
              <p className="text-sm text-zinc-500">Run estimate above to enable starting the scan.</p>
            )}
          </div>
        </>
      )}

      {optionsSidebarState === "scanning" && (
        <div className="p-6 flex flex-col items-center justify-center min-h-[400px]">
          <Loader2 className="h-8 w-8 text-blue-500 animate-spin mb-4" />
          <p className="text-zinc-300 text-center">Scan has started, this might take a while</p>
        </div>
      )}

      {optionsSidebarState === "done" && (
        <div className="p-6 space-y-4">
          <div className="flex flex-col items-center justify-center min-h-[200px] space-y-4">
            <p className="text-zinc-300 text-center">
              Scan has run successfully. You can now chat with your scan results.
            </p>
            <Button
              variant="ghost"
              size="sm"
              onClick={() => router.push(`/${team_id}/ai_bom/${scan_id}/results?origin=chat`)}
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
            {error_message ?? "An error occurred during the scan. Please try again."}
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
            onClick={() => {
              const validation = validateScanInputs();
              if (!validation.valid) {
                toast.error(validation.message);
                return;
              }
              reinitializeScanMutation.mutate();
            }}
            disabled={reinitializeScanMutation.isPending}
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
