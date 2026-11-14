"use client";

import { Dispatch, SetStateAction, useEffect, useState } from "react";
import { Button } from "@/components/ui/button";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Separator } from "@/components/ui/separator";
import { FieldLabel, InfoTip } from "@/components/ui/info-tip";
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
  SCASBOMConversationResponse,
  getSBOMExportResults,
  reinitializeSBOMScanWithPayload,
  estimateCreditsForScan,
  startScan,
  type StartScanPayload,
  type RepoMode,
} from "@/utils/backend_api";
import { toast } from "@/utils/toast";
import { useParams, useRouter } from "next/navigation";
import { handleApiError } from "@/utils/error-handler";
import { stateAfterError } from "@/utils/scanErrorRecovery";
import { ScanRequestError } from "@/components/scan-request-error";
import { scanFailureMessage } from "@/utils/scanFailure";
import { RerunNotice, RunAgainButton, useRerunPrefill } from "@/components/scan-run-again";
import { CancelledScanPanel, CancelScanButton } from "@/components/scan-cancel";

export type Mode = RepoMode | "unknown";

export function SCASBOMOptionsSidebar({
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
  query: UseQueryResult<SCASBOMConversationResponse>;
  mode: Mode;
  setMode: Dispatch<SetStateAction<Mode>>;
  repo_url: string;
  setRepoUrl: Dispatch<SetStateAction<string>>;
  PAT: string;
  setPAT: Dispatch<SetStateAction<string>>;
  branch: string;
  setBranch: Dispatch<SetStateAction<string>>;
}) {
  useEffect(() => {
    setMode(mode);
    setRepoUrl(repo_url);
    setPAT(PAT);
    setBranch(branch);
  }, [mode, repo_url, PAT, branch]);

  const [optionsSidebarState, setOptionsSidebarState] = useState<"ready" | "scanning" | "error" | "done" | "cancelled">("ready");
  const [error_message, setErrorMessage] = useState<string | null>(null);
  const [estimatedCredits, setEstimatedCredits] = useState<number | null>(null);
  /** Reset on mount so user must run estimate every time they come to this page (like SAST). */
  const [estimationProcessDone, setEstimationProcessDone] = useState(false);
  const [uploaded_file, setUploadedFile] = useState<File | null>(null);
  const [uploaded_sbom_file, setUploadedSbomFile] = useState<File | null>(null);

  const zip_file_used = uploaded_file !== null;
  const sbom_file_used = uploaded_sbom_file !== null;

  const queryClient = useQueryClient();
  const router = useRouter();
  const params = useParams();
  const team_id = parseInt(params?.team_id as string, 10);
  const scan_id = parseInt(params?.scan_id as string, 10);

  const validateScanInputs = (): { valid: true } | { valid: false; message: string } => {
    if (uploaded_file) return { valid: true };
    if (uploaded_sbom_file) return { valid: true };
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
      sbom_sca: {
        repo_context:
          zip_file_used || sbom_file_used
            ? null
            : { mode: mode as RepoMode, repo_url: repo_url.trim(), PAT: (PAT || "").trim(), branch: (branch?.trim() || "main") },
        zip_file_used,
        sbom_file_used,
      },
    };
    return JSON.stringify(payload);
  };

  /** File to send with estimate/start: either zip or SBOM file, not both. */
  const getUploadedFileForApi = (): File | undefined => {
    if (zip_file_used && uploaded_file) return uploaded_file;
    if (sbom_file_used && uploaded_sbom_file) return uploaded_sbom_file;
    return undefined;
  };

  // a scan opened by "Run again" on a failed scan: its settings, except an uploaded file and an access token
  const rerun = useRerunPrefill("sbom_sca", scan_id, (p) => {
    if (p.repo_url) setRepoUrl(p.repo_url);
    if (p.mode) setMode(p.mode);
    if (p.branch) setBranch(p.branch);
  });

  const estimateCreditsMutation = useMutation({
    mutationFn: () =>
      estimateCreditsForScan(team_id, "sbom_sca", scan_id, buildStartScanPayloadString(), getUploadedFileForApi()),
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
    mutationFn: () =>
      startScan(team_id, "sbom_sca", scan_id, buildStartScanPayloadString(), getUploadedFileForApi()),
    onSuccess: () => {
      setEstimatedCredits(null);
      setEstimationProcessDone(false);
      setOptionsSidebarState("scanning");
      queryClient.invalidateQueries({ queryKey: ["sbom_sca-conversation-data", team_id, scan_id] });
    },
    onError: (err) => {
      setErrorMessage(handleApiError(err).message);
      setOptionsSidebarState("ready");
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

  /** Reset estimation when inputs change; also run on mount so estimation must be run every time user comes to page. */
  useEffect(() => {
    setEstimationProcessDone(false);
    setEstimatedCredits(null);
    setErrorMessage(null);
  }, [mode, repo_url, PAT, uploaded_file, uploaded_sbom_file]);

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
    if (query.data?.scan_status === "cancelled") {
      setOptionsSidebarState("cancelled");
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
    mutationFn: () => getSBOMExportResults(team_id, scan_id),
    onSuccess: (data) => {
      const blob = new Blob([data], { type: "application/pdf" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `${query.data?.title ?? "sbom_sca"}_scan_report.pdf`;
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
      reinitializeSBOMScanWithPayload(
        team_id,
        scan_id,
        buildStartScanPayloadString(),
        getUploadedFileForApi() ?? undefined
      ),
    onSuccess: () => {
      setOptionsSidebarState("scanning");
      queryClient.invalidateQueries({ queryKey: ["sbom_sca-conversation-data", team_id, scan_id] });
    },
    onError: (err) => {
      setErrorMessage(handleApiError(err).message);
      setOptionsSidebarState("error");
    },
  });

  const onZipChange: Dispatch<SetStateAction<File | null>> = (value) => {
    setUploadedFile((prev) => {
      const next = typeof value === "function" ? value(prev) : value;
      if (next) setUploadedSbomFile(null);
      return next;
    });
  };

  const onSbomFileChange = (file: File | null) => {
    setUploadedSbomFile(file);
    if (file) {
      setUploadedFile(null);
      setRepoUrl("");
      setPAT("");
      setMode("unknown");
    }
  };

  /** When user enters repo URL or PAT, clear SBOM file so only one source is used. */
  const setRepoUrlAndClearSbom: Dispatch<SetStateAction<string>> = (value) => {
    setRepoUrl(value);
    setUploadedSbomFile(null);
  };
  const setPATAndClearSbom: Dispatch<SetStateAction<string>> = (value) => {
    setPAT(value);
    setUploadedSbomFile(null);
  };

  return (
    <ScrollArea className="w-full md:w-96 shrink-0 md:h-screen bg-neutral-900/70 border-t md:border-t-0 md:border-l border-zinc-800">
      <div className="p-6">
        <div className="flex items-center gap-2 flex-row mb-2">
          <h2 className="text-xl font-bold text-white">SCA + SBOM Configuration</h2>
          <ScanLine className="h-5 w-5 text-blue-400 shrink-0" />
        </div>
        <p className="text-sm text-zinc-400">
          Choose one: connect a repository (or upload zip) or upload an SBOM file.
        </p>
      </div>

      <Separator className="bg-zinc-800" />

      {optionsSidebarState === "ready" && (
        <>
          <div className="p-6 pb-8">
            {rerun && <div className="mb-4"><RerunNotice prefill={rerun} /></div>}
            <Accordion type="single" collapsible className="w-full">
              <AccordionItem value="repository" className="border-zinc-700 border rounded-lg px-3 data-[state=open]:border-blue-500/50">
                <AccordionTrigger className="text-zinc-300 hover:text-white cursor-pointer py-4 hover:no-underline [&[data-state=open]>svg]:rotate-180">
                  <div className="flex items-center gap-2">
                    <FolderGit2 className="h-4 w-4 text-zinc-400 shrink-0" />
                    <span>Analyze Repository</span>
                  </div>
                </AccordionTrigger>
                <AccordionContent className="pb-5 pt-0">
                  <p className="text-xs text-zinc-500 mb-3 flex items-center gap-1">
                    Builds the SBOM from your code, then checks every package for known vulnerabilities.
                    <InfoTip id="sbom.cfg.repository" />
                  </p>
                  <RepositoryCard
                    uploadedFile={uploaded_file}
                    setUploadedFile={onZipChange}
                    repoUrl={repo_url}
                    setRepoUrl={setRepoUrlAndClearSbom}
                    pat={PAT}
                    setPat={setPATAndClearSbom}
                    branch={branch}
                    setBranch={setBranch}
                    mode={mode}
                    setMode={setMode}
                  />
                </AccordionContent>
              </AccordionItem>
              <AccordionItem value="sbom" className="border-zinc-700 border rounded-lg px-3 mt-2 data-[state=open]:border-blue-500/50">
                <AccordionTrigger className="text-zinc-300 hover:text-white cursor-pointer py-4 hover:no-underline [&[data-state=open]>svg]:rotate-180">
                  <div className="flex items-center gap-2">
                    <FileJson className="h-4 w-4 text-zinc-400 shrink-0" />
                    <span>Analyze SBOM file</span>
                    {uploaded_sbom_file && (
                      <span className="text-xs text-zinc-500 font-normal">({uploaded_sbom_file.name})</span>
                    )}
                  </div>
                </AccordionTrigger>
                <AccordionContent className="pb-6 pt-0">
                  <p className="text-xs text-zinc-500 mb-3">
                    Upload an existing SBOM file (e.g. JSON). This will clear any repository or zip selection.
                  </p>
                  <FieldLabel htmlFor="sbom-file-upload" infoId="sbom.cfg.sbom_file" labelClassName="text-zinc-300 text-sm">SBOM file</FieldLabel>
                  <Input
                    id="sbom-file-upload"
                    type="file"
                    accept=".json,application/json"
                    className="bg-zinc-800 h-fit p-2 border-zinc-700 text-white file:mr-2 file:rounded file:border-0 file:bg-blue-600 file:cursor-pointer file:px-3 file:py-1 file:text-sm file:text-white mt-1"
                    onChange={(e) => onSbomFileChange(e.target.files?.[0] ?? null)}
                  />
                  {uploaded_sbom_file && (
                    <p className="text-xs text-zinc-500 mt-2 mb-2">{uploaded_sbom_file.name}</p>
                  )}
                </AccordionContent>
              </AccordionItem>
            </Accordion>
          </div>

          <Separator className="bg-zinc-800" />

          <div className="p-6">
            <h3 className="text-sm font-semibold text-zinc-200 mb-2 flex items-center gap-1">Estimate scan credits <InfoTip id="sbom.cfg.estimate" /></h3>
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
            {optionsSidebarState === "ready" && <ScanRequestError message={error_message} />}
            {displayCredits != null && (
              <p className="text-sm text-zinc-300 mt-3">
                {creditsInvalid ? (
                  <span className="font-semibold text-amber-400">These settings cannot be scanned. Check them and estimate again.</span>
                ) : (
                  <>Credits required: <span className="font-semibold text-blue-400">{displayCredits}</span></>
                )}
              </p>
            )}
          </div>

          <Separator className="bg-zinc-800" />

          <div className="p-6">
            <h3 className="text-sm font-semibold text-zinc-200 mb-2 flex items-center gap-1">Run scan <InfoTip id="scan.cfg.run" /></h3>
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
              <p className="text-sm text-amber-400">Credit Estimation failed due to invalid inputs from user . Ensure there are documents that match the include/exclude patterns.</p>
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
          <div className="w-full mt-4">
            <CancelScanButton type="sbom_sca" teamId={team_id} scanId={scan_id} scan={query.data} />
          </div>
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
              onClick={() => router.push(`/${team_id}/sbom_sca/${scan_id}/results?origin=chat`)}
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

      {optionsSidebarState === "cancelled" && (
        <CancelledScanPanel type="sbom_sca" teamId={team_id} scan={query.data} />
      )}

      {optionsSidebarState === "error" && (
        <div className="p-6 flex flex-col items-center justify-center min-h-[200px] space-y-4">
          <p className="text-red-400 text-center">
            {query.data?.scan_status === "failure" ? scanFailureMessage(query.data) : (error_message ?? "The request failed. Try again.")}
          </p>
          {query.data?.scan_status === "failure" ? (
            <RunAgainButton type="sbom_sca" teamId={team_id} scan={query.data} />
          ) : (
            <Button
              variant="ghost"
              size="sm"
              data-testid="scan-try-again"
              onClick={() => {
                // back to the view that matches the scan, with the form still filled in (no reload)
                setErrorMessage(null);
                setOptionsSidebarState(stateAfterError(query.data?.scan_status, true));
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
