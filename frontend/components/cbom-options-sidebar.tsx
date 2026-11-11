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
import Link from "next/link";
import { LinkedSourcesRun, SourcesAccordionItems, SourcesBreakdown, useSourcesOverview } from "@/components/cbom/sources/SidebarSources";
import { cbomSourcesKeys } from "@/components/cbom/sources/keys";
import { newRequestId } from "@/components/cbom/sources/logic";
import { useMutation, useQueryClient, UseQueryResult } from "@tanstack/react-query";
import {
  CBOMConversationResponse,
  getCBOMExportResults,
  reinitializeCBOMScanWithPayload,
  estimateCreditsForScan,
  startScan,
  estimateCbomSources,
  startCbomRun,
  type StartScanPayload,
  type RepoMode,
  type CbomEstimate,
  type CbomInclude,
  type CbomIncludeKey,
} from "@/utils/backend_api";
import { toast } from "sonner";
import { useParams, useRouter } from "next/navigation";
import { handleApiError } from "@/utils/error-handler";
import { stateAfterError } from "@/utils/scanErrorRecovery";
import { ScanRequestError } from "@/components/scan-request-error";
import { scanFailureMessage } from "@/utils/scanFailure";
import { RerunNotice, RunAgainButton, useRerunPrefill } from "@/components/scan-run-again";
import { CancelledScanPanel, CancelScanButton } from "@/components/scan-cancel";
import { importHeadline, importNoteLines, importReportHasNews } from "@/components/cbom/importNotes";
import type { CbomImportReport } from "@/utils/api/cbom_outputs";
import { estimateChangedOf } from "@/utils/estimateChanged";

export type Mode = RepoMode | "unknown";

export function CBOMOptionsSidebar({
  query,
  mode,
  setMode,
  repo_url,
  setRepoUrl,
  PAT,
  setPAT,
  branch,
  setBranch,
  scan_binaries,
  setScanBinaries,
}: {
  query: UseQueryResult<CBOMConversationResponse>;
  mode: Mode;
  setMode: Dispatch<SetStateAction<Mode>>;
  repo_url: string;
  setRepoUrl: Dispatch<SetStateAction<string>>;
  PAT: string;
  setPAT: Dispatch<SetStateAction<string>>;
  branch: string;
  setBranch: Dispatch<SetStateAction<string>>;
  scan_binaries: boolean;
  setScanBinaries: Dispatch<SetStateAction<boolean>>;
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
  // the least a code scan costs (1 credit for a repository or zip, decision D3); 0 for an uploaded CBOM file
  const [minimumCredits, setMinimumCredits] = useState<number | null>(null);
  const [estimationProcessDone, setEstimationProcessDone] = useState(false);
  const [uploaded_file, setUploadedFile] = useState<File | null>(null);
  const [uploaded_cbom_file, setUploadedCbomFile] = useState<File | null>(null);
  // Off by default: vendor/, dist/, build/ and node_modules/ are third-party or build output.
  const [include_vendored, setIncludeVendored] = useState(false);
  // Off by default (repository scans): a depth-1 clone; on, a capped clone whose history is read for keys.
  const [scan_history, setScanHistory] = useState(false);

  // CBOM Sources (servers, clusters, network) included in this scan: off by default, opt-in per group.
  const [sourceInclude, setSourceInclude] = useState<CbomInclude>({});
  const [socAck, setSocAck] = useState(false);
  const [sourcesEstimate, setSourcesEstimate] = useState<{ key: string; estimate: CbomEstimate; requestId: string } | null>(null);
  const includedGroups = (Object.keys(sourceInclude) as CbomIncludeKey[]).filter((k) => sourceInclude[k]);
  const anySourceIncluded = includedGroups.length > 0;

  const zip_file_used = uploaded_file !== null;
  const cbom_file_used = uploaded_cbom_file !== null;

  const queryClient = useQueryClient();
  const router = useRouter();
  const params = useParams();
  const team_id = parseInt(params?.team_id as string, 10);
  const scan_id = parseInt(params?.scan_id as string, 10);
  const sourcesOverview = useSourcesOverview(team_id);
  // The sources estimate belongs to one exact set of inputs; any change makes it stale (derived, no effect).
  const estimateKey = JSON.stringify([mode, repo_url, PAT, branch, uploaded_file?.name ?? null, uploaded_cbom_file?.name ?? null, scan_binaries, include_vendored, includedGroups]);
  const currentSourcesEstimate = sourcesEstimate && sourcesEstimate.key === estimateKey ? sourcesEstimate : null;
  const toggleSource = (key: CbomIncludeKey, on: boolean) => setSourceInclude((prev) => ({ ...prev, [key]: on }));

  const validateScanInputs = (): { valid: true } | { valid: false; message: string } => {
    if (uploaded_file) return { valid: true };
    if (uploaded_cbom_file) return { valid: true };
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
      cbom: {
        repo_context:
          zip_file_used || cbom_file_used
            ? null
            : { mode: mode as RepoMode, repo_url: repo_url.trim(), PAT: (PAT || "").trim(), branch: (branch?.trim() || "main") },
        zip_file_used,
        cbom_file_used,
        scan_binaries,
        // a code-scan option only: an uploaded CBOM file has no directories to read
        include_vendored: cbom_file_used ? false : include_vendored,
        // a repository-scan option only: an uploaded archive's own .git history is read when it is complete
        scan_history: zip_file_used || cbom_file_used ? false : scan_history,
      },
    };
    return JSON.stringify(payload);
  };

  const getUploadedFileForApi = (): File | undefined => {
    if (zip_file_used && uploaded_file) return uploaded_file;
    if (cbom_file_used && uploaded_cbom_file) return uploaded_cbom_file;
    return undefined;
  };

  // a scan opened by "Run again" on a failed scan: its settings, except an uploaded file and an access token
  const rerun = useRerunPrefill("cbom", scan_id, (p) => {
    if (p.repo_url) setRepoUrl(p.repo_url);
    if (p.mode) setMode(p.mode);
    if (p.branch) setBranch(p.branch);
    if (typeof p.options.scan_binaries === "boolean") setScanBinaries(p.options.scan_binaries);
    if (typeof p.options.include_vendored === "boolean") setIncludeVendored(p.options.include_vendored);
    if (typeof p.options.scan_history === "boolean") setScanHistory(p.options.scan_history);
  });

  const estimateCreditsMutation = useMutation({
    mutationFn: async () => {
      const key = estimateKey;
      const [code, sources] = await Promise.all([
        estimateCreditsForScan(team_id, "cbom", scan_id, buildStartScanPayloadString(), getUploadedFileForApi()),
        anySourceIncluded ? estimateCbomSources(team_id, sourceInclude) : Promise.resolve(null),
      ]);
      return { code, sources, key };
    },
    onSuccess: ({ code, sources, key }) => {
      const data = code;
      setEstimatedCredits(data.credits_required);
      setMinimumCredits(data.minimum_credits ?? null);
      setEstimationProcessDone(true);
      setSourcesEstimate(sources ? { key, estimate: sources, requestId: newRequestId() } : null);
      if (data.credits_required !== -1) {
        const total = Math.round((data.credits_required + (sources?.total_credits ?? 0)) * 100) / 100;
        toast.success(`This scan will use ${total} credits`);
      } else {
        toast.error("Invalid Input from user");
      }
    },
    onError: (err) => {
      setErrorMessage(handleApiError(err).message);
    },
  });

  const startSourcesRunMutation = useMutation({
    mutationFn: (snapshot: { estimate: CbomEstimate; requestId: string }) =>
      startCbomRun(team_id, {
        include: sourceInclude,
        scan_id,
        client_request_id: snapshot.requestId,
        expected_credits: snapshot.estimate.total_credits,
        soc_ack: socAck,
      }),
    onSettled: () => {
      queryClient.invalidateQueries({ queryKey: cbomSourcesKeys.all(team_id) });
      queryClient.invalidateQueries({ queryKey: ["teams"] });
    },
  });

  const startScanMutation = useMutation({
    mutationFn: () =>
      startScan(team_id, "cbom", scan_id, buildStartScanPayloadString(), getUploadedFileForApi()),
    onSuccess: () => {
      const snapshot = currentSourcesEstimate;
      setEstimatedCredits(null);
      setEstimationProcessDone(false);
      setOptionsSidebarState("scanning");
      queryClient.invalidateQueries({ queryKey: ["cbom-conversation-data", team_id, scan_id] });
      // the credits are charged at start: the team balance in the app sidebar must show it now, not after a reload
      queryClient.invalidateQueries({ queryKey: ["teams"] });
      // The code scan is running; queue the included sources as a linked run (its failure only toasts).
      if (snapshot && snapshot.estimate.items.some((i) => i.status === "queued")) {
        startSourcesRunMutation.mutate(snapshot);
      }
    },
    onError: (err) => {
      // The input or the pricing changed since the estimate: nothing was charged. Show the new price here; the
      // next "Start scan" charges exactly that.
      const changed = estimateChangedOf(err);
      if (changed) {
        setEstimatedCredits(changed.credits_required);
        setMinimumCredits(changed.minimum_credits);
        toast.warning(changed.detail);
        return;
      }
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
    if (anySourceIncluded && !currentSourcesEstimate) {
      toast.error("Sources changed since the estimate; run the estimate again.");
      return;
    }
    if (sourceInclude.network && !socAck) {
      toast.error("Confirm that your SOC has agreed the network ranges and scan windows.");
      return;
    }
    const balance = currentSourcesEstimate?.estimate.credit_balance;
    if (balance != null && estimatedCredits != null && estimatedCredits >= 0 &&
        estimatedCredits + (currentSourcesEstimate?.estimate.total_credits ?? 0) > balance) {
      toast.error(`Not enough credits: this scan needs ${Math.round((estimatedCredits + (currentSourcesEstimate?.estimate.total_credits ?? 0)) * 100) / 100}, the team has ${balance}.`);
      return;
    }
    startScanMutation.mutate();
  };

  const scanInputsValid = validateScanInputs().valid;

  useEffect(() => {
    setEstimationProcessDone(false);
    setEstimatedCredits(null);
    setErrorMessage(null);
  }, [mode, repo_url, PAT, branch, uploaded_file, uploaded_cbom_file, scan_binaries, include_vendored, scan_history]);

  const creditsInvalid = estimatedCredits === -1;
  const displayCredits =
    estimatedCredits != null && !creditsInvalid
      ? Math.round((estimatedCredits + (currentSourcesEstimate?.estimate.total_credits ?? 0)) * 100) / 100
      : estimatedCredits;
  const canRunScan = estimationProcessDone && !creditsInvalid && (!anySourceIncluded || !!currentSourcesEstimate);

  const failureMessage = scanFailureMessage(query.data);
  // an uploaded CBOM file's import report (null for code scans): shown right here when the run finishes
  const importReport = ((query.data?.scan_metadata as Record<string, unknown> | undefined)?.cbom_input ?? null) as CbomImportReport | null;
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

  // A finished scan settles its credits (a failed one is refunded): refresh the team balance in the app sidebar,
  // which otherwise kept showing the balance from before the scan until a reload.
  useEffect(() => {
    if (query.data?.scan_status === "success" || query.data?.scan_status === "failure") {
      queryClient.invalidateQueries({ queryKey: ["teams"] });
    }
  }, [query.data?.scan_status, queryClient]);

  const exportMutation = useMutation({
    mutationFn: () => getCBOMExportResults(team_id, scan_id),
    onSuccess: (data) => {
      const blob = new Blob([data], { type: "application/pdf" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `${query.data?.title ?? "cbom"}_scan_report.pdf`;
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
      reinitializeCBOMScanWithPayload(
        team_id,
        scan_id,
        buildStartScanPayloadString(),
        getUploadedFileForApi() ?? undefined
      ),
    onSuccess: () => {
      setOptionsSidebarState("scanning");
      queryClient.invalidateQueries({ queryKey: ["cbom-conversation-data", team_id, scan_id] });
    },
    onError: (err) => {
      setErrorMessage(handleApiError(err).message);
      setOptionsSidebarState("error");
    },
  });

  const onZipChange: Dispatch<SetStateAction<File | null>> = (value) => {
    setUploadedFile((prev) => {
      const next = typeof value === "function" ? value(prev) : value;
      if (next) setUploadedCbomFile(null);
      return next;
    });
  };

  const onCbomFileChange = (file: File | null) => {
    setUploadedCbomFile(file);
    if (file) {
      setUploadedFile(null);
      setRepoUrl("");
      setPAT("");
      setMode("unknown");
    }
  };

  const setRepoUrlAndClearCbom: Dispatch<SetStateAction<string>> = (value) => {
    setRepoUrl(value);
    setUploadedCbomFile(null);
  };
  const setPATAndClearCbom: Dispatch<SetStateAction<string>> = (value) => {
    setPAT(value);
    setUploadedCbomFile(null);
  };

  return (
    <ScrollArea className="w-full md:w-96 shrink-0 md:h-screen bg-neutral-900/70 border-t md:border-t-0 md:border-l border-zinc-800">
      <div className="p-6">
        <div className="flex items-center gap-2 flex-row mb-2">
          <h2 className="text-xl font-bold text-white">CBOM Configuration</h2>
          <ScanLine className="h-5 w-5 text-blue-400 shrink-0" />
        </div>
        <p className="text-sm text-zinc-400">
          Analyze cryptographic assets across code, servers, clusters, cloud and network, or upload an existing CBOM file.
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
                  <RepositoryCard
                    uploadedFile={uploaded_file}
                    setUploadedFile={onZipChange}
                    repoUrl={repo_url}
                    setRepoUrl={setRepoUrlAndClearCbom}
                    pat={PAT}
                    setPat={setPATAndClearCbom}
                    branch={branch}
                    setBranch={setBranch}
                    mode={mode}
                    setMode={setMode}
                  />
                </AccordionContent>
              </AccordionItem>
              <SourcesAccordionItems
                teamId={team_id}
                overview={sourcesOverview.data}
                include={sourceInclude}
                onToggle={toggleSource}
                socAck={socAck}
                setSocAck={setSocAck}
              />
              <AccordionItem value="cbom-file" className="border-zinc-700 border rounded-lg px-3 mt-2 data-[state=open]:border-blue-500/50">
                <AccordionTrigger className="text-zinc-300 hover:text-white cursor-pointer py-4 hover:no-underline [&[data-state=open]>svg]:rotate-180">
                  <div className="flex items-center gap-2">
                    <FileJson className="h-4 w-4 text-zinc-400 shrink-0" />
                    <span>Analyze CBOM file</span>
                    {uploaded_cbom_file && (
                      <span className="text-xs text-zinc-500 font-normal">({uploaded_cbom_file.name})</span>
                    )}
                  </div>
                </AccordionTrigger>
                <AccordionContent className="pb-6 pt-0">
                  <p className="text-xs text-zinc-500 mb-3">
                    Upload an existing CycloneDX CBOM JSON file. This will clear any repository or zip selection.
                  </p>
                  <Label className="text-zinc-300 text-sm">CBOM file</Label>
                  <Input
                    type="file"
                    accept=".json,application/json"
                    className="bg-zinc-800 h-fit p-2 border-zinc-700 text-white file:mr-2 file:rounded file:border-0 file:bg-blue-600 file:cursor-pointer file:px-3 file:py-1 file:text-sm file:text-white mt-1"
                    onChange={(e) => onCbomFileChange(e.target.files?.[0] ?? null)}
                  />
                  {uploaded_cbom_file && (
                    <p className="text-xs text-zinc-500 mt-2 mb-2">{uploaded_cbom_file.name}</p>
                  )}
                </AccordionContent>
              </AccordionItem>
            </Accordion>
            {!cbom_file_used && (
              <label className="flex items-start gap-2 mt-4 text-sm text-zinc-300 cursor-pointer">
                <input
                  type="checkbox"
                  className="mt-0.5 h-4 w-4 accent-blue-600"
                  checked={include_vendored}
                  onChange={(e) => setIncludeVendored(e.target.checked)}
                />
                <span>
                  Scan vendored and build directories
                  <span className="block text-xs text-zinc-500 mt-0.5">
                    Also reads vendor/, dist/, build/ and node_modules/ (third-party code and build output). Off by default.
                  </span>
                </span>
              </label>
            )}
            {!zip_file_used && !cbom_file_used && (
              <label className="flex items-start gap-2 mt-3 text-sm text-zinc-300 cursor-pointer">
                <input
                  type="checkbox"
                  className="mt-0.5 h-4 w-4 accent-blue-600"
                  checked={scan_history}
                  onChange={(e) => setScanHistory(e.target.checked)}
                />
                <span>
                  Scan git history for keys
                  <span className="block text-xs text-zinc-500 mt-0.5">
                    Clones up to 1,000 commits of the branch and reports key and certificate files that were committed and later removed. Off by default.
                  </span>
                </span>
              </label>
            )}
            {!cbom_file_used && (
              <label className="flex items-start gap-2 mt-3 text-sm text-zinc-300 cursor-pointer">
                <input
                  type="checkbox"
                  className="mt-0.5 h-4 w-4 accent-blue-600"
                  checked={scan_binaries}
                  onChange={(e) => setScanBinaries(e.target.checked)}
                  data-testid="cbom-scan-binaries"
                />
                <span>
                  Scan binaries, container images and firmware
                  <span className="block text-xs text-zinc-500 mt-0.5">
                    Reads compiled binaries, docker save / OCI image archives and firmware images in the upload or
                    repository: linked crypto libraries, crypto constants, embedded keys and the packages inside images.
                    Adds 1 credit per 5 MB of binary content. Off by default.
                  </span>
                </span>
              </label>
            )}
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
            {optionsSidebarState === "ready" && <ScanRequestError message={error_message} />}
            {displayCredits != null && (
              <p className="text-sm text-zinc-300 mt-3">
                {creditsInvalid ? (
                  <span className="font-semibold text-amber-400">Invalid Input from user</span>
                ) : (
                  <>Credits required: <span className="font-semibold text-blue-400">{displayCredits}</span></>
                )}
              </p>
            )}
            {displayCredits != null && !creditsInvalid && (
              <SourcesBreakdown estimate={currentSourcesEstimate?.estimate ?? null} codeCredits={estimatedCredits} />
            )}
            {!cbom_file_used && (
              <p className="text-xs text-zinc-500 mt-2" data-testid="cbom-minimum-credits">
                {minimumCredits && estimatedCredits != null && estimatedCredits <= minimumCredits
                  ? `Includes the minimum charge of ${minimumCredits} credit for a code scan.`
                  : "A repository or zip code scan costs at least 1 credit (1 credit per 0.5 MB scanned)."}
                {scan_binaries && " Scanning binaries, container images and firmware adds 1 credit per 5 MB of binary content."}
                {" "}If the files or options change before you start, the scan is estimated again.
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
            <Link href={`/${team_id}/cbom/sources?tab=review`} className="inline-block mt-3 text-sm text-blue-400 hover:text-blue-300">
              Review what will be scanned
            </Link>
          </div>
        </>
      )}

      {optionsSidebarState === "scanning" && (
        <div className="p-6 flex flex-col items-center justify-center min-h-[400px]">
          <Loader2 className="h-8 w-8 text-blue-500 animate-spin mb-4" />
          <p className="text-zinc-300 text-center">Scan has started, this might take a while</p>
          <div className="w-full mt-4">
            <CancelScanButton type="cbom" teamId={team_id} scanId={scan_id} scan={query.data} />
          </div>
          <div className="w-full">
            <LinkedSourcesRun teamId={team_id} scanId={scan_id} />
          </div>
        </div>
      )}

      {optionsSidebarState === "done" && (
        <div className="p-6 space-y-4">
          <div className="flex flex-col items-center justify-center min-h-[200px] space-y-4">
            <p className="text-zinc-300 text-center">
              Scan has run successfully. Open the results to see every finding with its fix and proof.
            </p>
            {importReport && importReportHasNews(importReport) && (
              <div className="w-full rounded-md border border-amber-700/60 bg-amber-950/30 p-3 text-xs text-amber-200 space-y-1"
                role="status" data-testid="cbom-sidebar-import-notes">
                <p className="font-semibold">{importHeadline(importReport)}</p>
                <ul className="list-disc pl-4 space-y-1 break-words">
                  {importNoteLines(importReport).map((line, i) => <li key={i}>{line}</li>)}
                </ul>
              </div>
            )}
            <Button
              variant="ghost"
              size="sm"
              onClick={() => router.push(`/${team_id}/cbom/${scan_id}/results?origin=chat`)}
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
            <div className="w-full">
              <LinkedSourcesRun teamId={team_id} scanId={scan_id} />
            </div>
          </div>
        </div>
      )}

      {optionsSidebarState === "cancelled" && (
        <CancelledScanPanel type="cbom" teamId={team_id} scan={query.data} />
      )}

      {optionsSidebarState === "error" && (
        <div className="p-6 flex flex-col items-center justify-center min-h-[200px] space-y-4">
          <p className="text-red-400 text-center">
            {query.data?.scan_status === "failure" ? scanFailureMessage(query.data) : (error_message ?? "The request failed. Try again.")}
          </p>
          {query.data?.scan_status === "failure" ? (
            <RunAgainButton type="cbom" teamId={team_id} scan={query.data} />
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
