"use client";

import { Dispatch, SetStateAction, useEffect, useState } from "react";
import { Button } from "@/components/ui/button";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Separator } from "@/components/ui/separator";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  ScanIcon,
  Download,
  Loader2,
  Eye,
  Filter,
  ScanLine,
  Plus,
  Trash2,
} from "lucide-react";
import { PathArraysInput } from "@/components/path-arrays-input";
import { RepositoryCard } from "@/components/repository-card";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { useMutation, useQueryClient, UseQueryResult } from "@tanstack/react-query";
import {
  IACConversationResponse,
  getIACExportResults,
  reinitializeIACScanWithPayload,
  estimateCreditsForScan,
  startScan,
  type StartScanPayload,
  type RepoMode,
  type IACContextMode,
  type IACContextSchema,
  type IACEnvironment,
} from "@/utils/backend_api";
import { toast } from "@/utils/toast";
import { useParams, useRouter } from "next/navigation";
import { handleApiError } from "@/utils/error-handler";
import { refreshCreditBalance } from "@/utils/creditBalance";
import { stateAfterError } from "@/utils/scanErrorRecovery";
import { ScanRequestError } from "@/components/scan-request-error";
import { scanFailureMessage } from "@/utils/scanFailure";
import { RerunNotice, RunAgainButton, useRerunPrefill } from "@/components/scan-run-again";
import { CancelledScanPanel, CancelScanButton } from "@/components/scan-cancel";

export type Mode = RepoMode | "unknown";

const IAC_MODES: { value: IACContextMode; label: string }[] = [
  { value: "terraform", label: "Terraform" },
  { value: "k8s", label: "Kubernetes" },
  { value: "pulumi", label: "Pulumi" },
  { value: "ansible", label: "Ansible" },
  { value: "helm", label: "Helm" },
  { value: "aws_cloudformation", label: "AWS CloudFormation" },
  { value: "aws_cdk", label: "AWS CDK" },
];

const IAC_ENVIRONMENTS: { value: IACEnvironment; label: string }[] = [
  { value: "development", label: "Development" },
  { value: "staging", label: "Staging" },
  { value: "production", label: "Production" },
];

export interface IACContextEntry {
  id: string;
  mode: IACContextMode;
  include_path_arrays: string[][];
}

export function IACOptionsSidebar({
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
  query: UseQueryResult<IACConversationResponse>;
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
  const [estimationProcessDone, setEstimationProcessDone] = useState(false);
  const [uploaded_file, setUploadedFile] = useState<File | null>(null);
  const [iac_contexts, setIacContexts] = useState<IACContextEntry[]>([
    { id: crypto.randomUUID(), mode: "terraform", include_path_arrays: [] },
  ]);
  const [environment, setEnvironment] = useState<IACEnvironment>("development");

  const zip_file_used = uploaded_file !== null;

  const queryClient = useQueryClient();
  const router = useRouter();
  const params = useParams();
  const team_id = parseInt(params?.team_id as string, 10);
  const scan_id = parseInt(params?.scan_id as string, 10);

  const validateScanInputs = (): { valid: true } | { valid: false; message: string } => {
    if (iac_contexts.length === 0) {
      return { valid: false, message: "Add at least one IAC context (e.g. Terraform, K8s)." };
    }
    if (uploaded_file) {
      return { valid: true };
    }
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
    if (!validation.valid) {
      throw new Error(validation.message);
    }
    const contexts: IACContextSchema[] = iac_contexts.map((c) => ({
      mode: c.mode,
      include_path_arrays: c.mode === "terraform"
        ? []
        : c.include_path_arrays
            .map((p) => p.map((s) => s.trim()).filter(Boolean))
            .filter((p) => p.length > 0),
    }));
    const payload: StartScanPayload = {
      iac: {
        repo_context: zip_file_used ? null : { mode: mode as RepoMode, repo_url: repo_url.trim(), PAT: (PAT || "").trim(), branch: (branch?.trim() || "main") },
        zip_file_used,
        iac_contexts: contexts,
        environment,
      },
    };
    return JSON.stringify(payload);
  };

  const INVALID_CREDITS_MESSAGE =
    "Invalid inputs from user. Make sure that there are documents that match the patterns included/excluded";

  // a scan opened by "Run again" on a failed scan: its settings, except an uploaded file and an access token
  const rerun = useRerunPrefill("iac", scan_id, (p) => {
    if (p.repo_url) setRepoUrl(p.repo_url);
    if (p.mode) setMode(p.mode);
    if (p.branch) setBranch(p.branch);
    const env = p.options.environment;
    if (env === "production" || env === "staging" || env === "development") setEnvironment(env);
    const contexts = p.options.iac_contexts;
    if (Array.isArray(contexts) && contexts.length) {
      setIacContexts(contexts.filter((c) => c && typeof c === "object").map((c) => ({
        id: crypto.randomUUID(),
        mode: String((c as { mode?: unknown }).mode ?? "terraform") as IACContextMode,
        include_path_arrays: Array.isArray((c as { include_path_arrays?: unknown }).include_path_arrays)
          ? (c as { include_path_arrays: unknown[] }).include_path_arrays.filter(Array.isArray).map((a) => (a as unknown[]).map(String))
          : [],
      })));
    }
  });

  const estimateCreditsMutation = useMutation({
    mutationFn: () =>
      estimateCreditsForScan(team_id, "iac", scan_id, buildStartScanPayloadString(), uploaded_file ?? undefined),
    onSuccess: (data) => {
      setEstimatedCredits(data.credits_required);
      setEstimationProcessDone(true);
      if (data.credits_required !== -1) {
        toast.success(`This scan will use ${data.credits_required} credits`);
      } else {
        toast.error(INVALID_CREDITS_MESSAGE);
      }
    },
    onError: (err) => {
      setErrorMessage(handleApiError(err).message);
    },
  });

  const startScanMutation = useMutation({
    mutationFn: () =>
      startScan(team_id, "iac", scan_id, buildStartScanPayloadString(), uploaded_file ?? undefined),
    onSuccess: () => {
      setEstimatedCredits(null);
      setEstimationProcessDone(false);
      setOptionsSidebarState("scanning");
      queryClient.invalidateQueries({ queryKey: ["iac-conversation-data", team_id, scan_id] });
    },
    onError: (err) => {
      setErrorMessage(handleApiError(err).message);
      setOptionsSidebarState("ready");
    },
    // the start charges credits: the balance in the app sidebar shows it without a reload (#13)
    onSettled: () => {
      refreshCreditBalance(queryClient);
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
    setErrorMessage(null);
  }, [mode, repo_url, PAT, uploaded_file, iac_contexts, environment]);

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
    mutationFn: () => getIACExportResults(team_id, scan_id),
    onSuccess: (data) => {
      const blob = new Blob([data], { type: "application/pdf" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `${query.data?.title ?? "iac"}_scan_report.pdf`;
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
      reinitializeIACScanWithPayload(team_id, scan_id, buildStartScanPayloadString(), uploaded_file ?? undefined),
    onSuccess: () => {
      setOptionsSidebarState("scanning");
      queryClient.invalidateQueries({ queryKey: ["iac-conversation-data", team_id, scan_id] });
    },
    onError: (err) => {
      setErrorMessage(handleApiError(err).message);
      setOptionsSidebarState("error");
    },
  });

  const usedModes = new Set(iac_contexts.map((c) => c.mode));

  const addContext = () => {
    const firstUnused = IAC_MODES.find((m) => !usedModes.has(m.value));
    if (!firstUnused) {
      toast.warning("Each IAC context type can only be added once. All types are already in use.");
      return;
    }
    setIacContexts((prev) => [
      ...prev,
      { id: crypto.randomUUID(), mode: firstUnused.value, include_path_arrays: [] },
    ]);
  };

  const removeContext = (id: string) => {
    setIacContexts((prev) => (prev.length <= 1 ? prev : prev.filter((c) => c.id !== id)));
  };

  const updateContext = (id: string, updates: Partial<Omit<IACContextEntry, "id">>) => {
    setIacContexts((prev) =>
      prev.map((c) => (c.id === id ? { ...c, ...updates } : c))
    );
  };

  const setContextMode = (ctxId: string, newMode: IACContextMode) => {
    const alreadyUsed = iac_contexts.some((c) => c.id !== ctxId && c.mode === newMode);
    if (alreadyUsed) {
      const label = IAC_MODES.find((m) => m.value === newMode)?.label ?? newMode;
      toast.warning(`${label} is already added. Each IAC context type can only be used once.`);
      return;
    }
    updateContext(ctxId, { mode: newMode });
  };

  return (
    <ScrollArea className="w-full md:w-96 shrink-0 md:h-screen bg-neutral-900/70 border-t md:border-t-0 md:border-l border-zinc-800">
      <div className="p-6">
        <div className="flex items-center gap-2 flex-row mb-2">
          <h2 className="text-xl font-bold text-white">IAC Configuration</h2>
          <ScanLine className="h-5 w-5 text-blue-400 shrink-0" />
        </div>
        <p className="text-sm text-zinc-400">
          Configure scan options to run an Infrastructure as Code scan.
        </p>
      </div>

      <Separator className="bg-zinc-800" />

      {optionsSidebarState === "ready" && (
        <>
          <div className="p-6 space-y-4">
            <RerunNotice prefill={rerun} />
            <RepositoryCard
              uploadedFile={uploaded_file}
              setUploadedFile={setUploadedFile}
              repoUrl={repo_url}
              setRepoUrl={setRepoUrl}
              pat={PAT}
              setPat={setPAT}
              branch={branch}
              setBranch={setBranch}
              mode={mode}
              setMode={setMode}
            />

            {/* Environment */}
            <Card className="border-zinc-700 bg-zinc-800/50 py-4 shadow-none">
              <CardHeader className="pb-2 px-4">
                <CardTitle className="text-sm font-medium text-zinc-300">Environment</CardTitle>
                <CardDescription className="text-zinc-500 text-xs">
                  Select the target environment for this IAC scan.
                </CardDescription>
              </CardHeader>
              <CardContent className="px-4 pt-0">
                <Select value={environment} onValueChange={(v) => setEnvironment(v as IACEnvironment)}>
                  <SelectTrigger className="h-8 bg-zinc-800 border-zinc-700 text-white text-xs cursor-pointer">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent className="bg-zinc-800 border-zinc-700">
                    {IAC_ENVIRONMENTS.map((e) => (
                      <SelectItem key={e.value} value={e.value} className="text-white hover:bg-zinc-700 cursor-pointer text-xs">
                        {e.label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </CardContent>
            </Card>

            {/* IAC contexts */}
            <Card className="border-zinc-700 bg-zinc-800/50 py-4 shadow-none">
              <CardHeader className="pb-2 px-4">
                <CardTitle className="text-sm font-medium text-zinc-300 flex items-center gap-2">
                  <Filter className="h-4 w-4 text-zinc-400 shrink-0" />
                  IAC contexts
                </CardTitle>
                <CardDescription className="text-zinc-500 text-xs">
                  Add one or more contexts (Terraform, K8s, etc.). For non-Terraform contexts, use include path patterns to specify where to find these files in your repo.
                </CardDescription>
              </CardHeader>
              <CardContent className="px-4 pt-0 space-y-4">
                {iac_contexts.map((ctx) => (
                  <div
                    key={ctx.id}
                    className="rounded-md border border-zinc-700 bg-zinc-800/30 p-3 space-y-3"
                  >
                    <div className="flex items-center justify-between gap-2">
                      <Label className="text-zinc-300 text-xs">Context type</Label>
                      <div className="flex items-center gap-1">
                        <Select
                          value={ctx.mode}
                          onValueChange={(v) => setContextMode(ctx.id, v as IACContextMode)}
                        >
                          <SelectTrigger className="h-8 bg-zinc-800 border-zinc-700 text-white text-xs cursor-pointer w-[140px]">
                            <SelectValue />
                          </SelectTrigger>
                          <SelectContent className="bg-zinc-800 border-zinc-700">
                            {IAC_MODES.map((m) => (
                              <SelectItem key={m.value} value={m.value} className="text-white hover:bg-zinc-700 cursor-pointer text-xs">
                                {m.label}
                              </SelectItem>
                            ))}
                          </SelectContent>
                        </Select>
                        {iac_contexts.length > 1 && (
                          <Button
                            type="button"
                            variant="ghost"
                            size="icon"
                            className="h-8 w-8 text-red-400 hover:text-red-300 hover:bg-red-950/30 cursor-pointer"
                            onClick={() => removeContext(ctx.id)}
                            aria-label="Remove this IaC context"
                          >
                            <Trash2 className="h-4 w-4" />
                          </Button>
                        )}
                      </div>
                    </div>
                    {ctx.mode !== "terraform" && (
                      <>
                        <p className="text-xs text-zinc-500">
                          Use the field below to specify where to find these files in your repository.
                        </p>
                        <PathArraysInput
                          label="Include path patterns"
                          value={ctx.include_path_arrays}
                          onChange={(v) => updateContext(ctx.id, { include_path_arrays: v })}
                          segmentPlaceholder="ex: **/*.yaml or charts/"
                        />
                      </>
                    )}
                  </div>
                ))}
                <Button
                  type="button"
                  variant="ghost"
                  size="sm"
                  disabled={usedModes.size >= IAC_MODES.length}
                  className="w-full h-8 border border-dashed border-zinc-600 text-zinc-400 hover:bg-zinc-700 hover:text-white cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed"
                  onClick={addContext}
                >
                  <Plus className="h-4 w-4 mr-2" />
                  Add context
                </Button>
              </CardContent>
            </Card>
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
                <><Loader2 className="size-4 animate-spin mr-2" />Estimating...</>
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
                    <><Loader2 className="size-4 animate-spin mr-2" />Starting...</>
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
          <p className="text-zinc-300 text-center">
            Scan has started, this might take a while
          </p>
          <div className="w-full mt-4">
            <CancelScanButton type="iac" teamId={team_id} scanId={scan_id} scan={query.data} />
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
              onClick={() => router.push(`/${team_id}/iac/${scan_id}/results?origin=chat`)}
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
        <CancelledScanPanel type="iac" teamId={team_id} scan={query.data} />
      )}

      {optionsSidebarState === "error" && (
        <div className="p-6 flex flex-col items-center justify-center min-h-[200px] space-y-4">
          <p className="text-red-400 text-center">
            {query.data?.scan_status === "failure" ? scanFailureMessage(query.data) : (error_message ?? "The request failed. Try again.")}
          </p>
          {query.data?.scan_status === "failure" ? (
            <RunAgainButton type="iac" teamId={team_id} scan={query.data} />
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
