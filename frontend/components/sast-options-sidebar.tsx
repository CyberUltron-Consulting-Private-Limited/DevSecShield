"use client";

import { Dispatch, SetStateAction, useEffect, useState } from "react";
import { Button } from "@/components/ui/button";
import { ScrollArea } from "@/components/ui/scroll-area";
import { ScanInputHint } from "@/components/scan-input-hint";
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
  Code,
  ScanLine,
} from "lucide-react";
import { PathArraysInput } from "@/components/path-arrays-input";
import { RepositoryCard } from "@/components/repository-card";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { useMutation, useQueryClient, UseQueryResult } from "@tanstack/react-query";
import {
  SastConversationResponse,
  getExportResults,
  reinitializeSastScan,
  estimateCreditsForScan,
  startScan,
  type StartScanPayload,
  type SastAppLang,
  type RepoMode,
} from "@/utils/backend_api";
import { toast } from "sonner";
import { useParams, useRouter } from "next/navigation";
import { handleApiError } from "@/utils/error-handler";



const languages = [
  "c",
  "java",
  "php",
  "ruby",
  "rust",
  "swift",
  "python",
  "csharp",
  "kotlin",
  "javascript",
];

export type AppLang = SastAppLang | "unknown";
export type Mode = RepoMode | "unknown";

export function SASTOptionsSidebar({
  query,
  app_lang,
  setAppLang,
  mode,
  setMode,
  repo_url,
  setRepoUrl,
  PAT,
  setPAT,
  branch,
  setBranch,
}:{
  query: UseQueryResult<SastConversationResponse>;
  app_lang: AppLang;
  setAppLang: Dispatch<SetStateAction<AppLang>>;
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
    setAppLang(app_lang);
    setMode(mode);
    setRepoUrl(repo_url);
    setPAT(PAT);
    setBranch(branch);
  }, [app_lang, mode, repo_url, PAT, branch]);

  const [ optionsSidebarState , setOptionsSidebarState ] = useState<"ready" | "scanning" | "error" | "done" >("ready");
  const [ error_message, setErrorMessage ] = useState<string | null>(null);
  const [ estimatedCredits, setEstimatedCredits ] = useState<number | null>(null);
  /** True only after estimation has been run successfully this session; ensures user must re-estimate when they come back. */
  const [ estimationProcessDone, setEstimationProcessDone ] = useState(false);
  /** Schema: exclude_path_arrays — list[list[str]] | null */
  const [ exclude_path_arrays, setExcludePathArrays ] = useState<string[][]>([]);
  const [ uploaded_file, setUploadedFile ] = useState<File | null>(null);
  /** Derived for API: true when user provides zip file, false when using repo */
  const zip_file_used = uploaded_file !== null;

  const queryClient = useQueryClient();
  const router = useRouter();
  const params = useParams();
  const team_id = parseInt(params?.team_id as string, 10);
  const scan_id = parseInt(params?.scan_id as string, 10);

  /** Validate required inputs before estimate/start. exclude_path_arrays is optional. */
  const validateScanInputs = (): { valid: true } | { valid: false; message: string } => {
    if (app_lang === "unknown") {
      return { valid: false, message: "Please select an application language." };
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
    // Guard against pasting the repo URL into the PAT field (breaks clone URL construction).
    if (PAT?.trim() && (/:\/\//.test(PAT) || /github\.com|gitlab\.com|bitbucket\.org/i.test(PAT))) {
      return { valid: false, message: "PAT looks like a URL. Paste a token (or leave blank for public GitHub repos)." };
    }
    return { valid: true };
  };

  /** Build StartScanPayload per schema: repo_context, zip_file_used, exclude_path_arrays, app_lang. */
  const buildStartScanPayloadString = (): string => {
    const validation = validateScanInputs();
    if (!validation.valid) {
      throw new Error(validation.message);
    }
    const normalizedExclude = exclude_path_arrays
      .map((p) => p.map((s) => s.trim()).filter(Boolean))
      .filter((p) => p.length > 0);
    const payload: StartScanPayload = {
      sast: {
        repo_context: zip_file_used ? null : { mode: mode as RepoMode, repo_url: repo_url.trim(), PAT: (PAT || "").trim(), branch: (branch?.trim() || "main") },
        zip_file_used,
        exclude_path_arrays: normalizedExclude.length > 0 ? normalizedExclude : null,
        app_lang: app_lang as SastAppLang,
      },
    };
    return JSON.stringify(payload);
  };

  const estimateCreditsMutation = useMutation({
    mutationFn: () => estimateCreditsForScan(team_id, "sast", scan_id, buildStartScanPayloadString(), uploaded_file ?? undefined),
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
    mutationFn: () => startScan(team_id, "sast", scan_id, buildStartScanPayloadString(), uploaded_file ?? undefined),
    onSuccess: () => {
      setEstimatedCredits(null);
      setEstimationProcessDone(false);
      setOptionsSidebarState("scanning");
      queryClient.invalidateQueries({ queryKey: ["sast-conversation-data", team_id, scan_id] });
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

  /** Reset estimation state when key scan inputs change so user must re-run estimate for new config. */
  useEffect(() => {
    setEstimationProcessDone(false);
    setEstimatedCredits(null);
  }, [app_lang, mode, repo_url, PAT, branch, uploaded_file]);

  /** Run scan allowed only after estimation process has been run this session (credits from estimate response only). */
  const displayCredits = estimatedCredits;
  const creditsInvalid = estimatedCredits === -1;
  const canRunScan = estimationProcessDone && !creditsInvalid;

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
      const msg = (query.data?.scan_metadata as { error_message?: string } | undefined)?.error_message ?? "The scan failed.";
      setErrorMessage(msg);
      setOptionsSidebarState("error");
    }
    if (query.data?.scan_status === "unknown") {
      setOptionsSidebarState("ready");
      setErrorMessage(null);
    }
  }, [query.data?.scan_status, query.data?.scan_metadata]);



  const exportMutation = useMutation({
    mutationFn: () => getExportResults(team_id, scan_id),
    onSuccess: (data, variables , context) => {
      const blob = new Blob([data], { type: "application/pdf" });
      const url = URL.createObjectURL(blob);

      // download the pdf file
      const a = document.createElement("a");
      a.href = url;
      a.download = `${query.data?.title}_scan_report.pdf`;
      a.click();

      setOptionsSidebarState("done");
    },
    onError: (err) => {
      setErrorMessage(handleApiError(err).message);
      setOptionsSidebarState("error");
    }
  })

  const handleReinitializeScan = ({
    team_id,
    scan_id,
    repo_url,
    PAT,
    app_lang,
    mode,
    branch,
  }: {
    team_id: number;
    scan_id: number;
    repo_url: string;
    PAT: string;
    app_lang: AppLang;
    mode: Mode;
    branch?: string;
  }) => {
    setOptionsSidebarState("ready");
    setErrorMessage(null);
    if (app_lang === "unknown") {
      const msg = "Please select a language";
      toast.error(msg);
      setErrorMessage(msg);
      setOptionsSidebarState("error");
      throw new Error(msg);
    }
    if (mode === "unknown") {
      const msg = "Please select a repository platform";
      toast.error(msg);
      setErrorMessage(msg);
      setOptionsSidebarState("error");
      throw new Error(msg);
    }
    return reinitializeSastScan({
      team_id,
      scan_id,
      repo_url,
      PAT,
      app_lang,
      mode,
      branch: branch?.trim() || "main",
    });
  };

  const reinitializeScanMutation = useMutation({
    mutationFn: handleReinitializeScan,
    onSuccess: () => {
      setOptionsSidebarState("scanning");
      queryClient.invalidateQueries({ queryKey: ['sast-conversation-data', team_id, scan_id] });
    },
    onError: (err) => {
      setErrorMessage(handleApiError(err).message);
      setOptionsSidebarState("error");
    }
  });


  return (
    <ScrollArea className="w-96 h-screen bg-neutral-900/70 border-l border-zinc-800">
      <div className="p-6">
        <div className="flex items-center gap-2 flex-row mb-2">
          <h2 className="text-xl font-bold text-white">SAST Configuration</h2>
          <ScanLine className="h-5 w-5 text-blue-400 shrink-0" />
        </div>
        <p className="text-sm text-zinc-400">
          Configure scan options to run a SAST scan 
        </p>
      </div>

      <Separator className="bg-zinc-800" />

      {optionsSidebarState === "ready" && (
        <>
          <div className="p-6 space-y-4">
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

            {/* Scan scope — exclude path arrays */}
            <Card className="border-zinc-700 bg-zinc-800/50 py-4 shadow-none">
              <CardHeader className="pb-2 px-4">
                <CardTitle className="text-sm font-medium text-zinc-300 flex items-center gap-2">
                  <Filter className="h-4 w-4 text-zinc-400 shrink-0" />
                  Scan scope
                </CardTitle>
                <CardDescription className="text-zinc-500 text-xs">
                  Paths or patterns to exclude from the scan (e.g. vendor, node_modules).
                </CardDescription>
              </CardHeader>
              <CardContent className="px-4 pt-0">
                <PathArraysInput
                  label="Exclude path patterns"
                  value={exclude_path_arrays}
                  onChange={setExcludePathArrays}
                  segmentPlaceholder="ex: directory or file_name.extension"
                />
              </CardContent>
            </Card>

            {/* App language */}
            <Card className="border-zinc-700 bg-zinc-800/50 py-4 shadow-none">
              <CardHeader className="pb-2 px-4">
                <CardTitle className="text-sm font-medium text-zinc-300 flex items-center gap-2">
                  <Code className="h-4 w-4 text-zinc-400 shrink-0" />
                  App language
                </CardTitle>
                <CardDescription className="text-zinc-500 text-xs">
                  Primary language of the application being scanned (used for analysis).
                </CardDescription>
              </CardHeader>
              <CardContent className="px-4 pt-0">
                <Label htmlFor="primary-language" className="text-zinc-300 text-sm">Primary app language <span className="text-red-500">*</span></Label>
                <Select value={app_lang} onValueChange={(value) => setAppLang(value as AppLang)}>
                  <SelectTrigger
                    id="primary-language"
                    className="bg-zinc-800 border-zinc-700 text-white focus:text-white cursor-pointer mt-1"
                  >
                    {app_lang !== "unknown" ? <SelectValue /> : <span className="text-zinc-400">Select language</span>}
                  </SelectTrigger>
                  <SelectContent className="bg-zinc-800 border-zinc-700">
                    {languages.map((language) => (
                      <SelectItem key={language} value={language} className="text-white hover:bg-zinc-700 cursor-pointer">
                        {language.charAt(0).toUpperCase() + language.slice(1)}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </CardContent>
            </Card>
          </div>

          <Separator className="bg-zinc-800" />

          {/* Estimate scan credits */}
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
            <ScanInputHint validation={validateScanInputs()} />
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

          {/* Run scan — allowed only after estimation process has been run this session */}
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
              onClick={() => {
                router.push(`/${team_id}/sast/${scan_id}/results?origin=chat`);
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
            {error_message ?? "An error occurred during the scan. Please try again."}
          </p>
          <Button 
            variant="ghost" 
            size="sm"
            onClick={() => {
              // refresh the entire page to reset the state
              window.location.reload();
            }}
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
              reinitializeScanMutation.mutate({
                team_id,
                scan_id,
                repo_url,
                PAT,
                app_lang,
                mode,
                branch,
              });
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
      {/* <Button onClick={() => {
        console.log(`Refreshing conversation ${scan_id} data`);
        queryClient.invalidateQueries({ queryKey: ['sast-conversation-data', team_id, scan_id] });
      }}
      className="w-full h-8 px-2 bg-zinc-700 hover:bg-zinc-600 text-white cursor-pointer hover:text-white active:bg-zinc-600 active:text-white">
        
        Refresh
      </Button> */}
    </ScrollArea>
  );
}

