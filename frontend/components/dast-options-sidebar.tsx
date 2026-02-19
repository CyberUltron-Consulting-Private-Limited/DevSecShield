"use client";

import { useEffect, useState } from "react";
import { Button } from "@/components/ui/button";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Separator } from "@/components/ui/separator";
import {
  Accordion,
  AccordionContent,
  AccordionItem,
  AccordionTrigger,
} from "@/components/ui/accordion";
import { Input } from "@/components/ui/input";
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
  Info,
} from "lucide-react";
import { useMutation, useQueryClient, UseQueryResult } from "@tanstack/react-query";
import {
  DASTScanResponse,
  estimateCreditsForScan,
  startDASTScan,
  getDASTExportResults,
  reinitializeDASTScan,
  StartDASTScanData,
  AuthRequirements,
} from "@/utils/backend_api";
import { toast } from "sonner";
import { useRouter } from "next/navigation";
import { handleApiError } from "@/utils/error-handler";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";

type UrlPatternMode = "none" | "include" | "exclude";

function buildAuthRequirements(
  xpathUsername: string,
  xpathPassword: string,
  username: string,
  password: string,
  xpathSubmit: string
): AuthRequirements {
  return {
    xpath_of_username_field: xpathUsername.trim(),
    xpath_of_password_field: xpathPassword.trim(),
    username: username.trim(),
    password: password.trim(),
    xpath_of_submit_button: xpathSubmit.trim(),
  };
}

function isAuthComplete(
  xpathUsername: string,
  xpathPassword: string,
  username: string,
  password: string,
  xpathSubmit: string
): boolean {
  return (
    Boolean(xpathUsername?.trim()) &&
    Boolean(xpathPassword?.trim()) &&
    Boolean(username?.trim()) &&
    Boolean(password?.trim()) &&
    Boolean(xpathSubmit?.trim())
  );
}

function buildStartDASTPayload(
  targetUrl: string,
  scanSpeed: "fast" | "medium" | "slow",
  maxUrls: number,
  auth: AuthRequirements,
  additionalUrls: string[],
  patternMode: UrlPatternMode,
  patternList: string[]
): StartDASTScanData {
  const payload: StartDASTScanData = {
    target_url: targetUrl.trim(),
    auth,
    scan_speed: scanSpeed,
    max_urls: typeof maxUrls === "number" && maxUrls >= 1 ? maxUrls : 100,
  };
  if (additionalUrls.length > 0) {
    payload.additional_urls_to_scan = additionalUrls.map((u) => u.trim()).filter(Boolean);
  }
  if (patternMode === "include" && patternList.length > 0) {
    payload.include_url_patterns = patternList.map((p) => p.trim()).filter(Boolean);
  }
  if (patternMode === "exclude" && patternList.length > 0) {
    payload.exclude_url_patterns = patternList.map((p) => p.trim()).filter(Boolean);
  }
  return payload;
}

export function DASTOptionsSidebar({
  team_id,
  scan_id,
  query,
}: {
  team_id: number;
  scan_id: number;
  query: UseQueryResult<DASTScanResponse>;
}) {
  const [targetUrl, setTargetUrl] = useState("");
  const [scanSpeed, setScanSpeed] = useState<"fast" | "medium" | "slow">("medium");
  const [maxUrls, setMaxUrls] = useState(100);
  const [xpathUsername, setXpathUsername] = useState("");
  const [xpathPassword, setXpathPassword] = useState("");
  const [authUsername, setAuthUsername] = useState("");
  const [authPassword, setAuthPassword] = useState("");
  const [xpathSubmit, setXpathSubmit] = useState("");
  const [additionalUrls, setAdditionalUrls] = useState<string[]>([]);
  const [additionalUrlInput, setAdditionalUrlInput] = useState("");
  const [urlPatternMode, setUrlPatternMode] = useState<UrlPatternMode>("none");
  const [urlPatterns, setUrlPatterns] = useState<string[]>([]);
  const [urlPatternInput, setUrlPatternInput] = useState("");

  const [optionsSidebarState, setOptionsSidebarState] = useState<
    "ready" | "scanning" | "error" | "done"
  >("ready");
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [estimatedCredits, setEstimatedCredits] = useState<number | null>(null);
  const [estimationProcessDone, setEstimationProcessDone] = useState(false);
  const [infoDialogOpen, setInfoDialogOpen] = useState(false);

  /** Validate required inputs before estimate/start. Target URL and all auth fields are required. */
  const validateScanInputs = (): { valid: true } | { valid: false; message: string } => {
    if (!targetUrl?.trim()) {
      return { valid: false, message: "Target URL is required." };
    }
    if (!isAuthComplete(xpathUsername, xpathPassword, authUsername, authPassword, xpathSubmit)) {
      return {
        valid: false,
        message: "Authentication is required: fill all auth fields (XPaths, username, password, submit button).",
      };
    }
    return { valid: true };
  };

  const scanInputsValid = validateScanInputs().valid;

  const buildDastPayloadString = (): string =>
    JSON.stringify({ dast: getPayload() });

  const estimateCreditsMutation = useMutation({
    mutationFn: () =>
      estimateCreditsForScan(team_id, "dast", scan_id, buildDastPayloadString(), null),
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

  const handleStartScan = ({
    team_id: tid,
    scan_id: sid,
    dast,
  }: {
    team_id: number;
    scan_id: number;
    dast: StartDASTScanData;
  }) => {
    setOptionsSidebarState("scanning");
    return startDASTScan({ team_id: tid, scan_id: sid, dast });
  };

  const queryClient = useQueryClient();
  const router = useRouter();

  const startScanMutation = useMutation({
    mutationFn: handleStartScan,
    onSuccess: () => {
      setEstimatedCredits(null);
      setEstimationProcessDone(false);
      setOptionsSidebarState("scanning");
      queryClient.invalidateQueries({
        queryKey: ["dast-scan", team_id, scan_id],
      });
    },
    onError: (err) => {
      setErrorMessage(handleApiError(err).message);
      setOptionsSidebarState("error");
    },
  });

  /** Reset estimation when key scan inputs change so user must re-run estimate for new config. */
  useEffect(() => {
    setEstimationProcessDone(false);
    setEstimatedCredits(null);
  }, [
    targetUrl,
    scanSpeed,
    maxUrls,
    xpathUsername,
    xpathPassword,
    authUsername,
    authPassword,
    xpathSubmit,
    additionalUrls,
    urlPatternMode,
    urlPatterns,
  ]);

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
      setOptionsSidebarState("error");
    }
    if (query.data?.scan_status === "not_started" || !query.data?.scan_status) {
      setOptionsSidebarState("ready");
      setErrorMessage(null);
    }
  }, [query.data?.scan_status]);

  const exportMutation = useMutation({
    mutationFn: ([tid, sid]: [number, number]) => getDASTExportResults(tid, sid),
    onSuccess: (data) => {
      const blob = new Blob([data], { type: "application/pdf" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `${query.data?.title}_scan_report.pdf`;
      a.click();
      setOptionsSidebarState("done");
    },
    onError: () => {
      setOptionsSidebarState("error");
    },
  });

  const handleReinitializeScan = ({
    team_id: tid,
    scan_id: sid,
    dast,
  }: {
    team_id: number;
    scan_id: number;
    dast: StartDASTScanData;
  }) => {
    setOptionsSidebarState("ready");
    return reinitializeDASTScan({ team_id: tid, scan_id: sid, dast });
  };

  const reinitializeScanMutation = useMutation({
    mutationFn: handleReinitializeScan,
    onSuccess: () => {
      setOptionsSidebarState("scanning");
      queryClient.invalidateQueries({
        queryKey: ["dast-scan", team_id, scan_id],
      });
    },
    onError: () => {
      setOptionsSidebarState("error");
    },
  });

  const addAdditionalUrl = () => {
    if (additionalUrlInput.trim()) {
      setAdditionalUrls([...additionalUrls, additionalUrlInput.trim()]);
      setAdditionalUrlInput("");
    }
  };

  const removeAdditionalUrl = (index: number) => {
    setAdditionalUrls(additionalUrls.filter((_, i) => i !== index));
  };

  const addUrlPattern = () => {
    if (urlPatternInput.trim()) {
      setUrlPatterns([...urlPatterns, urlPatternInput.trim()]);
      setUrlPatternInput("");
    }
  };

  const removeUrlPattern = (index: number) => {
    setUrlPatterns(urlPatterns.filter((_, i) => i !== index));
  };

  const getPayload = (): StartDASTScanData =>
    buildStartDASTPayload(
      targetUrl,
      scanSpeed,
      maxUrls,
      buildAuthRequirements(xpathUsername, xpathPassword, authUsername, authPassword, xpathSubmit),
      additionalUrls,
      urlPatternMode,
      urlPatterns
    );

  const handleEstimateCredits = () => {
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
    startScanMutation.mutate({
      team_id,
      scan_id,
      dast: getPayload(),
    });
  };

  return (
    <ScrollArea className="w-80 h-screen bg-zinc-900 dark:bg-zinc-950 border-l border-zinc-800 overflow-hidden">
      <div className="p-6">
        <h2 className="text-xl font-bold text-white mb-2">DAST Options</h2>
        <p className="text-sm text-zinc-400">
          Configure your Dynamic Application Security Testing options.
        </p>
      </div>

      <Separator className="bg-zinc-800" />

      {optionsSidebarState === "ready" && (
        <>
          <div
            className="p-6 w-full max-w-full overflow-hidden box-border"
            style={{
              width: "100%",
              maxWidth: "320px",
              boxSizing: "border-box",
              overflowX: "hidden",
            }}
          >
            <div className="mb-6 w-full space-y-4">
              <div className="space-y-2 w-full">
                <Label htmlFor="target-url" className="text-zinc-300">
                  Target URL <span className="text-red-500">*</span>
                </Label>
                <Input
                  id="target-url"
                  placeholder="https://example.com"
                  className="bg-zinc-800 border-zinc-700 text-white placeholder:text-zinc-500 w-full"
                  value={targetUrl}
                  onChange={(e) => setTargetUrl(e.target.value)}
                />
              </div>

              <div className="space-y-2 w-full">
                <Label htmlFor="scan-speed" className="text-zinc-300">
                  Scan speed
                </Label>
                <Select
                  value={scanSpeed}
                  onValueChange={(v: "fast" | "medium" | "slow") => setScanSpeed(v)}
                >
                  <SelectTrigger
                    id="scan-speed"
                    className="w-full bg-zinc-800 border-zinc-700 text-white cursor-pointer"
                  >
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent className="bg-zinc-800 border-zinc-700 w-[280px]">
                    <SelectItem
                      value="fast"
                      className="text-white hover:bg-zinc-700 cursor-pointer"
                    >
                      Fast
                    </SelectItem>
                    <SelectItem
                      value="medium"
                      className="text-white hover:bg-zinc-700 cursor-pointer"
                    >
                      Medium
                    </SelectItem>
                    <SelectItem
                      value="slow"
                      className="text-white hover:bg-zinc-700 cursor-pointer"
                    >
                      Slow
                    </SelectItem>
                  </SelectContent>
                </Select>
              </div>

              <div className="space-y-2 w-full">
                <Label htmlFor="max-urls" className="text-zinc-300">
                  Max URLs
                </Label>
                <Input
                  id="max-urls"
                  type="number"
                  min={1}
                  placeholder="100"
                  className="bg-zinc-800 border-zinc-700 text-white placeholder:text-zinc-500 w-full"
                  value={maxUrls}
                  onChange={(e) => setMaxUrls(Math.max(1, parseInt(e.target.value, 10) || 100))}
                />
              </div>

              <Accordion type="single" collapsible className="w-full">
                <AccordionItem value="auth" className="border-zinc-800">
                  <AccordionTrigger className="text-zinc-300 hover:text-white cursor-pointer text-sm">
                    Authentication <span className="text-red-500">*</span>
                  </AccordionTrigger>
                  <AccordionContent className="pt-4 space-y-4 w-full">
                    <div className="space-y-2">
                      <Label htmlFor="xpath-username" className="text-zinc-300">
                        XPath of username field <span className="text-red-500">*</span>
                      </Label>
                      <Input
                        id="xpath-username"
                        placeholder="//input[@name='username']"
                        className="bg-zinc-800 border-zinc-700 text-white placeholder:text-zinc-500 w-full"
                        value={xpathUsername}
                        onChange={(e) => setXpathUsername(e.target.value)}
                      />
                    </div>
                    <div className="space-y-2">
                      <Label htmlFor="xpath-password" className="text-zinc-300">
                        XPath of password field <span className="text-red-500">*</span>
                      </Label>
                      <Input
                        id="xpath-password"
                        placeholder="//input[@name='password']"
                        className="bg-zinc-800 border-zinc-700 text-white placeholder:text-zinc-500 w-full"
                        value={xpathPassword}
                        onChange={(e) => setXpathPassword(e.target.value)}
                      />
                    </div>
                    <div className="space-y-2">
                      <Label htmlFor="auth-username" className="text-zinc-300">
                        Username <span className="text-red-500">*</span>
                      </Label>
                      <Input
                        id="auth-username"
                        placeholder="user@example.com"
                        className="bg-zinc-800 border-zinc-700 text-white placeholder:text-zinc-500 w-full"
                        value={authUsername}
                        onChange={(e) => setAuthUsername(e.target.value)}
                      />
                    </div>
                    <div className="space-y-2">
                      <Label htmlFor="auth-password" className="text-zinc-300">
                        Password <span className="text-red-500">*</span>
                      </Label>
                      <Input
                        id="auth-password"
                        type="password"
                        placeholder="••••••••"
                        className="bg-zinc-800 border-zinc-700 text-white placeholder:text-zinc-500 w-full"
                        value={authPassword}
                        onChange={(e) => setAuthPassword(e.target.value)}
                      />
                    </div>
                    <div className="space-y-2">
                      <Label htmlFor="xpath-submit" className="text-zinc-300">
                        XPath of submit button <span className="text-red-500">*</span>
                      </Label>
                      <Input
                        id="xpath-submit"
                        placeholder="//button[@type='submit']"
                        className="bg-zinc-800 border-zinc-700 text-white placeholder:text-zinc-500 w-full"
                        value={xpathSubmit}
                        onChange={(e) => setXpathSubmit(e.target.value)}
                      />
                    </div>
                  </AccordionContent>
                </AccordionItem>
              </Accordion>

              <div className="space-y-2 w-full">
                <Label className="text-zinc-300">Additional URLs to scan</Label>
                <div className="flex gap-2 w-full">
                  <Input
                    placeholder="https://example.com/path"
                    className="bg-zinc-800 border-zinc-700 text-white placeholder:text-zinc-500 flex-1 min-w-0"
                    value={additionalUrlInput}
                    onChange={(e) => setAdditionalUrlInput(e.target.value)}
                    onKeyDown={(e) => {
                      if (e.key === "Enter") {
                        e.preventDefault();
                        addAdditionalUrl();
                      }
                    }}
                  />
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={addAdditionalUrl}
                    className="bg-zinc-800 hover:bg-zinc-700 text-white cursor-pointer shrink-0"
                  >
                    Add
                  </Button>
                </div>
                {additionalUrls.length > 0 && (
                  <div className="space-y-1 mt-2">
                    {additionalUrls.map((url, index) => (
                      <div
                        key={index}
                        className="flex items-center gap-2 bg-zinc-800 rounded p-2"
                      >
                        <span className="text-xs text-zinc-300 flex-1 truncate">{url}</span>
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => removeAdditionalUrl(index)}
                          className="text-red-400 hover:text-red-300 cursor-pointer shrink-0 w-6 h-6 p-0"
                        >
                          ×
                        </Button>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              <div className="space-y-2 w-full">
                <div className="flex flex-row items-center gap-2">
                  <Label className="text-zinc-300">URL patterns</Label>
                  <Dialog open={infoDialogOpen} onOpenChange={setInfoDialogOpen}>
                    <DialogTrigger asChild>
                      <Button
                        variant="ghost"
                        size="sm"
                        className="h-5 w-5 p-0 text-zinc-400 hover:text-zinc-300 hover:bg-zinc-800 cursor-pointer"
                      >
                        <Info className="h-4 w-4" />
                      </Button>
                    </DialogTrigger>
                    <DialogContent className="bg-zinc-900 border-zinc-700 text-white max-w-md">
                      <DialogHeader>
                        <DialogTitle className="text-white">URL patterns</DialogTitle>
                        <DialogDescription className="text-zinc-400">
                          Use either include or exclude patterns, not both. Include: only URLs
                          matching these patterns are scanned. Exclude: URLs matching these
                          patterns are skipped.
                        </DialogDescription>
                      </DialogHeader>
                    </DialogContent>
                  </Dialog>
                </div>
                <Select
                  value={urlPatternMode}
                  onValueChange={(v: UrlPatternMode) => setUrlPatternMode(v)}
                >
                  <SelectTrigger className="w-full bg-zinc-800 border-zinc-700 text-white cursor-pointer">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent className="bg-zinc-800 border-zinc-700 w-[280px]">
                    <SelectItem
                      value="none"
                      className="text-white hover:bg-zinc-700 cursor-pointer"
                    >
                      None
                    </SelectItem>
                    <SelectItem
                      value="include"
                      className="text-white hover:bg-zinc-700 cursor-pointer"
                    >
                      Include URLs matching patterns
                    </SelectItem>
                    <SelectItem
                      value="exclude"
                      className="text-white hover:bg-zinc-700 cursor-pointer"
                    >
                      Exclude URLs matching patterns
                    </SelectItem>
                  </SelectContent>
                </Select>
                {(urlPatternMode === "include" || urlPatternMode === "exclude") && (
                  <>
                    <div className="flex gap-2 w-full mt-2">
                      <Input
                        placeholder="/api/.* or path pattern"
                        className="bg-zinc-800 border-zinc-700 text-white placeholder:text-zinc-500 flex-1 min-w-0"
                        value={urlPatternInput}
                        onChange={(e) => setUrlPatternInput(e.target.value)}
                        onKeyDown={(e) => {
                          if (e.key === "Enter") {
                            e.preventDefault();
                            addUrlPattern();
                          }
                        }}
                      />
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={addUrlPattern}
                        className="bg-zinc-800 hover:bg-zinc-700 text-white cursor-pointer shrink-0"
                      >
                        Add
                      </Button>
                    </div>
                    {urlPatterns.length > 0 && (
                      <div className="space-y-1 mt-2">
                        {urlPatterns.map((pattern, index) => (
                          <div
                            key={index}
                            className="flex items-center gap-2 bg-zinc-800 rounded p-2"
                          >
                            <span className="text-xs text-zinc-300 flex-1 truncate">
                              {pattern}
                            </span>
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => removeUrlPattern(index)}
                              className="text-red-400 hover:text-red-300 cursor-pointer shrink-0 w-6 h-6 p-0"
                            >
                              ×
                            </Button>
                          </div>
                        ))}
                      </div>
                    )}
                  </>
                )}
              </div>
            </div>
          </div>

          <Separator className="bg-zinc-800" />

          {/* Estimate scan credits */}
          <div className="p-6">
            <h3 className="text-sm font-semibold text-zinc-200 mb-2">Estimate scan credits</h3>
            <Button
              variant="ghost"
              size="sm"
              onClick={handleEstimateCredits}
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
                Credit estimation failed due to invalid inputs. Check your target URL and options.
              </p>
            ) : (
              <p className="text-sm text-zinc-500">
                Run estimate above to enable starting the scan.
              </p>
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
              Scan has run successfully on the target{" "}
              <span className="text-blue-500 mx-3 text-xs p-1 bg-zinc-800 rounded-md">
                {(query.data?.scan_metadata as { target_url?: string } | null)?.target_url ?? "N/A"}
              </span>
              You can now chat with your scan results
            </p>
            <Button
              variant="ghost"
              size="sm"
              onClick={() => {
                router.push(`/${team_id}/dast/${scan_id}/results?origin=chat`);
              }}
              className="w-full h-8 px-2 bg-blue-600 hover:bg-blue-700 text-white cursor-pointer hover:text-white"
            >
              <Eye className="size-4" />
              <span className="ml-1">View Results</span>
            </Button>
            <Button
              variant="ghost"
              size="sm"
              onClick={() => {
                exportMutation.mutate([team_id, scan_id]);
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
            onClick={() => {
              const validation = validateScanInputs();
              if (!validation.valid) {
                toast.error(validation.message);
                return;
              }
              reinitializeScanMutation.mutate({
                team_id,
                scan_id,
                dast: getPayload(),
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
    </ScrollArea>
  );
}
