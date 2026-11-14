"use client";

import { useEffect, useState } from "react";
import { Button } from "@/components/ui/button";
import { ScrollArea } from "@/components/ui/scroll-area";
import { ScanInputHint } from "@/components/scan-input-hint";
import { Separator } from "@/components/ui/separator";
import {
  Accordion,
  AccordionContent,
  AccordionItem,
  AccordionTrigger,
} from "@/components/ui/accordion";
import { Input } from "@/components/ui/input";
import { FieldLabel, InfoTip } from "@/components/ui/info-tip";
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
import { toast } from "@/utils/toast";
import { useRouter } from "next/navigation";
import { handleApiError } from "@/utils/error-handler";
import { scanFailureMessage } from "@/utils/scanFailure";
import { stateAfterError } from "@/utils/scanErrorRecovery";
import { DAST_RERUN_NOTE, readDastRerun } from "@/utils/dastRerun";
import { DastRunAgainButton } from "@/components/scan-run-again";
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
  loginUrl: string,
  xpathUsername: string,
  xpathPassword: string,
  username: string,
  password: string,
  xpathSubmit: string
): AuthRequirements {
  return {
    login_url: loginUrl.trim(),
    xpath_of_username_field: xpathUsername.trim(),
    xpath_of_password_field: xpathPassword.trim(),
    username: username.trim(),
    password: password.trim(),
    xpath_of_submit_button: xpathSubmit.trim(),
  };
}

function isAuthComplete(
  loginUrl: string,
  xpathUsername: string,
  xpathPassword: string,
  username: string,
  password: string,
  xpathSubmit: string
): boolean {
  return (
    Boolean(loginUrl?.trim()) &&
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
  const [loginUrl, setLoginUrl] = useState("");
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
  const [rerunPrefilled, setRerunPrefilled] = useState(false);

  // A scan opened by "Run again" on a failed DAST scan: its settings, except the login password (never stored).
  useEffect(() => {
    const p = Number.isFinite(scan_id) ? readDastRerun(scan_id) : null;
    if (!p) return;
    // eslint-disable-next-line react-hooks/set-state-in-effect -- one read of sessionStorage after mount (none during SSR)
    if (p.target_url) setTargetUrl(p.target_url);
    if (p.scan_speed) setScanSpeed(p.scan_speed);
    if (p.max_urls) setMaxUrls(p.max_urls);
    setAdditionalUrls(p.additional_urls ?? []);
    setUrlPatternMode(p.pattern_mode ?? "none");
    setUrlPatterns(p.patterns ?? []);
    setLoginUrl(p.login_url ?? "");
    setXpathUsername(p.xpath_username ?? "");
    setXpathPassword(p.xpath_password ?? "");
    setAuthUsername(p.username ?? "");
    setXpathSubmit(p.xpath_submit ?? "");
    setRerunPrefilled(true);
  }, [scan_id]);

  /** Validate required inputs before estimate/start. Target URL and all auth fields are required. */
  const validateScanInputs = (): { valid: true } | { valid: false; message: string } => {
    if (!targetUrl?.trim()) {
      return { valid: false, message: "Target URL is required." };
    }
    if (!isAuthComplete(loginUrl, xpathUsername, xpathPassword, authUsername, authPassword, xpathSubmit)) {
      return {
        valid: false,
        message: "Authentication is required: fill login URL and all auth fields (XPaths, username, password, submit button).",
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
        toast.error("These settings cannot be scanned. Check them and estimate again.");
      }
    },
    onError: (err) => {
      // A refused estimate (private target, bad URL) is said under the button and the form keeps what was typed:
      // the error view's "Try Again" reloads the page and cleared the target and every authentication field.
      setErrorMessage(handleApiError(err).message);
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
      // The scan was refused before it started: back to the filled-in form with the reason, as for the estimate.
      setErrorMessage(handleApiError(err).message);
      setOptionsSidebarState("ready");
    },
  });

  /** Reset estimation when key scan inputs change so user must re-run estimate for new config. */
  useEffect(() => {
    setEstimationProcessDone(false);
    setEstimatedCredits(null);
    setErrorMessage(null);
  }, [
    targetUrl,
    scanSpeed,
    maxUrls,
    loginUrl,
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
    onError: (err) => {
      setErrorMessage(handleApiError(err).message);
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
    onError: (err) => {
      setErrorMessage(handleApiError(err).message);
      setOptionsSidebarState("error");
    },
  });

  // Why a failed scan failed, in the worker's words (scan.info.error); before, only "An error occurred during the scan".
  const failureMessage = query.data?.scan_status === "failure" ? scanFailureMessage(query.data) : null;

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
      buildAuthRequirements(loginUrl, xpathUsername, xpathPassword, authUsername, authPassword, xpathSubmit),
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
    <ScrollArea className="w-full md:w-80 shrink-0 md:h-screen bg-zinc-900 dark:bg-zinc-950 border-t md:border-t-0 md:border-l border-zinc-800 overflow-hidden">
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
              {rerunPrefilled && (
                <div className="rounded-md border border-blue-500/40 bg-blue-500/10 p-3 text-xs text-blue-200" role="status" data-testid="scan-rerun-notice">
                  <p>{DAST_RERUN_NOTE}</p>
                </div>
              )}
              <div className="space-y-2 w-full">
                <FieldLabel htmlFor="target-url" infoId="dast.cfg.target_url" labelClassName="text-zinc-300" required>
                  Target URL
                </FieldLabel>
                <Input
                  id="target-url"
                  placeholder="https://example.com"
                  className="bg-zinc-800 border-zinc-700 text-white placeholder:text-zinc-500 w-full"
                  value={targetUrl}
                  onChange={(e) => setTargetUrl(e.target.value)}
                />
              </div>

              <div className="space-y-2 w-full">
                <FieldLabel htmlFor="scan-speed" infoId="dast.cfg.speed" labelClassName="text-zinc-300">
                  Scan speed
                </FieldLabel>
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
                      Fast — 10 URLs in parallel, every check
                    </SelectItem>
                    <SelectItem
                      value="medium"
                      className="text-white hover:bg-zinc-700 cursor-pointer"
                    >
                      Medium — 5 URLs in parallel, every check
                    </SelectItem>
                    <SelectItem
                      value="slow"
                      className="text-white hover:bg-zinc-700 cursor-pointer"
                    >
                      Slow — 2 URLs in parallel, every check
                    </SelectItem>
                  </SelectContent>
                </Select>
                <p className="text-xs text-zinc-500">
                  All speeds run headers, Nuclei, page analysis, XSS, and SQLi. XSS and SQLi always run at the same time. Worker counts: slow 2, medium 5, fast 10.
                </p>
              </div>

              <div className="space-y-2 w-full">
                <FieldLabel htmlFor="max-urls" infoId="dast.cfg.max_urls" labelClassName="text-zinc-300">
                  Max URLs
                </FieldLabel>
                <Input
                  id="max-urls"
                  type="number"
                  min={1}
                  placeholder="100"
                  className="bg-zinc-800 border-zinc-700 text-white placeholder:text-zinc-500 w-full"
                  value={maxUrls ? maxUrls : ""}
                  onChange={(e) => setMaxUrls(Math.max(1, parseInt(e.target.value, 10)))}
                />
              </div>

              <Accordion type="single" collapsible className="w-full">
                <AccordionItem value="auth" className="border-zinc-800">
                  <div className="flex items-center gap-1">
                    <AccordionTrigger className="text-zinc-300 hover:text-white cursor-pointer text-sm flex-1 [&[data-state=open]>svg]:rotate-180">
                      Authentication <span className="text-red-500">*</span>
                    </AccordionTrigger>
                    <InfoTip id="dast.cfg.auth" />
                    <Dialog>
                      <DialogTrigger asChild>
                        <button
                          type="button"
                          className="p-1.5 rounded-md text-zinc-400 hover:text-zinc-200 hover:bg-zinc-700 cursor-pointer focus:outline-none focus:ring-2 focus:ring-zinc-500"
                          aria-label="How to get XPath for authentication fields"
                        >
                          <Info className="h-4 w-4" />
                        </button>
                      </DialogTrigger>
                      <DialogContent className="bg-zinc-900 border-zinc-700 text-zinc-200 max-w-md">
                        <DialogHeader>
                          <DialogTitle className="text-white">How to copy the full XPath</DialogTitle>
                          <DialogDescription className="text-zinc-400">
                            Use these steps to get the XPath for the username field, password field, and submit button on your login page.
                          </DialogDescription>
                        </DialogHeader>
                        <ol className="list-decimal list-inside space-y-2 text-sm text-zinc-300">
                          <li>Open your application’s <strong>login page</strong> in the browser.</li>
                          <li><strong>Right-click</strong> on the element (e.g. username input, password input, or submit button).</li>
                          <li>Choose <strong>Inspect</strong> (or Inspect Element) to open DevTools.</li>
                          <li>In the Elements panel, the corresponding HTML node will be highlighted. <strong>Right-click</strong> that node.</li>
                          <li>Select <strong>Copy</strong> → <strong>Copy full XPath</strong> (or “Copy XPath” depending on the browser).</li>
                          <li>Paste the copied XPath into the matching field above (username field, password field, or submit button).</li>
                        </ol>
                        <p className="text-xs text-zinc-500 mt-2">
                          You need the full XPath for: username input, password input, and the login/submit button.
                        </p>
                      </DialogContent>
                    </Dialog>
                  </div>
                  <AccordionContent className="pt-4 space-y-4 w-full">
                    <div className="space-y-2">
                      <FieldLabel htmlFor="login-url" infoId="dast.cfg.login_url" labelClassName="text-zinc-300" required>
                        Login URL
                      </FieldLabel>
                      <Input
                        id="login-url"
                        type="url"
                        placeholder="https://example.com/login"
                        className="bg-zinc-800 border-zinc-700 text-white placeholder:text-zinc-500 w-full"
                        value={loginUrl}
                        onChange={(e) => setLoginUrl(e.target.value)}
                      />
                    </div>
                    <div className="space-y-2">
                      <FieldLabel htmlFor="xpath-username" infoId="dast.cfg.xpath_user" labelClassName="text-zinc-300" required>
                        XPath of username field
                      </FieldLabel>
                      <Input
                        id="xpath-username"
                        placeholder="//input[@name='username']"
                        className="bg-zinc-800 border-zinc-700 text-white placeholder:text-zinc-500 w-full"
                        value={xpathUsername}
                        onChange={(e) => setXpathUsername(e.target.value)}
                      />
                    </div>
                    <div className="space-y-2">
                      <FieldLabel htmlFor="xpath-password" infoId="dast.cfg.xpath_pass" labelClassName="text-zinc-300" required>
                        XPath of password field
                      </FieldLabel>
                      <Input
                        id="xpath-password"
                        placeholder="//input[@name='password']"
                        className="bg-zinc-800 border-zinc-700 text-white placeholder:text-zinc-500 w-full"
                        value={xpathPassword}
                        onChange={(e) => setXpathPassword(e.target.value)}
                      />
                    </div>
                    <div className="space-y-2">
                      <FieldLabel htmlFor="auth-username" infoId="dast.cfg.username" labelClassName="text-zinc-300" required>
                        Username
                      </FieldLabel>
                      <Input
                        id="auth-username"
                        placeholder="user@example.com"
                        className="bg-zinc-800 border-zinc-700 text-white placeholder:text-zinc-500 w-full"
                        value={authUsername}
                        onChange={(e) => setAuthUsername(e.target.value)}
                      />
                    </div>
                    <div className="space-y-2">
                      <FieldLabel htmlFor="auth-password" infoId="dast.cfg.password" labelClassName="text-zinc-300" required>
                        Password
                      </FieldLabel>
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
                      <FieldLabel htmlFor="xpath-submit" infoId="dast.cfg.xpath_submit" labelClassName="text-zinc-300" required>
                        XPath of submit button
                      </FieldLabel>
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
                <FieldLabel htmlFor="dast-additional-url" infoId="dast.cfg.additional_urls" labelClassName="text-zinc-300">Additional URLs to scan</FieldLabel>
                <div className="flex gap-2 w-full">
                  <Input
                    id="dast-additional-url"
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
                          aria-label={`Remove ${url}`}
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
                  <FieldLabel htmlFor="dast-url-pattern-mode" infoId="dast.cfg.url_patterns" labelClassName="text-zinc-300">URL patterns</FieldLabel>
                  <Dialog open={infoDialogOpen} onOpenChange={setInfoDialogOpen}>
                    <DialogTrigger asChild>
                      <Button
                        variant="ghost"
                        size="sm"
                        className="h-5 w-5 p-0 text-zinc-400 hover:text-zinc-300 hover:bg-zinc-800 cursor-pointer"
                        aria-label="About URL patterns"
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
                  {/* infotip-shared: the URL patterns label above carries the tip (its help dialog sits between) */}
                  <SelectTrigger id="dast-url-pattern-mode" className="w-full bg-zinc-800 border-zinc-700 text-white cursor-pointer">
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
                      {/* infotip-shared: a pattern of the URL patterns field above */}
                      <Input
                        aria-label="URL pattern"
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
                              aria-label={`Remove pattern ${pattern}`}
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
            <h3 className="text-sm font-semibold text-zinc-200 mb-2 flex items-center gap-1">Estimate scan credits <InfoTip id="dast.cfg.estimate" /></h3>
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
            <ScanInputHint validation={validateScanInputs()} />
            {errorMessage && optionsSidebarState === "ready" && (
              <p role="alert" data-testid="dast-request-error" className="text-xs text-red-400 mt-2">
                {errorMessage}
              </p>
            )}
            {displayCredits != null && (
              <p className="text-sm text-zinc-300 mt-3">
                {creditsInvalid ? (
                  <span className="font-semibold text-amber-400">These settings cannot be scanned. Check them and estimate again.</span>
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
          <p role="alert" data-testid="scan-error-message" className="text-red-400 text-center">
            {failureMessage ?? errorMessage ?? "The request failed. Try again."}
          </p>
          {query.data?.scan_status === "failure" ? (
            <DastRunAgainButton teamId={team_id} scan={query.data} />
          ) : (
            <Button
              variant="ghost"
              size="sm"
              data-testid="scan-try-again"
              onClick={() => {
                // back to the view that matches the scan, with every field still filled in (no page reload)
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
