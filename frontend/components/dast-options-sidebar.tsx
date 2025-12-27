"use client";

import { Dispatch, SetStateAction, useEffect, useState } from "react";
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
import { Textarea } from "@/components/ui/textarea";
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
  Shield,
  Key,
} from "lucide-react";
import { useMutation, useQueryClient, UseQueryResult } from "@tanstack/react-query";
import { DASTConversationResponse, startDASTScan, getDASTExportResults, FormBasedDASTScanData, HeaderCookieDASTScanData } from "@/utils/backend_api";
import { toast } from "sonner";
import { useParams, useRouter } from "next/navigation";

export function DASTOptionsSidebar({
  query,
}:{
  query: UseQueryResult<DASTConversationResponse>;
}) {
  const [authMode, setAuthMode] = useState<"form_based" | "header_cookie_based">("form_based");
  
  // Form-based authentication state
  const [formTargetUrl, setFormTargetUrl] = useState("");
  const [formLoginUrl, setFormLoginUrl] = useState("");
  const [formIncludeUrls, setFormIncludeUrls] = useState<string[]>([]);
  const [formExcludeUrls, setFormExcludeUrls] = useState<string[]>([]);
  const [formIncludeUrlInput, setFormIncludeUrlInput] = useState("");
  const [formExcludeUrlInput, setFormExcludeUrlInput] = useState("");
  const [formMode, setFormMode] = useState<"St-Low-Th-High" | "API" | "API-Minimal" | "Pen Test" | "QA Standard">("Pen Test");
  const [formTimeoutMins, setFormTimeoutMins] = useState(20);
  const [formPollSeconds, setFormPollSeconds] = useState(5);
  const [formUsernameValue, setFormUsernameValue] = useState("");
  const [formPasswordValue, setFormPasswordValue] = useState("");
  const [formUsernameKey, setFormUsernameKey] = useState("username");
  const [formPasswordKey, setFormPasswordKey] = useState("password");
  const [formLoggedInRegex, setFormLoggedInRegex] = useState("");
  const [formLoggedOutRegex, setFormLoggedOutRegex] = useState("");

  // Header/Cookie-based authentication state
  const [headerTargetUrl, setHeaderTargetUrl] = useState("");
  const [headerAttackModules, setHeaderAttackModules] = useState<string[]>(["common"]);
  const [headerMaxScanTime, setHeaderMaxScanTime] = useState(60);
  const [headerUserAgent, setHeaderUserAgent] = useState("");
  const [headerHeaders, setHeaderHeaders] = useState<{ name: string; value: string }[]>([]);
  const [headerCookies, setHeaderCookies] = useState<{ name: string; value: string }[]>([]);
  const [headerScanForce, setHeaderScanForce] = useState<"paranoid" | "sneaky" | "polite" | "normal" | "aggressive" | "insane">("normal");
  const [headerExcludePatterns, setHeaderExcludePatterns] = useState<string[]>([]);

  const [optionsSidebarState, setOptionsSidebarState] = useState<"ready" | "scanning" | "error" | "done">("ready");

  const handleStartScan = ({
    conversation_id,
    auth_mode,
    form_based,
    header_cookie_based
  }: {
    conversation_id: number;
    auth_mode: "form_based" | "header_cookie_based";
    form_based?: FormBasedDASTScanData;
    header_cookie_based?: HeaderCookieDASTScanData;
  }) => {
    setOptionsSidebarState("scanning");
    return startDASTScan({
      conversation_id,
      auth_mode,
      form_based,
      header_cookie_based
    });
  };

  const queryClient = useQueryClient();
  const router = useRouter();
  const { conversation_id } = useParams();
  const startScanMutation = useMutation({
    mutationFn: handleStartScan,
    onSuccess: () => {
      setOptionsSidebarState("scanning");
      queryClient.invalidateQueries({ queryKey: ['dast-conversation-data', parseInt(conversation_id as string)] });
    },
    onError: () => {
      setOptionsSidebarState("error");
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

  // Update include URLs when target URL changes - add target URL by default
  useEffect(() => {
    if (formTargetUrl && authMode === "form_based") {
      // Check if target URL is already in include URLs
      if (!formIncludeUrls.includes(formTargetUrl)) {
        setFormIncludeUrls([formTargetUrl, ...formIncludeUrls.filter(url => url !== formTargetUrl)]);
      }
    }
  }, [formTargetUrl, authMode]);

  const exportMutation = useMutation({
    mutationFn: getDASTExportResults,
    onSuccess: (data, variables, context) => {
      const blob = new Blob([data], { type: "application/pdf" });
      const url = URL.createObjectURL(blob);

      // download the pdf file
      const a = document.createElement("a");
      a.href = url;
      a.download = `${query.data?.title}_scan_report.pdf`;
      a.click();

      setOptionsSidebarState("done");
    },
    onError: () => {
      setOptionsSidebarState("error");
    }
  });

  const addHeader = () => {
    setHeaderHeaders([...headerHeaders, { name: "", value: "" }]);
  };

  const removeHeader = (index: number) => {
    setHeaderHeaders(headerHeaders.filter((_, i) => i !== index));
  };

  const updateHeader = (index: number, field: "name" | "value", value: string) => {
    const updated = [...headerHeaders];
    updated[index][field] = value;
    setHeaderHeaders(updated);
  };

  const addCookie = () => {
    setHeaderCookies([...headerCookies, { name: "", value: "" }]);
  };

  const removeCookie = (index: number) => {
    setHeaderCookies(headerCookies.filter((_, i) => i !== index));
  };

  const updateCookie = (index: number, field: "name" | "value", value: string) => {
    const updated = [...headerCookies];
    updated[index][field] = value;
    setHeaderCookies(updated);
  };

  // Include/Exclude URLs handlers for form-based
  const addFormIncludeUrl = () => {
    if (formIncludeUrlInput.trim()) {
      setFormIncludeUrls([...formIncludeUrls, formIncludeUrlInput.trim()]);
      setFormIncludeUrlInput("");
    }
  };

  const removeFormIncludeUrl = (index: number) => {
    setFormIncludeUrls(formIncludeUrls.filter((_, i) => i !== index));
  };

  const addFormExcludeUrl = () => {
    if (formExcludeUrlInput.trim()) {
      setFormExcludeUrls([...formExcludeUrls, formExcludeUrlInput.trim()]);
      setFormExcludeUrlInput("");
    }
  };

  const removeFormExcludeUrl = (index: number) => {
    setFormExcludeUrls(formExcludeUrls.filter((_, i) => i !== index));
  };

  // Update include URLs when target URL changes
  useEffect(() => {
    if (formTargetUrl && authMode === "form_based") {
      // Check if target URL is already in include URLs
      if (!formIncludeUrls.includes(formTargetUrl)) {
        setFormIncludeUrls([formTargetUrl, ...formIncludeUrls]);
      }
    }
  }, [formTargetUrl, authMode]);

  const handleRunScan = () => {
    if (authMode === "form_based") {
      if (!formTargetUrl || !formLoginUrl || !formUsernameValue || !formPasswordValue || !formUsernameKey || !formPasswordKey || !formLoggedInRegex || !formLoggedOutRegex) {
        toast.error("Please fill in all required fields for form-based authentication");
        return;
      }
      // Ensure target URL is always in include URLs
      const finalIncludeUrls = formIncludeUrls.includes(formTargetUrl) 
        ? formIncludeUrls 
        : [formTargetUrl, ...formIncludeUrls];
      
      startScanMutation.mutate({
        conversation_id: parseInt(conversation_id as string),
        auth_mode: "form_based",
        form_based: {
          target_url: formTargetUrl,
          login_url: formLoginUrl,
          include_urls: finalIncludeUrls.length > 0 ? finalIncludeUrls : [formTargetUrl],
          exclude_urls: formExcludeUrls.length > 0 ? formExcludeUrls : undefined,
          mode: formMode,
          timeout_durations_mins: formTimeoutMins,
          poll_durations_seconds: formPollSeconds,
          username_value: formUsernameValue,
          password_value: formPasswordValue,
          username_key: formUsernameKey,
          password_key: formPasswordKey,
          logged_in_regex: formLoggedInRegex,
          logged_out_regex: formLoggedOutRegex,
        }
      });
    } else {
      if (!headerTargetUrl) {
        toast.error("Please fill in the target URL for header/cookie-based authentication");
        return;
      }
      startScanMutation.mutate({
        conversation_id: parseInt(conversation_id as string),
        auth_mode: "header_cookie_based",
        header_cookie_based: {
          target_url: headerTargetUrl,
          attack_modules: headerAttackModules.length > 0 ? headerAttackModules : undefined,
          max_scan_time: headerMaxScanTime,
          user_agent: headerUserAgent || undefined,
          headers: headerHeaders.length > 0 ? headerHeaders.filter(h => h.name && h.value) : undefined,
          cookies: headerCookies.length > 0 ? headerCookies.filter(c => c.name && c.value) : undefined,
          scan_force: headerScanForce,
          exclude_url_patterns: headerExcludePatterns.length > 0 ? headerExcludePatterns : undefined,
        }
      });
    }
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
          <div className="p-6 w-full max-w-full overflow-hidden box-border" style={{ width: '100%', maxWidth: '320px', boxSizing: 'border-box', overflowX: 'hidden' }}>
            {/* Authentication Mode Selection */}
            <div className="mb-8 w-full">
              <h3 className="text-sm font-semibold text-zinc-300 mb-4 flex flex-row items-center gap-2">
                Authentication Mode <p className="text-red-500">*</p>
              </h3>
              <Select value={authMode} onValueChange={(value: "form_based" | "header_cookie_based") => setAuthMode(value)}>
                <SelectTrigger className="w-full bg-zinc-800 border-zinc-700 text-white cursor-pointer">
                  <SelectValue>
                    {authMode === "form_based" ? (
                      <div className="flex items-center gap-2 truncate">
                        <Key className="h-4 w-4 flex-shrink-0" />
                        <span className="truncate">Form Based Authentication</span>
                      </div>
                    ) : (
                      <div className="flex items-center gap-2 truncate">
                        <Shield className="h-4 w-4 flex-shrink-0" />
                        <span className="truncate">Header/Cookie Based</span>
                      </div>
                    )}
                  </SelectValue>
                  </SelectTrigger>
                <SelectContent className="bg-zinc-800 border-zinc-700 w-[280px]">
                  <SelectItem value="form_based" className="text-white hover:bg-zinc-700 cursor-pointer">
                    <div className="flex items-center gap-2">
                      <Key className="h-4 w-4 flex-shrink-0" />
                      <span className="break-words">Form Based Authentication</span>
                    </div>
                    </SelectItem>
                  <SelectItem value="header_cookie_based" className="text-white hover:bg-zinc-700 cursor-pointer">
                    <div className="flex items-center gap-2">
                      <Shield className="h-4 w-4 flex-shrink-0" />
                      <span className="break-words">Header/Cookie Based Authentication</span>
                    </div>
                    </SelectItem>
                  </SelectContent>
                </Select>
          </div>

            {authMode === "form_based" ? (
              <Accordion type="single" collapsible className="w-full">
                <AccordionItem value="form-based" className="border-zinc-800">
                  <AccordionTrigger className="text-zinc-300 hover:text-white cursor-pointer text-sm">
                    Form Based Authentication
                  </AccordionTrigger>
                  <AccordionContent className="pt-4 space-y-4 w-full">
                    <div className="space-y-2 w-full">
                      <Label htmlFor="form-target-url" className="text-zinc-300">
                        Target URL <span className="text-red-500">*</span>
                </Label>
                      <Input
                        id="form-target-url"
                        placeholder="https://example.com"
                        className="bg-zinc-800 border-zinc-700 text-white placeholder:text-zinc-500"
                        style={{ width: '100%', maxWidth: '100%', boxSizing: 'border-box', overflow: 'hidden', textOverflow: 'ellipsis', wordBreak: 'break-all' }}
                        value={formTargetUrl}
                        onChange={(e) => setFormTargetUrl(e.target.value)}
                      />
                    </div>
                    <div className="space-y-2 w-full">
                      <Label htmlFor="form-login-url" className="text-zinc-300">
                        Login URL <span className="text-red-500">*</span>
                      </Label>
                      <Input
                        id="form-login-url"
                        placeholder="https://example.com/login"
                        className="bg-zinc-800 border-zinc-700 text-white placeholder:text-zinc-500"
                        style={{ width: '100%', maxWidth: '100%', boxSizing: 'border-box', overflow: 'hidden', textOverflow: 'ellipsis', wordBreak: 'break-all' }}
                        value={formLoginUrl}
                        onChange={(e) => setFormLoginUrl(e.target.value)}
                      />
                    </div>
                    <div className="space-y-2 w-full">
                      <Label htmlFor="form-username-key" className="text-zinc-300">
                        Username Field Name <span className="text-red-500">*</span>
                      </Label>
                      <Input
                        id="form-username-key"
                        placeholder="username"
                        className="bg-zinc-800 border-zinc-700 text-white placeholder:text-zinc-500"
                        style={{ width: '100%', maxWidth: '100%', boxSizing: 'border-box', overflow: 'hidden', textOverflow: 'ellipsis', wordBreak: 'break-all' }}
                        value={formUsernameKey}
                        onChange={(e) => setFormUsernameKey(e.target.value)}
                      />
                    </div>
                    <div className="space-y-2 w-full">
                      <Label htmlFor="form-username-value" className="text-zinc-300">
                        Username Value <span className="text-red-500">*</span>
                      </Label>
                      <Input
                        id="form-username-value"
                        placeholder="user@example.com"
                        className="bg-zinc-800 border-zinc-700 text-white placeholder:text-zinc-500"
                        style={{ width: '100%', maxWidth: '100%', boxSizing: 'border-box', overflow: 'hidden', textOverflow: 'ellipsis', wordBreak: 'break-all' }}
                        value={formUsernameValue}
                        onChange={(e) => setFormUsernameValue(e.target.value)}
                      />
                    </div>
                    <div className="space-y-2 w-full">
                      <Label htmlFor="form-password-key" className="text-zinc-300">
                        Password Field Name <span className="text-red-500">*</span>
                      </Label>
                      <Input
                        id="form-password-key"
                        placeholder="password"
                        className="bg-zinc-800 border-zinc-700 text-white placeholder:text-zinc-500"
                        style={{ width: '100%', maxWidth: '100%', boxSizing: 'border-box', overflow: 'hidden', textOverflow: 'ellipsis', wordBreak: 'break-all' }}
                        value={formPasswordKey}
                        onChange={(e) => setFormPasswordKey(e.target.value)}
                      />
              </div>
                    <div className="space-y-2 w-full">
                      <Label htmlFor="form-password-value" className="text-zinc-300">
                        Password Value <span className="text-red-500">*</span>
                </Label>
                      <Input
                        id="form-password-value"
                        type="password"
                        placeholder="password123"
                        className="bg-zinc-800 border-zinc-700 text-white placeholder:text-zinc-500"
                        style={{ width: '100%', maxWidth: '100%', boxSizing: 'border-box', overflow: 'hidden', textOverflow: 'ellipsis', wordBreak: 'break-all' }}
                        value={formPasswordValue}
                        onChange={(e) => setFormPasswordValue(e.target.value)}
                      />
                    </div>
                    <div className="space-y-2 w-full">
                      <Label htmlFor="form-logged-in-regex" className="text-zinc-300">
                        Logged In Regex <span className="text-red-500">*</span>
                      </Label>
                      <Textarea
                        id="form-logged-in-regex"
                        placeholder="\\QWelcome\\E|\\QLogout\\E"
                        className="bg-zinc-800 border-zinc-700 text-white placeholder:text-zinc-500 resize-none"
                        style={{ width: '100%', maxWidth: '100%', boxSizing: 'border-box', overflow: 'hidden', textOverflow: 'ellipsis', wordBreak: 'break-all' }}
                        rows={3}
                        value={formLoggedInRegex}
                        onChange={(e) => setFormLoggedInRegex(e.target.value)}
                      />
                    </div>
                    <div className="space-y-2 w-full">
                      <Label htmlFor="form-logged-out-regex" className="text-zinc-300">
                        Logged Out Regex <span className="text-red-500">*</span>
                      </Label>
                      <Textarea
                        id="form-logged-out-regex"
                        placeholder="\\Qlogin.jsp\\E|\\Q<form.*login\\E"
                        className="bg-zinc-800 border-zinc-700 text-white placeholder:text-zinc-500 resize-none"
                        style={{ width: '100%', maxWidth: '100%', boxSizing: 'border-box', overflow: 'hidden', textOverflow: 'ellipsis', wordBreak: 'break-all' }}
                        rows={3}
                        value={formLoggedOutRegex}
                        onChange={(e) => setFormLoggedOutRegex(e.target.value)}
                      />
                    </div>
                    <div className="space-y-2 w-full">
                      <Label htmlFor="form-mode" className="text-zinc-300">
                        Scan Mode
                      </Label>
                      <Select value={formMode} onValueChange={(value: any) => setFormMode(value)}>
                        <SelectTrigger className="w-full bg-zinc-800 border-zinc-700 text-white cursor-pointer">
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent className="bg-zinc-800 border-zinc-700 w-[280px]">
                          <SelectItem value="Pen Test" className="text-white hover:bg-zinc-700 cursor-pointer">Pen Test</SelectItem>
                          <SelectItem value="St-Low-Th-High" className="text-white hover:bg-zinc-700 cursor-pointer">St-Low-Th-High</SelectItem>
                          <SelectItem value="API" className="text-white hover:bg-zinc-700 cursor-pointer">API</SelectItem>
                          <SelectItem value="API-Minimal" className="text-white hover:bg-zinc-700 cursor-pointer">API-Minimal</SelectItem>
                          <SelectItem value="QA Standard" className="text-white hover:bg-zinc-700 cursor-pointer">QA Standard</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>
                    <div className="space-y-2 w-full">
                      <Label htmlFor="form-timeout" className="text-zinc-300">
                        Timeout (minutes)
                      </Label>
                      <Input
                        id="form-timeout"
                        type="number"
                        placeholder="20"
                        className="bg-zinc-800 border-zinc-700 text-white placeholder:text-zinc-500 w-full max-w-full"
                        style={{ maxWidth: '100%' }}
                        value={formTimeoutMins}
                        onChange={(e) => setFormTimeoutMins(parseInt(e.target.value) || 20)}
                      />
                    </div>
                    <div className="space-y-2 w-full">
                      <Label className="text-zinc-300">Include URLs</Label>
                      <div className="flex gap-2 w-full" style={{ width: '100%', maxWidth: '100%', boxSizing: 'border-box' }}>
                        <Input
                          placeholder="https://example.com/path"
                          className="bg-zinc-800 border-zinc-700 text-white placeholder:text-zinc-500 flex-1 min-w-0"
                          style={{ width: '0', flex: '1 1 0%', maxWidth: '100%', boxSizing: 'border-box', overflow: 'hidden', textOverflow: 'ellipsis', wordBreak: 'break-all' }}
                          value={formIncludeUrlInput}
                          onChange={(e) => setFormIncludeUrlInput(e.target.value)}
                          onKeyDown={(e) => {
                            if (e.key === "Enter") {
                              e.preventDefault();
                              addFormIncludeUrl();
                            }
                          }}
                        />
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={addFormIncludeUrl}
                          className="bg-zinc-800 hover:bg-zinc-700 text-white cursor-pointer flex-shrink-0"
                        >
                          Add
                        </Button>
                      </div>
                      {formIncludeUrls.length > 0 && (
                        <div className="space-y-1 mt-2">
                          {formIncludeUrls.map((url, index) => (
                            <div key={index} className="flex items-center gap-2 bg-zinc-800 rounded p-2">
                              <span className="text-xs text-zinc-300 flex-1 truncate">{url}</span>
                              <Button
                                variant="ghost"
                                size="sm"
                                onClick={() => removeFormIncludeUrl(index)}
                                className="text-red-400 hover:text-red-300 cursor-pointer flex-shrink-0 w-6 h-6 p-0"
                              >
                                ×
                              </Button>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                    <div className="space-y-2 w-full">
                      <Label className="text-zinc-300">Exclude URLs</Label>
                      <div className="flex gap-2 w-full" style={{ width: '100%', maxWidth: '100%', boxSizing: 'border-box' }}>
                        <Input
                          placeholder="https://example.com/exclude"
                          className="bg-zinc-800 border-zinc-700 text-white placeholder:text-zinc-500 flex-1 min-w-0"
                          style={{ width: '0', flex: '1 1 0%', maxWidth: '100%', boxSizing: 'border-box', overflow: 'hidden', textOverflow: 'ellipsis', wordBreak: 'break-all' }}
                          value={formExcludeUrlInput}
                          onChange={(e) => setFormExcludeUrlInput(e.target.value)}
                          onKeyDown={(e) => {
                            if (e.key === "Enter") {
                              e.preventDefault();
                              addFormExcludeUrl();
                            }
                          }}
                        />
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={addFormExcludeUrl}
                          className="bg-zinc-800 hover:bg-zinc-700 text-white cursor-pointer flex-shrink-0"
                        >
                          Add
                        </Button>
                      </div>
                      {formExcludeUrls.length > 0 && (
                        <div className="space-y-1 mt-2">
                          {formExcludeUrls.map((url, index) => (
                            <div key={index} className="flex items-center gap-2 bg-zinc-800 rounded p-2">
                              <span className="text-xs text-zinc-300 flex-1 truncate">{url}</span>
                              <Button
                                variant="ghost"
                                size="sm"
                                onClick={() => removeFormExcludeUrl(index)}
                                className="text-red-400 hover:text-red-300 cursor-pointer flex-shrink-0 w-6 h-6 p-0"
                              >
                                ×
                              </Button>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  </AccordionContent>
                </AccordionItem>
              </Accordion>
            ) : (
              <Accordion type="single" collapsible className="w-full">
                <AccordionItem value="header-cookie-based" className="border-zinc-800">
                  <AccordionTrigger className="text-zinc-300 hover:text-white cursor-pointer text-sm">
                    Header/Cookie Based Auth
                  </AccordionTrigger>
                  <AccordionContent className="pt-4 space-y-4 w-full">
                    <div className="space-y-2 w-full">
                      <Label htmlFor="header-target-url" className="text-zinc-300">
                        Target URL <span className="text-red-500">*</span>
                      </Label>
                      <Input
                        id="header-target-url"
                        placeholder="https://example.com"
                        className="bg-zinc-800 border-zinc-700 text-white placeholder:text-zinc-500 w-full"
                        value={headerTargetUrl}
                        onChange={(e) => setHeaderTargetUrl(e.target.value)}
                      />
                    </div>
                    <div className="space-y-2 w-full">
                      <Label htmlFor="header-scan-force" className="text-zinc-300">
                        Scan Force
                      </Label>
                      <Select value={headerScanForce} onValueChange={(value: any) => setHeaderScanForce(value)}>
                        <SelectTrigger className="w-full bg-zinc-800 border-zinc-700 text-white cursor-pointer">
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent className="bg-zinc-800 border-zinc-700 w-[280px]">
                          <SelectItem value="paranoid" className="text-white hover:bg-zinc-700 cursor-pointer">Paranoid</SelectItem>
                          <SelectItem value="sneaky" className="text-white hover:bg-zinc-700 cursor-pointer">Sneaky</SelectItem>
                          <SelectItem value="polite" className="text-white hover:bg-zinc-700 cursor-pointer">Polite</SelectItem>
                          <SelectItem value="normal" className="text-white hover:bg-zinc-700 cursor-pointer">Normal</SelectItem>
                          <SelectItem value="aggressive" className="text-white hover:bg-zinc-700 cursor-pointer">Aggressive</SelectItem>
                          <SelectItem value="insane" className="text-white hover:bg-zinc-700 cursor-pointer">Insane</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>
                    <div className="space-y-2 w-full">
                      <Label htmlFor="header-max-scan-time" className="text-zinc-300">
                        Max Scan Time (seconds)
                      </Label>
                      <Input
                        id="header-max-scan-time"
                        type="number"
                        placeholder="60"
                        className="bg-zinc-800 border-zinc-700 text-white placeholder:text-zinc-500"
                        style={{ width: '100%', maxWidth: '100%', boxSizing: 'border-box', overflow: 'hidden', textOverflow: 'ellipsis', wordBreak: 'break-all' }}
                        value={headerMaxScanTime}
                        onChange={(e) => setHeaderMaxScanTime(parseInt(e.target.value) || 60)}
                      />
                    </div>
                    <div className="space-y-2 w-full">
                      <Label htmlFor="header-user-agent" className="text-zinc-300">
                        User Agent (Optional)
                      </Label>
                      <Input
                        id="header-user-agent"
                        placeholder="Mozilla/5.0..."
                        className="bg-zinc-800 border-zinc-700 text-white placeholder:text-zinc-500"
                        style={{ width: '100%', maxWidth: '100%', boxSizing: 'border-box', overflow: 'hidden', textOverflow: 'ellipsis', wordBreak: 'break-all' }}
                        value={headerUserAgent}
                        onChange={(e) => setHeaderUserAgent(e.target.value)}
                      />
              </div>
                    <div className="space-y-2">
                      <Label className="text-zinc-300">Headers (Optional)</Label>
                      {headerHeaders.map((header, index) => (
                        <div key={index} className="flex gap-2 w-full" style={{ width: '100%', maxWidth: '100%', boxSizing: 'border-box' }}>
                          <Input
                            placeholder="Name"
                            className="bg-zinc-800 border-zinc-700 text-white placeholder:text-zinc-500 flex-1 min-w-0"
                            style={{ width: '0', flex: '1 1 0%', maxWidth: '100%', boxSizing: 'border-box', overflow: 'hidden', textOverflow: 'ellipsis', wordBreak: 'break-all' }}
                            value={header.name}
                            onChange={(e) => updateHeader(index, "name", e.target.value)}
                          />
                          <Input
                            placeholder="Value"
                            className="bg-zinc-800 border-zinc-700 text-white placeholder:text-zinc-500 flex-1 min-w-0"
                            style={{ width: '0', flex: '1 1 0%', maxWidth: '100%', boxSizing: 'border-box', overflow: 'hidden', textOverflow: 'ellipsis', wordBreak: 'break-all' }}
                            value={header.value}
                            onChange={(e) => updateHeader(index, "value", e.target.value)}
                          />
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => removeHeader(index)}
                            className="text-red-400 hover:text-red-300 flex-shrink-0 w-8 h-8 p-0 cursor-pointer"
                          >
                            ×
                          </Button>
                        </div>
                      ))}
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={addHeader}
                        className="w-full bg-zinc-800 hover:bg-zinc-700 text-white cursor-pointer"
                      >
                        + Add Header
                      </Button>
                    </div>
                    <div className="space-y-2">
                      <Label className="text-zinc-300">Cookies (Optional)</Label>
                      {headerCookies.map((cookie, index) => (
                        <div key={index} className="flex gap-2 w-full" style={{ width: '100%', maxWidth: '100%', boxSizing: 'border-box' }}>
                          <Input
                            placeholder="Name"
                            className="bg-zinc-800 border-zinc-700 text-white placeholder:text-zinc-500 flex-1 min-w-0"
                            style={{ width: '0', flex: '1 1 0%', maxWidth: '100%', boxSizing: 'border-box', overflow: 'hidden', textOverflow: 'ellipsis', wordBreak: 'break-all' }}
                            value={cookie.name}
                            onChange={(e) => updateCookie(index, "name", e.target.value)}
                          />
                          <Input
                            placeholder="Value"
                            className="bg-zinc-800 border-zinc-700 text-white placeholder:text-zinc-500 flex-1 min-w-0"
                            style={{ width: '0', flex: '1 1 0%', maxWidth: '100%', boxSizing: 'border-box', overflow: 'hidden', textOverflow: 'ellipsis', wordBreak: 'break-all' }}
                            value={cookie.value}
                            onChange={(e) => updateCookie(index, "value", e.target.value)}
                          />
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => removeCookie(index)}
                            className="text-red-400 hover:text-red-300 flex-shrink-0 w-8 h-8 p-0 cursor-pointer"
                          >
                            ×
                          </Button>
                        </div>
                      ))}
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={addCookie}
                        className="w-full bg-zinc-800 hover:bg-zinc-700 text-white cursor-pointer"
                      >
                        + Add Cookie
                      </Button>
                    </div>
                  </AccordionContent>
                </AccordionItem>
              </Accordion>
            )}
          </div>
          <div className="p-6">
            <Button 
              variant="ghost" 
              size="icon-lg"
              onClick={handleRunScan}
              className="w-fit h-8 px-4 bg-teal-600 hover:bg-teal-700 text-white cursor-pointer hover:text-white"
            >
              <ScanIcon className="size-4" />
              <span className="ml-1">Run Scan</span>
            </Button>
          </div>
        </>
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
              Scan has run successfully on the target <span className="text-teal-500 mx-3 text-xs p-1 bg-zinc-800 rounded-md">{query.data?.target_url || "N/A"}</span>
              You can now chat with your scan results
            </p>
            <Button 
              variant="ghost" 
              size="sm"
              onClick={() => {
                router.push(`/home/dast/${conversation_id}/results?origin=chat`);
              }}
              className="w-full h-8 px-2 bg-teal-600 hover:bg-teal-700 text-white cursor-pointer hover:text-white"
            >
              <Eye className="size-4" />
              <span className="ml-1">View Results</span>
            </Button>
            <Button 
              variant="ghost" 
              size="sm"
              onClick={async () => {
                exportMutation.mutate(parseInt(conversation_id as string));
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
            An error occurred during the scan. Please try again.
          </p>
          <Button 
            variant="ghost" 
            size="sm"
            onClick={() => {
              window.location.reload();
            }}
            className="w-full h-8 px-2 bg-zinc-700 hover:bg-zinc-600 text-white cursor-pointer hover:text-white"
          >
            <span>Try Again</span>
          </Button>
        </div>
      )}
    </ScrollArea>
  );
}
