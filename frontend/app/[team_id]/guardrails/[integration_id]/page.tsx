"use client";

import { usePathname } from "next/navigation";
import { useQuery, useQueryClient, useMutation } from "@tanstack/react-query";
import { useState, useEffect, useMemo } from "react";
import { getGuardrailsIntegrationDashboard, GuardrailsIntegrationDashboard, updateGuardrailsIntegration, CreateGuardrailsIntegrationData, SettingsData, UpdateGuardrailsIntegrationData } from "@/utils/backend_api";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Loader2, RefreshCcw, CheckCircle2, XCircle, Clock, PlayCircle, AlertCircle, X, Copy, Check, Settings, BarChart2, Save, Plus, BookOpen, Ticket, Search } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { toast } from "sonner";
import { showErrorToast } from "@/utils/error-handler";
import SettingsForm from "@/components/Settings";
import { defaultLanguages } from "@/components/Settings";
import { ScrollArea, ScrollBar } from "@/components/ui/scroll-area";
import GuardrailsApiDocs from "@/components/GuardrailsApiDocs";
import { GuardrailsDashboardData } from "@/components/GuardrailsDashboardData";
import {
  Accordion,
  AccordionContent,
  AccordionItem,
  AccordionTrigger,
} from "@/components/ui/accordion";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { JiraIcon } from "@/components/icons/arcticons-jira";


const extractResultMetadata = (results: any) => {
  // extract all the keys and values from results except sanitized_prompt
  const resultMetadata: Record<string, any> = {};
  for (const key in results) {
    if (key !== "sanitized_prompt") {
      resultMetadata[key] = results[key];
    }
  }
  return resultMetadata;
};

// Scanner name mapping for user-friendly display
const scannerNames: Record<string, string> = {
  anonymize: "Anonymize",
  toxicity: "Toxicity",
  token_limit: "Token Limit",
  prompt_injection: "Prompt Injection",
  regex: "Regex",
  code: "Code",
  secrets: "Secrets",
};

// Component to display scanner results in a user-friendly way
const ScannerResultsDisplay = ({ results }: { results: any }) => {
  const metadata = extractResultMetadata(results);
  // Filter to only show scanners with risk scores that are not -1.0
  const scannerKeys = Object.keys(metadata).filter(key => {
    const value = metadata[key];
    if (
      value &&
      typeof value === 'object' &&
      !Array.isArray(value) &&
      'score' in value
    ) {
      const rawRiskScore = value.score;
      // Only include if score exists and is not -1.0
      return rawRiskScore !== null && rawRiskScore !== undefined && rawRiskScore !== -1.0;
    }
    return false;
  });

  if (scannerKeys.length === 0) {
    return (
      <div className="text-center py-4">
        <span className="text-zinc-400 text-sm">No scanner results available</span>
      </div>
    );
  }

  return (
    <div className="space-y-2 max-w-md">
      {scannerKeys.map((scannerKey) => {
        const scannerData = metadata[scannerKey];
        const scannerName = scannerNames[scannerKey] || scannerKey.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
        const rawRiskScore = scannerData?.score !== undefined ? scannerData.score : null;
        // If risk score is not -1.0, take absolute value and show as percentage
        const riskScore = rawRiskScore !== null && rawRiskScore !== -1.0 ? Math.abs(rawRiskScore) : null;

        // This should never be null due to filtering, but keeping check for safety
        if (riskScore === null) {
          return null;
        }

        return (
          <div
            key={scannerKey}
            className="border border-zinc-200 dark:border-zinc-700 rounded-lg p-3 bg-zinc-50 dark:bg-zinc-900/50 hover:bg-zinc-100 dark:hover:bg-zinc-900 transition-colors"
          >
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm font-semibold text-zinc-900 dark:text-white">
                {scannerName}
              </span>
            </div>
            <div className="flex items-center gap-2 mt-2">
              <span className="text-xs text-zinc-600 dark:text-zinc-400 font-medium">Risk Score:</span>
              <div className="flex items-center gap-2 flex-1">
                <div className="flex-1 bg-zinc-200 dark:bg-zinc-700 rounded-full h-2 max-w-24">
                  <div
                    className={`h-2 rounded-full transition-all ${
                      riskScore < 0.3
                        ? "bg-green-500"
                        : riskScore < 0.7
                        ? "bg-yellow-500"
                        : "bg-red-500"
                    }`}
                    style={{ width: `${Math.min(riskScore * 100, 100)}%` }}
                  />
                </div>
                <span className="text-xs font-mono text-zinc-700 dark:text-zinc-300 min-w-12 text-right">
                  {(riskScore * 100).toFixed(0)}%
                </span>
              </div>
            </div>
          </div>
        );
      })}
    </div>
  );
};

export default function GuardrailsIntegrationDashboardPage() {
  const pathname = usePathname();
  const pathParts = pathname.split('/').filter(Boolean);
  const team_id = pathParts[0] ?? '';
  const integration_id = pathParts[2] ?? pathname.split('/').pop() ?? '';
  const queryClient = useQueryClient();
  const [copied, setCopied] = useState(false);
  const [activeTab, setActiveTab] = useState<"dashboard" | "settings" | "docs" | "ticketing">("dashboard");
  const [editSettings, setEditSettings] = useState(false);
  const [settingsForm, setSettingsForm] = useState<SettingsData>({
    anonymize_context: { preamble: "", threshold: 0.1, allowed_names: [] },
    toxicity_context: { threshold: 0.1 },
    tokenlimit_context: { max_tokens: 2000 },
    promptinjection_context: { threshold: 0.1 },
    regex_context: { regex_patterns: [], redact: false },
    code_context: { languages: defaultLanguages, is_blocked: true },
    secrets_context: { redact_mode: "REDACT_PARTIAL" },
  });
  const [jiraProjectId, setJiraProjectId] = useState("");
  const [logSearchQuery, setLogSearchQuery] = useState("");

  const query = useQuery({
    queryKey: ['guardrails-integration-dashboard', team_id, integration_id],
    queryFn: getGuardrailsIntegrationDashboard,
    enabled: !!team_id && !!integration_id,
  });

  const handleRefresh = () => {
    queryClient.invalidateQueries({ queryKey: ['guardrails-integration-dashboard', team_id, integration_id] });
  };

  const formatDate = (dateString: string) => {
    const date = new Date(dateString);
    return date.toLocaleDateString("en-US", {
      year: "numeric",
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    });
  };

  const redactApiKey = (apiKey: string) => {
    if (apiKey.length <= 8) {
      return "•".repeat(apiKey.length);
    }
    // Show first 4 and last 4 characters, redact the middle
    const start = apiKey.substring(0, 4);
    const end = apiKey.substring(apiKey.length - 4);
    return `${start}${"**********"}${end}`;
  };

  const copyApiKey = async (apiKey: string) => {
    try {
      await navigator.clipboard.writeText(apiKey);
      setCopied(true);
      toast.success("API key copied to clipboard");
      setTimeout(() => {
        setCopied(false);
      }, 2000);
    } catch (error) {
      toast.error("Failed to copy API key");
    }
  };

  // Initialize settings form when data loads
  useEffect(() => {
    if (query.data?.settings) {
      // Deep copy settings to avoid mutations
      const settingsCopy = JSON.parse(JSON.stringify(query.data.settings));
      setSettingsForm(settingsCopy);
    }
  }, [query.data?.settings]);

  // Sync Jira project ID from integration_settings (backend stores as jira_project_id: { jira_project_id: "..." })
  useEffect(() => {
    const is = query.data?.integration_settings;
    if (is && typeof is === "object" && !Array.isArray(is)) {
      const raw = is as Record<string, unknown>;
      const fromNested = (raw.jira_project_id as { jira_project_id?: string } | undefined)?.jira_project_id;
      const fromJira = (raw.jira as { jira_project_id?: string } | undefined)?.jira_project_id;
      setJiraProjectId(fromNested ?? fromJira ?? "");
    } else {
      setJiraProjectId("");
    }
  }, [query.data?.integration_settings]);

  const updateSettingsMutation = useMutation({
    mutationFn: (data: UpdateGuardrailsIntegrationData) =>
      updateGuardrailsIntegration({
        team_id: Number(team_id),
        integration_id: Number(integration_id),
        data,
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['guardrails-integration-dashboard', team_id, integration_id] });
      setEditSettings(false);
      toast.success('Settings updated successfully');
    },
    onError: (error) => {
      showErrorToast(error);
    }
  });

  const updateIntegrationSettingsMutation = useMutation({
    mutationFn: (data: UpdateGuardrailsIntegrationData) =>
      updateGuardrailsIntegration({
        team_id: Number(team_id),
        integration_id: Number(integration_id),
        data,
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['guardrails-integration-dashboard', team_id, integration_id] });
    },
    onError: (error) => {
      showErrorToast(error);
    }
  });

  const logData = query.data?.log_data ?? [];
  const filteredLogs = useMemo(() => {
    if (!logSearchQuery.trim()) return logData;
    const q = logSearchQuery.trim().toLowerCase();
    return logData.filter((log) => (log.input_prompt ?? "").toLowerCase().includes(q));
  }, [logData, logSearchQuery]);

  const getStatusBadge = (status: string) => {
    const statusLower = status.toLowerCase();
    if (statusLower === "success") {
      return <Badge className="bg-green-500 hover:bg-green-600"><CheckCircle2 className="w-3 h-3 mr-1" />Success</Badge>;
    } else if (statusLower === "failure") {
      return <Badge className="bg-red-600 hover:bg-red-700 text-white"><XCircle className="w-3 h-3 mr-1" />Failed</Badge>;
    } else if (statusLower === "pending") {
      return <Badge className="bg-yellow-500 hover:bg-yellow-600"><Clock className="w-3 h-3 mr-1" />Pending</Badge>;
    } else if (statusLower === "started") {
      return <Badge className="bg-blue-500 hover:bg-blue-600"><PlayCircle className="w-3 h-3 mr-1" />Started</Badge>;
    } else if (statusLower === "not_started") {
      return <Badge className="bg-gray-500 hover:bg-gray-600"><AlertCircle className="w-3 h-3 mr-1" />Not Started</Badge>;
    }
    return <Badge variant="outline">{status}</Badge>;
  };

  if (query.isError) {
    return (
      <div className="flex h-screen w-full items-center justify-center bg-white dark:bg-zinc-900">
        <div className="text-center">
          <p className="text-zinc-600 dark:text-zinc-400 mb-4">
            Error fetching dashboard data, please try again later
          </p>
          <Button onClick={handleRefresh}>Try Again</Button>
        </div>
      </div>
    );
  }

  if (query.isLoading) {
    return (
      <div className="flex h-screen bg-white dark:bg-zinc-900">
        <div className="flex-1 p-8 overflow-auto">
          <div className="max-w-7xl mx-auto">
            <div className="mb-8">
              <Skeleton className="h-10 w-64 mb-2" />
              <Skeleton className="h-5 w-48" />
            </div>
            <div className="flex flex-row gap-3 mb-8">
              {[1, 2, 3, 4, 5, 6].map((i) => (
                <Skeleton key={i} className="h-20 flex-1 rounded-lg" />
              ))}
            </div>
            <Skeleton className="h-96 w-full" />
          </div>
        </div>
      </div>
    );
  }

  const defaultSettings: SettingsData = {
    anonymize_context: { preamble: "", threshold: 0.1, allowed_names: [] },
    toxicity_context: { threshold: 0.1 },
    tokenlimit_context: { max_tokens: 2000 },
    promptinjection_context: { threshold: 0.1 },
    regex_context: { regex_patterns: [], redact: false },
    code_context: { languages: defaultLanguages, is_blocked: true },
    secrets_context: { redact_mode: "REDACT_PARTIAL" },
  };

  const dashboardData: GuardrailsIntegrationDashboard = query.data || {
    dashboard_data: {
      card_data: {
        total_logs: 0,
        successful_logs: 0,
        failed_logs: 0,
        pending_logs: 0,
        started_logs: 0,
        not_started_logs: 0,
      },
      recent_daily_detections_usage: {},
      high_or_critical_risks_daily_usage: {},
      past_30_days_risk_score_data: { critical: 0, high: 0, medium: 0, low: 0 },
      past_60_days_risk_score_data: { critical: 0, high: 0, medium: 0, low: 0 },
    },
    api_key: "",
    log_data: [],
    settings: defaultSettings,
    integration_settings: { jira_enabled: false },
  };

  return (
    <div className="flex h-screen bg-white dark:bg-zinc-900">
      <div className="flex-1 p-8 overflow-auto">
        <div className="max-w-7xl mx-auto">
          {/* Header */}
          <div className="mb-8 flex justify-between items-center">
            <div>
              <h1 className="text-3xl font-bold text-zinc-900 dark:text-white mb-2">
                AI Guardrails Dashboard
              </h1>
              <div className="flex flex-row items-center gap-2 mt-4 ">
                <p className="text-zinc-600 dark:text-zinc-400 text-sm font-medium">Copy API Key :</p>
                      <div className="flex items-center gap-2 max-w-md">
                        <code className="text-sm bg-zinc-100 dark:bg-zinc-800 px-3 py-1.5 rounded font-mono text-zinc-900 dark:text-zinc-100">
                          {dashboardData.api_key ? redactApiKey(dashboardData.api_key) : "Loading..."}
                        </code>
                        <Button
                          variant="ghost"
                          size="icon"
                          className="h-8 w-8 cursor-pointer"
                          onClick={() => dashboardData.api_key && copyApiKey(dashboardData.api_key)}
                          title="Copy API key"
                        >
                          {copied ? (
                            <Check className="h-4 w-4 text-green-600" />
                          ) : (
                            <Copy className="h-4 w-4" />
                          )}
                        </Button>
                      </div>
              </div>
            </div>
            <Button 
              onClick={handleRefresh} 
              disabled={query.isFetching}
              variant="outline"
              className="flex items-center gap-2 bg-blue-600 hover:bg-blue-700 text-white cursor-pointer hover:text-white"
            >
              {query.isFetching ? (
                <Loader2 className="w-4 h-4 animate-spin" />
              ) : (
                <RefreshCcw className="w-4 h-4" />
              )}
              Refresh
            </Button>
          </div>

          {/* Tabs */}
          <div className="flex gap-2 mb-6 border-b border-zinc-200 dark:border-zinc-800">
            <button
              onClick={() => setActiveTab("dashboard")}
              className={`px-4 py-2 font-medium text-sm transition-colors border-b-2 cursor-pointer ${
                activeTab === "dashboard"
                  ? "border-blue-600 text-blue-600 dark:text-blue-400"
                  : "border-transparent text-zinc-600 dark:text-zinc-400 hover:text-zinc-900 dark:hover:text-zinc-100"
              }`}
            >
              <div className="flex items-center gap-2">
                <BarChart2 className="w-4 h-4" />
                Dashboard
              </div>
            </button>
            <button
              onClick={() => setActiveTab("settings")}
              className={`px-4 py-2 font-medium text-sm transition-colors border-b-2 cursor-pointer ${
                activeTab === "settings"
                  ? "border-blue-600 text-blue-600 dark:text-blue-400"
                  : "border-transparent text-zinc-600 dark:text-zinc-400 hover:text-zinc-900 dark:hover:text-zinc-100"
              }`}
            >
              <div className="flex items-center gap-2">
                <Settings className="w-4 h-4" />
                Settings
              </div>
            </button>
            <button
              onClick={() => setActiveTab("ticketing")}
              className={`px-4 py-2 font-medium text-sm transition-colors border-b-2 cursor-pointer ${
                activeTab === "ticketing"
                  ? "border-blue-600 text-blue-600 dark:text-blue-400"
                  : "border-transparent text-zinc-600 dark:text-zinc-400 hover:text-zinc-900 dark:hover:text-zinc-100"
              }`}
            >
              <div className="flex items-center gap-2">
                <Ticket className="w-4 h-4" />
                Ticketing integrations
              </div>
            </button>
            <button
              onClick={() => setActiveTab("docs")}
              className={`px-4 py-2 font-medium text-sm transition-colors border-b-2 cursor-pointer ${
                activeTab === "docs"
                  ? "border-blue-600 text-blue-600 dark:text-blue-400"
                  : "border-transparent text-zinc-600 dark:text-zinc-400 hover:text-zinc-900 dark:hover:text-zinc-100"
              }`}
            >
              <div className="flex items-center gap-2">
                <BookOpen className="w-4 h-4" />
                API Documentation
              </div>
            </button>
          </div>

          {/* Dashboard Tab */}
          {activeTab === "dashboard" && (
            <>
              <div className="mb-8">
                <GuardrailsDashboardData dashboardData={query.data?.dashboard_data} />
              </div>

              {/* Logs Table */}
              <Card className="flex max-h-[75vh] flex-col overflow-hidden">
                <CardHeader className="shrink-0">
                  <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
                    <div>
                      <CardTitle>Logs</CardTitle>
                      <CardDescription className="mt-2">
                        {logSearchQuery.trim()
                          ? `${filteredLogs.length} of ${dashboardData.log_data.length} logs`
                          : `All Logs for this Integration (${dashboardData.log_data.length} total)`}
                      </CardDescription>
                    </div>
                    <div className="relative w-full sm:w-72">
                      <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-4 w-4 text-zinc-500 dark:text-zinc-400 pointer-events-none" />
                      <Input
                        type="text"
                        placeholder="Search by input prompt..."
                        value={logSearchQuery}
                        onChange={(e) => setLogSearchQuery(e.target.value)}
                        className="pl-8 h-9"
                      />
                    </div>
                  </div>
                </CardHeader>
                <CardContent className="min-h-0 flex-1 overflow-hidden p-0 ">
                  {dashboardData.log_data.length === 0 ? (
                    <div className="text-center py-12 text-zinc-600 dark:text-zinc-400 px-6">
                      No logs found for this integration
                    </div>
                  ) : filteredLogs.length === 0 ? (
                    <div className="text-center py-12 text-zinc-600 dark:text-zinc-400 px-6">
                      No logs match your search
                    </div>
                  ) : (
                    <ScrollArea className="h-[60vh] min-h-[200px] w-full rounded-none border-0 border-t border-zinc-200 dark:border-zinc-800">
                      <div className="min-w-0 px-6 pb-6 pt-4">
                        <Table>
                          <TableHeader>
                            <TableRow>
                              <TableHead className="w-28 min-w-28">ID</TableHead>
                              <TableHead>Status</TableHead>
                              <TableHead>Input Prompt</TableHead>
                              <TableHead>Created At</TableHead>
                              <TableHead>Sanitized Prompt</TableHead>
                              <TableHead>Result Metadata</TableHead>
                            </TableRow>
                          </TableHeader>
                          <TableBody>
                            {filteredLogs.map((log) => (
                              <TableRow key={log.id}>
                                <TableCell className="font-mono text-sm w-28 min-w-28 py-2 align-top">
                                  <div className="whitespace-nowrap overflow-visible">{log.id.toString().slice(-8)}</div>
                                </TableCell>
                                <TableCell className="py-2 align-top">
                                  {getStatusBadge(log.status)}
                                </TableCell>
                                <TableCell className="max-w-48 py-2 align-top">
                                  <ScrollArea className="h-14 w-full">
                                    <p className="text-sm whitespace-normal pr-2" style={{ wordBreak: 'break-word', overflowWrap: 'break-word' }}>{log.input_prompt || "-"}</p>
                                  </ScrollArea>
                                </TableCell>
                                <TableCell className="py-2 align-top whitespace-nowrap">
                                  {log.created_at ? formatDate(log.created_at) : "-"}
                                </TableCell>
                                <TableCell className="max-w-48 py-2 align-top">
                                  {log.results ? (
                                    <ScrollArea className="max-w-48 h-14 w-full">
                                      <p className="text-sm whitespace-normal pr-2" style={{ wordBreak: 'break-word', overflowWrap: 'break-word' }}>{log.results.sanitized_prompt || "-"}</p>
                                    </ScrollArea>
                                  ) : (
                                    <span className="text-zinc-400">-</span>
                                  )}
                                </TableCell>
                                <TableCell className="max-w-md py-2 align-top">
                                  {log.results ? (
                                    <ScrollArea className="max-w-md h-36">
                                      <ScannerResultsDisplay results={log.results} />
                                    </ScrollArea>
                                  ) : (
                                    <span className="text-zinc-400">-</span>
                                  )}
                                </TableCell>
                              </TableRow>
                            ))}
                          </TableBody>
                        </Table>
                      </div>
                      <ScrollBar orientation="vertical" />
                      <ScrollBar orientation="horizontal" />
                    </ScrollArea>
                  )}
                </CardContent>
              </Card>
            </>
          )}

          {/* Settings Tab */}
          {activeTab === "settings" && (
            <Card>
              <CardHeader>
                <div className="flex items-center justify-between">
                  <div>
                    <CardTitle>Guardrail Settings</CardTitle>
                    <CardDescription className="mt-2">
                      View and edit guardrails integration settings
                    </CardDescription>
                  </div>
                  {!editSettings ? (
                    <Button
                      onClick={() => setEditSettings(true)}
                      className="bg-blue-600 hover:bg-blue-700 text-white cursor-pointer"
                    >
                      <Settings className="w-4 h-4 mr-2" />
                      Edit Settings
                    </Button>
                  ) : (
                    <div className="flex gap-2">
                      <Button
                        variant="outline"
                        className="cursor-pointer"
                        onClick={() => {
                          setEditSettings(false);
                          setSettingsForm(dashboardData.settings);
                        }}
                      >
                        Cancel
                      </Button>
                      <Button
                        onClick={() => {
                          // Clean up settings - remove empty strings from arrays and validate thresholds
                          const cleanedSettings = { ...settingsForm };
                          let hasValidationError = false;
                          
                          const validateThreshold = (threshold: number | undefined, contextName: string): boolean => {
                            if (threshold === undefined || threshold === null) {
                              return true; // No threshold set, skip validation
                            }
                            if (threshold === 0) {
                              toast.error(`${contextName}: Threshold cannot be 0`);
                              return false;
                            }
                            if (threshold < 0.1) {
                              toast.error(`${contextName}: Threshold must be at least 0.1`);
                              return false;
                            }
                            if (Number.isInteger(threshold)) {
                              toast.error(`${contextName}: Threshold must be a decimal number (e.g., 0.1, 0.5, 1.2), not a whole number`);
                              return false;
                            }
                            return true;
                          };
                          
                          // Validate all thresholds first
                          if (cleanedSettings.anonymize_context?.threshold !== undefined) {
                            if (!validateThreshold(cleanedSettings.anonymize_context.threshold, "Anonymize Context")) {
                              hasValidationError = true;
                            }
                          }
                          
                          if (cleanedSettings.toxicity_context?.threshold !== undefined) {
                            if (!validateThreshold(cleanedSettings.toxicity_context.threshold, "Toxicity Context")) {
                              hasValidationError = true;
                            }
                          }
                          
                          if (cleanedSettings.promptinjection_context?.threshold !== undefined) {
                            if (!validateThreshold(cleanedSettings.promptinjection_context.threshold, "Prompt Injection Context")) {
                              hasValidationError = true;
                            }
                          }
                          
                          // If any validation failed, stop here and don't make API call
                          if (hasValidationError) {
                            return; // Don't submit if validation failed
                          }
                          
                          // All validation passed, proceed with cleanup and API call
                          if (cleanedSettings.anonymize_context) {
                            cleanedSettings.anonymize_context = {
                              ...cleanedSettings.anonymize_context,
                              allowed_names: cleanedSettings.anonymize_context.allowed_names?.filter(n => n.trim()) || [],
                            };
                          }
                          
                          if (cleanedSettings.regex_context) {
                            cleanedSettings.regex_context = {
                              ...cleanedSettings.regex_context,
                              regex_patterns: cleanedSettings.regex_context.regex_patterns?.filter(p => p.trim()) || [],
                            };
                          }
                          
                          // All validation passed, proceed with API call
                          updateSettingsMutation.mutate({ settings: cleanedSettings });
                        }}
                        disabled={updateSettingsMutation.isPending}
                        className="bg-blue-600 hover:bg-blue-700 text-white cursor-pointer"
                      >
                        {updateSettingsMutation.isPending ? (
                          <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                        ) : (
                          <Save className="w-4 h-4 mr-2" />
                        )}
                        Save Changes
                      </Button>
                    </div>
                  )}
                </div>
              </CardHeader>
              <CardContent>
                <SettingsForm 
                  settings={editSettings ? settingsForm : (dashboardData.settings || settingsForm)}
                  onChange={setSettingsForm}
                  disabled={!editSettings}
                />
              </CardContent>
            </Card>
          )}

          {/* Ticketing integrations Tab */}
          {activeTab === "ticketing" && (
            <Card>
              <CardHeader>
                <CardTitle>Ticketing integrations</CardTitle>
                <CardDescription>
                  Connect this guardrails integration to ticketing systems. Configure Jira project to send findings.
                </CardDescription>
              </CardHeader>
              <CardContent>
                <Accordion type="single" collapsible className="w-full">
                  <AccordionItem value="jira">
                    <AccordionTrigger className="cursor-pointer">
                      <span className="flex items-center gap-2">
                        <span className="inline-flex items-center justify-center rounded-md bg-blue-600 p-1.5">
                          <JiraIcon size={20} className="text-white" />
                        </span>
                        Jira
                      </span>
                    </AccordionTrigger>
                    <AccordionContent>
                      <p className="text-sm text-zinc-500 dark:text-zinc-400 mb-4">
                        Send guardrails findings to Jira as issues. Set the Jira project ID to link this integration to a project.
                      </p>
                      <div className="space-y-2 max-w-sm">
                        <Label htmlFor="guardrails-jira-project-id">Jira project ID</Label>
                        <Input
                          id="guardrails-jira-project-id"
                          value={jiraProjectId}
                          onChange={(e) => setJiraProjectId(e.target.value)}
                          placeholder="e.g. 10000"
                        />
                        <Button
                          onClick={() => {
                            updateIntegrationSettingsMutation.mutate({
                              integration_settings: {
                                jira: { jira_project_id: jiraProjectId.trim() || null },
                              },
                            });
                          }}
                          disabled={updateIntegrationSettingsMutation.isPending}
                          className="bg-blue-600 hover:bg-blue-700 text-white cursor-pointer mt-2"
                        >
                          {updateIntegrationSettingsMutation.isPending ? (
                            <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                          ) : (
                            <Save className="w-4 h-4 mr-2" />
                          )}
                          Save
                        </Button>
                      </div>
                    </AccordionContent>
                  </AccordionItem>
                </Accordion>
              </CardContent>
            </Card>
          )}

          {/* API Documentation Tab */}
          {activeTab === "docs" && <GuardrailsApiDocs />}
        </div>
      </div>
    </div>
  );
}
