"use client";

import { usePathname } from "next/navigation";
import { useQuery, useQueryClient, useMutation } from "@tanstack/react-query";
import { useState, useEffect } from "react";
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
import { Loader2, RefreshCcw, CheckCircle2, XCircle, Clock, PlayCircle, AlertCircle, BarChart3, CheckCircle, X, Hourglass, Play, Square, Copy, Check, Settings, BarChart2, Save, Plus, BookOpen } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { toast } from "sonner";
import { showErrorToast } from "@/utils/error-handler";
import SettingsForm from "@/components/Settings";
import { defaultLanguages } from "@/components/Settings";
import { ScrollArea } from "@/components/ui/scroll-area";
import GuardrailsApiDocs from "@/components/GuardrailsApiDocs";


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
  const scannerKeys = Object.keys(metadata).filter(key => {
    const value = metadata[key];
    return (
      value &&
      typeof value === 'object' &&
      !Array.isArray(value) &&
      ('valid' in value || 'score' in value)
    );
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
        const isValid = scannerData?.valid !== undefined ? scannerData.valid : true;
        const riskScore = scannerData?.score !== undefined ? scannerData.score : null;

        return (
          <div
            key={scannerKey}
            className="border border-zinc-200 dark:border-zinc-700 rounded-lg p-3 bg-zinc-50 dark:bg-zinc-900/50 hover:bg-zinc-100 dark:hover:bg-zinc-900 transition-colors"
          >
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm font-semibold text-zinc-900 dark:text-white">
                {scannerName}
              </span>
              <Badge
                className={
                  isValid
                    ? "bg-green-500 hover:bg-green-600 text-white"
                    : "bg-red-500 hover:bg-red-600 text-white"
                }
              >
                {isValid ? (
                  <>
                    <CheckCircle2 className="w-3 h-3 mr-1" />
                    Passed
                  </>
                ) : (
                  <>
                    <XCircle className="w-3 h-3 mr-1" />
                    Flagged
                  </>
                )}
              </Badge>
            </div>
            {riskScore !== null && (
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
                    {riskScore.toFixed(3)}
                  </span>
                </div>
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
};

export default function GuardrailsIntegrationDashboardPage() {
  const pathname = usePathname();
  const integration_id = pathname.split('/').pop() || '';
  const queryClient = useQueryClient();
  const [copied, setCopied] = useState(false);
  const [activeTab, setActiveTab] = useState<"dashboard" | "settings" | "docs">("dashboard");
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

  const query = useQuery({
    queryKey: ['guardrails-integration-dashboard', integration_id],
    queryFn: getGuardrailsIntegrationDashboard,
  });

  const handleRefresh = () => {
    queryClient.invalidateQueries({ queryKey: ['guardrails-integration-dashboard', integration_id] });
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

  const updateSettingsMutation = useMutation({
    mutationFn: (data: UpdateGuardrailsIntegrationData) => 
      updateGuardrailsIntegration(parseInt(integration_id), data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['guardrails-integration-dashboard', integration_id] });
      setEditSettings(false);
      toast.success('Settings updated successfully');
    },
    onError: (error) => {
      showErrorToast(error);
    }
  });

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

  const dashboardData: GuardrailsIntegrationDashboard = query.data || {
    total_logs: 0,
    successful_logs: 0,
    failed_logs: 0,
    pending_logs: 0,
    started_logs: 0,
    not_started_logs: 0,
    api_key: "",
    log_data: [],
    settings: {
      anonymize_context: { preamble: "", threshold: 0.1, allowed_names: [] },
      toxicity_context: { threshold: 0.1 },
      tokenlimit_context: { max_tokens: 2000 },
      promptinjection_context: { threshold: 0.1 },
      regex_context: { regex_patterns: [], redact: false },
      code_context: { languages: defaultLanguages, is_blocked: true },
      secrets_context: { redact_mode: "REDACT_PARTIAL" },
    } as SettingsData,
  };

  const metricsCards = [
    {
      title: "Total Logs",
      value: dashboardData.total_logs,
      description: "Total number of logs",
      icon: BarChart3,
    },
    {
      title: "Successful",
      value: dashboardData.successful_logs,
      description: "Successfully processed logs",
      icon: CheckCircle,
    },
    {
      title: "Failed",
      value: dashboardData.failed_logs,
      description: "Failed logs",
      icon: XCircle,
    },
    {
      title: "Pending",
      value: dashboardData.pending_logs,
      description: "Logs waiting to be processed",
      icon: Hourglass,
    },
    {
      title: "Started",
      value: dashboardData.started_logs,
      description: "Logs currently being processed",
      icon: Play,
    },
    {
      title: "Not Started",
      value: dashboardData.not_started_logs,
      description: "Logs not yet started",
      icon: Square,
    },
  ];

  return (
    <div className="flex h-screen bg-white dark:bg-zinc-900">
      <div className="flex-1 p-8 overflow-auto">
        <div className="max-w-7xl mx-auto">
          {/* Header */}
          <div className="mb-8 flex justify-between items-center">
            <div>
              <h1 className="text-3xl font-bold text-zinc-900 dark:text-white mb-2">
                Guardrails Integration Dashboard
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
              className="flex items-center gap-2 bg-teal-600 hover:bg-teal-700 text-white cursor-pointer hover:text-white"
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
                  ? "border-teal-600 text-teal-600 dark:text-teal-400"
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
                  ? "border-teal-600 text-teal-600 dark:text-teal-400"
                  : "border-transparent text-zinc-600 dark:text-zinc-400 hover:text-zinc-900 dark:hover:text-zinc-100"
              }`}
            >
              <div className="flex items-center gap-2">
                <Settings className="w-4 h-4" />
                Settings
              </div>
            </button>
            <button
              onClick={() => setActiveTab("docs")}
              className={`px-4 py-2 font-medium text-sm transition-colors border-b-2 cursor-pointer ${
                activeTab === "docs"
                  ? "border-teal-600 text-teal-600 dark:text-teal-400"
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
              {/* Metrics Cards */}
              <div className="flex flex-row gap-3 mb-8 overflow-x-auto">
                {metricsCards.map((card) => {
                  const IconComponent = card.icon;
                  return (
                    <div 
                      key={card.title} 
                      className="flex-1 min-w-0 border border-zinc-200 dark:border-zinc-800 rounded-lg p-4 bg-transparent hover:bg-zinc-50 dark:hover:bg-zinc-900/50 transition-colors"
                    >
                      <div className="flex items-center justify-between mb-2">
                        <span className="text-xs font-medium text-zinc-500 dark:text-zinc-400 uppercase tracking-wide">
                          {card.title}
                        </span>
                        <IconComponent className="w-4 h-4 text-zinc-400 dark:text-zinc-500" />
                      </div>
                      <div className="text-2xl font-semibold text-zinc-900 dark:text-zinc-100">
                        {card.value}
                      </div>
                    </div>
                  );
                })}
              </div>

              {/* Logs Table */}
              <Card>
                <CardHeader>
                  <CardTitle>Logs</CardTitle>
                  <CardDescription>
                    All logs for this integration ({dashboardData.log_data.length} total)
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  {dashboardData.log_data.length === 0 ? (
                    <div className="text-center py-12 text-zinc-600 dark:text-zinc-400">
                      No logs found for this integration
                    </div>
                  ) : (
                    <div className="overflow-x-auto">
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
                          {dashboardData.log_data.map((log) => (
                            <TableRow key={log.id}>
                              <TableCell className="font-mono text-sm w-28 min-w-28">
                                <div className="whitespace-nowrap overflow-visible">{log.id.toString().slice(-8)}</div>
                              </TableCell>
                              <TableCell>
                                {getStatusBadge(log.status)}
                              </TableCell>
                              <TableCell className="max-w-48">
                                <ScrollArea className="h-24 w-full">
                                    <p className="text-sm whitespace-normal pr-2" style={{ wordBreak: 'break-word', overflowWrap: 'break-word' }}>{log.input_prompt || "-"}</p>
                                </ScrollArea>
                              </TableCell>
                              <TableCell>
                                {log.created_at ? formatDate(log.created_at) : "-"}
                              </TableCell>
                              <TableCell>
                                {log.results ? (
                                  <ScrollArea className="max-w-48 h-24 w-full">
                                    <p className="text-sm whitespace-normal pr-2" style={{ wordBreak: 'break-word', overflowWrap: 'break-word' }}>{log.results.sanitized_prompt || "-"}</p>
                                  </ScrollArea>
                                ) : (
                                  <span className="text-zinc-400">-</span>
                                )}
                              </TableCell>
                              <TableCell>
                                {log.results ? (
                                  <ScrollArea className="max-w-md h-64">
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
                    <CardTitle>Integration Settings</CardTitle>
                    <CardDescription className="mt-2">
                      View and edit guardrails integration settings
                    </CardDescription>
                  </div>
                  {!editSettings ? (
                    <Button
                      onClick={() => setEditSettings(true)}
                      className="bg-teal-600 hover:bg-teal-700 text-white"
                    >
                      <Settings className="w-4 h-4 mr-2" />
                      Edit Settings
                    </Button>
                  ) : (
                    <div className="flex gap-2">
                      <Button
                        variant="outline"
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
                        className="bg-teal-600 hover:bg-teal-700 text-white"
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

          {/* API Documentation Tab */}
          {activeTab === "docs" && <GuardrailsApiDocs />}
        </div>
      </div>
    </div>
  );
}
