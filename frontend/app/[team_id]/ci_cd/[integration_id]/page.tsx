"use client";

import { usePathname, useRouter } from "next/navigation";
import { useQuery, useQueryClient, useMutation } from "@tanstack/react-query";
import { useState, useEffect, useMemo } from "react";
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
import { Loader2, RefreshCcw, CheckCircle2, XCircle, Clock, PlayCircle, AlertCircle, Eye, Copy, Check, BarChart2, BookOpen, Settings, Ticket, Save, ChevronLeft, ChevronRight, TrendingUp } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { toast } from "sonner";
import { showErrorToast } from "@/utils/error-handler";
import { getCicdIntegrationDashboard, CicdIntegrationDashboard, updateCicdIntegration, UpdateCicdIntegrationData, type SastAppLang } from "@/utils/backend_api";
import Link from "next/link";
import { GitHubActionsGuide } from "@/components/GitHubActionsIntegrationGuide";
import { JenkinsGuide } from "@/components/JenkinsIntegrationGuide";
import { BambooGuide } from "@/components/BambooIntegrationGuide";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Accordion,
  AccordionContent,
  AccordionItem,
  AccordionTrigger,
} from "@/components/ui/accordion";
import { JiraIcon } from "@/components/icons/arcticons-jira";
import { SastScanSettingsForm } from "@/components/sast-scan-settings-form";
import { sanitizePathArrays } from "@/components/path-arrays-input";
import {
  ChartContainer,
  ChartTooltip,
  ChartTooltipContent,
  type ChartConfig,
} from "@/components/ui/chart";
import {
  Area,
  AreaChart,
  CartesianGrid,
  XAxis,
  YAxis,
} from "recharts";

const LOGS_PAGE_SIZE = 10;

const vulnsOverTimeChartConfig = {
  date: { label: "Date" },
  Critical: { label: "Critical", color: "hsl(0 84% 60%)" },
  High: { label: "High", color: "hsl(25 95% 53%)" },
  Medium: { label: "Medium", color: "hsl(48 96% 53%)" },
  Low: { label: "Low", color: "hsl(142 71% 45%)" },
} satisfies ChartConfig;

export default function CicdIntegrationDashboardPage() {
  const pathname = usePathname();
  const router = useRouter();
  const pathParts = pathname.split('/').filter(Boolean);
  const team_id = pathParts[0] ?? '';
  const integration_id = pathParts[2] ?? pathname.split('/').pop() ?? '';
  const queryClient = useQueryClient();
  const [copied, setCopied] = useState(false);
  const [activeTab, setActiveTab] = useState<"dashboard" | "integration-guide" | "scan-settings" | "ticketing">("dashboard");
  const [activeSubTab, setActiveSubTab] = useState<"github-actions" | "jenkins" | "bamboo">("github-actions");
  const [logsPage, setLogsPage] = useState(1);
  const logsOffset = (logsPage - 1) * LOGS_PAGE_SIZE;

  const [scanSettingsSast, setScanSettingsSast] = useState<{ app_lang: SastAppLang; exclude_path_arrays: string[][] }>({
    app_lang: "python",
    exclude_path_arrays: [],
  });
  const [jiraProjectId, setJiraProjectId] = useState("");

  const query = useQuery({
    queryKey: ['cicd-integration-dashboard', team_id, integration_id, LOGS_PAGE_SIZE, logsOffset],
    queryFn: getCicdIntegrationDashboard,
    enabled: !!team_id && !!integration_id,
  });

  useEffect(() => {
    setLogsPage(1);
  }, [team_id, integration_id]);

  const ss = query.data?.scan_settings?.sast;
  useEffect(() => {
    if (ss?.app_lang) setScanSettingsSast((prev) => ({ ...prev, app_lang: ss.app_lang as SastAppLang }));
    if (ss?.exclude_path_arrays) setScanSettingsSast((prev) => ({ ...prev, exclude_path_arrays: ss.exclude_path_arrays ?? [] }));
  }, [ss?.app_lang, ss?.exclude_path_arrays]);

  const isJira = query.data?.integration_settings?.jira;
  useEffect(() => {
    setJiraProjectId(isJira?.jira_project_id ?? "");
  }, [isJira?.jira_project_id]);

  const handleRefresh = () => {
    queryClient.invalidateQueries({ queryKey: ['cicd-integration-dashboard', team_id, integration_id, LOGS_PAGE_SIZE, logsOffset] });
  };

  const updateCicdMutation = useMutation({
    mutationFn: (data: UpdateCicdIntegrationData) =>
      updateCicdIntegration({
        team_id: Number(team_id),
        integration_id: Number(integration_id),
        data,
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['cicd-integration-dashboard', team_id, integration_id, LOGS_PAGE_SIZE, logsOffset] });
      toast.success("Integration updated successfully");
    },
    onError: (error) => {
      showErrorToast(error);
    },
  });

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

  const getStatusBadge = (status: string) => {
    const statusLower = status.toLowerCase();
    if (statusLower === "success") {
      return <Badge className="bg-green-500 hover:bg-green-600 text-white"><CheckCircle2 className="w-3 h-3 mr-1" />Success</Badge>;
    } else if (statusLower === "failure") {
      return <Badge className="bg-red-600 hover:bg-red-700 text-white"><XCircle className="w-3 h-3 mr-1" />Failed</Badge>;
    } else if (statusLower === "pending") {
      return <Badge className="bg-yellow-500 hover:bg-yellow-600 text-white"><Clock className="w-3 h-3 mr-1" />Pending</Badge>;
    } else if (statusLower === "started") {
      return <Badge className="bg-blue-500 hover:bg-blue-600 text-white"><PlayCircle className="w-3 h-3 mr-1" />Started</Badge>;
    } else if (statusLower === "not_started") {
      return <Badge className="bg-gray-500 hover:bg-gray-600 text-white"><AlertCircle className="w-3 h-3 mr-1" />Not Started</Badge>;
    }
    return <Badge variant="outline">{status}</Badge>;
  };

  const handleViewResults = (logId: string) => {
    router.push(`/${team_id}/ci_cd/${integration_id}/sast/results?log_id=${logId}`);
  };

  const dashboardData: CicdIntegrationDashboard = query.data ?? {
    cicd_integration_id: 0,
    title: "",
    created_at: "",
    last_updated: "",
    scan_type: "sast",
    api_key: "",
    integration_active: false,
    logs: [],
    dashboard_data: undefined,
  };

  const vulnsOverTimeChartArray = useMemo(() => {
    const raw = dashboardData.dashboard_data;
    if (!raw || typeof raw !== "object") return [];
    return Object.entries(raw)
      .map(([date, counts]) => ({
        date,
        Critical: counts?.Critical ?? 0,
        High: counts?.High ?? 0,
        Medium: counts?.Medium ?? 0,
        Low: counts?.Low ?? 0,
      }))
      .sort((a, b) => a.date.localeCompare(b.date));
  }, [dashboardData.dashboard_data]);

  const hasVulnsOverTimeData = vulnsOverTimeChartArray.length > 0 && vulnsOverTimeChartArray.some(
    (d) => d.Critical > 0 || d.High > 0 || d.Medium > 0 || d.Low > 0
  );

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
            <div className="flex gap-4 mb-8 overflow-x-auto">
              <Skeleton className="h-32 flex-1 min-w-[160px] rounded-lg" />
              <Skeleton className="h-32 flex-1 min-w-[160px] rounded-lg" />
              <Skeleton className="h-32 flex-1 min-w-[160px] rounded-lg" />
              <Skeleton className="h-32 flex-1 min-w-[160px] rounded-lg" />
              <Skeleton className="h-32 flex-1 min-w-[160px] rounded-lg" />
              <Skeleton className="h-32 flex-1 min-w-[160px] rounded-lg" />
            </div>
            <Skeleton className="h-96 w-full" />
          </div>
        </div>
      </div>
    );
  }

  const hasNextLogsPage = dashboardData.logs.length === LOGS_PAGE_SIZE;
  const showLogsPagination = dashboardData.logs.length > 0 || logsPage > 1;

  // Calculate metrics from current page logs
  const totalLogs = dashboardData.logs.length;
  const successfulLogs = dashboardData.logs.filter(log => log.status.toLowerCase() === "success").length;
  const failedLogs = dashboardData.logs.filter(log => log.status.toLowerCase() === "failure").length;
  const pendingLogs = dashboardData.logs.filter(log => log.status.toLowerCase() === "pending").length;
  const startedLogs = dashboardData.logs.filter(log => log.status.toLowerCase() === "started").length;
  const notStartedLogs = dashboardData.logs.filter(log => log.status.toLowerCase() === "not_started").length;

  const metricsCards = [
    {
      title: "Total Scans",
      value: totalLogs,
      description: "Total number of scans",
    },
    {
      title: "Successful",
      value: successfulLogs,
      description: "Successfully completed scans",
    },
    {
      title: "Failed",
      value: failedLogs,
      description: "Failed scans",
    },
    {
      title: "Pending",
      value: pendingLogs,
      description: "Scans waiting to be processed",
    },
    {
      title: "Started",
      value: startedLogs,
      description: "Scans currently running",
    },
    {
      title: "Not Started",
      value: notStartedLogs,
      description: "Scans not yet started",
    },
  ];

  return (
    <div className="flex h-screen bg-white dark:bg-zinc-900">
      <div className="flex-1 p-8 overflow-auto">
        <div className="max-w-7xl mx-auto">
          {/* Header */}
          <div className="mb-8 flex justify-between items-start">
            <div className="flex-1">
              <div className="flex items-center gap-3 mb-2">
                <Link 
                  href={`/${team_id}/ci_cd`}
                  className="text-blue-600 hover:text-blue-700 dark:text-blue-400 dark:hover:text-blue-300 text-sm font-medium"
                >
                  ← Back to Integrations
                </Link>
              </div>
              <h1 className="text-3xl font-bold text-zinc-900 dark:text-white mb-2">
                {dashboardData.title}
              </h1>
              <div className="flex flex-wrap items-center gap-4 mt-4">
                <div className="flex items-center gap-2">
                  <span className="text-sm text-zinc-600 dark:text-zinc-400">Scan Type:</span>
                  <Badge variant="outline" className="capitalize">
                    {dashboardData.scan_type}
                  </Badge>
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-sm text-zinc-600 dark:text-zinc-400">Created:</span>
                  <span className="text-sm text-zinc-900 dark:text-zinc-100">
                    {formatDate(dashboardData.created_at)}
                  </span>
                </div>
              </div>
              <div className="flex flex-row items-center gap-2 mt-4">
                <p className="text-zinc-600 dark:text-zinc-400 text-sm font-medium">Copy API Key:</p>
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

          {/* Main Tabs */}
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
              onClick={() => setActiveTab("scan-settings")}
              className={`px-4 py-2 font-medium text-sm transition-colors border-b-2 cursor-pointer ${
                activeTab === "scan-settings"
                  ? "border-blue-600 text-blue-600 dark:text-blue-400"
                  : "border-transparent text-zinc-600 dark:text-zinc-400 hover:text-zinc-900 dark:hover:text-zinc-100"
              }`}
            >
              <div className="flex items-center gap-2">
                <Settings className="w-4 h-4" />
                Scan settings
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
                Ticketing settings
              </div>
            </button>
            <button
              onClick={() => setActiveTab("integration-guide")}
              className={`px-4 py-2 font-medium text-sm transition-colors border-b-2 cursor-pointer ${
                activeTab === "integration-guide"
                  ? "border-blue-600 text-blue-600 dark:text-blue-400"
                  : "border-transparent text-zinc-600 dark:text-zinc-400 hover:text-zinc-900 dark:hover:text-zinc-100"
              }`}
            >
              <div className="flex items-center gap-2">
                <BookOpen className="w-4 h-4" />
                Integration Guide
              </div>
            </button>
          </div>

          {/* Dashboard Tab Content */}
          {activeTab === "dashboard" && (
            <>
              {dashboardData.integration_active === false && (
                <div className="mb-6 rounded-lg border border-amber-200 bg-amber-50 dark:border-amber-800 dark:bg-amber-950/40 px-4 py-3 text-amber-800 dark:text-amber-200">
                  <p className="font-medium">Dashboard not active, configure the scanner</p>
                  <p className="text-sm mt-1 opacity-90">
                    Go to the <button type="button" onClick={() => setActiveTab("scan-settings")} className="underline cursor-pointer font-medium">Scan settings</button> tab to configure scan settings and activate the dashboard.
                  </p>
                </div>
              )}
              {/* Metrics Cards */}
              <div className="flex gap-4 mb-8 overflow-x-auto">
            {metricsCards.map((metric, index) => (
              <Card key={index} className="flex-1 min-w-[160px] border-zinc-200 dark:border-zinc-800 shadow-sm">
                <CardHeader className="pb-3">
                  <CardTitle className="text-xs font-semibold text-zinc-600 dark:text-zinc-400 uppercase tracking-wider">
                    {metric.title}
                  </CardTitle>
                </CardHeader>
                <CardContent className="pt-0">
                  <div className="text-3xl font-bold text-zinc-900 dark:text-white mb-1.5">
                    {metric.value}
                  </div>
                  <p className="text-xs text-zinc-500 dark:text-zinc-500 leading-relaxed">
                    {metric.description}
                  </p>
                </CardContent>
              </Card>
            ))}
          </div>

          {/* Vulnerabilities over time chart */}
          <Card className="mb-8 border-zinc-200 dark:border-zinc-800">
            <CardHeader>
              <CardTitle className="text-base flex items-center gap-2">
                <TrendingUp className="w-4 h-4" />
                Vulnerabilities over time by severity
              </CardTitle>
              <CardDescription>
                Count of findings per scan date by impact (Critical, High, Medium, Low)
              </CardDescription>
            </CardHeader>
            <CardContent>
              {!hasVulnsOverTimeData ? (
                <div className="flex items-center justify-center min-h-[280px] text-zinc-500 dark:text-zinc-400 text-sm">
                  No vulnerability data to display. Run scans to see trends over time.
                </div>
              ) : (
                <ChartContainer config={vulnsOverTimeChartConfig} className="aspect-auto h-[280px] w-full pb-8">
                  <AreaChart data={vulnsOverTimeChartArray} margin={{ top: 8, right: 8, bottom: 28, left: 0 }}>
                    <defs>
                      <linearGradient id="fillCicdCritical" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="hsl(0 84% 60%)" stopOpacity={0.8} />
                        <stop offset="95%" stopColor="hsl(0 84% 60%)" stopOpacity={0.1} />
                      </linearGradient>
                      <linearGradient id="fillCicdHigh" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="hsl(25 95% 53%)" stopOpacity={0.8} />
                        <stop offset="95%" stopColor="hsl(25 95% 53%)" stopOpacity={0.1} />
                      </linearGradient>
                      <linearGradient id="fillCicdMedium" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="hsl(48 96% 53%)" stopOpacity={0.8} />
                        <stop offset="95%" stopColor="hsl(48 96% 53%)" stopOpacity={0.1} />
                      </linearGradient>
                      <linearGradient id="fillCicdLow" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="hsl(142 71% 45%)" stopOpacity={0.8} />
                        <stop offset="95%" stopColor="hsl(142 71% 45%)" stopOpacity={0.1} />
                      </linearGradient>
                    </defs>
                    <CartesianGrid vertical={false} className="stroke-zinc-200 dark:stroke-zinc-800" />
                    <XAxis
                      dataKey="date"
                      tickLine={false}
                      axisLine={false}
                      tickMargin={8}
                      minTickGap={24}
                      height={40}
                      tickFormatter={(v) => {
                        const d = new Date(v);
                        return d.toLocaleDateString("en-US", { month: "short", day: "numeric", year: "2-digit" });
                      }}
                    />
                    <YAxis hide domain={[0, "auto"]} />
                    <ChartTooltip
                      cursor={false}
                      content={
                        <ChartTooltipContent
                          labelFormatter={(v) => new Date(v).toLocaleDateString("en-US", { dateStyle: "medium" })}
                        />
                      }
                    />
                    <Area type="monotone" dataKey="Critical" fill="url(#fillCicdCritical)" stroke="hsl(0 84% 60%)" strokeWidth={2} />
                    <Area type="monotone" dataKey="High" fill="url(#fillCicdHigh)" stroke="hsl(25 95% 53%)" strokeWidth={2} />
                    <Area type="monotone" dataKey="Medium" fill="url(#fillCicdMedium)" stroke="hsl(48 96% 53%)" strokeWidth={2} />
                    <Area type="monotone" dataKey="Low" fill="url(#fillCicdLow)" stroke="hsl(142 71% 45%)" strokeWidth={2} />
                  </AreaChart>
                </ChartContainer>
              )}
            </CardContent>
          </Card>

          {/* Logs Table */}
          <Card>
            <CardHeader>
              <CardTitle>Scan Logs</CardTitle>
              <CardDescription>
                View all scan logs for this integration
              </CardDescription>
            </CardHeader>
            {showLogsPagination && (
              <div className="flex items-center justify-between gap-4 px-6 py-3 border-t border-zinc-200 dark:border-zinc-800 bg-zinc-50/50 dark:bg-zinc-900/30">
                <span className="text-sm text-zinc-600 dark:text-zinc-400">
                  {dashboardData.logs.length > 0
                    ? `Showing logs ${logsOffset + 1} to ${logsOffset + dashboardData.logs.length}`
                    : `Page ${logsPage}`}
                </span>
                <div className="flex items-center gap-1">
                  <Button
                    variant="outline"
                    size="icon"
                    className="h-8 w-8 cursor-pointer"
                    disabled={logsPage <= 1}
                    onClick={() => setLogsPage((p) => Math.max(1, p - 1))}
                    aria-label="Previous page"
                  >
                    <ChevronLeft className="h-4 w-4" />
                  </Button>
                  <Button
                    variant="outline"
                    size="icon"
                    className="h-8 w-8 cursor-pointer"
                    disabled={!hasNextLogsPage}
                    onClick={() => setLogsPage((p) => p + 1)}
                    aria-label="Next page"
                  >
                    <ChevronRight className="h-4 w-4" />
                  </Button>
                </div>
              </div>
            )}
            <CardContent>
              {dashboardData.logs.length === 0 ? (
                <div className="text-center py-12">
                  <p className="text-zinc-600 dark:text-zinc-400 mb-4">
                    No scan logs yet. Scans will appear here once they are submitted.
                  </p>
                </div>
              ) : (
                <div className="border rounded-lg overflow-hidden">
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>Scan ID</TableHead>
                        <TableHead>Status</TableHead>
                        <TableHead>Credits</TableHead>
                        <TableHead>Error</TableHead>
                        <TableHead>Created At</TableHead>
                        <TableHead className="text-right">Actions</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {dashboardData.logs.map((log) => (
                        <TableRow key={log.id} className="hover:bg-zinc-50 dark:hover:bg-zinc-800">
                          <TableCell className="font-mono text-sm">
                            {log.id.toString().slice(-8)}
                          </TableCell>
                          <TableCell>
                            {getStatusBadge(log.status)}
                          </TableCell>
                          <TableCell className="text-zinc-600 dark:text-zinc-400 font-mono tabular-nums">
                            {log.credits_consumed != null ? log.credits_consumed : "—"}
                          </TableCell>
                          <TableCell className="text-zinc-600 dark:text-zinc-400 max-w-[200px]" title={log.error != null ? String(log.error) : undefined}>
                            <span className="block truncate">
                              {log.error != null ? String(log.error) : "—"}
                            </span>
                          </TableCell>
                          <TableCell className="text-zinc-600 dark:text-zinc-400">
                            {formatDate(log.created_at)}
                          </TableCell>
                          <TableCell className="text-right">
                            {log.status.toLowerCase() === "success" && (
                              <Button
                                variant="outline"
                                size="sm"
                                className="cursor-pointer"
                                onClick={() => handleViewResults(log.id)}
                              >
                                <Eye className="h-4 w-4 mr-2" />
                                View Results
                              </Button>
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

          {/* Scan settings Tab */}
          {activeTab === "scan-settings" && (
            <Card>
              <CardHeader>
                <CardTitle>Scan settings</CardTitle>
                <CardDescription>
                  Configure scan options for this CI/CD integration. These settings are used when scans are triggered.
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-6">
                {dashboardData.scan_type?.toLowerCase() === "sast" ? (
                  <SastScanSettingsForm
                    appLang={scanSettingsSast.app_lang}
                    onAppLangChange={(value) => setScanSettingsSast((prev) => ({ ...prev, app_lang: value }))}
                    excludePathArrays={scanSettingsSast.exclude_path_arrays}
                    onExcludePathArraysChange={(value) => setScanSettingsSast((prev) => ({ ...prev, exclude_path_arrays: value }))}
                    onSaveClick={() => {
                      const sanitized = sanitizePathArrays(scanSettingsSast.exclude_path_arrays);
                      updateCicdMutation.mutate({
                        scan_settings: {
                          sast: {
                            app_lang: scanSettingsSast.app_lang,
                            exclude_path_arrays: sanitized.length > 0 ? sanitized : null,
                          },
                        },
                      });
                    }}
                    isSaving={updateCicdMutation.isPending}
                  />
                ) : (
                  <p className="text-sm text-zinc-500 dark:text-zinc-400">
                    Scan settings are only available for SAST integrations. This integration uses scan type: {dashboardData.scan_type}.
                  </p>
                )}
              </CardContent>
            </Card>
          )}

          {/* Ticketing settings Tab */}
          {activeTab === "ticketing" && (
            <Card>
              <CardHeader>
                <CardTitle>Ticketing settings</CardTitle>
                <CardDescription>
                  Connect this CI/CD integration to ticketing systems. Configure Jira to send findings.
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
                        Send CI/CD scan findings to Jira as issues. Set the Jira project ID to link this integration to a project.
                      </p>
                      <div className="space-y-2 max-w-sm">
                        <Label htmlFor="cicd-jira-project-id">Jira project ID</Label>
                        <Input
                          id="cicd-jira-project-id"
                          value={jiraProjectId}
                          onChange={(e) => setJiraProjectId(e.target.value)}
                          placeholder="e.g. 10000"
                        />
                        <Button
                          onClick={() => {
                            updateCicdMutation.mutate({
                              integration_settings: {
                                jira: { jira_project_id: jiraProjectId.trim() || null },
                              },
                            });
                          }}
                          disabled={updateCicdMutation.isPending}
                          className="bg-blue-600 hover:bg-blue-700 text-white cursor-pointer mt-2"
                        >
                          {updateCicdMutation.isPending ? <Loader2 className="w-4 h-4 mr-2 animate-spin" /> : <Save className="w-4 h-4 mr-2" />}
                          Save
                        </Button>
                      </div>
                    </AccordionContent>
                  </AccordionItem>
                </Accordion>
              </CardContent>
            </Card>
          )}

          {/* Integration Guide Tab Content */}
          {activeTab === "integration-guide" && (
            <div className="space-y-6">
              {/* Sub-tabs */}
              <div className="flex gap-2 mb-6 border-b border-zinc-200 dark:border-zinc-800">
                <button
                  onClick={() => setActiveSubTab("github-actions")}
                  className={`px-4 py-2 font-medium text-sm transition-colors border-b-2 cursor-pointer ${
                    activeSubTab === "github-actions"
                      ? "border-blue-600 text-blue-600 dark:text-blue-400"
                      : "border-transparent text-zinc-600 dark:text-zinc-400 hover:text-zinc-900 dark:hover:text-zinc-100"
                  }`}
                >
                  GitHub Actions
                </button>
                <button
                  onClick={() => setActiveSubTab("jenkins")}
                  className={`px-4 py-2 font-medium text-sm transition-colors border-b-2 cursor-pointer ${
                    activeSubTab === "jenkins"
                      ? "border-blue-600 text-blue-600 dark:text-blue-400"
                      : "border-transparent text-zinc-600 dark:text-zinc-400 hover:text-zinc-900 dark:hover:text-zinc-100"
                  }`}
                >
                  Jenkins
                </button>
                <button
                  onClick={() => setActiveSubTab("bamboo")}
                  className={`px-4 py-2 font-medium text-sm transition-colors border-b-2 cursor-pointer ${
                    activeSubTab === "bamboo"
                      ? "border-blue-600 text-blue-600 dark:text-blue-400"
                      : "border-transparent text-zinc-600 dark:text-zinc-400 hover:text-zinc-900 dark:hover:text-zinc-100"
                  }`}
                >
                  Atlassian Bamboo
                </button>
              </div>

              {/* Sub-tab Content */}
              {activeSubTab === "github-actions" && (
                <GitHubActionsGuide apiKey={dashboardData.api_key} />
              )}

              {activeSubTab === "jenkins" && (
                <JenkinsGuide apiKey={dashboardData.api_key} />
              )}

              {activeSubTab === "bamboo" && (
                <BambooGuide apiKey={dashboardData.api_key} />
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

