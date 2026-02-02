"use client";

import { usePathname, useRouter } from "next/navigation";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
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
import { Loader2, RefreshCcw, CheckCircle2, XCircle, Clock, PlayCircle, AlertCircle, Eye, Copy, Check, BarChart2, BookOpen } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { toast } from "sonner";
import { showErrorToast } from "@/utils/error-handler";
import { getCicdIntegrationDashboard, CicdIntegrationDashboard } from "@/utils/backend_api";
import Link from "next/link";
import { GitHubActionsGuide } from "@/components/GitHubActionsIntegrationGuide";
import { JenkinsGuide } from "@/components/JenkinsIntegrationGuide";
import { BambooGuide } from "@/components/BambooIntegrationGuide";

export default function CicdIntegrationDashboardPage() {
  const pathname = usePathname();
  const router = useRouter();
  const pathParts = pathname.split('/').filter(Boolean);
  const team_id = pathParts[0] ?? '';
  const integration_id = pathParts[2] ?? pathname.split('/').pop() ?? '';
  const queryClient = useQueryClient();
  const [copied, setCopied] = useState(false);
  const [activeTab, setActiveTab] = useState<"dashboard" | "integration-guide">("dashboard");
  const [activeSubTab, setActiveSubTab] = useState<"github-actions" | "jenkins" | "bamboo">("github-actions");

  const query = useQuery({
    queryKey: ['cicd-integration-dashboard', team_id, integration_id],
    queryFn: getCicdIntegrationDashboard,
    enabled: !!team_id && !!integration_id,
  });

  const handleRefresh = () => {
    queryClient.invalidateQueries({ queryKey: ['cicd-integration-dashboard', team_id, integration_id] });
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

  const dashboardData: CicdIntegrationDashboard = query.data || {
    cicd_integration_id: 0,
    title: "",
    created_at: "",
    last_updated: "",
    scan_type: "sast",
    api_key: "",
    logs: [],
  };

  // Calculate metrics from logs
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

          {/* Logs Table */}
          <Card>
            <CardHeader>
              <CardTitle>Scan Logs</CardTitle>
              <CardDescription>
                View all scan logs for this integration
              </CardDescription>
            </CardHeader>
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

