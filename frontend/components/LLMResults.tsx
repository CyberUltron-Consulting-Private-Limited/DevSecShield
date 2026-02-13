"use client";

import { useState, useEffect, useMemo } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Checkbox } from "@/components/ui/checkbox";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { ArrowLeft, MessageCircle, Download, RefreshCcw, BarChart3, Ticket, PieChart as PieChartIcon, Activity, Shield } from "lucide-react";
import { ScrollArea } from "@/components/ui/scroll-area";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { useRouter, useSearchParams, useParams } from "next/navigation";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { COMPLIANCE_KEY_TO_LABEL, OWASP_LLM_KEY_TO_LABEL } from "@/lib/owasp-compliance-labels";
import { updateScan, createTicket } from "@/utils/backend_api";
import type { ScanTicketingIntegrationSettings, LLMDashboardData } from "@/utils/backend_api";
import { showErrorToast } from "@/utils/error-handler";
import FindingSelectionMenu from "@/components/finding-selection-menu";
import TicketingIntegrationsSettings from "@/components/ticketing-integrations-settings";
import {
  ChartContainer,
  ChartTooltip,
  ChartTooltipContent,
  type ChartConfig,
} from "@/components/ui/chart";
import { RadarChart, Radar, PolarGrid, PolarAngleAxis, RadialBarChart, RadialBar, PieChart, Pie, Cell } from "recharts";

// LLM Benchmark agent output: list of vulnerabilities (FinalLLMBenchmarkingVulnerabilities.vulnerabilities)
// Schema: title, description, impact, owasp_top_10_llm, compliance_controls, suggested_fix
type OwaspOrComplianceItem = Record<string, string>;
type OwaspOrCompliance = Record<string, string> | Array<OwaspOrComplianceItem> | null | undefined;

export interface LLMBenchmarkingVulnerability {
  title?: string | null;
  description?: string | null;
  impact?: string | null;
  owasp_top_10_llm?: OwaspOrCompliance;
  compliance_controls?: OwaspOrCompliance;
  suggested_fix?: string | null;
  cves?: unknown[] | Record<string, unknown> | null;
}

/** Normalized: either array of vulns or { vulnerabilities: array } */
type LLMResultsData =
  | LLMBenchmarkingVulnerability[]
  | { vulnerabilities?: LLMBenchmarkingVulnerability[] };

interface LLMResultsProps {
  data: LLMResultsData | null | undefined;
  dashboard?: LLMDashboardData | null;
  conversationId?: number;
  teamId?: string;
  integrationSettings?: Record<string, unknown> | null;
  onIntegrationSettingsUpdated?: () => void;
  onRefresh?: () => void;
  onDownloadReport?: () => void;
  isExporting?: boolean;
}

const RISK_ORDER = ["Critical", "High", "Medium", "Low"] as const;

function formatOwaspOrComplianceItem(item: OwaspOrComplianceItem): string {
  if (item == null || typeof item !== "object") return "—";
  const entries = Object.entries(item).filter(([, v]) => v != null && String(v).trim() !== "");
  if (entries.length === 0) return Object.keys(item)[0] ?? "—";
  return entries[0][1];
}

function getOwaspComplianceCount(val: OwaspOrCompliance): number {
  if (val == null) return 0;
  if (Array.isArray(val)) return val.length;
  if (typeof val === "object" && !Array.isArray(val)) return Object.keys(val).length;
  return 0;
}

function getOwaspComplianceEntries(val: OwaspOrCompliance): [string, string][] {
  if (val == null) return [];
  if (Array.isArray(val)) {
    return val.map((item) => {
      const s = formatOwaspOrComplianceItem(item);
      const k = item && typeof item === "object" ? Object.keys(item)[0] ?? s : s;
      return [k, s] as [string, string];
    });
  }
  if (typeof val === "object" && !Array.isArray(val)) {
    return Object.entries(val).filter(([, v]) => v != null && String(v).trim() !== "") as [string, string][];
  }
  return [];
}

function getImpactBadgeClass(impact: string): string {
  const i = (impact || "").toLowerCase();
  if (i === "critical") return "bg-red-600 hover:bg-red-700 text-white";
  if (i === "high") return "bg-orange-500 hover:bg-orange-600 text-white";
  if (i === "medium") return "bg-amber-500 hover:bg-amber-600 text-white";
  if (i === "low") return "bg-blue-500 hover:bg-blue-600 text-white";
  return "bg-zinc-500 hover:bg-zinc-600 text-white";
}

function normalizeVulnerabilities(data: LLMResultsData | null | undefined): LLMBenchmarkingVulnerability[] {
  if (data == null) return [];
  if (Array.isArray(data)) return data;
  if (data && typeof data === "object" && Array.isArray((data as { vulnerabilities?: LLMBenchmarkingVulnerability[] }).vulnerabilities)) {
    return (data as { vulnerabilities: LLMBenchmarkingVulnerability[] }).vulnerabilities;
  }
  return [];
}

function deriveLLMDashboard(vulnerabilities: LLMBenchmarkingVulnerability[]): LLMDashboardData {
  const owasp_top_10_llm_metrics: Record<string, number> = {};
  const compliance_controls_metrics: Record<string, number> = {};
  const risk_metrics: { Low: number; Medium: number; High: number; Critical: number } = { Low: 0, Medium: 0, High: 0, Critical: 0 };
  for (const v of vulnerabilities) {
    const owasp = v.owasp_top_10_llm;
    if (owasp && typeof owasp === "object" && !Array.isArray(owasp)) {
      for (const key of Object.keys(owasp)) {
        owasp_top_10_llm_metrics[key] = (owasp_top_10_llm_metrics[key] ?? 0) + 1;
      }
    }
    const comp = v.compliance_controls;
    if (comp && typeof comp === "object" && !Array.isArray(comp)) {
      for (const key of Object.keys(comp)) {
        compliance_controls_metrics[key] = (compliance_controls_metrics[key] ?? 0) + 1;
      }
    }
    const impactRaw = (v.impact ?? "").trim();
    const impact = impactRaw.charAt(0).toUpperCase() + impactRaw.slice(1).toLowerCase();
    if (impact && ["Low", "Medium", "High", "Critical"].includes(impact)) {
      risk_metrics[impact as keyof typeof risk_metrics] += 1;
    }
  }
  return { owasp_top_10_llm_metrics, compliance_controls_metrics, risk_metrics };
}

export default function LLMResults({ data, dashboard, conversationId, teamId: teamIdProp, integrationSettings, onIntegrationSettingsUpdated, onRefresh, onDownloadReport, isExporting }: LLMResultsProps) {
  const router = useRouter();
  const params = useParams();
  const searchParams = useSearchParams();
  const queryClient = useQueryClient();
  const origin = searchParams.get("origin");
  const teamId = teamIdProp ?? (params?.team_id as string | undefined);

  const vulnerabilities = normalizeVulnerabilities(data);
  const dashboardData = useMemo<LLMDashboardData | null>(() => {
    if (dashboard && (Object.keys(dashboard.owasp_top_10_llm_metrics ?? {}).length > 0 || Object.keys(dashboard.compliance_controls_metrics ?? {}).length > 0 || Object.values(dashboard.risk_metrics ?? {}).some((n) => n > 0))) {
      return dashboard;
    }
    if (vulnerabilities.length === 0) return null;
    return deriveLLMDashboard(vulnerabilities);
  }, [dashboard, vulnerabilities]);
  const [detailDialogOpen, setDetailDialogOpen] = useState(false);
  const [selectedVuln, setSelectedVuln] = useState<LLMBenchmarkingVulnerability | null>(null);
  const [activeTab, setActiveTab] = useState<"results" | "ticketing">("results");
  const [selectedRows, setSelectedRows] = useState<Set<number>>(new Set());
  const [jiraProjectId, setJiraProjectId] = useState("");

  const jiraFromSettings =
    integrationSettings && typeof integrationSettings === "object" && "jira" in integrationSettings
      ? (integrationSettings.jira as { jira_project_id?: string } | undefined)
      : undefined;
  const initialJiraProjectId = jiraFromSettings?.jira_project_id ?? "";
  useEffect(() => {
    setJiraProjectId(initialJiraProjectId);
  }, [initialJiraProjectId]);

  const updateIntegrationMutation = useMutation({
    mutationFn: (payload: { integration_settings: ScanTicketingIntegrationSettings }) =>
      updateScan({
        team_id: parseInt(teamId ?? "0", 10),
        type: "llm",
        scan_id: conversationId!,
        data: payload,
      }),
    onSuccess: () => {
      onIntegrationSettingsUpdated?.();
      const tid = parseInt(teamId ?? "0", 10);
      if (conversationId != null && tid > 0) {
        queryClient.invalidateQueries({ queryKey: ["llm-conversation-data", tid, conversationId] });
      }
      toast.success("Ticketing settings saved");
    },
    onError: (err) => {
      showErrorToast(err, "Failed to save ticketing settings");
    },
  });

  const hasTicketingTab = Boolean(teamId && conversationId != null && onIntegrationSettingsUpdated != null);

  const toggleRowSelection = (idx: number) => {
    setSelectedRows((prev) => {
      const next = new Set(prev);
      if (next.has(idx)) next.delete(idx);
      else next.add(idx);
      return next;
    });
  };

  const toggleSelectAll = () => {
    if (selectedRows.size === vulnerabilities.length) {
      setSelectedRows(new Set());
    } else {
      setSelectedRows(new Set(vulnerabilities.map((_, i) => i)));
    }
  };

  const createJiraTicketsMutation = useMutation({
    mutationFn: async () => {
      const tid = parseInt(teamId ?? "0", 10);
      if (!conversationId || Number.isNaN(tid)) throw new Error("Missing team or scan");
      const selectedFindings = Array.from(selectedRows).map((i) => vulnerabilities[i]);

      const impactCounts: Record<string, number> = {};
      for (const vuln of selectedFindings) {
        const impact = (vuln.impact ?? "Unknown").trim() || "Unknown";
        impactCounts[impact] = (impactCounts[impact] ?? 0) + 1;
      }
      let summary = Object.entries(impactCounts)
        .sort(([a], [b]) => RISK_ORDER.indexOf(a as (typeof RISK_ORDER)[number]) - RISK_ORDER.indexOf(b as (typeof RISK_ORDER)[number]))
        .map(([impact, count]) => `${count} ${impact}`)
        .join(", ") || `${selectedFindings.length} finding(s)`;
      summary = summary + " - Vulnerabilities found in LLM benchmark scan";

      const descSections = selectedFindings.map((vuln, idx) => {
        const parts: string[] = [`--- Finding ${idx + 1} ---`];
        parts.push(`Title: ${(vuln.title ?? "Untitled finding").trim() || "Untitled finding"}`);
        if ((vuln.description ?? "").trim()) parts.push(`Description: ${vuln.description!.trim()}`);
        if ((vuln.impact ?? "").trim()) parts.push(`Impact: ${vuln.impact!.trim()}`);
        if ((vuln.suggested_fix ?? "").trim()) parts.push(`Suggested fix: ${vuln.suggested_fix!.trim()}`);
        return parts.join("\n");
      });
      const description = descSections.join("\n\n");

      await createTicket(tid, "llm", conversationId, {
        ticket_type: "jira",
        summary,
        description,
      });
    },
    onMutate: () => {
      const toastId = toast.loading("Creating Jira ticket(s)...");
      return { toastId };
    },
    onSuccess: (_data, _variables, context) => {
      if (context?.toastId != null) {
        toast.success(`Jira ticket(s) created for ${selectedRows.size} finding(s)`, { id: context.toastId });
      } else {
        toast.success(`Jira ticket(s) created for ${selectedRows.size} finding(s)`);
      }
      setSelectedRows(new Set());
    },
    onError: (err, _variables, context) => {
      if (context?.toastId != null) toast.dismiss(context.toastId);
      showErrorToast(err, "Failed to create Jira ticket(s)");
    },
  });

  const handleCreateJiraTicket = () => createJiraTicketsMutation.mutate();

  const openVulnDetail = (vuln: LLMBenchmarkingVulnerability) => {
    setSelectedVuln(vuln);
    setDetailDialogOpen(true);
  };

  if (vulnerabilities.length === 0) {
    return (
      <div className="container mx-auto p-6 space-y-6">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-4">
            {conversationId && (
              <Button
                variant="outline"
                size="icon"
                onClick={() => {
                  const backRoute = origin === "list"
                    ? (teamId ? `/${teamId}/llm` : "/home/llm")
                    : (teamId ? `/${teamId}/llm/${conversationId}` : `/home/llm/${conversationId}`);
                  router.push(backRoute);
                }}
                className="cursor-pointer"
              >
                <ArrowLeft className="h-4 w-4" />
              </Button>
            )}
            <h1 className="text-3xl font-bold text-zinc-900 dark:text-white">LLM Benchmark Scan Results</h1>
          </div>
          {teamId && conversationId != null && (
            <Button
              variant="default"
              className="cursor-pointer bg-blue-600 hover:bg-blue-700 text-white"
              onClick={() => router.push(`/${teamId}/llm/${conversationId}`)}
            >
              <MessageCircle className="h-4 w-4 mr-2" />
              Chat with the Results
            </Button>
          )}
        </div>
        <Card>
          <CardContent className="py-12 text-center text-zinc-600 dark:text-zinc-400">
            No results available for this scan. The scan may not have completed yet or returned no findings.
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="container mx-auto p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          {conversationId && (
            <Button
              variant="outline"
              size="icon"
              onClick={() => {
                const backRoute = origin === "list"
                  ? (teamId ? `/${teamId}/llm` : "/home/llm")
                  : (teamId ? `/${teamId}/llm/${conversationId}` : `/home/llm/${conversationId}`);
                router.push(backRoute);
              }}
              className="cursor-pointer"
            >
              <ArrowLeft className="h-4 w-4" />
            </Button>
          )}
          <div>
            <h1 className="text-3xl font-bold text-zinc-900 dark:text-white">LLM Benchmark Scan Results</h1>
            <p className="text-sm text-zinc-600 dark:text-zinc-400 mt-1">
              {vulnerabilities.length} vulnerability finding(s) from LLM benchmarking
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          {onRefresh && (
            <Button variant="outline" size="icon" onClick={onRefresh} className="cursor-pointer" title="Refresh">
              <RefreshCcw className="h-4 w-4" />
            </Button>
          )}
          {onDownloadReport && teamId && conversationId != null && (
            <Button
              variant="outline"
              className="cursor-pointer bg-zinc-700 hover:bg-zinc-600 text-white border-zinc-600"
              onClick={onDownloadReport}
              disabled={isExporting}
            >
              <Download className="h-4 w-4 mr-2" />
              {isExporting ? "Downloading..." : "Download Scan Report"}
            </Button>
          )}
          {teamId && conversationId != null && (
            <Button
              variant="default"
              className="cursor-pointer bg-blue-600 hover:bg-blue-700 text-white"
              onClick={() => router.push(`/${teamId}/llm/${conversationId}`)}
            >
              <MessageCircle className="h-4 w-4 mr-2" />
              Chat with the Results
            </Button>
          )}
        </div>
      </div>

      {hasTicketingTab && (
        <div className="flex gap-2 mb-6 border-b border-zinc-200 dark:border-zinc-800">
          <button
            type="button"
            onClick={() => setActiveTab("results")}
            className={`px-4 py-2 font-medium text-sm transition-colors border-b-2 cursor-pointer ${
              activeTab === "results"
                ? "border-blue-600 text-blue-600 dark:text-blue-400"
                : "border-transparent text-zinc-600 dark:text-zinc-400 hover:text-zinc-900 dark:hover:text-zinc-100"
            }`}
          >
            <div className="flex items-center gap-2">
              <BarChart3 className="w-4 h-4" />
              Results
            </div>
          </button>
          <button
            type="button"
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
        </div>
      )}

      {activeTab === "ticketing" && hasTicketingTab ? (
        <TicketingIntegrationsSettings
          jiraProjectId={jiraProjectId}
          onJiraProjectIdChange={setJiraProjectId}
          onSave={() => {
            updateIntegrationMutation.mutate({
              integration_settings: {
                jira: { jira_project_id: jiraProjectId.trim() || null },
              },
            });
          }}
          isSaving={updateIntegrationMutation.isPending}
          inputId="llm-jira-project-id"
        />
      ) : (
        <>
      {/* Dashboard charts row — always visible in Results tab, empty state when no data */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
        {/* Radar: OWASP Top 10 LLM */}
        <Card className="border-zinc-200 dark:border-zinc-800">
          <CardHeader className="pb-2">
            <CardTitle className="text-base flex items-center gap-2">
              <Shield className="w-4 h-4" />
              OWASP Top 10 for LLM
            </CardTitle>
            <CardDescription>Findings by LLM category</CardDescription>
          </CardHeader>
          <CardContent>
            {dashboardData && Object.keys(dashboardData.owasp_top_10_llm_metrics ?? {}).length > 0 ? (
              (() => {
                const owasp = dashboardData.owasp_top_10_llm_metrics!;
                const radarData = Object.entries(owasp)
                  .map(([key, count]) => ({ subject: OWASP_LLM_KEY_TO_LABEL[key] ?? key, count, fullMark: Math.max(...Object.values(owasp), 1) }))
                  .sort((a, b) => b.count - a.count)
                  .slice(0, 10);
                const radarConfig: ChartConfig = { subject: { label: "Category" }, count: { label: "Count", color: "hsl(262 83% 58%)" } };
                return (
                  <ChartContainer config={radarConfig} className="mx-auto aspect-square max-h-[240px]">
                    <RadarChart data={radarData} margin={{ top: 8, right: 20, bottom: 8, left: 20 }}>
                      <PolarAngleAxis dataKey="subject" tick={{ fontSize: 9 }} />
                      <PolarGrid />
                      <Radar dataKey="count" fill="hsl(262 83% 58%)" fillOpacity={0.6} stroke="hsl(262 83% 58%)" />
                      <ChartTooltip cursor={false} content={<ChartTooltipContent nameKey="subject" formatter={(v) => [v, "Count"]} />} />
                    </RadarChart>
                  </ChartContainer>
                );
              })()
            ) : (
              <div className="flex items-center justify-center aspect-square max-h-[240px] text-sm text-zinc-500 dark:text-zinc-400">No data</div>
            )}
          </CardContent>
        </Card>
        {/* Radial: Risk (Impact) — always show 4 segments, use 0 when no data */}
        <Card className="border-zinc-200 dark:border-zinc-800">
          <CardHeader className="pb-2">
            <CardTitle className="text-base flex items-center gap-2">
              <Activity className="w-4 h-4" />
              Risk (Impact)
            </CardTitle>
            <CardDescription>By severity</CardDescription>
          </CardHeader>
          <CardContent>
            {(() => {
              const risk = dashboardData?.risk_metrics ?? {};
              const order = ["Critical", "High", "Medium", "Low"] as const;
              const total = order.reduce((s, k) => s + (risk[k] ?? 0), 0);
              const radialData = order.map((key) => ({
                name: key,
                count: total > 0 ? ((risk[key] ?? 0) / total) * 100 : 0,
                actualCount: risk[key] ?? 0,
                fill: key === "Critical" ? "hsl(0 84% 60%)" : key === "High" ? "hsl(25 95% 53%)" : key === "Medium" ? "hsl(48 96% 53%)" : "hsl(142 71% 45%)",
              }));
              const radialConfig: ChartConfig = {
                count: { label: "Share" },
                Critical: { label: "Critical", color: "hsl(0 84% 60%)" },
                High: { label: "High", color: "hsl(25 95% 53%)" },
                Medium: { label: "Medium", color: "hsl(48 96% 53%)" },
                Low: { label: "Low", color: "hsl(142 71% 45%)" },
              };
              return (
                <ChartContainer config={radialConfig} className="mx-auto aspect-square max-h-[240px]">
                  <RadialBarChart data={radialData} innerRadius={30} outerRadius={90} startAngle={90} endAngle={-270}>
                    <ChartTooltip cursor={false} content={<ChartTooltipContent nameKey="name" formatter={(_, __, ___, ____, payload) => [(payload as { actualCount?: number })?.actualCount ?? 0, "Count"]} />} />
                    <RadialBar dataKey="count" background fill={(entry: { fill?: string }) => entry?.fill ?? "hsl(0 0% 50%)"} />
                  </RadialBarChart>
                </ChartContainer>
              );
            })()}
          </CardContent>
        </Card>
        {/* Pie: Compliance controls */}
        <Card className="border-zinc-200 dark:border-zinc-800">
          <CardHeader className="pb-2">
            <CardTitle className="text-base flex items-center gap-2">
              <PieChartIcon className="w-4 h-4" />
              Compliance controls
            </CardTitle>
            <CardDescription>Top compliance categories</CardDescription>
          </CardHeader>
          <CardContent>
            {dashboardData && Object.keys(dashboardData.compliance_controls_metrics ?? {}).length > 0 ? (
              (() => {
                const comp = dashboardData.compliance_controls_metrics!;
                const total = Object.values(comp).reduce((s, n) => s + n, 0);
                if (total === 0) return <div className="flex items-center justify-center aspect-square max-h-[240px] text-sm text-zinc-500 dark:text-zinc-400">No data</div>;
                const colors = ["hsl(217 91% 60%)", "hsl(142 71% 45%)", "hsl(48 96% 53%)", "hsl(25 95% 53%)", "hsl(262 83% 58%)", "hsl(0 84% 60%)"];
                const pieData = Object.entries(comp)
                  .sort(([, a], [, b]) => b - a)
                  .slice(0, 8)
                  .map(([key, value], i) => ({
                    name: COMPLIANCE_KEY_TO_LABEL[key] ?? key,
                    value,
                    fill: colors[i % colors.length],
                  }));
                const pieConfig: ChartConfig = { value: { label: "Findings" }, ...Object.fromEntries(pieData.map((d) => [d.name, { label: d.name, color: d.fill }])) };
                return (
                  <ChartContainer config={pieConfig} className="mx-auto aspect-square max-h-[240px]">
                    <PieChart>
                      <ChartTooltip cursor={false} content={<ChartTooltipContent nameKey="name" />} />
                      <Pie data={pieData} dataKey="value" nameKey="name" cx="50%" cy="50%" innerRadius={40} outerRadius={80}>
                        {pieData.map((entry) => (
                          <Cell key={entry.name} fill={entry.fill} />
                        ))}
                      </Pie>
                    </PieChart>
                  </ChartContainer>
                );
              })()
            ) : (
              <div className="flex items-center justify-center aspect-square max-h-[240px] text-sm text-zinc-500 dark:text-zinc-400">No data</div>
            )}
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Findings</CardTitle>
          <CardDescription>
            {vulnerabilities.length} vulnerability findings. Click a title to view details. Select rows to create Jira tickets.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <FindingSelectionMenu
            selectedCount={selectedRows.size}
            onClearSelection={() => setSelectedRows(new Set())}
            jiraOnClickHandler={handleCreateJiraTicket}
            ticketType="jira"
            isJiraCreating={createJiraTicketsMutation.isPending}
          />
          <ScrollArea className="h-[500px] rounded-md border border-zinc-200 dark:border-zinc-800">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-[48px]">
                    <Checkbox
                      checked={vulnerabilities.length > 0 && selectedRows.size === vulnerabilities.length}
                      onCheckedChange={toggleSelectAll}
                      aria-label="Select all rows"
                      className="cursor-pointer"
                    />
                  </TableHead>
                  <TableHead className="w-[280px]">Vulnerability</TableHead>
                  <TableHead className="w-[80px] text-center">OWASP Top 10 LLM</TableHead>
                  <TableHead className="w-[80px] text-center">Compliance Controls</TableHead>
                  <TableHead className="w-[100px]">Impact</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {vulnerabilities.map((vuln, idx) => {
                  const vTitle = vuln.title ?? "Untitled finding";
                  const impact = (vuln.impact ?? "").trim() || "—";
                  const owaspLlmCount = getOwaspComplianceCount(vuln.owasp_top_10_llm);
                  const complianceCount = getOwaspComplianceCount(vuln.compliance_controls);
                  return (
                    <TableRow
                      key={idx}
                      className={`cursor-pointer hover:bg-zinc-50 dark:hover:bg-zinc-800/50 ${selectedRows.has(idx) ? "bg-zinc-100 dark:bg-zinc-800/70" : ""}`}
                    >
                      <TableCell onClick={(e) => e.stopPropagation()} className="w-[48px]">
                        <Checkbox
                          checked={selectedRows.has(idx)}
                          onCheckedChange={() => toggleRowSelection(idx)}
                          aria-label={`Select row ${idx + 1}`}
                          className="cursor-pointer"
                        />
                      </TableCell>
                      <TableCell className="font-medium">
                        <button
                          type="button"
                          onClick={() => openVulnDetail(vuln)}
                          className="text-left text-blue-600 hover:text-blue-700 dark:text-blue-400 dark:hover:text-blue-300 hover:underline cursor-pointer font-medium"
                        >
                          {vTitle}
                        </button>
                      </TableCell>
                      <TableCell className="text-center text-zinc-700 dark:text-zinc-300 tabular-nums">
                        {owaspLlmCount}
                      </TableCell>
                      <TableCell className="text-center text-zinc-700 dark:text-zinc-300 tabular-nums">
                        {complianceCount}
                      </TableCell>
                      <TableCell>
                        <Badge variant="outline" className={getImpactBadgeClass(impact)}>
                          {impact}
                        </Badge>
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          </ScrollArea>
        </CardContent>
      </Card>
        </>
      )}

      <Dialog open={detailDialogOpen} onOpenChange={setDetailDialogOpen}>
        <DialogContent className="max-w-4xl max-h-[90vh] flex flex-col p-0 gap-0 overflow-hidden bg-zinc-900">
          <DialogHeader className="px-6 pt-6 pb-2 shrink-0">
            <DialogTitle className="pr-8">
              {selectedVuln?.title ?? "Vulnerability details"}
            </DialogTitle>
          </DialogHeader>
          {selectedVuln && (
            <div className="h-[70vh] min-h-0 shrink px-6 pb-6">
              <ScrollArea className="h-full w-full rounded-md">
                <div className="space-y-4 pt-2 pr-4">
                  {(selectedVuln.impact ?? "").trim() && (
                    <div>
                      <div className="text-xs font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400 mb-1">Impact</div>
                      <Badge variant="outline" className={getImpactBadgeClass(selectedVuln.impact!.trim())}>
                        {selectedVuln.impact!.trim()}
                      </Badge>
                    </div>
                  )}
                  {(selectedVuln.description ?? "").trim() && (
                    <div>
                      <div className="text-xs font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400 mb-1">Description</div>
                      <p className="text-sm text-zinc-700 dark:text-zinc-300">{selectedVuln.description!.trim()}</p>
                    </div>
                  )}
                  {getOwaspComplianceEntries(selectedVuln.owasp_top_10_llm).length > 0 && (
                    <div>
                      <div className="text-xs font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400 mb-1">OWASP Top 10 for LLM</div>
                      <div className="flex flex-wrap gap-1">
                        {getOwaspComplianceEntries(selectedVuln.owasp_top_10_llm).map(([key, label]) => (
                          <Badge key={key} variant="secondary" className="text-xs bg-purple-100 dark:bg-purple-900/40 text-purple-800 dark:text-purple-200">
                            {OWASP_LLM_KEY_TO_LABEL[key] ?? label}
                          </Badge>
                        ))}
                      </div>
                    </div>
                  )}
                  {getOwaspComplianceEntries(selectedVuln.compliance_controls).length > 0 && (
                    <div>
                      <div className="text-xs font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400 mb-1">Compliance controls</div>
                      <div className="flex flex-wrap gap-1">
                        {getOwaspComplianceEntries(selectedVuln.compliance_controls).map(([key, label]) => (
                          <Badge key={key} variant="outline" className="text-xs">
                            {COMPLIANCE_KEY_TO_LABEL[key] ?? label}
                          </Badge>
                        ))}
                      </div>
                    </div>
                  )}
                  {(selectedVuln.suggested_fix ?? "").trim() && (
                    <div>
                      <div className="text-xs font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400 mb-1">Suggested fix</div>
                      <p className="text-sm text-zinc-700 dark:text-zinc-300">{selectedVuln.suggested_fix!.trim()}</p>
                    </div>
                  )}
                </div>
              </ScrollArea>
            </div>
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
}
