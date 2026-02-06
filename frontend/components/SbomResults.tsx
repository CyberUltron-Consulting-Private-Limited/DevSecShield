"use client";

import { useState, useEffect } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Checkbox } from "@/components/ui/checkbox";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import {
  AlertTriangle,
  ArrowLeft,
  MessageCircle,
  Download,
  Ticket,
} from "lucide-react";
import { ScrollArea, ScrollBar } from "@/components/ui/scroll-area";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { useRouter, useSearchParams, useParams } from "next/navigation";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { getSBOMExportResults, updateScan, createTicket, type SastDashboardData, type ScanTicketingIntegrationSettings } from "@/utils/backend_api";
import { showErrorToast } from "@/utils/error-handler";
import { OWASP_KEY_TO_LABEL, COMPLIANCE_KEY_TO_LABEL, OWASP_COLORS } from "@/lib/owasp-compliance-labels";
import {
  ChartContainer,
  ChartTooltip,
  ChartTooltipContent,
  type ChartConfig,
} from "@/components/ui/chart";
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  PolarAngleAxis,
  PolarGrid,
  Radar,
  RadarChart,
  RadialBar,
  RadialBarChart,
  XAxis,
  YAxis,
} from "recharts";
import { PieChart, BarChart3, TrendingUp } from "lucide-react";
import { toast } from "sonner";
import TicketingIntegrationsSettings from "@/components/ticketing-integrations-settings";
import FindingSelectionMenu from "@/components/finding-selection-menu";

// SBOM agent output format (from worker_sbom_agent_results_testing.json): array of flat vulnerability objects
type OwaspOrCompliance = Record<string, string> | null | undefined;

export interface SbomAgentVulnerability {
  title?: string | null;
  description?: string | null;
  impact?: string | null;
  owasp_top_10?: OwaspOrCompliance;
  compliance_controls?: OwaspOrCompliance;
  suggested_fix?: string | null;
  dependencies?: string[] | null;
  cves?: Record<string, string> | null;
}

function getOwaspComplianceCount(val: OwaspOrCompliance): number {
  if (val == null || typeof val !== "object") return 0;
  return Object.keys(val).length;
}

function getOwaspComplianceEntries(val: OwaspOrCompliance): [string, string][] {
  if (val == null || typeof val !== "object") return [];
  return Object.entries(val).filter(([, v]) => v != null && String(v).trim() !== "") as [string, string][];
}

interface SbomResultsProps {
  data: unknown;
  conversationId?: number;
  teamId?: string;
  dashboard?: SastDashboardData | null;
  integrationSettings?: Record<string, unknown> | null;
  onIntegrationSettingsUpdated?: () => void;
}

function getImpactBadgeClass(impact: string): string {
  const i = (impact || "").toLowerCase();
  if (i === "critical") return "bg-red-600 hover:bg-red-700 text-white";
  if (i === "high") return "bg-orange-500 hover:bg-orange-600 text-white";
  if (i === "medium") return "bg-amber-500 hover:bg-amber-600 text-white";
  if (i === "low") return "bg-blue-500 hover:bg-blue-600 text-white";
  return "bg-zinc-500 hover:bg-zinc-600 text-white";
}

const RISK_ORDER = ["Critical", "High", "Medium", "Low"] as const;
const riskRadarChartConfig = {
  subject: { label: "Severity" },
  count: { label: "Count", color: "hsl(0 84% 60%)" },
} satisfies ChartConfig;

const owaspRadialChartConfig = {
  count: { label: "Count" },
  ...Object.fromEntries(OWASP_COLORS.map((color, i) => [`fill_${i}`, { label: `Category ${i + 1}`, color }])),
} satisfies ChartConfig;

const complianceBarChartConfig = {
  name: { label: "Control" },
  count: { label: "Count", color: "hsl(217 91% 60%)" },
} satisfies ChartConfig;

const cvesAreaChartConfig = {
  cve: { label: "CVE" },
  count: { label: "Vulnerabilities", color: "hsl(0 84% 60%)" },
} satisfies ChartConfig;

function SbomDashboardCharts({ dashboard }: { dashboard: SastDashboardData }) {
  const riskMetrics = dashboard.risk_metrics ?? {};
  const owaspMetrics = dashboard.owasp_top_10_metrics ?? {};
  const complianceMetrics = dashboard.compliance_controls_metrics ?? {};
  const cvesMetrics = dashboard.cves_per_vulnerability ?? {};

  const riskRadarData = RISK_ORDER.map((subject) => ({
    subject,
    count: riskMetrics[subject] ?? 0,
  }));

  const owaspEntries = Object.entries(owaspMetrics).map(([key, actualCount], index) => {
    const displayValue = OWASP_KEY_TO_LABEL[key] ?? key;
    return {
      name: displayValue.length > 20 ? `${displayValue.slice(0, 20)}...` : displayValue,
      key,
      displayValue,
      actualCount,
      fill: OWASP_COLORS[index % OWASP_COLORS.length],
    };
  });
  const maxOwasp = Math.max(1, ...owaspEntries.map((d) => d.actualCount));
  const owaspRadialData = owaspEntries.map((d) => ({
    ...d,
    count: maxOwasp > 0 ? (d.actualCount / maxOwasp) * 100 : 0,
  }));

  const complianceBarData = Object.entries(complianceMetrics)
    .map(([key, count]) => ({ name: COMPLIANCE_KEY_TO_LABEL[key] ?? key, count }))
    .sort((a, b) => b.count - a.count);

  const cvesAreaData = Object.entries(cvesMetrics)
    .map(([cve, count]) => ({ cve, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 20);
  const cvesAreaDisplay = cvesAreaData.length > 0 ? cvesAreaData : [{ cve: "—", count: 0 }];

  const hasOwaspData = owaspEntries.length > 0 && owaspEntries.some((d) => d.actualCount > 0);
  const hasRiskData = riskRadarData.some((d) => d.count > 0);
  const hasCvesData = cvesAreaData.length > 0;
  const hasComplianceData = complianceBarData.length > 0;

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <Card className="border-zinc-200 dark:border-zinc-800">
          <CardHeader>
            <CardTitle className="text-base flex items-center gap-2">
              <PieChart className="w-4 h-4" />
              OWASP Top 10 metrics
            </CardTitle>
            <CardDescription>Distribution by OWASP category</CardDescription>
          </CardHeader>
          <CardContent>
            {!hasOwaspData ? (
              <div className="flex items-center justify-center min-h-[280px] text-zinc-500 dark:text-zinc-400 text-sm">No data to be displayed</div>
            ) : (
            <>
            <ChartContainer config={owaspRadialChartConfig} className="mx-auto aspect-square max-h-[280px] cursor-pointer">
              <RadialBarChart
                data={owaspRadialData}
                innerRadius={40}
                outerRadius={100}
                startAngle={90}
                endAngle={-270}
              >
                <ChartTooltip
                  cursor={false}
                  content={
                    <ChartTooltipContent
                      nameKey="displayValue"
                      labelFormatter={(_, payload) => (payload?.[0]?.payload as { displayValue?: string } | undefined)?.displayValue ?? "—"}
                      formatter={(_, __, ___, ____, payload) => {
                        const count = (payload as { actualCount?: number } | undefined)?.actualCount ?? 0;
                        return <>Count: <span className="font-mono font-semibold tabular-nums">{count}</span></>;
                      }}
                    />
                  }
                />
                <RadialBar dataKey="count" background className="cursor-pointer" />
              </RadialBarChart>
            </ChartContainer>
            <div className="mt-4 pt-3 border-t border-zinc-200 dark:border-zinc-700 flex flex-wrap gap-x-4 gap-y-1.5 justify-center">
              {owaspEntries.map(({ key, displayValue, fill }) => (
                <div key={key} className="flex items-center gap-1.5 text-xs">
                  <span className="shrink-0 w-3 h-3 rounded-full" style={{ backgroundColor: fill }} aria-hidden />
                  <span className="text-zinc-600 dark:text-zinc-400">{displayValue}</span>
                </div>
              ))}
            </div>
            </>
            )}
          </CardContent>
        </Card>

        <Card className="border-zinc-200 dark:border-zinc-800">
          <CardHeader>
            <CardTitle className="text-base flex items-center gap-2">
              <AlertTriangle className="w-4 h-4" />
              Risk metrics
            </CardTitle>
            <CardDescription>Findings by impact severity</CardDescription>
          </CardHeader>
          <CardContent>
            {!hasRiskData ? (
              <div className="flex items-center justify-center min-h-[280px] text-zinc-500 dark:text-zinc-400 text-sm">No data to be displayed</div>
            ) : (
            <ChartContainer config={riskRadarChartConfig} className="mx-auto aspect-square max-h-[280px] cursor-pointer">
              <RadarChart data={riskRadarData} margin={{ top: 8, right: 24, bottom: 8, left: 24 }}>
                <ChartTooltip cursor={false} content={<ChartTooltipContent nameKey="subject" formatter={(value) => [value, "Count"]} />} />
                <PolarAngleAxis dataKey="subject" />
                <PolarGrid />
                <Radar dataKey="count" fill="hsl(0 84% 60%)" fillOpacity={0.6} dot={{ r: 4, fillOpacity: 1 }} />
              </RadarChart>
            </ChartContainer>
            )}
            <p className="mt-4 pt-3 border-t border-zinc-200 dark:border-zinc-700 text-xs text-zinc-500 dark:text-zinc-400 text-center">
              Number of findings for each impact level (Critical, High, Medium, Low).
            </p>
          </CardContent>
        </Card>

        <Card className="border-zinc-200 dark:border-zinc-800 justify-between">
          <CardHeader>
            <CardTitle className="text-base flex items-center gap-2">
              <TrendingUp className="w-4 h-4" />
              CVEs per vulnerability
            </CardTitle>
            <CardDescription>Vulnerability count by CVE (top 20)</CardDescription>
          </CardHeader>
          <CardContent>
            {!hasCvesData ? (
              <div className="flex items-center justify-center min-h-[260px] text-zinc-500 dark:text-zinc-400 text-sm">No data to be displayed</div>
            ) : (
            <ChartContainer config={cvesAreaChartConfig} className="aspect-auto h-[260px] w-full pb-8 cursor-pointer">
              <AreaChart data={cvesAreaDisplay} margin={{ bottom: 28 }}>
                <defs>
                  <linearGradient id="fillSbomCves" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="hsl(0 84% 60%)" stopOpacity={0.8} />
                    <stop offset="95%" stopColor="hsl(0 84% 60%)" stopOpacity={0.1} />
                  </linearGradient>
                </defs>
                <CartesianGrid vertical={false} className="stroke-zinc-200 dark:stroke-zinc-800" />
                <XAxis
                  dataKey="cve"
                  tickLine={false}
                  axisLine={false}
                  tickMargin={8}
                  minTickGap={20}
                  height={56}
                  interval={0}
                  tickFormatter={(v) => (String(v).length > 12 ? `${String(v).slice(0, 12)}...` : v)}
                />
                <YAxis hide domain={[0, "auto"]} />
                <ChartTooltip cursor={false} content={<ChartTooltipContent formatter={(value) => [value, "Vulnerabilities"]} />} />
                <Area dataKey="count" type="monotone" fill="url(#fillSbomCves)" stroke="hsl(0 84% 60%)" strokeWidth={2} />
              </AreaChart>
            </ChartContainer>
            )}
          </CardContent>
        </Card>
      </div>

      <Card className="border-zinc-200 dark:border-zinc-800">
        <CardHeader>
          <CardTitle className="text-base flex items-center gap-2">
            <BarChart3 className="w-4 h-4" />
            Compliance Controls Failed count
          </CardTitle>
          <CardDescription>Findings by compliance control. Scroll horizontally if needed.</CardDescription>
        </CardHeader>
        <CardContent>
          {!hasComplianceData ? (
            <div className="flex items-center justify-center min-h-[260px] text-zinc-500 dark:text-zinc-400 text-sm">No data to be displayed</div>
          ) : (
          <ScrollArea className="w-full">
            <div className="min-w-max pb-2" style={{ minWidth: `${Math.max(400, complianceBarData.length * 56)}px` }}>
              <ChartContainer config={complianceBarChartConfig} className="aspect-auto h-[260px] w-full min-w-0 cursor-pointer">
                <BarChart data={complianceBarData} margin={{ top: 8, right: 8, bottom: 32, left: 0 }}>
                  <CartesianGrid vertical={false} className="stroke-zinc-200 dark:stroke-zinc-800" />
                  <XAxis
                    dataKey="name"
                    tickLine={false}
                    axisLine={false}
                    tickMargin={8}
                    height={56}
                    interval={0}
                    tickFormatter={(v) => (String(v).length > 10 ? `${String(v).slice(0, 10)}...` : v)}
                  />
                  <YAxis type="number" tickLine={false} axisLine={false} />
                  <ChartTooltip cursor={false} content={<ChartTooltipContent />} />
                  <Bar dataKey="count" fill="var(--color-count)" radius={[8, 8, 0, 0]} style={{ cursor: "pointer" }} />
                </BarChart>
              </ChartContainer>
            </div>
            <ScrollBar orientation="horizontal" />
          </ScrollArea>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

function SbomResultsView({
  vulnerabilities,
  conversationId,
  teamId,
  origin,
  router,
  onDownloadReport,
  isExporting = false,
  dashboard,
  integrationSettings,
  onIntegrationSettingsUpdated,
}: {
  vulnerabilities: SbomAgentVulnerability[];
  conversationId?: number;
  teamId?: string;
  origin: string | null;
  router: ReturnType<typeof useRouter>;
  onDownloadReport?: () => void;
  isExporting?: boolean;
  dashboard?: SastDashboardData | null;
  integrationSettings?: Record<string, unknown> | null;
  onIntegrationSettingsUpdated?: () => void;
}) {
  const [detailDialogOpen, setDetailDialogOpen] = useState(false);
  const [selectedVuln, setSelectedVuln] = useState<SbomAgentVulnerability | null>(null);
  const [activeTab, setActiveTab] = useState<"results" | "ticketing">("results");
  const [jiraProjectId, setJiraProjectId] = useState("");
  const [selectedRows, setSelectedRows] = useState<Set<number>>(new Set());
  const queryClient = useQueryClient();

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
        type: "sbom_sca",
        scan_id: conversationId!,
        data: payload,
      }),
    onSuccess: () => {
      onIntegrationSettingsUpdated?.();
      const tid = parseInt(teamId ?? "0", 10);
      if (conversationId != null && tid > 0) {
        queryClient.invalidateQueries({ queryKey: ["sbom_sca-conversation-data", tid, conversationId] });
      }
      toast.success("Ticketing settings saved");
    },
    onError: (err) => {
      showErrorToast(err, "Failed to save ticketing settings");
    },
  });

  const showTabs = teamId && conversationId != null;
  const hasTicketingTab = showTabs && onIntegrationSettingsUpdated != null;

  const totalFindings = vulnerabilities.length;
  const byImpact = vulnerabilities.reduce((acc, v) => {
    const impact = (v.impact ?? "Unknown").trim() || "Unknown";
    acc[impact] = (acc[impact] || 0) + 1;
    return acc;
  }, {} as Record<string, number>);

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

      summary = summary + " - Vulnerabilities found in SBOM scan";

      const descSections = selectedFindings.map((vuln, idx) => {
        const parts: string[] = [`--- Finding ${idx + 1} ---`];
        parts.push(`Title: ${(vuln.title ?? "Untitled finding").trim() || "Untitled finding"}`);
        if ((vuln.description ?? "").trim()) parts.push(`Description: ${vuln.description!.trim()}`);
        if ((vuln.impact ?? "").trim()) parts.push(`Impact: ${vuln.impact!.trim()}`);
        if (vuln.dependencies && vuln.dependencies.length > 0) parts.push(`Dependencies: ${vuln.dependencies.join(", ")}`);
        if ((vuln.suggested_fix ?? "").trim()) parts.push(`Suggested fix: ${vuln.suggested_fix!.trim()}`);
        if (vuln.cves && Object.keys(vuln.cves).length > 0) parts.push(`CVEs: ${Object.keys(vuln.cves).join(", ")}`);
        return parts.join("\n");
      });
      const description = descSections.join("\n\n");

      await createTicket(tid, "sbom_sca", conversationId, {
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

  const openVulnDetail = (vuln: SbomAgentVulnerability) => {
    setSelectedVuln(vuln);
    setDetailDialogOpen(true);
  };

  return (
    <div className="container mx-auto p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          {(conversationId != null || teamId) && (
            <Button
              variant="outline"
              size="icon"
              onClick={() => {
                const backRoute =
                  origin === "chat" && teamId && conversationId != null
                    ? `/${teamId}/sbom_sca/${conversationId}`
                    : teamId
                      ? `/${teamId}/sbom_sca`
                      : "/sbom_sca";
                router.push(backRoute);
              }}
              className="cursor-pointer"
            >
              <ArrowLeft className="h-4 w-4" />
            </Button>
          )}
          <div>
            <h1 className="text-3xl font-bold text-zinc-900 dark:text-white">SCA + SBOM Scan Results</h1>
            <p className="text-sm text-zinc-600 dark:text-zinc-400 mt-1">
              Agent analysis of dependency vulnerabilities
            </p>
          </div>
        </div>
        {teamId && conversationId != null && (
          <div className="flex items-center gap-2">
            {onDownloadReport && (
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
            <Button
              variant="default"
              className="cursor-pointer bg-blue-600 hover:bg-blue-700 text-white"
              onClick={() => router.push(`/${teamId}/sbom_sca/${conversationId}`)}
            >
              <MessageCircle className="h-4 w-4 mr-2" />
              Chat with the Results
            </Button>
          </div>
        )}
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
          inputId="sbom-jira-project-id"
        />
      ) : (
        <>
      {dashboard && <SbomDashboardCharts dashboard={dashboard} />}

      <Card>
        <CardHeader>
          <CardTitle>Findings</CardTitle>
          <CardDescription>{totalFindings} vulnerability findings — click a title to view details</CardDescription>
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
                  <TableHead className="w-[200px]">Dependencies</TableHead>
                  <TableHead className="w-[80px] text-center">OWASP Top 10</TableHead>
                  <TableHead className="w-[80px] text-center">Compliance Controls</TableHead>
                  <TableHead className="w-[100px]">Impact</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {vulnerabilities.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={6} className="text-center py-8 text-zinc-500 dark:text-zinc-400">
                      No findings to display.
                    </TableCell>
                  </TableRow>
                ) : (
                  vulnerabilities.map((vuln, idx) => {
                    const vTitle = vuln.title ?? "Untitled finding";
                    const impact = (vuln.impact ?? "").trim() || "—";
                    const owaspCount = getOwaspComplianceCount(vuln.owasp_top_10);
                    const complianceCount = getOwaspComplianceCount(vuln.compliance_controls);
                    const deps = vuln.dependencies ?? [];
                    const depSummary = deps.length === 0 ? "—" : deps.length === 1 ? deps[0] : `${deps.length} dependencies`;
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
                        <TableCell className="text-zinc-600 dark:text-zinc-400 text-sm max-w-[200px] truncate" title={deps.join(", ")}>
                          {depSummary}
                        </TableCell>
                        <TableCell className="text-center text-zinc-700 dark:text-zinc-300 tabular-nums">
                          {owaspCount}
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
                  })
                )}
              </TableBody>
            </Table>
          </ScrollArea>
        </CardContent>
      </Card>

      <Dialog open={detailDialogOpen} onOpenChange={setDetailDialogOpen}>
        <DialogContent className="max-w-4xl max-h-[90vh] flex flex-col p-0 gap-0 overflow-hidden bg-zinc-900">
          <DialogHeader className="px-6 pt-6 pb-2 shrink-0">
            <DialogTitle className="pr-8">{selectedVuln?.title ?? "Vulnerability details"}</DialogTitle>
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
                  {(selectedVuln.suggested_fix ?? "").trim() && (
                    <div>
                      <div className="text-xs font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400 mb-1">Suggested fix</div>
                      <p className="text-sm text-zinc-700 dark:text-zinc-300">{selectedVuln.suggested_fix!.trim()}</p>
                    </div>
                  )}
                  {selectedVuln.dependencies && selectedVuln.dependencies.length > 0 && (
                    <div>
                      <div className="text-xs font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400 mb-1">Dependencies</div>
                      <ul className="list-disc list-inside text-sm text-zinc-700 dark:text-zinc-300 space-y-1">
                        {selectedVuln.dependencies.map((dep, i) => (
                          <li key={i} className="font-mono text-xs">{dep}</li>
                        ))}
                      </ul>
                    </div>
                  )}
                  {getOwaspComplianceEntries(selectedVuln.owasp_top_10).length > 0 && (
                    <div>
                      <div className="text-xs font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400 mb-1">OWASP Top 10</div>
                      <div className="flex flex-wrap gap-1">
                        {getOwaspComplianceEntries(selectedVuln.owasp_top_10).map(([, description], i) => (
                          <Badge key={i} variant="secondary" className="text-xs bg-purple-100 dark:bg-purple-900/40 text-purple-800 dark:text-purple-200">
                            {description}
                          </Badge>
                        ))}
                      </div>
                    </div>
                  )}
                  {getOwaspComplianceEntries(selectedVuln.compliance_controls).length > 0 && (
                    <div>
                      <div className="text-xs font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400 mb-1">Compliance controls</div>
                      <div className="flex flex-wrap gap-1">
                        {getOwaspComplianceEntries(selectedVuln.compliance_controls).map(([, description], i) => (
                          <Badge key={i} variant="outline" className="text-xs">
                            {description}
                          </Badge>
                        ))}
                      </div>
                    </div>
                  )}
                  {selectedVuln.cves && Object.keys(selectedVuln.cves).length > 0 && (
                    <div>
                      <div className="text-xs font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400 mb-1">Related CVEs</div>
                      <ul className="space-y-2 text-sm">
                        {Object.entries(selectedVuln.cves).map(([id, desc], i) => (
                          <li key={i} className="rounded-md border border-zinc-200 dark:border-zinc-700 bg-zinc-50/50 dark:bg-zinc-800/30 px-3 py-2">
                            <span className="font-mono font-medium text-zinc-800 dark:text-zinc-200">{id}</span>
                            {desc && <p className="text-zinc-600 dark:text-zinc-400 mt-0.5 text-xs">{desc}</p>}
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}
                </div>
              </ScrollArea>
            </div>
          )}
        </DialogContent>
      </Dialog>
        </>
      )}
    </div>
  );
}

export default function SbomResults({ data, conversationId, teamId, dashboard, integrationSettings, onIntegrationSettingsUpdated }: SbomResultsProps) {
  const router = useRouter();
  const searchParams = useSearchParams();
  const origin = searchParams.get("origin");

  const exportMutation = useMutation({
    mutationFn: () => {
      const tid = teamId ? parseInt(teamId, 10) : NaN;
      if (conversationId == null || Number.isNaN(tid)) throw new Error("Missing team or scan");
      return getSBOMExportResults(tid, conversationId);
    },
    onSuccess: (blob) => {
      const url = URL.createObjectURL(new Blob([blob], { type: "application/pdf" }));
      const a = document.createElement("a");
      a.href = url;
      a.download = `sbom_sca_scan_${conversationId}_report.pdf`;
      a.click();
      URL.revokeObjectURL(url);
    },
    onError: (err) => {
      showErrorToast(err, "Failed to download scan report");
    },
  });

  const handleDownloadReport = () => exportMutation.mutate();
  const isExporting = exportMutation.isPending;

  if (data == null || (Array.isArray(data) && data.length === 0)) {
    return (
      <div className="container mx-auto p-6 space-y-6">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-4">
            {(conversationId != null || teamId) && (
              <Button
                variant="outline"
                size="icon"
                onClick={() => {
                  const backRoute =
                    origin === "chat" && teamId && conversationId != null
                      ? `/${teamId}/sbom_sca/${conversationId}`
                      : teamId
                        ? `/${teamId}/sbom_sca`
                        : "/sbom_sca";
                  router.push(backRoute);
                }}
                className="cursor-pointer"
              >
                <ArrowLeft className="h-4 w-4" />
              </Button>
            )}
            <h1 className="text-3xl font-bold text-zinc-900 dark:text-white">SCA + SBOM Scan Results</h1>
          </div>
          {teamId && conversationId != null && (
            <Button
              variant="default"
              className="cursor-pointer bg-blue-600 hover:bg-blue-700 text-white"
              onClick={() => router.push(`/${teamId}/sbom_sca/${conversationId}`)}
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
    <SbomResultsView
      vulnerabilities={data as SbomAgentVulnerability[]}
      conversationId={conversationId}
      teamId={teamId}
      origin={origin}
      router={router}
      onDownloadReport={teamId && conversationId != null ? handleDownloadReport : undefined}
      isExporting={isExporting}
      dashboard={dashboard}
      integrationSettings={integrationSettings}
      onIntegrationSettingsUpdated={onIntegrationSettingsUpdated}
    />
  );
}
