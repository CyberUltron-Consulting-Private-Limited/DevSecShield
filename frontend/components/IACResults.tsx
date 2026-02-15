"use client";

import { useState, useEffect } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Checkbox } from "@/components/ui/checkbox";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { AlertTriangle, ArrowLeft, MessageCircle, Download, Ticket } from "lucide-react";
import { ScrollArea, ScrollBar } from "@/components/ui/scroll-area";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { useRouter, useSearchParams, usePathname, useParams } from "next/navigation";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { getIACExportResults, updateScan, createTicket, type SastDashboardData, type ScanTicketingIntegrationSettings } from "@/utils/backend_api";
import { showErrorToast } from "@/utils/error-handler";
import { OWASP_KEY_TO_LABEL, COMPLIANCE_KEY_TO_LABEL, OWASP_COLORS } from "@/lib/owasp-compliance-labels";
import {
  ChartContainer,
  ChartTooltip,
  ChartTooltipContent,
  type ChartConfig,
} from "@/components/ui/chart";
import {
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
  PieChart as RechartsPieChart,
  Pie,
  Cell,
} from "recharts";
import { PieChart, BarChart3, ShieldCheck } from "lucide-react";
import { toast } from "sonner";
import TicketingIntegrationsSettings from "@/components/ticketing-integrations-settings";
import FindingSelectionMenu from "@/components/finding-selection-menu";

// IAC agent output format (from worker_iac_agent_results_testing.json): flat array of vulnerabilities
type OwaspOrComplianceItem = Record<string, string>;
type OwaspOrCompliance = Record<string, string> | Array<OwaspOrComplianceItem> | null | undefined;

export interface IACVulnerability {
  title?: string | null;
  description?: string | null;
  impact?: string | null;
  owasp_top_10?: OwaspOrCompliance;
  compliance_controls?: OwaspOrCompliance;
  suggested_fix?: string | null;
  location?: string | null;
  snippet?: string | null;
  cves?: unknown[] | Record<string, unknown> | null;
}

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

interface IACResultsProps {
  data: IACVulnerability[] | null | undefined;
  conversationId?: number;
  dashboard?: SastDashboardData | null;
  teamId?: string;
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

// ----- Risk metric cards -----
const RISK_CARDS = [
  { key: "Critical" as const, label: "Critical", description: "Most severe, requires immediate attention", color: "hsl(0 84% 60%)", icon: AlertTriangle },
  { key: "High" as const, label: "High", description: "Serious issues that should be addressed soon", color: "hsl(25 95% 53%)", icon: AlertTriangle },
  { key: "Medium" as const, label: "Medium", description: "Moderate risk, should be remediated", color: "hsl(48 96% 53%)", icon: AlertTriangle },
  { key: "Low" as const, label: "Low", description: "Minor findings, lower priority", color: "hsl(142 71% 45%)", icon: AlertTriangle },
] as const;

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

const complianceStandardsPieChartConfig = {
  value: { label: "Findings" },
} satisfies ChartConfig;

function IACDashboardCharts({ dashboard }: { dashboard: SastDashboardData }) {
  const riskMetrics = dashboard.risk_metrics ?? {};
  const owaspMetrics = dashboard.owasp_top_10_metrics ?? {};
  const complianceMetrics = dashboard.compliance_controls_metrics ?? {};
  const complianceStandardsMetrics = dashboard.compliance_standards_metrics ?? {};

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

  const complianceStandardsPieData = Object.entries(complianceStandardsMetrics)
    .filter(([, count]) => count > 0)
    .sort(([, a], [, b]) => b - a)
    .map(([name, value], i) => {
      const colors = ["hsl(217 91% 60%)", "hsl(142 71% 45%)", "hsl(48 96% 53%)", "hsl(25 95% 53%)", "hsl(262 83% 58%)", "hsl(0 84% 60%)"];
      return { name, value, fill: colors[i % colors.length] };
    });
  const pieChartConfig: ChartConfig = {
    ...complianceStandardsPieChartConfig,
    ...Object.fromEntries(complianceStandardsPieData.map((d) => [d.name, { label: d.name, color: d.fill }])),
  };

  const hasOwaspData = owaspEntries.length > 0 && owaspEntries.some((d) => d.actualCount > 0);
  const hasRiskData = riskRadarData.some((d) => d.count > 0);
  const hasComplianceStandardsData = complianceStandardsPieData.length > 0;
  const hasComplianceData = complianceBarData.length > 0;

  return (
    <div className="space-y-6">
      {/* Risk metrics — 4 cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {RISK_CARDS.map(({ key, label, description, color, icon: Icon }) => (
          <Card key={key} className="border-zinc-200 dark:border-zinc-800">
            <CardHeader className="pb-2">
              <div className="flex items-start justify-between">
                <CardTitle className="text-base">{label}</CardTitle>
                <Icon className="h-4 w-4 shrink-0" style={{ color }} />
              </div>
              <CardDescription>{description}</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold tabular-nums text-zinc-900 dark:text-zinc-100">{riskMetrics[key] ?? 0}</div>
            </CardContent>
          </Card>
        ))}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <Card className="border-zinc-200 dark:border-zinc-800">
          <CardHeader>
            <CardTitle className="text-base flex items-center gap-2">
              <ShieldCheck className="w-4 h-4" />
              Compliance standards
            </CardTitle>
            <CardDescription>Findings by compliance standard (e.g. NIST 800-53, ISO 27001)</CardDescription>
          </CardHeader>
          <CardContent>
            {!hasComplianceStandardsData ? (
              <div className="flex items-center justify-center min-h-[280px] text-zinc-500 dark:text-zinc-400 text-sm">No data to be displayed</div>
            ) : (
              <ChartContainer config={pieChartConfig} className="mx-auto aspect-square max-h-[280px] cursor-pointer">
                <RechartsPieChart>
                  <ChartTooltip cursor={false} content={<ChartTooltipContent nameKey="name" />} />
                  <Pie
                    data={complianceStandardsPieData}
                    dataKey="value"
                    nameKey="name"
                    cx="50%"
                    cy="50%"
                    innerRadius={40}
                    outerRadius={90}
                  >
                    {complianceStandardsPieData.map((entry) => (
                      <Cell key={entry.name} fill={entry.fill} />
                    ))}
                  </Pie>
                </RechartsPieChart>
              </ChartContainer>
            )}
            <p className="mt-4 pt-3 border-t border-zinc-200 dark:border-zinc-700 text-xs text-zinc-500 dark:text-zinc-400 text-center">
              Distribution of findings by compliance framework or standard.
            </p>
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
              <RadialBarChart data={owaspRadialData} innerRadius={40} outerRadius={100} startAngle={90} endAngle={-270}>
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

function IACResultsAgentView({
  vulnerabilities,
  conversationId,
  teamId,
  isCicdContext,
  integrationId,
  origin,
  router,
  onDownloadReport,
  isExporting = false,
  dashboard,
  integrationSettings,
  onIntegrationSettingsUpdated,
}: {
  vulnerabilities: IACVulnerability[];
  conversationId?: number;
  teamId?: string;
  isCicdContext: boolean;
  integrationId: string | null;
  origin: string | null;
  router: ReturnType<typeof useRouter>;
  onDownloadReport?: () => void;
  isExporting?: boolean;
  dashboard?: SastDashboardData | null;
  integrationSettings?: Record<string, unknown> | null;
  onIntegrationSettingsUpdated?: () => void;
}) {
  const [detailDialogOpen, setDetailDialogOpen] = useState(false);
  const [selectedVuln, setSelectedVuln] = useState<IACVulnerability | null>(null);
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
        type: "iac",
        scan_id: conversationId!,
        data: payload,
      }),
    onSuccess: () => {
      onIntegrationSettingsUpdated?.();
      const tid = parseInt(teamId ?? "0", 10);
      if (conversationId != null && tid > 0) {
        queryClient.invalidateQueries({ queryKey: ["iac-conversation-data", tid, conversationId] });
      }
      toast.success("Ticketing settings saved");
    },
    onError: (err) => {
      showErrorToast(err, "Failed to save ticketing settings");
    },
  });

  const hasTicketingTab = !isCicdContext && teamId && conversationId != null && onIntegrationSettingsUpdated != null;

  const totalFindings = vulnerabilities.length;

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
      
      summary = summary + " - Vulnerabilities found in IAC scan";

      const descSections = selectedFindings.map((vuln, idx) => {
        const parts: string[] = [`--- Finding ${idx + 1} ---`];
        parts.push(`Title: ${(vuln.title ?? "Untitled finding").trim() || "Untitled finding"}`);
        if ((vuln.description ?? "").trim()) parts.push(`Description: ${vuln.description!.trim()}`);
        if ((vuln.impact ?? "").trim()) parts.push(`Impact: ${vuln.impact!.trim()}`);
        if ((vuln.location ?? "").trim()) parts.push(`Location: ${vuln.location!.trim()}`);
        if ((vuln.suggested_fix ?? "").trim()) parts.push(`Suggested fix: ${vuln.suggested_fix!.trim()}`);
        return parts.join("\n");
      });
      const description = descSections.join("\n\n");

      await createTicket(tid, "iac", conversationId, {
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

  const openVulnDetail = (vuln: IACVulnerability) => {
    setSelectedVuln(vuln);
    setDetailDialogOpen(true);
  };

  return (
    <div className="container mx-auto p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          {(conversationId != null || isCicdContext) && (
            <Button
              variant="outline"
              size="icon"
              onClick={() => {
                const backRoute =
                  isCicdContext && integrationId
                    ? `/home/ci_cd/${integrationId}`
                    : origin === "chat"
                      ? teamId ? `/${teamId}/iac/${conversationId}` : `/home/iac/${conversationId}`
                      : teamId ? `/${teamId}/iac` : "/home/iac";
                router.push(backRoute);
              }}
              className="cursor-pointer"
            >
              <ArrowLeft className="h-4 w-4" />
            </Button>
          )}
          <div>
            <h1 className="text-3xl font-bold text-zinc-900 dark:text-white">IAC Scan Results</h1>
            <p className="text-sm text-zinc-600 dark:text-zinc-400 mt-1">
              Infrastructure as Code security analysis
            </p>
          </div>
        </div>
        {!isCicdContext && teamId && conversationId != null && (
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
              onClick={() => router.push(`/${teamId}/iac/${conversationId}`)}
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
          inputId="iac-jira-project-id"
        />
      ) : (
        <>
      {dashboard && <IACDashboardCharts dashboard={dashboard} />}

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
                  <TableHead className="w-[80px] text-center">OWASP Top 10</TableHead>
                  <TableHead className="w-[80px] text-center">Compliance Controls</TableHead>
                  <TableHead className="w-[100px]">Impact</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {vulnerabilities.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={5} className="text-center py-8 text-zinc-500 dark:text-zinc-400">
                      No findings to display.
                    </TableCell>
                  </TableRow>
                ) : (
                  vulnerabilities.map((vuln, idx) => {
                    const vTitle = vuln.title ?? "Untitled finding";
                    const impact = (vuln.impact ?? "").trim() || "—";
                    const owaspCount = getOwaspComplianceCount(vuln.owasp_top_10);
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
        <DialogContent className="max-w-4xl max-h-[90vh] flex flex-col p-0 gap-0 overflow-hidden">
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
                  {(selectedVuln.location ?? "").trim() && (
                    <div>
                      <div className="text-xs font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400 mb-1">Location</div>
                      <p className="text-sm font-mono text-zinc-700 dark:text-zinc-300">{selectedVuln.location!.trim()}</p>
                    </div>
                  )}
                  {(selectedVuln.snippet ?? "").trim() && (
                    <div>
                      <div className="text-xs font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400 mb-1">Code snippet</div>
                      <pre className="text-xs bg-zinc-100 dark:bg-zinc-800 p-3 rounded overflow-x-auto whitespace-pre-wrap font-mono text-zinc-800 dark:text-zinc-200">
                        {selectedVuln.snippet!.trim()}
                      </pre>
                    </div>
                  )}
                  {(selectedVuln.suggested_fix ?? "").trim() && (
                    <div>
                      <div className="text-xs font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400 mb-1">Suggested fix</div>
                      <p className="text-sm text-zinc-700 dark:text-zinc-300">{selectedVuln.suggested_fix!.trim()}</p>
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
                  {(() => {
                    const cves = selectedVuln.cves;
                    const cveEntries: [string, string][] = [];
                    if (Array.isArray(cves) && cves.length > 0) {
                      cves.forEach((cve) => {
                        const id = typeof cve === "string" ? cve : (cve && typeof cve === "object" && "id" in (cve as object) ? String((cve as { id?: string }).id) : null);
                        if (id) cveEntries.push([id, ""]);
                      });
                    } else if (cves && typeof cves === "object" && !Array.isArray(cves) && Object.keys(cves).length > 0) {
                      cveEntries.push(...(Object.entries(cves) as [string, string][]));
                    }
                    return cveEntries.length > 0 ? (
                      <div>
                        <div className="text-xs font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400 mb-1">Related CVEs</div>
                        <ul className="space-y-2 text-sm">
                          {cveEntries.map(([id, desc], i) => (
                            <li key={i} className="rounded-md border border-zinc-200 dark:border-zinc-700 bg-zinc-50/50 dark:bg-zinc-800/30 px-3 py-2">
                              <span className="font-mono font-medium text-zinc-800 dark:text-zinc-200">{id}</span>
                              {desc && <p className="text-zinc-600 dark:text-zinc-400 mt-0.5">{desc}</p>}
                            </li>
                          ))}
                        </ul>
                      </div>
                    ) : null;
                  })()}
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

export default function IACResults({ data, conversationId, dashboard, teamId: teamIdProp, integrationSettings, onIntegrationSettingsUpdated }: IACResultsProps) {
  const router = useRouter();
  const pathname = usePathname();
  const searchParams = useSearchParams();
  const origin = searchParams.get("origin");

  const isCicdContext = pathname.includes("ci_cd");
  let integrationId: string | null = null;
  if (isCicdContext) {
    const pathParts = pathname.split("/").filter(Boolean);
    const cicdIndex = pathParts.indexOf("ci_cd");
    if (cicdIndex !== -1 && cicdIndex + 1 < pathParts.length) {
      integrationId = pathParts[cicdIndex + 1];
    }
  }

  const params = useParams();
  const teamId = params?.team_id as string | undefined;

  const exportMutation = useMutation({
    mutationFn: () => {
      const tid = teamId ? parseInt(teamId, 10) : NaN;
      if (conversationId == null || Number.isNaN(tid)) throw new Error("Missing team or scan");
      return getIACExportResults(tid, conversationId);
    },
    onSuccess: (blob) => {
      const url = URL.createObjectURL(new Blob([blob], { type: "application/pdf" }));
      const a = document.createElement("a");
      a.href = url;
      a.download = `iac_scan_${conversationId}_report.pdf`;
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
            {(conversationId != null || isCicdContext) && (
              <Button
                variant="outline"
                size="icon"
                onClick={() => {
                  const backRoute =
                    isCicdContext && integrationId
                      ? `/home/ci_cd/${integrationId}`
                      : origin === "chat"
                        ? (teamId ? `/${teamId}/iac/${conversationId}` : `/home/iac/${conversationId}`)
                        : (teamId ? `/${teamId}/iac` : "/home/iac");
                  router.push(backRoute);
                }}
                className="cursor-pointer"
              >
                <ArrowLeft className="h-4 w-4" />
              </Button>
            )}
            <h1 className="text-3xl font-bold text-zinc-900 dark:text-white">IAC Scan Results</h1>
          </div>
          {!isCicdContext && teamId && conversationId != null && (
            <Button
              variant="default"
              className="cursor-pointer bg-blue-600 hover:bg-blue-700 text-white"
              onClick={() => router.push(`/${teamId}/iac/${conversationId}`)}
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
    <IACResultsAgentView
      vulnerabilities={data}
      conversationId={conversationId}
      teamId={teamId}
      isCicdContext={isCicdContext}
      integrationId={integrationId}
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
