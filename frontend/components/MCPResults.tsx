"use client";

import { useState, useMemo, useEffect } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Checkbox } from "@/components/ui/checkbox";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import {
  AlertTriangle,
  ArrowLeft,
  MessageCircle,
  Download,
  RefreshCcw,
  Search,
  Wrench,
  MessageSquare,
  FolderOpen,
  Eye,
  BarChart3,
  TrendingUp,
  Shield,
  Ticket,
} from "lucide-react";
import { ScrollArea } from "@/components/ui/scroll-area";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { useRouter, useSearchParams } from "next/navigation";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import type { MCPDashboardData, ScanTicketingIntegrationSettings } from "@/utils/backend_api";
import { updateScan, createTicket } from "@/utils/backend_api";
import { showErrorToast } from "@/utils/error-handler";
import FindingSelectionMenu from "@/components/finding-selection-menu";
import TicketingIntegrationsSettings from "@/components/ticketing-integrations-settings";
import {
  ChartContainer,
  ChartTooltip,
  ChartTooltipContent,
  type ChartConfig,
} from "@/components/ui/chart";
import { Area, AreaChart, Bar, BarChart, CartesianGrid, XAxis, YAxis } from "recharts";

// ----- Agent format -----
export interface MCPVulnerabilityAgent {
  title: string;
  description: string;
  impact: string;
  owasp_top_10?: Record<string, string>;
  owasp_top_10_llm?: Record<string, string>;
  compliance_controls?: Record<string, string>;
  suggested_fix: string;
}

export interface MCPToolFinding {
  tool_name: string;
  tool_description: string;
  tool_input_schema?: unknown;
  tool_output_schema?: unknown;
  vulnerabilities: MCPVulnerabilityAgent[];
}

export interface MCPPromptFinding {
  prompt_name: string;
  prompt_description: string;
  prompt_input_schema?: unknown;
  vulnerabilities: MCPVulnerabilityAgent[];
}

export interface MCPResourceFinding {
  resource_name: string;
  resource_description: string;
  resource_size?: unknown;
  resource_uri: string;
  vulnerabilities: MCPVulnerabilityAgent[];
}

export interface MCPAgentResultsData {
  tools?: MCPToolFinding[];
  prompts?: MCPPromptFinding[];
  resources?: MCPResourceFinding[];
}

// ----- Legacy format -----
interface MCPIssue {
  issue_code?: string;
  issue_message?: string;
  issue_type?: string;
  server?: string;
  tool?: { name?: string; description?: string } | null;
  issue_severity?: string;
}

interface MCPResultsDataLegacy {
  final_issues?: MCPIssue[];
  error_messages?: string[];
}

type MCPResultsData = MCPAgentResultsData & MCPResultsDataLegacy;

export type MCPEntityType = "tool" | "prompt" | "resource";

/** One row per vulnerability for the table */
interface VulnTableRow {
  resourceType: MCPEntityType;
  resourceName: string;
  vuln: MCPVulnerabilityAgent;
}

interface MCPResultsProps {
  data: MCPResultsData;
  conversationId?: number;
  teamId?: string;
  dashboard?: MCPDashboardData | null;
  integrationSettings?: Record<string, unknown> | null;
  onIntegrationSettingsUpdated?: () => void;
  onRefresh?: () => void;
  onDownloadReport?: () => void;
  isExporting?: boolean;
}

const RISK_ORDER = ["Critical", "High", "Medium", "Low"] as const;

function getImpactBadgeClass(impact: string): string {
  const s = (impact || "unknown").toLowerCase();
  if (s === "critical") return "bg-red-600 hover:bg-red-700 text-white";
  if (s === "high") return "bg-orange-500 hover:bg-orange-600 text-white";
  if (s === "medium") return "bg-amber-500 hover:bg-amber-600 text-white";
  if (s === "low") return "bg-blue-500 hover:bg-blue-600 text-white";
  return "bg-zinc-500 hover:bg-zinc-600 text-white";
}

function renderKeyValue(obj: Record<string, string> | undefined) {
  if (!obj || typeof obj !== "object") return null;
  const entries = Object.entries(obj);
  if (entries.length === 0) return null;
  return (
    <div className="flex flex-wrap gap-1.5">
      {entries.map(([key, label]) => (
        <Badge key={key} variant="secondary" className="text-xs font-normal">
          {label || key}
        </Badge>
      ))}
    </div>
  );
}

// ----- Risk metric cards -----
const RISK_CARDS = [
  { key: "Critical" as const, label: "Critical", description: "Most severe, requires immediate attention", color: "hsl(0 84% 60%)", icon: AlertTriangle },
  { key: "High" as const, label: "High", description: "Serious issues that should be addressed soon", color: "hsl(25 95% 53%)", icon: AlertTriangle },
  { key: "Medium" as const, label: "Medium", description: "Moderate risk, should be remediated", color: "hsl(48 96% 53%)", icon: AlertTriangle },
  { key: "Low" as const, label: "Low", description: "Minor findings, lower priority", color: "hsl(142 71% 45%)", icon: AlertTriangle },
] as const;

// ----- Dashboard charts (tools_* metrics) -----
const toolsVulnChartConfig = { name: { label: "Tool" }, count: { label: "Vulnerabilities", color: "hsl(0 84% 60%)" } } satisfies ChartConfig;
const toolsComplianceChartConfig = { name: { label: "Tool" }, count: { label: "Compliance controls", color: "hsl(217 91% 60%)" } } satisfies ChartConfig;
const toolsImpactChartConfig = {
  name: { label: "Tool" },
  critical: { label: "Critical", color: "hsl(0 84% 60%)" },
  high: { label: "High", color: "hsl(25 95% 53%)" },
  medium: { label: "Medium", color: "hsl(48 96% 53%)" },
  low: { label: "Low", color: "hsl(142 71% 45%)" },
} satisfies ChartConfig;

function MCPDashboardCharts({ dashboard }: { dashboard: MCPDashboardData }) {
  const riskMetrics = dashboard.risk_metrics ?? {};
  const toolsVuln = dashboard.tools_vulnerability_metrics ?? {};
  const toolsCompliance = dashboard.tools_compliance_controls_metrics ?? {};
  const toolsImpact = dashboard.tools_impact_metrics ?? {};

  const vulnBarData = Object.entries(toolsVuln)
    .map(([name, count]) => ({ name: name.length > 12 ? `${name.slice(0, 12)}...` : name, count }))
    .sort((a, b) => b.count - a.count);
  const complianceBarData = Object.entries(toolsCompliance)
    .map(([name, count]) => ({ name: name.length > 12 ? `${name.slice(0, 12)}...` : name, count }))
    .sort((a, b) => b.count - a.count);
  const impactAreaData = Object.entries(toolsImpact).map(([name, counts]) => ({
    name: name.length > 10 ? `${name.slice(0, 10)}...` : name,
    critical: counts?.critical ?? 0,
    high: counts?.high ?? 0,
    medium: counts?.medium ?? 0,
    low: counts?.low ?? 0,
  }));

  const hasVuln = vulnBarData.length > 0 && vulnBarData.some((d) => d.count > 0);
  const hasCompliance = complianceBarData.length > 0 && complianceBarData.some((d) => d.count > 0);
  const hasImpact = impactAreaData.length > 0 && impactAreaData.some((d) => d.critical + d.high + d.medium + d.low > 0);

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
              <BarChart3 className="w-4 h-4" />
              Tool vulnerability count
            </CardTitle>
            <CardDescription>Findings per tool</CardDescription>
          </CardHeader>
          <CardContent>
            {!hasVuln ? (
              <div className="flex items-center justify-center min-h-[260px] text-zinc-500 dark:text-zinc-400 text-sm">No data</div>
            ) : (
              <ChartContainer config={toolsVulnChartConfig} className="aspect-auto h-[260px] w-full pb-8">
                <BarChart data={vulnBarData} margin={{ top: 8, right: 8, bottom: 32, left: 0 }}>
                  <CartesianGrid vertical={false} className="stroke-zinc-200 dark:stroke-zinc-800" />
                  <XAxis dataKey="name" tickLine={false} axisLine={false} tickMargin={8} tickFormatter={(v) => (String(v).length > 10 ? `${String(v).slice(0, 10)}...` : v)} />
                  <YAxis type="number" tickLine={false} axisLine={false} />
                  <ChartTooltip cursor={false} content={<ChartTooltipContent />} />
                  <Bar dataKey="count" fill="var(--color-count)" radius={[8, 8, 0, 0]} />
                </BarChart>
              </ChartContainer>
            )}
          </CardContent>
        </Card>

        <Card className="border-zinc-200 dark:border-zinc-800">
          <CardHeader>
            <CardTitle className="text-base flex items-center gap-2">
              <Shield className="w-4 h-4" />
              Tool compliance controls count
            </CardTitle>
            <CardDescription>Compliance findings per tool</CardDescription>
          </CardHeader>
          <CardContent>
            {!hasCompliance ? (
              <div className="flex items-center justify-center min-h-[260px] text-zinc-500 dark:text-zinc-400 text-sm">No data</div>
            ) : (
              <ChartContainer config={toolsComplianceChartConfig} className="aspect-auto h-[260px] w-full pb-8">
                <BarChart data={complianceBarData} margin={{ top: 8, right: 8, bottom: 32, left: 0 }}>
                  <CartesianGrid vertical={false} className="stroke-zinc-200 dark:stroke-zinc-800" />
                  <XAxis dataKey="name" tickLine={false} axisLine={false} tickMargin={8} tickFormatter={(v) => (String(v).length > 10 ? `${String(v).slice(0, 10)}...` : v)} />
                  <YAxis type="number" tickLine={false} axisLine={false} />
                  <ChartTooltip cursor={false} content={<ChartTooltipContent />} />
                  <Bar dataKey="count" fill="var(--color-count)" radius={[8, 8, 0, 0]} />
                </BarChart>
              </ChartContainer>
            )}
          </CardContent>
        </Card>

        <Card className="border-zinc-200 dark:border-zinc-800">
          <CardHeader>
            <CardTitle className="text-base flex items-center gap-2">
              <TrendingUp className="w-4 h-4" />
              Tool impact by severity
            </CardTitle>
            <CardDescription>Critical / High / Medium / Low per tool</CardDescription>
          </CardHeader>
          <CardContent>
            {!hasImpact ? (
              <div className="flex items-center justify-center min-h-[260px] text-zinc-500 dark:text-zinc-400 text-sm">No data</div>
            ) : (
              <ChartContainer config={toolsImpactChartConfig} className="aspect-auto h-[260px] w-full pb-8">
                <AreaChart data={impactAreaData} margin={{ top: 8, right: 8, bottom: 28, left: 0 }}>
                  <defs>
                    <linearGradient id="mcpCritical" x1="0" y1="0" x2="0" y2="1"><stop offset="5%" stopColor="hsl(0 84% 60%)" stopOpacity={0.8} /><stop offset="95%" stopColor="hsl(0 84% 60%)" stopOpacity={0.1} /></linearGradient>
                    <linearGradient id="mcpHigh" x1="0" y1="0" x2="0" y2="1"><stop offset="5%" stopColor="hsl(25 95% 53%)" stopOpacity={0.8} /><stop offset="95%" stopColor="hsl(25 95% 53%)" stopOpacity={0.1} /></linearGradient>
                    <linearGradient id="mcpMedium" x1="0" y1="0" x2="0" y2="1"><stop offset="5%" stopColor="hsl(48 96% 53%)" stopOpacity={0.8} /><stop offset="95%" stopColor="hsl(48 96% 53%)" stopOpacity={0.1} /></linearGradient>
                    <linearGradient id="mcpLow" x1="0" y1="0" x2="0" y2="1"><stop offset="5%" stopColor="hsl(142 71% 45%)" stopOpacity={0.8} /><stop offset="95%" stopColor="hsl(142 71% 45%)" stopOpacity={0.1} /></linearGradient>
                  </defs>
                  <CartesianGrid vertical={false} className="stroke-zinc-200 dark:stroke-zinc-800" />
                  <XAxis dataKey="name" tickLine={false} axisLine={false} tickMargin={8} tickFormatter={(v) => (String(v).length > 10 ? `${String(v).slice(0, 10)}...` : v)} />
                  <YAxis hide domain={[0, "auto"]} />
                  <ChartTooltip cursor={false} content={<ChartTooltipContent />} />
                  <Area type="monotone" dataKey="critical" fill="url(#mcpCritical)" stroke="hsl(0 84% 60%)" strokeWidth={2} />
                  <Area type="monotone" dataKey="high" fill="url(#mcpHigh)" stroke="hsl(25 95% 53%)" strokeWidth={2} />
                  <Area type="monotone" dataKey="medium" fill="url(#mcpMedium)" stroke="hsl(48 96% 53%)" strokeWidth={2} />
                  <Area type="monotone" dataKey="low" fill="url(#mcpLow)" stroke="hsl(142 71% 45%)" strokeWidth={2} />
                </AreaChart>
              </ChartContainer>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

function AgentResultsView({
  data,
  conversationId,
  teamId,
  dashboard,
  integrationSettings,
  onIntegrationSettingsUpdated,
  onRefresh,
  onDownloadReport,
  isExporting,
}: {
  data: MCPAgentResultsData;
  conversationId?: number;
  teamId?: string;
  dashboard?: MCPDashboardData | null;
  integrationSettings?: Record<string, unknown> | null;
  onIntegrationSettingsUpdated?: () => void;
  onRefresh?: () => void;
  onDownloadReport?: () => void;
  isExporting?: boolean;
}) {
  const router = useRouter();
  const searchParams = useSearchParams();
  const queryClient = useQueryClient();
  const origin = searchParams.get("origin") || "chat";
  const [searchQuery, setSearchQuery] = useState("");
  const [detailOpen, setDetailOpen] = useState(false);
  const [selectedVuln, setSelectedVuln] = useState<VulnTableRow | null>(null);
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
        type: "mcp",
        scan_id: conversationId!,
        data: payload,
      }),
    onSuccess: () => {
      onIntegrationSettingsUpdated?.();
      const tid = parseInt(teamId ?? "0", 10);
      if (conversationId != null && tid > 0) {
        queryClient.invalidateQueries({ queryKey: ["mcp-conversation-data", tid, conversationId] });
      }
      toast.success("Ticketing settings saved");
    },
    onError: (err) => {
      showErrorToast(err, "Failed to save ticketing settings");
    },
  });

  const hasTicketingTab = Boolean(teamId && conversationId != null && onIntegrationSettingsUpdated != null);

  const tools = Array.isArray(data.tools) ? data.tools : [];
  const prompts = Array.isArray(data.prompts) ? data.prompts : [];
  const resources = Array.isArray(data.resources) ? data.resources : [];

  const tableRows: VulnTableRow[] = useMemo(() => {
    const rows: VulnTableRow[] = [];
    tools.forEach((t) =>
      (t.vulnerabilities ?? []).forEach((v) =>
        rows.push({ resourceType: "tool", resourceName: t.tool_name, vuln: v })
      )
    );
    prompts.forEach((p) =>
      (p.vulnerabilities ?? []).forEach((v) =>
        rows.push({ resourceType: "prompt", resourceName: p.prompt_name, vuln: v })
      )
    );
    resources.forEach((r) =>
      (r.vulnerabilities ?? []).forEach((v) =>
        rows.push({ resourceType: "resource", resourceName: r.resource_name, vuln: v })
      )
    );
    return rows;
  }, [tools, prompts, resources]);

  const filteredRows = useMemo(() => {
    const q = searchQuery.toLowerCase().trim();
    if (!q) return tableRows;
    return tableRows.filter(
      (r) =>
        r.resourceName.toLowerCase().includes(q) ||
        r.resourceType.toLowerCase().includes(q) ||
        (r.vuln.title ?? "").toLowerCase().includes(q) ||
        (r.vuln.description ?? "").toLowerCase().includes(q)
    );
  }, [tableRows, searchQuery]);

  const toggleRowSelection = (idx: number) => {
    setSelectedRows((prev) => {
      const next = new Set(prev);
      if (next.has(idx)) next.delete(idx);
      else next.add(idx);
      return next;
    });
  };

  const toggleSelectAll = () => {
    if (selectedRows.size === filteredRows.length) {
      setSelectedRows(new Set());
    } else {
      setSelectedRows(new Set(filteredRows.map((_, i) => i)));
    }
  };

  const createJiraTicketsMutation = useMutation({
    mutationFn: async () => {
      const tid = parseInt(teamId ?? "0", 10);
      if (!conversationId || Number.isNaN(tid)) throw new Error("Missing team or scan");
      const selectedFindings = Array.from(selectedRows).map((i) => filteredRows[i]);

      const impactCounts: Record<string, number> = {};
      for (const { vuln } of selectedFindings) {
        const impact = (vuln.impact ?? "Unknown").trim() || "Unknown";
        impactCounts[impact] = (impactCounts[impact] ?? 0) + 1;
      }
      let summary = Object.entries(impactCounts)
        .sort(([a], [b]) => RISK_ORDER.indexOf(a as (typeof RISK_ORDER)[number]) - RISK_ORDER.indexOf(b as (typeof RISK_ORDER)[number]))
        .map(([impact, count]) => `${count} ${impact}`)
        .join(", ") || `${selectedFindings.length} finding(s)`;
      summary = summary + " - Vulnerabilities found in MCP scan";

      const descSections = selectedFindings.map(({ resourceType, resourceName, vuln }, idx) => {
        const typeLabel = resourceType === "tool" ? "Tool" : resourceType === "prompt" ? "Prompt" : "Resource";
        const parts: string[] = [`--- Finding ${idx + 1} ---`];
        parts.push(`Title: ${(vuln.title ?? "Untitled finding").trim() || "Untitled finding"}`);
        if ((vuln.description ?? "").trim()) parts.push(`Description: ${vuln.description!.trim()}`);
        parts.push(`Resource: ${typeLabel} - ${resourceName}`);
        if ((vuln.impact ?? "").trim()) parts.push(`Impact: ${vuln.impact!.trim()}`);
        if ((vuln.suggested_fix ?? "").trim()) parts.push(`Suggested fix: ${vuln.suggested_fix!.trim()}`);
        return parts.join("\n");
      });
      const description = descSections.join("\n\n");

      await createTicket(tid, "mcp", conversationId, {
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

  const openDetail = (row: VulnTableRow) => {
    setSelectedVuln(row);
    setDetailOpen(true);
  };

  const typeLabel = (t: MCPEntityType) => (t === "tool" ? "Tool" : t === "prompt" ? "Prompt" : "Resource");
  const TypeIcon = ({ type }: { type: MCPEntityType }) => {
    if (type === "tool") return <Wrench className="h-4 w-4" />;
    if (type === "prompt") return <MessageSquare className="h-4 w-4" />;
    return <FolderOpen className="h-4 w-4" />;
  };

  return (
    <div className="container mx-auto p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          {conversationId && (
            <Button
              variant="outline"
              size="icon"
              onClick={() => router.push(origin === "list" ? (teamId ? `/${teamId}/mcp` : "/home/mcp") : (teamId ? `/${teamId}/mcp/${conversationId}` : `/home/mcp/${conversationId}`))}
              className="cursor-pointer"
            >
              <ArrowLeft className="h-4 w-4" />
            </Button>
          )}
          <div>
            <h1 className="text-3xl font-bold text-zinc-900 dark:text-white">MCP Scan Results</h1>
            <p className="text-sm text-zinc-600 dark:text-zinc-400 mt-1">
              Model Context Protocol — tools, prompts, and resources in one view
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
              onClick={() => router.push(`/${teamId}/mcp/${conversationId}`)}
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
          inputId="mcp-jira-project-id"
        />
      ) : (
        <>
      {dashboard && (dashboard.risk_metrics != null || dashboard.tools_vulnerability_metrics != null || dashboard.tools_impact_metrics != null || dashboard.tools_compliance_controls_metrics != null) && (
        <MCPDashboardCharts dashboard={dashboard} />
      )}

      <Card>
        <CardHeader>
          <CardTitle>Findings</CardTitle>
          <CardDescription>
            {tableRows.length} vulnerability findings. Click a title to view details. Select rows to create Jira tickets.
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
          <div className="relative mb-4">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-zinc-400" />
            <Input
              placeholder="Search by vulnerability, resource name..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="pl-9 max-w-sm"
            />
          </div>
          <ScrollArea className="h-[500px] rounded-md border border-zinc-200 dark:border-zinc-800">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-[48px]">
                    <Checkbox
                      checked={filteredRows.length > 0 && selectedRows.size === filteredRows.length}
                      onCheckedChange={toggleSelectAll}
                      aria-label="Select all rows"
                      className="cursor-pointer"
                    />
                  </TableHead>
                  <TableHead className="w-[280px]">Vulnerability</TableHead>
                  <TableHead className="w-[200px]">Resource</TableHead>
                  <TableHead className="w-[100px]">Impact</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {filteredRows.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={4} className="text-center py-8 text-zinc-500 dark:text-zinc-400">
                      No findings to display.
                    </TableCell>
                  </TableRow>
                ) : (
                  filteredRows.map((row, idx) => {
                    const vTitle = row.vuln.title ?? "Untitled finding";
                    const impact = (row.vuln.impact ?? "").trim() || "—";
                    return (
                      <TableRow
                        key={`${row.resourceType}-${row.resourceName}-${idx}`}
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
                            onClick={() => openDetail(row)}
                            className="text-left text-blue-600 hover:text-blue-700 dark:text-blue-400 dark:hover:text-blue-300 hover:underline cursor-pointer font-medium"
                          >
                            {vTitle}
                          </button>
                        </TableCell>
                        <TableCell className="text-zinc-600 dark:text-zinc-400 text-sm">
                          <span className="flex items-center gap-1.5 flex-wrap">
                            <Badge variant="outline" className="capitalize flex items-center gap-1 w-fit">
                              <TypeIcon type={row.resourceType} />
                              {typeLabel(row.resourceType)}
                            </Badge>
                            <span className="font-mono text-xs">{row.resourceName}</span>
                          </span>
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

      <Dialog open={detailOpen} onOpenChange={setDetailOpen}>
        <DialogContent className="max-w-4xl max-h-[90vh] flex flex-col p-0 gap-0 overflow-hidden">
          <DialogHeader className="px-6 pt-6 pb-2 shrink-0">
            <DialogTitle className="pr-8">
              {selectedVuln?.vuln.title ?? "Vulnerability details"}
            </DialogTitle>
          </DialogHeader>
          {selectedVuln && (
            <div className="min-h-0 flex-1 overflow-auto px-6 pb-6">
              <ScrollArea className="h-[70vh]">
                <div className="space-y-4 pr-4">
                  <div>
                    <div className="text-xs font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400 mb-1">Resource</div>
                    <span className="flex items-center gap-1.5">
                      <Badge variant="outline" className="capitalize flex items-center gap-1 w-fit">
                        <TypeIcon type={selectedVuln.resourceType} />
                        {typeLabel(selectedVuln.resourceType)}
                      </Badge>
                      <span className="font-mono text-sm text-zinc-700 dark:text-zinc-300">{selectedVuln.resourceName}</span>
                    </span>
                  </div>
                  {(selectedVuln.vuln.impact ?? "").trim() && (
                    <div>
                      <div className="text-xs font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400 mb-1">Impact</div>
                      <Badge variant="outline" className={getImpactBadgeClass(selectedVuln.vuln.impact!.trim())}>
                        {selectedVuln.vuln.impact!.trim()}
                      </Badge>
                    </div>
                  )}
                  {(selectedVuln.vuln.description ?? "").trim() && (
                    <div>
                      <div className="text-xs font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400 mb-1">Description</div>
                      <p className="text-sm text-zinc-700 dark:text-zinc-300">{selectedVuln.vuln.description!.trim()}</p>
                    </div>
                  )}
                  {selectedVuln.vuln.owasp_top_10 && Object.keys(selectedVuln.vuln.owasp_top_10).length > 0 && (
                    <div>
                      <div className="text-xs font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400 mb-1">OWASP Top 10</div>
                      {renderKeyValue(selectedVuln.vuln.owasp_top_10)}
                    </div>
                  )}
                  {selectedVuln.vuln.owasp_top_10_llm && Object.keys(selectedVuln.vuln.owasp_top_10_llm).length > 0 && (
                    <div>
                      <div className="text-xs font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400 mb-1">OWASP Top 10 for LLM</div>
                      {renderKeyValue(selectedVuln.vuln.owasp_top_10_llm)}
                    </div>
                  )}
                  {selectedVuln.vuln.compliance_controls && Object.keys(selectedVuln.vuln.compliance_controls).length > 0 && (
                    <div>
                      <div className="text-xs font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400 mb-1">Compliance controls</div>
                      {renderKeyValue(selectedVuln.vuln.compliance_controls)}
                    </div>
                  )}
                  {(selectedVuln.vuln.suggested_fix ?? "").trim() && (
                    <div>
                      <div className="text-xs font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400 mb-1">Suggested fix</div>
                      <p className="text-sm text-zinc-700 dark:text-zinc-300">{selectedVuln.vuln.suggested_fix!.trim()}</p>
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

function LegacyResultsView({ data, conversationId, teamId }: { data: MCPResultsDataLegacy; conversationId?: number; teamId?: string }) {
  const router = useRouter();
  const searchParams = useSearchParams();
  const origin = searchParams.get("origin") || "chat";
  const [searchQuery, setSearchQuery] = useState("");
  const issues: MCPIssue[] = Array.isArray(data?.final_issues) ? data.final_issues : [];
  const errorMessages: string[] = Array.isArray(data?.error_messages) ? data.error_messages : [];

  const filteredIssues = useMemo(() => {
    const q = searchQuery.toLowerCase();
    if (!q) return issues;
    return issues.filter(
      (i) =>
        (i.issue_code ?? "").toLowerCase().includes(q) ||
        (i.issue_message ?? "").toLowerCase().includes(q) ||
        (i.tool?.name ?? "").toLowerCase().includes(q)
    );
  }, [issues, searchQuery]);

  const getSeverityBadge = (severity?: string) => {
    const s = (severity || "unknown").toLowerCase();
    const cls = s === "critical" ? "bg-red-600 text-white" : s === "high" ? "bg-red-500 text-white" : s === "medium" ? "bg-orange-500 text-white" : s === "low" ? "bg-yellow-500 text-white" : "bg-gray-500 text-white";
    return <Badge variant="outline" className={cls}>{severity?.toUpperCase() ?? "UNKNOWN"}</Badge>;
  };

  return (
    <div className="container mx-auto p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          {conversationId && (
            <Button variant="outline" size="icon" onClick={() => router.push(origin === "list" ? (teamId ? `/${teamId}/mcp` : "/home/mcp") : (teamId ? `/${teamId}/mcp/${conversationId}` : `/home/mcp/${conversationId}`))} className="cursor-pointer">
              <ArrowLeft className="h-4 w-4" />
            </Button>
          )}
          <div>
            <h1 className="text-3xl font-bold text-zinc-900 dark:text-white">MCP Scan Results</h1>
            <p className="text-sm text-zinc-600 dark:text-zinc-400 mt-1">Legacy format: security issues</p>
          </div>
        </div>
        {teamId && conversationId != null && (
          <Button variant="default" className="cursor-pointer bg-blue-600 hover:bg-blue-700 text-white" onClick={() => router.push(`/${teamId}/mcp/${conversationId}`)}>
            <MessageCircle className="h-4 w-4 mr-2" />Chat with the Results
          </Button>
        )}
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Security Issues ({filteredIssues.length})</CardTitle>
          <CardDescription>Legacy scan issues</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="relative mb-4">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-zinc-400" />
            <Input placeholder="Search..." value={searchQuery} onChange={(e) => setSearchQuery(e.target.value)} className="pl-9 max-w-sm" />
          </div>
          <ScrollArea className="h-[400px]">
            <div className="space-y-2">
              {filteredIssues.length === 0 ? (
                <p className="text-center py-8 text-zinc-500">No issues match your search.</p>
              ) : (
                filteredIssues.map((issue, i) => (
                  <div key={i} className="flex items-center gap-2 p-3 rounded-lg border border-zinc-200 dark:border-zinc-700">
                    {getSeverityBadge(issue.issue_severity)}
                    <span className="font-mono text-sm">{issue.issue_code ?? "—"}</span>
                    <span className="text-sm text-zinc-600 truncate flex-1">{issue.issue_message}</span>
                    {issue.tool?.name && <Badge variant="outline">{issue.tool.name}</Badge>}
                  </div>
                ))
              )}
            </div>
          </ScrollArea>
        </CardContent>
      </Card>

      {errorMessages.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2"><AlertTriangle className="h-5 w-5 text-orange-500" />Scan Errors ({errorMessages.length})</CardTitle>
          </CardHeader>
          <CardContent>
            <ScrollArea className="h-[200px]">
              {errorMessages.map((err, idx) => (
                <div key={idx} className="p-3 bg-orange-50 dark:bg-orange-900/20 rounded border border-orange-200 dark:border-orange-800 text-sm text-orange-800 dark:text-orange-200 mb-2">{err}</div>
              ))}
            </ScrollArea>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

export default function MCPResults({ data, conversationId, teamId, dashboard, integrationSettings, onIntegrationSettingsUpdated, onRefresh, onDownloadReport, isExporting }: MCPResultsProps) {
  const hasAgentFormat = data && typeof data === "object" && (Array.isArray((data as MCPAgentResultsData).tools) || Array.isArray((data as MCPAgentResultsData).prompts) || Array.isArray((data as MCPAgentResultsData).resources));

  if (hasAgentFormat) {
    return (
      <AgentResultsView
        data={data as MCPAgentResultsData}
        conversationId={conversationId}
        teamId={teamId}
        dashboard={dashboard}
        integrationSettings={integrationSettings}
        onIntegrationSettingsUpdated={onIntegrationSettingsUpdated}
        onRefresh={onRefresh}
        onDownloadReport={onDownloadReport}
        isExporting={isExporting}
      />
    );
  }

  return (
    <LegacyResultsView
      data={data as MCPResultsDataLegacy}
      conversationId={conversationId}
      teamId={teamId}
    />
  );
}
