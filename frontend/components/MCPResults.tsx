"use client";

import { useState, useMemo, useEffect } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Checkbox } from "@/components/ui/checkbox";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
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
  BarChart3,
  TrendingUp,
  Shield,
  Ticket,
  Pencil,
  CheckCircle,
  EyeOff,
  Loader2,
  Circle,
  MoreVertical,
  Gauge,
  Bug,
  Clock,
  Percent,
  Crosshair,
  Filter,
  Check,
  X,
  ChevronDown,
} from "lucide-react";
import { ScrollArea } from "@/components/ui/scroll-area";
import RemediationPanel from "@/components/RemediationPanel";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
  DropdownMenuLabel,
  DropdownMenuSeparator,
} from "@/components/ui/dropdown-menu";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { useRouter, useSearchParams } from "next/navigation";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import type { MCPDashboardData, MCPFinding, MCPScanMetadata, ScanTicketingIntegrationSettings } from "@/utils/backend_api";
import { updateScan, createTicket, toggleFindingState } from "@/utils/backend_api";
import { showErrorToast } from "@/utils/error-handler";
import FindingSelectionMenu from "@/components/finding-selection-menu";
import TicketingIntegrationsSettings from "@/components/ticketing-integrations-settings";
import {
  ChartContainer,
  ChartTooltip,
  ChartTooltipContent,
  type ChartConfig,
} from "@/components/ui/chart";
import { Area, AreaChart, Bar, BarChart, CartesianGrid, Cell, Pie, PieChart, XAxis, YAxis } from "recharts";

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
  findings?: MCPFinding[] | null;
  scanMetadata?: MCPScanMetadata | Record<string, unknown> | null;
  onFindingsUpdated?: () => void;
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

/** Colored box classes for finding status (fixed, ignored, in_progress, not_started) */
function getFindingStatusBadgeClass(status: string): string {
  const s = (status ?? "").toLowerCase().replace(/\s/g, "_");
  if (s === "fixed") return "bg-emerald-100 text-emerald-800 dark:bg-emerald-900/40 dark:text-emerald-200";
  if (s === "ignored") return "bg-zinc-100 text-zinc-700 dark:bg-zinc-700/50 dark:text-zinc-200";
  if (s === "in_progress") return "bg-blue-100 text-blue-800 dark:bg-blue-900/40 dark:text-blue-200";
  if (s === "not_started") return "bg-slate-100 text-slate-600 dark:bg-slate-700/50 dark:text-slate-300";
  return "bg-zinc-100 text-zinc-600 dark:bg-zinc-700/50 dark:text-zinc-300";
}

function countFindingField(val: unknown): number {
  if (val == null) return 0;
  if (Array.isArray(val)) return val.length;
  if (typeof val === "object" && !Array.isArray(val)) return Object.keys(val).length;
  return 0;
}

// ----- Scan metadata (colored boxes below title) -----
function MCPScanMetadataBlock({ scanMetadata }: { scanMetadata: MCPScanMetadata | Record<string, unknown> | null }) {
  if (!scanMetadata || typeof scanMetadata !== "object") return null;
  const server_url = (scanMetadata as MCPScanMetadata).server_url ?? (scanMetadata as Record<string, unknown>).server_url;
  const server_mode = (scanMetadata as MCPScanMetadata).server_mode ?? (scanMetadata as Record<string, unknown>).server_mode;
  if (server_url == null && server_mode == null) return null;
  return (
    <div className="flex flex-wrap gap-3 mt-2">
      {server_url != null && String(server_url).trim() && (
        <div className="flex flex-col gap-0.5 rounded-lg bg-violet-500/15 dark:bg-violet-500/20 border border-violet-200/50 dark:border-violet-500/30 px-4 py-2 min-w-0 max-w-full">
          <span className="text-xs font-semibold uppercase tracking-wide text-violet-600 dark:text-violet-400">Server URL</span>
          <span className="font-mono text-sm text-violet-800 dark:text-violet-200 break-all">{String(server_url).trim()}</span>
        </div>
      )}
    </div>
  );
}

// ----- Dashboard charts (tools impact + full dashboard) -----
const toolsImpactChartConfig = {
  name: { label: "Tool" },
  critical: { label: "Critical", color: "hsl(0 84% 60%)" },
  high: { label: "High", color: "hsl(25 95% 53%)" },
  medium: { label: "Medium", color: "hsl(48 96% 53%)" },
  low: { label: "Low", color: "hsl(142 71% 45%)" },
} satisfies ChartConfig;

const SEVERITY_PIE_COLORS = ["hsl(0 84% 60%)", "hsl(25 95% 53%)", "hsl(48 96% 53%)", "hsl(142 71% 45%)"];
const COMPLIANCE_PIE_COLORS = ["#dc2626", "#ea580c", "#ca8a04", "#2563eb", "#7c3aed", "#0d9488", "#0891b2", "#db2777", "#65a30d", "#64748b"];

function formatMttr(mttr: number | [number, number, number] | undefined): string {
  if (mttr == null) return "—";
  if (Array.isArray(mttr)) {
    const [days, hours, mins] = mttr;
    const parts = [];
    if (days > 0) parts.push(`${days}d`);
    if (hours > 0) parts.push(`${hours}h`);
    if (mins > 0 || parts.length === 0) parts.push(`${mins}m`);
    return parts.join(" ");
  }
  return `${Number(mttr)}`;
}

function MCPDashboardCharts({ dashboard }: { dashboard: MCPDashboardData }) {
  const cardData = dashboard.card_data;
  const severityDist = dashboard.severity_distribution ?? { critical: 0, high: 0, medium: 0, low: 0 };
  const categoryCoverage = dashboard.category_coverage ?? {};
  const categoryThreat = dashboard.category_threat_landscape ?? {};
  const complianceFrameworks = dashboard.compliance_framework_scores ?? {};
  const complianceFailureTrends = dashboard.compliance_failure_trends ?? {};
  const assetAttackSurface = dashboard.asset_attack_surface ?? {};
  const toolImpactAnalysis = dashboard.tool_impact_analysis ?? dashboard.tools_impact_metrics ?? {};
  const assetComplianceViolations = dashboard.asset_compliance_violations ?? {};
  const owaspLlmMetrics = dashboard.owasp_top_10_llm_metrics ?? {};

  const toolsImpact = toolImpactAnalysis;

  const impactAreaData = Object.entries(toolsImpact).map(([name, counts], i) => ({
    xLabel: `T${i + 1}`,
    fullName: name,
    critical: counts?.critical ?? 0,
    high: counts?.high ?? 0,
    medium: counts?.medium ?? 0,
    low: counts?.low ?? 0,
  }));

  const hasImpact = impactAreaData.length > 0 && impactAreaData.some((d) => d.critical + d.high + d.medium + d.low > 0);

  const severityPieData = [
    { name: "Critical", value: severityDist.critical, fill: SEVERITY_PIE_COLORS[0] },
    { name: "High", value: severityDist.high, fill: SEVERITY_PIE_COLORS[1] },
    { name: "Medium", value: severityDist.medium, fill: SEVERITY_PIE_COLORS[2] },
    { name: "Low", value: severityDist.low, fill: SEVERITY_PIE_COLORS[3] },
  ].filter((d) => d.value > 0);
  const categoryPieData = Object.entries(categoryCoverage)
    .filter(([, v]) => Number(v) > 0)
    .map(([name, value]) => ({ name: name.replace(/_/g, " "), value: Number(value), fill: "hsl(217 91% 60%)" }));
  const compliancePieData = Object.entries(complianceFrameworks)
    .filter(([, v]) => Number(v) > 0)
    .map(([name, value], i) => ({ name, value: Number(value), fill: COMPLIANCE_PIE_COLORS[i % COMPLIANCE_PIE_COLORS.length] }));
  const categoryThreatBarData = Object.entries(categoryThreat).map(([name, v]) => ({
    name: name.replace(/_/g, " "),
    avg_risk_score: typeof v === "object" && v && "avg_risk_score" in v ? Number((v as { avg_risk_score: number }).avg_risk_score) : 0,
    total_issues: typeof v === "object" && v && "total_issues" in v ? Number((v as { total_issues: number }).total_issues) : 0,
  }));
  const complianceFailureData = Object.entries(complianceFailureTrends).map(([name, value], i) => ({
    xLabel: `F${i + 1}`,
    fullName: name,
    name: name.length > 20 ? `${name.slice(0, 20)}...` : name,
    count: Number(value),
  }));
  const assetAttackAreaData = Object.entries(assetAttackSurface).map(([name, level], i) => {
    const levelStr = String(level).toLowerCase();
    const score = levelStr === "critical" ? 4 : levelStr === "high" ? 3 : levelStr === "medium" ? 2 : 1;
    return {
      xLabel: `A${i + 1}`,
      fullName: name,
      name: name.length > 15 ? `${name.slice(0, 15)}...` : name,
      score,
    };
  });
  const assetComplianceAreaData = Object.entries(assetComplianceViolations)
    .map(([name, value]) => ({
      fullName: name,
      name: name.length > 12 ? `${name.slice(0, 12)}...` : name,
      count: Number(value),
    }))
    .filter((d) => d.count > 0)
    .sort((a, b) => b.count - a.count)
    .map((d, i) => ({ ...d, xLabel: `A${i + 1}` }));
  const owaspLlmData = Object.entries(owaspLlmMetrics)
    .filter(([, v]) => Number(v) > 0)
    .map(([name, value]) => ({ name: name.includes(" - ") ? name.split(" - ")[0] : name, count: Number(value) }));

  const hasCardData = cardData && typeof cardData === "object";
  const hasSeverityPie = severityPieData.length > 0;
  const hasCategoryPie = categoryPieData.length > 0;
  const hasCategoryThreat = categoryThreatBarData.length > 0 && categoryThreatBarData.some((d) => d.avg_risk_score > 0 || d.total_issues > 0);
  const hasCompliancePie = compliancePieData.length > 0;
  const hasComplianceTrends = complianceFailureData.length > 0;
  const hasAssetAttack = assetAttackAreaData.length > 0;
  const hasAssetCompliance = assetComplianceAreaData.length > 0;
  const hasOwaspLlm = owaspLlmData.length > 0;

  const overallRiskScore = cardData?.overall_risk_score != null ? Number(cardData.overall_risk_score) : null;

  return (
    <div className="space-y-6">
      {hasCardData && (
        <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-8 gap-4">
          <Card className="border-zinc-200 dark:border-zinc-800 py-3 px-3">
            <CardContent className="p-0">
              <div className="flex flex-col items-start gap-2">
                <div className={`flex h-8 w-8 shrink-0 items-center justify-center rounded-lg ${overallRiskScore != null && overallRiskScore >= 7 ? "bg-red-500/15 dark:bg-red-500/10" : overallRiskScore != null && overallRiskScore >= 5 ? "bg-amber-500/15 dark:bg-amber-500/10" : "bg-green-500/15 dark:bg-green-500/10"}`}>
                  <Gauge className={`h-4 w-4 ${overallRiskScore != null && overallRiskScore >= 7 ? "text-red-500" : overallRiskScore != null && overallRiskScore >= 5 ? "text-amber-500" : "text-green-500"}`} />
                </div>
                <div>
                  <p className="text-xs font-medium text-zinc-600 dark:text-zinc-400">Risk score</p>
                  <p className="text-xl font-bold text-zinc-900 dark:text-white">{cardData.overall_risk_score ?? "—"}</p>
                </div>
              </div>
            </CardContent>
          </Card>
          <Card className="border-zinc-200 dark:border-zinc-800 py-3 px-3">
            <CardContent className="p-0">
              <div className="flex flex-col items-start gap-2">
                <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-red-500/15 dark:bg-red-500/10">
                  <AlertTriangle className="h-4 w-4 text-red-500" />
                </div>
                <div>
                  <p className="text-xs font-medium text-zinc-600 dark:text-zinc-400">Total findings</p>
                  <p className="text-xl font-bold text-zinc-900 dark:text-white">{cardData.total_findings ?? "—"}</p>
                </div>
              </div>
            </CardContent>
          </Card>
          <Card className="border-zinc-200 dark:border-zinc-800 py-3 px-3">
            <CardContent className="p-0">
              <div className="flex flex-col items-start gap-2">
                <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-amber-500/15 dark:bg-amber-500/10">
                  <TrendingUp className="h-4 w-4 text-amber-500" />
                </div>
                <div>
                  <p className="text-xs font-medium text-zinc-600 dark:text-zinc-400">Exploitability index</p>
                  <p className="text-xl font-bold text-zinc-900 dark:text-white">{cardData.exploitability_index != null ? `${cardData.exploitability_index}%` : "—"}</p>
                </div>
              </div>
            </CardContent>
          </Card>
          <Card className="border-zinc-200 dark:border-zinc-800 py-3 px-3">
            <CardContent className="p-0">
              <div className="flex flex-col items-start gap-2">
                <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-blue-500/15 dark:bg-blue-500/10">
                  <Crosshair className="h-4 w-4 text-blue-500" />
                </div>
                <div>
                  <p className="text-xs font-medium text-zinc-600 dark:text-zinc-400">Attack surface</p>
                  <p className="text-xl font-bold text-zinc-900 dark:text-white">{cardData.attack_surface ?? "—"}</p>
                </div>
              </div>
            </CardContent>
          </Card>
          <Card className="border-zinc-200 dark:border-zinc-800 py-3 px-3">
            <CardContent className="p-0">
              <div className="flex flex-col items-start gap-2">
                <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-zinc-500/15 dark:bg-zinc-400/10">
                  <Clock className="h-4 w-4 text-zinc-500 dark:text-zinc-400" />
                </div>
                <div>
                  <p className="text-xs font-medium text-zinc-600 dark:text-zinc-400">MTTR</p>
                  <p className="text-xl font-bold text-zinc-900 dark:text-white">{formatMttr(cardData.mttr)}</p>
                </div>
              </div>
            </CardContent>
          </Card>
          <Card className="border-zinc-200 dark:border-zinc-800 py-3 px-3">
            <CardContent className="p-0">
              <div className="flex flex-col items-start gap-2">
                <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-red-500/15 dark:bg-red-500/10">
                  <Bug className="h-4 w-4 text-red-500" />
                </div>
                <div>
                  <p className="text-xs font-medium text-zinc-600 dark:text-zinc-400">Active vulnerabilities</p>
                  <p className="text-xl font-bold text-zinc-900 dark:text-white">{cardData.active_vulnerabilities ?? "—"}</p>
                </div>
              </div>
            </CardContent>
          </Card>
          <Card className="border-zinc-200 dark:border-zinc-800 py-3 px-3">
            <CardContent className="p-0">
              <div className="flex flex-col items-start gap-2">
                <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-green-500/15 dark:bg-green-500/10">
                  <Shield className="h-4 w-4 text-green-500" />
                </div>
                <div>
                  <p className="text-xs font-medium text-zinc-600 dark:text-zinc-400">Compliance score</p>
                  <p className="text-xl font-bold text-zinc-900 dark:text-white">{cardData.compliance_score != null ? `${cardData.compliance_score}%` : "—"}</p>
                </div>
              </div>
            </CardContent>
          </Card>
          <Card className="border-zinc-200 dark:border-zinc-800 py-3 px-3">
            <CardContent className="p-0">
              <div className="flex flex-col items-start gap-2">
                <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-blue-500/15 dark:bg-blue-500/10">
                  <Percent className="h-4 w-4 text-blue-500" />
                </div>
                <div>
                  <p className="text-xs font-medium text-zinc-600 dark:text-zinc-400">Category coverage</p>
                  <p className="text-xl font-bold text-zinc-900 dark:text-white">{cardData.category_coverage != null ? `${cardData.category_coverage}%` : "—"}</p>
                </div>
              </div>
            </CardContent>
          </Card>
        </div>
      )}
      {hasImpact && (
        <Card className="border-zinc-200 dark:border-zinc-800">
          <CardHeader>
            <CardTitle className="text-base flex items-center gap-2">
              <TrendingUp className="w-4 h-4" />
              Tool impact by severity
            </CardTitle>
            <CardDescription>Critical / High / Medium / Low per tool</CardDescription>
          </CardHeader>
          <CardContent>
            <ChartContainer config={toolsImpactChartConfig} className="aspect-auto h-[260px] w-full pb-8">
              <AreaChart data={impactAreaData} margin={{ top: 8, right: 8, bottom: 28, left: 0 }}>
                  <defs>
                    <linearGradient id="mcpCritical" x1="0" y1="0" x2="0" y2="1"><stop offset="5%" stopColor="hsl(0 84% 60%)" stopOpacity={0.8} /><stop offset="95%" stopColor="hsl(0 84% 60%)" stopOpacity={0.1} /></linearGradient>
                    <linearGradient id="mcpHigh" x1="0" y1="0" x2="0" y2="1"><stop offset="5%" stopColor="hsl(25 95% 53%)" stopOpacity={0.8} /><stop offset="95%" stopColor="hsl(25 95% 53%)" stopOpacity={0.1} /></linearGradient>
                    <linearGradient id="mcpMedium" x1="0" y1="0" x2="0" y2="1"><stop offset="5%" stopColor="hsl(48 96% 53%)" stopOpacity={0.8} /><stop offset="95%" stopColor="hsl(48 96% 53%)" stopOpacity={0.1} /></linearGradient>
                    <linearGradient id="mcpLow" x1="0" y1="0" x2="0" y2="1"><stop offset="5%" stopColor="hsl(142 71% 45%)" stopOpacity={0.8} /><stop offset="95%" stopColor="hsl(142 71% 45%)" stopOpacity={0.1} /></linearGradient>
                  </defs>
                  <CartesianGrid vertical={false} className="stroke-zinc-200 dark:stroke-zinc-800" />
                  <XAxis dataKey="xLabel" tickLine={false} axisLine={false} tickMargin={8} />
                  <YAxis hide domain={[0, "auto"]} />
                  <ChartTooltip
                    cursor={false}
                    content={
                      <ChartTooltipContent
                        labelFormatter={(_, payload) => (payload?.[0]?.payload as { fullName?: string })?.fullName ?? "—"}
                      />
                    }
                  />
                  <Area type="monotone" dataKey="critical" fill="url(#mcpCritical)" stroke="hsl(0 84% 60%)" strokeWidth={2} />
                  <Area type="monotone" dataKey="high" fill="url(#mcpHigh)" stroke="hsl(25 95% 53%)" strokeWidth={2} />
                  <Area type="monotone" dataKey="medium" fill="url(#mcpMedium)" stroke="hsl(48 96% 53%)" strokeWidth={2} />
                  <Area type="monotone" dataKey="low" fill="url(#mcpLow)" stroke="hsl(142 71% 45%)" strokeWidth={2} />
                </AreaChart>
              </ChartContainer>
          </CardContent>
        </Card>
      )}

      {(hasSeverityPie || hasCategoryPie) && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <Card className="border-zinc-200 dark:border-zinc-800">
            <CardHeader>
              <CardTitle className="text-base">Severity distribution</CardTitle>
              <CardDescription>Findings by impact level</CardDescription>
            </CardHeader>
            <CardContent className="pb-4">
              {!hasSeverityPie ? (
                <div className="flex items-center justify-center min-h-[260px] text-zinc-500 dark:text-zinc-400 text-sm">No data</div>
              ) : (
                <ChartContainer config={{ name: { label: "Severity" }, value: { label: "Count" } }} className="aspect-square max-h-[260px] w-full">
                  <PieChart>
                    <Pie data={severityPieData} dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius="80%" label={({ name, value }) => `${name}: ${value}`}>
                      {severityPieData.map((_, i) => (
                        <Cell key={i} fill={SEVERITY_PIE_COLORS[i % SEVERITY_PIE_COLORS.length]} />
                      ))}
                    </Pie>
                    <ChartTooltip content={<ChartTooltipContent />} />
                  </PieChart>
                </ChartContainer>
              )}
              <p className="text-xs text-zinc-500 dark:text-zinc-400 mt-4 pt-3 border-t border-zinc-200 dark:border-zinc-800">
                Shows the proportion of findings across Critical, High, Medium, and Low severity levels. Helps prioritize remediation efforts.
              </p>
            </CardContent>
          </Card>

          <Card className="border-zinc-200 dark:border-zinc-800">
            <CardHeader>
              <CardTitle className="text-base">Coverage by category</CardTitle>
              <CardDescription>Findings by category</CardDescription>
            </CardHeader>
            <CardContent className="pb-4">
              {!hasCategoryPie ? (
                <div className="flex items-center justify-center min-h-[260px] text-zinc-500 dark:text-zinc-400 text-sm">No data</div>
              ) : (
                <ChartContainer config={{ name: { label: "Category" }, value: { label: "Count" } }} className="aspect-square max-h-[260px] w-full">
                  <PieChart>
                    <Pie data={categoryPieData} dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius="80%" label={({ name, value }) => `${name}: ${value}`}>
                      {categoryPieData.map((entry) => (
                        <Cell key={entry.name} fill={entry.fill} />
                      ))}
                    </Pie>
                    <ChartTooltip content={<ChartTooltipContent />} />
                  </PieChart>
                </ChartContainer>
              )}
              <p className="text-xs text-zinc-500 dark:text-zinc-400 mt-4 pt-3 border-t border-zinc-200 dark:border-zinc-800">
                Breaks down findings by vulnerability category to show which areas need more attention and testing coverage.
              </p>
            </CardContent>
          </Card>
        </div>
      )}

      {(hasCategoryThreat || hasCompliancePie) && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <Card className="border-zinc-200 dark:border-zinc-800">
            <CardHeader>
              <CardTitle className="text-base">Category threat landscape</CardTitle>
              <CardDescription>Avg risk score and total issues per category</CardDescription>
            </CardHeader>
            <CardContent className="pb-4">
              {!hasCategoryThreat ? (
                <div className="flex items-center justify-center min-h-[260px] text-zinc-500 dark:text-zinc-400 text-sm">No data</div>
              ) : (
                <ChartContainer config={{ name: { label: "Category" }, avg_risk_score: { label: "Avg risk score", color: "hsl(217 91% 60%)" }, total_issues: { label: "Total issues", color: "hsl(142 71% 45%)" } }} className="aspect-auto h-[240px] w-full pb-8">
                  <BarChart data={categoryThreatBarData} margin={{ top: 8, right: 8, bottom: 32, left: 0 }}>
                    <CartesianGrid vertical={false} className="stroke-zinc-200 dark:stroke-zinc-800" />
                    <XAxis dataKey="name" tickLine={false} axisLine={false} tickMargin={8} />
                    <YAxis type="number" tickLine={false} axisLine={false} />
                    <ChartTooltip cursor={false} content={<ChartTooltipContent />} />
                    <Bar dataKey="avg_risk_score" fill="hsl(217 91% 60%)" radius={[8, 8, 0, 0]} />
                    <Bar dataKey="total_issues" fill="hsl(142 71% 45%)" radius={[8, 8, 0, 0]} />
                  </BarChart>
                </ChartContainer>
              )}
              <p className="text-xs text-zinc-500 dark:text-zinc-400 mt-4 pt-3 border-t border-zinc-200 dark:border-zinc-800">
                Displays average risk score and total issue count per category to identify high-threat areas in the MCP attack surface.
              </p>
            </CardContent>
          </Card>

          <Card className="border-zinc-200 dark:border-zinc-800">
            <CardHeader>
              <CardTitle className="text-base">Compliance framework scores</CardTitle>
              <CardDescription>Violations by framework</CardDescription>
            </CardHeader>
            <CardContent className="pb-4">
              {!hasCompliancePie ? (
                <div className="flex items-center justify-center min-h-[260px] text-zinc-500 dark:text-zinc-400 text-sm">No data</div>
              ) : (
                <ChartContainer config={{ name: { label: "Framework" }, value: { label: "Count" } }} className="aspect-square max-h-[240px] w-full">
                  <PieChart>
                    <Pie data={compliancePieData} dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius="80%" label={({ name, value }) => `${name}: ${value}`}>
                      {compliancePieData.map((entry) => (
                        <Cell key={entry.name} fill={entry.fill} />
                      ))}
                    </Pie>
                    <ChartTooltip content={<ChartTooltipContent />} />
                  </PieChart>
                </ChartContainer>
              )}
              <p className="text-xs text-zinc-500 dark:text-zinc-400 mt-4 pt-3 border-t border-zinc-200 dark:border-zinc-800">
                Summarizes compliance control violations by framework (e.g. SOC2, HIPAA) for audit and governance visibility.
              </p>
            </CardContent>
          </Card>
        </div>
      )}

      {hasComplianceTrends && (
        <Card className="border-zinc-200 dark:border-zinc-800">
          <CardHeader>
            <CardTitle className="text-base">Compliance failure trends</CardTitle>
            <CardDescription>Compliance controls violated per finding</CardDescription>
          </CardHeader>
          <CardContent>
            <ChartContainer config={{ name: { label: "Finding" }, count: { label: "Count", color: "hsl(217 91% 60%)" } }} className="aspect-auto h-[260px] w-full pb-8">
              <BarChart data={complianceFailureData} margin={{ top: 8, right: 8, bottom: 32, left: 0 }}>
                <CartesianGrid vertical={false} className="stroke-zinc-200 dark:stroke-zinc-800" />
                <XAxis dataKey="xLabel" tickLine={false} axisLine={false} tickMargin={8} />
                <YAxis type="number" tickLine={false} axisLine={false} />
                <ChartTooltip
                  cursor={false}
                  content={
                    <ChartTooltipContent
                      labelFormatter={(_, payload) => (payload?.[0]?.payload as { fullName?: string })?.fullName ?? "—"}
                    />
                  }
                />
                <Bar dataKey="count" fill="hsl(217 91% 60%)" radius={[8, 8, 0, 0]} />
              </BarChart>
            </ChartContainer>
          </CardContent>
        </Card>
      )}

      {hasAssetAttack && (
        <Card className="border-zinc-200 dark:border-zinc-800">
          <CardHeader>
            <CardTitle className="text-base">Asset attack surface</CardTitle>
            <CardDescription>Risk level per asset (tool / prompt / resource) — Critical=4, High=3, Medium=2, Low=1</CardDescription>
          </CardHeader>
          <CardContent>
            <ChartContainer config={{ name: { label: "Asset" }, score: { label: "Risk score", color: "hsl(0 84% 60%)" } }} className="aspect-auto h-[260px] w-full pb-8">
              <AreaChart data={assetAttackAreaData} margin={{ top: 8, right: 8, bottom: 32, left: 0 }}>
                <CartesianGrid vertical={false} className="stroke-zinc-200 dark:stroke-zinc-800" />
                <XAxis dataKey="xLabel" tickLine={false} axisLine={false} tickMargin={8} />
                <YAxis type="number" tickLine={false} axisLine={false} domain={[0, 4]} tickFormatter={(v) => (v === 4 ? "Critical" : v === 3 ? "High" : v === 2 ? "Medium" : v === 1 ? "Low" : "")} />
                <ChartTooltip
                  cursor={false}
                  content={
                    <ChartTooltipContent
                      labelFormatter={(_, payload) => (payload?.[0]?.payload as { fullName?: string })?.fullName ?? "—"}
                      formatter={(value) => [value, "Risk score"]}
                    />
                  }
                />
                <Area type="monotone" dataKey="score" fill="hsl(0 84% 60% / 0.4)" stroke="hsl(0 84% 60%)" strokeWidth={2} />
              </AreaChart>
            </ChartContainer>
          </CardContent>
        </Card>
      )}

      {hasAssetCompliance && (
        <Card className="border-zinc-200 dark:border-zinc-800">
          <CardHeader>
            <CardTitle className="text-base">Asset compliance violations</CardTitle>
            <CardDescription>Compliance controls violated per asset</CardDescription>
          </CardHeader>
          <CardContent>
            <ChartContainer config={{ name: { label: "Asset" }, count: { label: "Count", color: "hsl(48 96% 53%)" } }} className="aspect-auto h-[260px] w-full pb-8">
              <AreaChart data={assetComplianceAreaData} margin={{ top: 8, right: 8, bottom: 32, left: 0 }}>
                <CartesianGrid vertical={false} className="stroke-zinc-200 dark:stroke-zinc-800" />
                <XAxis dataKey="xLabel" tickLine={false} axisLine={false} tickMargin={8} />
                <YAxis type="number" tickLine={false} axisLine={false} allowDecimals={false} />
                <ChartTooltip
                  cursor={false}
                  content={
                    <ChartTooltipContent
                      labelFormatter={(_, payload) => (payload?.[0]?.payload as { fullName?: string })?.fullName ?? "—"}
                    />
                  }
                />
                <Area type="monotone" dataKey="count" fill="hsl(48 96% 53% / 0.4)" stroke="hsl(48 96% 53%)" strokeWidth={2} />
              </AreaChart>
            </ChartContainer>
          </CardContent>
        </Card>
      )}

      {hasOwaspLlm && (
        <Card className="border-zinc-200 dark:border-zinc-800">
          <CardHeader>
            <CardTitle className="text-base">OWASP Top 10 for LLM</CardTitle>
            <CardDescription>Findings by OWASP LLM category</CardDescription>
          </CardHeader>
          <CardContent>
            <ChartContainer config={{ name: { label: "Category" }, count: { label: "Count", color: "hsl(270 50% 60%)" } }} className="aspect-auto h-[260px] w-full pb-8">
              <BarChart data={owaspLlmData} margin={{ top: 8, right: 8, bottom: 32, left: 0 }}>
                <CartesianGrid vertical={false} className="stroke-zinc-200 dark:stroke-zinc-800" />
                <XAxis dataKey="name" tickLine={false} axisLine={false} tickMargin={8} tickFormatter={(v) => (String(v).length > 14 ? `${String(v).slice(0, 14)}...` : v)} />
                <YAxis type="number" tickLine={false} axisLine={false} />
                <ChartTooltip cursor={false} content={<ChartTooltipContent />} />
                <Bar dataKey="count" fill="hsl(270 50% 60%)" radius={[8, 8, 0, 0]} />
              </BarChart>
            </ChartContainer>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

function AgentResultsView({
  data,
  conversationId,
  teamId,
  dashboard,
  findings: apiFindings,
  scanMetadata,
  onFindingsUpdated,
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
  findings?: MCPFinding[] | null;
  scanMetadata?: MCPScanMetadata | Record<string, unknown> | null;
  onFindingsUpdated?: () => void;
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
  const [filterImpact, setFilterImpact] = useState<string>("all");
  type RiskScoreFilter = "all" | "critical" | "high" | "medium" | "low";
  const [filterRiskScore, setFilterRiskScore] = useState<RiskScoreFilter>("all");
  function matchesRiskScoreFilter(score: number | null | undefined, filter: RiskScoreFilter): boolean {
    if (filter === "all") return true;
    if (score == null) return false;
    if (filter === "critical") return score >= 9;
    if (filter === "high") return score >= 7 && score < 9;
    if (filter === "medium") return score >= 5 && score < 7;
    if (filter === "low") return score < 5;
    return true;
  }
  const RISK_SCORE_LABELS: Record<RiskScoreFilter, string> = {
    all: "Risk score",
    critical: "Critical",
    high: "High",
    medium: "Medium",
    low: "Low",
  };
  const [detailOpen, setDetailOpen] = useState(false);
  const [selectedVuln, setSelectedVuln] = useState<VulnTableRow | null>(null);
  const [selectedApiFinding, setSelectedApiFinding] = useState<MCPFinding | null>(null);
  const [activeTab, setActiveTab] = useState<"results" | "ticketing">("results");
  const [selectedRows, setSelectedRows] = useState<Set<number>>(new Set());
  const [selectedFindingIds, setSelectedFindingIds] = useState<Set<string>>(new Set());
  const [jiraProjectId, setJiraProjectId] = useState("");
  const [autoCreateTickets, setAutoCreateTickets] = useState(false);

  const findingsList = Array.isArray(apiFindings) ? apiFindings : [];
  const useApiFindings = findingsList.length > 0;
  const hasActiveFindingsFilters =
    searchQuery.trim() !== "" || filterImpact !== "all" || filterRiskScore !== "all";
  const clearFindingsFilters = () => {
    setSearchQuery("");
    setFilterImpact("all");
    setFilterRiskScore("all");
  };

  const jiraFromSettings =
    integrationSettings && typeof integrationSettings === "object" && "jira" in integrationSettings
      ? (integrationSettings.jira as { jira_project_id?: string; auto_create_tickets?: boolean } | undefined)
      : undefined;
  const initialJiraProjectId = jiraFromSettings?.jira_project_id ?? "";
  useEffect(() => {
    setJiraProjectId(initialJiraProjectId);
  }, [initialJiraProjectId]);
  useEffect(() => {
    setAutoCreateTickets(jiraFromSettings?.auto_create_tickets === true);
  }, [jiraFromSettings?.auto_create_tickets]);

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

  const toggleFindingMutation = useMutation({
    mutationFn: ({ finding_id, state }: { finding_id: string; state: "fixed" | "ignored" | "in_progress" | "not_started" }) => {
      const tid = parseInt(teamId ?? "0", 10);
      if (!conversationId || Number.isNaN(tid)) throw new Error("Missing team or scan");
      return toggleFindingState({ team_id: tid, type: "mcp", scan_id: conversationId, finding_id, state });
    },
    onSuccess: () => {
      onFindingsUpdated?.();
      toast.success("Finding status updated");
    },
    onError: (err) => {
      showErrorToast(err, "Failed to update finding status");
    },
  });

  const createJiraFromApiFindingsMutation = useMutation({
    mutationFn: async () => {
      const tid = parseInt(teamId ?? "0", 10);
      if (!conversationId || Number.isNaN(tid)) throw new Error("Missing team or scan");
      const selected = findingsList.filter((f) => selectedFindingIds.has(f.id));
      if (selected.length === 0) throw new Error("No findings selected");
      const impactCounts: Record<string, number> = {};
      for (const f of selected) {
        const impact = (f.impact ?? "Unknown").trim() || "Unknown";
        impactCounts[impact] = (impactCounts[impact] ?? 0) + 1;
      }
      let summary = Object.entries(impactCounts)
        .sort(([a], [b]) => RISK_ORDER.indexOf(a as (typeof RISK_ORDER)[number]) - RISK_ORDER.indexOf(b as (typeof RISK_ORDER)[number]))
        .map(([impact, count]) => `${count} ${impact}`)
        .join(", ") || `${selected.length} finding(s)`;
      summary = summary + " - Vulnerabilities found in MCP scan";
      const descSections = selected.map((f, idx) => {
        const parts = [`--- Finding ${idx + 1} ---`, `Title: ${(f.title ?? "Untitled").trim() || "Untitled"}`];
        if ((f.description ?? "").trim()) parts.push(`Description: ${f.description!.trim()}`);
        if ((f.type ?? "").trim()) parts.push(`Type: ${f.type!.trim()}`);
        if ((f.impact ?? "").trim()) parts.push(`Impact: ${f.impact!.trim()}`);
        if ((f.suggested_fix ?? "").trim()) parts.push(`Suggested fix: ${f.suggested_fix!.trim()}`);
        return parts.join("\n");
      });
      await createTicket(tid, "mcp", conversationId, {
        ticket_type: "jira",
        summary,
        description: descSections.join("\n\n"),
        finding_ids: selected.map((f) => f.id),
      });
    },
    onMutate: () => ({ toastId: toast.loading("Creating Jira ticket(s)...") }),
    onSuccess: (_data, _vars, context) => {
      if (context?.toastId != null) toast.dismiss(context.toastId);
      toast.success(`Jira ticket(s) created for ${selectedFindingIds.size} finding(s)`);
      setSelectedFindingIds(new Set());
    },
    onError: (err, _vars, context) => {
      if (context?.toastId != null) toast.dismiss(context.toastId);
      showErrorToast(err, "Failed to create Jira ticket(s)");
    },
  });

  const filteredApiFindings = useMemo(() => {
    let list = findingsList;
    const q = searchQuery.toLowerCase().trim();
    if (q) {
      list = list.filter(
        (f) =>
          (f.title ?? "").toLowerCase().includes(q) ||
          (f.description ?? "").toLowerCase().includes(q) ||
          (f.impact ?? "").toLowerCase().includes(q) ||
          (f.type ?? "").toLowerCase().includes(q)
      );
    }
    if (filterImpact && filterImpact !== "all") {
      list = list.filter((f) => (f.impact ?? "").trim().toLowerCase() === filterImpact.toLowerCase());
    }
    list = list.filter((f) => matchesRiskScoreFilter(f.risk_score ?? undefined, filterRiskScore));
    return list;
  }, [findingsList, searchQuery, filterImpact, filterRiskScore]);

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
          <div className="flex flex-col">
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

      {scanMetadata && <MCPScanMetadataBlock scanMetadata={scanMetadata} />}

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
          autoCreateTickets={autoCreateTickets}
          onAutoCreateTicketsChange={setAutoCreateTickets}
          onSave={() => {
            updateIntegrationMutation.mutate({
              integration_settings: {
                jira: { jira_project_id: jiraProjectId.trim() || null, auto_create_tickets: autoCreateTickets },
              },
            });
          }}
          isSaving={updateIntegrationMutation.isPending}
          inputId="mcp-jira-project-id"
        />
      ) : (
        <>
      {dashboard && (
        <MCPDashboardCharts dashboard={dashboard} />
      )}

      <Card>
        <CardHeader>
          <CardTitle>Findings</CardTitle>
          <CardDescription>
            {useApiFindings
              ? hasActiveFindingsFilters
                ? `Showing ${filteredApiFindings.length} of ${findingsList.length} findings. Click a title to view details. Select rows to create Jira tickets; use Action to change finding state.`
                : `${filteredApiFindings.length} findings. Click a title to view details. Select rows to create Jira tickets; use Action to change finding state.`
              : `${tableRows.length} vulnerability findings. Click a title to view details. Select rows to create Jira tickets.`}
          </CardDescription>
        </CardHeader>
        <CardContent>
          {useApiFindings ? (
            <>
              <FindingSelectionMenu
                selectedCount={selectedFindingIds.size}
                onClearSelection={() => setSelectedFindingIds(new Set())}
                jiraOnClickHandler={() => createJiraFromApiFindingsMutation.mutate()}
                ticketType="jira"
                isJiraCreating={createJiraFromApiFindingsMutation.isPending}
              />
              <div className="flex flex-wrap items-center gap-2 mb-4">
                <div className="relative flex-1 min-w-[200px] max-w-sm">
                  <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-4 w-4 text-zinc-500" />
                  <Input
                    placeholder="Search by title, description, impact, type..."
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    className="pl-8"
                  />
                </div>
                <Select value={filterImpact} onValueChange={setFilterImpact}>
                  <SelectTrigger className="w-[140px]">
                    <SelectValue placeholder="Impact" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All impacts</SelectItem>
                    <SelectItem value="critical">Critical</SelectItem>
                    <SelectItem value="high">High</SelectItem>
                    <SelectItem value="medium">Medium</SelectItem>
                    <SelectItem value="low">Low</SelectItem>
                  </SelectContent>
                </Select>
                <DropdownMenu>
                  <DropdownMenuTrigger asChild>
                    <Button
                      variant="outline"
                      size="sm"
                      className={`cursor-pointer ${
                        filterRiskScore === "critical"
                          ? "border-red-500/50 text-red-600 dark:text-red-400"
                          : filterRiskScore === "high"
                            ? "border-orange-500/50 text-orange-600 dark:text-orange-400"
                            : filterRiskScore === "medium"
                              ? "border-amber-500/50 text-amber-600 dark:text-amber-400"
                              : filterRiskScore === "low"
                                ? "border-blue-500/50 text-blue-600 dark:text-blue-400"
                                : "border-zinc-300 dark:border-zinc-600"
                      }`}
                    >
                      <Filter className="h-4 w-4 mr-1.5" />
                      {RISK_SCORE_LABELS[filterRiskScore]}
                      <ChevronDown className="h-4 w-4 ml-1.5" />
                    </Button>
                  </DropdownMenuTrigger>
                  <DropdownMenuContent align="start" className="w-[200px]">
                    <DropdownMenuLabel>Risk score</DropdownMenuLabel>
                    <DropdownMenuSeparator />
                    {(["all", "critical", "high", "medium", "low"] as const).map((level) => (
                      <DropdownMenuItem
                        key={level}
                        className="cursor-pointer"
                        onClick={() => setFilterRiskScore(level)}
                      >
                        {filterRiskScore === level ? <Check className="h-4 w-4 mr-2 text-emerald-600" /> : null}
                        {level === "all" ? "All" : level === "critical" ? "Critical (≥9)" : level === "high" ? "High (7–9)" : level === "medium" ? "Medium (5–7)" : "Low (<5)"}
                        {level !== "all" ? <Shield className="h-4 w-4 ml-2 opacity-70" /> : null}
                      </DropdownMenuItem>
                    ))}
                  </DropdownMenuContent>
                </DropdownMenu>
                {hasActiveFindingsFilters && (
                  <Button variant="ghost" size="sm" className="cursor-pointer" onClick={clearFindingsFilters}>
                    <X className="h-4 w-4 mr-1" />
                    Clear filters
                  </Button>
                )}
              </div>
              <ScrollArea className="h-[500px] rounded-md border border-zinc-200 dark:border-zinc-800">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead className="w-[48px]">
                        <Checkbox
                          checked={filteredApiFindings.length > 0 && selectedFindingIds.size === filteredApiFindings.length}
                          onCheckedChange={() => {
                            if (selectedFindingIds.size === filteredApiFindings.length) {
                              setSelectedFindingIds(new Set());
                            } else {
                              setSelectedFindingIds(new Set(filteredApiFindings.map((f) => f.id)));
                            }
                          }}
                          aria-label="Select all rows"
                          className="cursor-pointer"
                        />
                      </TableHead>
                      <TableHead className="min-w-[180px]">Title</TableHead>
                      <TableHead className="min-w-[200px]">Description</TableHead>
                      <TableHead className="min-w-[90px]">Impact</TableHead>
                      <TableHead className="min-w-[90px] text-center">Risk score</TableHead>
                      <TableHead className="min-w-[100px]">Status</TableHead>
                      <TableHead className="min-w-[90px]">Type</TableHead>
                      <TableHead className="min-w-[90px] text-center">OWASP</TableHead>
                      <TableHead className="min-w-[90px] text-center">Compliance</TableHead>
                      <TableHead className="min-w-[100px] text-right">Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {filteredApiFindings.length === 0 ? (
                      <TableRow>
                        <TableCell colSpan={10} className="text-center py-8 text-zinc-500 dark:text-zinc-400">
                          No findings to display.
                        </TableCell>
                      </TableRow>
                    ) : (
                      filteredApiFindings.map((f) => {
                        const impact = (f.impact ?? "").trim() || "—";
                        const desc = (f.description ?? "").trim();
                        const descTrunc = desc.length > 80 ? `${desc.slice(0, 80)}…` : desc || "—";
                        const statusLabel = (f.status ?? "not_started").replace(/_/g, " ");
                        const typeLabelVal = (f.type ?? "—").toString();
                        return (
                          <TableRow
                            key={f.id}
                            className={`hover:bg-zinc-50 dark:hover:bg-zinc-800/50 ${selectedFindingIds.has(f.id) ? "bg-zinc-100 dark:bg-zinc-800/70" : ""}`}
                          >
                            <TableCell onClick={(e) => e.stopPropagation()} className="w-[48px]">
                              <Checkbox
                                checked={selectedFindingIds.has(f.id)}
                                onCheckedChange={() => {
                                  setSelectedFindingIds((prev) => {
                                    const next = new Set(prev);
                                    if (next.has(f.id)) next.delete(f.id);
                                    else next.add(f.id);
                                    return next;
                                  });
                                }}
                                aria-label={`Select ${f.title ?? f.id}`}
                                className="cursor-pointer"
                              />
                            </TableCell>
                            <TableCell className="font-medium">
                              <button
                                type="button"
                                onClick={() => { setSelectedApiFinding(f); setDetailOpen(true); }}
                                className="text-left text-blue-600 hover:text-blue-700 dark:text-blue-400 dark:hover:text-blue-300 hover:underline cursor-pointer font-medium"
                              >
                                {(f.title ?? "").trim() || "Untitled"}
                              </button>
                            </TableCell>
                            <TableCell className="text-sm text-zinc-600 dark:text-zinc-400" title={desc || undefined}>
                              {descTrunc}
                            </TableCell>
                            <TableCell>
                              <Badge variant="outline" className={getImpactBadgeClass(impact)}>
                                {impact}
                              </Badge>
                            </TableCell>
                            <TableCell className="text-center">
                              <span className="inline-flex items-center justify-center min-w-9 px-2 py-1 rounded-md text-xs font-semibold tabular-nums bg-zinc-100 dark:bg-zinc-800">
                                {f.risk_score}
                              </span>
                            </TableCell>
                            <TableCell>
                              <span className={`inline-flex items-center justify-center px-2.5 py-1 rounded-md text-xs font-medium capitalize ${getFindingStatusBadgeClass(f.status ?? "not_started")}`}>
                                {statusLabel}
                              </span>
                            </TableCell>
                            <TableCell className="capitalize text-sm text-zinc-600 dark:text-zinc-400">
                              {typeLabelVal}
                            </TableCell>
                            <TableCell className="text-center">
                              <span className="inline-flex items-center justify-center min-w-9 px-2 py-1 rounded-md text-xs font-semibold tabular-nums bg-violet-100 text-violet-800 dark:bg-violet-900/40 dark:text-violet-200">
                                {countFindingField(f.owasp_top_10) + countFindingField(f.owasp_top_10_llm)}
                              </span>
                            </TableCell>
                            <TableCell className="text-center">
                              <span className="inline-flex items-center justify-center min-w-9 px-2 py-1 rounded-md text-xs font-semibold tabular-nums bg-sky-100 text-sky-800 dark:bg-sky-900/40 dark:text-sky-200">
                                {countFindingField(f.compliance_controls)}
                              </span>
                            </TableCell>
                            <TableCell className="text-right" onClick={(e) => e.stopPropagation()}>
                              <DropdownMenu>
                                <DropdownMenuTrigger asChild>
                                  <Button variant="outline" size="sm" className="cursor-pointer gap-1.5 h-8 shrink-0" aria-label="Finding actions">
                                    <Pencil className="h-3.5 w-3.5 opacity-70" />
                                    Action
                                  </Button>
                                </DropdownMenuTrigger>
                                <DropdownMenuContent align="end">
                                  <DropdownMenuItem className="cursor-pointer gap-2" onClick={() => toggleFindingMutation.mutate({ finding_id: f.id, state: "fixed" })} disabled={toggleFindingMutation.isPending}>
                                    <CheckCircle className="h-4 w-4" />
                                    Mark as Fixed
                                  </DropdownMenuItem>
                                  <DropdownMenuItem className="cursor-pointer gap-2" onClick={() => toggleFindingMutation.mutate({ finding_id: f.id, state: "ignored" })} disabled={toggleFindingMutation.isPending}>
                                    <EyeOff className="h-4 w-4" />
                                    Mark as Ignored
                                  </DropdownMenuItem>
                                  <DropdownMenuItem className="cursor-pointer gap-2" onClick={() => toggleFindingMutation.mutate({ finding_id: f.id, state: "in_progress" })} disabled={toggleFindingMutation.isPending}>
                                    <Loader2 className="h-4 w-4" />
                                    Mark as In progress
                                  </DropdownMenuItem>
                                  <DropdownMenuItem className="cursor-pointer gap-2" onClick={() => toggleFindingMutation.mutate({ finding_id: f.id, state: "not_started" })} disabled={toggleFindingMutation.isPending}>
                                    <Circle className="h-4 w-4" />
                                    Mark as Not started
                                  </DropdownMenuItem>
                                </DropdownMenuContent>
                              </DropdownMenu>
                            </TableCell>
                          </TableRow>
                        );
                      })
                    )}
                  </TableBody>
                </Table>
              </ScrollArea>
            </>
          ) : (
            <>
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
            </>
          )}
        </CardContent>
      </Card>

      <Dialog open={detailOpen} onOpenChange={(open) => { if (!open) { setSelectedVuln(null); setSelectedApiFinding(null); } setDetailOpen(open); }}>
        <DialogContent className="sm:max-w-3xl max-h-[90vh] flex flex-col p-0 gap-0 overflow-hidden bg-zinc-900">
          <DialogHeader className="px-6 pt-6 pb-2 shrink-0">
            <DialogTitle className="pr-8">
              {selectedApiFinding ? ((selectedApiFinding.title ?? "").trim() || "Finding details") : (selectedVuln?.vuln.title ?? "Vulnerability details")}
            </DialogTitle>
          </DialogHeader>
          {selectedApiFinding ? (
            <div className="min-h-0 flex-1 overflow-auto px-6 pb-6">
              <ScrollArea className="h-[70vh]">
                <div className="space-y-4 pr-4">
                  {(selectedApiFinding.type ?? "").trim() && (
                    <div>
                      <div className="text-xs font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400 mb-1">Type</div>
                      <span className="capitalize text-sm text-zinc-700 dark:text-zinc-300">{selectedApiFinding.type!.trim()}</span>
                    </div>
                  )}
                  {(selectedApiFinding.impact ?? "").trim() && (
                    <div>
                      <div className="text-xs font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400 mb-1">Impact</div>
                      <Badge variant="outline" className={getImpactBadgeClass(selectedApiFinding.impact!.trim())}>
                        {selectedApiFinding.impact!.trim()}
                      </Badge>
                    </div>
                  )}
                  {(selectedApiFinding.status ?? "").trim() && (
                    <div>
                      <div className="text-xs font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400 mb-1">Status</div>
                      <span className={`inline-flex items-center px-2.5 py-1 rounded-md text-xs font-medium capitalize ${getFindingStatusBadgeClass(selectedApiFinding.status ?? "not_started")}`}>
                        {(selectedApiFinding.status ?? "").replace(/_/g, " ")}
                      </span>
                    </div>
                  )}
                  {selectedApiFinding.risk_score != null && (
                    <div>
                      <div className="text-xs font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400 mb-1">Risk score</div>
                      <span className="text-sm text-zinc-700 dark:text-zinc-300">{selectedApiFinding.risk_score}</span>
                    </div>
                  )}
                  {(selectedApiFinding.description ?? "").trim() && (
                    <div>
                      <div className="text-xs font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400 mb-1">Description</div>
                      <p className="text-sm text-zinc-700 dark:text-zinc-300 whitespace-pre-wrap">{selectedApiFinding.description!.trim()}</p>
                    </div>
                  )}
                  {selectedApiFinding.owasp_top_10 != null && typeof selectedApiFinding.owasp_top_10 === "object" && Object.keys(selectedApiFinding.owasp_top_10 as object).length > 0 && (
                    <div>
                      <div className="text-xs font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400 mb-1">OWASP Top 10</div>
                      {renderKeyValue(selectedApiFinding.owasp_top_10 as Record<string, string>)}
                    </div>
                  )}
                  {selectedApiFinding.owasp_top_10_llm != null && typeof selectedApiFinding.owasp_top_10_llm === "object" && Object.keys(selectedApiFinding.owasp_top_10_llm as object).length > 0 && (
                    <div>
                      <div className="text-xs font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400 mb-1">OWASP Top 10 for LLM</div>
                      {renderKeyValue(selectedApiFinding.owasp_top_10_llm as Record<string, string>)}
                    </div>
                  )}
                  {selectedApiFinding.compliance_controls != null && typeof selectedApiFinding.compliance_controls === "object" && Object.keys(selectedApiFinding.compliance_controls as object).length > 0 && (
                    <div>
                      <div className="text-xs font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400 mb-1">Compliance controls</div>
                      {renderKeyValue(selectedApiFinding.compliance_controls as Record<string, string>)}
                    </div>
                  )}
                  {(selectedApiFinding.suggested_fix ?? "").trim() && (
                    <div>
                      <div className="text-xs font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400 mb-1">Suggested fix</div>
                      <p className="text-sm text-zinc-700 dark:text-zinc-300 whitespace-pre-wrap">{selectedApiFinding.suggested_fix!.trim()}</p>
                    </div>
                  )}
                  <RemediationPanel
                    teamId={teamId ?? ""}
                    scanType="mcp"
                    scanId={conversationId ?? 0}
                    findingId={selectedApiFinding.id}
                    existingRemediation={selectedApiFinding.remediation}
                  />
                </div>
              </ScrollArea>
            </div>
          ) : selectedVuln ? (
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
          ) : null}
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

export default function MCPResults({ data, conversationId, teamId, dashboard, findings, scanMetadata, onFindingsUpdated, integrationSettings, onIntegrationSettingsUpdated, onRefresh, onDownloadReport, isExporting }: MCPResultsProps) {
  const hasAgentFormat = data && typeof data === "object" && (Array.isArray((data as MCPAgentResultsData).tools) || Array.isArray((data as MCPAgentResultsData).prompts) || Array.isArray((data as MCPAgentResultsData).resources));
  const hasFindings = Array.isArray(findings) && findings.length > 0;

  if (hasAgentFormat || hasFindings) {
    return (
      <AgentResultsView
        data={(data && typeof data === "object" ? data : {}) as MCPAgentResultsData}
        conversationId={conversationId}
        teamId={teamId}
        dashboard={dashboard}
        findings={findings}
        scanMetadata={scanMetadata}
        onFindingsUpdated={onFindingsUpdated}
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
