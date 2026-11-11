"use client";

import Link from "next/link";
import { useParams, useRouter } from "next/navigation";
import { Button } from "@/components/ui/button";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
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
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { FieldLabel, InfoTip } from "@/components/ui/info-tip";
import { Plus, MoreVertical, Pencil, Trash2, RefreshCcw, Loader2, Eye, Clock, Play, CheckCircle, XCircle, CalendarPlus, CalendarCheck, Search, X, GitBranch, FileArchive, Shield, AlertTriangle, Check, ScanSearch, Target, Percent, AlertCircle, Server, Activity, Filter, ChevronDown, ArrowUpDown, DollarSign, TrendingUp, TrendingDown, Zap, Wrench, MinusCircle } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { singleFlight } from "@/utils/single_flight";
import { IACConversation, deleteIACConversation, getIACConversations, renameIACConversation, createIACConversation } from "@/utils/backend_api";
import type { IACListDashboardData } from "@/utils/backend_api";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "@/utils/toast";
import { showErrorToast } from "@/utils/error-handler";
import { formatDateIst as formatDate, formatChartDateIst } from "@/utils/datetime";
import { Avatar, AvatarFallback } from "@/components/ui/avatar";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Progress } from "@/components/ui/progress";
import { ScrollArea, ScrollBar } from "@/components/ui/scroll-area";
import {
  ChartContainer,
  ChartTooltip,
  ChartTooltipContent,
  ChartLegend,
  ChartLegendContent,
  type ChartConfig,
} from "@/components/ui/chart";
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Line,
  LineChart,
  Pie,
  PieChart,
  PolarAngleAxis,
  PolarGrid,
  Radar,
  RadarChart,
  XAxis,
  YAxis,
} from "recharts";

type ScanStatus = "pending" | "started" | "retry" | "failure" | "success" | "not_started" | "cancelled";

/** Risk score tiers for filtering: Critical ≥9, High 7–9, Medium 5–7, Low <5 */
type RiskScoreFilter = "all" | "critical" | "high" | "medium" | "low";
type TableSortBy =
  | "none"
  | "created_asc"
  | "created_desc"
  | "risk_desc"
  | "risk_asc"
  | "credits_desc"
  | "credits_asc";
type EnvironmentFilter = "all" | "production" | "staging" | "development";

const RISK_SCORE_LABELS: Record<RiskScoreFilter, string> = {
  all: "Risk score",
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
};

const SORT_BY_LABELS: Record<TableSortBy, string> = {
  none: "Sort by",
  created_asc: "Created (oldest)",
  created_desc: "Created (newest)",
  risk_desc: "Risk score (high first)",
  risk_asc: "Risk score (low first)",
  credits_desc: "Credits (high first)",
  credits_asc: "Credits (low first)",
};

/** IAC context mode keys (backend schema) -> display names for heatmap Y-axis */
const IAC_CONTEXT_MODE_LABELS: Record<string, string> = {
  terraform: "Terraform",
  k8s: "K8s",
  pulumi: "Pulumi",
  ansible: "Ansible",
  helm: "Helm",
  aws_cloudformation: "AWS CloudFormation",
  aws_cdk: "AWS CDK",
};

function getDisplayRiskScore(c: IACConversation): number | null {
  if (c.average_risk_score == null) return null;
  return Math.round(Math.min(10, Math.max(0, c.average_risk_score)) * 10) / 10;
}

function matchesRiskScoreFilter(score: number | null, filter: RiskScoreFilter): boolean {
  if (filter === "all") return true;
  if (score == null) return false;
  if (filter === "critical") return score >= 9;
  if (filter === "high") return score >= 7 && score < 9;
  if (filter === "medium") return score >= 5 && score < 7;
  if (filter === "low") return score < 5;
  return true;
}

// ─── Dashboard Tab ──────────────────────────────────────────────────────────────

function IACDashboard({ dashboardData }: { dashboardData: IACListDashboardData }) {
  const card = dashboardData.card_data;
  const totalIssues = card.total_issues;

  // Severity distribution for pie chart
  const severityPieData = useMemo(() => {
    const d = dashboardData.severity_distribution;
    return [
      { name: "Critical", value: d.critical, fill: "#dc2626" },
      { name: "High", value: d.high, fill: "#ea580c" },
      { name: "Medium", value: d.medium, fill: "#ca8a04" },
      { name: "Low", value: d.low, fill: "#2563eb" },
    ].filter((s) => s.value > 0);
  }, [dashboardData.severity_distribution]);

  // Issues over time (stacked area)
  const issuesOverTimeData = useMemo(() => {
    return Object.entries(dashboardData.issues_over_time)
      .map(([date, v]) => ({ date, ...v }))
      .sort((a, b) => a.date.localeCompare(b.date));
  }, [dashboardData.issues_over_time]);

  const areaConfig = {
    critical: { label: "Critical", color: "hsl(0 72% 51%)" },
    high: { label: "High", color: "hsl(25 95% 53%)" },
    medium: { label: "Medium", color: "hsl(45 93% 47%)" },
    low: { label: "Low", color: "hsl(217 91% 60%)" },
  } satisfies ChartConfig;

  // Security posture overview (radar: category -> count), numbered S1, S2, ... with legend
  const securityPostureData = useMemo(() => {
    return Object.entries(dashboardData.security_posture_overview).map(([category, count], i) => ({
      xLabel: `S${i + 1}`,
      category,
      count,
    }));
  }, [dashboardData.security_posture_overview]);

  const securityPostureConfig = { count: { label: "Count", color: "hsl(220 70% 50%)" } } satisfies ChartConfig;

  // Compliance: percentage = (count / sum_of_counts) * 100
  const complianceCounts = dashboardData.compliance_framework_counts ?? {};
  const sumOfCounts = useMemo(() => Object.values(complianceCounts).reduce((a, b) => a + b, 0), [complianceCounts]);

  // Remediation pipeline: Total (red) + Fixed (green), In progress (blue), Not started (orange), Ignored (grey)
  const pipeline = dashboardData.remediation_pipeline;
  const pipelineData = useMemo(() => [
    { label: "Total Issues", value: pipeline.total_issues, fill: "#dc2626", icon: AlertTriangle },
    { label: "Fixed", value: pipeline.fixed, fill: "#16a34a", icon: Zap },
    { label: "In progress", value: pipeline.in_progress, fill: "#2563eb", icon: Wrench },
    { label: "Not started", value: pipeline.not_started, fill: "#ea580c", icon: Clock },
    { label: "Ignored", value: pipeline.ignored, fill: "#71717a", icon: MinusCircle },
  ], [pipeline]);

  // MTTR per day: [d, h, m] -> days (decimal)
  const mttrPerDayData = useMemo(() => {
    return Object.entries(dashboardData.mttr_per_day)
      .map(([date, [d, h, m]]) => ({ date, days: d + h / 24 + m / (24 * 60) }))
      .sort((a, b) => a.date.localeCompare(b.date));
  }, [dashboardData.mttr_per_day]);

  const mttrConfig = { days: { label: "MTTR (days)", color: "hsl(217 91% 60%)" } } satisfies ChartConfig;

  // Resources by provider (bar)
  const resourcesByProviderData = useMemo(() => {
    return Object.entries(dashboardData.resources_by_provider)
      .map(([provider, count]) => ({ provider, count }))
      .sort((a, b) => b.count - a.count);
  }, [dashboardData.resources_by_provider]);

  const providerAreaConfig = { count: { label: "Resources", color: "hsl(220 70% 50%)" } } satisfies ChartConfig;
  // For area chart, keep same data (provider + count)

  // Environment list
  const environmentEntries = useMemo(() => Object.entries(dashboardData.environment), [dashboardData.environment]);

  // Heatmap: env -> { mode -> count }
  const heatmap = dashboardData.environment_cloud_resource_heatmap;
  const heatmapEnvs = useMemo(() => Object.keys(heatmap).sort(), [heatmap]);
  const heatmapModes = useMemo(() => {
    const set = new Set<string>();
    Object.values(heatmap).forEach((modes) => Object.keys(modes).forEach((m) => set.add(m)));
    return Array.from(set).sort();
  }, [heatmap]);
  const heatmapMax = useMemo(() => {
    let max = 0;
    heatmapEnvs.forEach((env) => heatmapModes.forEach((mode) => { const v = heatmap[env]?.[mode] ?? 0; if (v > max) max = v; }));
    return max || 1;
  }, [heatmap, heatmapEnvs, heatmapModes]);
  const complianceAccentColors = ["#2563eb", "#16a34a", "#7c3aed", "#ca8a04", "#dc2626", "#0284c7"];

  return (
    <div className="space-y-6">
      {/* 1. Card data: 7 cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-7 gap-4">
        <Card className="border-zinc-200 dark:border-zinc-800 py-3 px-3">
          <CardContent className="p-0">
            <div className="flex flex-col items-start gap-2">
              <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-blue-500/15 dark:bg-blue-500/10">
                <ScanSearch className="h-4 w-4 text-blue-500" />
              </div>
              <div>
                <p className="text-xs font-medium text-zinc-600 dark:text-zinc-400 flex items-center gap-1">Total scans <InfoTip id="iac.kpi.total_scans" /></p>
                <p className="text-xl font-bold text-zinc-900 dark:text-white">{card.total_scans}</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card className="border-zinc-200 dark:border-zinc-800 py-3 px-3">
          <CardContent className="p-0">
            <div className="flex flex-col items-start gap-2">
              <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-amber-500/15 dark:bg-amber-500/10">
                <AlertCircle className="h-4 w-4 text-amber-500" />
              </div>
              <div>
                <p className="text-xs font-medium text-zinc-600 dark:text-zinc-400 flex items-center gap-1">Total issues <InfoTip id="iac.kpi.total_issues" /></p>
                <p className="text-xl font-bold text-zinc-900 dark:text-white">{card.total_issues}</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card className="border-zinc-200 dark:border-zinc-800 py-3 px-3">
          <CardContent className="p-0">
            <div className="flex flex-col items-start gap-2">
              <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-red-500/15 dark:bg-red-500/10">
                <Target className="h-4 w-4 text-red-500" />
              </div>
              <div>
                <p className="text-xs font-medium text-zinc-600 dark:text-zinc-400 flex items-center gap-1">Total critical <InfoTip id="iac.kpi.critical" /></p>
                <p className="text-xl font-bold text-zinc-900 dark:text-white">{card.total_critical_issues}</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card className="border-zinc-200 dark:border-zinc-800 py-3 px-3">
          <CardContent className="p-0">
            <div className="flex flex-col items-start gap-2">
              <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-zinc-500/15 dark:bg-zinc-400/10">
                <Clock className="h-4 w-4 text-zinc-500" />
              </div>
              <div>
                <p className="text-xs font-medium text-zinc-600 dark:text-zinc-400 flex items-center gap-1">Avg MTTR (days) <InfoTip id="iac.kpi.mttr" /></p>
                <p className="text-xl font-bold text-zinc-900 dark:text-white">{card.avg_mttr_days.toFixed(1)}</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card className="border-zinc-200 dark:border-zinc-800 py-3 px-3">
          <CardContent className="p-0">
            <div className="flex flex-col items-start gap-2">
              <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-green-500/15 dark:bg-green-500/10">
                <Percent className="h-4 w-4 text-green-500" />
              </div>
              <div>
                <p className="text-xs font-medium text-zinc-600 dark:text-zinc-400 flex items-center gap-1">Coverage % <InfoTip id="iac.kpi.coverage" /></p>
                <p className="text-xl font-bold text-zinc-900 dark:text-white">{card.coverage_percentage.toFixed(1)}%</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card className="border-zinc-200 dark:border-zinc-800 py-3 px-3">
          <CardContent className="p-0">
            <div className="flex flex-col items-start gap-2">
              <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-red-500/15 dark:bg-red-500/10">
                <Shield className="h-4 w-4 text-red-500" />
              </div>
              <div>
                <p className="text-xs font-medium text-zinc-600 dark:text-zinc-400 flex items-center gap-1">Policy violations <InfoTip id="iac.kpi.policy" /></p>
                <p className="text-xl font-bold text-zinc-900 dark:text-white">{card.total_policy_violations}</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card className="border-zinc-200 dark:border-zinc-800 py-3 px-3">
          <CardContent className="p-0">
            <div className="flex flex-col items-start gap-2">
              <div className={`flex h-8 w-8 shrink-0 items-center justify-center rounded-lg ${card.average_risk_score >= 7 ? "bg-red-500/15 dark:bg-red-500/10" : card.average_risk_score >= 5 ? "bg-amber-500/15 dark:bg-amber-500/10" : "bg-green-500/15 dark:bg-green-500/10"}`}>
                <Activity className={`h-4 w-4 ${card.average_risk_score >= 7 ? "text-red-500" : card.average_risk_score >= 5 ? "text-amber-500" : "text-green-500"}`} />
              </div>
              <div>
                <p className="text-xs font-medium text-zinc-600 dark:text-zinc-400 flex items-center gap-1">Avg risk score <InfoTip id="iac.kpi.avg_risk" /></p>
                <p className="text-xl font-bold text-zinc-900 dark:text-white">{card.average_risk_score.toFixed(1)}</p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Row 1: Severity (pie) | Issues over time (area) | Security posture (radar) */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <Card className="border-zinc-200 dark:border-zinc-800">
          <CardHeader className="items-center pb-2">
            <CardTitle className="text-base flex items-center gap-1">Severity Distribution <InfoTip id="iac.chart.severity" /></CardTitle>
            <CardDescription>Critical / High / Medium / Low</CardDescription>
          </CardHeader>
          <CardContent>
            {severityPieData.length === 0 ? (
              <p className="text-center text-sm text-zinc-500 py-8">No data yet</p>
            ) : (
              <ChartContainer config={{}} className="mx-auto aspect-square max-h-[280px]">
                <PieChart>
                  <ChartTooltip content={<ChartTooltipContent />} />
                  <Pie
                    data={severityPieData}
                    dataKey="value"
                    nameKey="name"
                    cx="50%"
                    cy="50%"
                    innerRadius={50}
                    outerRadius={90}
                    paddingAngle={2}
                    label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                  >
                    {severityPieData.map((entry, i) => (
                      <Cell key={entry.name} fill={entry.fill} />
                    ))}
                  </Pie>
                </PieChart>
              </ChartContainer>
            )}
          </CardContent>
        </Card>
        <Card className="border-zinc-200 dark:border-zinc-800">
          <CardHeader className="pb-2">
            <CardTitle className="text-base flex items-center gap-1">Issues Over Time <InfoTip id="iac.chart.over_time" /></CardTitle>
            <CardDescription>Stacked by severity</CardDescription>
          </CardHeader>
          <CardContent>
            {issuesOverTimeData.length === 0 ? (
              <p className="text-center text-sm text-zinc-500 py-8">No data yet</p>
            ) : (
              <ChartContainer config={areaConfig} className="h-[280px] w-full">
                <AreaChart data={issuesOverTimeData}>
                  <CartesianGrid vertical={false} />
                  <XAxis dataKey="date" tickLine={false} axisLine={false} tickMargin={8} tickFormatter={(v) => formatChartDateIst(v)} />
                  <YAxis tickLine={false} axisLine={false} allowDecimals={false} />
                  <ChartTooltip content={<ChartTooltipContent />} />
                  <ChartLegend content={<ChartLegendContent />} />
                  <Area type="monotone" dataKey="critical" stackId="a" fill="var(--color-critical)" stroke="var(--color-critical)" fillOpacity={0.4} />
                  <Area type="monotone" dataKey="high" stackId="a" fill="var(--color-high)" stroke="var(--color-high)" fillOpacity={0.4} />
                  <Area type="monotone" dataKey="medium" stackId="a" fill="var(--color-medium)" stroke="var(--color-medium)" fillOpacity={0.4} />
                  <Area type="monotone" dataKey="low" stackId="a" fill="var(--color-low)" stroke="var(--color-low)" fillOpacity={0.4} />
                </AreaChart>
              </ChartContainer>
            )}
          </CardContent>
        </Card>
        <Card className="border-zinc-200 dark:border-zinc-800">
          <CardHeader className="items-center pb-2">
            <CardTitle className="text-base flex items-center gap-1">Security Posture Overview <InfoTip id="iac.chart.posture" /></CardTitle>
            <CardDescription>By category</CardDescription>
          </CardHeader>
          <CardContent>
            {securityPostureData.length === 0 ? (
              <p className="text-center text-sm text-zinc-500 py-8">No data yet</p>
            ) : (
              <>
                <ChartContainer config={securityPostureConfig} className="mx-auto aspect-square max-h-[280px]">
                  <RadarChart data={securityPostureData}>
                    <ChartTooltip
                      cursor={false}
                      content={
                        <ChartTooltipContent
                          labelFormatter={(_, payload) => (payload?.[0]?.payload as { category?: string })?.category ?? "—"}
                          formatter={(v) => [v, "Count"]}
                        />
                      }
                    />
                    <PolarAngleAxis dataKey="xLabel" />
                    <PolarGrid />
                    <Radar dataKey="count" fill="var(--color-count)" fillOpacity={0.6} dot={{ r: 4, fillOpacity: 1 }} />
                  </RadarChart>
                </ChartContainer>
                <div className="mt-4 pt-3 border-t border-zinc-200 dark:border-zinc-700 flex flex-wrap gap-x-4 gap-y-2 justify-center text-xs text-zinc-600 dark:text-zinc-400">
                  {securityPostureData.map((d) => (
                    <span key={d.xLabel}>
                      <span className="font-medium text-zinc-800 dark:text-zinc-200">{d.xLabel}</span>
                      <span className="mx-1.5">=</span>
                      <span>{d.category}</span>
                    </span>
                  ))}
                </div>
              </>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Remediation pipeline (full width) - styled like reference */}
      <Card className="border-zinc-200 dark:border-zinc-800">
        <CardHeader className="pb-2">
          <CardTitle className="text-base flex items-center gap-1">Remediation Pipeline <InfoTip id="iac.chart.pipeline" /></CardTitle>
          <CardDescription>Total issues and resolution status</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            {pipelineData.map(({ label, value, fill, icon: Icon }) => {
              const pct = label === "Total Issues" ? 100 : (pipeline.total_issues > 0 ? (value / pipeline.total_issues) * 100 : 0);
              return (
                <div key={label} className="flex items-center gap-3">
                  <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg" style={{ backgroundColor: `${fill}20` }}>
                    <Icon className="h-4 w-4" style={{ color: fill }} />
                  </div>
                  <span className="text-sm font-medium text-zinc-900 dark:text-white w-32 shrink-0">{label}</span>
                  <span className="text-sm font-bold text-zinc-900 dark:text-white tabular-nums w-10">{value}</span>
                  <div className="flex-1 flex items-center gap-2 min-w-0">
                    <div className="flex-1 h-3 rounded-full bg-zinc-200 dark:bg-zinc-700 overflow-hidden">
                      <div className="h-full rounded-full transition-all" style={{ width: `${pct}%`, backgroundColor: fill }} />
                    </div>
                    {label !== "Total Issues" && (
                      <span className="text-sm tabular-nums text-zinc-500 dark:text-zinc-400 w-10 shrink-0">{pct.toFixed(0)}%</span>
                    )}
                    {label === "Total Issues" && (
                      <span className="text-sm tabular-nums font-medium shrink-0 px-1.5 py-0.5 rounded text-white" style={{ backgroundColor: fill }}>100%</span>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        </CardContent>
      </Card>

      {/* Compliance framework violations (full width) - color accents on cards */}
      <Card className="border-zinc-200 dark:border-zinc-800">
        <CardHeader className="pb-2">
          <div className="flex items-center gap-2">
            <Shield className="h-5 w-5 text-zinc-600 dark:text-zinc-400" />
            <CardTitle className="text-base flex items-center gap-1">Compliance Framework Violations <InfoTip id="iac.chart.compliance" /></CardTitle>
          </div>
          <CardDescription>Violations by framework</CardDescription>
        </CardHeader>
        <CardContent>
          {Object.keys(complianceCounts).length === 0 ? (
            <p className="text-center text-sm text-zinc-500 py-8">No compliance data yet</p>
          ) : (
            <ScrollArea className="w-full">
              <div className="flex gap-4 pb-4 min-w-max pr-4">
                {Object.entries(complianceCounts).map(([framework, count], idx) => {
                  const pct = sumOfCounts > 0 ? (count / sumOfCounts) * 100 : 0;
                  const accent = complianceAccentColors[idx % complianceAccentColors.length];
                  return (
                    <Card key={framework} className="border-zinc-200 dark:border-zinc-800 shrink-0 w-[200px] border-l-4" style={{ borderLeftColor: accent }}>
                      <CardContent className="pt-4 pb-4">
                        <p className="text-sm font-medium text-zinc-900 dark:text-white mb-1">{framework}</p>
                        <p className="text-2xl font-bold" style={{ color: accent }}>{pct.toFixed(1)}%</p>
                        <Progress value={pct} className="h-2 mt-2" />
                        <div className="flex items-center gap-3 mt-3 text-sm flex-wrap">
                          <span className="flex items-center gap-1.5 text-zinc-600 dark:text-zinc-400">
                            <AlertTriangle className="h-4 w-4 text-red-500 shrink-0" />
                            Violations: {count}
                          </span>
                        </div>
                      </CardContent>
                    </Card>
                  );
                })}
              </div>
              <ScrollBar orientation="horizontal" />
            </ScrollArea>
          )}
        </CardContent>
      </Card>

      {/* Row: IAC context modes (Y) × Environments (X) heatmap | MTTR per day | Resources by provider (area chart) */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <Card className="border-zinc-200 dark:border-zinc-800">
          <CardHeader className="pb-2">
            <CardTitle className="text-base flex items-center gap-1">Environment × Cloud Resource Heatmap <InfoTip id="iac.chart.heatmap" /></CardTitle>
            <CardDescription>Count by IAC context mode (rows) and environment (columns)</CardDescription>
          </CardHeader>
          <CardContent>
            {heatmapEnvs.length === 0 || heatmapModes.length === 0 ? (
              <p className="text-center text-sm text-zinc-500 py-8">No data yet</p>
            ) : (
              <div className="overflow-x-auto">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead className="w-[100px]">IAC context{/* infotip-shared: the heatmap title explains rows and columns */}</TableHead>
                      {heatmapEnvs.map((env) => (
                        <TableHead key={env} className="text-center min-w-[70px] text-xs capitalize">{env}</TableHead>
                      ))}
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {heatmapModes.map((mode) => (
                      <TableRow key={mode}>
                        <TableCell className="font-medium text-sm">{IAC_CONTEXT_MODE_LABELS[mode] ?? mode}</TableCell>
                        {heatmapEnvs.map((env) => {
                          const v = heatmap[env]?.[mode] ?? 0;
                          const intensity = heatmapMax > 0 ? v / heatmapMax : 0;
                          const bg = intensity === 0 ? "bg-zinc-100 dark:bg-zinc-800" : intensity < 0.25 ? "bg-blue-200 dark:bg-blue-900/50" : intensity < 0.5 ? "bg-blue-300 dark:bg-blue-800/60" : intensity < 0.75 ? "bg-blue-400 dark:bg-blue-700/70" : "bg-blue-500 dark:bg-blue-600";
                          return (
                            <TableCell key={env} className={`text-center font-medium tabular-nums ${bg} text-zinc-900 dark:text-zinc-100 min-w-[70px]`}>
                              {v}
                            </TableCell>
                          );
                        })}
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            )}
          </CardContent>
        </Card>
        <Card className="border-zinc-200 dark:border-zinc-800">
          <CardHeader className="pb-2">
            <CardTitle className="text-base flex items-center gap-1">MTTR Per Day <InfoTip id="iac.chart.mttr_per_day" /></CardTitle>
            <CardDescription>Mean time to remediate (days)</CardDescription>
          </CardHeader>
          <CardContent>
            {mttrPerDayData.length === 0 ? (
              <p className="text-center text-sm text-zinc-500 py-8">No data yet</p>
            ) : (
              <ChartContainer config={mttrConfig} className="h-[280px] w-full">
                <LineChart data={mttrPerDayData}>
                  <CartesianGrid vertical={false} />
                  <XAxis dataKey="date" tickLine={false} axisLine={false} tickMargin={8} tickFormatter={(v) => formatChartDateIst(v)} />
                  <YAxis tickLine={false} axisLine={false} allowDecimals={true} />
                  <ChartTooltip content={<ChartTooltipContent />} />
                  <Line type="monotone" dataKey="days" stroke="var(--color-days)" strokeWidth={2} dot={{ r: 3 }} />
                </LineChart>
              </ChartContainer>
            )}
          </CardContent>
        </Card>
        <Card className="border-zinc-200 dark:border-zinc-800">
          <CardHeader className="pb-2">
            <CardTitle className="text-base flex items-center gap-1">Resources by Provider <InfoTip id="iac.chart.providers" /></CardTitle>
            <CardDescription>Terraform, K8s, etc.</CardDescription>
          </CardHeader>
          <CardContent>
            {resourcesByProviderData.length === 0 ? (
              <p className="text-center text-sm text-zinc-500 py-8">No data yet</p>
            ) : (
              <ChartContainer config={providerAreaConfig} className="h-[280px] w-full">
                <AreaChart data={resourcesByProviderData}>
                  <CartesianGrid vertical={false} />
                  <XAxis dataKey="provider" tickLine={false} axisLine={false} tickMargin={8} />
                  <YAxis tickLine={false} axisLine={false} allowDecimals={false} />
                  <ChartTooltip content={<ChartTooltipContent />} />
                  <Area type="monotone" dataKey="count" fill="hsl(220 70% 50% / 0.4)" stroke="hsl(220 70% 50%)" strokeWidth={2} />
                </AreaChart>
              </ChartContainer>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

// ─── Main Page ──────────────────────────────────────────────────────────────────

export default function IACPage() {
  const router = useRouter();
  const params = useParams();
  const team_id = params?.team_id as string;
  const [conversations, setConversations] = useState<IACConversation[]>([]);
  const [renameDialogOpen, setRenameDialogOpen] = useState(false);
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false);
  const [createDialogOpen, setCreateDialogOpen] = useState(false);
  const [selectedConversation, setSelectedConversation] = useState<IACConversation | null>(null);
  const [metadataDialogOpen, setMetadataDialogOpen] = useState(false);
  const [metadataScan, setMetadataScan] = useState<IACConversation | null>(null);
  const [newName, setNewName] = useState("");
  const [newScanTitle, setNewScanTitle] = useState("");
  const [searchQuery, setSearchQuery] = useState("");
  const [statusFilter, setStatusFilter] = useState<string>("all");
  const [riskScoreFilter, setRiskScoreFilter] = useState<RiskScoreFilter>("all");
  const [environmentFilter, setEnvironmentFilter] = useState<EnvironmentFilter>("all");
  const [sortBy, setSortBy] = useState<TableSortBy>("none");
  const queryClient = useQueryClient();

  const query = useQuery({
    queryKey: ["iac-conversations", team_id],
    queryFn: () => getIACConversations(parseInt(team_id)),
    enabled: !!team_id,
  });

  useEffect(() => {
    if (query.data) {
      setConversations(query.data.scans_list_data ?? []);
    }
    if (query.error) {
      showErrorToast(query.error, "Error fetching iac conversations");
    }
  }, [query.data, query.error]);

  const deleteIACConversationMutation = useMutation({
    mutationFn: ({ team_id, scan_id }: { team_id: number; scan_id: number }) => deleteIACConversation(team_id, scan_id),
    onSuccess: (data, variables) => {
      queryClient.invalidateQueries({ queryKey: ["iac-conversations", variables.team_id.toString()] });
      toast.success("IAC scan deleted");
    },
    onError: (error) => { showErrorToast(error); },
  });

  const renameIACConversationMutation = useMutation({
    mutationFn: renameIACConversation,
    onSuccess: (data, variables) => {
      queryClient.invalidateQueries({ queryKey: ["iac-conversations", variables.team_id.toString()] });
      toast.success("IAC scan renamed");
    },
    onError: (error) => { showErrorToast(error); },
  });

  // One create per click burst (double-click, Enter twice): isPending disables Create only after a re-render.
  const [createGuard] = useState(singleFlight);
  const createIACConversationMutation = useMutation({
    mutationFn: ({ team_id, title }: { team_id: number; title: string }) => createIACConversation(team_id, title),
    onSuccess: (scan_id, variables) => {
      queryClient.invalidateQueries({ queryKey: ["iac-conversations", variables.team_id.toString()] });
      setCreateDialogOpen(false);
      setNewScanTitle("");
      router.push(`/${variables.team_id}/iac/${scan_id}`);
    },
    onError: (error) => { showErrorToast(error); },
  });

  const getStatusBadge = (status: ScanStatus) => {
    const variants = {
      not_started: { variant: "outline" as const, className: "text-zinc-500 dark:text-zinc-500" },
      pending: { variant: "outline" as const, className: "text-zinc-600 dark:text-zinc-400" },
      started: { variant: "secondary" as const, className: "bg-blue-500 hover:bg-blue-600 text-white" },
      retry: { variant: "secondary" as const, className: "bg-yellow-500 hover:bg-yellow-600 text-white" },
      failure: { variant: "destructive" as const, className: "" },
      success: { variant: "default" as const, className: "bg-green-500 hover:bg-green-600 text-white" },
      cancelled: { variant: "outline" as const, className: "text-amber-600 dark:text-amber-400" },
    };
    const config = variants[status];
    const labels = { not_started: "Not Started", pending: "Pending", started: "Started", retry: "Retry", failure: "Failure", success: "Success", cancelled: "Cancelled" };
    return <Badge variant={config.variant} className={config.className}>{labels[status]}</Badge>;
  };

  const handleRename = (conversation: IACConversation) => { setSelectedConversation(conversation); setNewName(conversation.title); setRenameDialogOpen(true); };
  const handleDelete = (conversation: IACConversation) => { setSelectedConversation(conversation); setDeleteDialogOpen(true); };

  const confirmRename = () => {
    if (selectedConversation && newName.trim() && team_id) {
      renameIACConversationMutation.mutate({ team_id: parseInt(team_id), scan_id: selectedConversation.id, title: newName.trim() });
      setRenameDialogOpen(false); setSelectedConversation(null); setNewName("");
    }
  };

  const confirmDelete = () => {
    if (selectedConversation && team_id) {
      deleteIACConversationMutation.mutate({ team_id: parseInt(team_id), scan_id: selectedConversation.id });
      setDeleteDialogOpen(false); setSelectedConversation(null);
    }
  };

  const confirmCreate = () => {
    if (newScanTitle.trim() && team_id) {
      if (!createGuard.tryStart()) return;
      createIACConversationMutation.mutate({ team_id: parseInt(team_id), title: newScanTitle.trim() }, { onSettled: () => createGuard.done() });
    }
  };

  const hasActiveFilters =
    searchQuery !== "" ||
    statusFilter !== "all" ||
    riskScoreFilter !== "all" ||
    environmentFilter !== "all" ||
    sortBy !== "none";

  const filteredConversations = conversations
    .filter((c) => {
      if (searchQuery && !c.title.toLowerCase().includes(searchQuery.toLowerCase())) return false;
      if (statusFilter !== "all" && c.scan_status !== statusFilter) return false;
      const score = getDisplayRiskScore(c);
      if (!matchesRiskScoreFilter(score, riskScoreFilter)) return false;
      if (environmentFilter !== "all") {
        const env = (c.environment ?? "").toLowerCase();
        if (env !== environmentFilter) return false;
      }
      return true;
    })
    .sort((a, b) => {
      if (sortBy === "created_asc") return new Date(a.created_at).getTime() - new Date(b.created_at).getTime();
      if (sortBy === "created_desc") return new Date(b.created_at).getTime() - new Date(a.created_at).getTime();
      const scoreA = getDisplayRiskScore(a) ?? -1;
      const scoreB = getDisplayRiskScore(b) ?? -1;
      if (sortBy === "risk_desc") return scoreB - scoreA;
      if (sortBy === "risk_asc") return scoreA - scoreB;
      const credA = a.estimated_credits != null ? Number(a.estimated_credits) : -1;
      const credB = b.estimated_credits != null ? Number(b.estimated_credits) : -1;
      if (sortBy === "credits_desc") return credB - credA;
      if (sortBy === "credits_asc") return credA - credB;
      return 0;
    });

  const clearFilters = () => {
    setSearchQuery("");
    setStatusFilter("all");
    setRiskScoreFilter("all");
    setEnvironmentFilter("all");
    setSortBy("none");
  };

  const dashboardData = query.data?.dashboard_data;

  return (
    <div className="flex h-screen bg-white dark:bg-zinc-900">
      <div className="flex-1 p-8 overflow-auto">
        <div className="max-w-7xl mx-auto">
          {/* Header */}
          <div className="flex items-center justify-between mb-6">
            <div>
              <h1 className="text-3xl font-bold text-zinc-900 dark:text-white mb-2">IAC Scans</h1>
              <p className="text-zinc-600 dark:text-zinc-400">Manage and view all your IAC scans.</p>
            </div>
            <div className="flex flex-row items-center gap-2">
              <Button className="bg-blue-600 hover:bg-blue-700 text-white cursor-pointer" onClick={() => setCreateDialogOpen(true)}>
                <Plus className="h-4 w-4 mr-2" />New Scan
              </Button>
              <Button className="bg-blue-600 hover:bg-blue-700 text-white cursor-pointer" onClick={() => queryClient.invalidateQueries({ queryKey: ["iac-conversations", team_id] })}>
                <RefreshCcw className="h-4 w-4 mr-2" />Refresh
              </Button>
            </div>
          </div>

          {/* Loading / error states */}
          {query.isLoading ? (
            <div className="flex h-64 items-center justify-center">
              <Loader2 className="size-10 animate-spin text-blue-600" />
            </div>
          ) : query.isError ? (
            <div className="text-center py-12">
              <p className="text-zinc-600 dark:text-zinc-400 mb-4">Error in fetching conversations, please try again later</p>
            </div>
          ) : (
            /* Tabs: Dashboard & Table */
            <Tabs defaultValue="dashboard" className="w-full">
              <TabsList className="mb-4 bg-transparent">
                <TabsTrigger value="dashboard" className="cursor-pointer data-[state=active]:bg-blue-600 data-[state=active]:text-white ">Dashboard</TabsTrigger>
                <TabsTrigger value="table" className="cursor-pointer data-[state=active]:bg-blue-600 data-[state=active]:text-white ">Table</TabsTrigger>
              </TabsList>

              {/* ── Dashboard Tab ── */}
              <TabsContent value="dashboard">
                {dashboardData ? (
                  <IACDashboard dashboardData={dashboardData} />
                ) : (
                  <p className="text-center text-sm text-zinc-500 py-12">No dashboard data available.</p>
                )}
              </TabsContent>

              {/* ── Table Tab ── */}
              <TabsContent value="table">
                {/* Filter bar */}
                {conversations.length > 0 && (
                  <div className="flex flex-wrap items-center gap-3 mb-4">
                    <div className="relative flex-1 min-w-[200px] max-w-sm">
                      <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-zinc-400" />
                      <Input placeholder="Search by title..." value={searchQuery} onChange={(e) => setSearchQuery(e.target.value)} className="pl-9 h-9 cursor-text" />
                    </div>
                    <InfoTip id="scan.filter.search" className="-ml-2" />
                    <Select value={statusFilter} onValueChange={setStatusFilter}>
                      <SelectTrigger className="h-9 min-w-[150px] cursor-pointer"><SelectValue placeholder="Scan status" /></SelectTrigger>
                      <SelectContent>
                        <SelectItem value="all">All statuses</SelectItem>
                        <SelectItem value="not_started">Not Started</SelectItem>
                        <SelectItem value="pending">Pending</SelectItem>
                        <SelectItem value="started">Started</SelectItem>
                        <SelectItem value="retry">Retry</SelectItem>
                        <SelectItem value="success">Success</SelectItem>
                        <SelectItem value="failure">Failure</SelectItem>
                        <SelectItem value="cancelled">Cancelled</SelectItem>
                      </SelectContent>
                    </Select>
                    <InfoTip id="scan.status" className="-ml-2" />

                    <DropdownMenu>
                      <DropdownMenuTrigger asChild>
                        <Button
                          variant="outline"
                          size="sm"
                          className={`h-9 gap-1.5 cursor-pointer border-2 ${
                            riskScoreFilter === "critical"
                              ? "border-red-500 bg-red-50 text-red-700 hover:bg-red-100 dark:bg-red-950/30 dark:text-red-300 dark:hover:bg-red-950/50"
                              : riskScoreFilter === "high"
                                ? "border-orange-500 bg-orange-50 text-orange-700 hover:bg-orange-100 dark:bg-orange-950/30 dark:text-orange-300 dark:hover:bg-orange-950/50"
                                : riskScoreFilter === "medium"
                                  ? "border-amber-500 bg-amber-50 text-amber-700 hover:bg-amber-100 dark:bg-amber-950/30 dark:text-amber-300 dark:hover:bg-amber-950/50"
                                  : riskScoreFilter === "low"
                                    ? "border-blue-500 bg-blue-50 text-blue-700 hover:bg-blue-100 dark:bg-blue-950/30 dark:text-blue-300 dark:hover:bg-blue-950/50"
                                    : "border-zinc-200 dark:border-zinc-700"
                          }`}
                        >
                          <Filter className="h-2 w-2 shrink-0 text-zinc-400" />
                          <span className="capitalize font-normal">{RISK_SCORE_LABELS[riskScoreFilter]}</span>
                          <ChevronDown className="h-3 w-3 opacity-70 shrink-0" />
                        </Button>
                      </DropdownMenuTrigger>
                      <InfoTip id="scan.filter.risk" className="-ml-2" />
                      <DropdownMenuContent align="start" className="min-w-[180px]">
                        <DropdownMenuLabel className="text-xs font-normal text-zinc-500">Filter by risk score</DropdownMenuLabel>
                        <DropdownMenuSeparator />
                        <DropdownMenuItem className="cursor-pointer gap-2" onClick={() => setRiskScoreFilter("all")}>
                          {riskScoreFilter === "all" ? <Check className="h-4 w-4" /> : <span className="w-4" />}
                          All
                        </DropdownMenuItem>
                        <DropdownMenuItem className="cursor-pointer gap-2" onClick={() => setRiskScoreFilter("critical")}>
                          {riskScoreFilter === "critical" ? <Check className="h-4 w-4" /> : <AlertTriangle className="h-4 w-4 text-red-500" />}
                          Critical (≥9)
                        </DropdownMenuItem>
                        <DropdownMenuItem className="cursor-pointer gap-2" onClick={() => setRiskScoreFilter("high")}>
                          {riskScoreFilter === "high" ? <Check className="h-4 w-4" /> : <AlertTriangle className="h-4 w-4 text-orange-500" />}
                          High (7–9)
                        </DropdownMenuItem>
                        <DropdownMenuItem className="cursor-pointer gap-2" onClick={() => setRiskScoreFilter("medium")}>
                          {riskScoreFilter === "medium" ? <Check className="h-4 w-4" /> : <Shield className="h-4 w-4 text-amber-500" />}
                          Medium (5–7)
                        </DropdownMenuItem>
                        <DropdownMenuItem className="cursor-pointer gap-2" onClick={() => setRiskScoreFilter("low")}>
                          {riskScoreFilter === "low" ? <Check className="h-4 w-4" /> : <Shield className="h-4 w-4 text-blue-500" />}
                          Low (&lt;5)
                        </DropdownMenuItem>
                      </DropdownMenuContent>
                    </DropdownMenu>

                    <Select value={environmentFilter} onValueChange={(v) => setEnvironmentFilter(v as EnvironmentFilter)}>
                      <SelectTrigger className="h-9 min-w-[140px] cursor-pointer"><SelectValue placeholder="Environment" /></SelectTrigger>
                      <SelectContent>
                        <SelectItem value="all">All environments</SelectItem>
                        <SelectItem value="production">Production</SelectItem>
                        <SelectItem value="staging">Staging</SelectItem>
                        <SelectItem value="development">Development</SelectItem>
                      </SelectContent>
                    </Select>
                    <InfoTip id="iac.filter.environment" className="-ml-2" />

                    <DropdownMenu>
                      <DropdownMenuTrigger asChild>
                        <Button
                          variant="outline"
                          size="sm"
                          className={`h-9 gap-1.5 cursor-pointer border-2 ${
                            sortBy !== "none"
                              ? "border-violet-500 bg-violet-50 text-violet-700 hover:bg-violet-100 dark:bg-violet-950/30 dark:text-violet-300 dark:hover:bg-violet-950/50"
                              : "border-zinc-200 dark:border-zinc-700"
                          }`}
                        >
                          <ArrowUpDown className="h-2 w-2 shrink-0 text-zinc-400" />
                          <span className="capitalize font-normal">{SORT_BY_LABELS[sortBy]}</span>
                          <ChevronDown className="h-3 w-3 opacity-70 shrink-0" />
                        </Button>
                      </DropdownMenuTrigger>
                      <InfoTip id="scan.filter.sort" className="-ml-2" />
                      <DropdownMenuContent align="start" className="min-w-[200px]">
                        <DropdownMenuLabel className="text-xs font-normal text-zinc-500">Sort by</DropdownMenuLabel>
                        <DropdownMenuSeparator />
                        <DropdownMenuItem className="cursor-pointer gap-2" onClick={() => setSortBy("none")}>
                          {sortBy === "none" ? <Check className="h-4 w-4" /> : <span className="w-4" />}
                          Default
                        </DropdownMenuItem>
                        <DropdownMenuItem className="cursor-pointer gap-2" onClick={() => setSortBy("created_desc")}>
                          {sortBy === "created_desc" ? <Check className="h-4 w-4" /> : <CalendarPlus className="h-4 w-4" />}
                          Created (newest)
                        </DropdownMenuItem>
                        <DropdownMenuItem className="cursor-pointer gap-2" onClick={() => setSortBy("created_asc")}>
                          {sortBy === "created_asc" ? <Check className="h-4 w-4" /> : <CalendarCheck className="h-4 w-4" />}
                          Created (oldest)
                        </DropdownMenuItem>
                        <DropdownMenuItem className="cursor-pointer gap-2" onClick={() => setSortBy("risk_desc")}>
                          {sortBy === "risk_desc" ? <Check className="h-4 w-4" /> : <TrendingDown className="h-4 w-4" />}
                          Risk score (high first)
                        </DropdownMenuItem>
                        <DropdownMenuItem className="cursor-pointer gap-2" onClick={() => setSortBy("risk_asc")}>
                          {sortBy === "risk_asc" ? <Check className="h-4 w-4" /> : <TrendingUp className="h-4 w-4" />}
                          Risk score (low first)
                        </DropdownMenuItem>
                        <DropdownMenuItem className="cursor-pointer gap-2" onClick={() => setSortBy("credits_desc")}>
                          {sortBy === "credits_desc" ? <Check className="h-4 w-4" /> : <DollarSign className="h-4 w-4" />}
                          Credits (high first)
                        </DropdownMenuItem>
                        <DropdownMenuItem className="cursor-pointer gap-2" onClick={() => setSortBy("credits_asc")}>
                          {sortBy === "credits_asc" ? <Check className="h-4 w-4" /> : <DollarSign className="h-4 w-4" />}
                          Credits (low first)
                        </DropdownMenuItem>
                      </DropdownMenuContent>
                    </DropdownMenu>

                    {hasActiveFilters && (
                      <Button variant="ghost" size="sm" className="h-9 text-zinc-500 hover:text-zinc-700 dark:hover:text-zinc-300 cursor-pointer" onClick={clearFilters}>
                        <X className="h-4 w-4 mr-1" />Clear filters
                      </Button>
                    )}
                  </div>
                )}

                {/* Table content */}
                {conversations.length === 0 ? (
                  <div className="text-center py-12">
                    <p className="text-zinc-600 dark:text-zinc-400 mb-4">No scans yet. Create your first IAC scan to get started.</p>
                    <Button className="bg-blue-600 hover:bg-blue-700 text-white cursor-pointer" onClick={() => setCreateDialogOpen(true)}>
                      <Plus className="h-4 w-4 mr-2" />Create New Scan
                    </Button>
                  </div>
                ) : filteredConversations.length === 0 ? (
                  <div className="text-center py-12">
                    <p className="text-zinc-600 dark:text-zinc-400 mb-4">No scans match your filters.</p>
                    <Button variant="outline" className="cursor-pointer" onClick={clearFilters}><X className="h-4 w-4 mr-2" />Clear filters</Button>
                  </div>
                ) : (
                  <ScrollArea className="w-full border rounded-lg">
                    <div className="min-w-max">
                      <Table>
                        <TableHeader>
                          <TableRow>
                            <TableHead className="w-[160px] min-w-[120px]">Title</TableHead>
                            <TableHead><span className="inline-flex items-center gap-1">Created at <InfoTip id="scan.table.created" /></span></TableHead>
                            <TableHead><span className="inline-flex items-center gap-1">Last updated <InfoTip id="scan.table.updated" /></span></TableHead>
                            <TableHead><span className="inline-flex items-center gap-1">Scan status <InfoTip id="scan.status" /></span></TableHead>
                            <TableHead className="w-[180px]"><span className="inline-flex items-center gap-1">Vulnerabilities <InfoTip id="iac.table.vulns" /></span></TableHead>
                            <TableHead className="w-[90px]"><span className="inline-flex items-center gap-1">Risk score <InfoTip id="scan.table.risk4" /></span></TableHead>
                            <TableHead className="w-[100px]"><span className="inline-flex items-center gap-1">Cloud provider <InfoTip id="iac.table.provider" /></span></TableHead>
                            <TableHead className="w-[160px]"><span className="inline-flex items-center gap-1">Repo / Source <InfoTip id="scan.table.source" /></span></TableHead>
                            <TableHead className="w-[100px]"><span className="inline-flex items-center gap-1">Branch <InfoTip id="scan.table.branch" /></span></TableHead>
                            <TableHead className="w-[90px]"><span className="inline-flex items-center gap-1">Environment <InfoTip id="iac.table.environment" /></span></TableHead>
                            <TableHead className="w-[80px]"><span className="inline-flex items-center gap-1">Credits <InfoTip id="scan.table.credits" /></span></TableHead>
                            <TableHead><span className="inline-flex items-center gap-1">Owner <InfoTip id="scan.table.owner" /></span></TableHead>
                            <TableHead className="text-right w-[80px]">Actions</TableHead>
                          </TableRow>
                        </TableHeader>
                        <TableBody>
                          {filteredConversations.map((conversation) => (
                            <TableRow
                              key={conversation.id}
                              className="hover:bg-zinc-50 dark:hover:bg-zinc-800 cursor-pointer"
                              onClick={(e) => {
                                const target = e.target as HTMLElement;
                                if (target.closest("button") || target.closest("[role='menuitem']")) return;
                                const dest = (conversation.scan_status?.toLowerCase() ?? "") === "success"
                                  ? `/${team_id}/iac/${conversation.id}/results`
                                  : `/${team_id}/iac/${conversation.id}`;
                                router.push(dest);
                              }}
                            >
                              <TableCell className="font-medium max-w-[160px] min-w-[120px]">
                                <Link
                                  href={(conversation.scan_status?.toLowerCase() ?? "") === "success" ? `/${team_id}/iac/${conversation.id}/results` : `/${team_id}/iac/${conversation.id}`}
                                  className="text-blue-600 hover:text-blue-700 dark:text-blue-400 dark:hover:text-blue-300 hover:underline cursor-pointer truncate block"
                                  title={conversation.title}
                                >
                                  {conversation.title}
                                </Link>
                              </TableCell>
                              <TableCell className="text-zinc-600 dark:text-zinc-400 text-sm">{formatDate(conversation.created_at)}</TableCell>
                              <TableCell className="text-zinc-600 dark:text-zinc-400 text-sm">{formatDate(conversation.last_updated)}</TableCell>
                              <TableCell className="text-sm">
                                <div className="flex flex-col gap-1.5">
                                  {getStatusBadge(conversation.scan_status as ScanStatus)}
                                  {conversation.info?.current != null && conversation.scan_status !== "success" && conversation.scan_status !== "failure" && (
                                    <div className="flex items-center gap-2">
                                      <Progress value={conversation.info.current} className="h-1.5 flex-1" />
                                      <span className="text-xs text-zinc-500 tabular-nums">{conversation.info.current}%</span>
                                    </div>
                                  )}
                                </div>
                              </TableCell>
                              <TableCell className="text-zinc-600 dark:text-zinc-400 text-sm">
                                {conversation.risk_data ? (
                                  <div className="flex items-center gap-2 flex-wrap">
                                    {[
                                      { label: "Critical", n: conversation.risk_data.total_critical, dot: "bg-red-500" },
                                      { label: "High", n: conversation.risk_data.total_high, dot: "bg-orange-500" },
                                      { label: "Medium", n: conversation.risk_data.total_medium, dot: "bg-amber-500" },
                                      { label: "Low", n: conversation.risk_data.total_low, dot: "bg-blue-500" },
                                    ].map(({ label, n, dot }) => (
                                      <span key={label} className="flex items-center gap-1.5 shrink-0" title={label}>
                                        <span className={`h-2 w-2 rounded-full shrink-0 ${dot}`} aria-hidden />
                                        <span className="tabular-nums">{typeof n === "number" ? n : 0}</span>
                                      </span>
                                    ))}
                                  </div>
                                ) : "—"}
                              </TableCell>
                              <TableCell className="text-zinc-600 dark:text-zinc-400 text-sm tabular-nums">
                                {getDisplayRiskScore(conversation) != null ? getDisplayRiskScore(conversation) : "—"}
                              </TableCell>
                              <TableCell className="text-sm">
                                {conversation.cloud_provider && conversation.cloud_provider.length > 0 ? (
                                  <div className="flex flex-wrap gap-1">
                                    {conversation.cloud_provider.slice(0, 3).map((p) => (
                                      <span
                                        key={p}
                                        className="inline-flex items-center rounded-md px-2 py-0.5 text-xs font-medium bg-zinc-100 text-zinc-800 dark:bg-zinc-700 dark:text-zinc-200"
                                      >
                                        {p}
                                      </span>
                                    ))}
                                    {conversation.cloud_provider.length > 3 && (
                                      <span className="text-xs text-zinc-500">+{conversation.cloud_provider.length - 3}</span>
                                    )}
                                  </div>
                                ) : "—"}
                              </TableCell>
                              <TableCell className="text-zinc-600 dark:text-zinc-400 text-sm max-w-[160px]" title={conversation.repo_url ?? undefined}>
                                {conversation.zip_file_used ? (
                                  <span className="flex items-center gap-1.5 truncate">
                                    <FileArchive className="h-3.5 w-3.5 shrink-0 text-amber-500" aria-hidden />
                                    <span className="truncate">Zip file</span>
                                  </span>
                                ) : conversation.repo_url ? (
                                  <span className="flex items-center gap-1.5 truncate">
                                    <GitBranch className="h-3.5 w-3.5 shrink-0 text-blue-500" aria-hidden />
                                    <span className="truncate">{conversation.repo_url.split("/").pop() ?? conversation.repo_url}</span>
                                  </span>
                                ) : "—"}
                              </TableCell>
                              <TableCell className="text-zinc-600 dark:text-zinc-400 text-sm">
                                {conversation.branch != null && conversation.branch !== "" ? (
                                  <span className="flex items-center gap-1.5 truncate">
                                    <GitBranch className="h-3.5 w-3.5 shrink-0 text-blue-500" aria-hidden />
                                    <span className="truncate">{conversation.branch}</span>
                                  </span>
                                ) : "—"}
                              </TableCell>
                              <TableCell className="text-zinc-600 dark:text-zinc-400 text-sm">
                                {conversation.environment != null && conversation.environment !== "" ? (
                                  <span className="capitalize">{conversation.environment}</span>
                                ) : "—"}
                              </TableCell>
                              <TableCell className="text-zinc-600 dark:text-zinc-400 text-sm tabular-nums">
                                {conversation.estimated_credits != null ? conversation.estimated_credits : "—"}
                              </TableCell>
                              <TableCell className="text-zinc-600 dark:text-zinc-400">
                                {conversation.owner_user_full_name != null && conversation.owner_user_full_name !== "" || conversation.owner_user_email ? (
                                  <div className="flex items-center gap-2">
                                    <Avatar className="h-8 w-8 shrink-0">
                                      <AvatarFallback className="bg-blue-600 text-white text-xs font-medium">
                                        {conversation.owner_user_full_name
                                          ? conversation.owner_user_full_name.trim().split(/\s+/).map((p) => p.charAt(0)).slice(0, 2).join("").toUpperCase() || (conversation.owner_user_email?.[0] ?? "?").toUpperCase()
                                          : (conversation.owner_user_email?.[0] ?? "?").toUpperCase()}
                                    </AvatarFallback>
                                  </Avatar>
                                  <div className="min-w-0">
                                    {conversation.owner_user_full_name != null && conversation.owner_user_full_name !== "" && (
                                      <span className="block truncate max-w-[160px]" title={conversation.owner_user_email ?? ""}>{conversation.owner_user_full_name}</span>
                                    )}
                                    {conversation.owner_user_email != null && conversation.owner_user_email !== "" && (
                                      <span className="block text-xs text-zinc-500 dark:text-zinc-400 truncate max-w-[160px]">{conversation.owner_user_email}</span>
                                    )}
                                  </div>
                                </div>
                                ) : ("—")}
                              </TableCell>
                              <TableCell className="text-right">
                                <DropdownMenu>
                                  <DropdownMenuTrigger asChild>
                                    <Button variant="ghost" size="icon" className="h-8 w-8 cursor-pointer" aria-label={`Actions for ${conversation.title || `scan #${conversation.id}`}`}><MoreVertical className="h-4 w-4" /></Button>
                                  </DropdownMenuTrigger>
                                  <DropdownMenuContent align="end">
                                    {(conversation.scan_status?.toLowerCase() ?? "") === "success" && (
                                      <DropdownMenuItem className="cursor-pointer" onClick={() => router.push(`/${team_id}/iac/${conversation.id}/results?origin=list`)}>
                                        <Eye className="h-4 w-4 mr-2" />View Results
                                      </DropdownMenuItem>
                                    )}
                                    <DropdownMenuItem className="cursor-pointer" onClick={() => { setMetadataScan(conversation); setMetadataDialogOpen(true); }}>
                                      <Eye className="h-4 w-4 mr-2" />View metadata
                                    </DropdownMenuItem>
                                    <DropdownMenuItem className="cursor-pointer" onClick={() => handleRename(conversation)}>
                                      <Pencil className="h-4 w-4 mr-2" />Rename scan
                                    </DropdownMenuItem>
                                    <DropdownMenuItem className="cursor-pointer" onClick={() => handleDelete(conversation)} variant="destructive">
                                      <Trash2 className="h-4 w-4 mr-2" />Delete scan
                                    </DropdownMenuItem>
                                  </DropdownMenuContent>
                                </DropdownMenu>
                              </TableCell>
                            </TableRow>
                          ))}
                        </TableBody>
                      </Table>
                    </div>
                    <ScrollBar orientation="horizontal" />
                  </ScrollArea>
                )}
              </TabsContent>
            </Tabs>
          )}
        </div>
      </div>

      {/* Rename Dialog */}
      <Dialog open={renameDialogOpen} onOpenChange={setRenameDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Rename scan</DialogTitle>
            <DialogDescription>Enter a new name for this scan.</DialogDescription>
          </DialogHeader>
          <div className="py-4 space-y-2">
            <FieldLabel htmlFor="rename-scan-title" infoId="scan.rename.title">Scan name</FieldLabel>
            <Input id="rename-scan-title" value={newName} onChange={(e) => setNewName(e.target.value)} placeholder="Scan name" onKeyDown={(e) => { if (e.key === "Enter") confirmRename(); }} />
          </div>
          <DialogFooter>
            <Button variant="outline" className="cursor-pointer" onClick={() => { setRenameDialogOpen(false); setNewName(""); }}>Cancel</Button>
            <Button onClick={confirmRename} disabled={!newName.trim()} className="bg-blue-600 hover:bg-blue-700 text-white cursor-pointer">Save</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Delete Dialog */}
      <Dialog open={deleteDialogOpen} onOpenChange={setDeleteDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Delete scan</DialogTitle>
            <DialogDescription>Are you sure you want to delete &quot;{selectedConversation?.title}&quot;? This action cannot be undone.</DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" className="cursor-pointer" onClick={() => { setDeleteDialogOpen(false); setSelectedConversation(null); }}>Cancel</Button>
            <Button variant="destructive" className="cursor-pointer" onClick={confirmDelete}>Delete</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Scan metadata dialog */}
      <Dialog open={metadataDialogOpen} onOpenChange={setMetadataDialogOpen}>
        <DialogContent className="max-w-lg max-h-[80vh] overflow-auto">
          <DialogHeader>
            <DialogTitle>Scan metadata</DialogTitle>
            <DialogDescription>{metadataScan ? `Metadata for "${metadataScan.title}"` : "Scan metadata"}</DialogDescription>
          </DialogHeader>
          <div className="py-2">
            {metadataScan?.scan_metadata && typeof metadataScan.scan_metadata === "object" && Object.keys(metadataScan.scan_metadata).length > 0 ? (
              <dl className="space-y-2 text-sm">
                {Object.entries(metadataScan.scan_metadata).map(([key, value]) => (
                  <div key={key} className="flex gap-2 border-b border-zinc-200 dark:border-zinc-700 pb-2">
                    <dt className="font-medium text-zinc-700 dark:text-zinc-300 shrink-0 min-w-[120px]">{key}</dt>
                    <dd className="text-zinc-600 dark:text-zinc-400 break-all">{value !== null && typeof value === "object" ? JSON.stringify(value) : String(value)}</dd>
                  </div>
                ))}
              </dl>
            ) : (
              <p className="text-zinc-500 dark:text-zinc-400 text-sm">No metadata for this scan.</p>
            )}
          </div>
        </DialogContent>
      </Dialog>

      {/* Create Scan Dialog */}
      <Dialog open={createDialogOpen} onOpenChange={setCreateDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Create New Scan</DialogTitle>
            <DialogDescription>Enter a title for your new IAC scan.</DialogDescription>
          </DialogHeader>
          <div className="py-4 space-y-2">
            <FieldLabel htmlFor="new-scan-title" infoId="scan.new.title">Scan title</FieldLabel>
            <Input id="new-scan-title" value={newScanTitle} onChange={(e) => setNewScanTitle(e.target.value)} placeholder="Scan title" onKeyDown={(e) => { if (e.key === "Enter") confirmCreate(); }} />
          </div>
          <DialogFooter>
            <Button variant="outline" className="cursor-pointer" onClick={() => { setCreateDialogOpen(false); setNewScanTitle(""); }}>Cancel</Button>
            <Button onClick={confirmCreate} disabled={!newScanTitle.trim() || createIACConversationMutation.isPending} className="bg-blue-600 hover:bg-blue-700 text-white cursor-pointer">
              {createIACConversationMutation.isPending ? "Creating..." : "Create"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
