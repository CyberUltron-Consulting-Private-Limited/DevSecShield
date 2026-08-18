"use client";

import Link from "next/link";
import { useRouter, useParams } from "next/navigation";
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
import { Plus, MoreVertical, Pencil, Trash2, RefreshCcw, Loader2, Eye, Clock, Play, CheckCircle, XCircle, Search, X, Shield, Activity, AlertTriangle, ChevronDown, ArrowUpDown, Check, CalendarPlus, CalendarCheck } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { MCPConversation, deleteMCPConversation, getMCPConversations, renameMCPConversation, createMCPConversation } from "@/utils/backend_api";
import type { MCPListDashboardData } from "@/utils/backend_api";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
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
  Pie,
  PieChart,
  PolarAngleAxis,
  PolarGrid,
  Radar,
  RadarChart,
  RadialBar,
  RadialBarChart,
  XAxis,
  YAxis,
} from "recharts";

type ScanStatus = "pending" | "started" | "retry" | "failure" | "success" | "not_started";

/** List item from backend return_mcp_list_item */
type MCPListItem = MCPConversation;

// ─── MCP Dashboard ──────────────────────────────────────────────────────────────
const MCP_CATEGORIES = ["web", "file_system", "code_execution", "database", "search", "vector_store", "document_store"];
const PIE_COLORS = ["hsl(142 71% 45%)", "hsl(217 91% 60%)", "hsl(0 72% 51%)", "hsl(270 50% 60%)", "hsl(25 95% 53%)", "hsl(45 93% 47%)"];

function MCPScanListDashboard({ dashboardData }: { dashboardData: MCPListDashboardData }) {
  const card = dashboardData.card_data ?? { total_scans: 0, total_critical_issues: 0, average_risk_score: 0, total_active_scans: 0, total_resolved_issues: 0 };
  const scanStatus = dashboardData.scan_status_distribution ?? { not_started: 0, started: 0, success: 0, failure: 0 };
  const riskScoreTrend = dashboardData.risk_score_trend ?? {};
  const risksOverTime = dashboardData.risks_over_time ?? {};
  const severityDist = dashboardData.severity_distribution ?? { critical: 0, high: 0, medium: 0, low: 0 };
  const envRisk = dashboardData.environment_risk_analysis ?? { development: 0, production: 0, staging: 0 };
  const complianceDist = dashboardData.compliance_framework_distribution ?? {};
  const remediation = dashboardData.remediation_status_tracking ?? { not_started: 0, in_progress: 0, fixed: 0, ignored: 0 };
  const assetCat = dashboardData.asset_category_vulnerabilities ?? {};
  const scanDuration = dashboardData.scan_duration_trends ?? {};
  const securityPosture = dashboardData.security_posture_overview ?? {};
  const mttr = dashboardData.mttr_per_day ?? {};
  const effectiveness = dashboardData.scan_effectiveness_trend ?? {};
  const complianceScoreTrend = dashboardData.compliance_framework_score_trend ?? {};
  const vulnAge = dashboardData.vulnerability_age_distribution ?? {};

  const statusData = useMemo(() => [
    { status: "success", count: scanStatus.success, fill: "hsl(142 71% 45%)" },
    { status: "started", count: scanStatus.started, fill: "hsl(217 91% 60%)" },
    { status: "failure", count: scanStatus.failure, fill: "hsl(0 72% 51%)" },
    { status: "not_started", count: scanStatus.not_started, fill: "hsl(270 50% 60%)" },
  ], [scanStatus]);

  const riskScoreTrendData = useMemo(() =>
    Object.entries(riskScoreTrend)
      .map(([name, value]) => ({ name, value }))
      .sort((a, b) => a.name.localeCompare(b.name)),
  [riskScoreTrend]);

  const risksOverTimeData = useMemo(() =>
    Object.entries(risksOverTime)
      .map(([date, v]) => ({ date, ...v }))
      .sort((a, b) => a.date.localeCompare(b.date)),
  [risksOverTime]);

  const severityData = useMemo(() => [
    { severity: "Critical", count: severityDist.critical },
    { severity: "High", count: severityDist.high },
    { severity: "Medium", count: severityDist.medium },
    { severity: "Low", count: severityDist.low },
  ], [severityDist]);

  const envData = useMemo(() =>
    Object.entries(envRisk).map(([name, count], i) => ({ xLabel: `E${i + 1}`, name, count })),
  [envRisk]);

  const complianceData = useMemo(() =>
    Object.entries(complianceDist).map(([name, value]) => ({ name, value })),
  [complianceDist]);

  const remediationData = useMemo(() => [
    { xLabel: "R1", status: "Not Started", count: remediation.not_started },
    { xLabel: "R2", status: "In Progress", count: remediation.in_progress },
    { xLabel: "R3", status: "Fixed", count: remediation.fixed },
    { xLabel: "R4", status: "Ignored", count: remediation.ignored },
  ], [remediation]);

  const assetData = useMemo(() => {
    const entries = MCP_CATEGORIES.map((c) => ({ name: c.replace(/_/g, " "), count: assetCat[c] ?? 0 }));
    return entries.filter((e) => e.count > 0).length > 0 ? entries : MCP_CATEGORIES.map((c) => ({ name: c.replace(/_/g, " "), count: 0 }));
  }, [assetCat]);

  const durationData = useMemo(() =>
    Object.entries(scanDuration).map(([name, value]) => ({ name, duration: value })),
  [scanDuration]);

  // Security posture: S1, S2, ... with legend; one Radar per category for distinct colors
  const SECURITY_POSTURE_COLORS = ["hsl(217 91% 60%)", "hsl(142 71% 45%)", "hsl(48 96% 53%)", "hsl(25 95% 53%)", "hsl(270 50% 60%)", "hsl(0 84% 60%)", "hsl(180 70% 45%)"];
  const radarData = useMemo(() => {
    return MCP_CATEGORIES.map((c, i) => {
      const categoryLabel = c.replace(/_/g, " ");
      const value = securityPosture[c] ?? 0;
      const row: Record<string, string | number> = {
        xLabel: `S${i + 1}`,
        category: categoryLabel,
        value,
      };
      MCP_CATEGORIES.forEach((k, j) => {
        row[`s${j + 1}`] = j === i ? value : 0;
      });
      return row;
    });
  }, [securityPosture]);

  const mttrData = useMemo(() =>
    Object.entries(mttr)
      .map(([date, [d, h, m]]) => ({ date, totalMinutes: d * 24 * 60 + h * 60 + m }))
      .sort((a, b) => a.date.localeCompare(b.date)),
  [mttr]);

  const effectivenessData = useMemo(() =>
    Object.entries(effectiveness)
      .map(([date, v]) => ({ date, false_positive: v.false_positive, total_findings: v.total_findings }))
      .sort((a, b) => a.date.localeCompare(b.date)),
  [effectiveness]);

  const complianceScoreData = useMemo(() => {
    const dates = Object.keys(complianceScoreTrend).sort();
    const frameworks = new Set<string>();
    dates.forEach((d) => Object.keys(complianceScoreTrend[d] ?? {}).forEach((f) => frameworks.add(f)));
    const frameworkList = Array.from(frameworks);
    return dates.map((date) => {
      const row: Record<string, string | number> = { date };
      frameworkList.forEach((f) => { row[f] = (complianceScoreTrend[date] ?? {})[f] ?? 0; });
      return row;
    });
  }, [complianceScoreTrend]);

  const complianceScoreFrameworkKeys = useMemo(() => {
    if (complianceScoreData.length === 0) return [];
    return Object.keys(complianceScoreData[0] ?? {}).filter((k) => k !== "date");
  }, [complianceScoreData]);

  const vulnAgeData = useMemo(() =>
    Object.entries(vulnAge).map(([name, count]) => ({ name, count })),
  [vulnAge]);

  const areaConfig = {
    critical: { label: "Critical", color: "hsl(0 72% 51%)" },
    high: { label: "High", color: "hsl(25 95% 53%)" },
    medium: { label: "Medium", color: "hsl(45 93% 47%)" },
    low: { label: "Low", color: "hsl(217 91% 60%)" },
  } satisfies ChartConfig;

  const barConfig = { count: { label: "Count", color: "hsl(220 70% 50%)" } } satisfies ChartConfig;

  return (
    <div className="space-y-6">
      {/* 5 summary cards */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
        <Card className="border-zinc-200 dark:border-zinc-800 py-3 px-3">
          <CardContent className="p-0">
            <div className="flex flex-col items-start gap-2">
              <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-blue-500/15 dark:bg-blue-500/10">
                <Activity className="h-4 w-4 text-blue-500" />
              </div>
              <div>
                <p className="text-xs font-medium text-zinc-600 dark:text-zinc-400">Total Scans</p>
                <p className="text-xl font-bold text-zinc-900 dark:text-white">{card.total_scans}</p>
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
                <p className="text-xs font-medium text-zinc-600 dark:text-zinc-400">Critical Issues</p>
                <p className="text-xl font-bold text-zinc-900 dark:text-white">{card.total_critical_issues}</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card className="border-zinc-200 dark:border-zinc-800 py-3 px-3">
          <CardContent className="p-0">
            <div className="flex flex-col items-start gap-2">
              <div className={`flex h-8 w-8 shrink-0 items-center justify-center rounded-lg ${card.average_risk_score >= 7 ? "bg-red-500/15" : card.average_risk_score >= 5 ? "bg-amber-500/15" : "bg-green-500/15"}`}>
                <Shield className={`h-4 w-4 ${card.average_risk_score >= 7 ? "text-red-500" : card.average_risk_score >= 5 ? "text-amber-500" : "text-green-500"}`} />
              </div>
              <div>
                <p className="text-xs font-medium text-zinc-600 dark:text-zinc-400">Avg Risk Score</p>
                <p className="text-xl font-bold text-zinc-900 dark:text-white">{card.average_risk_score} / 10</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card className="border-zinc-200 dark:border-zinc-800 py-3 px-3">
          <CardContent className="p-0">
            <div className="flex flex-col items-start gap-2">
              <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-blue-500/15 dark:bg-blue-500/10">
                <Play className="h-4 w-4 text-blue-500" />
              </div>
              <div>
                <p className="text-xs font-medium text-zinc-600 dark:text-zinc-400">Active Scans</p>
                <p className="text-xl font-bold text-zinc-900 dark:text-white">{card.total_active_scans}</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card className="border-zinc-200 dark:border-zinc-800 py-3 px-3">
          <CardContent className="p-0">
            <div className="flex flex-col items-start gap-2">
              <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-green-500/15 dark:bg-green-500/10">
                <CheckCircle className="h-4 w-4 text-green-500" />
              </div>
              <div>
                <p className="text-xs font-medium text-zinc-600 dark:text-zinc-400">Resolved (7d)</p>
                <p className="text-xl font-bold text-zinc-900 dark:text-white">{card.total_resolved_issues}</p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Charts row 1: Scan Status | Risk Score Trend | Risks Over Time */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <Card className="border-zinc-200 dark:border-zinc-800">
          <CardHeader className="pb-2">
            <CardTitle className="text-base">Scan Status Distribution</CardTitle>
            <CardDescription>Distribution of scan outcomes</CardDescription>
          </CardHeader>
          <CardContent>
            {statusData.every((s) => s.count === 0) ? (
              <p className="text-center text-sm text-zinc-500 py-8">No scans yet</p>
            ) : (
              <ChartContainer config={barConfig} className="mx-auto aspect-square max-h-[220px]">
                <PieChart>
                  <ChartTooltip content={<ChartTooltipContent />} />
                  <Pie data={statusData} dataKey="count" nameKey="status" cx="50%" cy="50%" outerRadius={80} label>
                    {statusData.map((_, i) => <Cell key={i} fill={PIE_COLORS[i % PIE_COLORS.length]} />)}
                  </Pie>
                </PieChart>
              </ChartContainer>
            )}
            <div className="flex flex-wrap items-center justify-center gap-3 mt-2 text-sm text-zinc-600 dark:text-zinc-400">
              <span className="flex items-center gap-1.5"><span className="inline-block h-2.5 w-2.5 rounded-full" style={{ background: "hsl(142 71% 45%)" }} />Success</span>
              <span className="flex items-center gap-1.5"><span className="inline-block h-2.5 w-2.5 rounded-full" style={{ background: "hsl(217 91% 60%)" }} />Started</span>
              <span className="flex items-center gap-1.5"><span className="inline-block h-2.5 w-2.5 rounded-full" style={{ background: "hsl(0 72% 51%)" }} />Failure</span>
              <span className="flex items-center gap-1.5"><span className="inline-block h-2.5 w-2.5 rounded-full" style={{ background: "hsl(270 50% 60%)" }} />Not Started</span>
            </div>
          </CardContent>
        </Card>
        <Card className="border-zinc-200 dark:border-zinc-800">
          <CardHeader className="pb-2">
            <CardTitle className="text-base">Risk Score Trend</CardTitle>
            <CardDescription>Average risk score per MCP server scan</CardDescription>
          </CardHeader>
          <CardContent>
            {riskScoreTrendData.length === 0 ? (
              <p className="text-center text-sm text-zinc-500 py-8">No risk data yet</p>
            ) : (
              <ChartContainer config={{ value: { label: "Risk Score", color: "#2563eb" } }} className="h-[220px] w-full">
                <AreaChart data={riskScoreTrendData}>
                  <CartesianGrid vertical={false} />
                  <XAxis dataKey="name" tickLine={false} axisLine={false} tickMargin={8} tickFormatter={(v) => String(v).length > 10 ? `${String(v).slice(0, 10)}...` : v} />
                  <YAxis tickLine={false} axisLine={false} domain={[0, 10]} />
                  <ChartTooltip content={<ChartTooltipContent />} />
                  <Area type="monotone" dataKey="value" fill="#2563eb" stroke="#2563eb" fillOpacity={0.4} />
                </AreaChart>
              </ChartContainer>
            )}
          </CardContent>
        </Card>
        <Card className="border-zinc-200 dark:border-zinc-800">
          <CardHeader className="pb-2">
            <CardTitle className="text-base">Risks Over Time</CardTitle>
            <CardDescription>Vulnerability counts per date</CardDescription>
          </CardHeader>
          <CardContent>
            {risksOverTimeData.length === 0 ? (
              <p className="text-center text-sm text-zinc-500 py-8">No risk data yet</p>
            ) : (
              <ChartContainer config={areaConfig} className="h-[220px] w-full">
                <AreaChart data={risksOverTimeData}>
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
      </div>

      {/* Charts row 2: Severity | Environment | Compliance | Remediation */}
      <div className="grid grid-cols-1 lg:grid-cols-2 xl:grid-cols-4 gap-6">
        <Card className="border-zinc-200 dark:border-zinc-800">
          <CardHeader className="pb-2">
            <CardTitle className="text-base">Severity Distribution</CardTitle>
            <CardDescription>Issues by severity</CardDescription>
          </CardHeader>
          <CardContent>
            {severityData.every((s) => s.count === 0) ? (
              <p className="text-center text-sm text-zinc-500 py-8">No data</p>
            ) : (
              <ChartContainer config={barConfig} className="h-[200px] w-full">
                <BarChart data={severityData} layout="vertical" margin={{ left: 8 }}>
                  <CartesianGrid horizontal={false} />
                  <XAxis type="number" tickLine={false} axisLine={false} allowDecimals={false} />
                  <YAxis type="category" dataKey="severity" width={70} tickLine={false} axisLine={false} />
                  <ChartTooltip content={<ChartTooltipContent />} />
                  <Bar dataKey="count" fill="var(--color-count)" radius={[0, 4, 4, 0]} />
                </BarChart>
              </ChartContainer>
            )}
          </CardContent>
        </Card>
        <Card className="border-zinc-200 dark:border-zinc-800">
          <CardHeader className="pb-2">
            <CardTitle className="text-base">Environment Risk Analysis</CardTitle>
            <CardDescription>Issues by environment</CardDescription>
          </CardHeader>
          <CardContent>
            {envData.every((e) => e.count === 0) ? (
              <p className="text-center text-sm text-zinc-500 py-8">No data</p>
            ) : (
              <>
                <ChartContainer config={barConfig} className="h-[200px] w-full">
                  <BarChart data={envData}>
                    <CartesianGrid vertical={false} />
                    <XAxis dataKey="xLabel" tickLine={false} axisLine={false} />
                    <YAxis tickLine={false} axisLine={false} allowDecimals={false} />
                    <ChartTooltip content={<ChartTooltipContent nameKey="name" />} />
                    <Bar dataKey="count" fill="var(--color-count)" radius={[4, 4, 0, 0]} />
                  </BarChart>
                </ChartContainer>
                <div className="mt-4 pt-3 border-t border-zinc-200 dark:border-zinc-700 flex flex-wrap gap-x-4 gap-y-2 justify-center text-xs text-zinc-600 dark:text-zinc-400">
                  {envData.map((d) => (
                    <span key={d.xLabel}>
                      <span className="font-medium text-zinc-800 dark:text-zinc-200">{d.xLabel}</span>
                      <span className="mx-1.5">=</span>
                      <span>{d.name}</span>
                    </span>
                  ))}
                </div>
              </>
            )}
          </CardContent>
        </Card>
        <Card className="border-zinc-200 dark:border-zinc-800">
          <CardHeader className="pb-2">
            <CardTitle className="text-base">Compliance Framework Distribution</CardTitle>
            <CardDescription>Issues per framework</CardDescription>
          </CardHeader>
          <CardContent>
            {complianceData.length === 0 ? (
              <p className="text-center text-sm text-zinc-500 py-8">No data</p>
            ) : (
              <ChartContainer config={barConfig} className="mx-auto aspect-square max-h-[200px]">
                <PieChart>
                  <ChartTooltip content={<ChartTooltipContent />} />
                  <Pie data={complianceData} dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius={70}>
                    {complianceData.map((_, i) => <Cell key={i} fill={PIE_COLORS[i % PIE_COLORS.length]} />)}
                  </Pie>
                </PieChart>
              </ChartContainer>
            )}
          </CardContent>
        </Card>
        <Card className="border-zinc-200 dark:border-zinc-800">
          <CardHeader className="pb-2">
            <CardTitle className="text-base">Remediation Status</CardTitle>
            <CardDescription>Issue resolution status</CardDescription>
          </CardHeader>
          <CardContent>
            {remediationData.every((r) => r.count === 0) ? (
              <p className="text-center text-sm text-zinc-500 py-8">No data</p>
            ) : (
              <>
                <ChartContainer config={barConfig} className="h-[200px] w-full">
                  <BarChart data={remediationData}>
                    <CartesianGrid vertical={false} />
                    <XAxis dataKey="xLabel" tickLine={false} axisLine={false} />
                    <YAxis tickLine={false} axisLine={false} allowDecimals={false} />
                    <ChartTooltip content={<ChartTooltipContent nameKey="status" />} />
                    <Bar dataKey="count" fill="var(--color-count)" radius={[4, 4, 0, 0]} />
                  </BarChart>
                </ChartContainer>
                <div className="mt-4 pt-3 border-t border-zinc-200 dark:border-zinc-700 flex flex-wrap gap-x-4 gap-y-2 justify-center text-xs text-zinc-600 dark:text-zinc-400">
                  {remediationData.map((d) => (
                    <span key={d.xLabel}>
                      <span className="font-medium text-zinc-800 dark:text-zinc-200">{d.xLabel}</span>
                      <span className="mx-1.5">=</span>
                      <span>{d.status}</span>
                    </span>
                  ))}
                </div>
              </>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Charts row 3: Asset Categories | Scan Duration | Security Posture */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <Card className="border-zinc-200 dark:border-zinc-800">
          <CardHeader className="pb-2">
            <CardTitle className="text-base">Asset Category Vulnerabilities</CardTitle>
            <CardDescription>Issues by asset category</CardDescription>
          </CardHeader>
          <CardContent>
            {assetData.every((a) => a.count === 0) ? (
              <p className="text-center text-sm text-zinc-500 py-8">No data</p>
            ) : (
              <ChartContainer config={barConfig} className="h-[220px] w-full">
                <BarChart data={assetData} layout="vertical" margin={{ left: 8 }}>
                  <CartesianGrid horizontal={false} />
                  <XAxis type="number" tickLine={false} axisLine={false} allowDecimals={false} />
                  <YAxis type="category" dataKey="name" width={90} tickLine={false} axisLine={false} />
                  <ChartTooltip content={<ChartTooltipContent />} />
                  <Bar dataKey="count" fill="var(--color-count)" radius={[0, 4, 4, 0]} />
                </BarChart>
              </ChartContainer>
            )}
          </CardContent>
        </Card>
        <Card className="border-zinc-200 dark:border-zinc-800">
          <CardHeader className="pb-2">
            <CardTitle className="text-base">Scan Duration Trends</CardTitle>
            <CardDescription>Duration per MCP server scan (seconds)</CardDescription>
          </CardHeader>
          <CardContent>
            {durationData.length === 0 ? (
              <p className="text-center text-sm text-zinc-500 py-8">No data</p>
            ) : (
              <ChartContainer config={{ duration: { label: "Duration (s)", color: "#0d9488" } }} className="h-[220px] w-full">
                <BarChart data={durationData}>
                  <CartesianGrid vertical={false} />
                  <XAxis dataKey="name" tickLine={false} axisLine={false} tickFormatter={(v) => String(v).length > 10 ? `${String(v).slice(0, 10)}...` : v} />
                  <YAxis tickLine={false} axisLine={false} allowDecimals={false} />
                  <ChartTooltip content={<ChartTooltipContent />} />
                  <Bar dataKey="duration" fill="#0d9488" radius={[4, 4, 0, 0]} />
                </BarChart>
              </ChartContainer>
            )}
          </CardContent>
        </Card>
        <Card className="border-zinc-200 dark:border-zinc-800">
          <CardHeader className="pb-2">
            <CardTitle className="text-base">Security Posture Overview</CardTitle>
            <CardDescription>Risk score per category</CardDescription>
          </CardHeader>
          <CardContent>
            <ChartContainer
              config={{
                ...Object.fromEntries(MCP_CATEGORIES.map((_, i) => [`s${i + 1}`, { label: `S${i + 1}`, color: SECURITY_POSTURE_COLORS[i] }])),
                value: { label: "Risk Score" },
              }}
              className="mx-auto aspect-square max-h-[220px]"
            >
              <RadarChart data={radarData}>
                <ChartTooltip
                  cursor={false}
                  content={({ active, payload }) => {
                    if (!active || !payload?.length) return null;
                    const row = payload[0]?.payload as { category?: string; value?: number };
                    return (
                      <div className="rounded-lg border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 px-3 py-2 shadow-md">
                        <p className="font-medium text-zinc-900 dark:text-zinc-100">{row?.category ?? "—"}</p>
                        <p className="text-sm text-zinc-600 dark:text-zinc-400">Risk score: {typeof row?.value === "number" ? row.value : "—"}</p>
                      </div>
                    );
                  }}
                />
                <PolarAngleAxis dataKey="xLabel" />
                <PolarGrid />
                {MCP_CATEGORIES.map((_, i) => (
                  <Radar key={i} dataKey={`s${i + 1}`} fill={SECURITY_POSTURE_COLORS[i]} fillOpacity={0.6} stroke={SECURITY_POSTURE_COLORS[i]} strokeWidth={1} />
                ))}
              </RadarChart>
            </ChartContainer>
            <div className="mt-4 pt-3 border-t border-zinc-200 dark:border-zinc-700 flex flex-wrap gap-x-4 gap-y-2 justify-center text-xs text-zinc-600 dark:text-zinc-400">
              {radarData.map((d) => (
                <span key={d.xLabel as string}>
                  <span className="font-medium text-zinc-800 dark:text-zinc-200">{d.xLabel as string}</span>
                  <span className="mx-1.5">=</span>
                  <span>{d.category as string}</span>
                </span>
              ))}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Charts row 4: MTTR | Scan Effectiveness | Compliance Score | Vuln Age */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Card className="border-zinc-200 dark:border-zinc-800">
          <CardHeader className="pb-2">
            <CardTitle className="text-base">Mean Time to Remediate per Day</CardTitle>
            <CardDescription>Total remediation time (minutes) per date</CardDescription>
          </CardHeader>
          <CardContent>
            {mttrData.length === 0 ? (
              <p className="text-center text-sm text-zinc-500 py-8">No data</p>
            ) : (
              <ChartContainer config={{ totalMinutes: { label: "Minutes", color: "#7c3aed" } }} className="h-[220px] w-full">
                <AreaChart data={mttrData}>
                  <CartesianGrid vertical={false} />
                  <XAxis dataKey="date" tickLine={false} axisLine={false} tickFormatter={(v) => formatChartDateIst(v)} />
                  <YAxis tickLine={false} axisLine={false} allowDecimals={false} />
                  <ChartTooltip content={<ChartTooltipContent />} />
                  <Area type="monotone" dataKey="totalMinutes" fill="#7c3aed" stroke="#7c3aed" fillOpacity={0.4} />
                </AreaChart>
              </ChartContainer>
            )}
          </CardContent>
        </Card>
        <Card className="border-zinc-200 dark:border-zinc-800">
          <CardHeader className="pb-2">
            <CardTitle className="text-base">Scan Effectiveness Trend</CardTitle>
            <CardDescription>False positives vs total findings per date</CardDescription>
          </CardHeader>
          <CardContent>
            {effectivenessData.length === 0 ? (
              <p className="text-center text-sm text-zinc-500 py-8">No data</p>
            ) : (
              <ChartContainer
                config={{
                  false_positive: { label: "False Positives", color: "#dc2626" },
                  total_findings: { label: "Total Findings", color: "#2563eb" },
                }}
                className="h-[220px] w-full"
              >
                <BarChart data={effectivenessData}>
                  <CartesianGrid vertical={false} />
                  <XAxis dataKey="date" tickLine={false} axisLine={false} tickFormatter={(v) => formatChartDateIst(v)} />
                  <YAxis tickLine={false} axisLine={false} allowDecimals={false} />
                  <ChartTooltip content={<ChartTooltipContent />} />
                  <ChartLegend content={<ChartLegendContent />} />
                  <Bar dataKey="false_positive" fill="var(--color-false_positive)" radius={[4, 4, 0, 0]} />
                  <Bar dataKey="total_findings" fill="var(--color-total_findings)" radius={[4, 4, 0, 0]} />
                </BarChart>
              </ChartContainer>
            )}
          </CardContent>
        </Card>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Card className="border-zinc-200 dark:border-zinc-800">
          <CardHeader className="pb-2">
            <CardTitle className="text-base">Compliance Framework Score Trend</CardTitle>
            <CardDescription>Compliance score per framework over time</CardDescription>
          </CardHeader>
          <CardContent>
            {complianceScoreData.length === 0 || complianceScoreFrameworkKeys.length === 0 ? (
              <p className="text-center text-sm text-zinc-500 py-8">No data</p>
            ) : (
              <ChartContainer
                config={Object.fromEntries(complianceScoreFrameworkKeys.map((f, i) => [f, { label: f, color: PIE_COLORS[i % PIE_COLORS.length] }])) as ChartConfig}
                className="h-[220px] w-full"
              >
                <AreaChart data={complianceScoreData}>
                  <CartesianGrid vertical={false} />
                  <XAxis dataKey="date" tickLine={false} axisLine={false} tickFormatter={(v) => formatChartDateIst(v)} />
                  <YAxis tickLine={false} axisLine={false} domain={[0, 100]} />
                  <ChartTooltip content={<ChartTooltipContent />} />
                  <ChartLegend content={<ChartLegendContent />} />
                  {complianceScoreFrameworkKeys.map((k, i) => (
                    <Area key={k} type="monotone" dataKey={k} stackId={undefined} fill={PIE_COLORS[i % PIE_COLORS.length]} stroke={PIE_COLORS[i % PIE_COLORS.length]} fillOpacity={0.3} />
                  ))}
                </AreaChart>
              </ChartContainer>
            )}
          </CardContent>
        </Card>
        <Card className="border-zinc-200 dark:border-zinc-800">
          <CardHeader className="pb-2">
            <CardTitle className="text-base">Vulnerability Age Distribution</CardTitle>
            <CardDescription>Fixed/ignored issues by resolution time</CardDescription>
          </CardHeader>
          <CardContent>
            {vulnAgeData.length === 0 ? (
              <p className="text-center text-sm text-zinc-500 py-8">No data</p>
            ) : (
              <ChartContainer config={barConfig} className="h-[220px] w-full">
                <BarChart data={vulnAgeData}>
                  <CartesianGrid vertical={false} />
                  <XAxis dataKey="name" tickLine={false} axisLine={false} tickFormatter={(v) => String(v).length > 12 ? `${String(v).slice(0, 12)}...` : v} />
                  <YAxis tickLine={false} axisLine={false} allowDecimals={false} />
                  <ChartTooltip content={<ChartTooltipContent />} />
                  <Bar dataKey="count" fill="var(--color-count)" radius={[4, 4, 0, 0]} />
                </BarChart>
              </ChartContainer>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}


export default function MCPPage() {
  const router = useRouter();
  const params = useParams();
  const team_id = params?.team_id as string | undefined;
  const [conversations, setConversations] = useState<MCPListItem[]>([]);
  const [renameDialogOpen, setRenameDialogOpen] = useState(false);
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false);
  const [createDialogOpen, setCreateDialogOpen] = useState(false);
  const [selectedConversation, setSelectedConversation] = useState<MCPListItem | null>(null);
  const [metadataDialogOpen, setMetadataDialogOpen] = useState(false);
  const [metadataScan, setMetadataScan] = useState<MCPListItem | null>(null);
  const [newName, setNewName] = useState("");
  const [newScanTitle, setNewScanTitle] = useState("");
  const [searchQuery, setSearchQuery] = useState("");
  const [statusFilter, setStatusFilter] = useState<string>("all");
  const [createdAtSort, setCreatedAtSort] = useState<"none" | "asc" | "desc">("none");
  const queryClient = useQueryClient();

  const query = useQuery({
    queryKey: ['mcp-conversations', team_id],
    queryFn: () => getMCPConversations(Number(team_id)),
    enabled: !!team_id,
  });

  useEffect(() => {
    if (query.data?.scans_list_data) {
      setConversations(query.data.scans_list_data as MCPListItem[]);
    }
    if (query.error) {
      showErrorToast(query.error, 'Error fetching MCP conversations');
    }
  }, [query.data, query.error]);

  const hasActiveFilters = searchQuery !== "" || statusFilter !== "all" || createdAtSort !== "none";
  const filteredConversations = conversations
    .filter((c) => {
      if (searchQuery && !c.title.toLowerCase().includes(searchQuery.toLowerCase())) return false;
      if (statusFilter !== "all" && c.scan_status !== statusFilter) return false;
      return true;
    })
    .sort((a, b) => {
      if (createdAtSort === "asc") return new Date(a.created_at).getTime() - new Date(b.created_at).getTime();
      if (createdAtSort === "desc") return new Date(b.created_at).getTime() - new Date(a.created_at).getTime();
      return 0;
    });
  const clearFilters = () => { setSearchQuery(""); setStatusFilter("all"); setCreatedAtSort("none"); };
  const dashboardData = query.data?.dashboard_data as MCPListDashboardData | undefined;

  const deleteMCPConversationMutation = useMutation({
    mutationFn: ({ team_id, scan_id }: { team_id: number; scan_id: number }) => deleteMCPConversation(team_id, scan_id),
    onSuccess: (_, variables) => {
      queryClient.invalidateQueries({ queryKey: ['mcp-conversations', String(variables.team_id)] });
      toast.success('MCP conversation deleted successfully');
    },
    onError: (error) => {
      showErrorToast(error);
    }
  });

  const renameMCPConversationMutation = useMutation({
    mutationFn: renameMCPConversation,
    onSuccess: (_, variables) => {
      queryClient.invalidateQueries({ queryKey: ['mcp-conversations', String(variables.team_id)] });
      toast.success('MCP conversation renamed successfully');
    },
    onError: (error) => {
      showErrorToast(error);
    }
  });

  const createMCPConversationMutation = useMutation({
    mutationFn: (title: string) => createMCPConversation(Number(team_id), title),
    onSuccess: (conversationId) => {
      queryClient.invalidateQueries({ queryKey: ['mcp-conversations', team_id] });
      setCreateDialogOpen(false);
      setNewScanTitle("");
      router.push(`/${team_id}/mcp/${conversationId}`);
    },
    onError: (error) => {
      showErrorToast(error);
    }
  });

  const getStatusBadge = (status: ScanStatus) => {
    const variants = {
      not_started: { variant: "outline" as const, className: "text-zinc-500 dark:text-zinc-500" },
      pending: { variant: "outline" as const, className: "text-zinc-600 dark:text-zinc-400" },
      started: { variant: "secondary" as const, className: "bg-blue-500 hover:bg-blue-600 text-white" },
      retry: { variant: "secondary" as const, className: "bg-yellow-500 hover:bg-yellow-600 text-white" },
      failure: { variant: "destructive" as const, className: "" },
      success: { variant: "default" as const, className: "bg-green-500 hover:bg-green-600 text-white" },
    };

    const config = variants[status];
    const labels = {
      not_started: "Not Started",
      pending: "Pending",
      started: "Started",
      retry: "Retry",
      failure: "Failure",
      success: "Success",
    };

    return (
      <Badge variant={config.variant} className={config.className}>
        {labels[status]}
      </Badge>
    );
  };

  const handleRename = (conversation: MCPListItem) => {
    setSelectedConversation(conversation);
    setNewName(conversation.title);
    setRenameDialogOpen(true);
  };

  const handleDelete = (conversation: MCPListItem) => {
    setSelectedConversation(conversation);
    setDeleteDialogOpen(true);
  };

  const confirmRename = () => {
    if (selectedConversation && newName.trim() && team_id) {
      renameMCPConversationMutation.mutate({ team_id: Number(team_id), conversation_id: selectedConversation.id, title: newName.trim() });
      setRenameDialogOpen(false);
      setSelectedConversation(null);
      setNewName("");
    }
  };

  const confirmDelete = () => {
    if (selectedConversation && team_id) {
      deleteMCPConversationMutation.mutate({ team_id: Number(team_id), scan_id: selectedConversation.id });
      setDeleteDialogOpen(false);
      setSelectedConversation(null);
    }
  };

  const confirmCreate = () => {
    if (newScanTitle.trim() && team_id) {
      createMCPConversationMutation.mutate(newScanTitle.trim());
    }
  };

  return (
    <div className="flex h-screen bg-white dark:bg-zinc-900">
      <div className="flex-1 p-8 overflow-auto">
        <div className="max-w-7xl mx-auto">
          {/* Header */}
          <div className="flex items-center justify-between mb-6">
            <div>
              <h1 className="text-3xl font-bold text-zinc-900 dark:text-white mb-2">MCP Scans</h1>
              <p className="text-zinc-600 dark:text-zinc-400">Manage and view all your MCP server scan conversations.</p>
            </div>
            <div className="flex flex-row items-center gap-2">
              <Button className="bg-blue-600 hover:bg-blue-700 text-white cursor-pointer" onClick={() => setCreateDialogOpen(true)}>
                <Plus className="h-4 w-4 mr-2" />New Scan
              </Button>
              <Button className="bg-blue-600 hover:bg-blue-700 text-white cursor-pointer" onClick={() => queryClient.invalidateQueries({ queryKey: ['mcp-conversations', team_id] })}>
                <RefreshCcw className="h-4 w-4 mr-2" />Refresh
              </Button>
            </div>
          </div>

          {query.isLoading ? (
            <div className="flex h-64 items-center justify-center">
              <Loader2 className="size-10 animate-spin text-blue-600" />
            </div>
          ) : query.isError ? (
            <div className="text-center py-12">
              <p className="text-zinc-600 dark:text-zinc-400 mb-4">Error in fetching conversations, please try again later</p>
            </div>
          ) : (
            <Tabs defaultValue="dashboard" className="w-full">
              <TabsList className="mb-4 bg-transparent">
                <TabsTrigger value="dashboard" className="cursor-pointer data-[state=active]:bg-blue-600 data-[state=active]:text-white">Dashboard</TabsTrigger>
                <TabsTrigger value="table" className="cursor-pointer data-[state=active]:bg-blue-600 data-[state=active]:text-white">Table</TabsTrigger>
              </TabsList>

              <TabsContent value="dashboard">
                {dashboardData ? (
                  <MCPScanListDashboard dashboardData={dashboardData} />
                ) : (
                  <p className="text-center text-sm text-zinc-500 py-12">No dashboard data available.</p>
                )}
              </TabsContent>

              <TabsContent value="table">
                {conversations.length > 0 && (
                  <div className="flex flex-wrap items-center gap-3 mb-4">
                    <div className="relative flex-1 min-w-[200px] max-w-sm">
                      <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-zinc-400" />
                      <Input placeholder="Search by title..." value={searchQuery} onChange={(e) => setSearchQuery(e.target.value)} className="pl-9 h-9 cursor-text" />
                    </div>
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
                      </SelectContent>
                    </Select>
                    <DropdownMenu>
                      <DropdownMenuTrigger asChild>
                        <Button
                          variant="outline"
                          size="sm"
                          className={`h-9 gap-1.5 cursor-pointer border-2 ${
                            createdAtSort !== "none"
                              ? "border-violet-500 bg-violet-50 text-violet-700 hover:bg-violet-100 dark:bg-violet-950/30 dark:text-violet-300 dark:hover:bg-violet-950/50"
                              : "border-zinc-200 dark:border-zinc-700"
                          }`}
                        >
                          <ArrowUpDown className="h-2 w-2 shrink-0 text-zinc-400" />
                          <span className="capitalize font-normal">
                            {createdAtSort === "none" ? "Sort" : createdAtSort === "desc" ? "Newest" : "Oldest"}
                          </span>
                          <ChevronDown className="h-3 w-3 opacity-70 shrink-0" />
                        </Button>
                      </DropdownMenuTrigger>
                      <DropdownMenuContent align="start" className="min-w-[180px]">
                        <DropdownMenuLabel className="text-xs font-normal text-zinc-500">Sort by</DropdownMenuLabel>
                        <DropdownMenuSeparator />
                        <DropdownMenuItem className="cursor-pointer gap-2" onClick={() => setCreatedAtSort("none")}>
                          {createdAtSort === "none" ? <Check className="h-4 w-4" /> : <span className="w-4" />}
                          Default
                        </DropdownMenuItem>
                        <DropdownMenuItem className="cursor-pointer gap-2" onClick={() => setCreatedAtSort("desc")}>
                          {createdAtSort === "desc" ? <Check className="h-4 w-4" /> : <CalendarPlus className="h-4 w-4" />}
                          Created (newest)
                        </DropdownMenuItem>
                        <DropdownMenuItem className="cursor-pointer gap-2" onClick={() => setCreatedAtSort("asc")}>
                          {createdAtSort === "asc" ? <Check className="h-4 w-4" /> : <CalendarCheck className="h-4 w-4" />}
                          Created (oldest)
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

                {conversations.length === 0 ? (
                  <div className="text-center py-12">
                    <p className="text-zinc-600 dark:text-zinc-400 mb-4">No scans yet. Create your first MCP scan to get started.</p>
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
                            <TableHead className="w-[220px]">Title</TableHead>
                            <TableHead>Owner</TableHead>
                            <TableHead>Server</TableHead>
                            <TableHead>Risk Score</TableHead>
                            <TableHead>Discovery</TableHead>
                            <TableHead>Risky assets</TableHead>
                            <TableHead className="w-[180px]">Vulnerabilities</TableHead>
                            <TableHead>Created at</TableHead>
                            <TableHead>Last updated</TableHead>
                            <TableHead>Scan status</TableHead>
                            <TableHead className="w-[180px]">View scan metadata</TableHead>
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
                                  ? `/${team_id}/mcp/${conversation.id}/results`
                                  : `/${team_id}/mcp/${conversation.id}`;
                                router.push(dest);
                              }}
                            >
                              <TableCell className="font-medium max-w-[220px] min-w-[160px]">
                                <Link
                                  href={(conversation.scan_status?.toLowerCase() ?? "") === "success" ? `/${team_id}/mcp/${conversation.id}/results` : `/${team_id}/mcp/${conversation.id}`}
                                  className="text-green-600 hover:text-green-700 dark:text-green-400 dark:hover:text-green-300 hover:underline cursor-pointer truncate block"
                                  title={conversation.title}
                                >
                                  {conversation.title}
                                </Link>
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
                            <TableCell className="text-zinc-600 dark:text-zinc-400 text-sm">
                              {conversation.server ?? "—"}
                            </TableCell>
                            <TableCell className="text-zinc-600 dark:text-zinc-400 text-sm">
                              {conversation.average_risk_score != null
                                ? Number(conversation.average_risk_score).toFixed(1)
                                : "—"}
                            </TableCell>
                            <TableCell className="text-zinc-600 dark:text-zinc-400 text-sm">
                              {conversation.discovery_metrics
                                ? `T: ${conversation.discovery_metrics.total_tools} P: ${conversation.discovery_metrics.total_prompts} R: ${conversation.discovery_metrics.total_resources}`
                                : "—"}
                            </TableCell>
                            <TableCell className="text-zinc-600 dark:text-zinc-400 text-sm">
                              {conversation.risky_assets != null ? conversation.risky_assets : "—"}
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
                            <TableCell>
                              <Button variant="outline" size="sm" className="cursor-pointer" onClick={(e) => { e.stopPropagation(); setMetadataScan(conversation); setMetadataDialogOpen(true); }}>
                                <Eye className="h-4 w-4 mr-1.5" />View
                              </Button>
                            </TableCell>
                            <TableCell className="text-right">
                                <DropdownMenu>
                                  <DropdownMenuTrigger asChild>
                                    <Button variant="ghost" size="icon" className="h-8 w-8 cursor-pointer"><MoreVertical className="h-4 w-4" /></Button>
                                  </DropdownMenuTrigger>
                                  <DropdownMenuContent align="end">
                                    {(conversation.scan_status?.toLowerCase() ?? "") === "success" && (
                                      <DropdownMenuItem className="cursor-pointer" onClick={() => router.push(`/${team_id}/mcp/${conversation.id}/results?origin=list`)}>
                                        <Eye className="h-4 w-4 mr-2" />View Results
                                      </DropdownMenuItem>
                                    )}
                                    <DropdownMenuItem className="cursor-pointer" onClick={() => handleRename(conversation)}>
                                      <Pencil className="h-4 w-4 mr-2" />Rename
                                    </DropdownMenuItem>
                                    <DropdownMenuItem className="cursor-pointer" onClick={() => handleDelete(conversation)} variant="destructive">
                                      <Trash2 className="h-4 w-4 mr-2" />Delete
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
            <DialogTitle>Rename Conversation</DialogTitle>
            <DialogDescription>
              Enter a new name for this conversation.
            </DialogDescription>
          </DialogHeader>
          <div className="py-4">
            <Input
              value={newName}
              onChange={(e) => setNewName(e.target.value)}
              placeholder="Conversation name"
              onKeyDown={(e) => {
                if (e.key === "Enter") {
                  confirmRename();
                }
              }}
            />
          </div>
          <DialogFooter>
            <Button
              variant="outline"
              className="cursor-pointer"
              onClick={() => {
                setRenameDialogOpen(false);
                setNewName("");
              }}
            >
              Cancel
            </Button>
            <Button
              onClick={confirmRename}
              disabled={!newName.trim()}
              className="bg-blue-600 hover:bg-blue-700 text-white cursor-pointer"
            >
              Save
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Delete Dialog */}
      <Dialog open={deleteDialogOpen} onOpenChange={setDeleteDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Delete Conversation</DialogTitle>
            <DialogDescription>
              Are you sure you want to delete &quot;{selectedConversation?.title}&quot;? This action cannot be undone.
            </DialogDescription>
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
            <DialogDescription>
              Enter a title for your new MCP scan conversation.
            </DialogDescription>
          </DialogHeader>
          <div className="py-4">
            <Input
              value={newScanTitle}
              onChange={(e) => setNewScanTitle(e.target.value)}
              placeholder="Scan title"
              onKeyDown={(e) => {
                if (e.key === "Enter") {
                  confirmCreate();
                }
              }}
            />
          </div>
          <DialogFooter>
            <Button
              variant="outline"
              className="cursor-pointer"
              onClick={() => {
                setCreateDialogOpen(false);
                setNewScanTitle("");
              }}
            >
              Cancel
            </Button>
            <Button
              onClick={confirmCreate}
              disabled={!newScanTitle.trim() || !team_id || createMCPConversationMutation.isPending}
              className="bg-blue-600 hover:bg-blue-700 text-white cursor-pointer"
            >
              {createMCPConversationMutation.isPending ? "Creating..." : "Create"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
