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
import { Plus, MoreVertical, Pencil, Trash2, RefreshCcw, Loader2, Eye, Clock, Play, CheckCircle, XCircle, CalendarPlus, CalendarCheck, Search, X, Shield, Percent, Bug, ChevronDown, ArrowUpDown, Check, Filter, DollarSign, TrendingUp, TrendingDown, AlertTriangle } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { singleFlight } from "@/utils/single_flight";
import { deleteLLMConversation, getLLMConversations, renameLLMConversation, createLLMConversation, type LLMScanListItem } from "@/utils/backend_api";
import { getProbeDisplayName } from "@/utils/probe-display-names";
import { OWASP_LLM_KEY_TO_LABEL } from "@/lib/owasp-compliance-labels";
import type { LLMListDashboardData } from "@/utils/backend_api";

const OWASP_LLM_KEYS = Object.values(OWASP_LLM_KEY_TO_LABEL);
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
  type ChartConfig,
} from "@/components/ui/chart";
import {
  Bar,
  BarChart,
  CartesianGrid,
  XAxis,
  YAxis,
  RadialBar,
  RadialBarChart,
  Pie,
  PieChart,
  Cell,
  Area,
  AreaChart,
  Radar,
  RadarChart,
  PolarAngleAxis,
  PolarGrid,
} from "recharts";

type ScanStatus = "pending" | "started" | "retry" | "failure" | "success" | "not_started";

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

function getDisplayRiskScore(c: LLMScanListItem): number | null {
  if (c.average_risk_score != null) return Math.round(Math.min(10, Math.max(0, c.average_risk_score)) * 10) / 10;
  const rd = c.risk_data;
  if (!rd) return null;
  const total = (rd.total_critical ?? 0) + (rd.total_high ?? 0) + (rd.total_medium ?? 0) + (rd.total_low ?? 0);
  if (total === 0) return null;
  const weighted = ((rd.total_critical ?? 0) * 4 + (rd.total_high ?? 0) * 3 + (rd.total_medium ?? 0) * 2 + (rd.total_low ?? 0) * 1) / total;
  return Math.round(Math.min(10, Math.max(0, (weighted / 4) * 10)) * 10) / 10;
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

// ─── Full LLM Dashboard (status cards, LLM metrics, charts) ─────────────────────
function ScanListDashboardLLM({ dashboardData }: { dashboardData: LLMListDashboardData }) {
  const card = dashboardData.card_data;
  const notStarted = card.not_started_scans ?? 0;
  const pending = card.pending_scans ?? 0;
  const started = card.started_scans ?? 0;
  const success = card.success_scans ?? 0;
  const failure = card.failure_scans ?? 0;
  const createdToday = card.scans_created_today ?? 0;
  const updatedToday = card.scans_updated_today ?? 0;

  const scansPerDayData = useMemo(() => {
    const perDay = dashboardData.scans_per_day ?? {};
    return Object.entries(perDay)
      .map(([date, count]) => ({ date, scans: count }))
      .sort((a, b) => a.date.localeCompare(b.date));
  }, [dashboardData.scans_per_day]);

  const statusData = useMemo(() => [
    { status: "success", count: success, fill: "hsl(142 71% 45%)" },
    { status: "started", count: started, fill: "hsl(217 91% 60%)" },
    { status: "pending", count: pending, fill: "hsl(220 9% 46%)" },
    { status: "failure", count: failure, fill: "hsl(0 72% 51%)" },
    { status: "not_started", count: notStarted, fill: "hsl(270 50% 60%)" },
  ], [success, started, pending, failure, notStarted]);

  const riskLevelData = useMemo(() => [
    { name: "Critical", value: dashboardData.risk_level_distribution.critical, fill: "#dc2626" },
    { name: "High", value: dashboardData.risk_level_distribution.high, fill: "#ea580c" },
    { name: "Medium", value: dashboardData.risk_level_distribution.medium, fill: "#ca8a04" },
    { name: "Low", value: dashboardData.risk_level_distribution.low, fill: "#2563eb" },
  ].filter((d) => d.value > 0), [dashboardData.risk_level_distribution]);

  const attackVectorData = useMemo(() => {
    const av = dashboardData.attack_vector_test_results ?? {};
    return Object.entries(av).map(([probe, v]) => {
      const displayName = getProbeDisplayName(probe);
      return {
        probe: displayName.length > 28 ? `${displayName.slice(0, 28)}…` : displayName,
        fullProbe: displayName,
        passed: v.passed,
        failed: v.failed,
        total: v.passed + v.failed,
      };
    }).filter((d) => d.total > 0);
  }, [dashboardData.attack_vector_test_results]);

  const modelRiskData = useMemo(() => {
    const mr = dashboardData.model_risk_comparison ?? {};
    return Object.entries(mr).map(([model, score]) => ({
      model: model.length > 16 ? `${model.slice(0, 16)}…` : model,
      score,
      fullModel: model,
    })).sort((a, b) => b.score - a.score);
  }, [dashboardData.model_risk_comparison]);

  const radarData = useMemo(() => {
    const posture = dashboardData.ai_security_posture_overview ?? {};
    return Object.entries(posture).map(([subject, value]) => ({
      subject: subject.charAt(0).toUpperCase() + subject.slice(1).replace(/([A-Z])/g, " $1").trim(),
      value: Math.min(10, Math.max(0, value)),
      fullMark: 10,
    }));
  }, [dashboardData.ai_security_posture_overview]);

  const owaspData = useMemo(() => {
    const owasp = dashboardData.owasp_top_10_llm_metrics ?? {};
    const shortLabel = (k: string) => k.replace(/^LLM\d+:2025\s*-?\s*/, "").slice(0, 22);
    const entries = Object.keys(owasp).length > 0
      ? Object.entries(owasp)
      : OWASP_LLM_KEYS.map((k) => [k, 0] as [string, number]);
    return entries
      .map(([k, v]) => ({ name: shortLabel(k), value: v, fullName: k }))
      .sort((a, b) => b.value - a.value)
      .slice(0, 10);
  }, [dashboardData.owasp_top_10_llm_metrics]);

  const barConfig = { scans: { label: "Scans", color: "hsl(220 70% 50%)" } } satisfies ChartConfig;
  const radialConfig = { count: { label: "Scans" } } satisfies ChartConfig;
  const attackBarConfig = {
    passed: { label: "Passed", color: "hsl(142 71% 45%)" },
    failed: { label: "Failed", color: "hsl(0 72% 51%)" },
  } satisfies ChartConfig;
  const modelBarConfig = { score: { label: "Risk Score", color: "hsl(217 91% 60%)" } } satisfies ChartConfig;
  const radarConfig = { value: { label: "Score" } } satisfies ChartConfig;

  return (
    <div className="space-y-6">
      {/* Row 1: Status cards */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-7 gap-4">
        <Card className="border-zinc-200 dark:border-zinc-800">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium text-zinc-600 dark:text-zinc-400">Not Started</CardTitle>
            <Clock className="h-4 w-4 text-zinc-400" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-zinc-900 dark:text-white">{notStarted}</div>
            <p className="text-xs text-zinc-500 dark:text-zinc-400">Idle</p>
          </CardContent>
        </Card>
        <Card className="border-zinc-200 dark:border-zinc-800">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium text-zinc-600 dark:text-zinc-400">Pending</CardTitle>
            <Clock className="h-4 w-4 text-zinc-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-zinc-900 dark:text-white">{pending}</div>
            <p className="text-xs text-zinc-500 dark:text-zinc-400">Queued</p>
          </CardContent>
        </Card>
        <Card className="border-zinc-200 dark:border-zinc-800">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium text-zinc-600 dark:text-zinc-400">Started</CardTitle>
            <Play className="h-4 w-4 text-blue-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-zinc-900 dark:text-white">{started}</div>
            <p className="text-xs text-zinc-500 dark:text-zinc-400">In progress</p>
          </CardContent>
        </Card>
        <Card className="border-zinc-200 dark:border-zinc-800">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium text-zinc-600 dark:text-zinc-400">Success</CardTitle>
            <CheckCircle className="h-4 w-4 text-green-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-zinc-900 dark:text-white">{success}</div>
            <p className="text-xs text-zinc-500 dark:text-zinc-400">Completed</p>
          </CardContent>
        </Card>
        <Card className="border-zinc-200 dark:border-zinc-800">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium text-zinc-600 dark:text-zinc-400">Failure</CardTitle>
            <XCircle className="h-4 w-4 text-red-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-zinc-900 dark:text-white">{failure}</div>
            <p className="text-xs text-zinc-500 dark:text-zinc-400">Failed</p>
          </CardContent>
        </Card>
        <Card className="border-zinc-200 dark:border-zinc-800">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium text-zinc-600 dark:text-zinc-400">Created today</CardTitle>
            <CalendarPlus className="h-4 w-4 text-zinc-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-zinc-900 dark:text-white">{createdToday}</div>
            <p className="text-xs text-zinc-500 dark:text-zinc-400">New scans</p>
          </CardContent>
        </Card>
        <Card className="border-zinc-200 dark:border-zinc-800">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium text-zinc-600 dark:text-zinc-400">Updated today</CardTitle>
            <CalendarCheck className="h-4 w-4 text-zinc-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-zinc-900 dark:text-white">{updatedToday}</div>
            <p className="text-xs text-zinc-500 dark:text-zinc-400">Last 24h</p>
          </CardContent>
        </Card>
      </div>

      {/* Row 2: LLM metric cards */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
        <Card className="border-zinc-200 dark:border-zinc-800">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium text-zinc-600 dark:text-zinc-400">Scans (success)</CardTitle>
            <CheckCircle className="h-4 w-4 text-green-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-zinc-900 dark:text-white">{card.total_scans}</div>
            <p className="text-xs text-zinc-500 dark:text-zinc-400">Completed scans</p>
          </CardContent>
        </Card>
        <Card className="border-zinc-200 dark:border-zinc-800">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium text-zinc-600 dark:text-zinc-400">Avg Risk Score</CardTitle>
            <Shield className="h-4 w-4 text-zinc-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-zinc-900 dark:text-white">{card.average_risk_score} / 10</div>
            <p className="text-xs text-zinc-500 dark:text-zinc-400">Security posture</p>
          </CardContent>
        </Card>
        <Card className="border-zinc-200 dark:border-zinc-800">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium text-zinc-600 dark:text-zinc-400">Critical Vulns</CardTitle>
            <Bug className="h-4 w-4 text-red-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-zinc-900 dark:text-white">{card.total_critical_vulnerabilities}</div>
            <p className="text-xs text-zinc-500 dark:text-zinc-400">Critical issues</p>
          </CardContent>
        </Card>
        <Card className="border-zinc-200 dark:border-zinc-800">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium text-zinc-600 dark:text-zinc-400">Total Vulns</CardTitle>
            <Bug className="h-4 w-4 text-zinc-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-zinc-900 dark:text-white">{card.total_vulnerabilities}</div>
            <p className="text-xs text-zinc-500 dark:text-zinc-400">All findings</p>
          </CardContent>
        </Card>
        <Card className="border-zinc-200 dark:border-zinc-800">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium text-zinc-600 dark:text-zinc-400">OWASP Score</CardTitle>
            <Shield className="h-4 w-4 text-zinc-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-zinc-900 dark:text-white">{card.owasp_compliance_score} / 10</div>
            <p className="text-xs text-zinc-500 dark:text-zinc-400">Compliance</p>
          </CardContent>
        </Card>
        <Card className="border-zinc-200 dark:border-zinc-800">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium text-zinc-600 dark:text-zinc-400">Passed Rate</CardTitle>
            <Percent className="h-4 w-4 text-green-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-zinc-900 dark:text-white">{card.passed_rate}%</div>
            <p className="text-xs text-zinc-500 dark:text-zinc-400">Tests passed</p>
          </CardContent>
        </Card>
      </div>

      {/* Row 3: Risk Level | Attack Vector | Model Risk */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <Card className="border-zinc-200 dark:border-zinc-800">
          <CardHeader className="pb-2">
            <CardTitle className="text-base">Risk Level Distribution</CardTitle>
            <CardDescription>Vulnerability severity across scans</CardDescription>
          </CardHeader>
          <CardContent>
            {riskLevelData.length === 0 ? (
              <p className="text-center text-sm text-zinc-500 py-8">No vulnerability data yet</p>
            ) : (
              <ChartContainer config={{}} className="mx-auto aspect-square max-h-[260px]">
                <PieChart>
                  <ChartTooltip content={<ChartTooltipContent />} />
                  <Pie data={riskLevelData} dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius={80} label={(e) => `${e.name}: ${e.value}`}>
                    {riskLevelData.map((_, i) => (
                      <Cell key={i} fill={riskLevelData[i].fill} />
                    ))}
                  </Pie>
                </PieChart>
              </ChartContainer>
            )}
          </CardContent>
        </Card>
        <Card className="border-zinc-200 dark:border-zinc-800">
          <CardHeader className="pb-2">
            <CardTitle className="text-base">Attack Vector Test Results</CardTitle>
            <CardDescription>Passed vs failed per probe</CardDescription>
          </CardHeader>
          <CardContent>
            {attackVectorData.length === 0 ? (
              <p className="text-center text-sm text-zinc-500 py-8">No probe data yet</p>
            ) : (
              <ChartContainer config={attackBarConfig} className="h-[260px] w-full">
                <BarChart data={attackVectorData} layout="vertical" margin={{ left: 8, right: 8 }}>
                  <CartesianGrid horizontal={false} />
                  <XAxis type="number" tickLine={false} axisLine={false} allowDecimals={false} />
                  <YAxis type="category" dataKey="probe" width={120} tickLine={false} axisLine={false} />
                  <ChartTooltip content={<ChartTooltipContent labelKey="fullProbe" />} />
                  <Bar dataKey="passed" stackId="a" fill="var(--color-passed)" radius={[0, 2, 2, 0]} />
                  <Bar dataKey="failed" stackId="a" fill="var(--color-failed)" radius={[0, 2, 2, 0]} />
                </BarChart>
              </ChartContainer>
            )}
          </CardContent>
        </Card>
        <Card className="border-zinc-200 dark:border-zinc-800">
          <CardHeader className="pb-2">
            <CardTitle className="text-base">Model Risk Comparison</CardTitle>
            <CardDescription>Average risk score per model</CardDescription>
          </CardHeader>
          <CardContent>
            {modelRiskData.length === 0 ? (
              <p className="text-center text-sm text-zinc-500 py-8">No model data yet</p>
            ) : (
              <ChartContainer config={modelBarConfig} className="h-[260px] w-full">
                <BarChart data={modelRiskData} margin={{ left: 8, right: 8 }}>
                  <CartesianGrid vertical={false} />
                  <XAxis dataKey="model" tickLine={false} axisLine={false} tickMargin={8} />
                  <YAxis tickLine={false} axisLine={false} domain={[0, 10]} />
                  <ChartTooltip content={<ChartTooltipContent />} />
                  <Bar dataKey="score" fill="var(--color-score)" radius={[4, 4, 0, 0]} />
                </BarChart>
              </ChartContainer>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Row 4: AI Security Posture | OWASP Top 10 LLM */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Card className="border-zinc-200 dark:border-zinc-800">
          <CardHeader className="pb-2">
            <CardTitle className="text-base">AI Security Posture Overview</CardTitle>
            <CardDescription>Resistance scores across categories</CardDescription>
          </CardHeader>
          <CardContent>
            {radarData.length === 0 ? (
              <p className="text-center text-sm text-zinc-500 py-8">No posture data yet</p>
            ) : (
              <ChartContainer config={radarConfig} className="mx-auto aspect-square max-h-[280px]">
                <RadarChart data={radarData}>
                  <PolarGrid />
                  <PolarAngleAxis dataKey="subject" tick={{ fontSize: 11 }} />
                  <Radar name="Score" dataKey="value" stroke="hsl(217 91% 60%)" fill="hsl(217 91% 60%)" fillOpacity={0.4} />
                  <ChartTooltip content={<ChartTooltipContent />} />
                </RadarChart>
              </ChartContainer>
            )}
          </CardContent>
        </Card>
        <Card className="border-zinc-200 dark:border-zinc-800">
          <CardHeader className="pb-2">
            <CardTitle className="text-base">OWASP Top 10 LLM Metrics</CardTitle>
            <CardDescription>Issues by OWASP LLM category</CardDescription>
          </CardHeader>
          <CardContent>
            <ChartContainer config={{ value: { label: "Issues" } }} className="h-[280px] w-full">
              <BarChart data={owaspData} layout="vertical" margin={{ left: 8, right: 8 }}>
                <CartesianGrid strokeDasharray="3 3" className="stroke-zinc-200 dark:stroke-zinc-700" />
                <XAxis type="number" allowDecimals={false} />
                <YAxis type="category" dataKey="name" width={140} tick={{ fontSize: 10 }} />
                <ChartTooltip content={<ChartTooltipContent nameKey="fullName" formatter={(v) => [v, "Issues"]} />} />
                <Bar dataKey="value" fill="hsl(262 83% 58%)" radius={[0, 2, 2, 0]} />
              </BarChart>
            </ChartContainer>
          </CardContent>
        </Card>
      </div>

      {/* Row 5: Scans per day | Status breakdown */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Card className="border-zinc-200 dark:border-zinc-800">
          <CardHeader className="pb-2">
            <CardTitle className="text-base">Scans Per Day</CardTitle>
            <CardDescription>Number of scans created each day</CardDescription>
          </CardHeader>
          <CardContent>
            {scansPerDayData.length === 0 ? (
              <p className="text-center text-sm text-zinc-500 py-8">No scan activity yet</p>
            ) : (
              <ChartContainer config={barConfig} className="h-[280px] w-full">
                <BarChart data={scansPerDayData}>
                  <CartesianGrid vertical={false} />
                  <XAxis dataKey="date" tickLine={false} axisLine={false} tickMargin={8} tickFormatter={(v) => formatChartDateIst(v)} />
                  <YAxis tickLine={false} axisLine={false} allowDecimals={false} />
                  <ChartTooltip cursor={false} content={<ChartTooltipContent hideLabel />} />
                  <Bar dataKey="scans" fill="var(--color-scans)" radius={[4, 4, 0, 0]} />
                </BarChart>
              </ChartContainer>
            )}
          </CardContent>
        </Card>
        <Card className="border-zinc-200 dark:border-zinc-800">
          <CardHeader className="items-center pb-2">
            <CardTitle className="text-base">Scan Status Breakdown</CardTitle>
            <CardDescription>Distribution of scan outcomes</CardDescription>
          </CardHeader>
          <CardContent>
            {statusData.every((s) => s.count === 0) ? (
              <p className="text-center text-sm text-zinc-500 py-8">No scans yet</p>
            ) : (
              <ChartContainer config={radialConfig} className="mx-auto aspect-square max-h-[280px]">
                <RadialBarChart data={statusData} innerRadius={30} outerRadius={110}>
                  <ChartTooltip cursor={false} content={<ChartTooltipContent nameKey="status" hideLabel />} />
                  <RadialBar dataKey="count" background />
                </RadialBarChart>
              </ChartContainer>
            )}
            <div className="flex flex-wrap items-center justify-center gap-4 mt-3 text-sm text-zinc-600 dark:text-zinc-400">
              <span className="flex items-center gap-1.5"><span className="inline-block h-2.5 w-2.5 rounded-full" style={{ background: "hsl(142 71% 45%)" }} />Success</span>
              <span className="flex items-center gap-1.5"><span className="inline-block h-2.5 w-2.5 rounded-full" style={{ background: "hsl(217 91% 60%)" }} />Started</span>
              <span className="flex items-center gap-1.5"><span className="inline-block h-2.5 w-2.5 rounded-full" style={{ background: "hsl(220 9% 46%)" }} />Pending</span>
              <span className="flex items-center gap-1.5"><span className="inline-block h-2.5 w-2.5 rounded-full" style={{ background: "hsl(0 72% 51%)" }} />Failure</span>
              <span className="flex items-center gap-1.5"><span className="inline-block h-2.5 w-2.5 rounded-full" style={{ background: "hsl(270 50% 60%)" }} />Not Started</span>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}


export default function LLMPage() {
  const router = useRouter();
  const params = useParams();
  const team_id = params?.team_id as string | undefined;
  const [conversations, setConversations] = useState<LLMScanListItem[]>([]);
  const [renameDialogOpen, setRenameDialogOpen] = useState(false);
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false);
  const [createDialogOpen, setCreateDialogOpen] = useState(false);
  const [selectedConversation, setSelectedConversation] = useState<LLMScanListItem | null>(null);
  const [newName, setNewName] = useState("");
  const [newScanTitle, setNewScanTitle] = useState("");
  const [searchQuery, setSearchQuery] = useState("");
  const [statusFilter, setStatusFilter] = useState<string>("all");
  const [riskScoreFilter, setRiskScoreFilter] = useState<RiskScoreFilter>("all");
  const [sortBy, setSortBy] = useState<TableSortBy>("none");
  const queryClient = useQueryClient();

  const query = useQuery({
    queryKey: ['llm-conversations', team_id],
    queryFn: () => getLLMConversations(Number(team_id)),
    enabled: !!team_id,
  });

  useEffect(() => {
    if (query.data?.scans_list_data) {
      setConversations(query.data.scans_list_data);
    }
    if (query.error) {
      showErrorToast(query.error, "Error fetching LLM conversations");
    }
  }, [query.data, query.error]);

  const hasActiveFilters =
    searchQuery !== "" ||
    statusFilter !== "all" ||
    riskScoreFilter !== "all" ||
    sortBy !== "none";

  const filteredConversations = conversations
    .filter((c) => {
      if (searchQuery && !c.title.toLowerCase().includes(searchQuery.toLowerCase())) return false;
      if (statusFilter !== "all" && c.scan_status !== statusFilter) return false;
      const score = getDisplayRiskScore(c);
      if (!matchesRiskScoreFilter(score, riskScoreFilter)) return false;
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
    setSortBy("none");
  };

  const dashboardData = query.data?.dashboard_data;

  const deleteLLMConversationMutation = useMutation({
    mutationFn: ({ team_id, scan_id }: { team_id: number; scan_id: number }) => deleteLLMConversation(team_id, scan_id),
    onSuccess: (_, variables) => {
      queryClient.invalidateQueries({ queryKey: ['llm-conversations', String(variables.team_id)] });
      toast.success('LLM scan deleted successfully');
    },
    onError: (error) => {
      showErrorToast(error);
    }
  });

  const renameLLMConversationMutation = useMutation({
    mutationFn: renameLLMConversation,
    onSuccess: (_, variables) => {
      queryClient.invalidateQueries({ queryKey: ['llm-conversations', String(variables.team_id)] });
      toast.success('LLM scan renamed successfully');
    },
    onError: (error) => {
      showErrorToast(error);
    }
  });

  // One create per click burst (double-click, Enter twice): isPending disables Create only after a re-render.
  const [createGuard] = useState(singleFlight);
  const createLLMConversationMutation = useMutation({
    mutationFn: ({ team_id, title }: { team_id: number; title: string }) => createLLMConversation(team_id, title),
    onSuccess: (scan_id, variables) => {
      queryClient.invalidateQueries({ queryKey: ["llm-conversations", variables.team_id.toString()] });
      setCreateDialogOpen(false);
      setNewScanTitle("");
      router.push(`/${variables.team_id}/llm/${scan_id}`);
    },
    onError: (error) => {
      showErrorToast(error);
    },
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
    const labels = { not_started: "Not Started", pending: "Pending", started: "Started", retry: "Retry", failure: "Failure", success: "Success" };
    return <Badge variant={config.variant} className={config.className}>{labels[status]}</Badge>;
  };

  const handleRename = (conversation: LLMScanListItem) => { setSelectedConversation(conversation); setNewName(conversation.title); setRenameDialogOpen(true); };
  const handleDelete = (conversation: LLMScanListItem) => { setSelectedConversation(conversation); setDeleteDialogOpen(true); };

  const confirmRename = () => {
    if (selectedConversation && newName.trim() && team_id) {
      renameLLMConversationMutation.mutate({ team_id: Number(team_id), conversation_id: selectedConversation.id, title: newName.trim() });
      setRenameDialogOpen(false); setSelectedConversation(null); setNewName("");
    }
  };

  const confirmDelete = () => {
    if (selectedConversation && team_id) {
      deleteLLMConversationMutation.mutate({ team_id: Number(team_id), scan_id: selectedConversation.id });
      setDeleteDialogOpen(false); setSelectedConversation(null);
    }
  };

  const confirmCreate = () => {
    if (newScanTitle.trim() && team_id) {
      if (!createGuard.tryStart()) return;
      createLLMConversationMutation.mutate({ team_id: Number(team_id), title: newScanTitle.trim() }, { onSettled: () => createGuard.done() });
    }
  };

  return (
    <div className="flex h-screen bg-white dark:bg-zinc-900">
      <div className="flex-1 p-8 overflow-auto">
        <div className="max-w-7xl mx-auto">
          {/* Header */}
          <div className="flex items-center justify-between mb-6">
            <div>
              <h1 className="text-3xl font-bold text-zinc-900 dark:text-white mb-2">LLM Scans</h1>
              <p className="text-zinc-600 dark:text-zinc-400">Manage and view all your LLM scans.</p>
            </div>
            <div className="flex flex-row items-center gap-2">
              <Button className="bg-blue-600 hover:bg-blue-700 text-white cursor-pointer" onClick={() => setCreateDialogOpen(true)}>
                <Plus className="h-4 w-4 mr-2" />New Scan
              </Button>
              <Button className="bg-blue-600 hover:bg-blue-700 text-white cursor-pointer" onClick={() => queryClient.invalidateQueries({ queryKey: ['llm-conversations', team_id] })}>
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
            <Tabs defaultValue="dashboard" className="w-full">
              <TabsList className="mb-4 bg-transparent">
                <TabsTrigger value="dashboard" className="cursor-pointer data-[state=active]:bg-blue-600 data-[state=active]:text-white">Dashboard</TabsTrigger>
                <TabsTrigger value="table" className="cursor-pointer data-[state=active]:bg-blue-600 data-[state=active]:text-white">Table</TabsTrigger>
              </TabsList>

              {/* ── Dashboard Tab ── */}
              <TabsContent value="dashboard">
                {dashboardData ? (
                  <ScanListDashboardLLM dashboardData={dashboardData} />
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
                    <p className="text-zinc-600 dark:text-zinc-400 mb-4">No scans yet. Create your first LLM scan to get started.</p>
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
                            <TableHead>Created at</TableHead>
                            <TableHead>Last updated</TableHead>
                            <TableHead>Scan status</TableHead>
                            <TableHead className="w-[180px]">Vulnerabilities</TableHead>
                            <TableHead className="w-[90px]">Risk score</TableHead>
                            <TableHead className="w-[100px]">Model type</TableHead>
                            <TableHead className="w-[140px]">Model name</TableHead>
                            <TableHead className="w-[80px]">Probes</TableHead>
                            <TableHead className="w-[70px]">MITRE</TableHead>
                            <TableHead className="w-[80px]">Credits</TableHead>
                            <TableHead>Owner</TableHead>
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
                                  ? `/${team_id}/llm/${conversation.id}/results`
                                  : `/${team_id}/llm/${conversation.id}`;
                                router.push(dest);
                              }}
                            >
                              <TableCell className="font-medium max-w-[160px] min-w-[120px]">
                                <Link
                                  href={(conversation.scan_status?.toLowerCase() ?? "") === "success" ? `/${team_id}/llm/${conversation.id}/results` : `/${team_id}/llm/${conversation.id}`}
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
                              <TableCell className="text-zinc-600 dark:text-zinc-400">
                                {conversation.model_type ? (
                                  <Badge variant="outline" className="capitalize">{conversation.model_type}</Badge>
                                ) : (
                                  <span className="text-zinc-400 dark:text-zinc-500 italic">—</span>
                                )}
                              </TableCell>
                              <TableCell className="text-zinc-600 dark:text-zinc-400 text-sm max-w-[140px] truncate" title={conversation.model_name ?? undefined}>
                                {conversation.model_name || <span className="text-zinc-400 dark:text-zinc-500 italic">—</span>}
                              </TableCell>
                              <TableCell className="text-zinc-600 dark:text-zinc-400 text-sm tabular-nums">
                                {conversation.total_attacks_performed != null ? conversation.total_attacks_performed : "—"}
                              </TableCell>
                              <TableCell className="text-zinc-600 dark:text-zinc-400 text-sm tabular-nums">
                                {conversation.total_mitre_atlas_tactics != null && conversation.total_mitre_atlas_tactics > 0 ? conversation.total_mitre_atlas_tactics : "—"}
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
                                      <DropdownMenuItem className="cursor-pointer" onClick={() => router.push(`/${team_id}/llm/${conversation.id}/results?origin=list`)}>
                                        <Eye className="h-4 w-4 mr-2" />View Results
                                      </DropdownMenuItem>
                                    )}
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
          <div className="py-4">
            <Input value={newName} onChange={(e) => setNewName(e.target.value)} placeholder="Scan name" onKeyDown={(e) => { if (e.key === "Enter") confirmRename(); }} />
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

      {/* Create Scan Dialog */}
      <Dialog open={createDialogOpen} onOpenChange={setCreateDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Create New Scan</DialogTitle>
            <DialogDescription>Enter a title for your new LLM scan.</DialogDescription>
          </DialogHeader>
          <div className="py-4">
            <Input value={newScanTitle} onChange={(e) => setNewScanTitle(e.target.value)} placeholder="Scan title" onKeyDown={(e) => { if (e.key === "Enter") confirmCreate(); }} />
          </div>
          <DialogFooter>
            <Button variant="outline" className="cursor-pointer" onClick={() => { setCreateDialogOpen(false); setNewScanTitle(""); }}>Cancel</Button>
            <Button onClick={confirmCreate} disabled={!newScanTitle.trim() || !team_id || createLLMConversationMutation.isPending} className="bg-blue-600 hover:bg-blue-700 text-white cursor-pointer">
              {createLLMConversationMutation.isPending ? "Creating..." : "Create"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
