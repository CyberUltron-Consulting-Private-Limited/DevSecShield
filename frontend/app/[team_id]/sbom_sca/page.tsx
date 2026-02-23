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
import { Plus, MoreVertical, Pencil, Trash2, RefreshCcw, Loader2, Eye, Clock, CheckCircle, CalendarPlus, CalendarCheck, Search, X, GitBranch, FileArchive, MinusCircle, Shield, AlertTriangle, Activity, BookOpen, Crosshair, ChevronDown, ArrowUpDown, Check, Filter, DollarSign, TrendingUp, TrendingDown } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import {
  deleteSBOMSCAScan,
  getSBOMSCAScans,
  renameSBOMSCAScan,
  createSBOMSCAScan,
} from "@/utils/backend_api";
import type { SCASBOMConversation } from "@/utils/backend_api";
import type { SBOMSCADashboardData } from "@/utils/backend_api";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { showErrorToast } from "@/utils/error-handler";
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
  PolarAngleAxis,
  PolarGrid,
  Radar,
  RadarChart,
  XAxis,
  YAxis,
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

function getDisplayRiskScore(c: SCASBOMConversation): number | null {
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

function SBOMSCAScanListDashboard({ dashboardData }: { dashboardData: SBOMSCADashboardData }) {
  const card = dashboardData.card_data;
  const remediation = dashboardData.remediation_actions_required;
  const totalFindings = remediation.total_findings || 1;

  // Section 2: Severity distribution for radar
  const severityRadarData = useMemo(() => [
    { severity: "Critical", count: dashboardData.severity_distribution.critical },
    { severity: "High", count: dashboardData.severity_distribution.high },
    { severity: "Medium", count: dashboardData.severity_distribution.medium },
    { severity: "Low", count: dashboardData.severity_distribution.low },
  ], [dashboardData.severity_distribution]);

  const radarConfig = { count: { label: "Findings", color: "hsl(220 70% 50%)" } } satisfies ChartConfig;

  // Section 3: Reachability distribution for bar chart
  const reachabilityBarData = useMemo(() => [
    { name: "Reachable", count: dashboardData.reachability_distribution.reachable, fill: "hsl(142 71% 45%)" },
    { name: "Potentially Reachable", count: dashboardData.reachability_distribution.potentially_reachable, fill: "hsl(45 93% 47%)" },
    { name: "Not Reachable", count: dashboardData.reachability_distribution.not_reachable, fill: "hsl(25 95% 53%)" },
    { name: "Unknown", count: dashboardData.reachability_distribution.unknown, fill: "hsl(220 9% 46%)" },
  ].filter((r) => r.count > 0), [dashboardData.reachability_distribution]);

  const barConfig = { count: { label: "Issues", color: "hsl(220 70% 50%)" } } satisfies ChartConfig;

  // Section 4: Vulnerability trends over time (area chart)
  const vulnerabilityTrendsData = useMemo(() => {
    return Object.entries(dashboardData.vulnerability_trends_over_time)
      .map(([date, v]) => ({ date, ...v }))
      .sort((a, b) => a.date.localeCompare(b.date));
  }, [dashboardData.vulnerability_trends_over_time]);

  const areaConfig = {
    critical: { label: "Critical", color: "hsl(0 72% 51%)" },
    high: { label: "High", color: "hsl(25 95% 53%)" },
    medium: { label: "Medium", color: "hsl(45 93% 47%)" },
    low: { label: "Low", color: "hsl(217 91% 60%)" },
  } satisfies ChartConfig;

  // Section 5: Licenses distribution - all categories with default 0
  const LICENSE_CATEGORIES = ["permissive", "public_domain", "weak_copyleft", "creative_commons", "commercial", "strong_copyleft", "network_copyleft", "source_available", "unknown"] as const;
  const licenseLabels: Record<string, string> = {
    permissive: "Permissive",
    public_domain: "Public Domain",
    weak_copyleft: "Weak Copyleft",
    creative_commons: "Creative Commons",
    commercial: "Commercial",
    strong_copyleft: "Strong Copyleft",
    network_copyleft: "Network Copyleft",
    source_available: "Source Available",
    unknown: "Unknown",
  };
  const licensesTotal = useMemo(() => {
    const sum = LICENSE_CATEGORIES.reduce((a, k) => a + (dashboardData.licenses_distribution[k] ?? 0), 0);
    return sum || 1;
  }, [dashboardData.licenses_distribution]);

  // Section 8: Average risk score per reachability (radar) — R1, R2, R3, R4 with legend
  const reachabilityRadarData = useMemo(() => {
    const levels = [
      "Reachable",
      "Potentially Reachable",
      "Not Reachable",
      "Unknown",
    ] as const;
    const keys = ["reachable", "potentially_reachable", "not_reachable", "unknown"] as const;
    const scores = dashboardData.average_risk_score_per_reachability_level;
    return levels.map((level, i) => ({
      xLabel: `R${i + 1}`,
      level,
      score: scores[keys[i]] ?? 0,
    }));
  }, [dashboardData.average_risk_score_per_reachability_level]);

  const reachabilityRadarConfig = { score: { label: "Avg Risk", color: "hsl(217 91% 60%)" } } satisfies ChartConfig;

  const policyTotal = useMemo(() => {
    const vals = Object.values(dashboardData.policy_compliance_data);
    return vals.reduce((a, b) => a + b, 0) || 1;
  }, [dashboardData.policy_compliance_data]);

  return (
    <div className="space-y-6">
      {/* Section 7: Card Data - 7 summary stat cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-7 gap-4">
        <Card className="border-zinc-200 dark:border-zinc-800 py-3 px-3">
          <CardContent className="p-0">
            <div className="flex flex-col items-start gap-2">
              <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-amber-500/15 dark:bg-amber-500/10">
                <AlertTriangle className="h-4 w-4 text-amber-500" />
              </div>
              <div>
                <p className="text-xs font-medium text-zinc-600 dark:text-zinc-400">Total Vulnerabilities</p>
                <p className="text-xl font-bold text-zinc-900 dark:text-white">{card.total_vulnerabilities}</p>
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
                <p className="text-xs font-medium text-zinc-600 dark:text-zinc-400">Critical Vulnerabilities</p>
                <p className="text-xl font-bold text-zinc-900 dark:text-white">{card.total_critical_vulnerabilities}</p>
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
                <p className="text-xs font-medium text-zinc-600 dark:text-zinc-400">Policy Violations</p>
                <p className="text-xl font-bold text-zinc-900 dark:text-white">{card.total_policy_violations}</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card className="border-zinc-200 dark:border-zinc-800 py-3 px-3">
          <CardContent className="p-0">
            <div className="flex flex-col items-start gap-2">
              <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-amber-500/15 dark:bg-amber-500/10">
                <BookOpen className="h-4 w-4 text-amber-500" />
              </div>
              <div>
                <p className="text-xs font-medium text-zinc-600 dark:text-zinc-400">License Risks</p>
                <p className="text-xl font-bold text-zinc-900 dark:text-white">{card.total_license_risks}</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card className="border-zinc-200 dark:border-zinc-800 py-3 px-3">
          <CardContent className="p-0">
            <div className="flex flex-col items-start gap-2">
              <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-red-500/15 dark:bg-red-500/10">
                <BookOpen className="h-4 w-4 text-red-500" />
              </div>
              <div>
                <p className="text-xs font-medium text-zinc-600 dark:text-zinc-400">High Risk Licenses</p>
                <p className="text-xl font-bold text-zinc-900 dark:text-white">{card.total_high_risk_licenses}</p>
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
                <p className="text-xs font-medium text-zinc-600 dark:text-zinc-400">Avg Risk Score</p>
                <p className="text-xl font-bold text-zinc-900 dark:text-white">{card.average_risk_score.toFixed(1)}</p>
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
                <p className="text-xs font-medium text-zinc-600 dark:text-zinc-400">Reachable Issues</p>
                <p className="text-xl font-bold text-zinc-900 dark:text-white">{card.total_reachable_issues}</p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Section 1: Remediation Actions Required */}
      <Card className="border-zinc-200 dark:border-zinc-800">
        <CardHeader className="pb-2">
          <CardTitle className="text-base">Remediation Actions Required</CardTitle>
          <CardDescription>Finding status breakdown (total: {remediation.total_findings})</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <div className="flex items-center justify-between text-sm">
              <span className="flex items-center gap-2"><CheckCircle className="h-4 w-4 text-green-500" />Fixed</span>
              <span className="text-zinc-600 dark:text-zinc-400">{remediation.total_fixed}</span>
            </div>
            <Progress value={(remediation.total_fixed / totalFindings) * 100} className="h-2" />
          </div>
          <div className="space-y-2">
            <div className="flex items-center justify-between text-sm">
              <span className="flex items-center gap-2"><Loader2 className="h-4 w-4 text-blue-500" />In Progress</span>
              <span className="text-zinc-600 dark:text-zinc-400">{remediation.total_in_progress}</span>
            </div>
            <Progress value={(remediation.total_in_progress / totalFindings) * 100} className="h-2" />
          </div>
          <div className="space-y-2">
            <div className="flex items-center justify-between text-sm">
              <span className="flex items-center gap-2"><Clock className="h-4 w-4 text-amber-500" />Not Started</span>
              <span className="text-zinc-600 dark:text-zinc-400">{remediation.total_not_started}</span>
            </div>
            <Progress value={(remediation.total_not_started / totalFindings) * 100} className="h-2" />
          </div>
          <div className="space-y-2">
            <div className="flex items-center justify-between text-sm">
              <span className="flex items-center gap-2"><MinusCircle className="h-4 w-4 text-zinc-400" />Ignored</span>
              <span className="text-zinc-600 dark:text-zinc-400">{remediation.total_ignored}</span>
            </div>
            <Progress value={(remediation.total_ignored / totalFindings) * 100} className="h-2" />
          </div>
        </CardContent>
      </Card>

      {/* Sections 2–4: Severity radar, Reachability bar, Vulnerability trends */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <Card className="border-zinc-200 dark:border-zinc-800">
          <CardHeader className="items-center pb-2">
            <CardTitle className="text-base">Severity Distribution</CardTitle>
            <CardDescription>Critical / High / Medium / Low</CardDescription>
          </CardHeader>
          <CardContent>
            {severityRadarData.every((r) => r.count === 0) ? (
              <p className="text-center text-sm text-zinc-500 py-8">No vulnerability data yet</p>
            ) : (
              <ChartContainer config={radarConfig} className="mx-auto aspect-square max-h-[280px]">
                <RadarChart data={severityRadarData}>
                  <ChartTooltip cursor={false} content={<ChartTooltipContent />} />
                  <PolarAngleAxis dataKey="severity" />
                  <PolarGrid />
                  <Radar dataKey="count" fill="var(--color-count)" fillOpacity={0.6} dot={{ r: 4, fillOpacity: 1 }} />
                </RadarChart>
              </ChartContainer>
            )}
          </CardContent>
        </Card>

        <Card className="border-zinc-200 dark:border-zinc-800">
          <CardHeader className="pb-2">
            <CardTitle className="text-base">Reachability Distribution</CardTitle>
            <CardDescription>Issues by reachability status</CardDescription>
          </CardHeader>
          <CardContent>
            {reachabilityBarData.length === 0 ? (
              <p className="text-center text-sm text-zinc-500 py-8">No reachability data yet</p>
            ) : (
              <ChartContainer config={barConfig} className="h-[280px] w-full">
                <BarChart data={reachabilityBarData} layout="vertical" margin={{ left: 20, right: 20 }}>
                  <CartesianGrid horizontal={true} vertical={false} />
                  <XAxis type="number" tickLine={false} axisLine={false} allowDecimals={false} />
                  <YAxis type="category" dataKey="name" tickLine={false} axisLine={false} width={140} />
                  <ChartTooltip cursor={false} content={<ChartTooltipContent />} />
                  <Bar dataKey="count" radius={[0, 4, 4, 0]}>
                    {reachabilityBarData.map((entry, i) => (
                      <Cell key={i} fill={entry.fill} />
                    ))}
                  </Bar>
                </BarChart>
              </ChartContainer>
            )}
          </CardContent>
        </Card>

        <Card className="border-zinc-200 dark:border-zinc-800">
          <CardHeader className="pb-2">
            <CardTitle className="text-base">Vulnerability Trends Over Time</CardTitle>
            <CardDescription>By scan date</CardDescription>
          </CardHeader>
          <CardContent>
            {vulnerabilityTrendsData.length === 0 ? (
              <p className="text-center text-sm text-zinc-500 py-8">No trend data yet</p>
            ) : (
              <ChartContainer config={areaConfig} className="h-[280px] w-full">
                <AreaChart data={vulnerabilityTrendsData}>
                  <CartesianGrid vertical={false} />
                  <XAxis dataKey="date" tickLine={false} axisLine={false} tickMargin={8} tickFormatter={(v) => new Date(v).toLocaleDateString("en-US", { month: "short", day: "numeric" })} />
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

      {/* Section 5: Licenses Distribution | Section 6: Top Vulnerabilities | Section 8: Avg Risk per Reachability */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <Card className="border-zinc-200 dark:border-zinc-800">
          <CardHeader className="pb-2">
            <CardTitle className="text-base">Licenses Distribution</CardTitle>
            <CardDescription>By license type</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            {LICENSE_CATEGORIES.map((key) => {
              const value = dashboardData.licenses_distribution[key] ?? 0;
              return (
                <div key={key} className="space-y-1.5">
                  <div className="flex items-center justify-between text-sm">
                    <span className="text-zinc-700 dark:text-zinc-300">{licenseLabels[key] ?? key}</span>
                    <span className="text-zinc-600 dark:text-zinc-400">{value}</span>
                  </div>
                  <Progress value={(value / licensesTotal) * 100} className="h-1.5" />
                </div>
              );
            })}
          </CardContent>
        </Card>

        <Card className="border-zinc-200 dark:border-zinc-800 flex flex-col">
          <CardHeader className="pb-2">
            <CardTitle className="text-base">Top Vulnerabilities by Risk Score</CardTitle>
            <CardDescription>Sorted by impact</CardDescription>
          </CardHeader>
          <CardContent className="flex-1 min-h-0">
            {dashboardData.top_vulnerabilities_by_risk_score.length === 0 ? (
              <p className="text-center text-sm text-zinc-500 py-8">No vulnerability data yet</p>
            ) : (
              <ScrollArea className="h-[240px] pr-3">
                <ul className="space-y-2">
                  {dashboardData.top_vulnerabilities_by_risk_score.slice(0, 20).map((item, i) => (
                    <li key={i} className="text-sm border-b border-zinc-100 dark:border-zinc-800 pb-2 last:border-0">
                      <div className="font-medium text-zinc-900 dark:text-white truncate" title={item.dependency}>{item.dependency}</div>
                      <div className="flex flex-wrap gap-x-3 gap-y-0.5 text-xs text-zinc-500 dark:text-zinc-400 mt-0.5">
                        <span>{item.reachability}</span>
                        <span>{item.dependency_type}</span>
                        <span>{item.license_type}</span>
                        <Badge variant={item.impact?.toLowerCase() === "critical" || item.impact?.toLowerCase() === "high" ? "destructive" : "secondary"} className="text-xs">{item.impact}</Badge>
                      </div>
                    </li>
                  ))}
                </ul>
              </ScrollArea>
            )}
          </CardContent>
        </Card>

        <Card className="border-zinc-200 dark:border-zinc-800">
          <CardHeader className="items-center pb-2">
            <CardTitle className="text-base">Average Risk Score per Reachability</CardTitle>
            <CardDescription>Weighted by impact</CardDescription>
          </CardHeader>
          <CardContent>
            {reachabilityRadarData.every((r) => r.score === 0) ? (
              <p className="text-center text-sm text-zinc-500 py-8">No data yet</p>
            ) : (
              <>
                <ChartContainer config={reachabilityRadarConfig} className="mx-auto aspect-square max-h-[280px]">
                  <RadarChart data={reachabilityRadarData}>
                    <ChartTooltip
                      cursor={false}
                      content={
                        <ChartTooltipContent
                          labelFormatter={(_, payload) => (payload?.[0]?.payload as { level?: string })?.level ?? "—"}
                          formatter={(value) => [value, "Avg Risk"]}
                        />
                      }
                    />
                    <PolarAngleAxis dataKey="xLabel" />
                    <PolarGrid />
                    <Radar dataKey="score" fill="var(--color-score)" fillOpacity={0.6} dot={{ r: 4, fillOpacity: 1 }} />
                  </RadarChart>
                </ChartContainer>
                <div className="mt-4 pt-3 border-t border-zinc-200 dark:border-zinc-700 flex flex-wrap gap-x-6 gap-y-2 justify-center text-xs text-zinc-600 dark:text-zinc-400">
                  {reachabilityRadarData.map(({ xLabel, level }) => (
                    <span key={xLabel}>
                      <span className="font-medium text-zinc-800 dark:text-zinc-200">{xLabel}</span>
                      <span className="mx-1.5">=</span>
                      <span>{level}</span>
                    </span>
                  ))}
                </div>
              </>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Section 9: Policy Compliance Data */}
      <Card className="border-zinc-200 dark:border-zinc-800 overflow-hidden">
        <CardHeader className="pb-2">
          <CardTitle className="text-base flex items-center gap-2">
            <div className="rounded-lg bg-violet-500/10 p-1.5">
              <Shield className="h-4 w-4 text-violet-600 dark:text-violet-400" />
            </div>
            Policy Compliance Data
          </CardTitle>
          <CardDescription>Issues by compliance standard</CardDescription>
        </CardHeader>
        <CardContent>
          {policyTotal === 0 ? (
            <p className="text-center text-sm text-zinc-500 py-8">No policy compliance data yet</p>
          ) : (
            <ScrollArea className="w-full">
              <div className="flex gap-4 pb-2 min-w-max">
                {Object.entries(dashboardData.policy_compliance_data).map(([name, count], index) => {
                  const policyColors = [
                    { border: "border-l-blue-500", bg: "bg-blue-500/8", icon: "text-blue-600 dark:text-blue-400", bar: "bg-blue-500", accent: "text-blue-700 dark:text-blue-300" },
                    { border: "border-l-emerald-500", bg: "bg-emerald-500/8", icon: "text-emerald-600 dark:text-emerald-400", bar: "bg-emerald-500", accent: "text-emerald-700 dark:text-emerald-300" },
                    { border: "border-l-violet-500", bg: "bg-violet-500/8", icon: "text-violet-600 dark:text-violet-400", bar: "bg-violet-500", accent: "text-violet-700 dark:text-violet-300" },
                    { border: "border-l-amber-500", bg: "bg-amber-500/8", icon: "text-amber-600 dark:text-amber-400", bar: "bg-amber-500", accent: "text-amber-700 dark:text-amber-300" },
                    { border: "border-l-rose-500", bg: "bg-rose-500/8", icon: "text-rose-600 dark:text-rose-400", bar: "bg-rose-500", accent: "text-rose-700 dark:text-rose-300" },
                    { border: "border-l-cyan-500", bg: "bg-cyan-500/8", icon: "text-cyan-600 dark:text-cyan-400", bar: "bg-cyan-500", accent: "text-cyan-700 dark:text-cyan-300" },
                  ];
                  const c = policyColors[index % policyColors.length];
                  const pct = policyTotal > 0 ? (count / policyTotal) * 100 : 0;
                  return (
                    <div
                      key={name}
                      className={`shrink-0 w-[220px] rounded-xl border border-zinc-200 dark:border-zinc-700 dark:bg-zinc-800/30 bg-zinc-50/80 pl-4 border-l-4 ${c.border} ${c.bg} p-4 transition-shadow hover:shadow-md`}
                    >
                      <div className="flex items-start justify-between gap-2 mb-3">
                        <div className="flex items-center gap-2 min-w-0">
                          <BookOpen className={`h-4 w-4 shrink-0 ${c.icon}`} />
                          <span className={`font-semibold text-sm truncate ${c.accent}`} title={name}>
                            {name}
                          </span>
                        </div>
                        <Badge variant="secondary" className={`shrink-0 font-mono tabular-nums ${c.accent} border-0 bg-white/60 dark:bg-zinc-700/60`}>
                          {count}
                        </Badge>
                      </div>
                      <div className="h-2 w-full rounded-full bg-zinc-200 dark:bg-zinc-700 overflow-hidden">
                        <div
                          className={`h-full rounded-full ${c.bar} transition-all duration-500 ease-out`}
                          style={{ width: `${Math.min(100, pct)}%` }}
                        />
                      </div>
                      <p className="text-[11px] text-zinc-500 dark:text-zinc-400 mt-1.5 font-medium">
                        {pct.toFixed(1)}% of total
                      </p>
                    </div>
                  );
                })}
              </div>
              <ScrollBar orientation="horizontal" />
            </ScrollArea>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

// ─── Main Page ──────────────────────────────────────────────────────────────────

export default function SBOMSCAPage() {
  const router = useRouter();
  const params = useParams();
  const team_id = params?.team_id as string;
  const [conversations, setConversations] = useState<SCASBOMConversation[]>([]);
  const [renameDialogOpen, setRenameDialogOpen] = useState(false);
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false);
  const [createDialogOpen, setCreateDialogOpen] = useState(false);
  const [selectedConversation, setSelectedConversation] = useState<SCASBOMConversation | null>(null);
  const [metadataDialogOpen, setMetadataDialogOpen] = useState(false);
  const [metadataScan, setMetadataScan] = useState<SCASBOMConversation | null>(null);
  const [newName, setNewName] = useState("");
  const [newScanTitle, setNewScanTitle] = useState("");
  const [searchQuery, setSearchQuery] = useState("");
  const [statusFilter, setStatusFilter] = useState<string>("all");
  const [riskScoreFilter, setRiskScoreFilter] = useState<RiskScoreFilter>("all");
  const [sortBy, setSortBy] = useState<TableSortBy>("none");
  const queryClient = useQueryClient();

  const query = useQuery({
    queryKey: ["sbom_sca-conversations", team_id],
    queryFn: () => getSBOMSCAScans(parseInt(team_id)),
    enabled: !!team_id,
  });

  useEffect(() => {
    if (query.data) {
      setConversations(query.data.scans_list_data ?? []);
    }
    if (query.error) {
      showErrorToast(query.error, "Error fetching SCA + SBOM scans");
    }
  }, [query.data, query.error]);

  const deleteSBOMSCAScanMutation = useMutation({
    mutationFn: ({ team_id, scan_id }: { team_id: number; scan_id: number }) => deleteSBOMSCAScan(team_id, scan_id),
    onSuccess: (data, variables) => {
      queryClient.invalidateQueries({ queryKey: ["sbom_sca-conversations", variables.team_id.toString()] });
      toast.success("SCA + SBOM scan deleted successfully");
    },
    onError: (error) => { showErrorToast(error); },
  });

  const renameSBOMSCAScanMutation = useMutation({
    mutationFn: renameSBOMSCAScan,
    onSuccess: (data, variables) => {
      queryClient.invalidateQueries({ queryKey: ["sbom_sca-conversations", variables.team_id.toString()] });
      toast.success("SCA + SBOM scan renamed successfully");
    },
    onError: (error) => { showErrorToast(error); },
  });

  const createSBOMSCAScanMutation = useMutation({
    mutationFn: ({ team_id, title }: { team_id: number; title: string }) => createSBOMSCAScan(team_id, title),
    onSuccess: (scan_id, variables) => {
      queryClient.invalidateQueries({ queryKey: ["sbom_sca-conversations", variables.team_id.toString()] });
      setCreateDialogOpen(false);
      setNewScanTitle("");
      router.push(`/${variables.team_id}/sbom_sca/${scan_id}`);
    },
    onError: (error) => { showErrorToast(error); },
  });

  const formatDate = (dateString: string) => {
    const date = new Date(dateString);
    return date.toLocaleDateString("en-US", { year: "numeric", month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
  };

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

  const handleRename = (conversation: SCASBOMConversation) => { setSelectedConversation(conversation); setNewName(conversation.title); setRenameDialogOpen(true); };
  const handleDelete = (conversation: SCASBOMConversation) => { setSelectedConversation(conversation); setDeleteDialogOpen(true); };

  const confirmRename = () => {
    if (selectedConversation && newName.trim() && team_id) {
      renameSBOMSCAScanMutation.mutate({ team_id: parseInt(team_id), scan_id: selectedConversation.id, title: newName.trim() });
      setRenameDialogOpen(false); setSelectedConversation(null); setNewName("");
    }
  };

  const confirmDelete = () => {
    if (selectedConversation && team_id) {
      deleteSBOMSCAScanMutation.mutate({ team_id: parseInt(team_id), scan_id: selectedConversation.id });
      setDeleteDialogOpen(false); setSelectedConversation(null);
    }
  };

  const confirmCreate = () => {
    if (newScanTitle.trim() && team_id) {
      createSBOMSCAScanMutation.mutate({ team_id: parseInt(team_id), title: newScanTitle.trim() });
    }
  };

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

  return (
    <div className="flex h-screen bg-white dark:bg-zinc-900">
      <div className="flex-1 p-8 overflow-auto">
        <div className="max-w-7xl mx-auto">
          {/* Header */}
          <div className="flex items-center justify-between mb-6">
            <div>
              <h1 className="text-3xl font-bold text-zinc-900 dark:text-white mb-2">SCA + SBOM Scans</h1>
              <p className="text-zinc-600 dark:text-zinc-400">Manage and view all your SCA + SBOM scan conversations.</p>
            </div>
            <div className="flex flex-row items-center gap-2">
              <Button className="bg-blue-600 hover:bg-blue-700 text-white cursor-pointer" onClick={() => setCreateDialogOpen(true)}>
                <Plus className="h-4 w-4 mr-2" />New Scan
              </Button>
              <Button className="bg-blue-600 hover:bg-blue-700 text-white cursor-pointer" onClick={() => queryClient.invalidateQueries({ queryKey: ["sbom_sca-conversations", team_id] })}>
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
              <p className="text-zinc-600 dark:text-zinc-400 mb-4">Error in fetching scans, please try again later</p>
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
                  <SBOMSCAScanListDashboard dashboardData={dashboardData} />
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
                    <p className="text-zinc-600 dark:text-zinc-400 mb-4">No scans yet. Create your first SCA + SBOM scan to get started.</p>
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
                            <TableHead className="w-[160px]">Repo / Source</TableHead>
                            <TableHead className="w-[100px]">Branch</TableHead>
                            <TableHead className="w-[90px]">Credits</TableHead>
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
                                  ? `/${team_id}/sbom_sca/${conversation.id}/results`
                                  : `/${team_id}/sbom_sca/${conversation.id}`;
                                router.push(dest);
                              }}
                            >
                              <TableCell className="font-medium max-w-[160px] min-w-[120px]">
                                <Link
                                  href={(conversation.scan_status?.toLowerCase() ?? "") === "success" ? `/${team_id}/sbom_sca/${conversation.id}/results` : `/${team_id}/sbom_sca/${conversation.id}`}
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
                              <TableCell className="text-zinc-600 dark:text-zinc-400 text-sm tabular-nums">
                                {conversation.estimated_credits != null ? conversation.estimated_credits : "—"}
                              </TableCell>
                              <TableCell className="text-zinc-600 dark:text-zinc-400">
                                {(conversation.owner_user_full_name != null && conversation.owner_user_full_name !== "") || conversation.owner_user_email ? (
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
                                    <Button variant="ghost" size="icon" className="h-8 w-8 cursor-pointer"><MoreVertical className="h-4 w-4" /></Button>
                                  </DropdownMenuTrigger>
                                  <DropdownMenuContent align="end">
                                    {(conversation.scan_status?.toLowerCase() ?? "") === "success" && (
                                      <DropdownMenuItem className="cursor-pointer" onClick={() => router.push(`/${team_id}/sbom_sca/${conversation.id}/results?origin=list`)}>
                                        <Eye className="h-4 w-4 mr-2" />View Results
                                      </DropdownMenuItem>
                                    )}
                                    <DropdownMenuItem className="cursor-pointer" onClick={(e) => { e.stopPropagation(); setMetadataScan(conversation); setMetadataDialogOpen(true); }}>
                                      <Eye className="h-4 w-4 mr-2" />View metadata
                                    </DropdownMenuItem>
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
            <DialogDescription>Enter a new name for this conversation.</DialogDescription>
          </DialogHeader>
          <div className="py-4">
            <Input value={newName} onChange={(e) => setNewName(e.target.value)} placeholder="Conversation name" onKeyDown={(e) => { if (e.key === "Enter") confirmRename(); }} />
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
            <DialogTitle>Delete Conversation</DialogTitle>
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
            <DialogDescription>Enter a title for your new SCA + SBOM scan conversation.</DialogDescription>
          </DialogHeader>
          <div className="py-4">
            <Input value={newScanTitle} onChange={(e) => setNewScanTitle(e.target.value)} placeholder="Scan title" onKeyDown={(e) => { if (e.key === "Enter") confirmCreate(); }} />
          </div>
          <DialogFooter>
            <Button variant="outline" className="cursor-pointer" onClick={() => { setCreateDialogOpen(false); setNewScanTitle(""); }}>Cancel</Button>
            <Button onClick={confirmCreate} disabled={!newScanTitle.trim() || createSBOMSCAScanMutation.isPending} className="bg-blue-600 hover:bg-blue-700 text-white cursor-pointer">
              {createSBOMSCAScanMutation.isPending ? "Creating..." : "Create"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
