"use client";

import { useState, useEffect, useMemo } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  AlertTriangle,
  ArrowLeft,
  MessageCircle,
  Download,
  Ticket,
  Pencil,
  CheckCircle,
  EyeOff,
  Loader2,
  Circle,
  Github,
  GitBranch,
  Archive,
  Shield,
  AlertCircle,
  Scale,
  Package,
  Target,
  Activity,
  XCircle,
  HelpCircle,
} from "lucide-react";
import { ScrollArea, ScrollBar } from "@/components/ui/scroll-area";
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
import { Progress } from "@/components/ui/progress";
import { useRouter, useSearchParams, useParams } from "next/navigation";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { getSBOMExportResults, updateScan, createTicket, toggleFindingState, type SbomScanDashboardData, type SbomFinding, type SbomScanMetadata, type ScanTicketingIntegrationSettings } from "@/utils/backend_api";
import { showErrorToast } from "@/utils/error-handler";
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
  Cell,
  PolarAngleAxis,
  PolarGrid,
  Radar,
  RadarChart,
  XAxis,
  YAxis,
} from "recharts";
import { BarChart3, TrendingUp, Search, Filter, Check, X, ChevronDown } from "lucide-react";
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
  dashboard?: SbomScanDashboardData | null;
  findings?: SbomFinding[] | null;
  scanMetadata?: SbomScanMetadata | Record<string, unknown> | null;
  integrationSettings?: Record<string, unknown> | null;
  onIntegrationSettingsUpdated?: () => void;
  onFindingsUpdated?: () => void;
}

function getImpactBadgeClass(impact: string): string {
  const i = (impact || "").toLowerCase();
  if (i === "critical") return "bg-red-600 hover:bg-red-700 text-white";
  if (i === "high") return "bg-orange-500 hover:bg-orange-600 text-white";
  if (i === "medium") return "bg-amber-500 hover:bg-amber-600 text-white";
  if (i === "low") return "bg-blue-500 hover:bg-blue-600 text-white";
  return "bg-zinc-500 hover:bg-zinc-600 text-white";
}

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
  if (typeof val === "object") return Object.keys(val).length;
  return 0;
}

const RISK_ORDER = ["Critical", "High", "Medium", "Low"] as const;
const SEVERITY_KEYS = ["critical", "high", "medium", "low"] as const;
const REACHABILITY_KEYS = ["reachable", "potentially_reachable", "not_reachable", "unknown"] as const;

/** Reachability level → icon, label, box color for dashboard and table */
const REACHABILITY_DISPLAY: Record<string, { icon: typeof CheckCircle; label: string; boxClass: string }> = {
  reachable: { icon: CheckCircle, label: "Reachable", boxClass: "bg-emerald-100 text-emerald-800 dark:bg-emerald-900/40 dark:text-emerald-200" },
  potentially_reachable: { icon: AlertCircle, label: "Potentially reachable", boxClass: "bg-amber-100 text-amber-800 dark:bg-amber-900/40 dark:text-amber-200" },
  not_reachable: { icon: XCircle, label: "Not reachable", boxClass: "bg-red-100 text-red-800 dark:bg-red-900/40 dark:text-red-200" },
  unknown: { icon: HelpCircle, label: "Unknown", boxClass: "bg-zinc-100 text-zinc-700 dark:bg-zinc-700/50 dark:text-zinc-200" },
};

function getReachabilityBoxClass(reachability: string | null | undefined): string {
  const key = (reachability ?? "unknown").toLowerCase().replace(/\s/g, "_");
  return REACHABILITY_DISPLAY[key]?.boxClass ?? REACHABILITY_DISPLAY.unknown.boxClass;
}

function getRiskScoreBoxClass(score: number | null | undefined): string {
  const s = score ?? 0;
  if (s >= 4) return "bg-red-100 text-red-800 dark:bg-red-900/40 dark:text-red-200";
  if (s >= 3) return "bg-orange-100 text-orange-800 dark:bg-orange-900/40 dark:text-orange-200";
  if (s >= 2) return "bg-amber-100 text-amber-800 dark:bg-amber-900/40 dark:text-amber-200";
  return "bg-emerald-100 text-emerald-800 dark:bg-emerald-900/40 dark:text-emerald-200";
}

const LICENSE_CHART_COLORS = ["hsl(142 71% 45%)", "hsl(217 91% 60%)", "hsl(48 96% 53%)", "hsl(25 95% 53%)", "hsl(0 84% 60%)"];
const LICENSE_CATEGORIES = ["permissive", "public_domain", "weak_copyleft", "creative_commons", "commercial", "strong_copyleft", "network_copyleft", "source_available", "unknown"] as const;
const LICENSE_LABELS: Record<string, string> = {
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

const riskRadarChartConfig = {
  subject: { label: "Severity" },
  count: { label: "Count", color: "hsl(0 84% 60%)" },
} satisfies ChartConfig;

const reachabilityBarChartConfig = {
  name: { label: "Reachability" },
  count: { label: "Count", color: "hsl(217 91% 60%)" },
} satisfies ChartConfig;

const trendsChartConfig = {
  date: { label: "Date" },
  critical: { label: "Critical", color: "hsl(0 84% 60%)" },
  high: { label: "High", color: "hsl(25 95% 53%)" },
  medium: { label: "Medium", color: "hsl(48 96% 53%)" },
  low: { label: "Low", color: "hsl(142 71% 45%)" },
} satisfies ChartConfig;

function SbomDashboardCharts({ dashboard }: { dashboard: SbomScanDashboardData }) {
  const card = dashboard.card_data ?? {};
  const remediation = dashboard.remediation_actions_required ?? {};
  const severity = dashboard.severity_distribution ?? {};
  const reachability = dashboard.reachability_distribution ?? {};
  const trends = dashboard.vulnerability_trends_over_time ?? {};
  const licenses = dashboard.licenses_distribution ?? {};
  const topVulns = dashboard.top_vulnerabilities_by_risk_score ?? [];
  const avgRiskByReach = dashboard.average_risk_score_per_reachability ?? {};

  const severityRadarData = RISK_ORDER.map((label) => ({
    subject: label,
    count: severity[label.toLowerCase() as keyof typeof severity] ?? 0,
  }));
  const hasSeverityData = severityRadarData.some((d) => d.count > 0);

  const reachabilityBarData = REACHABILITY_KEYS.map((key) => ({
    name: key.replace(/_/g, " "),
    count: reachability[key as keyof typeof reachability] ?? 0,
  }));
  const hasReachabilityData = reachabilityBarData.some((d) => d.count > 0);

  const trendsEntries = Object.entries(trends).map(([date, counts]) => ({
    date: date.length > 10 ? date.slice(0, 10) : date,
    fullDate: date,
    ...counts,
    total: (counts.critical ?? 0) + (counts.high ?? 0) + (counts.medium ?? 0) + (counts.low ?? 0),
  }));
  const hasTrendsData = trendsEntries.some((d) => d.total > 0);

  const licensesTotal = LICENSE_CATEGORIES.reduce((a, k) => a + (Number(licenses[k]) || 0), 0) || 1;

  const totalFindings = remediation.total_findings ?? 0;
  const fixedPct = totalFindings > 0 ? Math.round(((remediation.total_fixed ?? 0) / totalFindings) * 100) : 0;
  const inProgressPct = totalFindings > 0 ? Math.round(((remediation.total_in_progress ?? 0) / totalFindings) * 100) : 0;
  const notStartedPct = totalFindings > 0 ? Math.round(((remediation.total_not_started ?? 0) / totalFindings) * 100) : 0;
  const ignoredPct = totalFindings > 0 ? Math.round(((remediation.total_ignored ?? 0) / totalFindings) * 100) : 0;

  return (
    <div className="space-y-6">
      {/* 1. Card data */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 xl:grid-cols-7 gap-4">
        <Card className="border-zinc-200 dark:border-zinc-800">
          <CardContent className="pt-4 pb-4 flex items-center gap-3">
            <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-red-100 dark:bg-red-900/30 text-red-600 dark:text-red-400">
              <AlertTriangle className="h-5 w-5" />
            </div>
            <div className="min-w-0">
              <p className="text-xs font-medium text-zinc-500 dark:text-zinc-400">Total vulnerabilities</p>
              <p className="text-lg font-semibold text-zinc-900 dark:text-zinc-100 tabular-nums">{card.total_vulnerabilities ?? 0}</p>
            </div>
          </CardContent>
        </Card>
        <Card className="border-zinc-200 dark:border-zinc-800">
          <CardContent className="pt-4 pb-4 flex items-center gap-3">
            <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-red-100 dark:bg-red-900/30 text-red-600 dark:text-red-400">
              <AlertCircle className="h-5 w-5" />
            </div>
            <div className="min-w-0">
              <p className="text-xs font-medium text-zinc-500 dark:text-zinc-400">Critical</p>
              <p className="text-lg font-semibold text-zinc-900 dark:text-zinc-100 tabular-nums">{card.total_critical_vulnerabilities ?? 0}</p>
            </div>
          </CardContent>
        </Card>
        <Card className="border-zinc-200 dark:border-zinc-800">
          <CardContent className="pt-4 pb-4 flex items-center gap-3">
            <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-amber-100 dark:bg-amber-900/30 text-amber-600 dark:text-amber-400">
              <Scale className="h-5 w-5" />
            </div>
            <div className="min-w-0">
              <p className="text-xs font-medium text-zinc-500 dark:text-zinc-400">Policy violations</p>
              <p className="text-lg font-semibold text-zinc-900 dark:text-zinc-100 tabular-nums">{card.total_policy_violations ?? 0}</p>
            </div>
          </CardContent>
        </Card>
        <Card className="border-zinc-200 dark:border-zinc-800">
          <CardContent className="pt-4 pb-4 flex items-center gap-3">
            <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-orange-100 dark:bg-orange-900/30 text-orange-600 dark:text-orange-400">
              <Shield className="h-5 w-5" />
            </div>
            <div className="min-w-0">
              <p className="text-xs font-medium text-zinc-500 dark:text-zinc-400">License risks</p>
              <p className="text-lg font-semibold text-zinc-900 dark:text-zinc-100 tabular-nums">{card.total_license_risks ?? 0}</p>
            </div>
          </CardContent>
        </Card>
        <Card className="border-zinc-200 dark:border-zinc-800">
          <CardContent className="pt-4 pb-4 flex items-center gap-3">
            <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-red-100 dark:bg-red-900/30 text-red-600 dark:text-red-400">
              <Package className="h-5 w-5" />
            </div>
            <div className="min-w-0">
              <p className="text-xs font-medium text-zinc-500 dark:text-zinc-400">High-risk licenses</p>
              <p className="text-lg font-semibold text-zinc-900 dark:text-zinc-100 tabular-nums">{card.total_high_risk_licenses ?? 0}</p>
            </div>
          </CardContent>
        </Card>
        <Card className="border-zinc-200 dark:border-zinc-800">
          <CardContent className="pt-4 pb-4 flex items-center gap-3">
            <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-blue-100 dark:bg-blue-900/30 text-blue-600 dark:text-blue-400">
              <Target className="h-5 w-5" />
            </div>
            <div className="min-w-0">
              <p className="text-xs font-medium text-zinc-500 dark:text-zinc-400">Avg risk score</p>
              <p className="text-lg font-semibold text-zinc-900 dark:text-zinc-100 tabular-nums">{Number(card.average_risk_score ?? 0).toFixed(1)}</p>
            </div>
          </CardContent>
        </Card>
        <Card className="border-zinc-200 dark:border-zinc-800">
          <CardContent className="pt-4 pb-4 flex items-center gap-3">
            <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-emerald-100 dark:bg-emerald-900/30 text-emerald-600 dark:text-emerald-400">
              <Activity className="h-5 w-5" />
            </div>
            <div className="min-w-0">
              <p className="text-xs font-medium text-zinc-500 dark:text-zinc-400">Reachable issues</p>
              <p className="text-lg font-semibold text-zinc-900 dark:text-zinc-100 tabular-nums">{card.total_reachable_issues ?? 0}</p>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* 2. Remediation actions */}
      <Card className="border-zinc-200 dark:border-zinc-800">
        <CardHeader>
          <CardTitle className="text-base">Remediation actions</CardTitle>
          <CardDescription>Finding status breakdown</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            {[
              { label: "Fixed", value: remediation.total_fixed ?? 0, pct: fixedPct, icon: CheckCircle, color: "text-emerald-600 dark:text-emerald-400" },
              { label: "In progress", value: remediation.total_in_progress ?? 0, pct: inProgressPct, icon: Loader2, color: "text-blue-600 dark:text-blue-400" },
              { label: "Not started", value: remediation.total_not_started ?? 0, pct: notStartedPct, icon: Circle, color: "text-slate-600 dark:text-slate-400" },
              { label: "Ignored", value: remediation.total_ignored ?? 0, pct: ignoredPct, icon: EyeOff, color: "text-zinc-600 dark:text-zinc-400" },
            ].map(({ label, value, pct, icon: Icon, color }) => (
              <div key={label} className="flex items-center gap-3">
                <Icon className={`h-5 w-5 shrink-0 ${color}`} />
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-medium text-zinc-900 dark:text-white">{label}</p>
                  <p className="text-xs text-zinc-500">{value} · {pct}%</p>
                  <Progress value={pct} className="h-2 mt-1" />
                </div>
              </div>
            ))}
            <div className="flex justify-between items-center pt-2 border-t border-zinc-200 dark:border-zinc-700">
              <span className="text-sm text-zinc-600 dark:text-zinc-400">Total findings</span>
              <span className="text-lg font-bold text-zinc-900 dark:text-white tabular-nums">{totalFindings}</span>
            </div>
          </div>
        </CardContent>
      </Card>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* 3. Severity distribution (radar) */}
        <Card className="border-zinc-200 dark:border-zinc-800">
          <CardHeader>
            <CardTitle className="text-base flex items-center gap-2">
              <AlertTriangle className="w-4 h-4" />
              Severity distribution
            </CardTitle>
            <CardDescription>By impact level</CardDescription>
          </CardHeader>
          <CardContent>
            {!hasSeverityData ? (
              <div className="flex items-center justify-center min-h-[240px] text-zinc-500 dark:text-zinc-400 text-sm">No data</div>
            ) : (
              <ChartContainer config={riskRadarChartConfig} className="mx-auto aspect-square max-h-[240px]">
                <RadarChart data={severityRadarData} margin={{ top: 8, right: 24, bottom: 8, left: 24 }}>
                  <ChartTooltip cursor={false} content={<ChartTooltipContent nameKey="subject" formatter={(value) => [value, "Count"]} />} />
                  <PolarAngleAxis dataKey="subject" />
                  <PolarGrid />
                  <Radar dataKey="count" fill="hsl(0 84% 60%)" fillOpacity={0.6} dot={{ r: 4, fillOpacity: 1 }} />
                </RadarChart>
              </ChartContainer>
            )}
          </CardContent>
        </Card>

        {/* 4. Reachability (bar) */}
        <Card className="border-zinc-200 dark:border-zinc-800">
          <CardHeader>
            <CardTitle className="text-base flex items-center gap-2">
              <BarChart3 className="w-4 h-4" />
              Reachability distribution
            </CardTitle>
            <CardDescription>Reachable vs not reachable</CardDescription>
          </CardHeader>
          <CardContent>
            {!hasReachabilityData ? (
              <div className="flex items-center justify-center min-h-[240px] text-zinc-500 dark:text-zinc-400 text-sm">No data</div>
            ) : (
              <ChartContainer config={reachabilityBarChartConfig} className="aspect-auto h-[240px] w-full">
                <BarChart data={reachabilityBarData} margin={{ top: 8, right: 8, bottom: 32, left: 0 }}>
                  <CartesianGrid vertical={false} className="stroke-zinc-200 dark:stroke-zinc-800" />
                  <XAxis dataKey="name" tickLine={false} axisLine={false} tickMargin={8} height={40} />
                  <YAxis type="number" tickLine={false} axisLine={false} />
                  <ChartTooltip cursor={false} content={<ChartTooltipContent />} />
                  <Bar dataKey="count" fill="var(--color-count)" radius={[8, 8, 0, 0]} />
                </BarChart>
              </ChartContainer>
            )}
          </CardContent>
        </Card>
      </div>

      {/* 5. Vulnerability remediation trends */}
      <Card className="border-zinc-200 dark:border-zinc-800">
        <CardHeader>
          <CardTitle className="text-base flex items-center gap-2">
            <TrendingUp className="w-4 h-4" />
            Vulnerability remediation trends
          </CardTitle>
          <CardDescription>Fixed/ignored over time by severity</CardDescription>
        </CardHeader>
        <CardContent>
          {!hasTrendsData ? (
            <div className="flex items-center justify-center min-h-[260px] text-zinc-500 dark:text-zinc-400 text-sm">No data</div>
          ) : (
            <ChartContainer config={trendsChartConfig} className="aspect-auto h-[260px] w-full">
              <AreaChart data={trendsEntries} margin={{ top: 8, right: 8, bottom: 28, left: 0 }}>
                <CartesianGrid vertical={false} className="stroke-zinc-200 dark:stroke-zinc-800" />
                <XAxis dataKey="date" tickLine={false} axisLine={false} tickMargin={8} height={40} />
                <YAxis type="number" tickLine={false} axisLine={false} />
                <ChartTooltip
                  cursor={false}
                  content={<ChartTooltipContent labelFormatter={(_, payload) => (payload?.[0]?.payload as { fullDate?: string })?.fullDate ?? ""} />}
                />
                <Area type="monotone" dataKey="critical" stackId="1" fill="hsl(0 84% 60%)" stroke="hsl(0 84% 60%)" fillOpacity={0.7} />
                <Area type="monotone" dataKey="high" stackId="1" fill="hsl(25 95% 53%)" stroke="hsl(25 95% 53%)" fillOpacity={0.7} />
                <Area type="monotone" dataKey="medium" stackId="1" fill="hsl(48 96% 53%)" stroke="hsl(48 96% 53%)" fillOpacity={0.7} />
                <Area type="monotone" dataKey="low" stackId="1" fill="hsl(142 71% 45%)" stroke="hsl(142 71% 45%)" fillOpacity={0.7} />
              </AreaChart>
            </ChartContainer>
          )}
        </CardContent>
      </Card>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* 6. Licenses distribution (card with progress bars) */}
        <Card className="border-zinc-200 dark:border-zinc-800">
          <CardHeader className="pb-2">
            <CardTitle className="text-base">Licenses Distribution</CardTitle>
            <CardDescription>
              Distribution of dependencies by license type. Risk levels: Low (permissive, public domain, unknown), Medium (weak copyleft, creative commons, commercial), High (strong copyleft, network copyleft, source available).
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            {LICENSE_CATEGORIES.map((key) => {
              const value = Number(licenses[key]) || 0;
              return (
                <div key={key} className="space-y-1.5">
                  <div className="flex items-center justify-between text-sm">
                    <span className="text-zinc-700 dark:text-zinc-300">{LICENSE_LABELS[key] ?? key}</span>
                    <span className="text-zinc-600 dark:text-zinc-400">{value}</span>
                  </div>
                  <Progress value={(value / licensesTotal) * 100} className="h-1.5" />
                </div>
              );
            })}
          </CardContent>
        </Card>

        {/* 8. Average risk score per reachability */}
        <Card className="border-zinc-200 dark:border-zinc-800">
          <CardHeader>
            <CardTitle className="text-base">Average risk score per reachability</CardTitle>
            <CardDescription>Weighted average by reachability level</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              {REACHABILITY_KEYS.map((key) => {
                const config = REACHABILITY_DISPLAY[key] ?? REACHABILITY_DISPLAY.unknown;
                const Icon = config.icon;
                const score = Number(avgRiskByReach[key] ?? 0).toFixed(1);
                return (
                  <div
                    key={key}
                    className="flex items-center justify-between gap-3 rounded-lg border border-zinc-200 dark:border-zinc-700 bg-zinc-50/50 dark:bg-zinc-800/30 px-3 py-2.5"
                  >
                    <div className="flex items-center gap-2.5 min-w-0 flex-1">
                      <div className={`flex h-8 w-8 shrink-0 items-center justify-center rounded-md ${config.boxClass}`}>
                        <Icon className="h-4 w-4" />
                      </div>
                      <span className="text-sm font-medium text-zinc-700 dark:text-zinc-300">{config.label}</span>
                    </div>
                    <span className={`inline-flex items-center justify-center min-w-10 px-2.5 py-1 rounded-md text-sm font-semibold tabular-nums ${config.boxClass}`} title="Average risk score">
                      {score}
                    </span>
                  </div>
                );
              })}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* 7. Top vulnerabilities by risk score */}
      <Card className="border-zinc-200 dark:border-zinc-800">
        <CardHeader>
          <CardTitle className="text-base">Top vulnerabilities by risk score</CardTitle>
          <CardDescription>Sorted by impact (descending)</CardDescription>
        </CardHeader>
        <CardContent>
          {topVulns.length === 0 ? (
            <div className="flex items-center justify-center min-h-[200px] text-zinc-500 dark:text-zinc-400 text-sm">No data</div>
          ) : (
            <ScrollArea className="h-[320px] w-full rounded-md border border-zinc-200 dark:border-zinc-800">
              <div className="p-2 space-y-2">
                {topVulns.slice(0, 20).map((v, i) => (
                  <div key={i} className="flex items-center justify-between gap-4 py-2 px-3 rounded-md bg-zinc-50 dark:bg-zinc-800/50">
                    <div className="min-w-0 flex-1">
                      <p className="text-sm font-medium text-zinc-900 dark:text-white truncate" title={v.dependency}>{v.dependency}</p>
                      <p className="text-xs text-zinc-500 dark:text-zinc-400">
                        {v.reachability} · {v.dependency_type} · {v.license_type}
                      </p>
                    </div>
                    <Badge variant="outline" className={getImpactBadgeClass(v.impact)}>{v.impact}</Badge>
                  </div>
                ))}
              </div>
            </ScrollArea>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

function SbomResultsView({
  vulnerabilities,
  findings,
  conversationId,
  teamId,
  origin,
  router,
  onDownloadReport,
  isExporting = false,
  dashboard,
  scanMetadata,
  integrationSettings,
  onIntegrationSettingsUpdated,
  onFindingsUpdated,
}: {
  vulnerabilities: SbomAgentVulnerability[];
  findings?: SbomFinding[] | null;
  conversationId?: number;
  teamId?: string;
  origin: string | null;
  router: ReturnType<typeof useRouter>;
  onDownloadReport?: () => void;
  isExporting?: boolean;
  dashboard?: SbomScanDashboardData | null;
  scanMetadata?: SbomScanMetadata | Record<string, unknown> | null;
  integrationSettings?: Record<string, unknown> | null;
  onIntegrationSettingsUpdated?: () => void;
  onFindingsUpdated?: () => void;
}) {
  const [detailDialogOpen, setDetailDialogOpen] = useState(false);
  const [selectedVuln, setSelectedVuln] = useState<SbomAgentVulnerability | null>(null);
  const [selectedFinding, setSelectedFinding] = useState<SbomFinding | null>(null);
  const [activeTab, setActiveTab] = useState<"results" | "ticketing">("results");
  const [jiraProjectId, setJiraProjectId] = useState("");
  const [selectedRows, setSelectedRows] = useState<Set<number>>(new Set());
  const [selectedRowIds, setSelectedRowIds] = useState<Set<string>>(new Set());
  const queryClient = useQueryClient();
  const useFindings = Boolean(findings && findings.length > 0);

  const [findingsSearchQuery, setFindingsSearchQuery] = useState("");
  const [filterImpact, setFilterImpact] = useState<string>("all");
  type RiskScoreFilter = "all" | "critical" | "high" | "medium" | "low";
  const [filterRiskScore, setFilterRiskScore] = useState<RiskScoreFilter>("all");
  function matchesRiskScoreFilter(score: number | null, filter: RiskScoreFilter): boolean {
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
  const findingsList = findings ?? [];
  const filteredFindingsList = useMemo(() => {
    if (!useFindings) return findingsList;
    let list = findingsList;
    const q = findingsSearchQuery.trim().toLowerCase();
    if (q) {
      list = list.filter((f) => {
        const title = ((f.title ?? "") + "").toLowerCase();
        const description = ((f.description ?? "") + "").toLowerCase();
        const impact = ((f.impact ?? "") + "").toLowerCase();
        const dependency = ((f.dependency ?? "") + "").toLowerCase();
        return title.includes(q) || description.includes(q) || impact.includes(q) || dependency.includes(q);
      });
    }
    if (filterImpact && filterImpact !== "all") {
      list = list.filter((f) => (f.impact ?? "").trim().toLowerCase() === filterImpact.toLowerCase());
    }
    list = list.filter((f) => matchesRiskScoreFilter(f.risk_score ?? null, filterRiskScore));
    return list;
  }, [findingsList, useFindings, findingsSearchQuery, filterImpact, filterRiskScore]);
  const hasActiveFindingsFilters =
    findingsSearchQuery.trim() !== "" || filterImpact !== "all" || filterRiskScore !== "all";
  const clearFindingsFilters = () => {
    setFindingsSearchQuery("");
    setFilterImpact("all");
    setFilterRiskScore("all");
  };

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

  const toggleFindingMutation = useMutation({
    mutationFn: ({ finding_id, state }: { finding_id: string; state: "fixed" | "ignored" | "in_progress" | "not_started" }) => {
      const tid = parseInt(teamId ?? "0", 10);
      if (!conversationId || Number.isNaN(tid)) throw new Error("Missing team or scan");
      return toggleFindingState({ team_id: tid, type: "sbom_sca", scan_id: conversationId, finding_id, state });
    },
    onSuccess: () => {
      onFindingsUpdated?.();
      const tid = parseInt(teamId ?? "0", 10);
      if (conversationId != null && tid > 0) {
        queryClient.invalidateQueries({ queryKey: ["sbom_sca-conversation-data", tid, conversationId] });
      }
      toast.success("Finding status updated");
    },
    onError: (err) => {
      showErrorToast(err, "Failed to update finding status");
    },
  });

  const showTabs = teamId && conversationId != null;
  const hasTicketingTab = showTabs && onIntegrationSettingsUpdated != null;

  const totalFindings = useFindings ? (findings?.length ?? 0) : vulnerabilities.length;
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
    if (useFindings && filteredFindingsList.length) {
      if (selectedRowIds.size === filteredFindingsList.length) setSelectedRowIds(new Set());
      else setSelectedRowIds(new Set(filteredFindingsList.map((f) => f.id)));
    } else if (!useFindings) {
      if (selectedRows.size === vulnerabilities.length) setSelectedRows(new Set());
      else setSelectedRows(new Set(vulnerabilities.map((_, i) => i)));
    }
  };

  const toggleFindingRowSelection = (findingId: string) => {
    setSelectedRowIds((prev) => {
      const next = new Set(prev);
      if (next.has(findingId)) next.delete(findingId);
      else next.add(findingId);
      return next;
    });
  };

  const createJiraTicketsMutation = useMutation({
    mutationFn: async () => {
      const tid = parseInt(teamId ?? "0", 10);
      if (!conversationId || Number.isNaN(tid)) throw new Error("Missing team or scan");
      const selectedFindingsList = useFindings && findingsList
        ? findingsList.filter((f) => selectedRowIds.has(f.id))
        : Array.from(selectedRows).map((i) => vulnerabilities[i]);
      if (selectedFindingsList.length === 0) throw new Error("No findings selected");

      const impactCounts: Record<string, number> = {};
      for (const f of selectedFindingsList) {
        const impact = (f.impact ?? "Unknown").trim() || "Unknown";
        impactCounts[impact] = (impactCounts[impact] ?? 0) + 1;
      }
      let summary = Object.entries(impactCounts)
        .sort(([a], [b]) => RISK_ORDER.indexOf(a as (typeof RISK_ORDER)[number]) - RISK_ORDER.indexOf(b as (typeof RISK_ORDER)[number]))
        .map(([impact, count]) => `${count} ${impact}`)
        .join(", ") || `${selectedFindingsList.length} finding(s)`;

      summary = summary + " - Vulnerabilities found in SBOM scan";

      const descSections = selectedFindingsList.map((f, idx) => {
        const parts: string[] = [`--- Finding ${idx + 1} ---`];
        parts.push(`Title: ${(f.title ?? "Untitled finding").trim() || "Untitled finding"}`);
        if ((f.description ?? "").trim()) parts.push(`Description: ${(f as SbomAgentVulnerability & SbomFinding).description!.trim()}`);
        if ((f.impact ?? "").trim()) parts.push(`Impact: ${f.impact!.trim()}`);
        const dep = "dependency" in f && f.dependency ? f.dependency : ("dependencies" in f && Array.isArray((f as SbomAgentVulnerability).dependencies) ? (f as SbomAgentVulnerability).dependencies!.join(", ") : "");
        if (dep) parts.push(`Dependency: ${dep}`);
        if ((f.suggested_fix ?? "").trim()) parts.push(`Suggested fix: ${f.suggested_fix!.trim()}`);
        const cves = f.cves;
        if (cves && typeof cves === "object" && Object.keys(cves).length > 0) parts.push(`CVEs: ${Object.keys(cves).join(", ")}`);
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
      const count = useFindings ? selectedRowIds.size : selectedRows.size;
      if (context?.toastId != null) {
        toast.success(`Jira ticket(s) created for ${count} finding(s)`, { id: context.toastId });
      } else {
        toast.success(`Jira ticket(s) created for ${count} finding(s)`);
      }
      setSelectedRows(new Set());
      setSelectedRowIds(new Set());
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
      {scanMetadata && typeof scanMetadata === "object" && (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
          {"repo_url" in scanMetadata && scanMetadata.repo_url != null && String(scanMetadata.repo_url).trim() !== "" && (
            <Card className="border-zinc-200 dark:border-zinc-800">
              <CardContent className="pt-4 pb-4 flex items-center gap-3">
                <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-violet-100 dark:bg-violet-900/30 text-violet-600 dark:text-violet-400">
                  <Github className="h-5 w-5" />
                </div>
                <div className="min-w-0 flex-1 overflow-hidden">
                  <p className="text-xs font-medium text-zinc-500 dark:text-zinc-400">Repository</p>
                  <p className="text-sm font-semibold text-zinc-900 dark:text-zinc-100 truncate" title={String(scanMetadata.repo_url)}>{String(scanMetadata.repo_url)}</p>
                </div>
              </CardContent>
            </Card>
          )}
          {"branch" in scanMetadata && scanMetadata.branch != null && String(scanMetadata.branch).trim() !== "" && (
            <Card className="border-zinc-200 dark:border-zinc-800">
              <CardContent className="pt-4 pb-4 flex items-center gap-3">
                <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-amber-100 dark:bg-amber-900/30 text-amber-600 dark:text-amber-400">
                  <GitBranch className="h-5 w-5" />
                </div>
                <div className="min-w-0">
                  <p className="text-xs font-medium text-zinc-500 dark:text-zinc-400">Branch</p>
                  <p className="text-lg font-semibold text-zinc-900 dark:text-zinc-100">{String(scanMetadata.branch)}</p>
                </div>
              </CardContent>
            </Card>
          )}
          {"zip_file_used" in scanMetadata && (
            <Card className="border-zinc-200 dark:border-zinc-800">
              <CardContent className="pt-4 pb-4 flex items-center gap-3">
                <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-zinc-100 dark:bg-zinc-800 text-zinc-600 dark:text-zinc-400">
                  <Archive className="h-5 w-5" />
                </div>
                <div className="min-w-0">
                  <p className="text-xs font-medium text-zinc-500 dark:text-zinc-400">Source</p>
                  <p className="text-sm font-semibold text-zinc-900 dark:text-zinc-100">{scanMetadata.zip_file_used ? "ZIP upload" : "Repository"}</p>
                </div>
              </CardContent>
            </Card>
          )}
        </div>
      )}
      {dashboard && "card_data" in dashboard && <SbomDashboardCharts dashboard={dashboard as SbomScanDashboardData} />}

      <Card>
        <CardHeader>
          <CardTitle>Findings</CardTitle>
          <CardDescription>
            {useFindings
              ? `${totalFindings} findings. Select rows to create Jira tickets; use Action to change finding state.`
              : `${totalFindings} vulnerability findings — click a title to view details`}
          </CardDescription>
        </CardHeader>
        <CardContent>
          {useFindings && findingsList.length > 0 && (
            <>
              <div className="flex flex-wrap items-center gap-3 mb-4">
                <div className="relative flex-1 min-w-[200px] max-w-sm">
                  <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-zinc-400" />
                  <Input
                    type="search"
                    placeholder="Search by title, description..."
                    value={findingsSearchQuery}
                    onChange={(e) => setFindingsSearchQuery(e.target.value)}
                    className="pl-9 h-9 cursor-text"
                    aria-label="Search findings table"
                  />
                </div>
                <Select value={filterImpact} onValueChange={setFilterImpact}>
                  <SelectTrigger className="h-9 min-w-[150px] cursor-pointer">
                    <SelectValue placeholder="Impact" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All impacts</SelectItem>
                    <SelectItem value="Critical">Critical</SelectItem>
                    <SelectItem value="High">High</SelectItem>
                    <SelectItem value="Medium">Medium</SelectItem>
                    <SelectItem value="Low">Low</SelectItem>
                  </SelectContent>
                </Select>
                <DropdownMenu>
                  <DropdownMenuTrigger asChild>
                    <Button
                      variant="outline"
                      size="sm"
                      className={`h-9 gap-1.5 cursor-pointer border-2 ${
                        filterRiskScore === "critical"
                          ? "border-red-500 bg-red-50 text-red-700 dark:bg-red-950/30 dark:text-red-300"
                          : filterRiskScore === "high"
                            ? "border-orange-500 bg-orange-50 text-orange-700 dark:bg-orange-950/30 dark:text-orange-300"
                            : filterRiskScore === "medium"
                              ? "border-amber-500 bg-amber-50 text-amber-700 dark:bg-amber-950/30 dark:text-amber-300"
                              : filterRiskScore === "low"
                                ? "border-blue-500 bg-blue-50 text-blue-700 dark:bg-blue-950/30 dark:text-blue-300"
                                : "border-zinc-200 dark:border-zinc-700"
                      }`}
                    >
                      <Filter className="h-2 w-2 shrink-0 text-zinc-400" />
                      <span className="capitalize font-normal">{RISK_SCORE_LABELS[filterRiskScore]}</span>
                      <ChevronDown className="h-3 w-3 opacity-70 shrink-0" />
                    </Button>
                  </DropdownMenuTrigger>
                  <DropdownMenuContent align="start" className="min-w-[180px]">
                    <DropdownMenuLabel className="text-xs font-normal text-zinc-500">Filter by risk score</DropdownMenuLabel>
                    <DropdownMenuSeparator />
                    <DropdownMenuItem className="cursor-pointer gap-2" onClick={() => setFilterRiskScore("all")}>
                      {filterRiskScore === "all" ? <Check className="h-4 w-4" /> : <span className="w-4" />}
                      All
                    </DropdownMenuItem>
                    <DropdownMenuItem className="cursor-pointer gap-2" onClick={() => setFilterRiskScore("critical")}>
                      {filterRiskScore === "critical" ? <Check className="h-4 w-4" /> : <AlertTriangle className="h-4 w-4 text-red-500" />}
                      Critical (≥9)
                    </DropdownMenuItem>
                    <DropdownMenuItem className="cursor-pointer gap-2" onClick={() => setFilterRiskScore("high")}>
                      {filterRiskScore === "high" ? <Check className="h-4 w-4" /> : <AlertTriangle className="h-4 w-4 text-orange-500" />}
                      High (7–9)
                    </DropdownMenuItem>
                    <DropdownMenuItem className="cursor-pointer gap-2" onClick={() => setFilterRiskScore("medium")}>
                      {filterRiskScore === "medium" ? <Check className="h-4 w-4" /> : <Shield className="h-4 w-4 text-amber-500" />}
                      Medium (5–7)
                    </DropdownMenuItem>
                    <DropdownMenuItem className="cursor-pointer gap-2" onClick={() => setFilterRiskScore("low")}>
                      {filterRiskScore === "low" ? <Check className="h-4 w-4" /> : <Shield className="h-4 w-4 text-blue-500" />}
                      Low (&lt;5)
                    </DropdownMenuItem>
                  </DropdownMenuContent>
                </DropdownMenu>
                {hasActiveFindingsFilters && (
                  <Button variant="ghost" size="sm" className="h-9 text-zinc-500 hover:text-zinc-700 cursor-pointer" onClick={clearFindingsFilters}>
                    <X className="h-4 w-4 mr-1" />
                    Clear filters
                  </Button>
                )}
              </div>
              {hasActiveFindingsFilters && (
                <span className="text-sm text-zinc-500 dark:text-zinc-400 block mb-4">
                  Showing {filteredFindingsList.length} of {findingsList.length} findings
                </span>
              )}
            </>
          )}
          <FindingSelectionMenu
            selectedCount={useFindings ? selectedRowIds.size : selectedRows.size}
            onClearSelection={() => { setSelectedRows(new Set()); setSelectedRowIds(new Set()); }}
            jiraOnClickHandler={handleCreateJiraTicket}
            ticketType="jira"
            isJiraCreating={createJiraTicketsMutation.isPending}
          />
          <ScrollArea className="h-[500px] rounded-md border border-zinc-200 dark:border-zinc-800">
            {useFindings && findingsList.length ? (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="w-[48px]">
                      <Checkbox
                        checked={filteredFindingsList.length > 0 && selectedRowIds.size === filteredFindingsList.length}
                        onCheckedChange={toggleSelectAll}
                        aria-label="Select all rows"
                        className="cursor-pointer"
                      />
                    </TableHead>
                    <TableHead className="min-w-[180px]">Title</TableHead>
                    <TableHead className="min-w-[120px]">Dependency</TableHead>
                    <TableHead className="min-w-[90px]">Impact</TableHead>
                    <TableHead className="min-w-[90px] text-center">Risk score</TableHead>
                    <TableHead className="min-w-[100px]">Status</TableHead>
                    <TableHead className="min-w-[100px]">Reachability</TableHead>
                    <TableHead className="min-w-[90px]">License</TableHead>
                    <TableHead className="min-w-[80px] text-center">OWASP</TableHead>
                    <TableHead className="min-w-[80px] text-center">Compliance</TableHead>
                    <TableHead className="min-w-[100px] text-right">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {filteredFindingsList.map((f) => {
                    const impact = (f.impact ?? "").trim() || "—";
                    const statusLabel = (f.status ?? "not_started").replace(/_/g, " ");
                    return (
                      <TableRow
                        key={f.id}
                        className={`hover:bg-zinc-50 dark:hover:bg-zinc-800/50 ${selectedRowIds.has(f.id) ? "bg-zinc-100 dark:bg-zinc-800/70" : ""}`}
                      >
                        <TableCell onClick={(e) => e.stopPropagation()} className="w-[48px]">
                          <Checkbox
                            checked={selectedRowIds.has(f.id)}
                            onCheckedChange={() => toggleFindingRowSelection(f.id)}
                            aria-label={`Select ${f.title ?? f.id}`}
                            className="cursor-pointer"
                          />
                        </TableCell>
                        <TableCell className="font-medium">
                          <button
                            type="button"
                            onClick={() => setSelectedFinding(f)}
                            className="text-left text-blue-600 hover:text-blue-700 dark:text-blue-400 dark:hover:text-blue-300 hover:underline cursor-pointer font-medium"
                          >
                            {(f.title ?? "").trim() || "Untitled"}
                          </button>
                        </TableCell>
                        <TableCell className="text-sm text-zinc-600 dark:text-zinc-400 max-w-[120px] truncate" title={f.dependency ?? undefined}>
                          {(f.dependency ?? "").trim() || "—"}
                        </TableCell>
                        <TableCell>
                          <Badge variant="outline" className={getImpactBadgeClass(impact)}>{impact}</Badge>
                        </TableCell>
                        <TableCell className="text-center">
                          <span
                            className={`inline-flex items-center justify-center min-w-9 px-2 py-1 rounded-md text-xs font-semibold tabular-nums ${getRiskScoreBoxClass(f.risk_score)}`}
                            title="Risk score"
                          >
                            {f.risk_score ?? "—"}
                          </span>
                        </TableCell>
                        <TableCell>
                          <span className={`inline-flex items-center justify-center px-2.5 py-1 rounded-md text-xs font-medium capitalize ${getFindingStatusBadgeClass(f.status ?? "not_started")}`}>
                            {statusLabel}
                          </span>
                        </TableCell>
                        <TableCell>
                          <span className={`inline-flex items-center justify-center min-w-0 px-2 py-1 rounded-md text-xs font-medium capitalize truncate max-w-[120px] ${getReachabilityBoxClass(f.reachability)}`} title={(f.reachability ?? "").replace(/_/g, " ")}>
                            {(f.reachability ?? "—").replace(/_/g, " ")}
                          </span>
                        </TableCell>
                        <TableCell>
                          <span className="inline-flex items-center justify-center min-w-0 px-2 py-1 rounded-md text-xs font-semibold truncate max-w-[100px] bg-slate-100 text-slate-800 dark:bg-slate-700/50 dark:text-slate-200" title={LICENSE_LABELS[(f.license_type ?? "").toLowerCase()] ?? (f.license_type ?? "—")}>
                            {LICENSE_LABELS[(f.license_type ?? "").toLowerCase()] ?? (f.license_type ?? "—").replace(/_/g, " ")}
                          </span>
                        </TableCell>
                        <TableCell className="text-center">
                          <span
                            className="inline-flex items-center justify-center min-w-9 px-2 py-1 rounded-md text-xs font-semibold tabular-nums bg-violet-100 text-violet-800 dark:bg-violet-900/40 dark:text-violet-200"
                            title="OWASP Top 10 count"
                          >
                            {countFindingField(f.owasp_top_10)}
                          </span>
                        </TableCell>
                        <TableCell className="text-center">
                          <span
                            className="inline-flex items-center justify-center min-w-9 px-2 py-1 rounded-md text-xs font-semibold tabular-nums bg-sky-100 text-sky-800 dark:bg-sky-900/40 dark:text-sky-200"
                            title="Compliance controls count"
                          >
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
                                <CheckCircle className="h-4 w-4" /> Mark as Fixed
                              </DropdownMenuItem>
                              <DropdownMenuItem className="cursor-pointer gap-2" onClick={() => toggleFindingMutation.mutate({ finding_id: f.id, state: "ignored" })} disabled={toggleFindingMutation.isPending}>
                                <EyeOff className="h-4 w-4" /> Mark as Ignored
                              </DropdownMenuItem>
                              <DropdownMenuItem className="cursor-pointer gap-2" onClick={() => toggleFindingMutation.mutate({ finding_id: f.id, state: "in_progress" })} disabled={toggleFindingMutation.isPending}>
                                <Loader2 className="h-4 w-4" /> Mark as In progress
                              </DropdownMenuItem>
                              <DropdownMenuItem className="cursor-pointer gap-2" onClick={() => toggleFindingMutation.mutate({ finding_id: f.id, state: "not_started" })} disabled={toggleFindingMutation.isPending}>
                                <Circle className="h-4 w-4" /> Mark as Not started
                              </DropdownMenuItem>
                            </DropdownMenuContent>
                          </DropdownMenu>
                        </TableCell>
                      </TableRow>
                    );
                  })}
                </TableBody>
              </Table>
            ) : (
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
            )}
          </ScrollArea>
        </CardContent>
      </Card>

      <Dialog open={!!selectedFinding} onOpenChange={(open) => !open && setSelectedFinding(null)}>
        <DialogContent className="sm:max-w-3xl max-h-[90vh] flex flex-col p-0 gap-0 overflow-hidden bg-zinc-900">
          <DialogHeader className="px-6 pt-6 pb-2 shrink-0">
            <DialogTitle className="pr-8">{selectedFinding?.title ?? "Finding details"}</DialogTitle>
          </DialogHeader>
          {selectedFinding && (
            <div className="h-[70vh] min-h-0 shrink px-6 pb-6">
              <ScrollArea className="h-full w-full rounded-md">
                <div className="space-y-4 pt-2 pr-4">
                  {(selectedFinding.impact ?? "").trim() && (
                    <div>
                      <div className="text-xs font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400 mb-1">Impact</div>
                      <Badge variant="outline" className={getImpactBadgeClass(selectedFinding.impact!.trim())}>{selectedFinding.impact!.trim()}</Badge>
                    </div>
                  )}
                  {(selectedFinding.status ?? "").trim() && (
                    <div>
                      <div className="text-xs font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400 mb-1">Status</div>
                      <span className={`inline-flex px-2.5 py-1 rounded-md text-xs font-medium capitalize ${getFindingStatusBadgeClass(selectedFinding.status!)}`}>
                        {selectedFinding.status!.replace(/_/g, " ")}
                      </span>
                    </div>
                  )}
                  {(selectedFinding.dependency ?? "").trim() && (
                    <div>
                      <div className="text-xs font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400 mb-1">Dependency</div>
                      <p className="text-sm text-zinc-700 dark:text-zinc-300 font-mono">{selectedFinding.dependency!.trim()}</p>
                    </div>
                  )}
                  {(selectedFinding.reachability ?? "").trim() && (
                    <div>
                      <div className="text-xs font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400 mb-1">Reachability</div>
                      <p className="text-sm text-zinc-700 dark:text-zinc-300">{selectedFinding.reachability!.trim().replace(/_/g, " ")}</p>
                    </div>
                  )}
                  {(selectedFinding.dependency_type ?? "").trim() && (
                    <div>
                      <div className="text-xs font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400 mb-1">Dependency type</div>
                      <p className="text-sm text-zinc-700 dark:text-zinc-300">{selectedFinding.dependency_type!.trim()}</p>
                    </div>
                  )}
                  {(selectedFinding.license_type ?? "").trim() && (
                    <div>
                      <div className="text-xs font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400 mb-1">License type</div>
                      <p className="text-sm text-zinc-700 dark:text-zinc-300">{selectedFinding.license_type!.trim().replace(/_/g, " ")}</p>
                    </div>
                  )}
                  {(selectedFinding.description ?? "").trim() && (
                    <div>
                      <div className="text-xs font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400 mb-1">Description</div>
                      <p className="text-sm text-zinc-700 dark:text-zinc-300">{selectedFinding.description!.trim()}</p>
                    </div>
                  )}
                  {(selectedFinding.suggested_fix ?? "").trim() && (
                    <div>
                      <div className="text-xs font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400 mb-1">Suggested fix</div>
                      <p className="text-sm text-zinc-700 dark:text-zinc-300">{selectedFinding.suggested_fix!.trim()}</p>
                    </div>
                  )}
                  {getOwaspComplianceEntries(selectedFinding.owasp_top_10 as OwaspOrCompliance).length > 0 && (
                    <div>
                      <div className="text-xs font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400 mb-1">OWASP Top 10</div>
                      <div className="flex flex-wrap gap-1">
                        {getOwaspComplianceEntries(selectedFinding.owasp_top_10 as OwaspOrCompliance).map(([, description], i) => (
                          <Badge key={i} variant="secondary" className="text-xs bg-purple-100 dark:bg-purple-900/40 text-purple-800 dark:text-purple-200">{description}</Badge>
                        ))}
                      </div>
                    </div>
                  )}
                  {getOwaspComplianceEntries(selectedFinding.compliance_controls as OwaspOrCompliance).length > 0 && (
                    <div>
                      <div className="text-xs font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400 mb-1">Compliance controls</div>
                      <div className="flex flex-wrap gap-1">
                        {getOwaspComplianceEntries(selectedFinding.compliance_controls as OwaspOrCompliance).map(([, description], i) => (
                          <Badge key={i} variant="outline" className="text-xs">{description}</Badge>
                        ))}
                      </div>
                    </div>
                  )}
                  {Boolean(selectedFinding.cves && typeof selectedFinding.cves === "object" && Object.keys(selectedFinding.cves as object).length > 0) && (
                    <div>
                      <div className="text-xs font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400 mb-1">Related CVEs</div>
                      <ul className="space-y-2 text-sm">
                        {Object.entries(selectedFinding.cves as Record<string, unknown>).map(([id, desc], i) => (
                          <li key={i} className="rounded-md border border-zinc-200 dark:border-zinc-700 bg-zinc-50/50 dark:bg-zinc-800/30 px-3 py-2">
                            <span className="font-mono font-medium text-zinc-800 dark:text-zinc-200">{id}</span>
                            {desc != null && String(desc).trim() !== "" && <p className="text-zinc-600 dark:text-zinc-400 mt-0.5 text-xs">{String(desc)}</p>}
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}
                  <RemediationPanel
                    teamId={teamId ?? ""}
                    scanType="sbom_sca"
                    scanId={conversationId ?? 0}
                    findingId={selectedFinding.id}
                    existingRemediation={selectedFinding.remediation}
                  />
                </div>
              </ScrollArea>
            </div>
          )}
        </DialogContent>
      </Dialog>

      <Dialog open={detailDialogOpen} onOpenChange={setDetailDialogOpen}>
        <DialogContent className="sm:max-w-3xl max-h-[90vh] flex flex-col p-0 gap-0 overflow-hidden bg-zinc-900">
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

export default function SbomResults({ data, conversationId, teamId, dashboard, findings, scanMetadata, integrationSettings, onIntegrationSettingsUpdated, onFindingsUpdated }: SbomResultsProps) {
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

  const hasFindings = findings && findings.length > 0;
  const hasData = data != null && (!Array.isArray(data) || data.length > 0);
  const isEmpty = !hasFindings && !hasData;

  if (isEmpty) {
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

  const vulnerabilities = (Array.isArray(data) ? data : []) as SbomAgentVulnerability[];

  return (
    <SbomResultsView
      vulnerabilities={vulnerabilities}
      findings={findings}
      conversationId={conversationId}
      teamId={teamId}
      origin={origin}
      router={router}
      onDownloadReport={teamId && conversationId != null ? handleDownloadReport : undefined}
      isExporting={isExporting}
      dashboard={dashboard}
      scanMetadata={scanMetadata}
      integrationSettings={integrationSettings}
      onIntegrationSettingsUpdated={onIntegrationSettingsUpdated}
      onFindingsUpdated={onFindingsUpdated}
    />
  );
}
