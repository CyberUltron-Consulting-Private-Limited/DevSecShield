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
  XCircle,
  Clock,
  Crosshair,
  Activity,
  Percent,
  FileStack,
  Github,
  GitBranch,
  Archive,
} from "lucide-react";
import { ScrollArea, ScrollBar } from "@/components/ui/scroll-area";
import RemediationPanel from "@/components/RemediationPanel";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
  DropdownMenuLabel,
  DropdownMenuSeparator,
} from "@/components/ui/dropdown-menu";
import { useRouter, useSearchParams, usePathname, useParams } from "next/navigation";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { getExportResults, updateScan, createTicket, toggleFindingState, type SastDashboardData, type SastScanMetadata, type SastFinding, type ScanTicketingIntegrationSettings } from "@/utils/backend_api";
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
import { PieChart, BarChart3, TrendingUp, ChevronDown, MoreVertical, Search, Filter, Check, X, Shield } from "lucide-react";
import { toast } from "@/utils/toast";
import TicketingIntegrationsSettings from "@/components/ticketing-integrations-settings";
import FindingSelectionMenu from "@/components/finding-selection-menu";
import { Progress } from "@/components/ui/progress";
import { InfoTip } from "@/components/ui/info-tip";

// Agent output format (from worker_sast_agent_results_testing.json)
type OwaspOrComplianceItem = Record<string, string>;
/** OWASP / compliance: either a dict (key = title, value = description) or legacy list of one-item dicts */
type OwaspOrCompliance = Record<string, string> | Array<OwaspOrComplianceItem> | null | undefined;

interface SastAgentVulnerability {
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
interface SastAgentLogicalComponent {
  logical_component_title?: string | null;
  vulnerabilities?: SastAgentVulnerability[] | null;
}
type SastAgentResult = SastAgentLogicalComponent;

/** Safe string from owasp/compliance item: { "KEY": "Label" } -> "Label" or key */
function formatOwaspOrComplianceItem(item: OwaspOrComplianceItem): string {
  if (item == null || typeof item !== "object") return "—";
  const entries = Object.entries(item).filter(([, v]) => v != null && String(v).trim() !== "");
  if (entries.length === 0) return Object.keys(item)[0] ?? "—";
  return entries[0][1];
}

/** Count for OWASP / compliance: supports dict (keys length) or legacy array (length) */
function getOwaspComplianceCount(val: OwaspOrCompliance): number {
  if (val == null) return 0;
  if (Array.isArray(val)) return val.length;
  if (typeof val === "object" && !Array.isArray(val)) return Object.keys(val).length;
  return 0;
}

/** Entries for display: [title, description][] — supports dict or legacy list of one-item dicts */
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

interface SASTResultsProps {
  conversationId?: number;
  dashboard?: SastDashboardData | null;
  findings?: SastFinding[] | null;
  teamId?: string;
  scanMetadata?: SastScanMetadata | Record<string, unknown> | null;
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

/** Colored box classes for finding status (fixed, ignored, in_progress, not_started) */
function getFindingStatusBadgeClass(status: string): string {
  const s = (status ?? "").toLowerCase().replace(/\s/g, "_");
  if (s === "fixed") return "bg-emerald-100 text-emerald-800 dark:bg-emerald-900/40 dark:text-emerald-200";
  if (s === "ignored") return "bg-zinc-100 text-zinc-700 dark:bg-zinc-700/50 dark:text-zinc-200";
  if (s === "in_progress") return "bg-blue-100 text-blue-800 dark:bg-blue-900/40 dark:text-blue-200";
  if (s === "not_started") return "bg-slate-100 text-slate-600 dark:bg-slate-700/50 dark:text-slate-300";
  return "bg-zinc-100 text-zinc-600 dark:bg-zinc-700/50 dark:text-zinc-300";
}

const RISK_ORDER = ["Critical", "High", "Medium", "Low"] as const;
const riskChartColors: Record<string, string> = {
  Critical: "hsl(0 84% 60%)",
  High: "hsl(25 95% 53%)",
  Medium: "hsl(48 96% 53%)",
  Low: "hsl(142 71% 45%)",
};

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

const riskScoreAreaChartConfig = {
  finding: { label: "Finding" },
  score: { label: "Risk score", color: "hsl(217 91% 60%)" },
} satisfies ChartConfig;

function SASTDashboardCharts({ dashboard }: { dashboard: SastDashboardData }) {
  const riskMetrics = dashboard.risk_metrics ?? {};
  const owaspMetrics = dashboard.owasp_top_10_metrics ?? {};
  const complianceMetrics = dashboard.compliance_controls_metrics ?? {};
  const cvesMetrics = dashboard.cves_per_vulnerability ?? {};
  const policyViolations = dashboard.policy_violations ?? {};
  const riskScoresPerFinding = dashboard.risk_scores_per_finding ?? {};
  const remediationMetrics = dashboard.remediation_metrics;

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

  const policyViolationsList = Object.entries(policyViolations)
    .map(([name, violations]) => ({ name, violations }))
    .sort((a, b) => b.violations - a.violations)
    .slice(0, 12);
  const totalViolations = policyViolationsList.reduce((acc, p) => acc + p.violations, 0);
  const policyViolationsWithCompliance = policyViolationsList.map((p) => ({
    ...p,
    compliance: totalViolations > 0 ? Math.round((p.violations / totalViolations) * 1000) / 10 : 0,
  }));
  const hasPolicyViolationsData = policyViolationsWithCompliance.length > 0;

  const riskScoresAreaData = Object.entries(riskScoresPerFinding)
    .map(([finding, score]) => ({ finding, score, fullName: finding }))
    .sort((a, b) => b.score - a.score)
    .slice(0, 24)
    .map((row, i) => ({ ...row, finding: `F${i + 1}` }));
  const hasRiskScoresData = riskScoresAreaData.length > 0;

  const criticalCount = riskMetrics["Critical"] ?? 0;

  return (
    <div className="space-y-6">
      {/* Row: Radial (OWASP) + Radar + CVEs area chart */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <Card className="border-zinc-200 dark:border-zinc-800">
          <CardHeader>
            <CardTitle className="text-base flex items-center gap-2">
              <PieChart className="w-4 h-4" />
              OWASP Top 10 metrics
              <InfoTip id="sast.res.owasp" />
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
                  <span
                    className="shrink-0 w-3 h-3 rounded-full"
                    style={{ backgroundColor: fill }}
                    aria-hidden
                  />
                  <span className="text-zinc-600 dark:text-zinc-400">
                    {displayValue}
                  </span>
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
              <InfoTip id="sast.res.risk" />
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
              Number of findings for each impact level (Critical, High, Medium, Low). Each axis shows the count for that severity.
            </p>
          </CardContent>
        </Card>

        <Card className="border-zinc-200 dark:border-zinc-800 justify-between">
          <CardHeader>
            <CardTitle className="text-base flex items-center gap-2">
              <TrendingUp className="w-4 h-4" />
              CVEs per vulnerability
              <InfoTip id="sast.res.cves" />
            </CardTitle>
            <CardDescription>Vulnerability count by CVE (top 20)</CardDescription>
          </CardHeader>
          <CardContent className="">
            {!hasCvesData ? (
              <div className="flex items-center justify-center min-h-[260px] text-zinc-500 dark:text-zinc-400 text-sm">No data to be displayed</div>
            ) : (
            <ChartContainer config={cvesAreaChartConfig} className="aspect-auto h-[260px] w-full pb-8 cursor-pointer">
              <AreaChart data={cvesAreaDisplay} margin={{ bottom: 28 }}>
                <defs>
                  <linearGradient id="fillSastCves" x1="0" y1="0" x2="0" y2="1">
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
                <Area dataKey="count" type="monotone" fill="url(#fillSastCves)" stroke="hsl(0 84% 60%)" strokeWidth={2} />
              </AreaChart>
            </ChartContainer>
            )}
            <p className="mt-4 pt-3 border-t border-zinc-200 dark:border-zinc-700 text-xs text-zinc-500 dark:text-zinc-400 text-center">
              Number of vulnerabilities linked to each CVE identifier. The chart shows the top 20 CVEs by count; hover for exact values.
            </p>
          </CardContent>
        </Card>
      </div>

      <Card className="border-zinc-200 dark:border-zinc-800">
        <CardHeader>
          <CardTitle className="text-base flex items-center gap-2">
            <BarChart3 className="w-4 h-4" />
            Compliance Controls Failed count
            <InfoTip id="sast.res.compliance" />
          </CardTitle>
          <CardDescription>Findings by compliance control (all). Scroll horizontally if needed.</CardDescription>
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

      {/* Row: Policy Violations | Risk scores per finding (area chart) */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Card className="border-zinc-200 dark:border-zinc-800">
          <CardHeader>
            <CardTitle className="text-base flex items-center gap-1">Policy Violations <InfoTip id="sast.res.policy" /></CardTitle>
            <CardDescription>Security standards adherence by violation count</CardDescription>
          </CardHeader>
          <CardContent>
            {!hasPolicyViolationsData ? (
              <div className="flex items-center justify-center h-[260px] text-zinc-500 dark:text-zinc-400 text-sm">No policy violation data to display</div>
            ) : (
              <ScrollArea className="h-[260px] w-full rounded-md border border-zinc-200 dark:border-zinc-800">
                <div className="space-y-4 p-2">
                  {policyViolationsWithCompliance.map((p) => (
                    <div key={p.name} className="flex items-center gap-3">
                      {p.compliance >= 90 ? (
                        <CheckCircle className="h-5 w-5 shrink-0 text-green-500" />
                      ) : p.compliance >= 70 ? (
                        <AlertTriangle className="h-5 w-5 shrink-0 text-amber-500" />
                      ) : (
                        <XCircle className="h-5 w-5 shrink-0 text-red-500" />
                      )}
                      <div className="flex-1 min-w-0">
                        <p className="text-sm font-medium text-zinc-900 dark:text-white truncate" title={p.name}>{p.name}</p>
                        <p className="text-xs text-zinc-500">{p.violations} violations · {p.compliance}% of total</p>
                        <Progress value={p.compliance} className="h-2 mt-1" />
                      </div>
                    </div>
                  ))}
                  <div className="flex justify-between items-center pt-2 border-t border-zinc-200 dark:border-zinc-700">
                    <span className="text-sm text-zinc-600 dark:text-zinc-400">Total violations</span>
                    <span className="text-lg font-bold text-zinc-900 dark:text-white tabular-nums">{totalViolations}</span>
                  </div>
                </div>
              </ScrollArea>
            )}
          </CardContent>
        </Card>

        <Card className="border-zinc-200 dark:border-zinc-800">
          <CardHeader>
            <CardTitle className="text-base flex items-center gap-2">
              <TrendingUp className="w-4 h-4" />
              Risk scores per finding
              <InfoTip id="sast.res.risk_scores" />
            </CardTitle>
            <CardDescription>Risk score by finding (top 24, descending)</CardDescription>
          </CardHeader>
          <CardContent>
            {!hasRiskScoresData ? (
              <div className="flex items-center justify-center min-h-[260px] text-zinc-500 dark:text-zinc-400 text-sm">No risk score data to display</div>
            ) : (
              <ChartContainer config={riskScoreAreaChartConfig} className="aspect-auto h-[260px] w-full pb-8 cursor-pointer">
                <AreaChart data={riskScoresAreaData} margin={{ top: 8, right: 8, bottom: 28, left: 0 }}>
                  <defs>
                    <linearGradient id="fillSastRiskScore" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="hsl(217 91% 60%)" stopOpacity={0.8} />
                      <stop offset="95%" stopColor="hsl(217 91% 60%)" stopOpacity={0.1} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid vertical={false} className="stroke-zinc-200 dark:stroke-zinc-800" />
                  <XAxis
                    dataKey="finding"
                    tickLine={false}
                    axisLine={false}
                    tickMargin={8}
                    minTickGap={16}
                    height={56}
                    interval={0}
                  />
                  <YAxis hide domain={[0, 10]} />
                  <ChartTooltip
                    cursor={false}
                    content={
                      <ChartTooltipContent
                        className="gap-2 py-2.5 px-3 min-w-48"
                        hideIndicator
                        formatter={(value) => ["Risk score  :  ",value]}
                        labelFormatter={(_, payload) => {
                          const fullName = (payload?.[0]?.payload as { fullName?: string } | undefined)?.fullName;
                          return fullName ? <span className="block font-medium text-zinc-900 dark:text-zinc-100">{fullName}</span> : "—";
                        }}
                      />
                    }
                  />
                  <Area type="monotone" dataKey="score" fill="url(#fillSastRiskScore)" stroke="hsl(217 91% 60%)" strokeWidth={2} />
                </AreaChart>
              </ChartContainer>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Remediation Metrics */}
      {remediationMetrics && (
        <Card className="border-zinc-200 dark:border-zinc-800 shadow-sm">
          <CardHeader>
            <CardTitle className="text-xl flex items-center gap-1">Remediation Metrics <InfoTip id="sast.res.remed.section" /></CardTitle>
            <CardDescription>Performance and efficiency tracking</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6">
              {(() => {
                const [days, hours, minutes] = remediationMetrics.mean_time_to_remediate;
                const totalDays = days + hours / 24 + minutes / (60 * 24);
                const targetDays = 3;
                const progress = totalDays <= 0 ? 100 : Math.min(100, (targetDays / totalDays) * 100);
                const delta = totalDays > 0 && targetDays > 0 ? `${Math.round(((totalDays - targetDays) / targetDays) * 100)}%` : "—";
                return (
                  <div className="space-y-3">
                    <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-teal-500/15 dark:bg-teal-500/10">
                      <Clock className="h-5 w-5 text-teal-600 dark:text-teal-400" />
                    </div>
                    <p className="text-sm font-medium text-zinc-600 dark:text-zinc-400 flex items-center gap-1">Mean Time to Remediate <InfoTip id="sast.res.remed.mttr" /></p>
                    <p className="text-2xl font-bold text-zinc-900 dark:text-white">
                      {totalDays < 0.1 && totalDays >= 0 ? "<0.1 days" : `${totalDays.toFixed(1)} days`}
                    </p>
                    <p className="text-xs text-zinc-500 dark:text-zinc-400">Target: {targetDays} days</p>
                    <div className="flex items-center gap-2">
                      <Progress value={progress} className="h-2 flex-1" />
                      <span className="text-xs text-zinc-500 tabular-nums shrink-0">{delta}</span>
                    </div>
                  </div>
                );
              })()}

              {(() => {
                const fixed = remediationMetrics.critical_issues_fixed;
                // risk_metrics counts every Critical finding of the scan, fixed ones included: fixed / all Critical
                // (was fixed / (fixed + all Critical), which never passed 50%)
                const totalCritical = criticalCount;
                const pct = totalCritical > 0 ? Math.min(100, Math.round((fixed / totalCritical) * 100)) : 0;
                const targetPct = 95;
                const progress = Math.min(100, (pct / targetPct) * 100);
                const delta = pct >= targetPct ? "+0%" : `+${targetPct - pct}%`;
                return (
                  <div className="space-y-3">
                    <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-teal-500/15 dark:bg-teal-500/10">
                      <CheckCircle className="h-5 w-5 text-teal-600 dark:text-teal-400" />
                    </div>
                    <p className="text-sm font-medium text-zinc-600 dark:text-zinc-400 flex items-center gap-1">Critical Issues Fixed <InfoTip id="sast.res.remed.critical_fixed" /></p>
                    <p className="text-2xl font-bold text-zinc-900 dark:text-white">{pct}%</p>
                    <p className="text-xs text-zinc-500 dark:text-zinc-400">Target: {targetPct}%</p>
                    <div className="flex items-center gap-2">
                      <Progress value={progress} className="h-2 flex-1" />
                      <span className="text-xs text-zinc-500 tabular-nums shrink-0">{delta}</span>
                    </div>
                  </div>
                );
              })()}

              {(() => {
                const backlog = remediationMetrics.high_priority_backlog;
                const target = 10;
                const progress = target <= 0 ? 100 : Math.max(0, Math.min(100, (1 - (backlog - target) / Math.max(target, backlog)) * 100));
                const delta = backlog > target ? `-${backlog - target}` : backlog < target ? `+${target - backlog}` : "0";
                return (
                  <div className="space-y-3">
                    <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-teal-500/15 dark:bg-teal-500/10">
                      <Crosshair className="h-5 w-5 text-teal-600 dark:text-teal-400" />
                    </div>
                    <p className="text-sm font-medium text-zinc-600 dark:text-zinc-400 flex items-center gap-1">High Priority Backlog <InfoTip id="sast.res.remed.backlog" /></p>
                    <p className="text-2xl font-bold text-zinc-900 dark:text-white">{backlog}</p>
                    <p className="text-xs text-zinc-500 dark:text-zinc-400">Target: {target}</p>
                    <div className="flex items-center gap-2">
                      <Progress value={backlog <= target ? 100 : Math.max(0, (target / backlog) * 100)} className="h-2 flex-1 [&>div]:bg-orange-500" />
                      <span className="text-xs text-zinc-500 tabular-nums shrink-0">{delta}</span>
                    </div>
                  </div>
                );
              })()}

              {(() => {
                const velocity = remediationMetrics.remediation_velocity;
                const target = 20;
                const progress = Math.min(100, (velocity / target) * 100);
                const delta = velocity >= target ? "+0" : `+${target - velocity}`;
                return (
                  <div className="space-y-3">
                    <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-teal-500/15 dark:bg-teal-500/10">
                      <Activity className="h-5 w-5 text-teal-600 dark:text-teal-400" />
                    </div>
                    <p className="text-sm font-medium text-zinc-600 dark:text-zinc-400 flex items-center gap-1">Remediation Velocity <InfoTip id="sast.res.remed.velocity" /></p>
                    <p className="text-2xl font-bold text-zinc-900 dark:text-white">{velocity}/week</p>
                    <p className="text-xs text-zinc-500 dark:text-zinc-400">Target: {target}/week</p>
                    <div className="flex items-center gap-2">
                      <Progress value={progress} className="h-2 flex-1" />
                      <span className="text-xs text-zinc-500 tabular-nums shrink-0">{delta}</span>
                    </div>
                  </div>
                );
              })()}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

/** Count from API finding list (owasp_top_10, compliance_controls, cves can be array or object) */
function countFindingField(val: unknown): number {
  if (val == null) return 0;
  if (Array.isArray(val)) return val.length;
  if (typeof val === "object") return Object.keys(val).length;
  return 0;
}

function SASTResultsAgentView({
  conversationId,
  teamId,
  isCicdContext,
  integrationId,
  origin,
  router,
  onDownloadReport,
  isExporting = false,
  dashboard,
  scanMetadata,
  findings,
  integrationSettings,
  onIntegrationSettingsUpdated,
  onFindingsUpdated,
}: {
  conversationId?: number;
  teamId?: string;
  isCicdContext: boolean;
  integrationId: string | null;
  origin: string | null;
  router: ReturnType<typeof useRouter>;
  onDownloadReport?: () => void;
  isExporting?: boolean;
  dashboard?: SastDashboardData | null;
  scanMetadata?: SastScanMetadata | Record<string, unknown> | null;
  findings?: SastFinding[] | null;
  integrationSettings?: Record<string, unknown> | null;
  onIntegrationSettingsUpdated?: () => void;
  onFindingsUpdated?: () => void;
}) {
  const [activeTab, setActiveTab] = useState<"results" | "ticketing">("results");
  const [jiraProjectId, setJiraProjectId] = useState("");
  const [autoCreateTickets, setAutoCreateTickets] = useState(false);
  const [selectedRowIds, setSelectedRowIds] = useState<Set<string>>(new Set());
  const [selectedFinding, setSelectedFinding] = useState<SastFinding | null>(null);
  const [findingsSearchQuery, setFindingsSearchQuery] = useState("");
  const [filterImpact, setFilterImpact] = useState<string>("all");
  type RiskScoreFilter = "all" | "critical" | "high" | "medium" | "low";
  const [filterRiskScore, setFilterRiskScore] = useState<RiskScoreFilter>("all");
  const queryClient = useQueryClient();

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
    let list = findingsList;
    const q = findingsSearchQuery.trim().toLowerCase();
    if (q) {
      list = list.filter((f) => {
        const title = ((f.title ?? "") + "").toLowerCase();
        const description = ((f.description ?? "") + "").toLowerCase();
        const impact = ((f.impact ?? "") + "").toLowerCase();
        const status = ((f.status ?? "") + "").toLowerCase();
        const suggestedFix = ((f.suggested_fix ?? "") + "").toLowerCase();
        const location = ((f.location ?? "") + "").toLowerCase();
        return title.includes(q) || description.includes(q) || impact.includes(q) || status.includes(q) || suggestedFix.includes(q) || location.includes(q);
      });
    }
    if (filterImpact && filterImpact !== "all") {
      list = list.filter((f) => (f.impact ?? "").trim().toLowerCase() === filterImpact.toLowerCase());
    }
    list = list.filter((f) => matchesRiskScoreFilter(f.risk_score ?? null, filterRiskScore));
    return list;
  }, [findingsList, findingsSearchQuery, filterImpact, filterRiskScore]);

  const hasActiveFindingsFilters =
    findingsSearchQuery.trim() !== "" || filterImpact !== "all" || filterRiskScore !== "all";
  const clearFindingsFilters = () => {
    setFindingsSearchQuery("");
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
        type: "sast",
        scan_id: conversationId!,
        data: payload,
      }),
    onSuccess: () => {
      onIntegrationSettingsUpdated?.();
      const tid = parseInt(teamId ?? "0", 10);
      if (conversationId != null && tid > 0) {
        queryClient.invalidateQueries({ queryKey: ["sast-conversation-data", tid, conversationId] });
      }
      toast.success("Ticketing settings saved");
    },
    onError: (err) => {
      showErrorToast(err, "Failed to save ticketing settings");
    },
  });

  const hasTicketingTab = !isCicdContext && teamId && conversationId != null && onIntegrationSettingsUpdated != null;

  const totalFindings = findings?.length ?? 0;

  const toggleRowSelection = (findingId: string) => {
    setSelectedRowIds((prev) => {
      const next = new Set(prev);
      if (next.has(findingId)) next.delete(findingId);
      else next.add(findingId);
      return next;
    });
  };

  const toggleSelectAll = () => {
    if (!filteredFindingsList.length) return;
    if (selectedRowIds.size === filteredFindingsList.length) {
      setSelectedRowIds(new Set());
    } else {
      setSelectedRowIds(new Set(filteredFindingsList.map((f) => f.id)));
    }
  };

  const createJiraTicketsMutation = useMutation({
    mutationFn: async () => {
      const tid = parseInt(teamId ?? "0", 10);
      if (!conversationId || Number.isNaN(tid)) throw new Error("Missing team or scan");
      const selected = (findingsList ?? []).filter((f) => selectedRowIds.has(f.id));
      if (selected.length === 0) throw new Error("No findings selected");

      const impactCounts: Record<string, number> = {};
      for (const f of selected) {
        const impact = (f.impact ?? "Unknown").trim() || "Unknown";
        impactCounts[impact] = (impactCounts[impact] ?? 0) + 1;
      }
      const RISK_ORDER = ["Critical", "High", "Medium", "Low"] as const;
      let summary =
        Object.entries(impactCounts)
          .sort(([a], [b]) => RISK_ORDER.indexOf(a as (typeof RISK_ORDER)[number]) - RISK_ORDER.indexOf(b as (typeof RISK_ORDER)[number]))
          .map(([impact, count]) => `${count} ${impact}`)
          .join(", ") || `${selected.length} finding(s)`;
      summary = summary + " - Vulnerabilities found in SAST scan";

      const descSections = selected.map((f, idx) => {
        const parts: string[] = [`--- Finding ${idx + 1} ---`];
        parts.push(`Title: ${(f.title ?? "Untitled").trim() || "Untitled"}`);
        if ((f.description ?? "").trim()) parts.push(`Description: ${f.description!.trim()}`);
        if ((f.impact ?? "").trim()) parts.push(`Impact: ${f.impact!.trim()}`);
        return parts.join("\n");
      });
      const description = descSections.join("\n\n");

      await createTicket(tid, "sast", conversationId, {
        ticket_type: "jira",
        summary,
        description,
        finding_ids: selected.map((f) => f.id),
      });
    },
    onMutate: () => {
      const toastId = toast.loading("Creating Jira ticket(s)...");
      return { toastId };
    },
    onSuccess: (_data, _variables, context) => {
      if (context?.toastId != null) {
        toast.success(`Jira ticket(s) created for ${selectedRowIds.size} finding(s)`, { id: context.toastId });
      } else {
        toast.success(`Jira ticket(s) created for ${selectedRowIds.size} finding(s)`);
      }
      setSelectedRowIds(new Set());
    },
    onError: (err, _variables, context) => {
      if (context?.toastId != null) toast.dismiss(context.toastId);
      showErrorToast(err, "Failed to create Jira ticket(s)");
    },
  });

  const toggleFindingMutation = useMutation({
    mutationFn: ({ finding_id, state }: { finding_id: string; state: "fixed" | "ignored" | "in_progress" | "not_started" }) => {
      const tid = parseInt(teamId ?? "0", 10);
      if (!conversationId || Number.isNaN(tid)) throw new Error("Missing team or scan");
      return toggleFindingState({ team_id: tid, type: "sast", scan_id: conversationId, finding_id, state });
    },
    onSuccess: () => {
      onFindingsUpdated?.();
      const tid = parseInt(teamId ?? "0", 10);
      if (conversationId != null && tid > 0) {
        queryClient.invalidateQueries({ queryKey: ["sast-conversation-data", tid, conversationId] });
      }
      toast.success("Finding status updated");
    },
    onError: (err) => {
      showErrorToast(err, "Failed to update finding status");
    },
  });

  return (
    <div className="container mx-auto p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          {(conversationId || isCicdContext) && (
            <Button
              variant="outline"
              size="icon"
                aria-label="Back"
              onClick={() => {
                const backRoute = isCicdContext && integrationId
                  ? `/home/ci_cd/${integrationId}`
                  : origin === "chat"
                    ? (teamId ? `/${teamId}/sast/${conversationId}` : `/home/sast/${conversationId}`)
                    : (teamId ? `/${teamId}/sast` : "/home/sast");
                router.push(backRoute);
              }}
              className="cursor-pointer"
            >
              <ArrowLeft className="h-4 w-4" />
            </Button>
          )}
          <div>
            <h1 className="text-3xl font-bold text-zinc-900 dark:text-white">SAST Scan Results</h1>
            <p className="text-sm text-zinc-600 dark:text-zinc-400 mt-1">
              Agent analysis by logical component
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
              onClick={() => router.push(`/${teamId}/sast/${conversationId}`)}
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
          inputId="sast-jira-project-id"
        />
      ) : (
        <>
      {scanMetadata && (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-5 gap-4">
          {"code_coverage" in scanMetadata && scanMetadata.code_coverage != null && (
            <Card className="border-zinc-200 dark:border-zinc-800">
              <CardContent className="pt-4 pb-4 flex items-center gap-3">
                <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-blue-100 dark:bg-blue-900/30 text-blue-600 dark:text-blue-400">
                  <Percent className="h-5 w-5" />
                </div>
                <div className="min-w-0">
                  <p className="text-xs font-medium text-zinc-500 dark:text-zinc-400 flex items-center gap-1">Code coverage <InfoTip id="sast.res.coverage" /></p>
                  <p className="text-lg font-semibold text-zinc-900 dark:text-zinc-100">{Number(scanMetadata.code_coverage).toFixed(1)}%</p>
                </div>
              </CardContent>
            </Card>
          )}
          {"files_scanned" in scanMetadata && scanMetadata.files_scanned != null && "total_files" in scanMetadata && scanMetadata.total_files != null && (
            <Card className="border-zinc-200 dark:border-zinc-800">
              <CardContent className="pt-4 pb-4 flex items-center gap-3">
                <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-emerald-100 dark:bg-emerald-900/30 text-emerald-600 dark:text-emerald-400">
                  <FileStack className="h-5 w-5" />
                </div>
                <div className="min-w-0">
                  <p className="text-xs font-medium text-zinc-500 dark:text-zinc-400 flex items-center gap-1">Files scanned <InfoTip id="sast.res.files" /></p>
                  <p className="text-lg font-semibold text-zinc-900 dark:text-zinc-100">{Number(scanMetadata.files_scanned)} / {Number(scanMetadata.total_files)}</p>
                </div>
              </CardContent>
            </Card>
          )}
          {"repo_url" in scanMetadata && scanMetadata.repo_url != null && String(scanMetadata.repo_url).trim() !== "" && (
            <Card className="border-zinc-200 dark:border-zinc-800 lg:col-span-1 xl:col-span-1">
              <CardContent className="pt-4 pb-4 flex items-center gap-3">
                <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-violet-100 dark:bg-violet-900/30 text-violet-600 dark:text-violet-400">
                  <Github className="h-5 w-5" />
                </div>
                <div className="min-w-0 flex-1 overflow-hidden">
                  <p className="text-xs font-medium text-zinc-500 dark:text-zinc-400 flex items-center gap-1">Repository <InfoTip id="results.meta.repository" /></p>
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
                  <p className="text-xs font-medium text-zinc-500 dark:text-zinc-400 flex items-center gap-1">Branch <InfoTip id="results.meta.branch" /></p>
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
                  <p className="text-xs font-medium text-zinc-500 dark:text-zinc-400 flex items-center gap-1">Source <InfoTip id="results.meta.source" /></p>
                  <p className="text-sm font-semibold text-zinc-900 dark:text-zinc-100">{scanMetadata.zip_file_used ? "ZIP upload" : "Repository"}</p>
                </div>
              </CardContent>
            </Card>
          )}
        </div>
      )}
      {dashboard && (
        <SASTDashboardCharts dashboard={dashboard} />
      )}

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-1">Findings <InfoTip id="results.findings" /></CardTitle>
          <CardDescription>
            {findings && findings.length > 0
              ? `${findings.length} findings. Select rows to create Jira tickets; use Action to change finding state.`
              : "No findings to display."}
          </CardDescription>
        </CardHeader>
        <CardContent>
          {findings && findings.length > 0 ? (
            <>
              <div className="flex flex-wrap items-center gap-3 mb-4">
                <div className="relative flex-1 min-w-[200px] max-w-sm">
                  <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-zinc-400" />
                  <Input
                    type="search"
                    placeholder="Search by title, URL, description..."
                    value={findingsSearchQuery}
                    onChange={(e) => setFindingsSearchQuery(e.target.value)}
                    className="pl-9 h-9 cursor-text"
                    aria-label="Search findings table"
                  />
                </div>
                <InfoTip id="sast.res.search" className="-ml-2" />
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
                <InfoTip id="results.filter.impact" className="-ml-2" />
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
                  <InfoTip id="sast.res.filter.risk" className="-ml-2" />
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
              <FindingSelectionMenu
                selectedCount={selectedRowIds.size}
                onClearSelection={() => setSelectedRowIds(new Set())}
                jiraOnClickHandler={() => createJiraTicketsMutation.mutate()}
                ticketType="jira"
                isJiraCreating={createJiraTicketsMutation.isPending}
              />
              <ScrollArea className="h-[500px] w-full rounded-md border border-zinc-200 dark:border-zinc-800">
                <div className="min-w-max">
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead className="min-w-[64px] w-16">
                          <div className="flex items-center gap-0.5">
                            <Checkbox
                              checked={filteredFindingsList.length > 0 && selectedRowIds.size === filteredFindingsList.length}
                              onCheckedChange={toggleSelectAll}
                              aria-label="Select all rows"
                              className="cursor-pointer"
                            />
                            <InfoTip id="results.select_all" />
                          </div>
                        </TableHead>
                        <TableHead className="min-w-[180px]">Title</TableHead>
                        <TableHead className="min-w-[200px]"><span className="inline-flex items-center gap-1">Description <InfoTip id="sast.res.description" /></span></TableHead>
                        <TableHead className="min-w-[90px]"><span className="inline-flex items-center gap-1">Impact <InfoTip id="results.table.impact" /></span></TableHead>
                        <TableHead className="min-w-[90px] text-center"><span className="inline-flex items-center gap-1">Risk score <InfoTip id="sast.res.table.risk" /></span></TableHead>
                        <TableHead className="min-w-[100px]"><span className="inline-flex items-center gap-1">Status <InfoTip id="results.table.status" /></span></TableHead>
                        <TableHead className="min-w-[90px] text-center"><span className="inline-flex items-center gap-1">OWASP count <InfoTip id="results.table.owasp" /></span></TableHead>
                        <TableHead className="min-w-[100px] text-center"><span className="inline-flex items-center gap-1">Compliance count <InfoTip id="results.table.compliance" /></span></TableHead>
                        <TableHead className="min-w-[70px] text-center"><span className="inline-flex items-center gap-1">CVE count <InfoTip id="sast.res.table.cves" /></span></TableHead>
                        <TableHead className="min-w-[120px] text-right"><span className="inline-flex items-center gap-1">Actions <InfoTip id="results.finding.action" /></span></TableHead>
                      </TableRow>
                    </TableHeader>
                  <TableBody>
                    {filteredFindingsList.map((f) => {
                      const impact = (f.impact ?? "").trim() || "—";
                      const desc = (f.description ?? "").trim();
                      const descTrunc = desc.length > 80 ? `${desc.slice(0, 80)}…` : desc || "—";
                      const statusLabel = (f.status ?? "not_started").replace(/_/g, " ");
                      const riskScore = f.risk_score;
                      const owaspCount = countFindingField(f.owasp_top_10);
                      const complianceCount = countFindingField(f.compliance_controls);
                      const cveCount = countFindingField(f.cves);
                      return (
                        <TableRow
                          key={f.id}
                          className={`hover:bg-zinc-50 dark:hover:bg-zinc-800/50 ${selectedRowIds.has(f.id) ? "bg-zinc-100 dark:bg-zinc-800/70" : ""}`}
                        >
                          <TableCell onClick={(e) => e.stopPropagation()} className="min-w-[64px] w-16">
                            {/* infotip-shared: row selection, explained by the (i) on the select-all box in the header */}
                            <Checkbox
                              checked={selectedRowIds.has(f.id)}
                              onCheckedChange={() => toggleRowSelection(f.id)}
                              aria-label={`Select finding ${f.title ?? f.id}`}
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
                          <TableCell className="text-sm text-zinc-600 dark:text-zinc-400" title={desc || undefined}>
                            {descTrunc}
                          </TableCell>
                          <TableCell>
                            <Badge variant="outline" className={getImpactBadgeClass(impact)}>
                              {impact}
                            </Badge>
                          </TableCell>
                          <TableCell className="text-center">
                            <span
                              className={`inline-flex items-center justify-center min-w-9 px-2 py-1 rounded-md text-xs font-semibold tabular-nums ${
                                riskScore >= 4 ? "bg-red-100 text-red-800 dark:bg-red-900/40 dark:text-red-200" :
                                riskScore >= 3 ? "bg-orange-100 text-orange-800 dark:bg-orange-900/40 dark:text-orange-200" :
                                riskScore >= 2 ? "bg-amber-100 text-amber-800 dark:bg-amber-900/40 dark:text-amber-200" :
                                "bg-emerald-100 text-emerald-800 dark:bg-emerald-900/40 dark:text-emerald-200"
                              }`}
                              title="Risk score"
                            >
                              {riskScore}
                            </span>
                          </TableCell>
                          <TableCell>
                            <span
                              className={`inline-flex items-center justify-center px-2.5 py-1 rounded-md text-xs font-medium capitalize ${getFindingStatusBadgeClass(f.status ?? "not_started")}`}
                              title="Finding status"
                            >
                              {statusLabel}
                            </span>
                          </TableCell>
                          <TableCell className="text-center">
                            <span
                              className="inline-flex items-center justify-center min-w-9 px-2 py-1 rounded-md text-xs font-semibold tabular-nums bg-violet-100 text-violet-800 dark:bg-violet-900/40 dark:text-violet-200"
                              title="OWASP Top 10 count"
                            >
                              {owaspCount}
                            </span>
                          </TableCell>
                          <TableCell className="text-center">
                            <span
                              className="inline-flex items-center justify-center min-w-9 px-2 py-1 rounded-md text-xs font-semibold tabular-nums bg-sky-100 text-sky-800 dark:bg-sky-900/40 dark:text-sky-200"
                              title="Compliance controls count"
                            >
                              {complianceCount}
                            </span>
                          </TableCell>
                          <TableCell className="text-center">
                            <span
                              className="inline-flex items-center justify-center min-w-9 px-2 py-1 rounded-md text-xs font-semibold tabular-nums bg-amber-100 text-amber-800 dark:bg-amber-900/40 dark:text-amber-200"
                              title="CVE count"
                            >
                              {cveCount}
                            </span>
                          </TableCell>
                          <TableCell className="text-right" onClick={(e) => e.stopPropagation()}>
                            <DropdownMenu>
                              {/* infotip-shared: explained by the (i) on the Actions column header */}
                              <DropdownMenuTrigger asChild>
                                <Button
                                  variant="outline"
                                  size="sm"
                                  className="cursor-pointer gap-1.5 h-8 shrink-0"
                                  aria-label="Finding actions"
                                >
                                  <Pencil className="h-3.5 w-3.5 opacity-70" />
                                  Action
                                </Button>
                              </DropdownMenuTrigger>
                              <DropdownMenuContent align="end">
                                <DropdownMenuItem
                                  className="cursor-pointer gap-2"
                                  onClick={() => toggleFindingMutation.mutate({ finding_id: f.id, state: "fixed" })}
                                  disabled={toggleFindingMutation.isPending}
                                >
                                  <CheckCircle className="h-4 w-4" />
                                  Mark as Fixed
                                </DropdownMenuItem>
                                <DropdownMenuItem
                                  className="cursor-pointer gap-2"
                                  onClick={() => toggleFindingMutation.mutate({ finding_id: f.id, state: "ignored" })}
                                  disabled={toggleFindingMutation.isPending}
                                >
                                  <EyeOff className="h-4 w-4" />
                                  Mark as Ignored
                                </DropdownMenuItem>
                                <DropdownMenuItem
                                  className="cursor-pointer gap-2"
                                  onClick={() => toggleFindingMutation.mutate({ finding_id: f.id, state: "in_progress" })}
                                  disabled={toggleFindingMutation.isPending}
                                >
                                  <Loader2 className="h-4 w-4" />
                                  Mark as In progress
                                </DropdownMenuItem>
                                <DropdownMenuItem
                                  className="cursor-pointer gap-2"
                                  onClick={() => toggleFindingMutation.mutate({ finding_id: f.id, state: "not_started" })}
                                  disabled={toggleFindingMutation.isPending}
                                >
                                  <Circle className="h-4 w-4" />
                                  Mark as Not started
                                </DropdownMenuItem>
                              </DropdownMenuContent>
                            </DropdownMenu>
                          </TableCell>
                        </TableRow>
                      );
                    })}
                  </TableBody>
                  </Table>
                </div>
                <ScrollBar orientation="horizontal" />
              </ScrollArea>
            </>
          ) : (
            <div className="flex items-center justify-center py-12 text-zinc-500 dark:text-zinc-400 text-sm">
              No findings to display.
            </div>
          )}
        </CardContent>
      </Card>

      <Dialog open={!!selectedFinding} onOpenChange={(open) => !open && setSelectedFinding(null)}>
        <DialogContent className="sm:max-w-3xl max-h-[90vh] flex flex-col p-0 gap-0 overflow-hidden bg-zinc-900">
          <DialogHeader className="px-6 pt-6 pb-2 shrink-0 border-b border-zinc-200 dark:border-zinc-800">
            <DialogTitle className="pr-8">
              {selectedFinding ? ((selectedFinding.title ?? "").trim() || "Finding details") : "Finding details"}
            </DialogTitle>
          </DialogHeader>
          {selectedFinding && (
            <ScrollArea className="h-[70vh] min-h-[200px] w-full px-6 pb-6">
              <div className="space-y-4 pt-4 pr-4 pb-4">
                {(selectedFinding.description ?? "").trim() && (
                  <div>
                    <div className="text-xs font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400 mb-1">Description</div>
                    <p className="text-sm text-zinc-800 dark:text-zinc-200 whitespace-pre-wrap">{selectedFinding.description!.trim()}</p>
                  </div>
                )}
                {(selectedFinding.location ?? "").trim() && (
                  <div>
                    <div className="text-xs font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400 mb-1">Location</div>
                    <p className="text-sm font-mono text-zinc-800 dark:text-zinc-200">{selectedFinding.location!.trim()}</p>
                  </div>
                )}
                {(selectedFinding.suggested_fix ?? "").trim() && (
                  <div>
                    <div className="text-xs font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400 mb-1">Suggested fix</div>
                    <p className="text-sm text-zinc-800 dark:text-zinc-200 whitespace-pre-wrap">{selectedFinding.suggested_fix!.trim()}</p>
                  </div>
                )}
                {(selectedFinding.snippet ?? "").trim() && (
                  <div>
                    <div className="text-xs font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400 mb-1">Code snippet</div>
                    <pre className="text-xs bg-zinc-100 dark:bg-zinc-800 p-3 rounded-md overflow-x-auto whitespace-pre-wrap font-mono text-zinc-800 dark:text-zinc-200 border border-zinc-200 dark:border-zinc-700">
                      {selectedFinding.snippet!.trim()}
                    </pre>
                  </div>
                )}
                <div>
                  <div className="text-xs font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400 mb-1">Impact</div>
                  <Badge variant="outline" className={getImpactBadgeClass((selectedFinding.impact ?? "").trim() || "—")}>
                    {(selectedFinding.impact ?? "").trim() || "—"}
                  </Badge>
                </div>
                <div>
                  <div className="text-xs font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400 mb-1">Risk score</div>
                  <span className="text-sm font-medium tabular-nums">{selectedFinding.risk_score}</span>
                </div>
                <div>
                  <div className="text-xs font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400 mb-1">Status</div>
                  <span className={`inline-flex items-center px-2.5 py-1 rounded-md text-xs font-medium capitalize ${getFindingStatusBadgeClass(selectedFinding.status ?? "not_started")}`}>
                    {(selectedFinding.status ?? "not_started").replace(/_/g, " ")}
                  </span>
                </div>
                {getOwaspComplianceEntries(selectedFinding.owasp_top_10 as OwaspOrCompliance).length > 0 && (
                  <div>
                    <div className="text-xs font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400 mb-1">OWASP Top 10</div>
                    <div className="flex flex-wrap gap-1">
                      {getOwaspComplianceEntries(selectedFinding.owasp_top_10 as OwaspOrCompliance).map(([, description], i) => (
                        <Badge key={i} variant="secondary" className="text-xs bg-violet-100 dark:bg-violet-900/40 text-violet-800 dark:text-violet-200">
                          {description}
                        </Badge>
                      ))}
                    </div>
                  </div>
                )}
                {getOwaspComplianceEntries(selectedFinding.compliance_controls as OwaspOrCompliance).length > 0 && (
                  <div>
                    <div className="text-xs font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400 mb-1">Compliance controls</div>
                    <div className="flex flex-wrap gap-1">
                      {getOwaspComplianceEntries(selectedFinding.compliance_controls as OwaspOrCompliance).map(([, description], i) => (
                        <Badge key={i} variant="outline" className="text-xs">
                          {description}
                        </Badge>
                      ))}
                    </div>
                  </div>
                )}
                {(() => {
                  const cves = selectedFinding.cves;
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

                {/* AI Remediation */}
                <RemediationPanel
                  teamId={teamId ?? ""}
                  scanType="sast"
                  scanId={conversationId ?? 0}
                  findingId={selectedFinding.id}
                  existingRemediation={selectedFinding.remediation}
                />
              </div>
            </ScrollArea>
          )}
        </DialogContent>
      </Dialog>
        </>
      )}
    </div>
  );
}

export default function SASTResults({ conversationId, dashboard, findings, teamId: teamIdProp, scanMetadata, integrationSettings, onIntegrationSettingsUpdated, onFindingsUpdated }: SASTResultsProps) {
  const router = useRouter();
  const pathname = usePathname();
  const searchParams = useSearchParams();
  // No query param â†’ back goes to SAST list; origin=chat â†’ back goes to chat (scan_id) page
  const origin = searchParams.get("origin");

  // Check if we're in CI/CD context and extract integration_id
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
  const teamId = teamIdProp ?? (params?.team_id as string | undefined);

  const exportMutation = useMutation({
    mutationFn: () => {
      const tid = teamId ? parseInt(teamId, 10) : NaN;
      if (conversationId == null || Number.isNaN(tid)) throw new Error("Missing team or scan");
      return getExportResults(tid, conversationId);
    },
    onSuccess: (data) => {
      const blob = new Blob([data], { type: "application/pdf" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `sast_scan_${conversationId}_report.pdf`;
      a.click();
      URL.revokeObjectURL(url);
    },
    onError: (err) => {
      showErrorToast(err, "Failed to download scan report");
    },
  });

  const handleDownloadReport = () => exportMutation.mutate();
  const isExporting = exportMutation.isPending;

  const hasFindings = Array.isArray(findings) && findings.length > 0;
  const hasDashboard = dashboard != null;
  if (!hasFindings && !hasDashboard) {
    return (
      <div className="container mx-auto p-6 space-y-6">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-4">
            {(conversationId || isCicdContext) && (
              <Button
                variant="outline"
                size="icon"
                aria-label="Back"
                onClick={() => {
                  const backRoute = isCicdContext && integrationId
                    ? `/home/ci_cd/${integrationId}`
                    : origin === "chat"
                      ? (teamId ? `/${teamId}/sast/${conversationId}` : `/home/sast/${conversationId}`)
                      : (teamId ? `/${teamId}/sast` : "/home/sast");
                  router.push(backRoute);
                }}
                className="cursor-pointer"
              >
              <ArrowLeft className="h-4 w-4" />
            </Button>
            )}
            <h1 className="text-3xl font-bold text-zinc-900 dark:text-white">SAST Scan Results</h1>
          </div>
          {!isCicdContext && teamId && conversationId != null && (
            <Button
              variant="default"
              className="cursor-pointer bg-blue-600 hover:bg-blue-700 text-white"
              onClick={() => router.push(`/${teamId}/sast/${conversationId}`)}
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
    <SASTResultsAgentView
      conversationId={conversationId}
      teamId={teamId}
      isCicdContext={isCicdContext}
      integrationId={integrationId}
      origin={origin}
      router={router}
      onDownloadReport={teamId && conversationId != null ? handleDownloadReport : undefined}
      isExporting={isExporting}
      dashboard={dashboard}
      scanMetadata={scanMetadata}
      findings={findings}
      integrationSettings={integrationSettings}
      onIntegrationSettingsUpdated={onIntegrationSettingsUpdated}
      onFindingsUpdated={onFindingsUpdated}
    />
  );
}
