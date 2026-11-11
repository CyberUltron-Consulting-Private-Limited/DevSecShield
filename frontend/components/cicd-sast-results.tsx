"use client";

import { useState } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { AlertTriangle, ArrowLeft, BarChart3, PieChart, TrendingUp } from "lucide-react";
import { ScrollArea, ScrollBar } from "@/components/ui/scroll-area";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { useRouter, useParams } from "next/navigation";
import { type SastDashboardData } from "@/utils/backend_api";
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

// Agent output format (aligned with SASTResults)
type OwaspOrComplianceItem = Record<string, string>;
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

function getImpactBadgeClass(impact: string): string {
  const i = (impact || "").toLowerCase();
  if (i === "critical") return "bg-red-600 hover:bg-red-700 text-white";
  if (i === "high") return "bg-orange-500 hover:bg-orange-600 text-white";
  if (i === "medium") return "bg-amber-500 hover:bg-amber-600 text-white";
  if (i === "low") return "bg-blue-500 hover:bg-blue-600 text-white";
  return "bg-zinc-500 hover:bg-zinc-600 text-white";
}

const RISK_ORDER = ["Critical", "High", "Medium", "Low"] as const;

const RISK_SCORE_FOR_IMPACT: Record<string, number> = {
  critical: 10,
  high: 7.5,
  medium: 5,
  low: 2.5,
};

/** Build dashboard metrics from components (same shape as backend get_cicd_sast_dashboard_data) so charts always have data. */
function deriveDashboardFromComponents(components: SastAgentLogicalComponent[]): SastDashboardData {
  const owasp_top_10_metrics: Record<string, number> = {};
  const compliance_controls_metrics: Record<string, number> = {};
  const risk_metrics: Record<string, number> = { Low: 0, Medium: 0, High: 0, Critical: 0 };
  const cves_per_vulnerability: Record<string, number> = {};
  const policy_violations: Record<string, number> = {};
  const risk_scores_per_finding: Record<string, number> = {};

  for (const item of components) {
    for (const vuln of item.vulnerabilities ?? []) {
      const impactRaw = (vuln.impact ?? "").trim();
      const impactKey = impactRaw.charAt(0).toUpperCase() + impactRaw.slice(1).toLowerCase();
      if (impactKey === "Critical" || impactKey === "High" || impactKey === "Medium" || impactKey === "Low") {
        risk_metrics[impactKey] = (risk_metrics[impactKey] ?? 0) + 1;
      }
      const impactLower = impactRaw.toLowerCase();
      if (impactLower in RISK_SCORE_FOR_IMPACT) {
        risk_scores_per_finding[vuln.title ?? ""] = RISK_SCORE_FOR_IMPACT[impactLower];
      }
      for (const [, value] of getOwaspComplianceEntries(vuln.owasp_top_10)) {
        if (value) owasp_top_10_metrics[value] = (owasp_top_10_metrics[value] ?? 0) + 1;
      }
      for (const [, value] of getOwaspComplianceEntries(vuln.compliance_controls)) {
        if (value) compliance_controls_metrics[value] = (compliance_controls_metrics[value] ?? 0) + 1;
      }
      const cves = vuln.cves;
      if (cves && typeof cves === "object") {
        if (Array.isArray(cves)) {
          for (const c of cves) {
            const s = c != null ? String(c).trim() : "";
            if (s) cves_per_vulnerability[s] = (cves_per_vulnerability[s] ?? 0) + 1;
          }
        } else {
          for (const v of Object.values(cves)) {
            const s = v != null ? String(v).trim() : "";
            if (s) cves_per_vulnerability[s] = (cves_per_vulnerability[s] ?? 0) + 1;
          }
        }
      }
      for (const [, value] of getOwaspComplianceEntries(vuln.compliance_controls)) {
        if (value && value.includes(" - ")) {
          const key = value.split(" - ")[0].trim();
          if (key) policy_violations[key] = (policy_violations[key] ?? 0) + 1;
        }
      }
    }
  }

  return {
    risk_metrics,
    owasp_top_10_metrics,
    compliance_controls_metrics,
    cves_per_vulnerability,
    policy_violations,
    risk_scores_per_finding,
  };
}

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

const policyViolationsBarChartConfig = {
  name: { label: "Policy / Standard" },
  count: { label: "Violations", color: "hsl(25 95% 53%)" },
} satisfies ChartConfig;

const riskScoresAreaChartConfig = {
  name: { label: "Finding" },
  score: { label: "Risk Score", color: "hsl(262 83% 58%)" },
} satisfies ChartConfig;

function CicdSastDashboardCharts({ dashboard }: { dashboard: SastDashboardData }) {
  const riskMetrics = dashboard.risk_metrics ?? {};
  const owaspMetrics = dashboard.owasp_top_10_metrics ?? {};
  const complianceMetrics = dashboard.compliance_controls_metrics ?? {};
  const cvesMetrics = dashboard.cves_per_vulnerability ?? {};
  const policyViolations = dashboard.policy_violations ?? {};
  const riskScoresPerFinding = dashboard.risk_scores_per_finding ?? {};

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

  const policyViolationsBarData = Object.entries(policyViolations)
    .map(([key, count]) => ({ name: key, count }))
    .sort((a, b) => b.count - a.count);

  const riskScoresAreaData = Object.entries(riskScoresPerFinding)
    .filter(([, score]) => score != null && !Number.isNaN(score))
    .map(([title, score]) => ({
      fullName: title,
      score: Number(score),
    }))
    .sort((a, b) => b.score - a.score)
    .slice(0, 20)
    .map((d, i) => ({ ...d, xLabel: `F${i + 1}` }));

  const hasOwaspData = owaspEntries.length > 0 && owaspEntries.some((d) => d.actualCount > 0);
  const hasRiskData = riskRadarData.some((d) => d.count > 0);
  const hasCvesData = cvesAreaData.length > 0;
  const hasComplianceData = complianceBarData.length > 0;
  const hasPolicyViolationsData = policyViolationsBarData.length > 0;
  const hasRiskScoresData = riskScoresAreaData.length > 0;

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
                    <linearGradient id="fillCicdSastCves" x1="0" y1="0" x2="0" y2="1">
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
                  <Area dataKey="count" type="monotone" fill="url(#fillCicdSastCves)" stroke="hsl(0 84% 60%)" strokeWidth={2} />
                </AreaChart>
              </ChartContainer>
            )}
            <p className="mt-4 pt-3 border-t border-zinc-200 dark:border-zinc-700 text-xs text-zinc-500 dark:text-zinc-400 text-center">
              Top 20 CVEs by count; hover for exact values.
            </p>
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

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Card className="border-zinc-200 dark:border-zinc-800">
          <CardHeader>
            <CardTitle className="text-base flex items-center gap-2">
              <BarChart3 className="w-4 h-4" />
              Policy violations
            </CardTitle>
            <CardDescription>Findings by policy / compliance standard violated</CardDescription>
          </CardHeader>
          <CardContent>
            {!hasPolicyViolationsData ? (
              <div className="flex items-center justify-center min-h-[260px] text-zinc-500 dark:text-zinc-400 text-sm">No data to be displayed</div>
            ) : (
              <ScrollArea className="w-full">
                <div className="min-w-max pb-2" style={{ minWidth: `${Math.max(300, policyViolationsBarData.length * 80)}px` }}>
                  <ChartContainer config={policyViolationsBarChartConfig} className="aspect-auto h-[260px] w-full min-w-0 cursor-pointer">
                    <BarChart data={policyViolationsBarData} margin={{ top: 8, right: 8, bottom: 32, left: 0 }}>
                      <CartesianGrid vertical={false} className="stroke-zinc-200 dark:stroke-zinc-800" />
                      <XAxis
                        dataKey="name"
                        tickLine={false}
                        axisLine={false}
                        tickMargin={8}
                        height={56}
                        interval={0}
                        tickFormatter={(v) => (String(v).length > 12 ? `${String(v).slice(0, 12)}...` : v)}
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
            <p className="mt-4 pt-3 border-t border-zinc-200 dark:border-zinc-700 text-xs text-zinc-500 dark:text-zinc-400 text-center">
              Violation count per policy or compliance standard (e.g. PCI DSS, ISO 27001).
            </p>
          </CardContent>
        </Card>

        <Card className="border-zinc-200 dark:border-zinc-800">
          <CardHeader>
            <CardTitle className="text-base flex items-center gap-2">
              <TrendingUp className="w-4 h-4" />
              Risk score per finding
            </CardTitle>
            <CardDescription>Top 20 findings by risk score (0–10)</CardDescription>
          </CardHeader>
          <CardContent>
            {!hasRiskScoresData ? (
              <div className="flex items-center justify-center min-h-[260px] text-zinc-500 dark:text-zinc-400 text-sm">No data to be displayed</div>
            ) : (
              <ChartContainer config={riskScoresAreaChartConfig} className="aspect-auto h-[260px] w-full pb-8 cursor-pointer">
                <AreaChart data={riskScoresAreaData} margin={{ top: 8, right: 8, bottom: 28, left: 0 }}>
                  <defs>
                    <linearGradient id="fillCicdSastRiskScore" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="var(--color-score)" stopOpacity={0.8} />
                      <stop offset="95%" stopColor="var(--color-score)" stopOpacity={0.1} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid vertical={false} className="stroke-zinc-200 dark:stroke-zinc-800" />
                  <XAxis
                    dataKey="xLabel"
                    tickLine={false}
                    axisLine={false}
                    tickMargin={8}
                    minTickGap={24}
                  />
                  <YAxis type="number" domain={[0, 10]} tickLine={false} axisLine={false} width={28} />
                  <ChartTooltip
                    cursor={false}
                    content={
                      <ChartTooltipContent
                        labelFormatter={(_, payload) => (payload?.[0]?.payload as { fullName?: string })?.fullName ?? "—"}
                        formatter={(value) => [value, "Risk score"]}
                        indicator="dot"
                      />
                    }
                  />
                  <Area
                    dataKey="score"
                    type="monotone"
                    fill="url(#fillCicdSastRiskScore)"
                    stroke="var(--color-score)"
                    strokeWidth={2}
                  />
                </AreaChart>
              </ChartContainer>
            )}
            <p className="mt-4 pt-3 border-t border-zinc-200 dark:border-zinc-700 text-xs text-zinc-500 dark:text-zinc-400 text-center">
              Risk scores derived from impact severity (Critical=10, High=7.5, Medium=5, Low=2.5).
            </p>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

/** Full SAST result object as returned by the worker (DataSpecs.md): results array + optional metadata/duration */
export interface SastAgentResultPayload {
  results?: SastAgentLogicalComponent[] | null;
  metadata?: { excluded_documents?: string[]; included_documents?: string[] } | null;
  duration_of_scan?: number | null;
}

export interface CicdSastResultsProps {
  /** SAST agent data: either the full result object (with .results array) or the components array directly (CICD log stores the full object) */
  data: SastAgentLogicalComponent[] | SastAgentResultPayload | null | undefined;
  /** Dashboard metrics from backend generate_scan_dashboard (per log) */
  dashboard?: SastDashboardData | null;
  /** Integration ID for back navigation */
  integrationId: string;
}

/** Normalize CICD SAST data: log.results is the full payload { results: [...] }; accept array or payload. */
function normalizeSastComponents(
  data: SastAgentLogicalComponent[] | SastAgentResultPayload | null | undefined
): SastAgentLogicalComponent[] {
  if (data == null) return [];
  if (Array.isArray(data)) return data;
  const results = (data as SastAgentResultPayload).results;
  return Array.isArray(results) ? results : [];
}

export default function CicdSastResults({ data, dashboard, integrationId }: CicdSastResultsProps) {
  const router = useRouter();
  const params = useParams();
  const teamId = (params?.team_id as string) ?? "";

  const [detailDialogOpen, setDetailDialogOpen] = useState(false);
  const [selectedVuln, setSelectedVuln] = useState<{ vuln: SastAgentVulnerability; componentTitle: string } | null>(null);

  const components = normalizeSastComponents(data);
  const totalFindings = components.reduce((sum, c) => sum + (Array.isArray(c.vulnerabilities) ? c.vulnerabilities.length : 0), 0);
  // Use API dashboard when present; otherwise derive from components so charts always show
  const dashboardToShow = dashboard ?? deriveDashboardFromComponents(components);

  const tableRows: { componentTitle: string; vuln: SastAgentVulnerability }[] = [];
  components.forEach((comp, compIndex) => {
    const title = comp.logical_component_title ?? `Component ${compIndex + 1}`;
    (comp.vulnerabilities ?? []).forEach((v) => {
      tableRows.push({ componentTitle: title, vuln: v });
    });
  });

  const openVulnDetail = (vuln: SastAgentVulnerability, componentTitle: string) => {
    setSelectedVuln({ vuln, componentTitle });
    setDetailDialogOpen(true);
  };

  const backRoute = teamId ? `/${teamId}/ci_cd/${integrationId}` : `/home/ci_cd/${integrationId}`;

  if (components.length === 0) {
    return (
      <div className="container mx-auto p-6 space-y-6">
        <div className="flex items-center gap-4">
          <Button variant="outline" size="icon"
                aria-label="Back" onClick={() => router.push(backRoute)} className="cursor-pointer">
            <ArrowLeft className="h-4 w-4" />
          </Button>
          <div>
            <h1 className="text-3xl font-bold text-zinc-900 dark:text-white">CICD SAST Scan Results</h1>
            <p className="text-sm text-zinc-600 dark:text-zinc-400 mt-1">Agent analysis by logical component</p>
          </div>
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
    <div className="container mx-auto p-6 space-y-6">
      <div className="flex items-center gap-4">
        <Button variant="outline" size="icon"
                aria-label="Back" onClick={() => router.push(backRoute)} className="cursor-pointer">
          <ArrowLeft className="h-4 w-4" />
        </Button>
        <div>
          <h1 className="text-3xl font-bold text-zinc-900 dark:text-white">CICD SAST Scan Results</h1>
          <p className="text-sm text-zinc-600 dark:text-zinc-400 mt-1">Agent analysis by logical component</p>
        </div>
      </div>

      <CicdSastDashboardCharts dashboard={dashboardToShow} />

      <Card>
        <CardHeader>
          <CardTitle>Findings</CardTitle>
          <CardDescription>{totalFindings} vulnerability findings. Click a title to view details</CardDescription>
        </CardHeader>
        <CardContent>
          <ScrollArea className="h-[500px] rounded-md border border-zinc-200 dark:border-zinc-800">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-[280px]">Vulnerability</TableHead>
                  <TableHead className="w-[200px]">Logical component</TableHead>
                  <TableHead className="w-[80px] text-center">OWASP Top 10</TableHead>
                  <TableHead className="w-[80px] text-center">Compliance Controls</TableHead>
                  <TableHead className="w-[100px]">Impact</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {tableRows.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={5} className="text-center py-8 text-zinc-500 dark:text-zinc-400">
                      No findings to display.
                    </TableCell>
                  </TableRow>
                ) : (
                  tableRows.map(({ componentTitle, vuln }, idx) => {
                    const vTitle = vuln.title ?? "Untitled finding";
                    const impact = (vuln.impact ?? "").trim() || "—";
                    const owaspCount = getOwaspComplianceCount(vuln.owasp_top_10);
                    const complianceCount = getOwaspComplianceCount(vuln.compliance_controls);
                    return (
                      <TableRow
                        key={idx}
                        className="cursor-pointer hover:bg-zinc-50 dark:hover:bg-zinc-800/50"
                      >
                        <TableCell className="font-medium">
                          <button
                            type="button"
                            onClick={() => openVulnDetail(vuln, componentTitle)}
                            className="text-left text-blue-600 hover:text-blue-700 dark:text-blue-400 dark:hover:text-blue-300 hover:underline cursor-pointer font-medium"
                          >
                            {vTitle}
                          </button>
                        </TableCell>
                        <TableCell className="text-zinc-600 dark:text-zinc-400 text-sm">{componentTitle}</TableCell>
                        <TableCell className="text-center text-zinc-700 dark:text-zinc-300 tabular-nums">{owaspCount}</TableCell>
                        <TableCell className="text-center text-zinc-700 dark:text-zinc-300 tabular-nums">{complianceCount}</TableCell>
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
            <DialogTitle className="pr-8">{selectedVuln?.vuln.title ?? "Vulnerability details"}</DialogTitle>
          </DialogHeader>
          {selectedVuln && (
            <div className="h-[70vh] min-h-0 shrink px-6 pb-6">
              <ScrollArea className="h-full w-full rounded-md">
                <div className="space-y-4 pt-2 pr-4">
                  {selectedVuln.componentTitle && (
                    <div>
                      <div className="text-xs font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400 mb-1">Logical component</div>
                      <p className="text-sm text-zinc-800 dark:text-zinc-200">{selectedVuln.componentTitle}</p>
                    </div>
                  )}
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
                  {(selectedVuln.vuln.location ?? "").trim() && (
                    <div>
                      <div className="text-xs font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400 mb-1">Location</div>
                      <p className="text-sm font-mono text-zinc-700 dark:text-zinc-300">{selectedVuln.vuln.location!.trim()}</p>
                    </div>
                  )}
                  {(selectedVuln.vuln.snippet ?? "").trim() && (
                    <div>
                      <div className="text-xs font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400 mb-1">Code snippet</div>
                      <pre className="text-xs bg-zinc-100 dark:bg-zinc-800 p-3 rounded overflow-x-auto whitespace-pre-wrap font-mono text-zinc-800 dark:text-zinc-200">
                        {selectedVuln.vuln.snippet!.trim()}
                      </pre>
                    </div>
                  )}
                  {(selectedVuln.vuln.suggested_fix ?? "").trim() && (
                    <div>
                      <div className="text-xs font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400 mb-1">Suggested fix</div>
                      <p className="text-sm text-zinc-700 dark:text-zinc-300">{selectedVuln.vuln.suggested_fix!.trim()}</p>
                    </div>
                  )}
                  {getOwaspComplianceEntries(selectedVuln.vuln.owasp_top_10).length > 0 && (
                    <div>
                      <div className="text-xs font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400 mb-1">OWASP Top 10</div>
                      <div className="flex flex-wrap gap-1">
                        {getOwaspComplianceEntries(selectedVuln.vuln.owasp_top_10).map(([, description], i) => (
                          <Badge key={i} variant="secondary" className="text-xs bg-purple-100 dark:bg-purple-900/40 text-purple-800 dark:text-purple-200">
                            {description}
                          </Badge>
                        ))}
                      </div>
                    </div>
                  )}
                  {getOwaspComplianceEntries(selectedVuln.vuln.compliance_controls).length > 0 && (
                    <div>
                      <div className="text-xs font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400 mb-1">Compliance controls</div>
                      <div className="flex flex-wrap gap-1">
                        {getOwaspComplianceEntries(selectedVuln.vuln.compliance_controls).map(([, description], i) => (
                          <Badge key={i} variant="outline" className="text-xs">
                            {description}
                          </Badge>
                        ))}
                      </div>
                    </div>
                  )}
                  {(() => {
                    const cves = selectedVuln.vuln.cves;
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
    </div>
  );
}
