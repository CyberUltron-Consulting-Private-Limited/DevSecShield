"use client";

// The CBOM dashboard charts (cards, remediation progress, OWASP, risk metrics, compliance controls, algorithm types,
// strength, quantum readiness, risk score per finding, remediation metrics). Moved unchanged out of CbomResults.tsx
// (CB-38) so the code-scan page and the Sources run page render the same charts from a CbomScanDashboardData.

import { useMemo } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import {
  AlertTriangle,
  CheckCircle,
  EyeOff,
  Loader2,
  Circle,
  Shield,
  Lock,
  Key,
  ShieldCheck,
  ShieldAlert,
  Activity,
  Clock,
  Crosshair,
} from "lucide-react";
import { Progress } from "@/components/ui/progress";
import type { CbomScanDashboardData, CbomFinding } from "@/utils/backend_api";
import { readinessText } from "@/utils/cbomReadiness";
import { OWASP_KEY_TO_LABEL, COMPLIANCE_KEY_TO_LABEL, OWASP_COLORS } from "@/lib/owasp-compliance-labels";
import { FRAMEWORK_LABELS } from "@/components/compliance/frameworkLabels";
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
  RadialBar,
  RadialBarChart,
  XAxis,
  YAxis,
} from "recharts";
import { PieChart, BarChart3, TrendingUp } from "lucide-react";

/** Resolve a compliance-controls chart key to a short display label. */
function complianceChartLabel(key: string): string {
  const full =
    COMPLIANCE_KEY_TO_LABEL[key] ?? FRAMEWORK_LABELS[key] ?? key;
  // Keep Y-axis ticks single-line so they never wrap into neighboring rows.
  return full.length > 32 ? `${full.slice(0, 30)}…` : full;
}

const RISK_ORDER = ["Critical", "High", "Medium", "Low"] as const;

const radarConfig = {
  count: { label: "Count", color: "hsl(220 70% 50%)" },
} satisfies ChartConfig;

const barConfig = {
  count: { label: "Count", color: "hsl(220 70% 50%)" },
} satisfies ChartConfig;

const owaspRadialChartConfig = {
  count: { label: "Count" },
  ...Object.fromEntries(OWASP_COLORS.map((color, i) => [`fill_${i}`, { label: `Category ${i + 1}`, color }])),
} satisfies ChartConfig;

const complianceBarChartConfig = {
  name: { label: "Control" },
  count: { label: "Count", color: "hsl(217 91% 60%)" },
} satisfies ChartConfig;

const riskScoreAreaChartConfig = {
  finding: { label: "Finding" },
  score: { label: "Risk score", color: "hsl(217 91% 60%)" },
} satisfies ChartConfig;

export function CbomDashboardCharts({
  dashboard,
  findingsList,
}: {
  dashboard: CbomScanDashboardData;
  findingsList: CbomFinding[];
}) {
  const cardData = dashboard.card_data;
  const remediation = dashboard.remediation_actions_required;
  const remediationKpis = dashboard.remediation_metrics;
  const totalFindings = remediation ? remediation.total_findings || 1 : 1;

  // Charts data
  const severityRadarData = useMemo(() => {
    return RISK_ORDER.map((subject) => ({
      subject,
      count: dashboard.severity_distribution[subject.toLowerCase() as keyof typeof dashboard.severity_distribution] ?? 0,
    }));
  }, [dashboard]);

  const algorithmTypeData = useMemo(() => {
    return Object.entries(dashboard.algorithm_type_distribution)
      .map(([name, count]) => ({ name: name.replace(/_/g, " "), count }))
      .filter((d) => d.count > 0)
      .sort((a, b) => b.count - a.count);
  }, [dashboard]);

  const strengthData = useMemo(() => {
    const COLORS: Record<string, string> = {
      weak: "hsl(0 72% 51%)",
      moderate: "hsl(45 93% 47%)",
      strong: "hsl(142 71% 45%)",
      quantum_safe: "hsl(220 70% 50%)",
    };
    return Object.entries(dashboard.strength_distribution)
      .map(([name, count]) => ({
        name: name === "quantum_safe" ? "Quantum-Safe" : name.charAt(0).toUpperCase() + name.slice(1),
        count,
        fill: COLORS[name] ?? "hsl(220 9% 46%)",
      }))
      .filter((d) => d.count > 0);
  }, [dashboard]);

  const quantumData = useMemo(() => {
    if (!dashboard.quantum_readiness) return [];
    return [
      { name: "Safe", count: dashboard.quantum_readiness.quantum_safe, fill: "hsl(142 71% 45%)" },
      { name: "Vulnerable", count: dashboard.quantum_readiness.quantum_vulnerable, fill: "hsl(0 72% 51%)" },
    ].filter((d) => d.count > 0);
  }, [dashboard]);

  // OWASP Top 10 data
  const owaspMetrics = dashboard.owasp_top_10_issues ?? {};
  const owaspEntries = useMemo(() => {
    return Object.entries(owaspMetrics).map(([key, actualCount], index) => {
      const displayValue = OWASP_KEY_TO_LABEL[key] ?? key;
      return {
        name: displayValue.length > 20 ? `${displayValue.slice(0, 20)}...` : displayValue,
        key,
        displayValue,
        actualCount,
        fill: OWASP_COLORS[index % OWASP_COLORS.length],
      };
    });
  }, [owaspMetrics]);
  const maxOwasp = Math.max(1, ...owaspEntries.map((d) => d.actualCount));
  const owaspRadialData = owaspEntries.map((d) => ({
    ...d,
    count: maxOwasp > 0 ? (d.actualCount / maxOwasp) * 100 : 0,
  }));
  const hasOwaspData = owaspEntries.length > 0 && owaspEntries.some((d) => d.actualCount > 0);

  // Compliance controls data
  const complianceMetrics = dashboard.compliance_controls ?? {};
  const complianceBarData = useMemo(() => {
    return Object.entries(complianceMetrics)
      .map(([key, count]) => ({
        name: complianceChartLabel(key),
        fullName: COMPLIANCE_KEY_TO_LABEL[key] ?? FRAMEWORK_LABELS[key] ?? key,
        count,
      }))
      .sort((a, b) => b.count - a.count);
  }, [complianceMetrics]);
  const complianceChartRows = complianceBarData.slice(0, 10);
  const complianceChartHeight = Math.max(280, complianceChartRows.length * 36);
  const hasComplianceData = complianceBarData.length > 0;

  // Risk scores per finding
  const riskScoresAreaData = useMemo(() => {
    if (!findingsList || findingsList.length === 0) return [];
    return findingsList
      .filter((f) => f.risk_score != null)
      .map((f) => ({ finding: f.algorithm_name || f.title, score: f.risk_score, fullName: f.algorithm_name || f.title }))
      .sort((a, b) => b.score - a.score)
      .slice(0, 24)
      .map((row, i) => ({ ...row, finding: `F${i + 1}` }));
  }, [findingsList]);
  const hasRiskScoresData = riskScoresAreaData.length > 0;

  const hasRiskData = severityRadarData.some((d) => d.count > 0);
  const hasAlgorithmTypeData = algorithmTypeData.length > 0;
  const hasStrengthData = strengthData.length > 0;
  const hasQuantumData = quantumData.length > 0;
  const criticalCount = dashboard.severity_distribution?.critical ?? 0;

  const totalAll = remediation?.total_findings ?? 0;
  const fixedPct = totalAll > 0 ? Math.round(((remediation?.total_fixed ?? 0) / totalAll) * 100) : 0;
  const inProgressPct = totalAll > 0 ? Math.round(((remediation?.total_in_progress ?? 0) / totalAll) * 100) : 0;
  const notStartedPct = totalAll > 0 ? Math.round(((remediation?.total_not_started ?? 0) / totalAll) * 100) : 0;
  const ignoredPct = totalAll > 0 ? Math.round(((remediation?.total_ignored ?? 0) / totalAll) * 100) : 0;

  return (
    <div className="space-y-6">
      {/* Summary cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 xl:grid-cols-7 gap-4">
        {[
          { label: "Crypto assets", value: cardData.total_crypto_assets, icon: Lock, box: "bg-violet-100 dark:bg-violet-900/30 text-violet-600 dark:text-violet-400" },
          { label: "Weak", value: cardData.total_weak_algorithms, icon: ShieldAlert, box: "bg-red-100 dark:bg-red-900/30 text-red-600 dark:text-red-400" },
          { label: "Quantum vulnerable", value: cardData.total_quantum_vulnerable, icon: AlertTriangle, box: "bg-orange-100 dark:bg-orange-900/30 text-orange-600 dark:text-orange-400" },
          { label: "Certificates", value: cardData.total_certificates, icon: ShieldCheck, box: "bg-emerald-100 dark:bg-emerald-900/30 text-emerald-600 dark:text-emerald-400" },
          { label: "Keys", value: cardData.total_keys, icon: Key, box: "bg-amber-100 dark:bg-amber-900/30 text-amber-600 dark:text-amber-400" },
          { label: "Quantum ready", value: readinessText(cardData), icon: Shield, box: "bg-blue-100 dark:bg-blue-900/30 text-blue-600 dark:text-blue-400" },
          { label: "Avg risk score", value: cardData.average_risk_score?.toFixed(1) ?? "N/A", icon: Activity, box: "bg-teal-100 dark:bg-teal-900/30 text-teal-600 dark:text-teal-400" },
        ].map(({ label, value, icon: Icon, box }) => (
          <Card key={label} className="border-zinc-200 dark:border-zinc-800">
            <CardContent className="pt-4 pb-4 flex items-center gap-3">
              <div className={`flex h-10 w-10 shrink-0 items-center justify-center rounded-lg ${box}`}>
                <Icon className="h-5 w-5" />
              </div>
              <div className="min-w-0">
                <p className="text-xs font-medium text-zinc-500 dark:text-zinc-400">{label}</p>
                <p className="text-lg font-semibold text-zinc-900 dark:text-zinc-100 tabular-nums">{value}</p>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Remediation actions */}
      {remediation && (
        <Card className="border-zinc-200 dark:border-zinc-800">
          <CardHeader>
            <CardTitle className="text-base">Remediation progress</CardTitle>
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
                <span className="text-sm text-zinc-600 dark:text-zinc-400">Findings resolved</span>
                <span className="text-lg font-bold text-zinc-900 dark:text-white tabular-nums">{remediation.total_fixed}/{totalFindings}</span>
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Row 1: OWASP + Risk Radar + Compliance */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* OWASP Top 10 */}
        <Card className="border-zinc-200 dark:border-zinc-800">
          <CardHeader>
            <CardTitle className="text-base flex items-center gap-2">
              <PieChart className="w-4 h-4" />
              OWASP Top 10 issues
            </CardTitle>
            <CardDescription>Distribution by OWASP category</CardDescription>
          </CardHeader>
          <CardContent>
            {!hasOwaspData ? (
              <div className="flex items-center justify-center min-h-[280px] text-zinc-500 dark:text-zinc-400 text-sm">No OWASP data available</div>
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

        {/* Severity Radar */}
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
              <div className="flex items-center justify-center min-h-[280px] text-zinc-500 dark:text-zinc-400 text-sm">No data to display</div>
            ) : (
              <ChartContainer config={radarConfig} className="mx-auto aspect-square max-h-[280px] cursor-pointer">
                <RadarChart data={severityRadarData} margin={{ top: 8, right: 24, bottom: 8, left: 24 }}>
                  <ChartTooltip cursor={false} content={<ChartTooltipContent nameKey="subject" formatter={(value) => [value, "Count"]} />} />
                  <PolarAngleAxis dataKey="subject" />
                  <PolarGrid />
                  <Radar dataKey="count" fill="hsl(220 70% 50%)" fillOpacity={0.4} stroke="hsl(220 70% 50%)" strokeWidth={2} dot={{ r: 4, fillOpacity: 1 }} />
                </RadarChart>
              </ChartContainer>
            )}
            <p className="mt-4 pt-3 border-t border-zinc-200 dark:border-zinc-700 text-xs text-zinc-500 dark:text-zinc-400 text-center">
              Findings for each impact level (Critical, High, Medium, Low)
            </p>
          </CardContent>
        </Card>

        {/* Compliance Controls */}
        <Card className="border-zinc-200 dark:border-zinc-800">
          <CardHeader>
            <CardTitle className="text-base flex items-center gap-2">
              <BarChart3 className="w-4 h-4" />
              Compliance controls
            </CardTitle>
            <CardDescription>Findings mapped to compliance frameworks</CardDescription>
          </CardHeader>
          <CardContent>
            {!hasComplianceData ? (
              <div className="flex items-center justify-center min-h-[280px] text-zinc-500 dark:text-zinc-400 text-sm">No compliance data available</div>
            ) : (
              <ChartContainer
                config={complianceBarChartConfig}
                className="aspect-auto w-full cursor-pointer"
                style={{ height: complianceChartHeight }}
              >
                <BarChart
                  data={complianceChartRows}
                  layout="vertical"
                  margin={{ top: 4, right: 12, bottom: 4, left: 4 }}
                  barCategoryGap={10}
                >
                  <CartesianGrid horizontal={false} className="stroke-zinc-200 dark:stroke-zinc-800" />
                  <XAxis type="number" hide />
                  <YAxis
                    dataKey="name"
                    type="category"
                    width={168}
                    interval={0}
                    tickLine={false}
                    axisLine={false}
                    tick={{ fontSize: 11 }}
                    className="text-xs"
                  />
                  <ChartTooltip
                    content={
                      <ChartTooltipContent
                        labelFormatter={(_, payload) =>
                          String(
                            (payload?.[0]?.payload as { fullName?: string } | undefined)
                              ?.fullName ?? "",
                          )
                        }
                      />
                    }
                  />
                  <Bar dataKey="count" fill="hsl(217 91% 60%)" radius={[0, 4, 4, 0]} />
                </BarChart>
              </ChartContainer>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Row 2: CBOM-specific charts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Algorithm Types */}
        <Card className="border-zinc-200 dark:border-zinc-800">
          <CardHeader>
            <CardTitle className="text-base flex items-center gap-2">
              <BarChart3 className="w-4 h-4" />
              Algorithm types
            </CardTitle>
            <CardDescription>Distribution by algorithm category</CardDescription>
          </CardHeader>
          <CardContent>
            {!hasAlgorithmTypeData ? (
              <div className="flex items-center justify-center min-h-[280px] text-zinc-500 dark:text-zinc-400 text-sm">No data to display</div>
            ) : (
              <ChartContainer config={barConfig} className="aspect-auto h-[280px] w-full">
                <BarChart data={algorithmTypeData} layout="vertical" margin={{ top: 0, right: 8, bottom: 0, left: 0 }}>
                  <CartesianGrid horizontal={false} className="stroke-zinc-200 dark:stroke-zinc-800" />
                  <XAxis type="number" tickLine={false} axisLine={false} className="text-xs" />
                  <YAxis dataKey="name" type="category" width={120} tickLine={false} axisLine={false} className="text-xs" />
                  <ChartTooltip content={<ChartTooltipContent />} />
                  <Bar dataKey="count" fill="hsl(220 70% 50%)" radius={[0, 4, 4, 0]} />
                </BarChart>
              </ChartContainer>
            )}
          </CardContent>
        </Card>

        {/* Strength */}
        <Card className="border-zinc-200 dark:border-zinc-800">
          <CardHeader>
            <CardTitle className="text-base flex items-center gap-2">
              <ShieldCheck className="w-4 h-4" />
              Crypto strength
            </CardTitle>
            <CardDescription>Distribution by cryptographic strength</CardDescription>
          </CardHeader>
          <CardContent>
            {!hasStrengthData ? (
              <div className="flex items-center justify-center min-h-[280px] text-zinc-500 dark:text-zinc-400 text-sm">No data to display</div>
            ) : (
              <ChartContainer config={barConfig} className="aspect-auto h-[280px] w-full">
                <BarChart data={strengthData} margin={{ top: 8, right: 8, bottom: 0, left: 0 }}>
                  <CartesianGrid vertical={false} className="stroke-zinc-200 dark:stroke-zinc-800" />
                  <XAxis dataKey="name" tickLine={false} axisLine={false} tickMargin={8} className="text-xs" />
                  <YAxis tickLine={false} axisLine={false} className="text-xs" />
                  <ChartTooltip content={<ChartTooltipContent />} />
                  <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                    {strengthData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.fill} />
                    ))}
                  </Bar>
                </BarChart>
              </ChartContainer>
            )}
          </CardContent>
        </Card>

        {/* Quantum Readiness */}
        <Card className="border-zinc-200 dark:border-zinc-800">
          <CardHeader>
            <CardTitle className="text-base flex items-center gap-2">
              <Shield className="w-4 h-4" />
              Quantum readiness
            </CardTitle>
            <CardDescription>Safe vs vulnerable cryptographic assets</CardDescription>
          </CardHeader>
          <CardContent>
            {!hasQuantumData ? (
              <div className="flex items-center justify-center min-h-[280px] text-zinc-500 dark:text-zinc-400 text-sm">No data to display</div>
            ) : (
              <ChartContainer config={barConfig} className="aspect-auto h-[280px] w-full">
                <BarChart data={quantumData} margin={{ top: 8, right: 8, bottom: 0, left: 0 }}>
                  <CartesianGrid vertical={false} className="stroke-zinc-200 dark:stroke-zinc-800" />
                  <XAxis dataKey="name" tickLine={false} axisLine={false} tickMargin={8} className="text-xs" />
                  <YAxis tickLine={false} axisLine={false} className="text-xs" />
                  <ChartTooltip content={<ChartTooltipContent />} />
                  <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                    {quantumData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.fill} />
                    ))}
                  </Bar>
                </BarChart>
              </ChartContainer>
            )}
          </CardContent>
        </Card>

        {/* Risk Scores per Finding */}
        <Card className="border-zinc-200 dark:border-zinc-800">
          <CardHeader>
            <CardTitle className="text-base flex items-center gap-2">
              <TrendingUp className="w-4 h-4" />
              Risk scores per finding
            </CardTitle>
            <CardDescription>Risk score by finding (top 24, descending)</CardDescription>
          </CardHeader>
          <CardContent>
            {!hasRiskScoresData ? (
              <div className="flex items-center justify-center min-h-[280px] text-zinc-500 dark:text-zinc-400 text-sm">No risk score data to display</div>
            ) : (
              <ChartContainer config={riskScoreAreaChartConfig} className="aspect-auto h-[280px] w-full cursor-pointer">
                <AreaChart data={riskScoresAreaData} margin={{ top: 8, right: 8, bottom: 28, left: 0 }}>
                  <defs>
                    <linearGradient id="fillCbomRiskScore" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="hsl(217 91% 60%)" stopOpacity={0.8} />
                      <stop offset="95%" stopColor="hsl(217 91% 60%)" stopOpacity={0.1} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid vertical={false} className="stroke-zinc-200 dark:stroke-zinc-800" />
                  <XAxis dataKey="finding" tickLine={false} axisLine={false} tickMargin={8} minTickGap={16} height={40} interval={0} />
                  <YAxis hide domain={[0, 10]} />
                  <ChartTooltip
                    cursor={false}
                    content={
                      <ChartTooltipContent
                        className="gap-2 py-2.5 px-3 min-w-48"
                        hideIndicator
                        formatter={(value) => ["Risk score  :  ", value]}
                        labelFormatter={(_, payload) => {
                          const fullName = (payload?.[0]?.payload as { fullName?: string } | undefined)?.fullName;
                          return fullName ? <span className="block font-medium text-zinc-900 dark:text-zinc-100">{fullName}</span> : "—";
                        }}
                      />
                    }
                  />
                  <Area type="monotone" dataKey="score" fill="url(#fillCbomRiskScore)" stroke="hsl(217 91% 60%)" strokeWidth={2} />
                </AreaChart>
              </ChartContainer>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Remediation KPIs */}
      {remediationKpis && (
        <Card className="border-zinc-200 dark:border-zinc-800 shadow-sm">
          <CardHeader>
            <CardTitle className="text-base">Remediation metrics</CardTitle>
            <CardDescription>Performance and efficiency tracking</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6">
              {(() => {
                const [days, hours, minutes] = remediationKpis.mean_time_to_remediate;
                const totalDays = days + hours / 24 + minutes / (60 * 24);
                const targetDays = 3;
                const progress = totalDays <= 0 ? 100 : Math.min(100, (targetDays / totalDays) * 100);
                const delta = totalDays > 0 && targetDays > 0 ? `${Math.round(((totalDays - targetDays) / targetDays) * 100)}%` : "—";
                return (
                  <div className="space-y-3">
                    <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-teal-500/15 dark:bg-teal-500/10">
                      <Clock className="h-5 w-5 text-teal-600 dark:text-teal-400" />
                    </div>
                    <p className="text-sm font-medium text-zinc-600 dark:text-zinc-400">Mean time to remediate</p>
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
                const fixed = remediationKpis.critical_issues_fixed;
                const total = fixed + criticalCount;
                const pct = total > 0 ? Math.round((fixed / total) * 100) : 0;
                const targetPct = 95;
                const progress = Math.min(100, (pct / targetPct) * 100);
                const delta = pct >= targetPct ? "+0%" : `+${targetPct - pct}%`;
                return (
                  <div className="space-y-3">
                    <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-teal-500/15 dark:bg-teal-500/10">
                      <CheckCircle className="h-5 w-5 text-teal-600 dark:text-teal-400" />
                    </div>
                    <p className="text-sm font-medium text-zinc-600 dark:text-zinc-400">Critical issues fixed</p>
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
                const backlog = remediationKpis.high_priority_backlog;
                const target = 10;
                const progress = target <= 0 ? 100 : Math.max(0, Math.min(100, (1 - (backlog - target) / Math.max(target, backlog)) * 100));
                const delta = backlog > target ? `-${backlog - target}` : backlog < target ? `+${target - backlog}` : "0";
                return (
                  <div className="space-y-3">
                    <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-teal-500/15 dark:bg-teal-500/10">
                      <Crosshair className="h-5 w-5 text-teal-600 dark:text-teal-400" />
                    </div>
                    <p className="text-sm font-medium text-zinc-600 dark:text-zinc-400">High priority backlog</p>
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
                const velocity = remediationKpis.remediation_velocity;
                const target = 20;
                const progress = Math.min(100, (velocity / target) * 100);
                const delta = velocity >= target ? "+0" : `+${target - velocity}`;
                return (
                  <div className="space-y-3">
                    <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-teal-500/15 dark:bg-teal-500/10">
                      <Activity className="h-5 w-5 text-teal-600 dark:text-teal-400" />
                    </div>
                    <p className="text-sm font-medium text-zinc-600 dark:text-zinc-400">Remediation velocity</p>
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

export default CbomDashboardCharts;
