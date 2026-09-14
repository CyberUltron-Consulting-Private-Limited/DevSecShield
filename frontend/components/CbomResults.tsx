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
  GitBranch,
  Archive,
  Shield,
  Lock,
  Key,
  ShieldCheck,
  ShieldAlert,
  Activity,
  Clock,
  Crosshair,
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
} from "@/components/ui/dropdown-menu";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { useRouter, useSearchParams, useParams } from "next/navigation";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { getCBOMExportResults, updateScan, toggleFindingState, createTicket, postCertInAttestation, postCertInSign, getCertInVex, getCertInEvidencePack, type CbomScanDashboardData, type CbomFinding, type CbomScanMetadata, type CbomGraph, type ScanTicketingIntegrationSettings } from "@/utils/backend_api";
import { showErrorToast } from "@/utils/error-handler";
import { overlayBomCompliance } from "@/utils/overlayBomCompliance";
import {
  buildRefAliasMap,
  findingMatchesRelatedRefs,
} from "@/utils/relatedFindingMatch";
import { OWASP_KEY_TO_LABEL, COMPLIANCE_KEY_TO_LABEL, OWASP_COLORS } from "@/lib/owasp-compliance-labels";
import { FRAMEWORK_LABELS } from "@/components/compliance/frameworkLabels";

/** Resolve a compliance-controls chart key to a short display label. */
function complianceChartLabel(key: string): string {
  const full =
    COMPLIANCE_KEY_TO_LABEL[key] ?? FRAMEWORK_LABELS[key] ?? key;
  // Keep Y-axis ticks single-line so they never wrap into neighboring rows.
  return full.length > 32 ? `${full.slice(0, 30)}…` : full;
}
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
import { PieChart, BarChart3, TrendingUp, Search } from "lucide-react";
import { toast } from "sonner";
import TicketingIntegrationsSettings from "@/components/ticketing-integrations-settings";
import FindingSelectionMenu from "@/components/finding-selection-menu";
import {
  CbomCryptoCharts,
  type CbomDistributions,
  type CbomCompliance,
} from "@/components/cbom/CbomCryptoCharts";
import { RbiCsfRollup, type RbiCsfRollupData } from "@/components/rbi/RbiCsfRollup";
import { CertInLanePosture } from "@/components/certin/CertInLanePosture";
import { type CertInRollupData } from "@/components/certin/certinShared";

interface CbomResultsProps {
  data: unknown;
  conversationId?: number;
  teamId?: string;
  dashboard?: CbomScanDashboardData | null;
  findings?: CbomFinding[] | null;
  scanMetadata?: CbomScanMetadata | Record<string, unknown> | null;
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

function getStrengthBadgeClass(strength: string | undefined | null): string {
  const s = (strength ?? "").toLowerCase();
  if (s === "weak") return "border-red-500/50 text-red-600 dark:text-red-400";
  if (s === "moderate") return "border-amber-500/50 text-amber-600 dark:text-amber-400";
  if (s === "strong") return "border-emerald-500/50 text-emerald-600 dark:text-emerald-400";
  if (s === "quantum_safe") return "border-blue-500/50 text-blue-600 dark:text-blue-400";
  return "border-zinc-400/50 text-zinc-600 dark:text-zinc-400";
}

/** Risk score color tiers on the 0–10 scale (Critical ≥9, High 7–9, Medium 5–7, Low <5), matching SBOM/SAST/list page. */
function getRiskScoreBoxClass(score: number | null | undefined): string {
  const s = score ?? 0;
  if (s >= 9) return "bg-red-100 text-red-800 dark:bg-red-900/40 dark:text-red-200";
  if (s >= 7) return "bg-orange-100 text-orange-800 dark:bg-orange-900/40 dark:text-orange-200";
  if (s >= 5) return "bg-amber-100 text-amber-800 dark:bg-amber-900/40 dark:text-amber-200";
  return "bg-emerald-100 text-emerald-800 dark:bg-emerald-900/40 dark:text-emerald-200";
}

/** Safe entries for OWASP/compliance fields (handles dict or legacy array) */
type OwaspOrCompliance = Record<string, string> | Array<Record<string, string>> | null | undefined;
function getOwaspComplianceEntries(val: OwaspOrCompliance): [string, string][] {
  if (val == null) return [];
  if (Array.isArray(val)) {
    return val.map((item) => {
      const k = item && typeof item === "object" ? Object.keys(item)[0] ?? "—" : "—";
      const v = item && typeof item === "object" ? Object.values(item)[0] ?? k : k;
      return [k, v] as [string, string];
    });
  }
  if (typeof val === "object") {
    return Object.entries(val).filter(([, v]) => v != null && String(v).trim() !== "") as [string, string][];
  }
  return [];
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

type RiskScoreFilter = "all" | "critical" | "high" | "medium" | "low";
/** Risk score tiers (0–10 scale, matching SBOM/SAST/list page): Critical ≥9, High 7–9, Medium 5–7, Low <5 */
function matchesRiskScoreFilter(score: number | null, filter: RiskScoreFilter): boolean {
  if (filter === "all") return true;
  if (score == null) return false;
  if (filter === "critical") return score >= 9;
  if (filter === "high") return score >= 7 && score < 9;
  if (filter === "medium") return score >= 5 && score < 7;
  if (filter === "low") return score < 5;
  return true;
}

function CbomDashboardCharts({
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
          { label: "Quantum ready", value: `${cardData.quantum_readiness_score}%`, icon: Shield, box: "bg-blue-100 dark:bg-blue-900/30 text-blue-600 dark:text-blue-400" },
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

export default function CbomResults({
  data,
  conversationId,
  teamId,
  dashboard,
  findings: findingsList = [],
  scanMetadata,
  integrationSettings,
  onIntegrationSettingsUpdated,
  onFindingsUpdated,
}: CbomResultsProps) {
  const router = useRouter();
  const params = useParams();
  const searchParams = useSearchParams();
  const origin = searchParams.get("origin");
  const team_id = teamId ?? params?.team_id;
  const scan_id = conversationId ?? params?.scan_id;
  const queryClient = useQueryClient();

  const [activeTab, setActiveTab] = useState<"results" | "ticketing">("results");
  const [searchQuery, setSearchQuery] = useState("");
  const [relatedFindingRefs, setRelatedFindingRefs] = useState<string[]>([]);
  const [strengthFilter, setStrengthFilter] = useState("all");
  const [typeFilter, setTypeFilter] = useState("all");
  const [quantumFilter, setQuantumFilter] = useState("all");
  const [filterImpact, setFilterImpact] = useState("all");
  const [filterRiskScore, setFilterRiskScore] = useState<RiskScoreFilter>("all");
  const [selectedFinding, setSelectedFinding] = useState<CbomFinding | null>(null);
  const [selectedFindings, setSelectedFindings] = useState<Set<string>>(new Set());

  // Jira ticketing state
  const jiraFromSettings =
    integrationSettings && typeof integrationSettings === "object" && "jira" in integrationSettings
      ? (integrationSettings.jira as { jira_project_id?: string; auto_create_tickets?: boolean } | undefined)
      : undefined;
  const initialJiraProjectId = jiraFromSettings?.jira_project_id ?? "";
  const [jiraProjectId, setJiraProjectId] = useState(initialJiraProjectId);
  const [autoCreateTickets, setAutoCreateTickets] = useState(jiraFromSettings?.auto_create_tickets === true);

  useEffect(() => {
    setJiraProjectId(initialJiraProjectId);
  }, [initialJiraProjectId]);
  useEffect(() => {
    setAutoCreateTickets(jiraFromSettings?.auto_create_tickets === true);
  }, [jiraFromSettings?.auto_create_tickets]);

  const relatedRefAliases = useMemo(() => {
    const fromData = (data as Record<string, unknown> | null)?.cbom_graph as
      | { nodes?: { id?: string; label?: string }[] }
      | undefined;
    const fromMeta = (scanMetadata as Record<string, unknown> | null)?.cbom_graph as
      | { nodes?: { id?: string; label?: string }[] }
      | undefined;
    const nodes =
      fromData?.nodes && fromData.nodes.length > 0
        ? fromData.nodes
        : fromMeta?.nodes;
    return buildRefAliasMap(nodes);
  }, [data, scanMetadata]);

  const filteredFindings = useMemo(() => {
    if (!findingsList) return [];
    return findingsList.filter((f, i) => {
      const q = searchQuery.toLowerCase();
      const name = (f.algorithm_name || f.title || "").toLowerCase();
      const desc = (f.description || "").toLowerCase();
      const loc = (f.location || "").toLowerCase();
      const id = (f.id || "").toLowerCase();
      const matchSearch =
        !q ||
        name.includes(q) ||
        desc.includes(q) ||
        loc.includes(q) ||
        id.includes(q);
      const matchRefs = findingMatchesRelatedRefs(f, relatedFindingRefs, {
        aliases: relatedRefAliases,
        findingIndex: i,
      });
      const matchStrength = strengthFilter === "all" || f.crypto_strength === strengthFilter;
      const matchType = typeFilter === "all" || f.algorithm_type === typeFilter;
      const matchQuantum =
        quantumFilter === "all" ||
        (quantumFilter === "safe" && f.quantum_safe === true) ||
        (quantumFilter === "vulnerable" && f.quantum_safe === false);
      const matchImpact = filterImpact === "all" || (f.impact || "").toLowerCase() === filterImpact.toLowerCase();
      const matchRisk = matchesRiskScoreFilter(f.risk_score, filterRiskScore);
      return matchSearch && matchRefs && matchStrength && matchType && matchQuantum && matchImpact && matchRisk;
    });
  }, [findingsList, searchQuery, relatedFindingRefs, relatedRefAliases, strengthFilter, typeFilter, quantumFilter, filterImpact, filterRiskScore]);

  const handleViewRelatedFindings = (refs: string[]) => {
    setRelatedFindingRefs(refs);
    setSearchQuery("");
    requestAnimationFrame(() => {
      document.getElementById("bom-findings")?.scrollIntoView({ behavior: "smooth", block: "start" });
    });
  };

  const uniqueTypes = useMemo(() => {
    if (!findingsList) return [];
    const types = new Set(findingsList.map((f) => f.algorithm_type).filter(Boolean) as string[]);
    return Array.from(types).sort();
  }, [findingsList]);

  const tid = parseInt(String(team_id ?? "0"), 10);
  const sid = typeof scan_id === "number" ? scan_id : parseInt(String(scan_id), 10);

  const updateIntegrationMutation = useMutation({
    mutationFn: (payload: { integration_settings: ScanTicketingIntegrationSettings }) =>
      updateScan({ team_id: tid, type: "cbom", scan_id: sid, data: payload }),
    onSuccess: () => {
      onIntegrationSettingsUpdated?.();
      queryClient.invalidateQueries({ queryKey: ["cbom-conversation-data"] });
      toast.success("Ticketing settings saved");
    },
    onError: (err) => showErrorToast(err, "Failed to save ticketing settings"),
  });

  const toggleFindingMutation = useMutation({
    mutationFn: ({ finding_id, state }: { finding_id: string; state: "fixed" | "ignored" | "in_progress" | "not_started" }) => {
      if (!sid || Number.isNaN(tid)) throw new Error("Missing team or scan");
      return toggleFindingState({ team_id: tid, type: "cbom", scan_id: sid, finding_id, state });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["cbom-conversation-data"] });
      onFindingsUpdated?.();
      toast.success("Finding status updated");
    },
    onError: (err) => showErrorToast(err, "Error updating finding status"),
  });

  const createJiraTicketsMutation = useMutation({
    mutationFn: async () => {
      if (!sid || Number.isNaN(tid)) throw new Error("Missing team or scan");
      const selected = (findingsList ?? []).filter((f) => selectedFindings.has(f.id));
      if (selected.length === 0) throw new Error("No findings selected");

      const impactCounts: Record<string, number> = {};
      for (const f of selected) {
        const impact = (f.impact ?? "Unknown").trim() || "Unknown";
        impactCounts[impact] = (impactCounts[impact] ?? 0) + 1;
      }
      let summary =
        Object.entries(impactCounts)
          .sort(([a], [b]) => RISK_ORDER.indexOf(a as (typeof RISK_ORDER)[number]) - RISK_ORDER.indexOf(b as (typeof RISK_ORDER)[number]))
          .map(([impact, count]) => `${count} ${impact}`)
          .join(", ") || `${selected.length} finding(s)`;
      summary = summary + " - Cryptographic vulnerabilities found in CBOM scan";

      const descSections = selected.map((f, idx) => {
        const parts: string[] = [`--- Finding ${idx + 1} ---`];
        parts.push(`Algorithm: ${(f.algorithm_name ?? f.title ?? "Unknown").trim()}`);
        if ((f.algorithm_type ?? "").trim()) parts.push(`Type: ${f.algorithm_type!.trim()}`);
        if ((f.crypto_strength ?? "").trim()) parts.push(`Strength: ${f.crypto_strength!.trim()}`);
        if ((f.impact ?? "").trim()) parts.push(`Impact: ${f.impact!.trim()}`);
        if (f.risk_score != null) parts.push(`Risk Score: ${f.risk_score}`);
        if ((f.location ?? "").trim()) parts.push(`Location: ${f.location!.trim()}`);
        if (f.quantum_safe === false) parts.push("Quantum Safety: Vulnerable");
        if ((f.suggested_fix ?? "").trim()) parts.push(`Suggested Fix: ${f.suggested_fix!.trim()}`);
        return parts.join("\n");
      });
      const description = descSections.join("\n\n");

      await createTicket(tid, "cbom", sid, {
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
        toast.success(`Jira ticket created for ${selectedFindings.size} finding(s)`, { id: context.toastId });
      } else {
        toast.success(`Jira ticket created for ${selectedFindings.size} finding(s)`);
      }
      setSelectedFindings(new Set());
    },
    onError: (err, _variables, context) => {
      if (context?.toastId != null) toast.dismiss(context.toastId);
      showErrorToast(err, "Failed to create Jira ticket(s)");
    },
  });

  const bulkStatusMutation = useMutation({
    mutationFn: async (state: "fixed" | "ignored" | "in_progress" | "not_started") => {
      if (!sid || Number.isNaN(tid)) throw new Error("Missing team or scan");
      const ids = Array.from(selectedFindings);
      const results = await Promise.allSettled(
        ids.map((finding_id) =>
          toggleFindingState({ team_id: tid, type: "cbom", scan_id: sid, finding_id, state }),
        ),
      );
      const succeededIds = ids.filter((_, i) => results[i].status === "fulfilled");
      const failedCount = ids.length - succeededIds.length;
      return { succeededIds, succeededCount: succeededIds.length, failedCount };
    },
    onSuccess: ({ succeededIds, succeededCount, failedCount }) => {
      // Refetch so any succeeded status changes are reflected, even on partial failure.
      queryClient.invalidateQueries({ queryKey: ["cbom-conversation-data"] });
      onFindingsUpdated?.();
      if (failedCount === 0) {
        toast.success(`Updated ${succeededCount} finding(s)`);
      } else if (succeededCount === 0) {
        toast.error(`Failed to update ${failedCount} finding(s)`);
      } else {
        toast.warning(`Updated ${succeededCount} finding(s), ${failedCount} failed`);
      }
      // Clear only the findings that succeeded; keep failed ones selected for retry.
      setSelectedFindings((prev) => {
        const next = new Set(prev);
        for (const id of succeededIds) next.delete(id);
        return next;
      });
    },
    onError: (err) => showErrorToast(err, "Error updating finding status"),
  });

  const exportMutation = useMutation({
    mutationFn: () => {
      if (Number.isNaN(tid) || Number.isNaN(sid) || !tid || !sid) {
        throw new Error("Missing or invalid team or scan id");
      }
      return getCBOMExportResults(tid, sid);
    },
    onSuccess: (result) => {
      const blob = result instanceof Blob ? result : new Blob([result]);
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `cbom-report-${scan_id}.pdf`;
      a.click();
      URL.revokeObjectURL(url);
      toast.success("Report downloaded");
    },
    onError: (err) => showErrorToast(err, "Error exporting PDF"),
  });

  const handleDownloadCBOMJson = () => {
    const meta = scanMetadata as Record<string, unknown> | null;
    const cbomJson = meta?.cbom_json ?? (data as Record<string, unknown> | null)?.cbom_json;
    if (!cbomJson) { toast.error("No CBOM JSON available"); return; }
    try {
      const bom = overlayBomCompliance(cbomJson, meta?.cbom_compliance);
      const blob = new Blob([JSON.stringify(bom, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `cbom-cyclonedx-${scan_id}.json`;
      a.click();
      URL.revokeObjectURL(url);
      toast.success("CycloneDX CBOM JSON downloaded");
    } catch (err) {
      showErrorToast(err, "Failed to download CycloneDX CBOM JSON");
    }
  };

  const downloadBlob = (blob: Blob, filename: string) => {
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleCertInAttest = async (
    frameworkKey: string,
    requirementId: string,
    file: File,
  ) => {
    if (Number.isNaN(tid) || Number.isNaN(sid) || !tid || !sid) {
      throw new Error("Missing team or scan id");
    }
    await postCertInAttestation(tid, "cbom", sid, frameworkKey, requirementId, file);
    queryClient.invalidateQueries({ queryKey: ["cbom-conversation-data"] });
  };

  const handleDownloadVex = async () => {
    try {
      const cached = (scanMetadata as CbomScanMetadata | null)?.vex_json;
      const vex = cached ?? (await getCertInVex(tid, "cbom", sid));
      downloadBlob(
        new Blob([JSON.stringify(vex, null, 2)], { type: "application/json" }),
        `cbom-vex-${scan_id}.json`,
      );
      toast.success("VEX downloaded");
      queryClient.invalidateQueries({ queryKey: ["cbom-conversation-data"] });
    } catch (err) {
      showErrorToast(err, "Failed to download VEX");
    }
  };

  const handleDownloadSignature = async () => {
    try {
      let sig = (scanMetadata as CbomScanMetadata | null)?.bom_signature;
      if (!sig) {
        const res = await postCertInSign(tid, "cbom", sid);
        sig = res.bom_signature;
        queryClient.invalidateQueries({ queryKey: ["cbom-conversation-data"] });
      }
      downloadBlob(
        new Blob([JSON.stringify(sig, null, 2)], { type: "application/json" }),
        `cbom-signature-${scan_id}.json`,
      );
      toast.success("BOM signature downloaded");
    } catch (err) {
      showErrorToast(err, "Failed to download BOM signature");
    }
  };

  const handleDownloadEvidencePack = async () => {
    try {
      const blob = await getCertInEvidencePack(tid, "cbom", sid);
      downloadBlob(blob, `certin-evidence-pack-cbom-${scan_id}.zip`);
      toast.success("Evidence pack downloaded");
      queryClient.invalidateQueries({ queryKey: ["cbom-conversation-data"] });
    } catch (err) {
      showErrorToast(err, "Failed to download evidence pack");
    }
  };

  const cardData = dashboard?.card_data;
  const meta = scanMetadata as CbomScanMetadata | null;

  // Crypto-asset charts from the aibom CBOM lane's run-object (C9). Present only
  // on scans produced by the reconciled aibom lane; legacy worker CBOM scans
  // carry no `cbom_distributions`, so the charts simply don't render.
  const cryptoDistributions = useMemo<CbomDistributions | null>(() => {
    const fromData = (data as Record<string, unknown> | null)?.cbom_distributions;
    const fromMeta = (scanMetadata as Record<string, unknown> | null)?.cbom_distributions;
    const dist = (fromData ?? fromMeta) as CbomDistributions | undefined;
    return dist ?? null;
  }, [data, scanMetadata]);

  // Crypto dependency graph (I1 cbom_graph). Same source precedence as the
  // distributions — present only on reconciled aibom-lane scans; F1's asset-type
  // breakdown + dependency-graph viz render only when it carries nodes.
  const cryptoGraph = useMemo<CbomGraph | null>(() => {
    const fromData = (data as Record<string, unknown> | null)?.cbom_graph;
    const fromMeta = (scanMetadata as Record<string, unknown> | null)?.cbom_graph;
    const g = (fromData ?? fromMeta) as CbomGraph | undefined;
    return g && Array.isArray(g.nodes) ? g : null;
  }, [data, scanMetadata]);

  const cryptoGraphCompact = useMemo<CbomGraph | null>(() => {
    const fromData = (data as Record<string, unknown> | null)?.cbom_graph_compact;
    const fromMeta = (scanMetadata as Record<string, unknown> | null)?.cbom_graph_compact;
    const g = (fromData ?? fromMeta) as CbomGraph | undefined;
    return g && Array.isArray(g.nodes) ? g : null;
  }, [data, scanMetadata]);

  const cryptoGraphExpanded = useMemo<CbomGraph | null>(() => {
    const fromData = (data as Record<string, unknown> | null)?.cbom_graph_expanded;
    const fromMeta = (scanMetadata as Record<string, unknown> | null)?.cbom_graph_expanded;
    const g = (fromData ?? fromMeta) as CbomGraph | undefined;
    return g && Array.isArray(g.nodes) ? g : null;
  }, [data, scanMetadata]);

  // Tri-state compliance matrix (F3). Same source precedence as the
  // distributions/graph — present only on reconciled aibom-lane scans; the
  // matrix renders only when it carries ≥1 framework object.
  const cryptoCompliance = useMemo<CbomCompliance | null>(() => {
    const fromData = (data as Record<string, unknown> | null)?.cbom_compliance;
    const fromMeta = (scanMetadata as Record<string, unknown> | null)?.cbom_compliance;
    const c = (fromData ?? fromMeta) as CbomCompliance | undefined;
    return c && typeof c === "object" ? c : null;
  }, [data, scanMetadata]);

  const showTabs = team_id && scan_id != null;
  const hasTicketingTab = showTabs && onIntegrationSettingsUpdated != null;

  const hasActiveFindingsFilters =
    searchQuery.trim() !== "" ||
    relatedFindingRefs.length > 0 ||
    filterImpact !== "all" ||
    filterRiskScore !== "all" ||
    strengthFilter !== "all" ||
    typeFilter !== "all" ||
    quantumFilter !== "all";

  return (
    <div className="container mx-auto p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          {(scan_id != null || team_id) && (
            <Button
              variant="outline"
              size="icon"
              onClick={() => {
                const backRoute =
                  origin === "chat" && team_id && scan_id != null
                    ? `/${team_id}/cbom/${scan_id}`
                    : team_id
                      ? `/${team_id}/cbom`
                      : "/cbom";
                router.push(backRoute);
              }}
              className="cursor-pointer"
            >
              <ArrowLeft className="h-4 w-4" />
            </Button>
          )}
          <div>
            <h1 className="text-3xl font-bold text-zinc-900 dark:text-white flex items-center gap-2">
              <ShieldCheck className="h-7 w-7 text-blue-600 dark:text-blue-400" />
              CBOM Scan Results
            </h1>
            <div className="flex flex-wrap items-center gap-3 mt-1 text-sm text-zinc-600 dark:text-zinc-400">
              {meta?.repo_url && (
                <span className="flex items-center gap-1"><GitBranch className="h-3.5 w-3.5" /> {meta.repo_url}</span>
              )}
              {meta?.branch && <span className="flex items-center gap-1">Branch: {meta.branch}</span>}
              {meta?.zip_file_used && (
                <Badge variant="outline" className="border-zinc-300 text-zinc-600 dark:border-zinc-700 dark:text-zinc-400">
                  <Archive className="h-3 w-3 mr-1" /> Zip Upload
                </Badge>
              )}
              {meta?.cbom_file_used && (
                <Badge variant="outline" className="border-zinc-300 text-zinc-600 dark:border-zinc-700 dark:text-zinc-400">
                  <Lock className="h-3 w-3 mr-1" /> CBOM File
                </Badge>
              )}
              {meta?.scan_binaries && (
                <Badge variant="outline" className="border-blue-500/50 text-blue-600 dark:text-blue-400">Binary Scan</Badge>
              )}
            </div>
          </div>
        </div>
        {team_id && scan_id != null && (
          <div className="flex items-center gap-2 flex-wrap justify-end">
            <Button
              variant="outline"
              className="cursor-pointer"
              onClick={handleDownloadCBOMJson}
            >
              <Download className="h-4 w-4 mr-2" />
              CycloneDX JSON
            </Button>
            <Button
              variant="outline"
              className="cursor-pointer"
              onClick={() => void handleDownloadVex()}
            >
              <Download className="h-4 w-4 mr-2" />
              VEX
            </Button>
            <Button
              variant="outline"
              className="cursor-pointer"
              onClick={() => void handleDownloadSignature()}
            >
              <Download className="h-4 w-4 mr-2" />
              Signature
            </Button>
            <Button
              variant="outline"
              className="cursor-pointer"
              onClick={() => void handleDownloadEvidencePack()}
            >
              <Download className="h-4 w-4 mr-2" />
              Evidence pack
            </Button>
            <Button
              variant="outline"
              className="cursor-pointer bg-zinc-700 hover:bg-zinc-600 text-white border-zinc-600"
              onClick={() => exportMutation.mutate()}
              disabled={exportMutation.isPending}
            >
              {exportMutation.isPending ? <Loader2 className="h-4 w-4 mr-2 animate-spin" /> : <Download className="h-4 w-4 mr-2" />}
              {exportMutation.isPending ? "Downloading..." : "PDF Report"}
            </Button>
            <Button
              variant="default"
              className="cursor-pointer bg-blue-600 hover:bg-blue-700 text-white"
              onClick={() => router.push(`/${team_id}/cbom/${scan_id}`)}
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
          inputId="cbom-jira-project-id"
        />
      ) : (
        <>
          {/* Scan metadata cards */}
          {meta && typeof meta === "object" && (
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
              {meta.branch != null && String(meta.branch).trim() !== "" && (
                <Card className="border-zinc-200 dark:border-zinc-800">
                  <CardContent className="pt-4 pb-4 flex items-center gap-3">
                    <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-amber-100 dark:bg-amber-900/30 text-amber-600 dark:text-amber-400">
                      <GitBranch className="h-5 w-5" />
                    </div>
                    <div className="min-w-0">
                      <p className="text-xs font-medium text-zinc-500 dark:text-zinc-400">Branch</p>
                      <p className="text-lg font-semibold text-zinc-900 dark:text-zinc-100">{String(meta.branch)}</p>
                    </div>
                  </CardContent>
                </Card>
              )}
              {meta.zip_file_used != null && (
                <Card className="border-zinc-200 dark:border-zinc-800">
                  <CardContent className="pt-4 pb-4 flex items-center gap-3">
                    <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-zinc-100 dark:bg-zinc-800 text-zinc-600 dark:text-zinc-400">
                      <Archive className="h-5 w-5" />
                    </div>
                    <div className="min-w-0">
                      <p className="text-xs font-medium text-zinc-500 dark:text-zinc-400">Source</p>
                      <p className="text-sm font-semibold text-zinc-900 dark:text-zinc-100">{meta.zip_file_used ? "ZIP upload" : "Repository"}</p>
                    </div>
                  </CardContent>
                </Card>
              )}
              {meta.cbom_file_used && (
                <Card className="border-zinc-200 dark:border-zinc-800">
                  <CardContent className="pt-4 pb-4 flex items-center gap-3">
                    <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-violet-100 dark:bg-violet-900/30 text-violet-600 dark:text-violet-400">
                      <Lock className="h-5 w-5" />
                    </div>
                    <div className="min-w-0">
                      <p className="text-xs font-medium text-zinc-500 dark:text-zinc-400">Input</p>
                      <p className="text-sm font-semibold text-zinc-900 dark:text-zinc-100">CBOM file</p>
                    </div>
                  </CardContent>
                </Card>
              )}
            </div>
          )}

          {/* Crypto-asset charts (aibom CBOM lane) */}
          {cryptoDistributions && (
            <CbomCryptoCharts
              distributions={cryptoDistributions}
              graph={cryptoGraph}
              graphCompact={cryptoGraphCompact}
              graphExpanded={cryptoGraphExpanded}
              compliance={cryptoCompliance}
              onAttest={handleCertInAttest}
              findings={findingsList ?? []}
              onOpenFinding={(f) => setSelectedFinding(f)}
            />
          )}
          <RbiCsfRollup
            rollup={meta?.rbi_csf_rollup as RbiCsfRollupData | undefined}
            onAttest={handleCertInAttest}
            onViewFindings={handleViewRelatedFindings}
            findings={findingsList ?? []}
            refAliases={relatedRefAliases}
          />
          <CertInLanePosture
            lane="cbom"
            rollup={meta?.certin_posture as CertInRollupData | undefined}
            onAttest={handleCertInAttest}
            onViewFindings={handleViewRelatedFindings}
            findings={findingsList ?? []}
            refAliases={relatedRefAliases}
          />

          {/* Dashboard */}
          {dashboard && cardData && (
            <CbomDashboardCharts dashboard={dashboard} findingsList={findingsList ?? []} />
          )}

          {/* Findings */}
          <Card id="bom-findings">
            <CardHeader>
              <CardTitle>Cryptographic findings</CardTitle>
              <CardDescription>
                {filteredFindings.length} of {(findingsList ?? []).length} findings. Select rows to create Jira tickets; use Action to change finding state.
              </CardDescription>
            </CardHeader>
            <CardContent>
              {(findingsList ?? []).length > 0 && (
                <div className="flex flex-wrap items-center gap-3 mb-4">
                  <div className="relative flex-1 min-w-[200px] max-w-sm">
                    <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-zinc-400" />
                    <Input
                      type="search"
                      placeholder="Search by algorithm, description, location..."
                      value={searchQuery}
                      onChange={(e) => {
                        setRelatedFindingRefs([]);
                        setSearchQuery(e.target.value);
                      }}
                      className="pl-9 h-9 cursor-text"
                      aria-label="Search findings table"
                    />
                  </div>
                  <Select value={filterImpact} onValueChange={setFilterImpact}>
                    <SelectTrigger className="h-9 min-w-[140px] cursor-pointer">
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
                  <Select value={filterRiskScore} onValueChange={(v) => setFilterRiskScore(v as RiskScoreFilter)}>
                    <SelectTrigger className="h-9 min-w-[140px] cursor-pointer">
                      <SelectValue placeholder="Risk score" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="all">Risk score</SelectItem>
                      <SelectItem value="critical">Critical (≥9)</SelectItem>
                      <SelectItem value="high">High (7–9)</SelectItem>
                      <SelectItem value="medium">Medium (5–7)</SelectItem>
                      <SelectItem value="low">Low (&lt;5)</SelectItem>
                    </SelectContent>
                  </Select>
                  <Select value={strengthFilter} onValueChange={setStrengthFilter}>
                    <SelectTrigger className="h-9 min-w-[140px] cursor-pointer">
                      <SelectValue placeholder="Strength" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="all">All strengths</SelectItem>
                      <SelectItem value="weak">Weak</SelectItem>
                      <SelectItem value="moderate">Moderate</SelectItem>
                      <SelectItem value="strong">Strong</SelectItem>
                      <SelectItem value="quantum_safe">Quantum-Safe</SelectItem>
                    </SelectContent>
                  </Select>
                  <Select value={typeFilter} onValueChange={setTypeFilter}>
                    <SelectTrigger className="h-9 min-w-[150px] cursor-pointer">
                      <SelectValue placeholder="Type" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="all">All types</SelectItem>
                      {uniqueTypes.map((t) => (
                        <SelectItem key={t} value={t}>{t.replace(/_/g, " ")}</SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                  <Select value={quantumFilter} onValueChange={setQuantumFilter}>
                    <SelectTrigger className="h-9 min-w-[140px] cursor-pointer">
                      <SelectValue placeholder="Quantum" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="all">All</SelectItem>
                      <SelectItem value="safe">Quantum-Safe</SelectItem>
                      <SelectItem value="vulnerable">Vulnerable</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              )}
              {hasActiveFindingsFilters && (
                <span className="text-sm text-zinc-500 dark:text-zinc-400 block mb-4">
                  Showing {filteredFindings.length} of {(findingsList ?? []).length} findings
                </span>
              )}
              <FindingSelectionMenu
                selectedCount={selectedFindings.size}
                onClearSelection={() => setSelectedFindings(new Set())}
                ticketType="jira"
                jiraOnClickHandler={() => createJiraTicketsMutation.mutate()}
                isJiraCreating={createJiraTicketsMutation.isPending}
                onBulkStatusChange={(status) => bulkStatusMutation.mutate(status)}
                isBulkStatusChanging={bulkStatusMutation.isPending}
              />
              <ScrollArea className="h-[500px] rounded-md border border-zinc-200 dark:border-zinc-800">
                <Table className="min-w-max">
                  <TableHeader>
                    <TableRow>
                      <TableHead className="w-[48px]">
                        <Checkbox
                          checked={filteredFindings.length > 0 && selectedFindings.size === filteredFindings.length}
                          onCheckedChange={() => {
                            if (selectedFindings.size === filteredFindings.length) setSelectedFindings(new Set());
                            else setSelectedFindings(new Set(filteredFindings.map((f) => f.id)));
                          }}
                          aria-label="Select all rows"
                          className="cursor-pointer"
                        />
                      </TableHead>
                      <TableHead className="min-w-[160px]">Algorithm</TableHead>
                      <TableHead className="min-w-[120px]">Type</TableHead>
                      <TableHead className="min-w-[90px]">Impact</TableHead>
                      <TableHead className="min-w-[110px]">Strength</TableHead>
                      <TableHead className="min-w-[100px]">Quantum</TableHead>
                      <TableHead className="min-w-[90px] text-center">Risk score</TableHead>
                      <TableHead className="min-w-[140px]">Location</TableHead>
                      <TableHead className="min-w-[100px]">Status</TableHead>
                      <TableHead className="min-w-[100px] text-right">Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {filteredFindings.length === 0 ? (
                      <TableRow>
                        <TableCell colSpan={10} className="text-center py-8 text-zinc-500 dark:text-zinc-400">
                          {relatedFindingRefs.length > 0
                            ? "No findings match these related assets. Related refs may point at inventory-only components without a finding row — clear the related-asset filter to see all findings."
                            : "No findings match your filters."}
                        </TableCell>
                      </TableRow>
                    ) : (
                      filteredFindings.map((finding) => {
                        const statusLabel = (finding.status ?? "not_started").replace(/_/g, " ");
                        return (
                          <TableRow
                            key={finding.id}
                            className={`hover:bg-zinc-50 dark:hover:bg-zinc-800/50 ${selectedFindings.has(finding.id) ? "bg-zinc-100 dark:bg-zinc-800/70" : ""}`}
                          >
                            <TableCell onClick={(e) => e.stopPropagation()} className="w-[48px]">
                              <Checkbox
                                checked={selectedFindings.has(finding.id)}
                                onCheckedChange={() => {
                                  const next = new Set(selectedFindings);
                                  if (next.has(finding.id)) next.delete(finding.id);
                                  else next.add(finding.id);
                                  setSelectedFindings(next);
                                }}
                                aria-label={`Select ${finding.algorithm_name || finding.title}`}
                                className="cursor-pointer"
                              />
                            </TableCell>
                            <TableCell className="font-medium">
                              <button
                                type="button"
                                onClick={() => setSelectedFinding(finding)}
                                className="text-left text-blue-600 hover:text-blue-700 dark:text-blue-400 dark:hover:text-blue-300 hover:underline cursor-pointer font-medium max-w-[150px] truncate block"
                                title={finding.algorithm_name || finding.title}
                              >
                                {finding.algorithm_name || finding.title}
                              </button>
                            </TableCell>
                            <TableCell className="text-sm text-zinc-600 dark:text-zinc-400">
                              {finding.algorithm_type?.replace(/_/g, " ") ?? "—"}
                            </TableCell>
                            <TableCell>
                              <Badge variant="outline" className={getImpactBadgeClass(finding.impact)}>{finding.impact}</Badge>
                            </TableCell>
                            <TableCell>
                              <Badge variant="outline" className={getStrengthBadgeClass(finding.crypto_strength)}>
                                {finding.crypto_strength ?? "—"}
                              </Badge>
                            </TableCell>
                            <TableCell>
                              {finding.quantum_safe === true ? (
                                <Badge variant="outline" className="border-emerald-500/50 text-emerald-600 dark:text-emerald-400">Safe</Badge>
                              ) : finding.quantum_safe === false ? (
                                <Badge variant="outline" className="border-red-500/50 text-red-600 dark:text-red-400">Vulnerable</Badge>
                              ) : (
                                <span className="text-zinc-500 dark:text-zinc-400 text-xs">—</span>
                              )}
                            </TableCell>
                            <TableCell className="text-center">
                              <span
                                className={`inline-flex items-center justify-center min-w-9 px-2 py-1 rounded-md text-xs font-semibold tabular-nums ${getRiskScoreBoxClass(finding.risk_score)}`}
                                title="Risk score"
                              >
                                {finding.risk_score?.toFixed(1) ?? "—"}
                              </span>
                            </TableCell>
                            <TableCell className="text-sm text-zinc-600 dark:text-zinc-400 max-w-[150px] truncate" title={finding.location ?? ""}>
                              {finding.location ?? "—"}
                            </TableCell>
                            <TableCell>
                              <span className={`inline-flex items-center justify-center px-2.5 py-1 rounded-md text-xs font-medium capitalize ${getFindingStatusBadgeClass(finding.status ?? "not_started")}`}>
                                {statusLabel}
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
                                  <DropdownMenuItem className="cursor-pointer gap-2" onClick={() => toggleFindingMutation.mutate({ finding_id: finding.id, state: "fixed" })} disabled={toggleFindingMutation.isPending}>
                                    <CheckCircle className="h-4 w-4" /> Mark as Fixed
                                  </DropdownMenuItem>
                                  <DropdownMenuItem className="cursor-pointer gap-2" onClick={() => toggleFindingMutation.mutate({ finding_id: finding.id, state: "ignored" })} disabled={toggleFindingMutation.isPending}>
                                    <EyeOff className="h-4 w-4" /> Mark as Ignored
                                  </DropdownMenuItem>
                                  <DropdownMenuItem className="cursor-pointer gap-2" onClick={() => toggleFindingMutation.mutate({ finding_id: finding.id, state: "in_progress" })} disabled={toggleFindingMutation.isPending}>
                                    <Loader2 className="h-4 w-4" /> Mark as In progress
                                  </DropdownMenuItem>
                                  <DropdownMenuItem className="cursor-pointer gap-2" onClick={() => toggleFindingMutation.mutate({ finding_id: finding.id, state: "not_started" })} disabled={toggleFindingMutation.isPending}>
                                    <Circle className="h-4 w-4" /> Mark as Not started
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
            </CardContent>
          </Card>

          {/* Top Cryptographic Risks */}
          {dashboard?.top_risks && dashboard.top_risks.length > 0 && (
            <Card className="border-zinc-200 dark:border-zinc-800">
              <CardHeader>
                <CardTitle className="text-base">Top cryptographic risks</CardTitle>
                <CardDescription>Highest-risk cryptographic assets</CardDescription>
              </CardHeader>
              <CardContent>
                <ScrollArea className="h-[320px] w-full rounded-md border border-zinc-200 dark:border-zinc-800">
                  <Table className="min-w-max">
                    <TableHeader>
                      <TableRow>
                        <TableHead className="min-w-[160px]">Algorithm</TableHead>
                        <TableHead className="min-w-[120px]">Type</TableHead>
                        <TableHead className="min-w-[110px]">Strength</TableHead>
                        <TableHead className="min-w-[110px]">Quantum safe</TableHead>
                        <TableHead className="min-w-[120px]">Impact</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {dashboard.top_risks.map((risk, i) => (
                        <TableRow key={i} className="hover:bg-zinc-50 dark:hover:bg-zinc-800/50">
                          <TableCell className="font-medium text-zinc-900 dark:text-zinc-100">{risk.algorithm_name}</TableCell>
                          <TableCell className="text-sm text-zinc-600 dark:text-zinc-400">{risk.algorithm_type?.replace(/_/g, " ")}</TableCell>
                          <TableCell>
                            <Badge variant="outline" className={getStrengthBadgeClass(risk.crypto_strength)}>
                              {risk.crypto_strength}
                            </Badge>
                          </TableCell>
                          <TableCell>
                            {risk.quantum_safe ? (
                              <Badge variant="outline" className="border-emerald-500/50 text-emerald-600 dark:text-emerald-400">Yes</Badge>
                            ) : (
                              <Badge variant="outline" className="border-red-500/50 text-red-600 dark:text-red-400">No</Badge>
                            )}
                          </TableCell>
                          <TableCell className="text-sm text-zinc-600 dark:text-zinc-400 max-w-[200px] truncate" title={risk.impact}>{risk.impact}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </ScrollArea>
              </CardContent>
            </Card>
          )}
        </>
      )}

      {/* Finding Detail Dialog */}
      <Dialog open={!!selectedFinding} onOpenChange={(open) => !open && setSelectedFinding(null)}>
        <DialogContent className="sm:max-w-3xl max-h-[90vh] flex flex-col p-0 gap-0 overflow-hidden bg-white dark:bg-zinc-900">
          <DialogHeader className="px-6 pt-6 pb-2 shrink-0">
            <DialogTitle className="pr-8">{selectedFinding?.algorithm_name || selectedFinding?.title || "Finding details"}</DialogTitle>
          </DialogHeader>
          {selectedFinding && (
            <div className="h-[70vh] min-h-0 shrink px-6 pb-6">
              <ScrollArea className="h-full w-full rounded-md">
                <div className="space-y-4 pt-2 pr-4">
                  {/* Metadata grid */}
                  <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
                    <div>
                      <div className="text-xs font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400 mb-1">Algorithm type</div>
                      <p className="text-sm text-zinc-700 dark:text-zinc-300">{selectedFinding.algorithm_type?.replace(/_/g, " ") ?? "—"}</p>
                    </div>
                    <div>
                      <div className="text-xs font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400 mb-1">Crypto strength</div>
                      <Badge variant="outline" className={getStrengthBadgeClass(selectedFinding.crypto_strength)}>{selectedFinding.crypto_strength ?? "—"}</Badge>
                    </div>
                    <div>
                      <div className="text-xs font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400 mb-1">Key size</div>
                      <p className="text-sm text-zinc-700 dark:text-zinc-300">{selectedFinding.key_size ? `${selectedFinding.key_size} bits` : "—"}</p>
                    </div>
                    <div>
                      <div className="text-xs font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400 mb-1">Quantum safe</div>
                      {selectedFinding.quantum_safe === true ? (
                        <Badge variant="outline" className="border-emerald-500/50 text-emerald-600 dark:text-emerald-400">Yes</Badge>
                      ) : selectedFinding.quantum_safe === false ? (
                        <Badge variant="outline" className="border-red-500/50 text-red-600 dark:text-red-400">No</Badge>
                      ) : <span className="text-sm text-zinc-700 dark:text-zinc-300">—</span>}
                    </div>
                    <div>
                      <div className="text-xs font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400 mb-1">Impact</div>
                      <Badge variant="outline" className={getImpactBadgeClass(selectedFinding.impact)}>{selectedFinding.impact}</Badge>
                    </div>
                    <div>
                      <div className="text-xs font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400 mb-1">Risk score</div>
                      <span
                        className={`inline-flex items-center justify-center min-w-9 px-2 py-1 rounded-md text-xs font-semibold tabular-nums ${getRiskScoreBoxClass(selectedFinding.risk_score)}`}
                        title="Risk score"
                      >
                        {selectedFinding.risk_score?.toFixed(1) ?? "—"}
                      </span>
                    </div>
                  </div>

                  {selectedFinding.location && (
                    <div>
                      <div className="text-xs font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400 mb-1">Location</div>
                      <p className="text-sm font-mono text-zinc-700 dark:text-zinc-300 bg-zinc-100 dark:bg-zinc-800 px-3 py-2 rounded-md border border-zinc-200 dark:border-zinc-700 break-all">{selectedFinding.location}</p>
                    </div>
                  )}

                  {selectedFinding.description && (
                    <div>
                      <div className="text-xs font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400 mb-1">Description</div>
                      <p className="text-sm text-zinc-700 dark:text-zinc-300 whitespace-pre-wrap">{selectedFinding.description}</p>
                    </div>
                  )}

                  {selectedFinding.snippet && (
                    <div>
                      <div className="text-xs font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400 mb-1">Code snippet</div>
                      <pre className="text-xs font-mono text-zinc-700 dark:text-zinc-300 bg-zinc-100 dark:bg-zinc-800 px-3 py-2 rounded-md overflow-x-auto whitespace-pre-wrap border border-zinc-200 dark:border-zinc-700">{selectedFinding.snippet}</pre>
                    </div>
                  )}

                  {/* OWASP Top 10 */}
                  {(() => {
                    const entries = getOwaspComplianceEntries(selectedFinding.owasp_top_10 as OwaspOrCompliance);
                    if (entries.length === 0) return null;
                    return (
                      <div>
                        <div className="text-xs font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400 mb-1">OWASP Top 10</div>
                        <div className="flex flex-wrap gap-1">
                          {entries.map(([key, value]) => (
                            <Badge key={key} variant="secondary" className="text-xs bg-purple-100 dark:bg-purple-900/40 text-purple-800 dark:text-purple-200">
                              {OWASP_KEY_TO_LABEL[key] ?? value}
                            </Badge>
                          ))}
                        </div>
                      </div>
                    );
                  })()}

                  {/* Compliance Controls */}
                  {(() => {
                    const entries = getOwaspComplianceEntries(selectedFinding.compliance_controls as OwaspOrCompliance);
                    if (entries.length === 0) return null;
                    return (
                      <div>
                        <div className="text-xs font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400 mb-1">Compliance controls</div>
                        <div className="flex flex-wrap gap-1">
                          {entries.map(([key, value]) => (
                            <Badge key={key} variant="outline" className="text-xs">
                              {COMPLIANCE_KEY_TO_LABEL[key] ?? value}
                            </Badge>
                          ))}
                        </div>
                      </div>
                    );
                  })()}

                  {selectedFinding.suggested_fix && (
                    <div>
                      <div className="text-xs font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400 mb-1">Suggested fix</div>
                      <p className="text-sm text-zinc-700 dark:text-zinc-300 whitespace-pre-wrap">{selectedFinding.suggested_fix}</p>
                    </div>
                  )}

                  <RemediationPanel
                    teamId={String(team_id)}
                    scanType="cbom"
                    scanId={typeof scan_id === "number" ? scan_id : parseInt(String(scan_id), 10)}
                    findingId={selectedFinding.id}
                    existingRemediation={selectedFinding.remediation}
                  />
                </div>
              </ScrollArea>
            </div>
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
}
