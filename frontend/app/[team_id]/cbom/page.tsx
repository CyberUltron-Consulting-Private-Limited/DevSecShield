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
import { Plus, MoreVertical, Pencil, Trash2, RefreshCcw, Loader2, Eye, Clock, CheckCircle, CalendarPlus, CalendarCheck, Search, X, GitBranch, FileArchive, MinusCircle, Shield, AlertTriangle, Activity, ChevronDown, ArrowUpDown, Check, Filter, DollarSign, TrendingUp, TrendingDown, Lock, ShieldAlert, ShieldCheck, Key, Download, FileText, Network } from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";
import { singleFlight } from "@/utils/single_flight";
import {
  CBOM_DELIVERABLES,
  deleteCBOMScan,
  downloadCbomDeliverable,
  getCbomDeliverables,
  getCBOMScans,
  getCbomRun,
  renameCBOMScan,
  createCBOMScan,
} from "@/utils/backend_api";
import type { CBOMConversation } from "@/utils/backend_api";
import type { CBOMDashboardData } from "@/utils/backend_api";
import type { CbomDeliverableSlug } from "@/utils/backend_api";
import { useMutation, useQueries, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { showErrorToast } from "@/utils/error-handler";
import { formatDateIst as formatDate } from "@/utils/datetime";
import { readinessText, readinessTone, type ReadinessTone } from "@/utils/cbomReadiness";
import { originLabel, sourcesRunsHref } from "@/components/cbom/resultOrigin";
import {
  filterAndSortRows,
  displayRiskScore,
  rowsFromListResponse,
  activeRunIds,
  changedRunStatuses,
  liveRunFromDetail,
  refundedHint,
  runCountsLine,
  withLiveProgress,
  RUNS_LIST_ERROR_NOTICE,
  type LiveRun,
  runProgress,
  runsLoadedNote,
  type ResultRow,
  type RiskCounts,
  type RiskScoreFilter,
  type RunResultRow,
  type TableSortBy,
} from "@/components/cbom/results/resultRows";
import { resultsHref } from "@/components/cbom/results/resultsHref";
import { isActiveStatus } from "@/components/cbom/results/statusBuckets";
import { createOutageGate, listView } from "@/components/cbom/results/listErrors";
import { cbomResultsListKey, cbomSourcesKeys } from "@/components/cbom/sources/keys";
import { AgilityBaselineSection } from "@/components/cbom/grade/AgilityBaseline";
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
  Cell,
  PolarAngleAxis,
  PolarGrid,
  Radar,
  RadarChart,
  XAxis,
  YAxis,
} from "recharts";

type ScanStatus = "pending" | "started" | "retry" | "failure" | "success" | "partial" | "not_started" | "cancelled";

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

/** CBOM `info` is typed string | null; safely extract a numeric progress percent if present. */
function getScanProgress(info: CBOMConversation["info"]): number | null {
  if (info != null && typeof info === "object" && typeof (info as { current?: number }).current === "number") {
    return (info as { current?: number }).current ?? null;
  }
  return null;
}

const STATUS_BADGES: Record<ScanStatus, { variant: "outline" | "secondary" | "destructive" | "default"; className: string; label: string }> = {
  not_started: { variant: "outline", className: "text-zinc-500 dark:text-zinc-500", label: "Not Started" },
  pending: { variant: "outline", className: "text-zinc-600 dark:text-zinc-400", label: "Pending" },
  started: { variant: "secondary", className: "bg-blue-500 hover:bg-blue-600 text-white", label: "Started" },
  retry: { variant: "secondary", className: "bg-yellow-500 hover:bg-yellow-600 text-white", label: "Retry" },
  failure: { variant: "destructive", className: "", label: "Failure" },
  success: { variant: "default", className: "bg-green-500 hover:bg-green-600 text-white", label: "Success" },
  // a Sources run that finished with some jobs failed: its results exist and open like a success
  partial: { variant: "outline", className: "border-amber-500/60 bg-amber-500/15 text-amber-700 dark:text-amber-300", label: "Partial" },
  cancelled: { variant: "outline", className: "text-amber-600 dark:text-amber-400", label: "Cancelled" },
};

function StatusBadge({ status }: { status: string }) {
  const config = STATUS_BADGES[status as ScanStatus];
  if (!config) return <Badge variant="outline" className="text-zinc-600 dark:text-zinc-400">{status || "—"}</Badge>;
  return <Badge variant={config.variant} className={config.className} data-status={status}>{config.label}</Badge>;
}

function RiskDots({ risk, title }: { risk: RiskCounts; title?: string }) {
  return (
    <div className="flex items-center gap-2 flex-wrap" title={title}>
      {[
        { label: "Critical", n: risk.total_critical, dot: "bg-red-500" },
        { label: "High", n: risk.total_high, dot: "bg-orange-500" },
        { label: "Medium", n: risk.total_medium, dot: "bg-amber-500" },
        { label: "Low", n: risk.total_low, dot: "bg-blue-500" },
      ].map(({ label, n, dot }) => (
        <span key={label} className="flex items-center gap-1.5 shrink-0" title={title ? `${label} (${title.toLowerCase()})` : label}>
          <span className={`h-2 w-2 rounded-full shrink-0 ${dot}`} aria-hidden />
          <span className="tabular-nums">{typeof n === "number" ? n : 0}</span>
        </span>
      ))}
      {risk.total_quantum_vulnerable != null && risk.total_quantum_vulnerable > 0 && (
        <Badge variant="outline" className="border-red-500/50 text-red-600 dark:text-red-400 text-[10px] py-0 shrink-0" title="Quantum Vulnerable">QV:{risk.total_quantum_vulnerable}</Badge>
      )}
    </div>
  );
}

function OwnerCell({ name, email }: { name: string | null; email: string | null }) {
  if (!((name != null && name !== "") || email)) return <>—</>;
  const initials = name
    ? name.trim().split(/\s+/).map((p) => p.charAt(0)).slice(0, 2).join("").toUpperCase() || (email?.[0] ?? "?").toUpperCase()
    : (email?.[0] ?? "?").toUpperCase();
  return (
    <div className="flex items-center gap-2">
      <Avatar className="h-8 w-8 shrink-0">
        <AvatarFallback className="bg-blue-600 text-white text-xs font-medium">{initials}</AvatarFallback>
      </Avatar>
      <div className="min-w-0">
        {name != null && name !== "" && (
          <span className="block truncate max-w-[160px]" title={email ?? ""}>{name}</span>
        )}
        {email != null && email !== "" && (
          <span className="block text-xs text-zinc-500 dark:text-zinc-400 truncate max-w-[160px]">{email}</span>
        )}
      </div>
    </div>
  );
}

/** Mirrors the server's Content-Disposition name: cbom-<slug>-team<id>-<YYYYMMDD>.pdf (UTC date). */
function deliverableFileName(slug: CbomDeliverableSlug, teamId: number, now: Date): string {
  const yyyymmdd = now.toISOString().slice(0, 10).replace(/-/g, "");
  return `cbom-${slug}-team${teamId}-${yyyymmdd}.pdf`;
}

// ─── Dashboard Tab ──────────────────────────────────────────────────────────────

// unjudged readiness (no asset has a quantum verdict) is "n/a" in a neutral colour, never a red 0 %
const READINESS_BOX: Record<ReadinessTone, string> = {
  good: "bg-green-500/15 dark:bg-green-500/10",
  fair: "bg-amber-500/15 dark:bg-amber-500/10",
  poor: "bg-red-500/15 dark:bg-red-500/10",
  none: "bg-zinc-500/15 dark:bg-zinc-500/10",
};
const READINESS_ICON: Record<ReadinessTone, string> = {
  good: "text-green-500",
  fair: "text-amber-500",
  poor: "text-red-500",
  none: "text-zinc-500",
};

function CBOMScanListDashboard({ dashboardData }: { dashboardData: CBOMDashboardData }) {
  const card = dashboardData.card_data;
  const remediation = dashboardData.remediation_actions_required;
  const totalFindings = remediation.total_findings || 1;

  // Severity distribution for radar
  const severityRadarData = useMemo(() => [
    { severity: "Critical", count: dashboardData.severity_distribution.critical },
    { severity: "High", count: dashboardData.severity_distribution.high },
    { severity: "Medium", count: dashboardData.severity_distribution.medium },
    { severity: "Low", count: dashboardData.severity_distribution.low },
  ], [dashboardData.severity_distribution]);

  const radarConfig = { count: { label: "Findings", color: "hsl(220 70% 50%)" } } satisfies ChartConfig;

  // Algorithm type distribution for horizontal bar chart
  const algorithmTypeData = useMemo(() => {
    return Object.entries(dashboardData.algorithm_type_distribution)
      .map(([name, count]) => ({ name: name.replace(/_/g, " "), count, fill: "hsl(220 70% 50%)" }))
      .filter((d) => d.count > 0)
      .sort((a, b) => b.count - a.count);
  }, [dashboardData.algorithm_type_distribution]);

  const barConfig = { count: { label: "Assets", color: "hsl(220 70% 50%)" } } satisfies ChartConfig;

  // Crypto strength distribution for vertical bar chart
  const strengthData = useMemo(() => {
    const COLORS: Record<string, string> = {
      weak: "hsl(0 72% 51%)",
      moderate: "hsl(45 93% 47%)",
      strong: "hsl(142 71% 45%)",
      quantum_safe: "hsl(220 70% 50%)",
    };
    return Object.entries(dashboardData.strength_distribution)
      .map(([name, count]) => ({
        name: name === "quantum_safe" ? "Quantum-Safe" : name.charAt(0).toUpperCase() + name.slice(1),
        count,
        fill: COLORS[name] ?? "hsl(220 9% 46%)",
      }))
      .filter((d) => d.count > 0);
  }, [dashboardData.strength_distribution]);

  const strengthConfig = { count: { label: "Assets", color: "hsl(220 70% 50%)" } } satisfies ChartConfig;

  // Quantum readiness for vertical bar chart (algorithm-only; no Unknown)
  const quantumData = useMemo(() => [
    { name: "Safe", count: dashboardData.quantum_readiness.quantum_safe, fill: "hsl(142 71% 45%)" },
    { name: "Vulnerable", count: dashboardData.quantum_readiness.quantum_vulnerable, fill: "hsl(0 72% 51%)" },
  ].filter((d) => d.count > 0), [dashboardData.quantum_readiness]);

  const quantumConfig = { count: { label: "Assets", color: "hsl(220 70% 50%)" } } satisfies ChartConfig;

  return (
    <div className="space-y-6">
      {/* Card Data - 7 summary stat cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-7 gap-4">
        <Card className="border-zinc-200 dark:border-zinc-800 py-3 px-3">
          <CardContent className="p-0">
            <div className="flex flex-col items-start gap-2">
              <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-blue-500/15 dark:bg-blue-500/10">
                <Lock className="h-4 w-4 text-blue-500" />
              </div>
              <div>
                <p className="text-xs font-medium text-zinc-600 dark:text-zinc-400">Crypto Assets</p>
                <p className="text-xl font-bold text-zinc-900 dark:text-white">{card.total_crypto_assets}</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card className="border-zinc-200 dark:border-zinc-800 py-3 px-3">
          <CardContent className="p-0">
            <div className="flex flex-col items-start gap-2">
              <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-red-500/15 dark:bg-red-500/10">
                <ShieldAlert className="h-4 w-4 text-red-500" />
              </div>
              <div>
                <p className="text-xs font-medium text-zinc-600 dark:text-zinc-400">Weak Algorithms</p>
                <p className="text-xl font-bold text-zinc-900 dark:text-white">{card.total_weak_algorithms}</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card className="border-zinc-200 dark:border-zinc-800 py-3 px-3">
          <CardContent className="p-0">
            <div className="flex flex-col items-start gap-2">
              <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-amber-500/15 dark:bg-amber-500/10">
                <AlertTriangle className="h-4 w-4 text-amber-500" />
              </div>
              <div>
                <p className="text-xs font-medium text-zinc-600 dark:text-zinc-400">Quantum Vulnerable</p>
                <p className="text-xl font-bold text-zinc-900 dark:text-white">{card.total_quantum_vulnerable}</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card className="border-zinc-200 dark:border-zinc-800 py-3 px-3">
          <CardContent className="p-0">
            <div className="flex flex-col items-start gap-2">
              <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-green-500/15 dark:bg-green-500/10">
                <ShieldCheck className="h-4 w-4 text-green-500" />
              </div>
              <div>
                <p className="text-xs font-medium text-zinc-600 dark:text-zinc-400">Certificates</p>
                <p className="text-xl font-bold text-zinc-900 dark:text-white">{card.total_certificates}</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card className="border-zinc-200 dark:border-zinc-800 py-3 px-3">
          <CardContent className="p-0">
            <div className="flex flex-col items-start gap-2">
              <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-violet-500/15 dark:bg-violet-500/10">
                <Key className="h-4 w-4 text-violet-500" />
              </div>
              <div>
                <p className="text-xs font-medium text-zinc-600 dark:text-zinc-400">Keys</p>
                <p className="text-xl font-bold text-zinc-900 dark:text-white">{card.total_keys}</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card className="border-zinc-200 dark:border-zinc-800 py-3 px-3">
          <CardContent className="p-0">
            <div className="flex flex-col items-start gap-2">
              <div className={`flex h-8 w-8 shrink-0 items-center justify-center rounded-lg ${READINESS_BOX[readinessTone(card)]}`}>
                <Shield className={`h-4 w-4 ${READINESS_ICON[readinessTone(card)]}`} />
              </div>
              <div>
                <p className="text-xs font-medium text-zinc-600 dark:text-zinc-400">Quantum Readiness</p>
                <p className="text-xl font-bold text-zinc-900 dark:text-white" title={readinessTone(card) === "none" ? "No asset has a quantum verdict yet (hashes, certificates and protocols are not graded)" : undefined}>{readinessText(card)}</p>
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
                <p className="text-xl font-bold text-zinc-900 dark:text-white">{card.average_risk_score?.toFixed(1) ?? "N/A"}</p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Remediation Actions Required */}
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

      {/* Severity radar, Algorithm type bar, Crypto strength bar */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <Card className="border-zinc-200 dark:border-zinc-800">
          <CardHeader className="items-center pb-2">
            <CardTitle className="text-base">Severity Distribution</CardTitle>
            <CardDescription>Critical / High / Medium / Low</CardDescription>
          </CardHeader>
          <CardContent>
            {severityRadarData.every((r) => r.count === 0) ? (
              <p className="text-center text-sm text-zinc-500 py-8">No severity data yet</p>
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
            <CardTitle className="text-base">Algorithm Type Distribution</CardTitle>
            <CardDescription>Crypto assets by algorithm type</CardDescription>
          </CardHeader>
          <CardContent>
            {algorithmTypeData.length === 0 ? (
              <p className="text-center text-sm text-zinc-500 py-8">No algorithm data yet</p>
            ) : (
              <ChartContainer config={barConfig} className="aspect-auto h-[280px] w-full">
                <BarChart data={algorithmTypeData} layout="vertical" margin={{ left: 20, right: 20 }}>
                  <CartesianGrid horizontal={true} vertical={false} />
                  <XAxis type="number" tickLine={false} axisLine={false} allowDecimals={false} />
                  <YAxis type="category" dataKey="name" tickLine={false} axisLine={false} width={140} />
                  <ChartTooltip cursor={false} content={<ChartTooltipContent />} />
                  <Bar dataKey="count" radius={[0, 4, 4, 0]}>
                    {algorithmTypeData.map((entry, i) => (
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
            <CardTitle className="text-base">Crypto Strength Distribution</CardTitle>
            <CardDescription>Assets by cryptographic strength</CardDescription>
          </CardHeader>
          <CardContent>
            {strengthData.length === 0 ? (
              <p className="text-center text-sm text-zinc-500 py-8">No strength data yet</p>
            ) : (
              <ChartContainer config={strengthConfig} className="aspect-auto h-[280px] w-full">
                <BarChart data={strengthData} margin={{ left: 12, right: 12 }}>
                  <CartesianGrid vertical={false} />
                  <XAxis dataKey="name" tickLine={false} axisLine={false} tickMargin={8} />
                  <YAxis tickLine={false} axisLine={false} allowDecimals={false} />
                  <ChartTooltip cursor={false} content={<ChartTooltipContent />} />
                  <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                    {strengthData.map((entry, i) => (
                      <Cell key={i} fill={entry.fill} />
                    ))}
                  </Bar>
                </BarChart>
              </ChartContainer>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Quantum readiness bar | Top Cryptographic Risks */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <Card className="border-zinc-200 dark:border-zinc-800">
          <CardHeader className="pb-2">
            <CardTitle className="text-base">Quantum Readiness</CardTitle>
            <CardDescription>Assets by quantum safety</CardDescription>
          </CardHeader>
          <CardContent>
            {quantumData.length === 0 ? (
              <p className="text-center text-sm text-zinc-500 py-8">No quantum data yet</p>
            ) : (
              <ChartContainer config={quantumConfig} className="aspect-auto h-[280px] w-full">
                <BarChart data={quantumData} margin={{ left: 12, right: 12 }}>
                  <CartesianGrid vertical={false} />
                  <XAxis dataKey="name" tickLine={false} axisLine={false} tickMargin={8} />
                  <YAxis tickLine={false} axisLine={false} allowDecimals={false} />
                  <ChartTooltip cursor={false} content={<ChartTooltipContent />} />
                  <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                    {quantumData.map((entry, i) => (
                      <Cell key={i} fill={entry.fill} />
                    ))}
                  </Bar>
                </BarChart>
              </ChartContainer>
            )}
          </CardContent>
        </Card>

        <Card className="border-zinc-200 dark:border-zinc-800 flex flex-col lg:col-span-2">
          <CardHeader className="pb-2">
            <CardTitle className="text-base">Top Cryptographic Risks</CardTitle>
            <CardDescription>Sorted by impact</CardDescription>
          </CardHeader>
          <CardContent className="flex-1 min-h-0">
            {!dashboardData.top_risks || dashboardData.top_risks.length === 0 ? (
              <p className="text-center text-sm text-zinc-500 py-8">No cryptographic risk data yet</p>
            ) : (
              <ScrollArea className="h-[280px] w-full">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Algorithm</TableHead>
                      <TableHead>Type</TableHead>
                      <TableHead>Strength</TableHead>
                      <TableHead>Quantum Safe</TableHead>
                      <TableHead>Impact</TableHead>
                      <TableHead>Source</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {dashboardData.top_risks.slice(0, 10).map((risk, i) => (
                      <TableRow key={i} className="hover:bg-zinc-50 dark:hover:bg-zinc-800">
                        <TableCell className="font-medium text-zinc-900 dark:text-white">{risk.algorithm_name}</TableCell>
                        <TableCell className="text-zinc-600 dark:text-zinc-400">{risk.algorithm_type?.replace(/_/g, " ")}</TableCell>
                        <TableCell>
                          <Badge variant="outline" className={
                            risk.crypto_strength === "weak" ? "border-red-500/50 text-red-600 dark:text-red-400" :
                            risk.crypto_strength === "moderate" ? "border-amber-500/50 text-amber-600 dark:text-amber-400" :
                            risk.crypto_strength === "strong" ? "border-green-500/50 text-green-600 dark:text-green-400" :
                            "border-blue-500/50 text-blue-600 dark:text-blue-400"
                          }>{risk.crypto_strength}</Badge>
                        </TableCell>
                        <TableCell>
                          {risk.quantum_safe ? (
                            <Badge variant="outline" className="border-green-500/50 text-green-600 dark:text-green-400">Yes</Badge>
                          ) : (
                            <Badge variant="outline" className="border-red-500/50 text-red-600 dark:text-red-400">No</Badge>
                          )}
                        </TableCell>
                        <TableCell className="text-zinc-600 dark:text-zinc-400 max-w-[200px] truncate" title={risk.impact}>{risk.impact}</TableCell>
                        <TableCell className="text-zinc-600 dark:text-zinc-400 max-w-[220px] truncate" title={originLabel(risk.origin)} data-testid="cbom-top-risk-origin">{originLabel(risk.origin)}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
                <ScrollBar orientation="vertical" />
              </ScrollArea>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

// ─── Main Page ──────────────────────────────────────────────────────────────────

export default function CBOMPage() {
  const router = useRouter();
  const params = useParams();
  const team_id = params?.team_id as string;
  const teamIdNumber = parseInt(team_id);
  const [renameDialogOpen, setRenameDialogOpen] = useState(false);
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false);
  const [createDialogOpen, setCreateDialogOpen] = useState(false);
  const [selectedConversation, setSelectedConversation] = useState<CBOMConversation | null>(null);
  const [metadataDialogOpen, setMetadataDialogOpen] = useState(false);
  const [metadataScan, setMetadataScan] = useState<CBOMConversation | null>(null);
  const [newName, setNewName] = useState("");
  const [newScanTitle, setNewScanTitle] = useState("");
  const [searchQuery, setSearchQuery] = useState("");
  const [statusFilter, setStatusFilter] = useState<string>("all");
  const [riskScoreFilter, setRiskScoreFilter] = useState<RiskScoreFilter>("all");
  const [sortBy, setSortBy] = useState<TableSortBy>("none");
  const queryClient = useQueryClient();

  // CB-38: one list for code scans and CBOM Sources runs. The key carries the numeric team id, so another team's
  // rows never render while the new team's list loads, and Sources run mutations refresh it (sources/keys.ts).
  const listKey = cbomResultsListKey(teamIdNumber);
  const query = useQuery({
    queryKey: listKey,
    queryFn: () => getCBOMScans(teamIdNumber, { toast: false }),
    enabled: Number.isFinite(teamIdNumber),
  });

  // One error toast per outage (not one per failed refetch); a success ends the outage.
  const [outage] = useState(createOutageGate);
  useEffect(() => {
    if (query.errorUpdatedAt && query.error && outage.failed()) showErrorToast(query.error, "Error fetching CBOM scans");
  }, [query.errorUpdatedAt, query.error, outage]);
  useEffect(() => {
    if (query.dataUpdatedAt) outage.succeeded();
  }, [query.dataUpdatedAt, outage]);
  // a failed refetch keeps the loaded rows, the tab and the filters; only a first load that fails shows the error screen
  const view = listView({ isLoading: query.isLoading, isError: query.isError, hasData: query.data !== undefined });

  // runs_list_error (the backend could not list the runs): rows fall back to sources_runs and a notice says so
  const listed = useMemo(() => rowsFromListResponse(query.data), [query.data]);
  const [activeTab, setActiveTab] = useState("dashboard");

  // Live progress of active runs without re-fetching the list (whose build loads every Sources asset): poll each
  // active run's GET /runs/{id} every 15 s, only while the Table tab is open (and the browser tab is visible:
  // react-query pauses intervals in the background). When a run's status changes, the list is refreshed once.
  const liveIds = useMemo(() => activeRunIds(listed.rows), [listed.rows]);
  const liveQueries = useQueries({
    queries: liveIds.map((runId) => ({
      queryKey: cbomSourcesKeys.run(teamIdNumber, runId),
      // a malformed answer is "no live data" (react-query rejects undefined)
      queryFn: async () => (await getCbomRun(teamIdNumber, runId)) ?? null,
      enabled: activeTab === "table" && Number.isFinite(teamIdNumber),
      refetchInterval: 15000,
      retry: 1,
    })),
  });
  const liveSignature = liveQueries.map((q) => `${q.dataUpdatedAt}`).join(",");
  const live = useMemo(() => {
    const m = new Map<number, LiveRun>();
    liveQueries.forEach((q, i) => { if (q.data) m.set(liveIds[i], liveRunFromDetail(q.data)); });
    return m;
    // liveQueries is a new array every render; its data changes only when a dataUpdatedAt does
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [liveIds, liveSignature]);
  const allRows = useMemo(() => withLiveProgress(listed.rows, live), [listed.rows, live]);
  const refreshedFor = useRef(new Set<string>());
  useEffect(() => {
    const changed = changedRunStatuses(listed.rows, live).filter((k) => !refreshedFor.current.has(k));
    if (changed.length === 0) return;
    changed.forEach((k) => refreshedFor.current.add(k));
    queryClient.invalidateQueries({ queryKey: cbomResultsListKey(teamIdNumber) });
  }, [listed.rows, live, queryClient, teamIdNumber]);

  const deleteCBOMScanMutation = useMutation({
    mutationFn: ({ team_id, scan_id }: { team_id: number; scan_id: number }) => deleteCBOMScan(team_id, scan_id),
    onSuccess: (data, variables) => {
      queryClient.invalidateQueries({ queryKey: cbomResultsListKey(variables.team_id) });
      toast.success("CBOM scan deleted successfully");
    },
    onError: (error) => { showErrorToast(error); },
  });

  const renameCBOMScanMutation = useMutation({
    mutationFn: renameCBOMScan,
    onSuccess: (data, variables) => {
      queryClient.invalidateQueries({ queryKey: cbomResultsListKey(variables.team_id) });
      toast.success("CBOM scan renamed successfully");
    },
    onError: (error) => { showErrorToast(error); },
  });

  // One create per click burst (double-click, Enter twice): isPending disables Create only after a re-render.
  const [createGuard] = useState(singleFlight);
  const createCBOMScanMutation = useMutation({
    mutationFn: ({ team_id, title }: { team_id: number; title: string }) => createCBOMScan(team_id, title),
    onSuccess: (scan_id, variables) => {
      queryClient.invalidateQueries({ queryKey: cbomResultsListKey(variables.team_id) });
      setCreateDialogOpen(false);
      setNewScanTitle("");
      router.push(`/${variables.team_id}/cbom/${scan_id}`);
    },
    onError: (error) => { showErrorToast(error); },
  });

  // Team-wide regulatory deliverables (PDF). The manifest only supplies availability hints:
  // while it loads or if it fails, every item stays enabled (the PDF route itself answers
  // 200 with a banner even for teams that have no completed scans).
  const deliverablesQuery = useQuery({
    queryKey: ["cbom-deliverables", team_id],
    queryFn: () => getCbomDeliverables(parseInt(team_id)),
    enabled: !!team_id,
    retry: 1,
  });

  const downloadDeliverableMutation = useMutation({
    mutationFn: (slug: CbomDeliverableSlug) => {
      const tid = parseInt(team_id);
      if (Number.isNaN(tid)) throw new Error("Missing or invalid team id");
      return downloadCbomDeliverable(tid, slug);
    },
    onSuccess: (blob, slug) => {
      const url = URL.createObjectURL(new Blob([blob], { type: "application/pdf" }));
      const a = document.createElement("a");
      a.href = url;
      a.download = deliverableFileName(slug, parseInt(team_id), new Date());
      a.click();
      URL.revokeObjectURL(url);
      const title = CBOM_DELIVERABLES.find((d) => d.slug === slug)?.title ?? slug;
      toast.success(`Downloaded ${title}`);
    },
    onError: (error) => { showErrorToast(error, "Error downloading deliverable"); },
  });

  const pendingSlug = downloadDeliverableMutation.isPending ? (downloadDeliverableMutation.variables ?? null) : null;
  const manifestItems = deliverablesQuery.data?.deliverables;
  const deliverableHints = new Map(
    (Array.isArray(manifestItems) ? manifestItems : []).map((d) => [d.slug, d] as const),
  );

  const handleRename = (conversation: CBOMConversation) => { setSelectedConversation(conversation); setNewName(conversation.title); setRenameDialogOpen(true); };
  const handleDelete = (conversation: CBOMConversation) => { setSelectedConversation(conversation); setDeleteDialogOpen(true); };

  const confirmRename = () => {
    if (selectedConversation && newName.trim() && team_id) {
      renameCBOMScanMutation.mutate({ team_id: parseInt(team_id), scan_id: selectedConversation.id, title: newName.trim() });
      setRenameDialogOpen(false); setSelectedConversation(null); setNewName("");
    }
  };

  const confirmDelete = () => {
    if (selectedConversation && team_id) {
      deleteCBOMScanMutation.mutate({ team_id: parseInt(team_id), scan_id: selectedConversation.id });
      setDeleteDialogOpen(false); setSelectedConversation(null);
    }
  };

  const confirmCreate = () => {
    if (newScanTitle.trim() && team_id) {
      if (!createGuard.tryStart()) return;
      createCBOMScanMutation.mutate({ team_id: parseInt(team_id), title: newScanTitle.trim() }, { onSettled: () => createGuard.done() });
    }
  };

  const hasActiveFilters =
    searchQuery !== "" ||
    statusFilter !== "all" ||
    riskScoreFilter !== "all" ||
    sortBy !== "none";

  const filteredRows = useMemo(
    () => filterAndSortRows(allRows, { search: searchQuery, status: statusFilter, risk: riskScoreFilter, sort: sortBy }),
    [allRows, searchQuery, statusFilter, riskScoreFilter, sortBy],
  );
  const runsNote = runsLoadedNote(listed.runsLoaded, listed.runsTotal);

  const clearFilters = () => {
    setSearchQuery("");
    setStatusFilter("all");
    setRiskScoreFilter("all");
    setSortBy("none");
  };

  const dashboardData = query.data?.dashboard_data;

  const openRow = (row: ResultRow) => router.push(resultsHref(team_id, row));

  return (
    <div className="flex h-screen bg-white dark:bg-zinc-900">
      <div className="flex-1 min-w-0 p-4 sm:p-8 overflow-auto">
        <div className="max-w-7xl mx-auto min-w-0">
          {/* Header */}
          <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between mb-6">
            <div className="min-w-0">
              <h1 className="text-3xl font-bold text-zinc-900 dark:text-white mb-2">CBOM Scans</h1>
              <p className="text-zinc-600 dark:text-zinc-400">Cryptography Bill of Materials — analyze cryptographic assets across your codebase and the systems your CBOM Sources collect.</p>
            </div>
            <div className="flex flex-row flex-wrap items-center gap-2">
              <Button asChild variant="outline" className="cursor-pointer" data-testid="cbom-sources-link">
                <Link href={`/${team_id}/cbom/sources`}>
                  <Network className="h-4 w-4 mr-2" />CBOM Sources
                </Link>
              </Button>
              <Button className="bg-blue-600 hover:bg-blue-700 text-white cursor-pointer" onClick={() => setCreateDialogOpen(true)}>
                <Plus className="h-4 w-4 mr-2" />New Scan
              </Button>
              <DropdownMenu>
                <DropdownMenuTrigger asChild>
                  <Button className="bg-blue-600 hover:bg-blue-700 text-white cursor-pointer" data-testid="cbom-deliverables-trigger">
                    {pendingSlug ? <Loader2 className="h-4 w-4 mr-2 animate-spin" /> : <Download className="h-4 w-4 mr-2" />}
                    Deliverables
                    <ChevronDown className="h-4 w-4 ml-1.5 opacity-70" />
                  </Button>
                </DropdownMenuTrigger>
                <DropdownMenuContent align="end" className="w-[30rem] max-w-[calc(100vw-2rem)]">
                  <DropdownMenuLabel className="text-xs font-normal text-zinc-500">Team-wide regulatory deliverables (PDF)</DropdownMenuLabel>
                  <DropdownMenuSeparator />
                  {CBOM_DELIVERABLES.map((d) => {
                    const hint = deliverableHints.get(d.slug);
                    const unavailable = hint?.available === false;
                    return (
                      <DropdownMenuItem
                        key={d.slug}
                        data-testid={`cbom-deliverable-${d.slug}`}
                        className="cursor-pointer whitespace-normal data-[disabled]:pointer-events-auto data-[disabled]:cursor-not-allowed"
                        disabled={unavailable || pendingSlug !== null}
                        title={unavailable ? (hint?.reason ?? undefined) : undefined}
                        onSelect={() => downloadDeliverableMutation.mutate(d.slug)}
                      >
                        {pendingSlug === d.slug ? <Loader2 className="animate-spin" /> : <FileText />}
                        <span>{`#${d.number} · ${d.title}`}</span>
                      </DropdownMenuItem>
                    );
                  })}
                </DropdownMenuContent>
              </DropdownMenu>
              <Button className="bg-blue-600 hover:bg-blue-700 text-white cursor-pointer" onClick={() => queryClient.invalidateQueries({ queryKey: listKey })}>
                <RefreshCcw className="h-4 w-4 mr-2" />Refresh
              </Button>
            </div>
          </div>

          {/* Loading / error states */}
          {view === "loading" ? (
            <div className="flex h-64 items-center justify-center">
              <Loader2 className="size-10 animate-spin text-blue-600" />
            </div>
          ) : view === "error" ? (
            <div className="text-center py-12">
              <p className="text-zinc-600 dark:text-zinc-400 mb-4">Error in fetching scans, please try again later</p>
            </div>
          ) : (
            /* Tabs: Dashboard & Table */
            <>
            {query.isError && query.dataUpdatedAt > 0 && (
              <p className="mb-3 rounded-md border border-amber-500/40 bg-amber-500/10 px-3 py-2 text-sm text-amber-800 dark:text-amber-200" role="status" data-testid="cbom-results-stale">
                {`Couldn't refresh the list; showing what was loaded at ${formatDate(new Date(query.dataUpdatedAt).toISOString())}.`}
              </p>
            )}
            <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full">
              <TabsList className="mb-4 bg-transparent">
                <TabsTrigger value="dashboard" className="cursor-pointer data-[state=active]:bg-blue-600 data-[state=active]:text-white ">Dashboard</TabsTrigger>
                <TabsTrigger value="table" className="cursor-pointer data-[state=active]:bg-blue-600 data-[state=active]:text-white ">Table</TabsTrigger>
              </TabsList>

              {/* ── Dashboard Tab ── */}
              <TabsContent value="dashboard">
                {dashboardData ? (
                  <CBOMScanListDashboard dashboardData={dashboardData} />
                ) : (
                  <p className="text-center text-sm text-zinc-500 py-12">No dashboard data available.</p>
                )}
                {/* CB-25: crypto-agility baseline of the current estate (enterprise, systems, drill-down) */}
                <div className="mt-6">
                  <AgilityBaselineSection teamId={teamIdNumber} />
                </div>
              </TabsContent>

              {/* ── Table Tab ── */}
              <TabsContent value="table" className="min-w-0">
                {listed.runsListError && (
                  <p className="mb-3 rounded-md border border-amber-500/40 bg-amber-500/10 px-3 py-2 text-sm text-amber-800 dark:text-amber-200" role="status" data-testid="cbom-results-runs-error">
                    {RUNS_LIST_ERROR_NOTICE}
                  </p>
                )}
                {/* Filter bar */}
                {allRows.length > 0 && (
                  <div className="flex flex-wrap items-center gap-3 mb-4">
                    <div className="relative flex-1 min-w-[180px] max-w-sm">
                      <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-zinc-400" />
                      <Input placeholder="Search scans and runs" title="Search by title, repository, branch, source name or run number" aria-label="Search scans and runs" data-testid="cbom-results-search" value={searchQuery} onChange={(e) => setSearchQuery(e.target.value)} className="pl-9 h-9 cursor-text" />
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
                        <SelectItem value="partial">Partial</SelectItem>
                        <SelectItem value="failure">Failure</SelectItem>
                        <SelectItem value="cancelled">Cancelled</SelectItem>
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

                {/* Table content: code scans and CBOM Sources runs in one table (CB-38) */}
                {allRows.length === 0 ? (
                  <div className="text-center py-12" data-testid="cbom-results-empty">
                    <p className="text-zinc-900 dark:text-white font-medium mb-1">No scans or runs yet</p>
                    <p className="text-zinc-600 dark:text-zinc-400 mb-4">Create a CBOM scan for your code, or start a CBOM Sources run to collect the cryptography of your systems.</p>
                    <div className="flex flex-wrap items-center justify-center gap-2">
                      <Button className="bg-blue-600 hover:bg-blue-700 text-white cursor-pointer" onClick={() => setCreateDialogOpen(true)}>
                        <Plus className="h-4 w-4 mr-2" />Create New Scan
                      </Button>
                      <Button asChild variant="outline" className="cursor-pointer">
                        <Link href={sourcesRunsHref(team_id)}><Network className="h-4 w-4 mr-2" />Open CBOM Sources</Link>
                      </Button>
                    </div>
                  </div>
                ) : filteredRows.length === 0 ? (
                  <div className="text-center py-12">
                    <p className="text-zinc-600 dark:text-zinc-400 mb-4">No scans or runs match your filters.</p>
                    <Button variant="outline" className="cursor-pointer" onClick={clearFilters}><X className="h-4 w-4 mr-2" />Clear filters</Button>
                  </div>
                ) : (
                  <ScrollArea className="w-full max-w-full border rounded-lg" data-testid="cbom-results-table">
                    <div className="min-w-max">
                      <Table>
                        <TableHeader>
                          <TableRow>
                            <TableHead className="w-[200px] min-w-[140px]">Title</TableHead>
                            <TableHead>Created at</TableHead>
                            <TableHead>Last updated</TableHead>
                            <TableHead>Scan status</TableHead>
                            <TableHead className="w-[200px]">Risks</TableHead>
                            <TableHead className="w-[90px]">Risk score</TableHead>
                            <TableHead className="w-[180px]">Repo / Source</TableHead>
                            <TableHead className="w-[100px]">Branch</TableHead>
                            <TableHead className="w-[90px]">Credits</TableHead>
                            <TableHead>Owner</TableHead>
                            <TableHead className="text-right w-[80px]">Actions</TableHead>
                          </TableRow>
                        </TableHeader>
                        <TableBody>
                          {filteredRows.map((row) => {
                            const href = resultsHref(team_id, row);
                            const score = displayRiskScore(row);
                            const isRun = row.kind === "run";
                            const run = isRun ? (row as RunResultRow) : null;
                            const conversation = row.kind === "scan" ? row.scan : null;
                            const scanPct = conversation ? getScanProgress(conversation.info) : null;
                            const progressNow = run && isActiveStatus(run.scan_status) ? runProgress(run) : null;
                            return (
                            <TableRow
                              key={row.key}
                              data-testid={`cbom-result-${row.key}`}
                              data-kind={row.kind}
                              className="hover:bg-zinc-50 dark:hover:bg-zinc-800 cursor-pointer"
                              onClick={(e) => {
                                const target = e.target as HTMLElement;
                                if (target.closest("button") || target.closest("a") || target.closest("[role='menuitem']")) return;
                                openRow(row);
                              }}
                            >
                              <TableCell className="font-medium max-w-[200px] min-w-[140px]">
                                <Link
                                  href={href}
                                  className="text-blue-600 hover:text-blue-700 dark:text-blue-400 dark:hover:text-blue-300 hover:underline cursor-pointer truncate block"
                                  title={row.title}
                                >
                                  {row.title}
                                </Link>
                                {run && (
                                  <Badge variant="outline" className="mt-1 text-[10px] py-0 border-violet-500/50 text-violet-600 dark:text-violet-400" data-testid={`cbom-result-run-badge-${run.id}`}>
                                    Sources run
                                  </Badge>
                                )}
                              </TableCell>
                              <TableCell className="text-zinc-600 dark:text-zinc-400 text-sm">{row.created_at ? formatDate(row.created_at) : "—"}</TableCell>
                              <TableCell className="text-zinc-600 dark:text-zinc-400 text-sm">{row.last_updated ? formatDate(row.last_updated) : "—"}</TableCell>
                              <TableCell className="text-sm">
                                <div className="flex flex-col gap-1.5">
                                  <StatusBadge status={row.scan_status} />
                                  {conversation && scanPct != null && row.scan_status !== "success" && row.scan_status !== "failure" && (
                                    <div className="flex items-center gap-2">
                                      <Progress value={scanPct} className="h-1.5 flex-1" />
                                      <span className="text-xs text-zinc-500 tabular-nums">{scanPct}%</span>
                                    </div>
                                  )}
                                  {progressNow && (
                                    <div className="flex items-center gap-2" data-testid={`cbom-result-run-progress-${row.id}`}>
                                      <Progress value={progressNow.pct} className="h-1.5 flex-1 min-w-[48px]" />
                                      <span className="text-xs text-zinc-500 tabular-nums">{progressNow.done}/{progressNow.total} jobs</span>
                                    </div>
                                  )}
                                </div>
                              </TableCell>
                              <TableCell className="text-zinc-600 dark:text-zinc-400 text-sm">
                                {row.risk_data ? (
                                  <RiskDots risk={row.risk_data} title={isRun ? "As collected" : undefined} />
                                ) : (
                                  <span title={run?.limited ? "Open the run's results for its findings" : undefined}>—</span>
                                )}
                              </TableCell>
                              <TableCell className="text-zinc-600 dark:text-zinc-400 text-sm tabular-nums">
                                {score != null ? score : "—"}
                              </TableCell>
                              <TableCell className="text-zinc-600 dark:text-zinc-400 text-sm max-w-[180px]" title={run ? run.sources.map((s) => s.name).join(", ") : (conversation?.repo_url ?? undefined)}>
                                {run ? (
                                  <>
                                    {run.sources.length > 0 ? (
                                      <span className="flex items-center gap-1.5 truncate">
                                        <Network className="h-3.5 w-3.5 shrink-0 text-violet-500" aria-hidden />
                                        <span className="truncate">{run.sources.map((s) => s.name).join(", ")}</span>
                                      </span>
                                    ) : "—"}
                                    {runCountsLine(run) && (
                                      <span className="block text-xs text-zinc-500 dark:text-zinc-500 mt-0.5" data-testid={`cbom-result-run-counts-${run.id}`}>{runCountsLine(run)}</span>
                                    )}
                                  </>
                                ) : conversation?.zip_file_used ? (
                                  <span className="flex items-center gap-1.5 truncate">
                                    <FileArchive className="h-3.5 w-3.5 shrink-0 text-amber-500" aria-hidden />
                                    <span className="truncate">Zip file</span>
                                  </span>
                                ) : conversation?.cbom_file_used ? (
                                  <span className="flex items-center gap-1.5 truncate">
                                    <Lock className="h-3.5 w-3.5 shrink-0 text-violet-500" aria-hidden />
                                    <span className="truncate">CBOM file</span>
                                  </span>
                                ) : conversation?.repo_url ? (
                                  <span className="flex items-center gap-1.5 truncate">
                                    <GitBranch className="h-3.5 w-3.5 shrink-0 text-blue-500" aria-hidden />
                                    <span className="truncate">{conversation.repo_url.split("/").pop() ?? conversation.repo_url}</span>
                                  </span>
                                ) : "—"}
                              </TableCell>
                              <TableCell className="text-zinc-600 dark:text-zinc-400 text-sm">
                                {row.branch != null && row.branch !== "" ? (
                                  <span className="flex items-center gap-1.5 truncate">
                                    <GitBranch className="h-3.5 w-3.5 shrink-0 text-blue-500" aria-hidden />
                                    <span className="truncate">{row.branch}</span>
                                  </span>
                                ) : "—"}
                              </TableCell>
                              <TableCell className="text-zinc-600 dark:text-zinc-400 text-sm tabular-nums">
                                {row.estimated_credits != null ? row.estimated_credits : "—"}
                                {run && refundedHint(run) && (
                                  <span className="block text-xs text-zinc-500 dark:text-zinc-500" title={`${run.credits_charged ?? 0} charged, ${run.credits_refunded} refunded`}>{refundedHint(run)}</span>
                                )}
                              </TableCell>
                              <TableCell className="text-zinc-600 dark:text-zinc-400">
                                <OwnerCell name={row.owner_user_full_name} email={row.owner_user_email} />
                              </TableCell>
                              <TableCell className="text-right">
                                <DropdownMenu>
                                  <DropdownMenuTrigger asChild>
                                    <Button variant="ghost" size="icon" className="h-8 w-8 cursor-pointer" aria-label={`Actions for ${row.title || (isRun ? `Sources run #${row.id}` : `scan #${row.id}`)}`}><MoreVertical className="h-4 w-4" /></Button>
                                  </DropdownMenuTrigger>
                                  {run ? (
                                    <DropdownMenuContent align="end">
                                      <DropdownMenuItem className="cursor-pointer" data-testid={`cbom-result-run-view-${run.id}`} onClick={() => openRow(run)}>
                                        <Eye className="h-4 w-4 mr-2" />View results
                                      </DropdownMenuItem>
                                      <DropdownMenuItem className="cursor-pointer" data-testid={`cbom-result-run-sources-${run.id}`} onClick={() => router.push(sourcesRunsHref(team_id))}>
                                        <Network className="h-4 w-4 mr-2" />Open in CBOM Sources
                                      </DropdownMenuItem>
                                    </DropdownMenuContent>
                                  ) : conversation ? (
                                    <DropdownMenuContent align="end">
                                      {row.scan_status === "success" && (
                                        <DropdownMenuItem className="cursor-pointer" onClick={() => router.push(`/${team_id}/cbom/${conversation.id}/results?origin=list`)}>
                                          <Eye className="h-4 w-4 mr-2" />View Results
                                        </DropdownMenuItem>
                                      )}
                                      <DropdownMenuItem className="cursor-pointer" onClick={(e) => { e.stopPropagation(); setMetadataScan(conversation); setMetadataDialogOpen(true); }}>
                                        <Eye className="h-4 w-4 mr-2" />View metadata
                                      </DropdownMenuItem>
                                      <DropdownMenuItem className="cursor-pointer" onClick={() => handleRename(conversation)}>
                                        <Pencil className="h-4 w-4 mr-2" />Rename scan
                                      </DropdownMenuItem>
                                      <DropdownMenuItem className="cursor-pointer" onClick={() => handleDelete(conversation)} variant="destructive">
                                        <Trash2 className="h-4 w-4 mr-2" />Delete scan
                                      </DropdownMenuItem>
                                    </DropdownMenuContent>
                                  ) : null}
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
                )}
                {runsNote && allRows.length > 0 && (
                  <p className="mt-2 text-xs text-zinc-500 dark:text-zinc-400" data-testid="cbom-results-runs-note">
                    {runsNote}. Older runs are listed in <Link href={sourcesRunsHref(team_id)} className="text-blue-600 hover:underline">CBOM Sources</Link>.
                  </p>
                )}
              </TabsContent>
            </Tabs>
            </>
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
            <Input value={newName} onChange={(e) => setNewName(e.target.value)} placeholder="Scan name" maxLength={256} onKeyDown={(e) => { if (e.key === "Enter") confirmRename(); }} />
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
            <DialogDescription>Enter a title for your new CBOM scan.</DialogDescription>
          </DialogHeader>
          <div className="py-4">
            <Input value={newScanTitle} onChange={(e) => setNewScanTitle(e.target.value)} placeholder="Scan title" maxLength={256} onKeyDown={(e) => { if (e.key === "Enter") confirmCreate(); }} />
          </div>
          <DialogFooter>
            <Button variant="outline" className="cursor-pointer" onClick={() => { setCreateDialogOpen(false); setNewScanTitle(""); }}>Cancel</Button>
            <Button onClick={confirmCreate} disabled={!newScanTitle.trim() || createCBOMScanMutation.isPending} className="bg-blue-600 hover:bg-blue-700 text-white cursor-pointer">
              {createCBOMScanMutation.isPending ? "Creating..." : "Create"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
