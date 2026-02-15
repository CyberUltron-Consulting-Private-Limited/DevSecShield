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
  DialogTrigger,
} from "@/components/ui/dialog";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Plus, MoreVertical, Pencil, Trash2, RefreshCcw, Loader2, Eye, Play, CheckCircle, XCircle, CalendarPlus, CalendarCheck, Search, X, GitBranch, FileArchive, AlertTriangle, TrendingUp, TrendingDown, Bug, Shield, CircleDot, Timer } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { SastConversation, deleteSastConversation, getSastConversations, renameSastConversation, createSastConversation } from "@/utils/backend_api";
import type { ScanListDashboardData } from "@/utils/backend_api";
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
import { ScrollArea } from "@/components/ui/scroll-area";
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

// ─── Dashboard Tab ──────────────────────────────────────────────────────────────

function ScanListDashboard({ dashboardData, scansListData = [] }: { dashboardData: ScanListDashboardData; scansListData?: SastConversation[] }) {
  const card = dashboardData.card_data;

  // ── Radar: risk severity totals across all scans ──
  const riskTotals = useMemo(() => {
    let critical = 0, high = 0, medium = 0, low = 0;
    for (const day of Object.values(dashboardData.risks_per_day)) {
      critical += day.critical;
      high += day.high;
      medium += day.medium;
      low += day.low;
    }
    return [
      { severity: "Critical", count: critical },
      { severity: "High", count: high },
      { severity: "Medium", count: medium },
      { severity: "Low", count: low },
    ];
  }, [dashboardData.risks_per_day]);

  const radarConfig = {
    count: { label: "Findings", color: "hsl(220 70% 50%)" },
  } satisfies ChartConfig;

  // ── Area: risks per day (stacked) ──
  const risksPerDayData = useMemo(() => {
    return Object.entries(dashboardData.risks_per_day)
      .map(([date, v]) => ({ date, ...v }))
      .sort((a, b) => a.date.localeCompare(b.date));
  }, [dashboardData.risks_per_day]);

  const areaConfig = {
    critical: { label: "Critical", color: "hsl(0 72% 51%)" },
    high: { label: "High", color: "hsl(25 95% 53%)" },
    medium: { label: "Medium", color: "hsl(45 93% 47%)" },
    low: { label: "Low", color: "hsl(217 91% 60%)" },
  } satisfies ChartConfig;

  // ── Bar: scans per day ──
  const scansPerDayData = useMemo(() => {
    return Object.entries(dashboardData.scans_per_day)
      .map(([date, count]) => ({ date, scans: count }))
      .sort((a, b) => a.date.localeCompare(b.date));
  }, [dashboardData.scans_per_day]);

  const barConfig = {
    scans: { label: "Scans", color: "hsl(220 70% 50%)" },
  } satisfies ChartConfig;

  // ── Radial: scan status distribution ──
  const statusData = useMemo(() => [
    { status: "success", count: card.success_scans, fill: "var(--color-success)" },
    { status: "started", count: card.started_scans, fill: "var(--color-started)" },
    { status: "pending", count: card.pending_scans, fill: "var(--color-pending)" },
    { status: "failure", count: card.failure_scans, fill: "var(--color-failure)" },
    { status: "not_started", count: card.not_started_scans, fill: "var(--color-not_started)" },
  ], [card]);

  const radialConfig = {
    count: { label: "Scans" },
    success: { label: "Success", color: "hsl(142 71% 45%)" },
    started: { label: "Started", color: "hsl(217 91% 60%)" },
    pending: { label: "Pending", color: "hsl(220 9% 46%)" },
    failure: { label: "Failure", color: "hsl(0 72% 51%)" },
    not_started: { label: "Not Started", color: "hsl(270 50% 60%)" },
  } satisfies ChartConfig;

  // ── Average Risk Score (weighted 1–10) ──
  const { averageRiskScore, totalIssues, criticalCount } = useMemo(() => {
    const critical = riskTotals.find((r) => r.severity === "Critical")?.count ?? 0;
    const high = riskTotals.find((r) => r.severity === "High")?.count ?? 0;
    const medium = riskTotals.find((r) => r.severity === "Medium")?.count ?? 0;
    const low = riskTotals.find((r) => r.severity === "Low")?.count ?? 0;
    const total = critical + high + medium + low;
    const weighted = total > 0 ? (critical * 4 + high * 3 + medium * 2 + low * 1) / total : 0;
    const score = Math.min(10, Math.max(0, (weighted / 4) * 10));
    const result = {
      averageRiskScore: Math.round(score * 10) / 10,
      totalIssues: total,
      criticalCount: critical,
    };
    // #region agent log
    fetch('http://127.0.0.1:7242/ingest/3a590bd9-f575-449d-91a2-d6c8197f7d92',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({location:'sast/page.tsx:avgRisk',message:'Average risk score calc',data:{critical,high,medium,low,total,weighted,score,avgScore:result.averageRiskScore},timestamp:Date.now(),hypothesisId:'H2'})}).catch(()=>{});
    // #endregion
    return result;
  }, [riskTotals]);

  // ── OWASP by category (from raw_scan_data) ──
  const owaspByCategory = useMemo(() => {
    const map: Record<string, number> = {};
    const labelMap: Record<string, string> = {
      "A03:2021 - Injection": "Injection",
      "A07:2021 - Identification and Authentication Failures": "Auth",
      "A03:2021": "Injection",
      "A07:2021": "Auth",
      "A02:2021 - Cryptographic Failures": "Crypto",
      "A02:2021": "Crypto",
      "A01:2021 - Broken Access Control": "Access Control",
      "A01:2021": "Access Control",
      "A05:2021 - Security Misconfiguration": "Config",
      "A05:2021": "Config",
      "A09:2021 - Security Logging and Monitoring Failures": "Data Exposure",
      "A09:2021": "Data Exposure",
      "A10:2021 - Server-Side Request Forgery (SSRF)": "CSRF",
      "A10:2021": "CSRF",
    };
    const shortLabel = (key: string) => labelMap[key] ?? key.replace(/^A\d+:\d+ -? ?/, "").slice(0, 20);

    for (const scan of scansListData) {
      const raw = scan.raw_scan_data;
      if (!raw || !Array.isArray(raw)) continue;
      for (const item of raw) {
        const vulns = item?.vulnerabilities;
        if (!Array.isArray(vulns)) continue;
        for (const v of vulns) {
          const owasp = v?.owasp_top_10;
          if (Array.isArray(owasp)) {
            for (const o of owasp) {
              const k = typeof o === "string" ? o : (o as { value?: string })?.value ?? String(o);
              const label = shortLabel(k);
              map[label] = (map[label] ?? 0) + 1;
            }
          } else if (owasp && typeof owasp === "object") {
            // base_vuln.py serializes as { name: value }; use VALUES (e.g. "A03:2021 - Injection") not keys
            for (const val of Object.values(owasp)) {
              const s = typeof val === "string" ? val : String(val);
              const label = shortLabel(s);
              map[label] = (map[label] ?? 0) + 1;
            }
          }
        }
      }
    }
    return Object.entries(map)
      .map(([category, count]) => ({ category, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 8);
  }, [scansListData]);

  // ── Policy compliance (from raw_scan_data): compliance % = share of that standard in total controls ──
  const policyCompliance = useMemo(() => {
    const standards: Record<string, number> = {};

    const extractStandard = (s: string): string => {
      const parts = s.split(" - ");
      return (parts[0] ?? s).trim();
    };

    for (const scan of scansListData) {
      const raw = scan.raw_scan_data;
      if (!raw || !Array.isArray(raw)) continue;
      for (const item of raw) {
        const vulns = item?.vulnerabilities;
        if (!Array.isArray(vulns)) continue;
        for (const v of vulns) {
          const cc = v?.compliance_controls;
          if (Array.isArray(cc)) {
            for (const c of cc) {
              const s = typeof c === "string" ? c : (c as { value?: string })?.value ?? String(c);
              const std = extractStandard(s);
              if (std) standards[std] = (standards[std] ?? 0) + 1;
            }
          } else if (cc && typeof cc === "object") {
            // base_vuln.py serializes as { name: value }; use VALUES (e.g. "ISO 27001 - A.9 Access Control") not keys
            for (const val of Object.values(cc)) {
              const s = typeof val === "string" ? val : String(val);
              const std = extractStandard(s);
              if (std) standards[std] = (standards[std] ?? 0) + 1;
            }
          }
        }
      }
    }

    const total = Object.values(standards).reduce((a, b) => a + b, 0);

    return Object.entries(standards)
      .map(([name, count]) => ({
        name,
        violations: count,
        compliance: total > 0 ? Math.round((count / total) * 1000) / 10 : 0,
      }))
      .sort((a, b) => b.violations - a.violations)
      .slice(0, 8);
  }, [scansListData]);

  const overallComplianceScore = useMemo(() => {
    if (policyCompliance.length === 0) return 0;
    const sum = policyCompliance.reduce((acc, p) => acc + p.compliance, 0);
    return Math.round((sum / policyCompliance.length) * 10) / 10;
  }, [policyCompliance]);

  // ── By language (from scan_metadata.app_lang per metadata.py) ──
  const byLanguage = useMemo(() => {
    const map: Record<string, number> = {};
    const langDisplay: Record<string, string> = {
      python: "Python",
      javascript: "JavaScript",
      java: "Java",
      typescript: "TypeScript",
      php: "PHP",
      c: "C",
      ruby: "Ruby",
      rust: "Rust",
      swift: "Swift",
      csharp: "C#",
      kotlin: "Kotlin",
    };

    for (const scan of scansListData) {
      const raw = scan.raw_scan_data;
      const meta = scan.scan_metadata as { app_lang?: string } | undefined;
      const appLang = meta?.app_lang?.toLowerCase() ?? "unknown";
      const displayLang = langDisplay[appLang] ?? appLang.charAt(0).toUpperCase() + appLang.slice(1);

      if (!raw || !Array.isArray(raw)) continue;
      let vulnCount = 0;
      for (const item of raw) {
        const vulns = item?.vulnerabilities;
        if (!Array.isArray(vulns)) continue;
        vulnCount += vulns.length;
      }
      if (vulnCount > 0) {
        map[displayLang] = (map[displayLang] ?? 0) + vulnCount;
      }
    }
    return Object.entries(map)
      .filter(([, count]) => count > 0)
      .map(([language, count]) => ({ language, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 8);
  }, [scansListData]);

  // ── Top repos by risk ──
  const topReposByRisk = useMemo(() => {
    const langDisplay: Record<string, string> = {
      python: "Python",
      javascript: "JavaScript",
      java: "Java",
      typescript: "TypeScript",
      php: "PHP",
      c: "C",
      ruby: "Ruby",
      rust: "Rust",
      swift: "Swift",
      csharp: "C#",
      kotlin: "Kotlin",
    };
    return scansListData
      .filter((s) => s.scan_status === "success" && s.risk_data)
      .map((s) => {
        const rd = s.risk_data!;
        const meta = s.scan_metadata as { repo_url?: string; zip_file_used?: boolean; app_lang?: string } | undefined;
        const appLang = meta?.app_lang?.toLowerCase() ?? "unknown";
        const displayLang = langDisplay[appLang] ?? appLang.charAt(0).toUpperCase() + appLang.slice(1);
        const total = (rd.total_critical ?? 0) + (rd.total_high ?? 0) + (rd.total_medium ?? 0) + (rd.total_low ?? 0);
        const weighted = total > 0
          ? ((rd.total_critical ?? 0) * 4 + (rd.total_high ?? 0) * 3 + (rd.total_medium ?? 0) * 2 + (rd.total_low ?? 0) * 1) / total
          : 0;
        const score = Math.min(10, Math.max(0, (weighted / 4) * 10));
        const repoUrl = meta?.repo_url;
        const zipFileUsed = !!meta?.zip_file_used;
        const repoName = repoUrl
          ? String(repoUrl).split("/").pop() ?? s.title
          : s.title;
        return {
          name: repoName,
          repoUrl: repoUrl ?? null,
          zipFileUsed,
          issues: total,
          riskScore: Math.round(score * 10) / 10,
          trend: "—" as string,
          language: displayLang,
        };
      })
      .sort((a, b) => b.riskScore - a.riskScore)
      .slice(0, 5);
  }, [scansListData]);

  const lineChartConfig = {
    critical: { label: "critical", color: "#dc2626" },
    high: { label: "high", color: "#ea580c" },
    medium: { label: "medium", color: "#ca8a04" },
    low: { label: "low", color: "#2563eb" },
  } satisfies ChartConfig;
  const categoryBarConfig = { count: { label: "Count", color: "#15803d" } } satisfies ChartConfig;
  const languageColors = ["#2563eb", "#ea580c", "#dc2626", "#7c3aed", "#0d9488"];

  return (
    <div className="space-y-6">
      {/* Summary stat cards: 4 per row, 2 rows (8 cards) — styled with icon accents */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <Card className="border-zinc-200 dark:border-zinc-800">
          <CardContent className="p-3">
            <div className="flex flex-col justify-between gap-2 min-h-[72px]">
              <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-zinc-500/15 dark:bg-zinc-400/10">
                <CircleDot className="h-5 w-5 text-zinc-500 dark:text-zinc-400" />
              </div>
              <div>
                <p className="text-sm font-medium text-zinc-600 dark:text-zinc-400">Not Started</p>
                <div className="text-2xl font-bold text-zinc-900 dark:text-white">{card.not_started_scans}</div>
                <p className="text-xs text-zinc-500 dark:text-zinc-400">Idle</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card className="border-zinc-200 dark:border-zinc-800">
          <CardContent className="p-3">
            <div className="flex flex-col justify-between gap-2 min-h-[72px]">
              <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-blue-500/15 dark:bg-blue-500/10">
                <Timer className="h-5 w-5 text-blue-500" />
              </div>
              <div>
                <p className="text-sm font-medium text-zinc-600 dark:text-zinc-400">Pending</p>
                <div className="text-2xl font-bold text-zinc-900 dark:text-white">{card.pending_scans}</div>
                <p className="text-xs text-zinc-500 dark:text-zinc-400">Queued</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card className="border-zinc-200 dark:border-zinc-800">
          <CardContent className="p-3">
            <div className="flex flex-col justify-between gap-2 min-h-[72px]">
              <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-blue-500/15 dark:bg-blue-500/10">
                <Play className="h-5 w-5 text-blue-500" />
              </div>
              <div>
                <p className="text-sm font-medium text-zinc-600 dark:text-zinc-400">Started</p>
                <div className="text-2xl font-bold text-zinc-900 dark:text-white">{card.started_scans}</div>
                <p className="text-xs text-zinc-500 dark:text-zinc-400">In progress</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card className="border-zinc-200 dark:border-zinc-800">
          <CardContent className="p-3">
            <div className="flex flex-col justify-between gap-2 min-h-[72px]">
              <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-green-500/15 dark:bg-green-500/10">
                <CheckCircle className="h-5 w-5 text-green-500" />
              </div>
              <div>
                <p className="text-sm font-medium text-zinc-600 dark:text-zinc-400">Success</p>
                <div className="text-2xl font-bold text-zinc-900 dark:text-white">{card.success_scans}</div>
                <p className="text-xs text-zinc-500 dark:text-zinc-400">Completed</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card className="border-zinc-200 dark:border-zinc-800">
          <CardContent className="p-3">
            <div className="flex flex-col justify-between gap-2 min-h-[72px]">
              <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-red-500/15 dark:bg-red-500/10">
                <XCircle className="h-5 w-5 text-red-500" />
              </div>
              <div>
                <p className="text-sm font-medium text-zinc-600 dark:text-zinc-400">Failure</p>
                <div className="text-2xl font-bold text-zinc-900 dark:text-white">{card.failure_scans}</div>
                <p className="text-xs text-zinc-500 dark:text-zinc-400">Failed</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card className="border-zinc-200 dark:border-zinc-800">
          <CardContent className="p-3">
            <div className="flex flex-col justify-between gap-2 min-h-[72px]">
              <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-amber-500/15 dark:bg-amber-500/10">
                <CalendarPlus className="h-5 w-5 text-amber-500" />
              </div>
              <div>
                <p className="text-sm font-medium text-zinc-600 dark:text-zinc-400">Created today</p>
                <div className="text-2xl font-bold text-zinc-900 dark:text-white">{card.scans_created_today}</div>
                <p className="text-xs text-zinc-500 dark:text-zinc-400">New scans</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card className="border-zinc-200 dark:border-zinc-800">
          <CardContent className="p-3">
            <div className="flex flex-col justify-between gap-2 min-h-[72px]">
              <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-amber-500/15 dark:bg-amber-500/10">
                <CalendarCheck className="h-5 w-5 text-amber-500" />
              </div>
              <div>
                <p className="text-sm font-medium text-zinc-600 dark:text-zinc-400">Updated today</p>
                <div className="text-2xl font-bold text-zinc-900 dark:text-white">{card.scans_updated_today}</div>
                <p className="text-xs text-zinc-500 dark:text-zinc-400">Last 24h</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card className="border-zinc-200 dark:border-zinc-800">
          <CardContent className="p-3">
            <div className="flex flex-col justify-between gap-2 min-h-[72px]">
              <div className={`flex h-10 w-10 shrink-0 items-center justify-center rounded-lg ${averageRiskScore >= 7 ? "bg-red-500/15 dark:bg-red-500/10" : averageRiskScore >= 5 ? "bg-amber-500/15 dark:bg-amber-500/10" : "bg-green-500/15 dark:bg-green-500/10"}`}>
                <Shield className={`h-5 w-5 ${averageRiskScore >= 7 ? "text-red-500" : averageRiskScore >= 5 ? "text-amber-500" : "text-green-500"}`} />
              </div>
              <div>
                <p className="text-sm font-medium text-zinc-600 dark:text-zinc-400">Average Risk Score</p>
                <div className="text-2xl font-bold text-zinc-900 dark:text-white">{averageRiskScore} / 10</div>
                <p className="text-xs text-zinc-500 dark:text-zinc-400">Security posture</p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Charts row 1: Risk Severity | Policy Compliance | Top Repositories */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Radar: Risk severity totals */}
        <Card className="border-zinc-200 dark:border-zinc-800">
          <CardHeader className="items-center pb-2">
            <CardTitle className="text-base">Risk Severity Distribution</CardTitle>
            <CardDescription>Total findings across all successful scans</CardDescription>
          </CardHeader>
          <CardContent>
            {riskTotals.every((r) => r.count === 0) ? (
              <p className="text-center text-sm text-zinc-500 py-8">No vulnerability data yet</p>
            ) : (
              <ChartContainer config={radarConfig} className="mx-auto aspect-square max-h-[280px]">
                <RadarChart data={riskTotals}>
                  <ChartTooltip cursor={false} content={<ChartTooltipContent />} />
                  <PolarAngleAxis dataKey="severity" />
                  <PolarGrid />
                  <Radar dataKey="count" fill="var(--color-count)" fillOpacity={0.6} dot={{ r: 4, fillOpacity: 1 }} />
                </RadarChart>
              </ChartContainer>
            )}
          </CardContent>
        </Card>

        {/* Policy Compliance */}
        <Card className="border-zinc-200 dark:border-zinc-800">
          <CardHeader className="pb-2">
            <CardTitle className="text-base">Policy Compliance</CardTitle>
            <CardDescription>Security standards adherence</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              {policyCompliance.length === 0 ? (
                <p className="text-center text-sm text-zinc-500 py-8">No compliance data yet</p>
              ) : (
                <>
                  {policyCompliance.map((p) => (
                    <div key={p.name} className="flex items-center gap-3">
                      {p.compliance >= 90 ? (
                        <CheckCircle className="h-5 w-5 shrink-0 text-green-500" />
                      ) : p.compliance >= 70 ? (
                        <AlertTriangle className="h-5 w-5 shrink-0 text-amber-500" />
                      ) : (
                        <XCircle className="h-5 w-5 shrink-0 text-red-500" />
                      )}
                      <div className="flex-1 min-w-0">
                        <p className="text-sm font-medium text-zinc-900 dark:text-white">{p.name}</p>
                        <p className="text-xs text-zinc-500">{p.violations} violations {p.compliance}%</p>
                        <Progress value={p.compliance} className="h-2 mt-1" />
                      </div>
                    </div>
                  ))}
                  <div className="flex justify-between items-center pt-2">
                    <span className="text-sm text-zinc-600 dark:text-zinc-400">Overall Compliance Score</span>
                    <span className="text-xl font-bold text-zinc-900 dark:text-white">{overallComplianceScore}%</span>
                  </div>
                </>
              )}
            </div>
          </CardContent>
        </Card>

        {/* Top Repositories by Risk */}
        <Card className="border-zinc-200 dark:border-zinc-800 flex flex-col min-w-0 overflow-hidden">
          <CardHeader className="pb-2 shrink-0">
            <CardTitle className="text-base">Top Repositories by Risk</CardTitle>
            <CardDescription>Highest vulnerability concentration</CardDescription>
          </CardHeader>
          <CardContent className="min-w-0 overflow-hidden">
            {topReposByRisk.length === 0 ? (
              <p className="text-center text-sm text-zinc-500 py-8">No repository data yet</p>
            ) : (
              <ScrollArea className="h-[280px] w-full">
                <div className="space-y-3 pr-4 pb-4 w-full max-w-full box-border">
                  {topReposByRisk.map((r, i) => (
                      <div key={i} className="flex items-center justify-between gap-2 rounded-lg border border-zinc-200 dark:border-zinc-700 p-2.5 w-full min-w-0 overflow-hidden">
                        <div className="min-w-0 flex-1 overflow-hidden w-0">
                          <div className="flex items-center gap-2 min-w-0 overflow-hidden">
                            {r.zipFileUsed ? (
                              <FileArchive className="h-4 w-4 shrink-0 text-amber-500" aria-label="Zip upload" />
                            ) : (
                              <GitBranch className="h-4 w-4 shrink-0 text-blue-500" aria-label="Repository" />
                            )}
                            <div className="min-w-0 flex-1 overflow-hidden">
                              <p className="font-semibold text-zinc-900 dark:text-white truncate text-sm">{r.name}</p>
                              {r.repoUrl && (
                                <p className="text-xs text-zinc-500 truncate mt-0.5" title={r.repoUrl}>{r.repoUrl}</p>
                              )}
                            </div>
                          </div>
                          <div className="flex items-center gap-2 mt-1.5 text-xs text-zinc-500 flex-wrap">
                            <Badge variant="outline" className="text-xs font-normal shrink-0">{r.language}</Badge>
                            <span className="flex items-center gap-1 shrink-0">
                              <Bug className="h-3.5 w-3.5 text-zinc-500" />
                              {r.issues} issues
                            </span>
                            <span className="flex items-center gap-0.5 shrink-0">
                              {r.trend.startsWith("↗") ? (
                                <TrendingUp className="h-3.5 w-3.5 text-red-500" />
                              ) : r.trend.startsWith("↘") ? (
                                <TrendingDown className="h-3.5 w-3.5 text-green-500" />
                              ) : null}
                              <span className={r.trend.startsWith("↗") ? "text-red-500" : r.trend.startsWith("↘") ? "text-green-500" : "text-zinc-500"}>{r.trend}</span>
                            </span>
                          </div>
                        </div>
                        <Badge
                          className={`shrink-0 font-bold text-xs ${r.riskScore >= 7 ? "bg-red-500" : r.riskScore >= 5 ? "bg-amber-500" : "bg-amber-400"}`}
                        >
                          {r.riskScore}
                        </Badge>
                      </div>
                    ))}
                </div>
              </ScrollArea>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Charts row 2 */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Bar: Scans per day */}
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
                  <XAxis dataKey="date" tickLine={false} axisLine={false} tickMargin={8} tickFormatter={(v) => new Date(v).toLocaleDateString("en-US", { month: "short", day: "numeric" })} />
                  <YAxis tickLine={false} axisLine={false} allowDecimals={false} />
                  <ChartTooltip cursor={false} content={<ChartTooltipContent hideLabel />} />
                  <Bar dataKey="scans" fill="var(--color-scans)" radius={[4, 4, 0, 0]} />
                </BarChart>
              </ChartContainer>
            )}
          </CardContent>
        </Card>

        {/* Radial: Scan status breakdown */}
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
            {/* Legend */}
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

      {/* Charts row 3: Average Risk Score | Risks Over Time */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Average Risk Score (radial gauge) */}
        <Card className="border-zinc-200 dark:border-zinc-800">
          <CardHeader className="pb-2">
            <CardTitle className="text-base">Average Risk Score</CardTitle>
            <CardDescription>Organization security posture</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="flex flex-col items-center">
              <div className="h-[200px] w-full max-w-[220px]">
                <ChartContainer config={lineChartConfig} className="h-full w-full">
                  <RadialBarChart
                    data={[
                      { name: "ref", value: 100, fill: "hsl(220 13% 91%)" },
                      { name: "score", value: Math.min(100, Math.max(0, averageRiskScore * 10)), fill: averageRiskScore >= 7 ? "#dc2626" : averageRiskScore >= 5 ? "#ea580c" : "#22c55e" },
                    ]}
                    innerRadius={60}
                    outerRadius={90}
                    startAngle={180}
                    endAngle={0}
                  >
                    <RadialBar dataKey="value" cornerRadius={4} background />
                  </RadialBarChart>
                </ChartContainer>
              </div>
              <p className="text-2xl font-bold text-zinc-900 dark:text-white mt-2">{averageRiskScore} out of 10</p>
              <div className="flex gap-6 mt-4 text-sm text-zinc-600 dark:text-zinc-400">
                <span>{totalIssues} Total Issues</span>
                <span>0% Fix Rate</span>
                <span>{criticalCount} Critical</span>
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Risks Over Time */}
        <Card className="border-zinc-200 dark:border-zinc-800">
          <CardHeader className="pb-2">
            <CardTitle className="text-base">Risks Over Time</CardTitle>
            <CardDescription>Vulnerability counts per scan date</CardDescription>
          </CardHeader>
          <CardContent>
            {risksPerDayData.length === 0 ? (
              <p className="text-center text-sm text-zinc-500 py-8">No vulnerability data yet</p>
            ) : (
              <ChartContainer config={areaConfig} className="h-[280px] w-full">
                <AreaChart data={risksPerDayData}>
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

      {/* Charts row 4: Vulnerabilities by Category */}
      <div className="grid grid-cols-1 gap-6">
        {/* Vulnerabilities by Category (horizontal bar) */}
        <Card className="border-zinc-200 dark:border-zinc-800">
          <CardHeader className="pb-2">
            <CardTitle className="text-base">Vulnerabilities by Category</CardTitle>
            <CardDescription>OWASP Top 10 classification</CardDescription>
          </CardHeader>
          <CardContent>
            {owaspByCategory.length === 0 ? (
              <p className="text-center text-sm text-zinc-500 py-8">No category data yet</p>
            ) : (
              <ChartContainer config={categoryBarConfig} className="h-[280px] w-full">
                <BarChart data={owaspByCategory} layout="vertical" margin={{ left: 8, right: 8 }}>
                  <CartesianGrid horizontal={false} strokeDasharray="3 3" />
                  <XAxis type="number" tickLine={false} axisLine={false} allowDecimals={false} domain={[0, "auto"]} />
                  <YAxis type="category" dataKey="category" width={100} tickLine={false} axisLine={false} tickFormatter={(v) => String(v).length > 12 ? `${String(v).slice(0, 12)}...` : v} />
                  <ChartTooltip content={<ChartTooltipContent />} />
                  <Bar dataKey="count" fill="#15803d" radius={[0, 4, 4, 0]} />
                </BarChart>
              </ChartContainer>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Charts row 5: Vulnerabilities by Language | Scan Sources */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Vulnerabilities by Language */}
        <Card className="border-zinc-200 dark:border-zinc-800">
          <CardHeader className="pb-2">
            <CardTitle className="text-base">Vulnerabilities by Language</CardTitle>
            <CardDescription>Distribution across programming languages</CardDescription>
          </CardHeader>
          <CardContent>
            {byLanguage.length === 0 ? (
              <p className="text-center text-sm text-zinc-500 py-8">No language data yet</p>
            ) : (
              <ChartContainer config={{}} className="h-[280px] w-full">
                <BarChart data={byLanguage}>
                  <CartesianGrid vertical={false} strokeDasharray="3 3" />
                  <XAxis dataKey="language" tickLine={false} axisLine={false} tickMargin={8} />
                  <YAxis tickLine={false} axisLine={false} allowDecimals={false} domain={[0, "auto"]} />
                  <ChartTooltip content={<ChartTooltipContent />} />
                  <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                    {byLanguage.map((_, i) => (
                      <Cell key={i} fill={languageColors[i % languageColors.length]} />
                    ))}
                  </Bar>
                </BarChart>
              </ChartContainer>
            )}
          </CardContent>
        </Card>

        {/* Scan Sources: repos + zip files */}
        <Card className="border-zinc-200 dark:border-zinc-800 flex flex-col">
          <CardHeader className="pb-2">
            <CardTitle className="text-base">Scan Sources</CardTitle>
            <CardDescription>Repositories and zip uploads scanned</CardDescription>
          </CardHeader>
          <CardContent className="flex-1 flex flex-col gap-4 overflow-hidden justify-items-start">
            {/* Zip files */}
            <div>
              <div className="flex items-center gap-2">
                <FileArchive className="h-4 w-4 text-amber-500" />
                <span className="text-sm font-medium text-zinc-700 dark:text-zinc-300">Zip Uploads</span>
              </div>
              <div className="flex items-center gap-2 pl-6 mt-1">
                <FileArchive className="h-3.5 w-3.5 shrink-0 text-zinc-400" />
                <span className="text-2xl font-bold text-zinc-900 dark:text-white">{dashboardData.zip_files_scanned}</span>
                <span className="text-xs text-zinc-500">file{dashboardData.zip_files_scanned !== 1 ? "s" : ""} uploaded</span>
              </div>
            </div>

            {/* Repos list */}
            <div className="flex-1 min-h-0">
              <div className="flex items-center gap-2 mb-2">
                <GitBranch className="h-4 w-4 text-blue-500" />
                <span className="text-sm font-medium text-zinc-700 dark:text-zinc-300">Repositories ({dashboardData.repos_scanned.length})</span>
              </div>
              {dashboardData.repos_scanned.length === 0 ? (
                <p className="text-xs text-zinc-500 pl-6">No repositories scanned yet.</p>
              ) : (
                <ScrollArea className="h-[180px] pl-6">
                  <ul className="space-y-1 pr-3">
                    {dashboardData.repos_scanned.map((r, i) => {
                      const url = typeof r === "string" ? r : r.repo_url;
                      return (
                        <li key={i} className="flex items-center gap-2 text-sm text-zinc-700 dark:text-zinc-300">
                          <GitBranch className="h-3.5 w-3.5 shrink-0 text-zinc-400" />
                          <span className="truncate" title={url}>{url}</span>
                        </li>
                      );
                    })}
                  </ul>
                </ScrollArea>
              )}
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

// ─── Main Page ──────────────────────────────────────────────────────────────────

export default function SASTPage() {
  const router = useRouter();
  const params = useParams();
  const team_id = params?.team_id as string;
  const [conversations, setConversations] = useState<SastConversation[]>([]);
  const [renameDialogOpen, setRenameDialogOpen] = useState(false);
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false);
  const [createDialogOpen, setCreateDialogOpen] = useState(false);
  const [selectedConversation, setSelectedConversation] = useState<SastConversation | null>(null);
  const [metadataDialogOpen, setMetadataDialogOpen] = useState(false);
  const [metadataScan, setMetadataScan] = useState<SastConversation | null>(null);
  const [newName, setNewName] = useState("");
  const [newScanTitle, setNewScanTitle] = useState("");
  const [searchQuery, setSearchQuery] = useState("");
  const [statusFilter, setStatusFilter] = useState<string>("all");
  const [createdAtSort, setCreatedAtSort] = useState<"none" | "asc" | "desc">("none");
  const queryClient = useQueryClient();

  const query = useQuery({
    queryKey: ['sast-conversations', team_id],
    queryFn: () => getSastConversations(parseInt(team_id)),
    enabled: !!team_id,
  });

  useEffect(() => {
    if (query.data) {
      setConversations(query.data.scans_list_data ?? []);
    }
    if (query.error) {
      showErrorToast(query.error, 'Error fetching sast conversations');
    }
  }, [query.data, query.error]);

  const deleteSastConversationMutation = useMutation({
    mutationFn: ({ team_id, scan_id }: { team_id: number; scan_id: number }) => deleteSastConversation(team_id, scan_id),
    onSuccess: (data, variables) => {
      queryClient.invalidateQueries({ queryKey: ['sast-conversations', variables.team_id.toString()] });
      toast.success('Sast conversation deleted successfully');
    },
    onError: (error) => { showErrorToast(error); },
  });

  const renameSastConversationMutation = useMutation({
    mutationFn: renameSastConversation,
    onSuccess: (data, variables) => {
      queryClient.invalidateQueries({ queryKey: ['sast-conversations', variables.team_id.toString()] });
      toast.success('Sast conversation renamed successfully');
    },
    onError: (error) => { showErrorToast(error); },
  });

  const createSastConversationMutation = useMutation({
    mutationFn: ({ team_id, title }: { team_id: number; title: string }) => createSastConversation(team_id, title),
    onSuccess: (scan_id, variables) => {
      queryClient.invalidateQueries({ queryKey: ['sast-conversations', variables.team_id.toString()] });
      setCreateDialogOpen(false);
      setNewScanTitle("");
      router.push(`/${variables.team_id}/sast/${scan_id}`);
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

  const handleRename = (conversation: SastConversation) => { setSelectedConversation(conversation); setNewName(conversation.title); setRenameDialogOpen(true); };
  const handleDelete = (conversation: SastConversation) => { setSelectedConversation(conversation); setDeleteDialogOpen(true); };

  const confirmRename = () => {
    if (selectedConversation && newName.trim() && team_id) {
      renameSastConversationMutation.mutate({ team_id: parseInt(team_id), scan_id: selectedConversation.id, title: newName.trim() });
      setRenameDialogOpen(false); setSelectedConversation(null); setNewName("");
    }
  };

  const confirmDelete = () => {
    if (selectedConversation && team_id) {
      deleteSastConversationMutation.mutate({ team_id: parseInt(team_id), scan_id: selectedConversation.id });
      setDeleteDialogOpen(false); setSelectedConversation(null);
    }
  };

  const confirmCreate = () => {
    if (newScanTitle.trim() && team_id) {
      createSastConversationMutation.mutate({ team_id: parseInt(team_id), title: newScanTitle.trim() });
    }
  };

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

  const dashboardData = query.data?.dashboard_data;

  return (
    <div className="flex h-screen bg-white dark:bg-zinc-900">
      <div className="flex-1 p-8 overflow-auto">
        <div className="max-w-7xl mx-auto">
          {/* Header */}
          <div className="flex items-center justify-between mb-6">
            <div>
              <h1 className="text-3xl font-bold text-zinc-900 dark:text-white mb-2">SAST Scans</h1>
              <p className="text-zinc-600 dark:text-zinc-400">Manage and view all your SAST scan conversations.</p>
            </div>
            <div className="flex flex-row items-center gap-2">
              <Button className="bg-blue-600 hover:bg-blue-700 text-white cursor-pointer" onClick={() => setCreateDialogOpen(true)}>
                <Plus className="h-4 w-4 mr-2" />New Scan
              </Button>
              <Button className="bg-blue-600 hover:bg-blue-700 text-white cursor-pointer" onClick={() => queryClient.invalidateQueries({ queryKey: ['sast-conversations', team_id] })}>
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
                  <ScanListDashboard dashboardData={dashboardData} scansListData={conversations} />
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
                    <div className="text-zinc-600 dark:text-zinc-400 text-sm">Sort by</div>
                    <Select value={createdAtSort} onValueChange={(v) => setCreatedAtSort(v as "none" | "asc" | "desc")}>
                      <SelectTrigger className="h-9 min-w-[170px] cursor-pointer"><SelectValue placeholder="Created at" /></SelectTrigger>
                      <SelectContent>
                        <SelectItem value="none">Default</SelectItem>
                        <SelectItem value="desc">Newest</SelectItem>
                        <SelectItem value="asc">Oldest</SelectItem>
                      </SelectContent>
                    </Select>
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
                    <p className="text-zinc-600 dark:text-zinc-400 mb-4">No scans yet. Create your first SAST scan to get started.</p>
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
                  <div className="border rounded-lg overflow-hidden">
                    <Table>
                      <TableHeader>
                        <TableRow>
                          <TableHead className="w-[220px]">Title</TableHead>
                          <TableHead>Owner</TableHead>
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
                                ? `/${team_id}/sast/${conversation.id}/results`
                                : `/${team_id}/sast/${conversation.id}`;
                              router.push(dest);
                            }}
                          >
                            <TableCell className="font-medium">
                              <Link
                                href={(conversation.scan_status?.toLowerCase() ?? "") === "success" ? `/${team_id}/sast/${conversation.id}/results` : `/${team_id}/sast/${conversation.id}`}
                                className="text-blue-600 hover:text-blue-700 dark:text-blue-400 dark:hover:text-blue-300 hover:underline cursor-pointer"
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
                              <Button variant="outline" size="sm" className="cursor-pointer" onClick={() => { setMetadataScan(conversation); setMetadataDialogOpen(true); }}>
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
                                    <DropdownMenuItem className="cursor-pointer" onClick={() => router.push(`/${team_id}/sast/${conversation.id}/results?origin=list`)}>
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
            <DialogDescription>Enter a title for your new SAST scan conversation.</DialogDescription>
          </DialogHeader>
          <div className="py-4">
            <Input value={newScanTitle} onChange={(e) => setNewScanTitle(e.target.value)} placeholder="Scan title" onKeyDown={(e) => { if (e.key === "Enter") confirmCreate(); }} />
          </div>
          <DialogFooter>
            <Button variant="outline" className="cursor-pointer" onClick={() => { setCreateDialogOpen(false); setNewScanTitle(""); }}>Cancel</Button>
            <Button onClick={confirmCreate} disabled={!newScanTitle.trim() || createSastConversationMutation.isPending} className="bg-blue-600 hover:bg-blue-700 text-white cursor-pointer">
              {createSastConversationMutation.isPending ? "Creating..." : "Create"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
