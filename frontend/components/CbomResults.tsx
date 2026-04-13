"use client";

import { useState, useMemo, useEffect } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
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
} from "@/components/ui/dropdown-menu";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { useRouter, useSearchParams, useParams } from "next/navigation";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { getCBOMExportResults, updateScan, toggleFindingState, createTicket, type CbomScanDashboardData, type CbomFinding, type CbomScanMetadata, type ScanTicketingIntegrationSettings } from "@/utils/backend_api";
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
import { PieChart, BarChart3, TrendingUp, Search, ChevronDown } from "lucide-react";
import { toast } from "sonner";
import TicketingIntegrationsSettings from "@/components/ticketing-integrations-settings";
import FindingSelectionMenu from "@/components/finding-selection-menu";

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
  if (s === "weak") return "border-red-500/50 text-red-400";
  if (s === "moderate") return "border-yellow-500/50 text-yellow-400";
  if (s === "strong") return "border-green-500/50 text-green-400";
  if (s === "quantum_safe") return "border-blue-500/50 text-blue-400";
  return "border-zinc-500/50 text-zinc-400";
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
function matchesRiskScoreFilter(score: number | null, filter: RiskScoreFilter): boolean {
  if (filter === "all") return true;
  if (score == null) return false;
  if (filter === "critical") return score >= 4;
  if (filter === "high") return score >= 3 && score < 4;
  if (filter === "medium") return score >= 2 && score < 3;
  if (filter === "low") return score < 2;
  return true;
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
      ? (integrationSettings.jira as { jira_project_id?: string } | undefined)
      : undefined;
  const initialJiraProjectId = jiraFromSettings?.jira_project_id ?? "";
  const [jiraProjectId, setJiraProjectId] = useState(initialJiraProjectId);

  useEffect(() => {
    setJiraProjectId(initialJiraProjectId);
  }, [initialJiraProjectId]);

  const filteredFindings = useMemo(() => {
    if (!findingsList) return [];
    return findingsList.filter((f) => {
      const q = searchQuery.toLowerCase();
      const matchSearch =
        !q ||
        (f.algorithm_name || f.title || "").toLowerCase().includes(q) ||
        (f.description || "").toLowerCase().includes(q) ||
        (f.location || "").toLowerCase().includes(q);
      const matchStrength = strengthFilter === "all" || f.crypto_strength === strengthFilter;
      const matchType = typeFilter === "all" || f.algorithm_type === typeFilter;
      const matchQuantum =
        quantumFilter === "all" ||
        (quantumFilter === "safe" && f.quantum_safe === true) ||
        (quantumFilter === "vulnerable" && f.quantum_safe === false);
      const matchImpact = filterImpact === "all" || (f.impact || "").toLowerCase() === filterImpact.toLowerCase();
      const matchRisk = matchesRiskScoreFilter(f.risk_score, filterRiskScore);
      return matchSearch && matchStrength && matchType && matchQuantum && matchImpact && matchRisk;
    });
  }, [findingsList, searchQuery, strengthFilter, typeFilter, quantumFilter, filterImpact, filterRiskScore]);

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
      const RISK_ORDER = ["Critical", "High", "Medium", "Low"] as const;
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
      for (const finding_id of ids) {
        await toggleFindingState({ team_id: tid, type: "cbom", scan_id: sid, finding_id, state });
      }
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["cbom-conversation-data"] });
      onFindingsUpdated?.();
      toast.success(`Updated ${selectedFindings.size} finding(s)`);
      setSelectedFindings(new Set());
    },
    onError: (err) => showErrorToast(err, "Error updating finding status"),
  });

  const exportMutation = useMutation({
    mutationFn: () => getCBOMExportResults(Number(team_id), Number(scan_id)),
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
    const blob = new Blob([JSON.stringify(cbomJson, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `cbom-cyclonedx-${scan_id}.json`;
    a.click();
    URL.revokeObjectURL(url);
    toast.success("CycloneDX CBOM JSON downloaded");
  };

  const cardData = dashboard?.card_data;
  const remediation = dashboard?.remediation_actions_required;
  const remediationKpis = dashboard?.remediation_metrics;
  const totalFindings = remediation ? remediation.total_findings || 1 : 1;

  // Charts data
  const severityRadarData = useMemo(() => {
    if (!dashboard) return [];
    return RISK_ORDER.map((subject) => ({
      subject,
      count: dashboard.severity_distribution[subject.toLowerCase() as keyof typeof dashboard.severity_distribution] ?? 0,
    }));
  }, [dashboard]);

  const algorithmTypeData = useMemo(() => {
    if (!dashboard) return [];
    return Object.entries(dashboard.algorithm_type_distribution)
      .map(([name, count]) => ({ name: name.replace(/_/g, " "), count }))
      .filter((d) => d.count > 0)
      .sort((a, b) => b.count - a.count);
  }, [dashboard]);

  const strengthData = useMemo(() => {
    if (!dashboard) return [];
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
    if (!dashboard?.quantum_readiness) return [];
    return [
      { name: "Safe", count: dashboard.quantum_readiness.quantum_safe, fill: "hsl(142 71% 45%)" },
      { name: "Vulnerable", count: dashboard.quantum_readiness.quantum_vulnerable, fill: "hsl(0 72% 51%)" },
      { name: "Unknown", count: dashboard.quantum_readiness.unknown, fill: "hsl(220 9% 46%)" },
    ].filter((d) => d.count > 0);
  }, [dashboard]);

  // OWASP Top 10 data
  const owaspMetrics = dashboard?.owasp_top_10_issues ?? {};
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
  const complianceMetrics = dashboard?.compliance_controls ?? {};
  const complianceBarData = useMemo(() => {
    return Object.entries(complianceMetrics)
      .map(([key, count]) => ({ name: COMPLIANCE_KEY_TO_LABEL[key] ?? key, count }))
      .sort((a, b) => b.count - a.count);
  }, [complianceMetrics]);
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
  const criticalCount = dashboard?.severity_distribution?.critical ?? 0;
  const meta = scanMetadata as CbomScanMetadata | null;

  return (
    <ScrollArea className="h-screen">
      <div className="max-w-7xl mx-auto p-6 space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-4">
            {origin === "chat" && (
              <Button variant="ghost" size="sm" onClick={() => router.back()} className="text-zinc-400 hover:text-white cursor-pointer">
                <ArrowLeft className="size-4 mr-1" /> Back
              </Button>
            )}
            <div>
              <h1 className="text-2xl font-bold text-white flex items-center gap-2">
                <ShieldCheck className="size-6 text-blue-400" />
                CBOM Scan Results
              </h1>
              <div className="flex items-center gap-3 mt-1 text-sm text-zinc-400">
                {meta?.repo_url && (
                  <span className="flex items-center gap-1"><GitBranch className="size-3" /> {meta.repo_url}</span>
                )}
                {meta?.branch && <span className="flex items-center gap-1">Branch: {meta.branch}</span>}
                {meta?.zip_file_used && <Badge variant="outline" className="border-zinc-700 text-zinc-400"><Archive className="size-3 mr-1" /> Zip Upload</Badge>}
                {meta?.cbom_file_used && <Badge variant="outline" className="border-zinc-700 text-zinc-400"><Lock className="size-3 mr-1" /> CBOM File</Badge>}
                {meta?.scan_binaries && <Badge variant="outline" className="border-blue-500/50 text-blue-400">Binary Scan</Badge>}
              </div>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <Button variant="ghost" size="sm" onClick={handleDownloadCBOMJson} className="text-zinc-400 hover:text-white cursor-pointer">
              <Download className="size-4 mr-1" /> CycloneDX JSON
            </Button>
            <Button variant="ghost" size="sm" onClick={() => exportMutation.mutate()} disabled={exportMutation.isPending} className="text-zinc-400 hover:text-white cursor-pointer">
              {exportMutation.isPending ? <Loader2 className="size-4 animate-spin mr-1" /> : <Download className="size-4 mr-1" />}
              PDF Report
            </Button>
            <Button variant="ghost" size="sm" onClick={() => router.push(`/${team_id}/cbom/${scan_id}`)} className="text-zinc-400 hover:text-white cursor-pointer">
              <MessageCircle className="size-4 mr-1" /> Chat
            </Button>
          </div>
        </div>

        {/* Dashboard Summary */}
        {dashboard && cardData && (
          <>
            {/* Summary Cards */}
            <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-7 gap-3">
              {[
                { label: "Crypto Assets", value: cardData.total_crypto_assets, icon: Lock },
                { label: "Weak", value: cardData.total_weak_algorithms, icon: ShieldAlert },
                { label: "Quantum Vulnerable", value: cardData.total_quantum_vulnerable, icon: AlertTriangle },
                { label: "Certificates", value: cardData.total_certificates, icon: ShieldCheck },
                { label: "Keys", value: cardData.total_keys, icon: Key },
                { label: "Quantum Ready", value: `${cardData.quantum_readiness_score}%`, icon: Shield },
                { label: "Avg Risk", value: cardData.average_risk_score?.toFixed(1) ?? "N/A", icon: Activity },
              ].map((c) => (
                <Card key={c.label} className="bg-zinc-900 border-zinc-800">
                  <CardContent className="p-4 flex flex-col gap-1">
                    <div className="flex items-center gap-2">
                      <c.icon className="size-4 text-zinc-400" />
                      <span className="text-xs text-zinc-400">{c.label}</span>
                    </div>
                    <span className="text-xl font-bold text-white">{c.value}</span>
                  </CardContent>
                </Card>
              ))}
            </div>

            {/* Remediation Progress */}
            {remediation && (
              <Card className="bg-zinc-900 border-zinc-800">
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm text-zinc-300">Remediation Progress</CardTitle>
                </CardHeader>
                <CardContent className="space-y-2">
                  <div className="flex items-center gap-4 text-sm text-zinc-400">
                    <span>Fixed: <span className="text-green-400 font-medium">{remediation.total_fixed}</span></span>
                    <span>In Progress: <span className="text-yellow-400 font-medium">{remediation.total_in_progress}</span></span>
                    <span>Not Started: <span className="text-zinc-300 font-medium">{remediation.total_not_started}</span></span>
                    <span>Ignored: <span className="text-zinc-500 font-medium">{remediation.total_ignored}</span></span>
                  </div>
                  <Progress value={(remediation.total_fixed / totalFindings) * 100} className="h-2" />
                  <p className="text-xs text-zinc-500">{remediation.total_fixed}/{totalFindings} findings resolved</p>
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
                    OWASP Top 10 Issues
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
                    Risk Metrics
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
                    Compliance Controls
                  </CardTitle>
                  <CardDescription>Findings mapped to compliance frameworks</CardDescription>
                </CardHeader>
                <CardContent>
                  {!hasComplianceData ? (
                    <div className="flex items-center justify-center min-h-[280px] text-zinc-500 dark:text-zinc-400 text-sm">No compliance data available</div>
                  ) : (
                    <ChartContainer config={complianceBarChartConfig} className="mx-auto aspect-auto max-h-[280px] cursor-pointer">
                      <BarChart data={complianceBarData.slice(0, 10)} layout="vertical" margin={{ top: 0, right: 8, bottom: 0, left: 0 }}>
                        <CartesianGrid horizontal={false} className="stroke-zinc-200 dark:stroke-zinc-800" />
                        <XAxis type="number" hide />
                        <YAxis dataKey="name" type="category" width={140} tickLine={false} axisLine={false} className="text-xs" />
                        <ChartTooltip content={<ChartTooltipContent />} />
                        <Bar dataKey="count" fill="hsl(217 91% 60%)" radius={[0, 4, 4, 0]} />
                      </BarChart>
                    </ChartContainer>
                  )}
                </CardContent>
              </Card>
            </div>

            {/* Row 2: CBOM-specific charts */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {/* Algorithm Types */}
              <Card className="bg-zinc-900 border-zinc-800">
                <CardHeader className="pb-2"><CardTitle className="text-sm text-zinc-300">Algorithm Types</CardTitle></CardHeader>
                <CardContent>
                  <ChartContainer config={barConfig} className="mx-auto aspect-square max-h-[240px]">
                    <BarChart data={algorithmTypeData} layout="vertical">
                      <CartesianGrid strokeDasharray="3 3" className="stroke-zinc-800" />
                      <XAxis type="number" className="text-xs text-zinc-500" />
                      <YAxis dataKey="name" type="category" className="text-xs text-zinc-500" width={120} />
                      <ChartTooltip content={<ChartTooltipContent />} />
                      <Bar dataKey="count" fill="hsl(220 70% 50%)" radius={[0, 4, 4, 0]} />
                    </BarChart>
                  </ChartContainer>
                </CardContent>
              </Card>

              {/* Strength */}
              <Card className="bg-zinc-900 border-zinc-800">
                <CardHeader className="pb-2"><CardTitle className="text-sm text-zinc-300">Crypto Strength</CardTitle></CardHeader>
                <CardContent>
                  <ChartContainer config={barConfig} className="mx-auto aspect-square max-h-[240px]">
                    <BarChart data={strengthData}>
                      <CartesianGrid strokeDasharray="3 3" className="stroke-zinc-800" />
                      <XAxis dataKey="name" className="text-xs text-zinc-500" />
                      <YAxis className="text-xs text-zinc-500" />
                      <ChartTooltip content={<ChartTooltipContent />} />
                      <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                        {strengthData.map((entry, index) => (
                          <Cell key={`cell-${index}`} fill={entry.fill} />
                        ))}
                      </Bar>
                    </BarChart>
                  </ChartContainer>
                </CardContent>
              </Card>

              {/* Quantum Readiness */}
              <Card className="bg-zinc-900 border-zinc-800">
                <CardHeader className="pb-2"><CardTitle className="text-sm text-zinc-300">Quantum Readiness</CardTitle></CardHeader>
                <CardContent>
                  <ChartContainer config={barConfig} className="mx-auto aspect-square max-h-[240px]">
                    <BarChart data={quantumData}>
                      <CartesianGrid strokeDasharray="3 3" className="stroke-zinc-800" />
                      <XAxis dataKey="name" className="text-xs text-zinc-500" />
                      <YAxis className="text-xs text-zinc-500" />
                      <ChartTooltip content={<ChartTooltipContent />} />
                      <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                        {quantumData.map((entry, index) => (
                          <Cell key={`cell-${index}`} fill={entry.fill} />
                        ))}
                      </Bar>
                    </BarChart>
                  </ChartContainer>
                </CardContent>
              </Card>

              {/* Risk Scores per Finding */}
              <Card className="border-zinc-200 dark:border-zinc-800">
                <CardHeader>
                  <CardTitle className="text-base flex items-center gap-2">
                    <TrendingUp className="w-4 h-4" />
                    Risk Scores per Finding
                  </CardTitle>
                  <CardDescription>Risk score by finding (top 24, descending)</CardDescription>
                </CardHeader>
                <CardContent>
                  {!hasRiskScoresData ? (
                    <div className="flex items-center justify-center min-h-[240px] text-zinc-500 dark:text-zinc-400 text-sm">No risk score data to display</div>
                  ) : (
                    <ChartContainer config={riskScoreAreaChartConfig} className="aspect-auto h-[240px] w-full pb-8 cursor-pointer">
                      <AreaChart data={riskScoresAreaData} margin={{ top: 8, right: 8, bottom: 28, left: 0 }}>
                        <defs>
                          <linearGradient id="fillCbomRiskScore" x1="0" y1="0" x2="0" y2="1">
                            <stop offset="5%" stopColor="hsl(217 91% 60%)" stopOpacity={0.8} />
                            <stop offset="95%" stopColor="hsl(217 91% 60%)" stopOpacity={0.1} />
                          </linearGradient>
                        </defs>
                        <CartesianGrid vertical={false} className="stroke-zinc-200 dark:stroke-zinc-800" />
                        <XAxis dataKey="finding" tickLine={false} axisLine={false} tickMargin={8} minTickGap={16} height={56} interval={0} />
                        <YAxis hide domain={[0, 5]} />
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
                  <CardTitle className="text-xl">Remediation Metrics</CardTitle>
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
                          <p className="text-sm font-medium text-zinc-600 dark:text-zinc-400">Mean Time to Remediate</p>
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
                          <p className="text-sm font-medium text-zinc-600 dark:text-zinc-400">Critical Issues Fixed</p>
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
                          <p className="text-sm font-medium text-zinc-600 dark:text-zinc-400">High Priority Backlog</p>
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
                          <p className="text-sm font-medium text-zinc-600 dark:text-zinc-400">Remediation Velocity</p>
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
          </>
        )}

        {/* Tabs: Results | Ticketing */}
        <div className="flex items-center gap-1 border-b border-zinc-800 mb-2">
          <button
            className={`px-4 py-2 text-sm font-medium transition-colors cursor-pointer ${activeTab === "results" ? "text-white border-b-2 border-blue-500" : "text-zinc-400 hover:text-zinc-200"}`}
            onClick={() => setActiveTab("results")}
          >
            Results
          </button>
          <button
            className={`px-4 py-2 text-sm font-medium transition-colors cursor-pointer ${activeTab === "ticketing" ? "text-white border-b-2 border-blue-500" : "text-zinc-400 hover:text-zinc-200"}`}
            onClick={() => setActiveTab("ticketing")}
          >
            Ticketing Settings
          </button>
        </div>

        {activeTab === "ticketing" && (
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
            inputId="cbom-jira-project-id"
          />
        )}

        {activeTab === "results" && (
          <>
            {/* Findings Table */}
            <Card className="bg-zinc-900 border-zinc-800">
              <CardHeader className="pb-3">
                <div className="flex items-center justify-between">
                  <CardTitle className="text-lg text-white">Cryptographic Findings</CardTitle>
                  <div className="flex items-center gap-2">
                    <FindingSelectionMenu
                      selectedCount={selectedFindings.size}
                      onClearSelection={() => setSelectedFindings(new Set())}
                      ticketType="jira"
                      jiraOnClickHandler={() => createJiraTicketsMutation.mutate()}
                      isJiraCreating={createJiraTicketsMutation.isPending}
                      onBulkStatusChange={(status) => bulkStatusMutation.mutate(status)}
                      isBulkStatusChanging={bulkStatusMutation.isPending}
                    />
                  </div>
                </div>
              </CardHeader>
              <CardContent className="space-y-3">
                {/* Filters */}
                <div className="flex items-center gap-3 flex-wrap">
                  <div className="relative flex-1 min-w-[200px] max-w-sm">
                    <Search className="absolute left-3 top-1/2 -translate-y-1/2 size-4 text-zinc-500" />
                    <Input
                      placeholder="Search findings..."
                      className="pl-9 bg-zinc-800 border-zinc-700 text-white placeholder:text-zinc-500"
                      value={searchQuery}
                      onChange={(e) => setSearchQuery(e.target.value)}
                    />
                  </div>
                  <Select value={filterImpact} onValueChange={setFilterImpact}>
                    <SelectTrigger className="w-[130px] bg-zinc-800 border-zinc-700 text-zinc-300">
                      <SelectValue placeholder="Impact" />
                    </SelectTrigger>
                    <SelectContent className="bg-zinc-800 border-zinc-700">
                      <SelectItem value="all">All impacts</SelectItem>
                      <SelectItem value="critical">Critical</SelectItem>
                      <SelectItem value="high">High</SelectItem>
                      <SelectItem value="medium">Medium</SelectItem>
                      <SelectItem value="low">Low</SelectItem>
                    </SelectContent>
                  </Select>
                  <Select value={filterRiskScore} onValueChange={(v) => setFilterRiskScore(v as RiskScoreFilter)}>
                    <SelectTrigger className="w-[130px] bg-zinc-800 border-zinc-700 text-zinc-300">
                      <SelectValue placeholder="Risk score" />
                    </SelectTrigger>
                    <SelectContent className="bg-zinc-800 border-zinc-700">
                      <SelectItem value="all">Risk score</SelectItem>
                      <SelectItem value="critical">Critical (4)</SelectItem>
                      <SelectItem value="high">High (3)</SelectItem>
                      <SelectItem value="medium">Medium (2)</SelectItem>
                      <SelectItem value="low">Low (1)</SelectItem>
                    </SelectContent>
                  </Select>
                  <Select value={strengthFilter} onValueChange={setStrengthFilter}>
                    <SelectTrigger className="w-[140px] bg-zinc-800 border-zinc-700 text-zinc-300">
                      <SelectValue placeholder="Strength" />
                    </SelectTrigger>
                    <SelectContent className="bg-zinc-800 border-zinc-700">
                      <SelectItem value="all">All strengths</SelectItem>
                      <SelectItem value="weak">Weak</SelectItem>
                      <SelectItem value="moderate">Moderate</SelectItem>
                      <SelectItem value="strong">Strong</SelectItem>
                      <SelectItem value="quantum_safe">Quantum-Safe</SelectItem>
                    </SelectContent>
                  </Select>
                  <Select value={typeFilter} onValueChange={setTypeFilter}>
                    <SelectTrigger className="w-[160px] bg-zinc-800 border-zinc-700 text-zinc-300">
                      <SelectValue placeholder="Type" />
                    </SelectTrigger>
                    <SelectContent className="bg-zinc-800 border-zinc-700">
                      <SelectItem value="all">All types</SelectItem>
                      {uniqueTypes.map((t) => (
                        <SelectItem key={t} value={t}>{t.replace(/_/g, " ")}</SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                  <Select value={quantumFilter} onValueChange={setQuantumFilter}>
                    <SelectTrigger className="w-[150px] bg-zinc-800 border-zinc-700 text-zinc-300">
                      <SelectValue placeholder="Quantum" />
                    </SelectTrigger>
                    <SelectContent className="bg-zinc-800 border-zinc-700">
                      <SelectItem value="all">All</SelectItem>
                      <SelectItem value="safe">Quantum-Safe</SelectItem>
                      <SelectItem value="vulnerable">Vulnerable</SelectItem>
                    </SelectContent>
                  </Select>
                </div>

                {/* Results Count */}
                <p className="text-xs text-zinc-500">{filteredFindings.length} of {(findingsList ?? []).length} findings</p>

                {/* Table */}
                {filteredFindings.length === 0 ? (
                  <div className="text-center text-zinc-500 py-8">No findings match your filters.</div>
                ) : (
                  <div className="rounded-lg border border-zinc-800 overflow-hidden">
                    <Table>
                      <TableHeader>
                        <TableRow className="border-zinc-800 hover:bg-transparent">
                          <TableHead className="w-8 text-zinc-400">
                            <input
                              type="checkbox"
                              className="rounded border-zinc-600"
                              checked={selectedFindings.size === filteredFindings.length && filteredFindings.length > 0}
                              onChange={(e) => {
                                if (e.target.checked) {
                                  setSelectedFindings(new Set(filteredFindings.map((f) => f.id)));
                                } else {
                                  setSelectedFindings(new Set());
                                }
                              }}
                            />
                          </TableHead>
                          <TableHead className="text-zinc-400">Algorithm</TableHead>
                          <TableHead className="text-zinc-400">Type</TableHead>
                          <TableHead className="text-zinc-400">Impact</TableHead>
                          <TableHead className="text-zinc-400">Strength</TableHead>
                          <TableHead className="text-zinc-400">Quantum</TableHead>
                          <TableHead className="text-zinc-400">Risk</TableHead>
                          <TableHead className="text-zinc-400">Location</TableHead>
                          <TableHead className="text-zinc-400">Status</TableHead>
                          <TableHead className="text-zinc-400 text-right">Actions</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {filteredFindings.map((finding) => (
                          <TableRow
                            key={finding.id}
                            className="border-zinc-800 hover:bg-zinc-800/50 cursor-pointer"
                            onClick={() => setSelectedFinding(finding)}
                          >
                            <TableCell onClick={(e) => e.stopPropagation()}>
                              <input
                                type="checkbox"
                                className="rounded border-zinc-600"
                                checked={selectedFindings.has(finding.id)}
                                onChange={(e) => {
                                  const next = new Set(selectedFindings);
                                  if (e.target.checked) next.add(finding.id);
                                  else next.delete(finding.id);
                                  setSelectedFindings(next);
                                }}
                              />
                            </TableCell>
                            <TableCell className="text-zinc-200 font-medium max-w-[150px] truncate">
                              {finding.algorithm_name || finding.title}
                            </TableCell>
                            <TableCell className="text-zinc-400 text-sm">
                              {finding.algorithm_type?.replace(/_/g, " ") ?? "—"}
                            </TableCell>
                            <TableCell>
                              <Badge className={getImpactBadgeClass(finding.impact)}>
                                {finding.impact}
                              </Badge>
                            </TableCell>
                            <TableCell>
                              <Badge variant="outline" className={getStrengthBadgeClass(finding.crypto_strength)}>
                                {finding.crypto_strength ?? "unknown"}
                              </Badge>
                            </TableCell>
                            <TableCell>
                              {finding.quantum_safe === true ? (
                                <Badge variant="outline" className="border-green-500/50 text-green-400">Safe</Badge>
                              ) : finding.quantum_safe === false ? (
                                <Badge variant="outline" className="border-red-500/50 text-red-400">Vulnerable</Badge>
                              ) : (
                                <span className="text-zinc-500 text-xs">—</span>
                              )}
                            </TableCell>
                            <TableCell>
                              <Badge className={getImpactBadgeClass(finding.impact)}>
                                {finding.risk_score?.toFixed(1) ?? "—"}
                              </Badge>
                            </TableCell>
                            <TableCell className="text-zinc-500 text-xs max-w-[150px] truncate" title={finding.location ?? ""}>
                              {finding.location ?? "—"}
                            </TableCell>
                            <TableCell>
                              <Badge className={getFindingStatusBadgeClass(finding.status)}>
                                {finding.status?.replace(/_/g, " ") ?? "not started"}
                              </Badge>
                            </TableCell>
                            <TableCell className="text-right" onClick={(e) => e.stopPropagation()}>
                              <DropdownMenu>
                                <DropdownMenuTrigger asChild>
                                  <Button variant="ghost" size="sm" className="h-8 w-8 p-0 text-zinc-400 hover:text-white cursor-pointer">
                                    <ChevronDown className="size-4" />
                                  </Button>
                                </DropdownMenuTrigger>
                                <DropdownMenuContent align="end" className="bg-zinc-800 border-zinc-700">
                                  <DropdownMenuLabel className="text-zinc-400 text-xs">Status</DropdownMenuLabel>
                                  {(["not_started", "in_progress", "fixed", "ignored"] as const).map((state) => (
                                    <DropdownMenuItem
                                      key={state}
                                      className="text-zinc-300 focus:bg-zinc-700 cursor-pointer"
                                      onClick={() => toggleFindingMutation.mutate({ finding_id: finding.id, state })}
                                    >
                                      {state === "fixed" && <CheckCircle className="size-3 mr-2 text-green-400" />}
                                      {state === "ignored" && <EyeOff className="size-3 mr-2 text-zinc-500" />}
                                      {state === "in_progress" && <Loader2 className="size-3 mr-2 text-blue-400" />}
                                      {state === "not_started" && <Circle className="size-3 mr-2 text-zinc-400" />}
                                      {state.replace(/_/g, " ")}
                                    </DropdownMenuItem>
                                  ))}
                                </DropdownMenuContent>
                              </DropdownMenu>
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </div>
                )}
              </CardContent>
            </Card>

            {/* Top Risks Table */}
            {dashboard?.top_risks && dashboard.top_risks.length > 0 && (
              <Card className="bg-zinc-900 border-zinc-800">
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm text-zinc-300">Top Cryptographic Risks</CardTitle>
                </CardHeader>
                <CardContent>
                  <Table>
                    <TableHeader>
                      <TableRow className="border-zinc-800 hover:bg-transparent">
                        <TableHead className="text-zinc-400">Algorithm</TableHead>
                        <TableHead className="text-zinc-400">Type</TableHead>
                        <TableHead className="text-zinc-400">Strength</TableHead>
                        <TableHead className="text-zinc-400">Quantum Safe</TableHead>
                        <TableHead className="text-zinc-400">Impact</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {dashboard.top_risks.map((risk, i) => (
                        <TableRow key={i} className="border-zinc-800 hover:bg-zinc-800/50">
                          <TableCell className="text-zinc-200 font-medium">{risk.algorithm_name}</TableCell>
                          <TableCell className="text-zinc-400">{risk.algorithm_type?.replace(/_/g, " ")}</TableCell>
                          <TableCell>
                            <Badge variant="outline" className={getStrengthBadgeClass(risk.crypto_strength)}>
                              {risk.crypto_strength}
                            </Badge>
                          </TableCell>
                          <TableCell>
                            {risk.quantum_safe ? (
                              <Badge variant="outline" className="border-green-500/50 text-green-400">Yes</Badge>
                            ) : (
                              <Badge variant="outline" className="border-red-500/50 text-red-400">No</Badge>
                            )}
                          </TableCell>
                          <TableCell className="text-zinc-400 max-w-[200px] truncate">{risk.impact}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </CardContent>
              </Card>
            )}
          </>
        )}
      </div>

      {/* Finding Detail Dialog */}
      <Dialog open={!!selectedFinding} onOpenChange={(open) => !open && setSelectedFinding(null)}>
        <DialogContent className="sm:max-w-4xl max-h-[90vh] flex flex-col p-0 gap-0 overflow-hidden bg-zinc-900 border-zinc-800">
          {selectedFinding && (
            <>
              <DialogHeader className="px-6 pt-6 pb-3 shrink-0 border-b border-zinc-800">
                <DialogTitle className="text-white text-lg pr-8">
                  {selectedFinding.algorithm_name || selectedFinding.title}
                </DialogTitle>
              </DialogHeader>
              <ScrollArea className="h-[75vh] min-h-[200px] w-full px-6 pb-6">
                <div className="space-y-5 pt-4 pr-2">
                  {/* Metadata grid — 3 columns on md+, 2 on sm */}
                  <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
                    <div>
                      <div className="text-xs font-semibold uppercase tracking-wide text-zinc-500 mb-1">Algorithm Type</div>
                      <p className="text-sm text-zinc-200">{selectedFinding.algorithm_type?.replace(/_/g, " ") ?? "—"}</p>
                    </div>
                    <div>
                      <div className="text-xs font-semibold uppercase tracking-wide text-zinc-500 mb-1">Crypto Strength</div>
                      <Badge variant="outline" className={getStrengthBadgeClass(selectedFinding.crypto_strength)}>{selectedFinding.crypto_strength ?? "unknown"}</Badge>
                    </div>
                    <div>
                      <div className="text-xs font-semibold uppercase tracking-wide text-zinc-500 mb-1">Key Size</div>
                      <p className="text-sm text-zinc-200">{selectedFinding.key_size ? `${selectedFinding.key_size} bits` : "—"}</p>
                    </div>
                    <div>
                      <div className="text-xs font-semibold uppercase tracking-wide text-zinc-500 mb-1">Quantum Safe</div>
                      {selectedFinding.quantum_safe === true ? (
                        <Badge variant="outline" className="border-green-500/50 text-green-400">Yes</Badge>
                      ) : selectedFinding.quantum_safe === false ? (
                        <Badge variant="outline" className="border-red-500/50 text-red-400">No</Badge>
                      ) : <span className="text-sm text-zinc-400">—</span>}
                    </div>
                    <div>
                      <div className="text-xs font-semibold uppercase tracking-wide text-zinc-500 mb-1">Impact</div>
                      <Badge className={getImpactBadgeClass(selectedFinding.impact)}>{selectedFinding.impact}</Badge>
                    </div>
                    <div>
                      <div className="text-xs font-semibold uppercase tracking-wide text-zinc-500 mb-1">Risk Score</div>
                      <Badge className={getImpactBadgeClass(selectedFinding.impact)}>{selectedFinding.risk_score?.toFixed(1) ?? "—"}</Badge>
                    </div>
                  </div>

                  {selectedFinding.location && (
                    <div>
                      <div className="text-xs font-semibold uppercase tracking-wide text-zinc-500 mb-1">Location</div>
                      <p className="text-sm font-mono text-zinc-200 bg-zinc-800 px-3 py-2 rounded-md border border-zinc-700 break-all">{selectedFinding.location}</p>
                    </div>
                  )}

                  {selectedFinding.description && (
                    <div>
                      <div className="text-xs font-semibold uppercase tracking-wide text-zinc-500 mb-1">Description</div>
                      <p className="text-sm text-zinc-200 whitespace-pre-wrap">{selectedFinding.description}</p>
                    </div>
                  )}

                  {selectedFinding.snippet && (
                    <div>
                      <div className="text-xs font-semibold uppercase tracking-wide text-zinc-500 mb-1">Code Snippet</div>
                      <pre className="text-xs font-mono text-zinc-200 bg-zinc-800 px-3 py-2 rounded-md overflow-x-auto whitespace-pre-wrap border border-zinc-700">{selectedFinding.snippet}</pre>
                    </div>
                  )}

                  {/* OWASP Top 10 */}
                  {(() => {
                    const entries = getOwaspComplianceEntries(selectedFinding.owasp_top_10 as OwaspOrCompliance);
                    if (entries.length === 0) return null;
                    return (
                      <div>
                        <div className="text-xs font-semibold uppercase tracking-wide text-zinc-500 mb-1">OWASP Top 10</div>
                        <div className="flex flex-wrap gap-1.5">
                          {entries.map(([key, value]) => (
                            <Badge key={key} variant="outline" className="border-orange-500/50 text-orange-400 text-xs">
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
                        <div className="text-xs font-semibold uppercase tracking-wide text-zinc-500 mb-1">Compliance Controls</div>
                        <div className="flex flex-wrap gap-1.5">
                          {entries.map(([key, value]) => (
                            <Badge key={key} variant="outline" className="border-blue-500/50 text-blue-400 text-xs">
                              {COMPLIANCE_KEY_TO_LABEL[key] ?? value}
                            </Badge>
                          ))}
                        </div>
                      </div>
                    );
                  })()}

                  {selectedFinding.suggested_fix && (
                    <div>
                      <div className="text-xs font-semibold uppercase tracking-wide text-zinc-500 mb-1">Suggested Fix</div>
                      <p className="text-sm text-zinc-200 whitespace-pre-wrap">{selectedFinding.suggested_fix}</p>
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
            </>
          )}
        </DialogContent>
      </Dialog>
      <ScrollBar orientation="vertical" />
    </ScrollArea>
  );
}
