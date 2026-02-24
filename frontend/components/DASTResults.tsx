"use client";

import { useMemo, useState, useEffect } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
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
import { ScrollArea, ScrollBar } from "@/components/ui/scroll-area";
import {
  AlertTriangle,
  ArrowLeft,
  ScanSearch,
  Search,
  Target,
  Percent,
  Shield,
  Activity,
  Zap,
  Wrench,
  Clock,
  MinusCircle,
  Pencil,
  CheckCircle,
  EyeOff,
  Loader2,
  Circle,
  Download,
  MessageCircle,
  BarChart3,
  Ticket,
  Filter,
  ChevronDown,
  Check,
  X,
} from "lucide-react";
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
  XAxis,
  YAxis,
} from "recharts";
import { Progress } from "@/components/ui/progress";
import type { DASTSingleScanDashboard } from "@/utils/backend_api";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { toggleFindingState, createTicket, updateScan, type ScanTicketingIntegrationSettings } from "@/utils/backend_api";
import { toast } from "sonner";
import { showErrorToast } from "@/utils/error-handler";
import FindingSelectionMenu from "@/components/finding-selection-menu";
import TicketingIntegrationsSettings from "@/components/ticketing-integrations-settings";
import Link from "next/link";

/** DAST finding as returned by backend (get_findings_for_scan_type dast branch) */
export interface DASTFinding {
  id: string;
  title?: string | null;
  url?: string | null;
  description?: string | null;
  impact?: string | null;
  risk_score?: number;
  status?: string | null;
  compliance_controls?: Record<string, string> | unknown;
  owasp_top_10?: Record<string, string> | unknown;
  suggested_fix?: string | null;
  category?: string | null;
  confidence?: string | null;
}

export interface DASTResultsProps {
  teamId: string;
  scanId: number;
  title?: string;
  scanStatus?: string;
  dashboard: DASTSingleScanDashboard | null;
  findings?: DASTFinding[] | unknown[] | null;
  scanMetadata?: Record<string, unknown> | null;
  integrationSettings?: Record<string, unknown> | null;
  onIntegrationSettingsUpdated?: () => void;
  onDownloadReport?: () => void;
  isExporting?: boolean;
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

function getCategoryBadgeClass(category: string): string {
  const c = (category ?? "").toLowerCase().replace(/\s/g, "_");
  if (!c || c === "—") return "bg-zinc-100 text-zinc-600 dark:bg-zinc-700/50 dark:text-zinc-300";
  if (c.includes("xss")) return "bg-rose-100 text-rose-800 dark:bg-rose-900/40 dark:text-rose-200";
  if (c.includes("sql") || c.includes("injection")) return "bg-red-100 text-red-800 dark:bg-red-900/40 dark:text-red-200";
  if (c.includes("header") || c.includes("security")) return "bg-violet-100 text-violet-800 dark:bg-violet-900/40 dark:text-violet-200";
  if (c.includes("ssrf") || c.includes("redirect")) return "bg-amber-100 text-amber-800 dark:bg-amber-900/40 dark:text-amber-200";
  if (c.includes("xxe") || c.includes("xml")) return "bg-orange-100 text-orange-800 dark:bg-orange-900/40 dark:text-orange-200";
  if (c.includes("csrf")) return "bg-cyan-100 text-cyan-800 dark:bg-cyan-900/40 dark:text-cyan-200";
  if (c.includes("auth") || c.includes("login")) return "bg-indigo-100 text-indigo-800 dark:bg-indigo-900/40 dark:text-indigo-200";
  return "bg-sky-100 text-sky-800 dark:bg-sky-900/40 dark:text-sky-200";
}

function getConfidenceBadgeClass(confidence: string): string {
  const c = (confidence ?? "").toLowerCase().trim();
  if (!c || c === "—") return "bg-zinc-100 text-zinc-600 dark:bg-zinc-700/50 dark:text-zinc-300";
  if (c === "high") return "bg-emerald-100 text-emerald-800 dark:bg-emerald-900/40 dark:text-emerald-200";
  if (c === "medium") return "bg-amber-100 text-amber-800 dark:bg-amber-900/40 dark:text-amber-200";
  if (c === "low") return "bg-blue-100 text-blue-800 dark:bg-blue-900/40 dark:text-blue-200";
  return "bg-slate-100 text-slate-600 dark:bg-slate-700/50 dark:text-slate-300";
}

function countFindingField(val: unknown): number {
  if (val == null) return 0;
  if (Array.isArray(val)) return val.length;
  if (typeof val === "object" && !Array.isArray(val)) return Object.keys(val).length;
  return 0;
}

function getOwaspComplianceEntries(val: unknown): [string, string][] {
  if (val == null) return [];
  if (Array.isArray(val)) {
    return val.map((item) => {
      if (item && typeof item === "object") {
        const entries = Object.entries(item).filter(([, v]) => v != null && String(v).trim() !== "");
        if (entries.length > 0) return [entries[0][0], String(entries[0][1])] as [string, string];
        const k = Object.keys(item)[0];
        return [k ?? "", ""] as [string, string];
      }
      return ["", ""] as [string, string];
    });
  }
  if (typeof val === "object" && !Array.isArray(val)) {
    return Object.entries(val).filter(([, v]) => v != null && String(v).trim() !== "") as [string, string][];
  }
  return [];
}

export default function DASTResults({
  teamId,
  scanId,
  dashboard,
  findings,
  scanMetadata,
  integrationSettings,
  onIntegrationSettingsUpdated,
  onDownloadReport,
  isExporting = false,
}: DASTResultsProps) {
  const queryClient = useQueryClient();
  const router = useRouter();
  const searchParams = useSearchParams();
  const origin = searchParams.get("origin");

  const [selectedFinding, setSelectedFinding] = useState<DASTFinding | null>(null);
  const [activeTab, setActiveTab] = useState<"results" | "ticketing">("results");
  const [selectedRowIds, setSelectedRowIds] = useState<Set<string>>(new Set());
  const [jiraProjectId, setJiraProjectId] = useState("");

  const findingsList = Array.isArray(findings) ? (findings as DASTFinding[]) : [];
  const hasFindings = findingsList.length > 0;

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

  const filteredFindingsList = useMemo(() => {
    let list = findingsList;

    const q = findingsSearchQuery.trim().toLowerCase();
    if (q) {
      list = list.filter((f) => {
        const title = ((f.title ?? "") + "").toLowerCase();
        const url = ((f.url ?? "") + "").toLowerCase();
        const description = ((f.description ?? "") + "").toLowerCase();
        const impact = ((f.impact ?? "") + "").toLowerCase();
        const status = ((f.status ?? "") + "").toLowerCase();
        const category = ((f.category ?? "") + "").toLowerCase();
        const confidence = ((f.confidence ?? "") + "").toLowerCase();
        const suggestedFix = ((f.suggested_fix ?? "") + "").toLowerCase();
        return (
          title.includes(q) ||
          url.includes(q) ||
          description.includes(q) ||
          impact.includes(q) ||
          status.includes(q) ||
          category.includes(q) ||
          confidence.includes(q) ||
          suggestedFix.includes(q)
        );
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
      ? (integrationSettings.jira as { jira_project_id?: string } | undefined)
      : undefined;
  const initialJiraProjectId = jiraFromSettings?.jira_project_id ?? "";
  useEffect(() => {
    setJiraProjectId(initialJiraProjectId);
  }, [initialJiraProjectId]);

  const hasTicketingTab = !!teamId && !!scanId && onIntegrationSettingsUpdated != null;

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

  const toggleFindingMutation = useMutation({
    mutationFn: ({ finding_id, state }: { finding_id: string; state: "fixed" | "ignored" | "in_progress" | "not_started" }) => {
      const tid = parseInt(teamId ?? "0", 10);
      if (!scanId || Number.isNaN(tid)) throw new Error("Missing team or scan");
      return toggleFindingState({ team_id: tid, type: "dast", scan_id: scanId, finding_id, state });
    },
    onSuccess: () => {
      const tid = parseInt(teamId ?? "0", 10);
      if (scanId != null && !Number.isNaN(tid)) {
        queryClient.invalidateQueries({ queryKey: ["dast-scan", tid, scanId] });
      }
      toast.success("Finding status updated");
    },
    onError: (err) => {
      showErrorToast(err, "Failed to update finding status");
    },
  });

  const updateIntegrationMutation = useMutation({
    mutationFn: (payload: { integration_settings: ScanTicketingIntegrationSettings }) => {
      const tid = parseInt(teamId ?? "0", 10);
      if (!scanId || Number.isNaN(tid)) throw new Error("Missing team or scan");
      return updateScan({ team_id: tid, type: "dast", scan_id: scanId, data: payload });
    },
    onSuccess: () => {
      onIntegrationSettingsUpdated?.();
      const tid = parseInt(teamId ?? "0", 10);
      if (scanId != null && !Number.isNaN(tid)) {
        queryClient.invalidateQueries({ queryKey: ["dast-scan", tid, scanId] });
      }
      toast.success("Ticketing settings saved");
    },
    onError: (err) => {
      showErrorToast(err, "Failed to save ticketing settings");
    },
  });

  const createJiraTicketsMutation = useMutation({
    mutationFn: async () => {
      const tid = parseInt(teamId ?? "0", 10);
      if (!scanId || Number.isNaN(tid)) throw new Error("Missing team or scan");
      const selected = findingsList.filter((f) => selectedRowIds.has(f.id));
      if (selected.length === 0) throw new Error("No findings selected");
      const impactCounts: Record<string, number> = {};
      for (const f of selected) {
        const impact = (f.impact ?? "Unknown").trim() || "Unknown";
        impactCounts[impact] = (impactCounts[impact] ?? 0) + 1;
      }
      const summary = `DAST findings: ${selected.length} (${Object.entries(impactCounts)
        .map(([k, v]) => `${k}: ${v}`)
        .join(", ")})`;
      const description = selected
        .map(
          (f) =>
            `[${(f.impact ?? "").trim() || "—"}] ${(f.title ?? "").trim() || "Untitled"}\nURL: ${f.url ?? "—"}\n${(f.description ?? "").trim().slice(0, 300)}`
        )
        .join("\n\n---\n\n");
      await createTicket(tid, "dast", scanId, { ticket_type: "jira", summary, description });
    },
    onMutate: () => {
      const toastId = toast.loading("Creating Jira ticket(s)...");
      return { toastId };
    },
    onSuccess: (_, __, context) => {
      if (context?.toastId != null) toast.success(`Jira ticket(s) created for ${selectedRowIds.size} finding(s)`, { id: context.toastId });
      else toast.success(`Jira ticket(s) created for ${selectedRowIds.size} finding(s)`);
      setSelectedRowIds(new Set());
    },
    onError: (err, __, context) => {
      if (context?.toastId != null) toast.dismiss(context.toastId);
      showErrorToast(err, "Failed to create Jira ticket(s)");
    },
  });

  if (!dashboard && !hasFindings) {
    return (
      <div className="p-6 text-center text-zinc-500 dark:text-zinc-400">
        No dashboard data or findings available for this scan.
      </div>
    );
  }

  if (!dashboard) {
    return (
      <div className="min-h-screen bg-white dark:bg-zinc-900">
        <div className="border-b border-zinc-200 dark:border-zinc-800 px-4 py-3">
          <div className="max-w-7xl mx-auto flex items-center gap-4">
            <Link
              href={`/${teamId}/dast`}
              className="inline-flex items-center gap-2 text-sm text-zinc-600 hover:text-zinc-900 dark:text-zinc-400 dark:hover:text-zinc-100"
            >
              <ArrowLeft className="h-4 w-4" />
              Back to DAST scans
            </Link>
            View Your DAST Scan results in Detail
          
          </div>
        </div>
        <div className="p-6 max-w-7xl mx-auto space-y-4">
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
          <FindingsTable
            findingsList={filteredFindingsList}
            selectedFinding={selectedFinding}
            setSelectedFinding={setSelectedFinding}
            selectedRowIds={new Set()}
            toggleRowSelection={() => {}}
            toggleSelectAll={() => {}}
            toggleFindingMutation={toggleFindingMutation}
            getImpactBadgeClass={getImpactBadgeClass}
            getFindingStatusBadgeClass={getFindingStatusBadgeClass}
            countFindingField={countFindingField}
            getOwaspComplianceEntries={getOwaspComplianceEntries}
          />
        </div>
        <FindingDetailDialog
          finding={selectedFinding}
          onClose={() => setSelectedFinding(null)}
          getImpactBadgeClass={getImpactBadgeClass}
          getFindingStatusBadgeClass={getFindingStatusBadgeClass}
          getOwaspComplianceEntries={getOwaspComplianceEntries}
        />
      </div>
    );
  }

  const card = dashboard.card_data;
  const severityPieData = useMemo(() => {
    const d = dashboard.severity_distribution;
    return [
      { name: "Critical", value: d.critical, fill: "#dc2626" },
      { name: "High", value: d.high, fill: "#ea580c" },
      { name: "Medium", value: d.medium, fill: "#ca8a04" },
      { name: "Low", value: d.low, fill: "#2563eb" },
    ].filter((s) => s.value > 0);
  }, [dashboard.severity_distribution]);

  const complianceStatusEntries = useMemo(
    () => Object.entries(dashboard.compliance_status).filter(([, v]) => v > 0),
    [dashboard.compliance_status]
  );

  const owaspBarData = useMemo(() => {
    return Object.entries(dashboard.owasp_top_10_issues).map(([name, count]) => ({
      name: name.includes(" - ") ? name.split(" - ")[1]?.slice(0, 24) ?? name : name.slice(0, 24),
      fullName: name,
      count,
    }));
  }, [dashboard.owasp_top_10_issues]);

  const vulnCategoryBarData = useMemo(() => {
    return Object.entries(dashboard.vulnerability_category_issues_distribution).map(([category, count]) => ({
      category: category.replace(/_/g, " "),
      count,
    }));
  }, [dashboard.vulnerability_category_issues_distribution]);

  const riskScoresPerCategoryData = useMemo(() => {
    const categories = Object.keys(dashboard.risk_scores_per_category);
    if (categories.length === 0) return [];
    const severityKeys = ["critical", "high", "medium", "low"] as const;
    return categories.map((cat) => {
      const o = dashboard.risk_scores_per_category[cat] ?? {};
      const row: Record<string, string | number> = { category: cat.replace(/_/g, " ") };
      severityKeys.forEach((s) => (row[s] = o[s] ?? 0));
      return row;
    });
  }, [dashboard.risk_scores_per_category]);

  const areaConfig = {
    critical: { label: "Critical", color: "hsl(0 72% 51%)" },
    high: { label: "High", color: "hsl(25 95% 53%)" },
    medium: { label: "Medium", color: "hsl(45 93% 47%)" },
    low: { label: "Low", color: "hsl(217 91% 60%)" },
  } satisfies ChartConfig;

  const confidencePieData = useMemo(() => {
    const d = dashboard.confidence_distribution;
    return [
      { name: "High", value: d.high, fill: "#16a34a" },
      { name: "Medium", value: d.medium, fill: "#ca8a04" },
      { name: "Low", value: d.low, fill: "#2563eb" },
    ].filter((s) => s.value > 0);
  }, [dashboard.confidence_distribution]);

  const securityCategoryBarData = useMemo(() => {
    return Object.entries(dashboard.security_category_assessment).map(([category, score]) => ({
      category: category.replace(/_/g, " "),
      score,
    }));
  }, [dashboard.security_category_assessment]);

  const complianceRiskBarData = useMemo(() => {
    return Object.entries(dashboard.compliance_risk_assessment).map(([name, score]) => ({ name, score }));
  }, [dashboard.compliance_risk_assessment]);

  const remediation = dashboard.remediation_metrics;
  const totalFindings = remediation.total_findings || 1;
  const remediationBars = [
    { label: "Total findings", value: remediation.total_findings, fill: "#dc2626", icon: AlertTriangle },
    { label: "Fixed", value: remediation.total_fixed, fill: "#16a34a", icon: Zap },
    { label: "In progress", value: remediation.total_in_progress, fill: "#2563eb", icon: Wrench },
    { label: "Not started", value: remediation.total_not_started, fill: "#ea580c", icon: Clock },
    { label: "Ignored", value: remediation.total_ignored, fill: "#71717a", icon: MinusCircle },
  ];

  return (
    <div className="min-h-screen bg-white dark:bg-zinc-900">
      <div className="container mx-auto p-6 space-y-6">
        {/* Page title – SAST-style layout */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-4">
            <Button
              variant="outline"
              size="icon"
              onClick={() => router.push(origin === "chat" ? `/${teamId}/dast/${scanId}` : `/${teamId}/dast`)}
              className="cursor-pointer"
              aria-label="Back"
            >
              <ArrowLeft className="h-4 w-4" />
            </Button>
            <div>
              <h1 className="text-3xl font-bold text-zinc-900 dark:text-white">DAST Scan Results</h1>
              <p className="text-sm text-zinc-600 dark:text-zinc-400 mt-1">
              Findings and security metrics
              </p>
            </div>
          </div>
          {teamId && scanId && (
            <div className="flex items-center gap-2">
              {onDownloadReport && (
                <Button
                  variant="outline"
                  className="cursor-pointer bg-zinc-700 hover:bg-zinc-600 text-white border-zinc-600"
                  onClick={onDownloadReport}
                  disabled={isExporting}
                  aria-label="Download scan report"
                >
                  <Download className="h-4 w-4 mr-2" />
                  {isExporting ? "Downloading..." : "Download Scan Report"}
                </Button>
              )}
              <Button
                variant="default"
                className="cursor-pointer bg-blue-600 hover:bg-blue-700 text-white"
                onClick={() => router.push(`/${teamId}/dast/${scanId}`)}
              >
                <MessageCircle className="h-4 w-4 mr-2" />
                Chat with the Results
              </Button>
            </div>
          )}
        </div>

        {/* Tabs: Results | Ticketing integrations */}
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
                integration_settings: { jira: { jira_project_id: jiraProjectId.trim() || null } },
              });
            }}
            isSaving={updateIntegrationMutation.isPending}
            inputId="dast-jira-project-id"
          />
        ) : (
          <>
      <div className="space-y-6">
        {/* Card data */}
        <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-7 gap-4">
          <Card className="border-zinc-200 dark:border-zinc-800 py-3 px-3">
            <CardContent className="p-0">
              <div className="flex flex-col items-start gap-2">
                <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-red-500/15 dark:bg-red-500/10">
                  <Target className="h-4 w-4 text-red-500" />
                </div>
                <p className="text-xs font-medium text-zinc-600 dark:text-zinc-400">Critical</p>
                <p className="text-xl font-bold text-zinc-900 dark:text-white">{card.total_critical_issues}</p>
              </div>
            </CardContent>
          </Card>
          <Card className="border-zinc-200 dark:border-zinc-800 py-3 px-3">
            <CardContent className="p-0">
              <div className="flex flex-col items-start gap-2">
                <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-orange-500/15 dark:bg-orange-500/10">
                  <AlertTriangle className="h-4 w-4 text-orange-500" />
                </div>
                <p className="text-xs font-medium text-zinc-600 dark:text-zinc-400">High</p>
                <p className="text-xl font-bold text-zinc-900 dark:text-white">{card.total_high_issues}</p>
              </div>
            </CardContent>
          </Card>
          <Card className="border-zinc-200 dark:border-zinc-800 py-3 px-3">
            <CardContent className="p-0">
              <div className="flex flex-col items-start gap-2">
                <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-amber-500/15 dark:bg-amber-500/10">
                  <Shield className="h-4 w-4 text-amber-500" />
                </div>
                <p className="text-xs font-medium text-zinc-600 dark:text-zinc-400">Medium</p>
                <p className="text-xl font-bold text-zinc-900 dark:text-white">{card.total_medium_issues}</p>
              </div>
            </CardContent>
          </Card>
          <Card className="border-zinc-200 dark:border-zinc-800 py-3 px-3">
            <CardContent className="p-0">
              <div className="flex flex-col items-start gap-2">
                <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-blue-500/15 dark:bg-blue-500/10">
                  <Shield className="h-4 w-4 text-blue-500" />
                </div>
                <p className="text-xs font-medium text-zinc-600 dark:text-zinc-400">Low</p>
                <p className="text-xl font-bold text-zinc-900 dark:text-white">{card.total_low_issues}</p>
              </div>
            </CardContent>
          </Card>
          <Card className="border-zinc-200 dark:border-zinc-800 py-3 px-3">
            <CardContent className="p-0">
              <div className="flex flex-col items-start gap-2">
                <div
                  className={`flex h-8 w-8 shrink-0 items-center justify-center rounded-lg ${
                    card.average_risk_score >= 7 ? "bg-red-500/15" : card.average_risk_score >= 5 ? "bg-amber-500/15" : "bg-green-500/15"
                  }`}
                >
                  <Activity className={`h-4 w-4 ${card.average_risk_score >= 7 ? "text-red-500" : card.average_risk_score >= 5 ? "text-amber-500" : "text-green-500"}`} />
                </div>
                <p className="text-xs font-medium text-zinc-600 dark:text-zinc-400">Avg risk score</p>
                <p className="text-xl font-bold text-zinc-900 dark:text-white">{card.average_risk_score.toFixed(1)}</p>
              </div>
            </CardContent>
          </Card>
          <Card className="border-zinc-200 dark:border-zinc-800 py-3 px-3">
            <CardContent className="p-0">
              <div className="flex flex-col items-start gap-2">
                <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-zinc-500/15 dark:bg-zinc-400/10">
                  <ScanSearch className="h-4 w-4 text-zinc-500" />
                </div>
                <p className="text-xs font-medium text-zinc-600 dark:text-zinc-400">URLs scanned</p>
                <p className="text-xl font-bold text-zinc-900 dark:text-white">{card.urls_scanned}</p>
              </div>
            </CardContent>
          </Card>
          <Card className="border-zinc-200 dark:border-zinc-800 py-3 px-3">
            <CardContent className="p-0">
              <div className="flex flex-col items-start gap-2">
                <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-green-500/15 dark:bg-green-500/10">
                  <Percent className="h-4 w-4 text-green-500" />
                </div>
                <p className="text-xs font-medium text-zinc-600 dark:text-zinc-400">Coverage %</p>
                <p className="text-xl font-bold text-zinc-900 dark:text-white">{card.coverage_percentage.toFixed(1)}%</p>
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Severity distribution (pie) */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <Card className="border-zinc-200 dark:border-zinc-800">
            <CardHeader className="pb-2">
              <CardTitle className="text-base">Severity Distribution</CardTitle>
              <CardDescription>Critical / High / Medium / Low</CardDescription>
            </CardHeader>
            <CardContent>
              {severityPieData.length === 0 ? (
                <p className="text-center text-sm text-zinc-500 py-8">No data yet</p>
              ) : (
                <ChartContainer config={{}} className="mx-auto aspect-square max-h-[260px]">
                  <PieChart>
                    <ChartTooltip content={<ChartTooltipContent />} />
                    <Pie
                      data={severityPieData}
                      dataKey="value"
                      nameKey="name"
                      cx="50%"
                      cy="50%"
                      innerRadius={50}
                      outerRadius={90}
                      paddingAngle={2}
                      label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                    >
                      {severityPieData.map((entry, i) => (
                        <Cell key={entry.name} fill={entry.fill} />
                      ))}
                    </Pie>
                  </PieChart>
                </ChartContainer>
              )}
            </CardContent>
          </Card>

          {/* Compliance status (cards with progress bars) */}
          <Card className="border-zinc-200 dark:border-zinc-800">
            <CardHeader className="pb-2">
              <CardTitle className="text-base">Compliance Status</CardTitle>
              <CardDescription>Issues per standard (PCI DSS, ISO 27001–27004)</CardDescription>
            </CardHeader>
            <CardContent>
              {complianceStatusEntries.length === 0 ? (
                <p className="text-center text-sm text-zinc-500 py-8">No compliance data yet</p>
              ) : (
                <div className="space-y-4">
                  {complianceStatusEntries.map(([name, count]) => {
                    const max = Math.max(1, ...Object.values(dashboard.compliance_status));
                    const pct = (count / max) * 100;
                    return (
                      <div key={name} className="flex items-center gap-3">
                        <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-blue-500/15 dark:bg-blue-500/10">
                          <Shield className="h-4 w-4 text-blue-500" />
                        </div>
                        <span className="text-sm font-medium text-zinc-900 dark:text-white w-28 shrink-0">{name}</span>
                        <span className="text-sm font-bold tabular-nums w-10">{count}</span>
                        <div className="flex-1 min-w-0">
                          <div className="h-3 rounded-full bg-zinc-200 dark:bg-zinc-700 overflow-hidden">
                            <div
                              className="h-full rounded-full transition-all bg-blue-500"
                              style={{ width: `${Math.min(100, pct)}%` }}
                            />
                          </div>
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </CardContent>
          </Card>
        </div>

        {/* OWASP Top 10 (bar) */}
        <Card className="border-zinc-200 dark:border-zinc-800">
          <CardHeader className="pb-2">
            <CardTitle className="text-base">OWASP Top 10 Issues</CardTitle>
            <CardDescription>Issue count by OWASP category</CardDescription>
          </CardHeader>
          <CardContent>
            {owaspBarData.every((d) => d.count === 0) ? (
              <p className="text-center text-sm text-zinc-500 py-8">No data yet</p>
            ) : (
              <ChartContainer config={{ count: { label: "Count", color: "hsl(217 91% 60%)" } }} className="h-[300px] w-full">
                <BarChart data={owaspBarData} layout="vertical" margin={{ left: 8, right: 8 }}>
                  <CartesianGrid horizontal={false} />
                  <XAxis type="number" tickLine={false} axisLine={false} allowDecimals={false} />
                  <YAxis type="category" dataKey="name" tickLine={false} axisLine={false} width={140} tick={{ fontSize: 11 }} />
                  <ChartTooltip content={<ChartTooltipContent />} formatter={(value) => [value, "Count"]} />
                  <Bar dataKey="count" radius={[0, 4, 4, 0]} fill="var(--color-count)" />
                </BarChart>
              </ChartContainer>
            )}
          </CardContent>
        </Card>

        {/* Vulnerability category issues distribution (bar) */}
        <Card className="border-zinc-200 dark:border-zinc-800">
          <CardHeader className="pb-2">
            <CardTitle className="text-base">Vulnerability Category Issues Distribution</CardTitle>
            <CardDescription>Five categories</CardDescription>
          </CardHeader>
          <CardContent>
            {vulnCategoryBarData.every((d) => d.count === 0) ? (
              <p className="text-center text-sm text-zinc-500 py-8">No data yet</p>
            ) : (
              <ChartContainer config={{ count: { label: "Count", color: "hsl(25 95% 53%)" } }} className="h-[260px] w-full">
                <BarChart data={vulnCategoryBarData}>
                  <CartesianGrid vertical={false} />
                  <XAxis dataKey="category" tickLine={false} axisLine={false} />
                  <YAxis tickLine={false} axisLine={false} allowDecimals={false} />
                  <ChartTooltip content={<ChartTooltipContent />} />
                  <Bar dataKey="count" radius={[4, 4, 0, 0]} fill="var(--color-count)" />
                </BarChart>
              </ChartContainer>
            )}
          </CardContent>
        </Card>

        {/* Risk scores per category (area/line) */}
        <Card className="border-zinc-200 dark:border-zinc-800">
          <CardHeader className="pb-2">
            <CardTitle className="text-base">Risk Scores per Category</CardTitle>
            <CardDescription>Count by severity for each category</CardDescription>
          </CardHeader>
          <CardContent>
            {riskScoresPerCategoryData.length === 0 ? (
              <p className="text-center text-sm text-zinc-500 py-8">No data yet</p>
            ) : (
              <ChartContainer config={areaConfig} className="h-[280px] w-full">
                <AreaChart data={riskScoresPerCategoryData}>
                  <CartesianGrid vertical={false} />
                  <XAxis dataKey="category" tickLine={false} axisLine={false} />
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

        {/* Confidence distribution (pie) + Security category assessment (bar) */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <Card className="border-zinc-200 dark:border-zinc-800">
            <CardHeader className="pb-2">
              <CardTitle className="text-base">Confidence Distribution</CardTitle>
              <CardDescription>High / Medium / Low</CardDescription>
            </CardHeader>
            <CardContent>
              {confidencePieData.length === 0 ? (
                <p className="text-center text-sm text-zinc-500 py-8">No data yet</p>
              ) : (
                <ChartContainer config={{}} className="mx-auto aspect-square max-h-[240px]">
                  <PieChart>
                    <ChartTooltip content={<ChartTooltipContent />} />
                    <Pie
                      data={confidencePieData}
                      dataKey="value"
                      nameKey="name"
                      cx="50%"
                      cy="50%"
                      innerRadius={40}
                      outerRadius={80}
                      paddingAngle={2}
                      label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                    >
                      {confidencePieData.map((entry, i) => (
                        <Cell key={entry.name} fill={entry.fill} />
                      ))}
                    </Pie>
                  </PieChart>
                </ChartContainer>
              )}
            </CardContent>
          </Card>
          <Card className="border-zinc-200 dark:border-zinc-800">
            <CardHeader className="pb-2">
              <CardTitle className="text-base">Security Category Assessment</CardTitle>
              <CardDescription>Average risk score per category</CardDescription>
            </CardHeader>
            <CardContent>
              {securityCategoryBarData.every((d) => d.score === 0) ? (
                <p className="text-center text-sm text-zinc-500 py-8">No data yet</p>
              ) : (
                <ChartContainer config={{ score: { label: "Score", color: "hsl(25 95% 53%)" } }} className="h-[240px] w-full">
                  <BarChart data={securityCategoryBarData}>
                    <CartesianGrid vertical={false} />
                    <XAxis dataKey="category" tickLine={false} axisLine={false} />
                    <YAxis tickLine={false} axisLine={false} allowDecimals={true} />
                    <ChartTooltip content={<ChartTooltipContent />} />
                    <Bar dataKey="score" radius={[4, 4, 0, 0]} fill="var(--color-score)" />
                  </BarChart>
                </ChartContainer>
              )}
            </CardContent>
          </Card>
        </div>

        {/* Compliance risk assessment (bar) */}
        <Card className="border-zinc-200 dark:border-zinc-800">
          <CardHeader className="pb-2">
            <CardTitle className="text-base">Compliance Risk Assessment</CardTitle>
            <CardDescription>Average risk score per compliance control</CardDescription>
          </CardHeader>
          <CardContent>
            {complianceRiskBarData.every((d) => d.score === 0) ? (
              <p className="text-center text-sm text-zinc-500 py-8">No data yet</p>
            ) : (
              <ChartContainer config={{ score: { label: "Score", color: "hsl(0 72% 51%)" } }} className="h-[260px] w-full">
                <BarChart data={complianceRiskBarData}>
                  <CartesianGrid vertical={false} />
                  <XAxis dataKey="name" tickLine={false} axisLine={false} />
                  <YAxis tickLine={false} axisLine={false} allowDecimals={true} />
                  <ChartTooltip content={<ChartTooltipContent />} />
                  <Bar dataKey="score" radius={[4, 4, 0, 0]} fill="var(--color-score)" />
                </BarChart>
              </ChartContainer>
            )}
          </CardContent>
        </Card>

        {/* Remediation metrics (progress bars) */}
        <Card className="border-zinc-200 dark:border-zinc-800">
          <CardHeader className="pb-2">
            <CardTitle className="text-base">Remediation Metrics</CardTitle>
            <CardDescription>Finding status breakdown</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              {remediationBars.map(({ label, value, fill, icon: Icon }) => {
                const pct = label === "Total findings" ? 100 : totalFindings > 0 ? (value / totalFindings) * 100 : 0;
                return (
                  <div key={label} className="flex items-center gap-3">
                    <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg" style={{ backgroundColor: `${fill}20` }}>
                      <Icon className="h-4 w-4" style={{ color: fill }} />
                    </div>
                    <span className="text-sm font-medium text-zinc-900 dark:text-white w-32 shrink-0">{label}</span>
                    <span className="text-sm font-bold tabular-nums w-10">{value}</span>
                    <div className="flex-1 flex items-center gap-2 min-w-0">
                      <div className="flex-1 h-3 rounded-full bg-zinc-200 dark:bg-zinc-700 overflow-hidden">
                        <div className="h-full rounded-full transition-all" style={{ width: `${pct}%`, backgroundColor: fill }} />
                      </div>
                      {label !== "Total findings" && (
                        <span className="text-sm tabular-nums text-zinc-500 dark:text-zinc-400 w-10 shrink-0">
                          {pct.toFixed(0)}%
                        </span>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
          </CardContent>
        </Card>

        {/* Findings table */}
        <Card className="border-zinc-200 dark:border-zinc-800">
          <CardHeader>
            <CardTitle>Findings</CardTitle>
            <CardDescription>
              {hasFindings
                ? `${findingsList.length} findings. Select rows to create Jira tickets; use Action to change finding state.`
                : "No findings to display."}
            </CardDescription>
          </CardHeader>
          <CardContent>
            {hasFindings ? (
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
                <FindingSelectionMenu
                  selectedCount={selectedRowIds.size}
                  onClearSelection={() => setSelectedRowIds(new Set())}
                  jiraOnClickHandler={() => createJiraTicketsMutation.mutate()}
                  ticketType="jira"
                  isJiraCreating={createJiraTicketsMutation.isPending}
                />
                <FindingsTable
                  findingsList={filteredFindingsList}
                  selectedFinding={selectedFinding}
                  setSelectedFinding={setSelectedFinding}
                  selectedRowIds={selectedRowIds}
                  toggleRowSelection={toggleRowSelection}
                  toggleSelectAll={toggleSelectAll}
                  toggleFindingMutation={toggleFindingMutation}
                  getImpactBadgeClass={getImpactBadgeClass}
                  getFindingStatusBadgeClass={getFindingStatusBadgeClass}
                  countFindingField={countFindingField}
                  getOwaspComplianceEntries={getOwaspComplianceEntries}
                />
              </>
            ) : (
              <div className="flex items-center justify-center py-12 text-zinc-500 dark:text-zinc-400 text-sm">
                No findings to display.
              </div>
            )}
          </CardContent>
        </Card>
      </div>
      <FindingDetailDialog
        finding={selectedFinding}
        onClose={() => setSelectedFinding(null)}
        getImpactBadgeClass={getImpactBadgeClass}
        getFindingStatusBadgeClass={getFindingStatusBadgeClass}
        getOwaspComplianceEntries={getOwaspComplianceEntries}
      />
        </>
        )}
      </div>
    </div>
  );
}

function FindingsTable({
  findingsList,
  selectedFinding,
  setSelectedFinding,
  selectedRowIds,
  toggleRowSelection,
  toggleSelectAll,
  toggleFindingMutation,
  getImpactBadgeClass,
  getFindingStatusBadgeClass,
  countFindingField,
  getOwaspComplianceEntries,
}: {
  findingsList: DASTFinding[];
  selectedFinding: DASTFinding | null;
  setSelectedFinding: (f: DASTFinding | null) => void;
  selectedRowIds: Set<string>;
  toggleRowSelection: (id: string) => void;
  toggleSelectAll: () => void;
  toggleFindingMutation: { mutate: (args: { finding_id: string; state: "fixed" | "ignored" | "in_progress" | "not_started" }) => void; isPending: boolean };
  getImpactBadgeClass: (impact: string) => string;
  getFindingStatusBadgeClass: (status: string) => string;
  countFindingField: (val: unknown) => number;
  getOwaspComplianceEntries: (val: unknown) => [string, string][];
}) {
  return (
    <ScrollArea className="w-full rounded-md border border-zinc-200 dark:border-zinc-800 min-h-[300px]">
      <div className="min-w-max">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="min-w-[48px] w-12">
                <Checkbox
                  checked={findingsList.length > 0 && selectedRowIds.size === findingsList.length}
                  onCheckedChange={toggleSelectAll}
                  aria-label="Select all rows"
                  className="cursor-pointer"
                />
              </TableHead>
              <TableHead className="min-w-[180px]">Title</TableHead>
              <TableHead className="min-w-[200px]">URL</TableHead>
              <TableHead className="min-w-[200px]">Description</TableHead>
              <TableHead className="min-w-[90px]">Impact</TableHead>
              <TableHead className="min-w-[90px] text-center">Risk score</TableHead>
              <TableHead className="min-w-[100px]">Status</TableHead>
              <TableHead className="min-w-[120px]">Category</TableHead>
              <TableHead className="min-w-[90px]">Confidence</TableHead>
              <TableHead className="min-w-[80px] text-center">OWASP</TableHead>
              <TableHead className="min-w-[90px] text-center">Compliance</TableHead>
              <TableHead className="min-w-[100px] text-right">Actions</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {findingsList.map((f) => {
              const impact = (f.impact ?? "").trim() || "—";
              const desc = (f.description ?? "").trim();
              const descTrunc = desc.length > 80 ? `${desc.slice(0, 80)}…` : desc || "—";
              const statusLabel = (f.status ?? "not_started").replace(/_/g, " ");
              const riskScore = f.risk_score ?? 0;
              const owaspCount = countFindingField(f.owasp_top_10);
              const complianceCount = countFindingField(f.compliance_controls);
              return (
                <TableRow
                  key={f.id}
                  className={`hover:bg-zinc-50 dark:hover:bg-zinc-800/50 ${selectedRowIds.has(f.id) ? "bg-zinc-100 dark:bg-zinc-800/70" : ""}`}
                >
                  <TableCell onClick={(e) => e.stopPropagation()} className="min-w-[48px] w-12">
                    <Checkbox
                      checked={selectedRowIds.has(f.id)}
                      onCheckedChange={() => toggleRowSelection(f.id)}
                      aria-label={`Select finding ${(f.title ?? "").trim() || f.id}`}
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
                  <TableCell className="text-sm text-zinc-600 dark:text-zinc-400 max-w-[200px] truncate" title={f.url ?? undefined}>
                    {f.url ?? "—"}
                  </TableCell>
                  <TableCell className="text-sm text-zinc-600 dark:text-zinc-400 max-w-[200px]" title={desc || undefined}>
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
                        riskScore >= 7 ? "bg-red-100 text-red-800 dark:bg-red-900/40 dark:text-red-200" :
                        riskScore >= 5 ? "bg-orange-100 text-orange-800 dark:bg-orange-900/40 dark:text-orange-200" :
                        riskScore >= 3 ? "bg-amber-100 text-amber-800 dark:bg-amber-900/40 dark:text-amber-200" :
                        "bg-emerald-100 text-emerald-800 dark:bg-emerald-900/40 dark:text-emerald-200"
                      }`}
                    >
                      {riskScore}
                    </span>
                  </TableCell>
                  <TableCell>
                    <span className={`inline-flex px-2.5 py-1 rounded-md text-xs font-medium capitalize ${getFindingStatusBadgeClass(f.status ?? "not_started")}`}>
                      {statusLabel}
                    </span>
                  </TableCell>
                  <TableCell>
                    <span className={`inline-flex px-2.5 py-1 capitalize rounded-md text-xs font-medium ${getCategoryBadgeClass(f.category ?? "")}`}>
                      {(f.category ?? "—").replace(/_/g, " ")}
                    </span>
                  </TableCell>
                  <TableCell>
                    <span className={`inline-flex px-2.5 py-1 rounded-md text-xs font-medium capitalize ${getConfidenceBadgeClass(f.confidence ?? "")}`}>
                      {f.confidence ?? "—"}
                    </span>
                  </TableCell>
                  <TableCell className="text-center">
                    <span className="inline-flex min-w-9 px-2 py-1 rounded-md text-xs font-semibold tabular-nums bg-violet-100 text-violet-800 dark:bg-violet-900/40 dark:text-violet-200">
                      {owaspCount}
                    </span>
                  </TableCell>
                  <TableCell className="text-center">
                    <span className="inline-flex min-w-9 px-2 py-1 rounded-md text-xs font-semibold tabular-nums bg-sky-100 text-sky-800 dark:bg-sky-900/40 dark:text-sky-200">
                      {complianceCount}
                    </span>
                  </TableCell>
                  <TableCell className="text-right">
                    <DropdownMenu>
                      <DropdownMenuTrigger asChild>
                        <Button variant="outline" size="sm" className="cursor-pointer gap-1.5 h-8 shrink-0" aria-label="Finding actions">
                          <Pencil className="h-3.5 w-3.5 opacity-70" />
                          Action
                        </Button>
                      </DropdownMenuTrigger>
                      <DropdownMenuContent align="end">
                        <DropdownMenuItem className="cursor-pointer gap-2" onClick={() => toggleFindingMutation.mutate({ finding_id: f.id, state: "fixed" })} disabled={toggleFindingMutation.isPending}>
                          <CheckCircle className="h-4 w-4" />
                          Mark as Fixed
                        </DropdownMenuItem>
                        <DropdownMenuItem className="cursor-pointer gap-2" onClick={() => toggleFindingMutation.mutate({ finding_id: f.id, state: "ignored" })} disabled={toggleFindingMutation.isPending}>
                          <EyeOff className="h-4 w-4" />
                          Mark as Ignored
                        </DropdownMenuItem>
                        <DropdownMenuItem className="cursor-pointer gap-2" onClick={() => toggleFindingMutation.mutate({ finding_id: f.id, state: "in_progress" })} disabled={toggleFindingMutation.isPending}>
                          <Loader2 className="h-4 w-4" />
                          Mark as In progress
                        </DropdownMenuItem>
                        <DropdownMenuItem className="cursor-pointer gap-2" onClick={() => toggleFindingMutation.mutate({ finding_id: f.id, state: "not_started" })} disabled={toggleFindingMutation.isPending}>
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
  );
}

function FindingDetailDialog({
  finding,
  onClose,
  getImpactBadgeClass,
  getFindingStatusBadgeClass,
  getOwaspComplianceEntries,
}: {
  finding: DASTFinding | null;
  onClose: () => void;
  getImpactBadgeClass: (impact: string) => string;
  getFindingStatusBadgeClass: (status: string) => string;
  getOwaspComplianceEntries: (val: unknown) => [string, string][];
}) {
  if (!finding) return null;
  return (
    <Dialog open={!!finding} onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="sm:max-w-3xl max-h-[90vh] flex flex-col p-0 gap-0 overflow-hidden bg-zinc-900">
        <DialogHeader className="px-6 pt-6 pb-2 shrink-0 border-b border-zinc-200 dark:border-zinc-800">
          <DialogTitle className="pr-8 text-zinc-900 dark:text-white">
            {(finding.title ?? "").trim() || "Finding details"}
          </DialogTitle>
        </DialogHeader>
        <ScrollArea className="h-[70vh] min-h-[200px] w-full px-6 pb-6">
          <div className="space-y-4 pt-4 pr-4 pb-4">
            {(finding.url ?? "").trim() && (
              <div>
                <div className="text-xs font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400 mb-1">URL</div>
                <p className="text-sm font-mono text-zinc-800 dark:text-zinc-200 break-all">{finding.url!.trim()}</p>
              </div>
            )}
            {(finding.description ?? "").trim() && (
              <div>
                <div className="text-xs font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400 mb-1">Description</div>
                <p className="text-sm text-zinc-800 dark:text-zinc-200 whitespace-pre-wrap">{finding.description!.trim()}</p>
              </div>
            )}
            {(finding.suggested_fix ?? "").trim() && (
              <div>
                <div className="text-xs font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400 mb-1">Suggested fix</div>
                <p className="text-sm text-zinc-800 dark:text-zinc-200 whitespace-pre-wrap">{finding.suggested_fix!.trim()}</p>
              </div>
            )}
            <div>
              <div className="text-xs font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400 mb-1">Impact</div>
              <Badge variant="outline" className={getImpactBadgeClass((finding.impact ?? "").trim() || "—")}>
                {(finding.impact ?? "").trim() || "—"}
              </Badge>
            </div>
            <div>
              <div className="text-xs font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400 mb-1">Risk score</div>
              <span className="text-sm font-medium tabular-nums">{finding.risk_score ?? "—"}</span>
            </div>
            <div>
              <div className="text-xs font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400 mb-1">Status</div>
              <span className={`inline-flex px-2.5 py-1 rounded-md text-xs font-medium capitalize ${getFindingStatusBadgeClass(finding.status ?? "not_started")}`}>
                {(finding.status ?? "not_started").replace(/_/g, " ")}
              </span>
            </div>
            {(finding.category ?? "").trim() && (
              <div>
                <div className="text-xs font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400 mb-1">Category</div>
                <span className={`inline-flex px-2.5 py-1 rounded-md text-xs font-medium ${getCategoryBadgeClass(finding.category ?? "")}`}>
                  {(finding.category ?? "").replace(/_/g, " ")}
                </span>
              </div>
            )}
            {(finding.confidence ?? "").trim() && (
              <div>
                <div className="text-xs font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400 mb-1">Confidence</div>
                <span className={`inline-flex px-2.5 py-1 rounded-md text-xs font-medium capitalize ${getConfidenceBadgeClass(finding.confidence ?? "")}`}>
                  {finding.confidence}
                </span>
              </div>
            )}
            {getOwaspComplianceEntries(finding.owasp_top_10).length > 0 && (
              <div>
                <div className="text-xs font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400 mb-1">OWASP Top 10</div>
                <div className="flex flex-wrap gap-1">
                  {getOwaspComplianceEntries(finding.owasp_top_10).map(([, description], i) => (
                    <Badge key={i} variant="secondary" className="text-xs bg-violet-100 dark:bg-violet-900/40 text-violet-800 dark:text-violet-200">
                      {description}
                    </Badge>
                  ))}
                </div>
              </div>
            )}
            {getOwaspComplianceEntries(finding.compliance_controls).length > 0 && (
              <div>
                <div className="text-xs font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400 mb-1">Compliance controls</div>
                <div className="flex flex-wrap gap-1">
                  {getOwaspComplianceEntries(finding.compliance_controls).map(([, description], i) => (
                    <Badge key={i} variant="outline" className="text-xs">
                      {description}
                    </Badge>
                  ))}
                </div>
              </div>
            )}
          </div>
        </ScrollArea>
      </DialogContent>
    </Dialog>
  );
}
