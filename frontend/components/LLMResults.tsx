"use client";

import { useState, useEffect, useMemo } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Checkbox } from "@/components/ui/checkbox";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { ArrowLeft, MessageCircle, Download, RefreshCcw, BarChart3, Ticket, PieChart as PieChartIcon, Activity, Shield, Target, Swords, Table2, Zap, AlertTriangle, Percent, Clock, Pencil, Wrench, Bot, FlaskConical, CheckCircle, EyeOff, Loader2, Circle, BoxIcon } from "lucide-react";
import { ScrollArea, ScrollBar } from "@/components/ui/scroll-area";
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
import { useRouter, useSearchParams, useParams } from "next/navigation";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { COMPLIANCE_KEY_TO_LABEL, OWASP_LLM_KEY_TO_LABEL, OWASP_COLORS, COMPLIANCE_COLORS } from "@/lib/owasp-compliance-labels";

const OWASP_LLM_KEYS = Object.values(OWASP_LLM_KEY_TO_LABEL);
import { getProbeDisplayName } from "@/utils/probe-display-names";
import { updateScan, createTicket, toggleFindingState } from "@/utils/backend_api";
import type { ScanTicketingIntegrationSettings, LLMDashboardData, LLMFinding, LLMScanMetadata } from "@/utils/backend_api";
import { showErrorToast } from "@/utils/error-handler";
import FindingSelectionMenu from "@/components/finding-selection-menu";
import TicketingIntegrationsSettings from "@/components/ticketing-integrations-settings";
import {
  ChartContainer,
  ChartTooltip,
  ChartTooltipContent,
  type ChartConfig,
} from "@/components/ui/chart";
import { RadarChart, Radar, PolarGrid, PolarAngleAxis, RadialBarChart, RadialBar, PieChart, Pie, Cell, Bar, BarChart, XAxis, YAxis, CartesianGrid } from "recharts";

// LLM Benchmark agent output: list of vulnerabilities (FinalLLMBenchmarkingVulnerabilities.vulnerabilities)
// Schema: title, description, impact, owasp_top_10_llm, compliance_controls, suggested_fix
type OwaspOrComplianceItem = Record<string, string>;
type OwaspOrCompliance = Record<string, string> | Array<OwaspOrComplianceItem> | null | undefined;

export interface LLMBenchmarkingVulnerability {
  title?: string | null;
  description?: string | null;
  impact?: string | null;
  owasp_top_10_llm?: OwaspOrCompliance;
  compliance_controls?: OwaspOrCompliance;
  suggested_fix?: string | null;
  cves?: unknown[] | Record<string, unknown> | null;
}

/** Normalized: either array of vulns or { vulnerabilities: array } */
type LLMResultsData =
  | LLMBenchmarkingVulnerability[]
  | { vulnerabilities?: LLMBenchmarkingVulnerability[] };

/** One row in the findings table: from API findings (id) or normalized data (synthetic id) */
export interface LLMDisplayFinding {
  id: string;
  title?: string | null;
  description?: string | null;
  impact?: string | null;
  status?: string | null;
  owasp_top_10_llm?: OwaspOrCompliance;
  compliance_controls?: OwaspOrCompliance;
  suggested_fix?: string | null;
  vulnerability_predictions?: unknown;
}

interface LLMResultsProps {
  data: LLMResultsData | null | undefined;
  dashboard?: LLMDashboardData | null;
  findings?: LLMFinding[] | null;
  scanMetadata?: LLMScanMetadata | null;
  conversationId?: number;
  teamId?: string;
  integrationSettings?: Record<string, unknown> | null;
  onIntegrationSettingsUpdated?: () => void;
  onFindingsUpdated?: () => void;
  onRefresh?: () => void;
  onDownloadReport?: () => void;
  isExporting?: boolean;
}

const RISK_ORDER = ["Critical", "High", "Medium", "Low"] as const;

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

/** Risk score from impact: Critical=10, High=7.5, Medium=5, Low=2.5 */
const RISK_SCORE_FOR_IMPACT: Record<string, number> = {
  critical: 10,
  high: 7.5,
  medium: 5,
  low: 2.5,
};

function getRiskScoreFromImpact(impact: string): number {
  return RISK_SCORE_FOR_IMPACT[(impact || "").toLowerCase()] ?? 2.5;
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

function getRiskScoreBoxClass(score: number): string {
  if (score >= 7.5) return "bg-red-100 text-red-800 dark:bg-red-900/40 dark:text-red-200";
  if (score >= 5) return "bg-orange-100 text-orange-800 dark:bg-orange-900/40 dark:text-orange-200";
  if (score >= 2.5) return "bg-amber-100 text-amber-800 dark:bg-amber-900/40 dark:text-amber-200";
  return "bg-emerald-100 text-emerald-800 dark:bg-emerald-900/40 dark:text-emerald-200";
}

/** Hit rate box: high = attacks succeeded (bad), low = attacks failed (good) */
function getHitRateBoxClass(hitRate: number): string {
  if (hitRate >= 50) return "bg-red-100 text-red-800 dark:bg-red-900/40 dark:text-red-200";
  if (hitRate >= 25) return "bg-amber-100 text-amber-800 dark:bg-amber-900/40 dark:text-amber-200";
  return "bg-emerald-100 text-emerald-800 dark:bg-emerald-900/40 dark:text-emerald-200";
}

function normalizeVulnerabilities(data: LLMResultsData | null | undefined): LLMBenchmarkingVulnerability[] {
  if (data == null) return [];
  if (Array.isArray(data)) return data;
  if (data && typeof data === "object" && Array.isArray((data as { vulnerabilities?: LLMBenchmarkingVulnerability[] }).vulnerabilities)) {
    return (data as { vulnerabilities: LLMBenchmarkingVulnerability[] }).vulnerabilities;
  }
  return [];
}

function deriveLLMDashboard(vulnerabilities: LLMBenchmarkingVulnerability[]): LLMDashboardData {
  // Ensure all OWASP LLM categories are present as keys with default 0 (matches backend)
  const owasp_top_10_llm_metrics: Record<string, number> = Object.fromEntries(OWASP_LLM_KEYS.map((k) => [k, 0]));
  const compliance_controls_metrics: Record<string, number> = {};
  const risk_metrics: { Low: number; Medium: number; High: number; Critical: number } = { Low: 0, Medium: 0, High: 0, Critical: 0 };
  for (const v of vulnerabilities) {
    const owasp = v.owasp_top_10_llm;
    if (owasp && typeof owasp === "object" && !Array.isArray(owasp)) {
      for (const key of Object.keys(owasp)) {
        owasp_top_10_llm_metrics[key] = (owasp_top_10_llm_metrics[key] ?? 0) + 1;
      }
    }
    const comp = v.compliance_controls;
    if (comp && typeof comp === "object" && !Array.isArray(comp)) {
      for (const key of Object.keys(comp)) {
        compliance_controls_metrics[key] = (compliance_controls_metrics[key] ?? 0) + 1;
      }
    }
    const impactRaw = (v.impact ?? "").trim();
    const impact = impactRaw.charAt(0).toUpperCase() + impactRaw.slice(1).toLowerCase();
    if (impact && ["Low", "Medium", "High", "Critical"].includes(impact)) {
      risk_metrics[impact as keyof typeof risk_metrics] += 1;
    }
  }
  return { owasp_top_10_llm_metrics, compliance_controls_metrics, risk_metrics };
}

function buildDisplayList(findings: LLMFinding[] | null | undefined, fromData: LLMBenchmarkingVulnerability[]): LLMDisplayFinding[] {
  if (findings && findings.length > 0) {
    return findings.map((f) => ({
      id: f.id,
      title: f.title,
      description: f.description,
      impact: f.impact,
      status: f.status ?? "not_started",
      owasp_top_10_llm: f.owasp_top_10_llm as OwaspOrCompliance,
      compliance_controls: f.compliance_controls as OwaspOrCompliance,
      suggested_fix: f.suggested_fix,
      vulnerability_predictions: f.vulnerability_predictions,
    }));
  }
  return fromData.map((v, i) => ({
    id: `vuln-${i}`,
    title: v.title,
    description: v.description,
    impact: v.impact,
    status: "not_started",
    owasp_top_10_llm: v.owasp_top_10_llm,
    compliance_controls: v.compliance_controls,
    suggested_fix: v.suggested_fix,
    vulnerability_predictions: (v as LLMDisplayFinding).vulnerability_predictions,
  }));
}

export default function LLMResults({ data, dashboard, findings, scanMetadata, conversationId, teamId: teamIdProp, integrationSettings, onIntegrationSettingsUpdated, onFindingsUpdated, onRefresh, onDownloadReport, isExporting }: LLMResultsProps) {
  const router = useRouter();
  const params = useParams();
  const searchParams = useSearchParams();
  const queryClient = useQueryClient();
  const origin = searchParams.get("origin");
  const teamId = teamIdProp ?? (params?.team_id as string | undefined);

  const vulnerabilities = normalizeVulnerabilities(data);
  const displayList = useMemo<LLMDisplayFinding[]>(
    () => buildDisplayList(findings ?? null, vulnerabilities),
    [findings, vulnerabilities]
  );
  const dashboardData = useMemo<LLMDashboardData | null>(() => {
    if (dashboard && (Object.keys(dashboard.owasp_top_10_llm_metrics ?? {}).length > 0 || Object.keys(dashboard.compliance_controls_metrics ?? {}).length > 0 || Object.values(dashboard.risk_metrics ?? {}).some((n) => n > 0) || dashboard.card_data != null || dashboard.security_posture != null || (dashboard.vulnerability_breakdown && Object.values(dashboard.vulnerability_breakdown).some((n) => n > 0)))) {
      return dashboard;
    }
    if (displayList.length === 0) return null;
    const vulnLike = displayList.map((d) => ({ title: d.title, description: d.description, impact: d.impact, owasp_top_10_llm: d.owasp_top_10_llm, compliance_controls: d.compliance_controls, suggested_fix: d.suggested_fix }));
    return deriveLLMDashboard(vulnLike);
  }, [dashboard, displayList]);
  const [detailDialogOpen, setDetailDialogOpen] = useState(false);
  const [selectedVuln, setSelectedVuln] = useState<LLMDisplayFinding | null>(null);
  const [activeTab, setActiveTab] = useState<"results" | "ticketing">("results");
  const [selectedRows, setSelectedRows] = useState<Set<string>>(new Set());
  const [jiraProjectId, setJiraProjectId] = useState("");

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
        type: "llm",
        scan_id: conversationId!,
        data: payload,
      }),
    onSuccess: () => {
      onIntegrationSettingsUpdated?.();
      const tid = parseInt(teamId ?? "0", 10);
      if (conversationId != null && tid > 0) {
        queryClient.invalidateQueries({ queryKey: ["llm-conversation-data", tid, conversationId] });
      }
      toast.success("Ticketing settings saved");
    },
    onError: (err) => {
      showErrorToast(err, "Failed to save ticketing settings");
    },
  });

  const hasTicketingTab = Boolean(teamId && conversationId != null && onIntegrationSettingsUpdated != null);

  const toggleFindingMutation = useMutation({
    mutationFn: ({ finding_id, state }: { finding_id: string; state: "fixed" | "ignored" | "in_progress" | "not_started" }) => {
      const tid = parseInt(teamId ?? "0", 10);
      if (!conversationId || Number.isNaN(tid)) throw new Error("Missing team or scan");
      return toggleFindingState({ team_id: tid, type: "llm", scan_id: conversationId, finding_id, state });
    },
    onSuccess: () => {
      onFindingsUpdated?.();
      const tid = parseInt(teamId ?? "0", 10);
      if (conversationId != null && tid > 0) {
        queryClient.invalidateQueries({ queryKey: ["llm-conversation-data", tid, conversationId] });
      }
      toast.success("Finding status updated");
    },
    onError: (err) => {
      showErrorToast(err, "Failed to update finding status");
    },
  });

  const toggleRowSelection = (id: string) => {
    setSelectedRows((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const toggleSelectAll = () => {
    if (selectedRows.size === displayList.length) {
      setSelectedRows(new Set());
    } else {
      setSelectedRows(new Set(displayList.map((r) => r.id)));
    }
  };

  const createJiraTicketsMutation = useMutation({
    mutationFn: async () => {
      const tid = parseInt(teamId ?? "0", 10);
      if (!conversationId || Number.isNaN(tid)) throw new Error("Missing team or scan");
      const selectedFindings = displayList.filter((r) => selectedRows.has(r.id));

      const impactCounts: Record<string, number> = {};
      for (const vuln of selectedFindings) {
        const impact = (vuln.impact ?? "Unknown").trim() || "Unknown";
        impactCounts[impact] = (impactCounts[impact] ?? 0) + 1;
      }
      let summary = Object.entries(impactCounts)
        .sort(([a], [b]) => RISK_ORDER.indexOf(a as (typeof RISK_ORDER)[number]) - RISK_ORDER.indexOf(b as (typeof RISK_ORDER)[number]))
        .map(([impact, count]) => `${count} ${impact}`)
        .join(", ") || `${selectedFindings.length} finding(s)`;
      summary = summary + " - Vulnerabilities found in LLM benchmark scan";

      const descSections = selectedFindings.map((vuln, idx) => {
        const parts: string[] = [`--- Finding ${idx + 1} ---`];
        parts.push(`Title: ${(vuln.title ?? "Untitled finding").trim() || "Untitled finding"}`);
        if ((vuln.description ?? "").trim()) parts.push(`Description: ${vuln.description!.trim()}`);
        if ((vuln.impact ?? "").trim()) parts.push(`Impact: ${vuln.impact!.trim()}`);
        if ((vuln.suggested_fix ?? "").trim()) parts.push(`Suggested fix: ${vuln.suggested_fix!.trim()}`);
        return parts.join("\n");
      });
      const description = descSections.join("\n\n");

      await createTicket(tid, "llm", conversationId, {
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
        toast.success(`Jira ticket(s) created for ${selectedRows.size} finding(s)`, { id: context.toastId });
      } else {
        toast.success(`Jira ticket(s) created for ${selectedRows.size} finding(s)`);
      }
      setSelectedRows(new Set());
    },
    onError: (err, _variables, context) => {
      if (context?.toastId != null) toast.dismiss(context.toastId);
      showErrorToast(err, "Failed to create Jira ticket(s)");
    },
  });

  const handleCreateJiraTicket = () => createJiraTicketsMutation.mutate();

  const openVulnDetail = (row: LLMDisplayFinding) => {
    setSelectedVuln(row);
    setDetailDialogOpen(true);
  };

  if (displayList.length === 0) {
    return (
      <div className="container mx-auto p-6 space-y-6">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-4">
            {conversationId && (
              <Button
                variant="outline"
                size="icon"
                onClick={() => {
                  const backRoute = origin === "list"
                    ? (teamId ? `/${teamId}/llm` : "/home/llm")
                    : (teamId ? `/${teamId}/llm/${conversationId}` : `/home/llm/${conversationId}`);
                  router.push(backRoute);
                }}
                className="cursor-pointer"
              >
                <ArrowLeft className="h-4 w-4" />
              </Button>
            )}
            <h1 className="text-3xl font-bold text-zinc-900 dark:text-white">LLM Benchmark Scan Results</h1>
          </div>
          {teamId && conversationId != null && (
            <Button
              variant="default"
              className="cursor-pointer bg-blue-600 hover:bg-blue-700 text-white"
              onClick={() => router.push(`/${teamId}/llm/${conversationId}`)}
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
    <div className="container mx-auto p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          {conversationId && (
            <Button
              variant="outline"
              size="icon"
              onClick={() => {
                const backRoute = origin === "list"
                  ? (teamId ? `/${teamId}/llm` : "/home/llm")
                  : (teamId ? `/${teamId}/llm/${conversationId}` : `/home/llm/${conversationId}`);
                router.push(backRoute);
              }}
              className="cursor-pointer"
            >
              <ArrowLeft className="h-4 w-4" />
            </Button>
          )}
          <div className="space-y-2">
            <div className="flex items-center gap-3">
              <div>
                <h1 className="text-3xl font-bold text-zinc-900 dark:text-white">LLM Benchmark Scan Results</h1>
                
              </div>
            </div>
            {scanMetadata && (scanMetadata.model_type != null || (Array.isArray(scanMetadata.probes) && scanMetadata.probes.length > 0)) && (
              <div className="flex flex-wrap gap-2">
                {scanMetadata.model_type != null && (
                  <span className="inline-flex capitalize items-center gap-1.5 rounded-md bg-violet-500/15 dark:bg-violet-500/20 px-2.5 py-1 text-xs font-medium text-violet-700 dark:text-violet-300">
                    <BoxIcon className="h-3.5 w-3.5" />
                    {scanMetadata.model_type}
                  </span>
                )}
                {Array.isArray(scanMetadata.probes) && scanMetadata.probes.length > 0 && (
                  <span className="inline-flex items-center gap-1.5 rounded-md bg-emerald-500/15 dark:bg-emerald-500/20 px-2.5 py-1 text-xs font-medium text-emerald-700 dark:text-emerald-300">
                    <Activity className="h-3.5 w-3.5" />
                    {scanMetadata.probes.length} Attacks 
                  </span>
                )}
              </div>
            )}
          </div>
        </div>
        <div className="flex items-center gap-2">
          {onRefresh && (
            <Button variant="outline" size="icon" onClick={onRefresh} className="cursor-pointer" title="Refresh">
              <RefreshCcw className="h-4 w-4" />
            </Button>
          )}
          {onDownloadReport && teamId && conversationId != null && (
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
          {teamId && conversationId != null && (
            <Button
              variant="default"
              className="cursor-pointer bg-blue-600 hover:bg-blue-700 text-white"
              onClick={() => router.push(`/${teamId}/llm/${conversationId}`)}
            >
              <MessageCircle className="h-4 w-4 mr-2" />
              Chat with the Results
            </Button>
          )}
        </div>
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
          inputId="llm-jira-project-id"
        />
      ) : (
        <>
      {/* Card row: attacks_run, total_vulnerabilities_found, pass_rate, risk_score, scan_duration, policy_violations */}
      {dashboardData?.card_data != null && (
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3 mb-6">
          <Card className="border-zinc-200 dark:border-zinc-800 min-w-0 overflow-hidden py-4 gap-2">
            <CardHeader className="flex flex-row items-center justify-between space-y-0 p-4 pb-2">
              <CardTitle className="text-sm font-medium text-zinc-600 dark:text-zinc-400 truncate">Attacks run</CardTitle>
              <Zap className="h-4 w-4 text-amber-500 shrink-0" />
            </CardHeader>
            <CardContent className="px-4 pb-4 pt-0">
              <p className="text-xl font-semibold tabular-nums truncate">{dashboardData.card_data.attacks_run ?? "—"}</p>
            </CardContent>
          </Card>
          <Card className="border-zinc-200 dark:border-zinc-800 min-w-0 overflow-hidden py-4 gap-2">
            <CardHeader className="flex flex-row items-center justify-between space-y-0 p-4 pb-2">
              <CardTitle className="text-sm font-medium text-zinc-600 dark:text-zinc-400 truncate">Vulnerabilities found</CardTitle>
              <AlertTriangle className="h-4 w-4 text-red-500 shrink-0" />
            </CardHeader>
            <CardContent className="px-4 pb-4 pt-0">
              <p className="text-xl font-semibold tabular-nums truncate">{dashboardData.card_data.total_vulnerabilities_found ?? "—"}</p>
            </CardContent>
          </Card>
          <Card className="border-zinc-200 dark:border-zinc-800 min-w-0 overflow-hidden py-4 gap-2">
            <CardHeader className="flex flex-row items-center justify-between space-y-0 p-4 pb-2">
              <CardTitle className="text-sm font-medium text-zinc-600 dark:text-zinc-400 truncate">Pass rate</CardTitle>
              <Percent className="h-4 w-4 text-green-500 shrink-0" />
            </CardHeader>
            <CardContent className="px-4 pb-4 pt-0">
              <p className="text-xl font-semibold tabular-nums truncate">{dashboardData.card_data.pass_rate != null ? `${dashboardData.card_data.pass_rate}%` : "—"}</p>
            </CardContent>
          </Card>
          <Card className="border-zinc-200 dark:border-zinc-800 min-w-0 overflow-hidden py-4 gap-2">
            <CardHeader className="flex flex-row items-center justify-between space-y-0 p-4 pb-2">
              <CardTitle className="text-sm font-medium text-zinc-600 dark:text-zinc-400 truncate">Risk score</CardTitle>
              <Activity className="h-4 w-4 text-zinc-500 shrink-0" />
            </CardHeader>
            <CardContent className="px-4 pb-4 pt-0">
              <p className="text-xl font-semibold tabular-nums truncate">{dashboardData.card_data.risk_score ?? "—"}</p>
            </CardContent>
          </Card>
          <Card className="border-zinc-200 dark:border-zinc-800 min-w-0 overflow-hidden py-4 gap-2">
            <CardHeader className="flex flex-row items-center justify-between space-y-0 p-4 pb-2">
              <CardTitle className="text-sm font-medium text-zinc-600 dark:text-zinc-400 truncate">Scan duration</CardTitle>
              <Clock className="h-4 w-4 text-blue-500 shrink-0" />
            </CardHeader>
            <CardContent className="px-4 pb-4 pt-0">
              <p className="text-xl font-semibold tabular-nums truncate">
                {dashboardData.card_data.scan_duration != null
                  ? `${Number(dashboardData.card_data.scan_duration).toFixed(2)}s`
                  : "—"}
              </p>
            </CardContent>
          </Card>
          <Card className="border-zinc-200 dark:border-zinc-800 min-w-0 overflow-hidden py-4 gap-2">
            <CardHeader className="flex flex-row items-center justify-between space-y-0 p-4 pb-2">
              <CardTitle className="text-sm font-medium text-zinc-600 dark:text-zinc-400 truncate">Policy violations</CardTitle>
              <Shield className="h-4 w-4 text-amber-500 shrink-0" />
            </CardHeader>
            <CardContent className="px-4 pb-4 pt-0">
              <p className="text-xl font-semibold tabular-nums truncate">{dashboardData.card_data.policy_violations ?? "—"}</p>
            </CardContent>
          </Card>
        </div>
      )}

      {/* Dashboard charts row — 3 cards per row: Security Posture, OWASP, Risk */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 mb-6">
        {/* Security Posture radar — when dashboard.security_posture exists */}
        {dashboardData?.security_posture != null && (
          <Card className="border-zinc-200 dark:border-zinc-800 py-4 gap-2">
            <CardHeader className="p-4 pb-2">
              <CardTitle className="text-base flex items-center gap-2">
                <Target className="w-4 h-4" />
                Security Posture
              </CardTitle>
              <CardDescription>Model resistance scores</CardDescription>
            </CardHeader>
            <CardContent className="px-4">
              {(() => {
                const sp = dashboardData.security_posture!;
                const labels: Record<string, string> = {
                  jailbreak_resistance_score: "Jailbreak resistance",
                  injection_resistance_score: "Injection resistance",
                  hallucination_resistance_score: "Hallucination resistance",
                  bias_resistance_score: "Bias resistance",
                  content_safety_score: "Content safety",
                  data_privacy_score: "Data privacy",
                };
                const radarData = Object.entries(sp).map(([key, value]) => ({
                  subject: labels[key] ?? key,
                  count: Number(value) ?? 0,
                  fullMark: 10,
                }));
                const radarConfig: ChartConfig = { subject: { label: "Category" }, count: { label: "Score", color: "hsl(217 91% 60%)" } };
                return (
                  <ChartContainer config={radarConfig} className="mx-auto aspect-square max-h-[240px]">
                    <RadarChart data={radarData} margin={{ top: 8, right: 20, bottom: 8, left: 20 }}>
                      <PolarAngleAxis dataKey="subject" tick={{ fontSize: 9 }} />
                      <PolarGrid />
                      <Radar dataKey="count" fill="hsl(217 91% 60%)" fillOpacity={0.6} stroke="hsl(217 91% 60%)" />
                      <ChartTooltip cursor={false} content={<ChartTooltipContent nameKey="subject" formatter={(v) => [v, "Score"]} />} />
                    </RadarChart>
                  </ChartContainer>
                );
              })()}
            </CardContent>
          </Card>
        )}
        {/* Radar: OWASP Top 10 LLM */}
        <Card className="border-zinc-200 dark:border-zinc-800 py-4 gap-2">
          <CardHeader className="p-4 pb-2">
            <CardTitle className="text-base flex items-center gap-2">
              <Shield className="w-4 h-4" />
              OWASP Top 10 for LLM
            </CardTitle>
            <CardDescription>Findings by LLM category</CardDescription>
          </CardHeader>
          <CardContent className="px-4">
            {dashboardData && Object.keys(dashboardData.owasp_top_10_llm_metrics ?? {}).length > 0 ? (
              (() => {
                const owasp = dashboardData.owasp_top_10_llm_metrics!;
                const radarData = Object.entries(owasp)
                  .map(([key, count]) => ({ subject: OWASP_LLM_KEY_TO_LABEL[key] ?? key, count, fullMark: Math.max(...Object.values(owasp), 1) }))
                  .sort((a, b) => b.count - a.count)
                  .slice(0, 10);
                const radarConfig: ChartConfig = { subject: { label: "Category" }, count: { label: "Count", color: "hsl(262 83% 58%)" } };
                return (
                  <ChartContainer config={radarConfig} className="mx-auto aspect-square max-h-[240px]">
                    <RadarChart data={radarData} margin={{ top: 8, right: 20, bottom: 8, left: 20 }}>
                      <PolarAngleAxis dataKey="subject" tick={{ fontSize: 9 }} />
                      <PolarGrid />
                      <Radar dataKey="count" fill="hsl(262 83% 58%)" fillOpacity={0.6} stroke="hsl(262 83% 58%)" />
                      <ChartTooltip cursor={false} content={<ChartTooltipContent nameKey="subject" formatter={(v) => [v, "Count"]} />} />
                    </RadarChart>
                  </ChartContainer>
                );
              })()
            ) : (
              <div className="flex items-center justify-center aspect-square max-h-[240px] text-sm text-zinc-500 dark:text-zinc-400">No data</div>
            )}
          </CardContent>
        </Card>
        {/* Radial: Risk (Impact) — always show 4 segments, use 0 when no data */}
        <Card className="border-zinc-200 dark:border-zinc-800 py-4 gap-2">
          <CardHeader className="p-4 pb-2">
            <CardTitle className="text-base flex items-center gap-2">
              <Activity className="w-4 h-4" />
              Risk (Impact)
            </CardTitle>
            <CardDescription>By severity</CardDescription>
          </CardHeader>
          <CardContent className="px-4">
            {(() => {
              const breakdown = dashboardData?.vulnerability_breakdown;
              const riskMetrics = dashboardData?.risk_metrics;
              const risk = breakdown != null
                ? { Critical: breakdown.critical ?? 0, High: breakdown.high ?? 0, Medium: breakdown.medium ?? 0, Low: breakdown.low ?? 0 }
                : (riskMetrics ?? {});
              const order = ["Critical", "High", "Medium", "Low"] as const;
              const total = order.reduce((s, k) => s + (risk[k] ?? 0), 0);
              const radialData = order.map((key) => ({
                name: key,
                count: total > 0 ? ((risk[key] ?? 0) / total) * 100 : 0,
                actualCount: risk[key] ?? 0,
                fill: key === "Critical" ? "hsl(0 84% 60%)" : key === "High" ? "hsl(25 95% 53%)" : key === "Medium" ? "hsl(48 96% 53%)" : "hsl(142 71% 45%)",
              }));
              const radialConfig: ChartConfig = {
                count: { label: "Share" },
                Critical: { label: "Critical", color: "hsl(0 84% 60%)" },
                High: { label: "High", color: "hsl(25 95% 53%)" },
                Medium: { label: "Medium", color: "hsl(48 96% 53%)" },
                Low: { label: "Low", color: "hsl(142 71% 45%)" },
              };
              return (
                <ChartContainer config={radialConfig} className="mx-auto aspect-square max-h-[240px]">
                  <RadialBarChart data={radialData} innerRadius={30} outerRadius={90} startAngle={90} endAngle={-270}>
                    <ChartTooltip cursor={false} content={<ChartTooltipContent nameKey="name" formatter={(_, __, ___, ____, payload) => [(payload as { actualCount?: number })?.actualCount ?? 0, "Count"]} />} />
                    <RadialBar dataKey="count" background fill={(entry: { fill?: string }) => entry?.fill ?? "hsl(0 0% 50%)"} />
                  </RadialBarChart>
                </ChartContainer>
              );
            })()}
          </CardContent>
        </Card>
      </div>

      {/* Row A: Compliance + MITRE Atlas only */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-6">
        {/* Compliance controls */}
        <Card className="border-zinc-200 dark:border-zinc-800 py-4 gap-2">
          <CardHeader className="p-4 pb-2">
            <CardTitle className="text-base flex items-center gap-2">
              <PieChartIcon className="w-4 h-4" />
              Compliance controls
            </CardTitle>
            <CardDescription>Top compliance categories</CardDescription>
          </CardHeader>
          <CardContent className="px-4">
            {dashboardData && Object.keys(dashboardData.compliance_controls_metrics ?? {}).length > 0 ? (
              (() => {
                const comp = dashboardData.compliance_controls_metrics!;
                const total = Object.values(comp).reduce((s, n) => s + n, 0);
                if (total === 0) return <div className="flex items-center justify-center aspect-square max-h-[240px] text-sm text-zinc-500 dark:text-zinc-400">No data</div>;
                const colors = ["hsl(217 91% 60%)", "hsl(142 71% 45%)", "hsl(48 96% 53%)", "hsl(25 95% 53%)", "hsl(262 83% 58%)", "hsl(0 84% 60%)"];
                const pieData = Object.entries(comp)
                  .sort(([, a], [, b]) => b - a)
                  .slice(0, 8)
                  .map(([key, value], i) => ({
                    name: COMPLIANCE_KEY_TO_LABEL[key] ?? key,
                    value,
                    fill: colors[i % colors.length],
                  }));
                const pieConfig: ChartConfig = { value: { label: "Findings" }, ...Object.fromEntries(pieData.map((d) => [d.name, { label: d.name, color: d.fill }])) };
                return (
                  <ChartContainer config={pieConfig} className="mx-auto aspect-square max-h-[240px]">
                    <PieChart>
                      <ChartTooltip cursor={false} content={<ChartTooltipContent nameKey="name" />} />
                      <Pie data={pieData} dataKey="value" nameKey="name" cx="50%" cy="50%" innerRadius={40} outerRadius={80}>
                        {pieData.map((entry) => (
                          <Cell key={entry.name} fill={entry.fill} />
                        ))}
                      </Pie>
                    </PieChart>
                  </ChartContainer>
                );
              })()
            ) : (
              <div className="flex items-center justify-center aspect-square max-h-[240px] text-sm text-zinc-500 dark:text-zinc-400">No data</div>
            )}
          </CardContent>
        </Card>
          {dashboardData?.mitre_atlas_metrics != null && (
            <Card className="border-zinc-200 dark:border-zinc-800 py-4 gap-2">
              <CardHeader className="p-4 pb-2">
                <CardTitle className="text-base flex items-center gap-2">
                  <Zap className="w-4 h-4" />
                  MITRE Atlas Tactics
                </CardTitle>
                <CardDescription>Count by tactic</CardDescription>
              </CardHeader>
              <CardContent className="px-4">
                {(() => {
                  const mitre = dashboardData.mitre_atlas_metrics!;
                  const data = Object.entries(mitre).map(([tactic, count]) => ({
                    name: tactic.charAt(0).toUpperCase() + tactic.slice(1).replace(/_/g, " "),
                    count,
                  })).filter((d) => d.count > 0).sort((a, b) => b.count - a.count);
                  if (data.length === 0) return <div className="flex items-center justify-center min-h-[200px] text-sm text-zinc-500 dark:text-zinc-400">No data</div>;
                  const barConfig: ChartConfig = { name: { label: "Tactic" }, count: { label: "Count", color: "hsl(262 83% 58%)" } };
                  return (
                    <ChartContainer config={barConfig} className="h-[280px] w-full">
                      <BarChart data={data} layout="vertical" margin={{ left: 8, right: 8 }}>
                        <CartesianGrid strokeDasharray="3 3" className="stroke-zinc-200 dark:stroke-zinc-700" />
                        <XAxis type="number" />
                        <YAxis type="category" dataKey="name" width={120} tick={{ fontSize: 10 }} />
                        <ChartTooltip content={<ChartTooltipContent />} />
                        <Bar dataKey="count" fill="hsl(262 83% 58%)" radius={[0, 2, 2, 0]} />
                      </BarChart>
                    </ChartContainer>
                  );
                })()}
              </CardContent>
            </Card>
          )}
      </div>

      {/* Row B: Adversarial Attack Outcomes — full-width own row */}
      {dashboardData?.adversarial_attack_outcomes != null && (
        <div className="mb-6">
          <Card className="border-zinc-200 dark:border-zinc-800 w-full py-4 gap-2">
            <CardHeader className="p-4 pb-2">
              <CardTitle className="text-base flex items-center gap-2">
                <Swords className="w-4 h-4" />
                Adversarial Attack Outcomes
              </CardTitle>
              <CardDescription>Passed vs total per Attack</CardDescription>
            </CardHeader>
            <CardContent className="px-4">
              {(() => {
                const outcomes = dashboardData.adversarial_attack_outcomes!;
                const data = Object.entries(outcomes).map(([probe, { passed, total }]) => ({
                  attack: getProbeDisplayName(probe),
                  passed,
                  failed: total - passed,
                  total,
                })).filter((d) => d.total > 0);
                if (data.length === 0) return <div className="flex items-center justify-center min-h-[200px] text-sm text-zinc-500 dark:text-zinc-400">No data</div>;
                const barConfig: ChartConfig = { attack: { label: "Attack" }, passed: { label: "Passed", color: "hsl(142 71% 45%)" }, failed: { label: "Failed", color: "hsl(0 84% 60%)" } };
                return (
                  <ChartContainer config={barConfig} className="h-[280px] w-full">
                    <BarChart data={data} layout="vertical" margin={{ left: 8, right: 8 }}>
                      <CartesianGrid strokeDasharray="3 3" className="stroke-zinc-200 dark:stroke-zinc-700" />
                      <XAxis type="number" />
                      <YAxis type="category" dataKey="attack" width={220} tick={{ fontSize: 9 }} />
                      <ChartTooltip content={<ChartTooltipContent />} />
                      <Bar dataKey="passed" stackId="a" fill="hsl(142 71% 45%)" name="Passed" radius={[0, 0, 0, 0]} />
                      <Bar dataKey="failed" stackId="a" fill="hsl(0 84% 60%)" name="Failed" radius={[0, 2, 2, 0]} />
                    </BarChart>
                  </ChartContainer>
                );
              })()}
            </CardContent>
          </Card>
        </div>
      )}

      {/* Attack Details table — when dashboard.attack_details exists */}
      {dashboardData?.attack_details != null && Object.keys(dashboardData.attack_details).length > 0 && (
        <Card className="border-zinc-200 dark:border-zinc-800 mb-6 py-4 gap-2">
          <CardHeader className="p-4 pb-2">
            <CardTitle className="text-base flex items-center gap-2">
              <Table2 className="w-4 h-4 text-blue-500" />
              Attack Details
            </CardTitle>
            <CardDescription>Per-attack passed, total, hit rate, and description</CardDescription>
          </CardHeader>
          <CardContent className="px-4">
            <ScrollArea className="w-full rounded-md border border-zinc-200 dark:border-zinc-800">
              <div className="min-w-max">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead className="min-w-[280px] flex flex-row items-center gap-2"><Wrench className="w-4 h-4 text-blue-500" /> Attack</TableHead>
                      <TableHead className="min-w-[80px] text-right">Passed</TableHead>
                      <TableHead className="min-w-[80px] text-right">Total</TableHead>
                      <TableHead className="min-w-[90px] text-right">Hit rate %</TableHead>
                      <TableHead className="min-w-[400px]">Description</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {Object.entries(dashboardData.attack_details).map(([probeName, row]) => {
                      const hitRate = typeof row.hit_rate === "number" ? row.hit_rate : parseFloat(String(row.hit_rate)) || 0;
                      return (
                        <TableRow key={probeName}>
                          <TableCell>
                            <span className="inline-flex items-center rounded-md bg-violet-100 px-2.5 py-1 text-xs font-medium text-violet-800 dark:bg-violet-900/40 dark:text-violet-200">
                              {getProbeDisplayName(probeName)}
                            </span>
                          </TableCell>
                          <TableCell className="text-right">
                            <span className="inline-flex justify-center rounded-md bg-emerald-100 px-2.5 py-1 text-xs font-semibold tabular-nums text-emerald-800 dark:bg-emerald-900/40 dark:text-emerald-200">
                              {row.passed}
                            </span>
                          </TableCell>
                          <TableCell className="text-right">
                            <span className="inline-flex justify-center rounded-md bg-sky-100 px-2.5 py-1 text-xs font-semibold tabular-nums text-sky-800 dark:bg-sky-900/40 dark:text-sky-200">
                              {row.total}
                            </span>
                          </TableCell>
                          <TableCell className="text-right">
                            <span className={`inline-flex justify-center rounded-md px-2.5 py-1 text-xs font-semibold tabular-nums ${getHitRateBoxClass(hitRate)}`}>
                              {row.hit_rate}%
                            </span>
                          </TableCell>
                          <TableCell>
                            <span className="inline-flex rounded-md bg-zinc-100 px-2.5 py-1 text-sm text-zinc-700 dark:bg-zinc-800/60 dark:text-zinc-300">
                              {row.description || "—"}
                            </span>
                          </TableCell>
                        </TableRow>
                      );
                    })}
                  </TableBody>
                </Table>
              </div>
              <ScrollBar orientation="horizontal" />
            </ScrollArea>
          </CardContent>
        </Card>
      )}

      <Card>
        <CardHeader>
          <CardTitle>Findings</CardTitle>
          <CardDescription>
            {displayList.length} vulnerability findings. Click a title to view details. Select rows to create Jira tickets.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <FindingSelectionMenu
            selectedCount={selectedRows.size}
            onClearSelection={() => setSelectedRows(new Set())}
            jiraOnClickHandler={handleCreateJiraTicket}
            ticketType="jira"
            isJiraCreating={createJiraTicketsMutation.isPending}
          />
          <ScrollArea className="h-[500px] w-full rounded-md border border-zinc-200 dark:border-zinc-800">
            <div className="min-w-max">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="min-w-[48px] w-12">
                      <Checkbox
                        checked={displayList.length > 0 && selectedRows.size === displayList.length}
                        onCheckedChange={toggleSelectAll}
                        aria-label="Select all rows"
                        className="cursor-pointer"
                      />
                    </TableHead>
                    <TableHead className="min-w-[180px]">Title</TableHead>
                    <TableHead className="min-w-[200px]">Description</TableHead>
                    <TableHead className="min-w-[90px]">Impact</TableHead>
                    <TableHead className="min-w-[90px] text-center">Risk score</TableHead>
                    <TableHead className="min-w-[100px]">Status</TableHead>
                    <TableHead className="min-w-[90px] text-center">OWASP count</TableHead>
                    <TableHead className="min-w-[100px] text-center">Compliance count</TableHead>
                    <TableHead className="min-w-[120px] text-right">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {findings?.map((row) => {
                    const vTitle = (row.title ?? "Untitled finding").trim() || "Untitled finding";
                    const impact = (row.impact ?? "").trim() || "—";
                    const desc = (row.description ?? "").trim();
                    const descTrunc = desc.length > 80 ? `${desc.slice(0, 80)}…` : desc || "—";
                    const owaspLlmCount = getOwaspComplianceCount(row.owasp_top_10_llm as OwaspOrCompliance);
                    const complianceCount = getOwaspComplianceCount(row.compliance_controls as OwaspOrCompliance);
                    const riskScore = getRiskScoreFromImpact(impact);
                    return (
                      <TableRow
                        key={row.id}
                        className={`hover:bg-zinc-50 dark:hover:bg-zinc-800/50 ${selectedRows.has(row.id) ? "bg-zinc-100 dark:bg-zinc-800/70" : ""}`}
                      >
                        <TableCell onClick={(e) => e.stopPropagation()} className="min-w-[48px] w-12">
                          <Checkbox
                            checked={selectedRows.has(row.id)}
                            onCheckedChange={() => toggleRowSelection(row.id)}
                            aria-label={`Select row ${row.id}`}
                            className="cursor-pointer"
                          />
                        </TableCell>
                        <TableCell className="font-medium">
                          <button
                            type="button"
                            onClick={() => openVulnDetail(row)}
                            className="text-left text-blue-600 hover:text-blue-700 dark:text-blue-400 dark:hover:text-blue-300 hover:underline cursor-pointer font-medium"
                          >
                            {vTitle}
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
                            className={`inline-flex items-center justify-center min-w-9 px-2 py-1 rounded-md text-xs font-semibold tabular-nums ${getRiskScoreBoxClass(riskScore)}`}
                            title="Risk score (derived from impact)"
                          >
                            {riskScore}
                          </span>
                        </TableCell>
                        <TableCell>
                          <span
                            className={`inline-flex items-center justify-center px-2.5 py-1 rounded-md text-xs font-medium capitalize ${getFindingStatusBadgeClass(row.status ?? "not_started")}`}
                            title="Finding status"
                          >
                            {(row.status ?? "not_started").replace(/_/g, " ")}
                          </span>
                        </TableCell>
                        <TableCell className="text-center">
                          <span
                            className="inline-flex items-center justify-center min-w-9 px-2 py-1 rounded-md text-xs font-semibold tabular-nums bg-violet-100 text-violet-800 dark:bg-violet-900/40 dark:text-violet-200"
                            title="OWASP Top 10 LLM count"
                          >
                            {owaspLlmCount}
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
                        <TableCell className="text-right" onClick={(e) => e.stopPropagation()}>
                          <DropdownMenu>
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
                                onClick={() => toggleFindingMutation.mutate({ finding_id: row.id, state: "fixed" })}
                                disabled={toggleFindingMutation.isPending}
                              >
                                <CheckCircle className="h-4 w-4" />
                                Mark as Fixed
                              </DropdownMenuItem>
                              <DropdownMenuItem
                                className="cursor-pointer gap-2"
                                onClick={() => toggleFindingMutation.mutate({ finding_id: row.id, state: "ignored" })}
                                disabled={toggleFindingMutation.isPending}
                              >
                                <EyeOff className="h-4 w-4" />
                                Mark as Ignored
                              </DropdownMenuItem>
                              <DropdownMenuItem
                                className="cursor-pointer gap-2"
                                onClick={() => toggleFindingMutation.mutate({ finding_id: row.id, state: "in_progress" })}
                                disabled={toggleFindingMutation.isPending}
                              >
                                <Loader2 className="h-4 w-4" />
                                Mark as In progress
                              </DropdownMenuItem>
                              <DropdownMenuItem
                                className="cursor-pointer gap-2"
                                onClick={() => toggleFindingMutation.mutate({ finding_id: row.id, state: "not_started" })}
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
        </CardContent>
      </Card>
        </>
      )}

      <Dialog open={detailDialogOpen} onOpenChange={setDetailDialogOpen}>
        <DialogContent className="max-w-4xl max-h-[90vh] flex flex-col p-0 gap-0 overflow-hidden bg-zinc-900">
          <DialogHeader className="px-6 pt-6 pb-2 shrink-0">
            <DialogTitle className="pr-8">
              {selectedVuln?.title ?? "Vulnerability details"}
            </DialogTitle>
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
                  {(selectedVuln.status ?? "").trim() && (
                    <div>
                      <div className="text-xs font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400 mb-1">Status</div>
                      <span className={`inline-flex items-center px-2.5 py-1 rounded-md text-xs font-medium capitalize ${getFindingStatusBadgeClass(selectedVuln.status ?? "not_started")}`}>
                        {(selectedVuln.status ?? "not_started").replace(/_/g, " ")}
                      </span>
                    </div>
                  )}
                  {(selectedVuln.description ?? "").trim() && (
                    <div>
                      <div className="text-xs font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400 mb-1">Description</div>
                      <p className="text-sm text-zinc-700 dark:text-zinc-300">{selectedVuln.description!.trim()}</p>
                    </div>
                  )}
                  {getOwaspComplianceEntries(selectedVuln.owasp_top_10_llm).length > 0 && (
                    <div>
                      <div className="text-xs font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400 mb-1">OWASP Top 10 for LLM</div>
                      <div className="flex flex-wrap gap-1">
                        {getOwaspComplianceEntries(selectedVuln.owasp_top_10_llm).map(([key, label], i) => {
                          const c = OWASP_COLORS[i % OWASP_COLORS.length];
                          return (
                            <span
                              key={key}
                              className="inline-flex items-center px-2.5 py-1 rounded-md text-xs font-medium border"
                              style={{
                                backgroundColor: c.replace(")", " / 0.15)"),
                                color: c,
                                borderColor: c,
                              }}
                            >
                              {OWASP_LLM_KEY_TO_LABEL[key] ?? label}
                            </span>
                          );
                        })}
                      </div>
                    </div>
                  )}
                  {getOwaspComplianceEntries(selectedVuln.compliance_controls).length > 0 && (
                    <div>
                      <div className="text-xs font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400 mb-1">Compliance controls</div>
                      <div className="flex flex-wrap gap-1">
                        {getOwaspComplianceEntries(selectedVuln.compliance_controls).map(([key, label], i) => {
                          const c = COMPLIANCE_COLORS[i % COMPLIANCE_COLORS.length];
                          return (
                            <span
                              key={key}
                              className="inline-flex items-center px-2.5 py-1 rounded-md text-xs font-medium border"
                              style={{
                                backgroundColor: c.replace(")", " / 0.15)"),
                                color: c,
                                borderColor: c,
                              }}
                            >
                              {COMPLIANCE_KEY_TO_LABEL[key] ?? label}
                            </span>
                          );
                        })}
                      </div>
                    </div>
                  )}
                  {(selectedVuln.suggested_fix ?? "").trim() && (
                    <div>
                      <div className="text-xs font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400 mb-1">Suggested fix</div>
                      <p className="text-sm text-zinc-700 dark:text-zinc-300">{selectedVuln.suggested_fix!.trim()}</p>
                    </div>
                  )}
                  {selectedVuln.vulnerability_predictions != null && (() => {
                    const pred = selectedVuln.vulnerability_predictions;
                    const isObj = typeof pred === "object" && pred !== null && !Array.isArray(pred);
                    const entries = isObj
                      ? Object.entries(pred as Record<string, number>).filter(([, v]) => v != null && typeof v === "number")
                      : [];
                    const getScoreColor = (score: number) => {
                      if (score >= 7) return { bg: "bg-red-500/15", border: "border-red-500", text: "text-red-600 dark:text-red-400" };
                      if (score >= 4) return { bg: "bg-amber-500/15", border: "border-amber-500", text: "text-amber-600 dark:text-amber-400" };
                      return { bg: "bg-emerald-500/15", border: "border-emerald-500", text: "text-emerald-600 dark:text-emerald-400" };
                    };
                    const labels: Record<string, string> = {
                      prompt_injection_score: "Prompt injection",
                      jailbreak_score: "Jailbreak",
                      bias_score: "Bias",
                      hallucination_score: "Hallucination",
                    };
                    if (entries.length === 0) {
                      return (
                        <div>
                          <div className="text-xs font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400 mb-1">Vulnerability predictions</div>
                          <pre className="text-xs text-zinc-700 dark:text-zinc-300 overflow-auto rounded bg-zinc-800 p-3">
                            {JSON.stringify(pred, null, 2)}
                          </pre>
                        </div>
                      );
                    }
                    return (
                      <div>
                        <div className="text-xs font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400 mb-1">Vulnerability predictions</div>
                        <div className="flex flex-wrap gap-2">
                          {entries.map(([key, value]) => {
                            const colors = getScoreColor(Number(value));
                            const label = labels[key] ?? key.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
                            return (
                              <div
                                key={key}
                                className={`inline-flex flex-col items-center justify-center rounded-lg border px-3 py-2 min-w-[80px] ${colors.bg} ${colors.border}`}
                              >
                                <span className={`text-xs font-medium ${colors.text}`}>{label}</span>
                                <span className={`text-lg font-bold tabular-nums ${colors.text}`}>{value}/10</span>
                              </div>
                            );
                          })}
                        </div>
                      </div>
                    );
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
