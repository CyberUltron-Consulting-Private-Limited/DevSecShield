"use client";

import { useState, useEffect, useRef, useCallback, useMemo } from "react";
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
import { AlertTriangle, ArrowLeft, MessageCircle, Download, Ticket, Shield, CheckCircle, EyeOff, Loader2, Circle, MoreVertical, Waypoints } from "lucide-react";
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
import { useRouter, useSearchParams, usePathname, useParams } from "next/navigation";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { getIACExportResults, updateScan, createTicket, toggleFindingState, type SastDashboardData, type IACScanDashboardData, type IACFinding, type IACScanMetadata, type ScanTicketingIntegrationSettings } from "@/utils/backend_api";
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
  Pie,
  PieChart as RechartsPieChart,
  PolarAngleAxis,
  PolarGrid,
  Radar,
  RadarChart,
  RadialBar,
  RadialBarChart,
  XAxis,
  YAxis,
} from "recharts";
import { PieChart, BarChart3, TrendingUp, GitBranch, FileArchive, ImageIcon, Github, Search, Filter, Check, X, ChevronDown } from "lucide-react";
import { toast } from "sonner";
import TicketingIntegrationsSettings from "@/components/ticketing-integrations-settings";
import FindingSelectionMenu from "@/components/finding-selection-menu";

// IAC agent output format (from worker_iac_agent_results_testing.json): flat array of vulnerabilities
type OwaspOrComplianceItem = Record<string, string>;
type OwaspOrCompliance = Record<string, string> | Array<OwaspOrComplianceItem> | null | undefined;

export interface IACVulnerability {
  title?: string | null;
  description?: string | null;
  impact?: string | null;
  owasp_top_10?: OwaspOrCompliance;
  compliance_controls?: OwaspOrCompliance;
  suggested_fix?: string | null;
  location?: string | null;
  snippet?: string | null;
  cves?: unknown[] | Record<string, unknown> | null;
  category?: string | null;
  resource?: string | null;
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

function countFindingField(field: unknown): number {
  if (field == null) return 0;
  if (Array.isArray(field)) return field.length;
  if (typeof field === "object" && !Array.isArray(field)) return Object.keys(field).length;
  return 0;
}

function getFindingStatusBadgeClass(status: string): string {
  const s = (status ?? "").toLowerCase().replace(/\s/g, "_");
  if (s === "fixed") return "bg-emerald-100 text-emerald-800 dark:bg-emerald-900/40 dark:text-emerald-200";
  if (s === "ignored") return "bg-zinc-100 text-zinc-700 dark:bg-zinc-700/50 dark:text-zinc-200";
  if (s === "in_progress") return "bg-blue-100 text-blue-800 dark:bg-blue-900/40 dark:text-blue-200";
  if (s === "not_started") return "bg-slate-100 text-slate-600 dark:bg-slate-700/50 dark:text-slate-300";
  return "bg-zinc-100 text-zinc-600 dark:bg-zinc-700/50 dark:text-zinc-300";
}

interface IACResultsProps {
  data: IACVulnerability[] | null | undefined;
  conversationId?: number;
  dashboard?: IACScanDashboardData | SastDashboardData | null;
  findings?: IACFinding[] | null;
  scanMetadata?: IACScanMetadata | Record<string, unknown> | null;
  teamId?: string;
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

const RISK_ORDER = ["Critical", "High", "Medium", "Low"] as const;

/** Clean repo URL for display: trim, strip trailing slash, collapse repeated slashes */
function cleanRepoUrlDisplay(url: string | null | undefined): string {
  if (url == null || typeof url !== "string") return "—";
  let s = url.trim();
  if (!s) return "—";
  s = s.replace(/\/+/g, "/").replace(/\/$/, "");
  return s || "—";
}

const riskRadarChartConfig = {
  subject: { label: "Severity" },
  count: { label: "Count", color: "hsl(0 84% 60%)" },
} satisfies ChartConfig;


const complianceAccentColors = ["#3b82f6", "#10b981", "#f59e0b", "#ef4444", "#8b5cf6", "#ec4899"];



const DIAGRAM_MIN_SCALE = 0.25;
const DIAGRAM_MAX_SCALE = 4;
const DIAGRAM_SCALE_STEP = 0.15;

/** Inline dependency diagram section (renders mermaid when diagramCode is set) with pan and zoom */
function DependencyDiagramSection({ diagramCode }: { diagramCode: string | null | undefined }) {
  const [svg, setSvg] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [scale, setScale] = useState(1);
  const [translate, setTranslate] = useState({ x: 0, y: 0 });
  const [isPanning, setIsPanning] = useState(false);
  const panStart = useRef({ x: 0, y: 0, translateX: 0, translateY: 0 });
  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!diagramCode?.trim()) {
      setSvg(null);
      setError(null);
      return;
    }
    setError(null);
    setScale(1);
    setTranslate({ x: 0, y: 0 });
    let cancelled = false;
    (async () => {
      try {
        const mermaid = (await import("mermaid")).default;
        mermaid.initialize({ startOnLoad: false });
        const id = `mermaid-inline-${Date.now()}-${Math.random().toString(36).slice(2, 9)}`;
        const { svg: out } = await mermaid.render(id, diagramCode.trim());
        if (!cancelled) setSvg(out);
      } catch (e) {
        if (!cancelled) setError(e instanceof Error ? e.message : "Failed to render diagram");
      }
    })();
    return () => { cancelled = true; };
  }, [diagramCode]);

  const handleWheel = useCallback((e: WheelEvent) => {
    if (!svg || !containerRef.current?.contains(e.target as Node)) return;
    e.preventDefault();
    const delta = e.deltaY > 0 ? -DIAGRAM_SCALE_STEP : DIAGRAM_SCALE_STEP;
    setScale((s) => Math.min(DIAGRAM_MAX_SCALE, Math.max(DIAGRAM_MIN_SCALE, s + delta)));
  }, [svg]);

  useEffect(() => {
    const el = containerRef.current;
    if (!el) return;
    el.addEventListener("wheel", handleWheel, { passive: false });
    return () => el.removeEventListener("wheel", handleWheel);
  }, [handleWheel]);

  const handlePointerDown = useCallback((e: React.PointerEvent) => {
    if (e.button !== 0 || !svg) return;
    e.preventDefault();
    setIsPanning(true);
    panStart.current = { x: e.clientX, y: e.clientY, translateX: translate.x, translateY: translate.y };
    (e.target as HTMLElement).setPointerCapture?.(e.pointerId);
  }, [svg, translate.x, translate.y]);

  const handlePointerMove = useCallback((e: React.PointerEvent) => {
    if (!isPanning) return;
    setTranslate({
      x: panStart.current.translateX + (e.clientX - panStart.current.x),
      y: panStart.current.translateY + (e.clientY - panStart.current.y),
    });
  }, [isPanning]);

  const handlePointerUp = useCallback((e: React.PointerEvent) => {
    if (e.button !== 0) return;
    setIsPanning(false);
    (e.target as HTMLElement).releasePointerCapture?.(e.pointerId);
  }, []);

  const handleDoubleClick = useCallback(() => {
    setScale(1);
    setTranslate({ x: 0, y: 0 });
  }, []);

  if (!diagramCode?.trim()) return null;

  return (
    <Card className="border-zinc-200 dark:border-zinc-800">
      <CardHeader>
        <CardTitle className="text-base flex items-center gap-2">
          <Waypoints className="h-4 w-4 text-yellow-500" />
          Dependency diagram
        </CardTitle>
        <CardDescription>Infrastructure and dependency relationships from this scan</CardDescription>
      </CardHeader>
      <CardContent>
        <div
          ref={containerRef}
          className="rounded-md border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 p-4 min-h-[200px] max-h-[500px] overflow-hidden touch-none select-none cursor-grab active:cursor-grabbing"
          onPointerDown={handlePointerDown}
          onPointerMove={handlePointerMove}
          onPointerUp={handlePointerUp}
          onPointerLeave={handlePointerUp}
          onDoubleClick={handleDoubleClick}
          style={{ userSelect: "none" }}
        >
          {error && <p className="text-sm text-red-600 dark:text-red-400">{error}</p>}
          {svg && !error && (
            <div
              className="flex justify-center origin-center will-change-transform"
              style={{
                transform: `translate(${translate.x}px, ${translate.y}px) scale(${scale})`,
                minHeight: "200px",
              }}
              dangerouslySetInnerHTML={{ __html: svg }}
            />
          )}
          {!svg && !error && <p className="text-sm text-zinc-500">Rendering…</p>}
        </div>
        <p className="text-xs text-zinc-500 dark:text-zinc-400 mt-2">
          Scroll to zoom · Drag to pan · Double-click to reset
        </p>
      </CardContent>
    </Card>
  );
}

function IACResultsAgentView({
  vulnerabilities,
  conversationId,
  teamId,
  isCicdContext,
  integrationId,
  origin,
  router,
  onDownloadReport,
  isExporting = false,
  dashboard,
  findings,
  scanMetadata,
  onFindingsUpdated,
  integrationSettings,
  onIntegrationSettingsUpdated,
}: {
  vulnerabilities: IACVulnerability[];
  conversationId?: number;
  teamId?: string;
  isCicdContext: boolean;
  integrationId: string | null;
  origin: string | null;
  router: ReturnType<typeof useRouter>;
  onDownloadReport?: () => void;
  isExporting?: boolean;
  dashboard?: IACScanDashboardData | SastDashboardData | null;
  findings?: IACFinding[] | null;
  scanMetadata?: IACScanMetadata | Record<string, unknown> | null;
  onFindingsUpdated?: () => void;
  integrationSettings?: Record<string, unknown> | null;
  onIntegrationSettingsUpdated?: () => void;
}) {
  const [detailDialogOpen, setDetailDialogOpen] = useState(false);
  const [selectedVuln, setSelectedVuln] = useState<IACFinding | IACVulnerability | null>(null);
  const [activeTab, setActiveTab] = useState<"results" | "ticketing">("results");
  const [jiraProjectId, setJiraProjectId] = useState("");
  const [autoCreateTickets, setAutoCreateTickets] = useState(false);
  const [selectedRows, setSelectedRows] = useState<Set<number>>(new Set());
  const [selectedFindingIds, setSelectedFindingIds] = useState<Set<string>>(new Set());
  const queryClient = useQueryClient();

  const meta = scanMetadata && typeof scanMetadata === "object" ? scanMetadata as IACScanMetadata : null;
  const dependencyDiagram = meta?.dependency_diagram ?? null;

  const useFindingsMode = Boolean(findings && findings.length > 0);

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
    if (!useFindingsMode) return findingsList;
    let list = findingsList;
    const q = findingsSearchQuery.trim().toLowerCase();
    if (q) {
      list = list.filter((f) => {
        const title = ((f.title ?? "") + "").toLowerCase();
        const description = ((f.description ?? "") + "").toLowerCase();
        const impact = ((f.impact ?? "") + "").toLowerCase();
        const status = ((f.status ?? "") + "").toLowerCase();
        const category = ((f.category ?? "") + "").toLowerCase();
        const resource = ((f.resource ?? "") + "").toLowerCase();
        return title.includes(q) || description.includes(q) || impact.includes(q) || status.includes(q) || category.includes(q) || resource.includes(q);
      });
    }
    if (filterImpact && filterImpact !== "all") {
      list = list.filter((f) => (f.impact ?? "").trim().toLowerCase() === filterImpact.toLowerCase());
    }
    list = list.filter((f) => matchesRiskScoreFilter(f.risk_score ?? null, filterRiskScore));
    return list;
  }, [findingsList, useFindingsMode, findingsSearchQuery, filterImpact, filterRiskScore]);
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
        type: "iac",
        scan_id: conversationId!,
        data: payload,
      }),
    onSuccess: () => {
      onIntegrationSettingsUpdated?.();
      const tid = parseInt(teamId ?? "0", 10);
      if (conversationId != null && tid > 0) {
        queryClient.invalidateQueries({ queryKey: ["iac-conversation-data", tid, conversationId] });
      }
      toast.success("Ticketing settings saved");
    },
    onError: (err) => {
      showErrorToast(err, "Failed to save ticketing settings");
    },
  });

  const hasTicketingTab = !isCicdContext && teamId && conversationId != null && onIntegrationSettingsUpdated != null;

  const totalFindings = useFindingsMode ? (findings?.length ?? 0) : vulnerabilities.length;

  const toggleRowSelection = (idx: number) => {
    setSelectedRows((prev) => {
      const next = new Set(prev);
      if (next.has(idx)) next.delete(idx);
      else next.add(idx);
      return next;
    });
  };

  const toggleSelectAll = () => {
    if (useFindingsMode && filteredFindingsList.length) {
      if (selectedFindingIds.size === filteredFindingsList.length) {
        setSelectedFindingIds(new Set());
      } else {
        setSelectedFindingIds(new Set(filteredFindingsList.map((f) => f.id)));
      }
    } else if (!useFindingsMode) {
      if (selectedRows.size === vulnerabilities.length) {
        setSelectedRows(new Set());
      } else {
        setSelectedRows(new Set(vulnerabilities.map((_, i) => i)));
      }
    }
  };

  const toggleFindingIdSelection = (findingId: string) => {
    setSelectedFindingIds((prev) => {
      const next = new Set(prev);
      if (next.has(findingId)) next.delete(findingId);
      else next.add(findingId);
      return next;
    });
  };

  const toggleFindingMutation = useMutation({
    mutationFn: ({ finding_id, state }: { finding_id: string; state: "fixed" | "ignored" | "in_progress" | "not_started" }) => {
      const tid = parseInt(teamId ?? "0", 10);
      if (!conversationId || Number.isNaN(tid)) throw new Error("Missing team or scan");
      return toggleFindingState({ team_id: tid, type: "iac", scan_id: conversationId, finding_id, state });
    },
    onSuccess: () => {
      onFindingsUpdated?.();
      const tid = parseInt(teamId ?? "0", 10);
      if (conversationId != null && tid > 0) {
        queryClient.invalidateQueries({ queryKey: ["iac-conversation-data", tid, conversationId] });
      }
      toast.success("Finding status updated");
    },
    onError: (err) => {
      showErrorToast(err, "Failed to update finding status");
    },
  });

  const createJiraTicketsMutation = useMutation({
    mutationFn: async () => {
      const tid = parseInt(teamId ?? "0", 10);
      if (!conversationId || Number.isNaN(tid)) throw new Error("Missing team or scan");
      const selectedFindings = useFindingsMode && findingsList?.length
        ? findingsList.filter((f) => selectedFindingIds.has(f.id))
        : Array.from(selectedRows).map((i) => vulnerabilities[i]);
      if (selectedFindings.length === 0) throw new Error("No findings selected");

      const impactCounts: Record<string, number> = {};
      for (const vuln of selectedFindings) {
        const impact = (vuln.impact ?? "Unknown").trim() || "Unknown";
        impactCounts[impact] = (impactCounts[impact] ?? 0) + 1;
      }
      let summary = Object.entries(impactCounts)
        .sort(([a], [b]) => RISK_ORDER.indexOf(a as (typeof RISK_ORDER)[number]) - RISK_ORDER.indexOf(b as (typeof RISK_ORDER)[number]))
        .map(([impact, count]) => `${count} ${impact}`)
        .join(", ") || `${selectedFindings.length} finding(s)`;
      
      summary = summary + " - Vulnerabilities found in IAC scan";

      const descSections = selectedFindings.map((vuln, idx) => {
        const parts: string[] = [`--- Finding ${idx + 1} ---`];
        parts.push(`Title: ${(vuln.title ?? "Untitled finding").trim() || "Untitled finding"}`);
        if ((vuln.description ?? "").trim()) parts.push(`Description: ${vuln.description!.trim()}`);
        if ((vuln.impact ?? "").trim()) parts.push(`Impact: ${vuln.impact!.trim()}`);
        if ((vuln.location ?? "").trim()) parts.push(`Location: ${vuln.location!.trim()}`);
        if ((vuln.suggested_fix ?? "").trim()) parts.push(`Suggested fix: ${vuln.suggested_fix!.trim()}`);
        return parts.join("\n");
      });
      const description = descSections.join("\n\n");

      await createTicket(tid, "iac", conversationId, {
        ticket_type: "jira",
        summary,
        description,
        finding_ids: selectedFindings
          .map((vuln) => ("id" in vuln ? vuln.id : undefined))
          .filter((id): id is string => typeof id === "string" && id.length > 0),
      });
    },
    onMutate: () => {
      const toastId = toast.loading("Creating Jira ticket(s)...");
      return { toastId };
    },
    onSuccess: (_data, _variables, context) => {
      const count = useFindingsMode ? selectedFindingIds.size : selectedRows.size;
      if (context?.toastId != null) {
        toast.success(`Jira ticket(s) created for ${count} finding(s)`, { id: context.toastId });
      } else {
        toast.success(`Jira ticket(s) created for ${count} finding(s)`);
      }
      setSelectedRows(new Set());
      setSelectedFindingIds(new Set());
    },
    onError: (err, _variables, context) => {
      if (context?.toastId != null) toast.dismiss(context.toastId);
      showErrorToast(err, "Failed to create Jira ticket(s)");
    },
  });

  const handleCreateJiraTicket = () => createJiraTicketsMutation.mutate();

  const openVulnDetail = (vuln: IACFinding | IACVulnerability) => {
    setSelectedVuln(vuln);
    setDetailDialogOpen(true);
  };

  const selectedCount = useFindingsMode ? selectedFindingIds.size : selectedRows.size;

  return (
    <div className="container mx-auto p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          {(conversationId != null || isCicdContext) && (
            <Button
              variant="outline"
              size="icon"
              onClick={() => {
                const backRoute =
                  isCicdContext && integrationId
                    ? `/home/ci_cd/${integrationId}`
                    : origin === "chat"
                      ? teamId ? `/${teamId}/iac/${conversationId}` : `/home/iac/${conversationId}`
                      : teamId ? `/${teamId}/iac` : "/home/iac";
                router.push(backRoute);
              }}
              className="cursor-pointer"
            >
              <ArrowLeft className="h-4 w-4" />
            </Button>
          )}
          <div>
            <h1 className="text-3xl font-bold text-zinc-900 dark:text-white">IAC Scan Results</h1>
            <p className="text-sm text-zinc-600 dark:text-zinc-400 mt-1">
              Infrastructure as Code security analysis
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
              onClick={() => router.push(`/${teamId}/iac/${conversationId}`)}
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
          inputId="iac-jira-project-id"
        />
      ) : (
        <>
      {/* Top cards: metadata + risk — SAST-style (icon top-left, text bottom-left, uniform padding) */}
      <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-4">
        <Card className="border-zinc-200 dark:border-zinc-800 py-3 px-3 min-w-0 overflow-hidden">
          <CardContent className="p-0 min-w-0 overflow-hidden">
            <div className="flex flex-col items-start gap-2 min-w-0 overflow-hidden">
              <div className={`flex h-8 w-8 shrink-0 items-center justify-center rounded-lg ${meta?.zip_file_used ? "bg-amber-100 dark:bg-amber-900/30 text-amber-600 dark:text-amber-400" : "bg-violet-100 dark:bg-violet-900/30 text-violet-600 dark:text-violet-400"}`}>
                {meta?.zip_file_used ? <FileArchive className="h-4 w-4" /> : <Github className="h-4 w-4" />}
              </div>
              <div className="min-w-0 w-full overflow-hidden">
                <p className="text-xs font-medium text-zinc-500 dark:text-zinc-400">Source</p>
                <p className="text-sm font-semibold text-zinc-900 dark:text-zinc-100 truncate" title={meta?.zip_file_used ? undefined : (meta?.repo_url?.trim() ?? undefined)}>
                  {meta?.zip_file_used ? "ZIP upload" : cleanRepoUrlDisplay(meta?.repo_url)}
                </p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card className="border-zinc-200 dark:border-zinc-800 py-3 px-3 min-w-0 overflow-hidden">
          <CardContent className="p-0 min-w-0 overflow-hidden">
            <div className="flex flex-col items-start gap-2 min-w-0 overflow-hidden">
              <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-amber-100 dark:bg-amber-900/30 text-amber-600 dark:text-amber-400">
                <GitBranch className="h-4 w-4" />
              </div>
              <div className="min-w-0 w-full overflow-hidden">
                <p className="text-xs font-medium text-zinc-500 dark:text-zinc-400">Branch</p>
                <p className="text-sm font-semibold text-zinc-900 dark:text-zinc-100 truncate" title={meta?.branch?.trim() || undefined}>{meta?.branch?.trim() || "—"}</p>
              </div>
            </div>
          </CardContent>
        </Card>
        {dashboard && "risk_metrics" in dashboard && (() => {
          const risk = (dashboard as IACScanDashboardData).risk_metrics ?? {};
          const order = ["Critical", "High", "Medium", "Low"] as const;
          const riskIconColors = ["bg-red-100 dark:bg-red-900/30 text-red-600 dark:text-red-400", "bg-orange-100 dark:bg-orange-900/30 text-orange-600 dark:text-orange-400", "bg-amber-100 dark:bg-amber-900/30 text-amber-600 dark:text-amber-400", "bg-blue-100 dark:bg-blue-900/30 text-blue-600 dark:text-blue-400"];
          return order.map((severity, idx) => (
            <Card key={severity} className="border-zinc-200 dark:border-zinc-800 py-3 px-3 min-w-0 overflow-hidden">
              <CardContent className="p-0 min-w-0 overflow-hidden">
                <div className="flex flex-col items-start gap-2 min-w-0 overflow-hidden">
                  <div className={`flex h-8 w-8 shrink-0 items-center justify-center rounded-lg ${riskIconColors[idx] ?? "bg-zinc-100 dark:bg-zinc-800 text-zinc-600 dark:text-zinc-400"}`}>
                    <Shield className="h-4 w-4" />
                  </div>
                  <div className="min-w-0 overflow-hidden">
                    <p className="text-xs font-medium text-zinc-500 dark:text-zinc-400">{severity}</p>
                    <p className="text-xl font-bold text-zinc-900 dark:text-white truncate">{risk[severity] ?? 0}</p>
                  </div>
                </div>
              </CardContent>
            </Card>
          ));
        })()}
      </div>

      {dashboard && "compliance_framework_coverage" in dashboard && (dashboard.policy_violations != null || dashboard.compliance_framework_coverage != null) && (
        <Card className="border-zinc-200 dark:border-zinc-800">
          <CardHeader className="pb-2">
            <div className="flex items-center gap-2">
              <Shield className="h-5 w-5 text-zinc-600 dark:text-zinc-400" />
              <CardTitle className="text-base">Compliance Violations</CardTitle>
            </div>
            <CardDescription>Violations by framework</CardDescription>
          </CardHeader>
          <CardContent>
            {(() => {
              const policyViolations = (dashboard as IACScanDashboardData).policy_violations ?? {};
              const coverage = (dashboard as IACScanDashboardData).compliance_framework_coverage ?? {};
              const frameworks = Array.from(new Set([...Object.keys(policyViolations), ...Object.keys(coverage)]));
              if (frameworks.length === 0) {
                return <p className="text-center text-sm text-zinc-500 py-8">No compliance data yet</p>;
              }
              const sumViolations = Object.values(policyViolations).reduce((a, b) => a + b, 0);
              return (
                <ScrollArea className="w-full">
                  <div className="flex gap-4 pb-4 min-w-max pr-4">
                    {frameworks.map((framework, idx) => {
                      const violations = policyViolations[framework] ?? 0;
                      const pct = coverage[framework] ?? (sumViolations > 0 ? (violations / sumViolations) * 100 : 0);
                      const accent = complianceAccentColors[idx % complianceAccentColors.length];
                      return (
                        <Card key={framework} className="border-zinc-200 dark:border-zinc-800 shrink-0 w-[200px] border-l-4" style={{ borderLeftColor: accent }}>
                          <CardContent className="pt-4 pb-4">
                            <p className="text-sm font-medium text-zinc-900 dark:text-white mb-1">{framework}</p>
                            <p className="text-2xl font-bold" style={{ color: accent }}>{Number(pct).toFixed(1)}%</p>
                            <Progress value={Number(pct)} className="h-2 mt-2" />
                            <div className="flex items-center gap-3 mt-3 text-sm flex-wrap">
                              <span className="flex items-center gap-1.5 text-zinc-600 dark:text-zinc-400">
                                <AlertTriangle className="h-4 w-4 text-red-500 shrink-0" />
                                Violations: {violations}
                              </span>
                            </div>
                          </CardContent>
                        </Card>
                      );
                    })}
                  </div>
                  <ScrollBar orientation="horizontal" />
                </ScrollArea>
              );
            })()}
          </CardContent>
        </Card>
      )}

      {/* First chart row: Issues by severity (pie), Issues by category (radar), Average risk score by category (area) */}
      {dashboard && "issues_by_severity" in dashboard && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {(() => {
            const iacDash = dashboard as IACScanDashboardData;
            const severityData = (iacDash.issues_by_severity ?? {});
            const severityPieData = (["Critical", "High", "Medium", "Low"] as const)
              .filter((s) => (severityData[s] ?? 0) > 0)
              .map((s) => ({ name: s, value: severityData[s] ?? 0 }));
            const categoryData = Object.entries(iacDash.issues_by_category ?? {}).map(([name, count], i) => ({ xLabel: `C${i + 1}`, subject: name.length > 18 ? `${name.slice(0, 18)}…` : name, fullName: name, count }));
            const avgRiskData = Object.entries(iacDash.average_risk_score_per_category ?? {}).map(([name, score]) => ({ name: name.length > 10 ? `${name.slice(0, 10)}…` : name, fullName: name, score }));
            const severityColors = { Critical: "hsl(0 84% 60%)", High: "hsl(25 95% 53%)", Medium: "hsl(48 96% 53%)", Low: "hsl(217 91% 60%)" };
            const issue_status_display_names: Record<string, string> = { "not_started": "Not Started", "in_progress": "In Progress", "fixed": "Fixed", "ignored": "Ignored" };
            const issueStatusData = Object.entries(iacDash.issue_status_metrics ?? {}).map(([name, count]) => ({ name: issue_status_display_names[name as keyof typeof issue_status_display_names] ?? name, fullName: name, count }));
            return (
              <>
                <Card className="border-zinc-200 dark:border-zinc-800">
                  <CardHeader>
                    <CardTitle className="text-base">Issues by severity</CardTitle>
                    <CardDescription>Distribution by impact</CardDescription>
                  </CardHeader>
                  <CardContent>
                    {severityPieData.length === 0 ? (
                      <div className="flex items-center justify-center min-h-[260px] text-zinc-500 dark:text-zinc-400 text-sm">No data to display</div>
                    ) : (
                      <ChartContainer config={{ value: { label: "Count" } }} className="aspect-square max-h-[260px] mx-auto">
                        <RechartsPieChart>
                          <ChartTooltip content={<ChartTooltipContent />} />
                          <Pie data={severityPieData} dataKey="value" nameKey="name" cx="50%" cy="50%" innerRadius={50} outerRadius={80}>
                            {severityPieData.map((entry, i) => (
                              <Cell key={entry.name} fill={(severityColors as Record<string, string>)[entry.name] ?? "hsl(0 0% 70%)"} />
                            ))}
                          </Pie>
                        </RechartsPieChart>
                      </ChartContainer>
                    )}
                  </CardContent>
                </Card>
                <Card className="border-zinc-200 dark:border-zinc-800">
                  <CardHeader>
                    <CardTitle className="text-base">Issues by category</CardTitle>
                    <CardDescription>Count per category</CardDescription>
                  </CardHeader>
                  <CardContent>
                    {categoryData.length === 0 ? (
                      <div className="flex items-center justify-center min-h-[260px] text-zinc-500 dark:text-zinc-400 text-sm">No data to display</div>
                    ) : (
                      <>
                        <ChartContainer config={riskRadarChartConfig} className="aspect-square max-h-[280px] min-h-[260px] mx-auto w-full max-w-[320px]">
                          <RadarChart data={categoryData} margin={{ top: 32, right: 48, bottom: 32, left: 48 }}>
                            <ChartTooltip cursor={false} content={<ChartTooltipContent nameKey="fullName" formatter={(v) => [v, "Count"]} />} />
                            <PolarAngleAxis dataKey="xLabel" tick={{ fontSize: 11 }} />
                            <PolarGrid />
                            <Radar dataKey="count" fill="hsl(217 91% 60%)" fillOpacity={0.6} dot={{ r: 4, fillOpacity: 1 }} />
                          </RadarChart>
                        </ChartContainer>
                        <div className="mt-4 pt-3 border-t border-zinc-200 dark:border-zinc-700 flex flex-wrap gap-x-4 gap-y-2 justify-center text-xs text-zinc-600 dark:text-zinc-400">
                          {categoryData.map((d) => (
                            <span key={d.xLabel}>
                              <span className="font-medium text-zinc-800 dark:text-zinc-200">{d.xLabel}</span>
                              <span className="mx-1.5">=</span>
                              <span>{d.fullName}</span>
                            </span>
                          ))}
                        </div>
                      </>
                    )}
                  </CardContent>
                </Card>
                <Card className="border-zinc-200 dark:border-zinc-800">
                  <CardHeader>
                    <CardTitle className="text-base">Issue Status Metrics</CardTitle>
                    <CardDescription>Distribution by status</CardDescription>
                  </CardHeader>
                  <CardContent>
                    {issueStatusData.length === 0 ? (
                      <div className="flex items-center justify-center min-h-[260px] text-zinc-500 dark:text-zinc-400 text-sm">No data to display</div>
                    ) : (
                      <ChartContainer config={{ name: { label: "Status" }, score: { label: "Count", color: "hsl(217 91% 60%)" } }} className="h-[260px] w-full">
                        <AreaChart data={issueStatusData} margin={{ top: 8, right: 8, bottom: 24, left: 0 }}>
                          <CartesianGrid vertical={false} className="stroke-zinc-200 dark:stroke-zinc-800" />
                          <XAxis dataKey="name" tickLine={false} axisLine={false} tickMargin={8} tickFormatter={(v) => (String(v).length > 8 ? `${String(v).slice(0, 8)}…` : v)} />
                          <YAxis tickLine={false} axisLine={false} allowDecimals domain={[0, "auto"]} />
                          <ChartTooltip content={<ChartTooltipContent nameKey="fullName" />} />
                          <Area type="monotone" dataKey="count" fill="hsl(217 91% 60% / 0.3)" stroke="hsl(217 91% 60%)" strokeWidth={2} />
                        </AreaChart>
                      </ChartContainer>
                    )}
                  </CardContent>
                </Card>
              </>
            );
          })()}
        </div>
      )}

      {/* Second chart row: Average risk scores per category (red), Issue address metrics */}
      {dashboard && "average_risk_score_per_category" in dashboard && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {(() => {
            const iacDash = dashboard as IACScanDashboardData;
            const avgRiskData = Object.entries(iacDash.average_risk_score_per_category ?? {}).map(([name, score], i) => ({ xLabel: `A${i + 1}`, name: name.length > 10 ? `${name.slice(0, 10)}…` : name, fullName: name, score }));
            const addressMetrics = iacDash.issue_address_metrics ?? {};
            const addressData = Object.entries(addressMetrics).map(([finding, arr], i) => {
              const [d = 0, h = 0, m = 0] = Array.isArray(arr) ? arr : [0, 0, 0];
              const totalHours = d * 24 + h + m / 60;
              return { finding: `F${i + 1}`, fullName: finding, value: Math.round(totalHours * 10) / 10, days: d, hours: h, minutes: m };
            });
            return (
              <>
                <Card className="border-zinc-200 dark:border-zinc-800">
                  <CardHeader>
                    <CardTitle className="text-base">Average risk scores per category</CardTitle>
                    <CardDescription>Risk score by category</CardDescription>
                  </CardHeader>
                  <CardContent>
                    {avgRiskData.length === 0 ? (
                      <div className="flex items-center justify-center min-h-[260px] text-zinc-500 dark:text-zinc-400 text-sm">No data to display</div>
                    ) : (
                      <>
                        <ChartContainer config={{ name: { label: "Category" }, score: { label: "Score", color: "hsl(0 84% 60%)" } }} className="h-[260px] w-full">
                          <AreaChart data={avgRiskData} margin={{ top: 8, right: 8, bottom: 24, left: 0 }}>
                            <defs>
                              <linearGradient id="fillIacRiskScore" x1="0" y1="0" x2="0" y2="1">
                                <stop offset="5%" stopColor="hsl(0 84% 60%)" stopOpacity={0.8} />
                                <stop offset="95%" stopColor="hsl(0 84% 60%)" stopOpacity={0.1} />
                              </linearGradient>
                            </defs>
                            <CartesianGrid vertical={false} className="stroke-zinc-200 dark:stroke-zinc-800" />
                            <XAxis dataKey="xLabel" tickLine={false} axisLine={false} tickMargin={8} />
                            <YAxis tickLine={false} axisLine={false} allowDecimals domain={[0, "auto"]} />
                            <ChartTooltip
                              content={
                                <ChartTooltipContent
                                  labelFormatter={(_, payload) => {
                                    const p = payload?.[0]?.payload as { fullName?: string } | undefined;
                                    return p?.fullName ?? "";
                                  }}
                                />
                              }
                            />
                            <Area type="monotone" dataKey="score" fill="url(#fillIacRiskScore)" stroke="hsl(0 84% 60%)" strokeWidth={2} />
                          </AreaChart>
                        </ChartContainer>
                        <div className="mt-4 pt-3 border-t border-zinc-200 dark:border-zinc-700 flex flex-wrap gap-x-4 gap-y-2 justify-center text-xs text-zinc-600 dark:text-zinc-400">
                          {avgRiskData.map((d) => (
                            <span key={d.xLabel}>
                              <span className="font-medium text-zinc-800 dark:text-zinc-200">{d.xLabel}</span>
                              <span className="mx-1.5">=</span>
                              <span>{d.fullName}</span>
                            </span>
                          ))}
                        </div>
                      </>
                    )}
                  </CardContent>
                </Card>
                <Card className="border-zinc-200 dark:border-zinc-800">
                  <CardHeader>
                    <CardTitle className="text-base">Issue address metrics</CardTitle>
                    <CardDescription>Time to address (hours) per finding</CardDescription>
                  </CardHeader>
                  <CardContent>
                    {addressData.length === 0 ? (
                      <div className="flex items-center justify-center min-h-[260px] text-zinc-500 dark:text-zinc-400 text-sm">No data to display</div>
                    ) : (
                      <ChartContainer config={{ finding: { label: "Finding" }, value: { label: "Hours", color: "hsl(217 91% 60%)" } }} className="h-[260px] w-full">
                        <AreaChart data={addressData} margin={{ top: 8, right: 8, bottom: 24, left: 0 }}>
                          <CartesianGrid vertical={false} className="stroke-zinc-200 dark:stroke-zinc-800" />
                          <XAxis dataKey="finding" tickLine={false} axisLine={false} tickMargin={8} />
                          <YAxis tickLine={false} axisLine={false} allowDecimals domain={[0, "auto"]} />
                          <ChartTooltip content={<ChartTooltipContent nameKey="fullName" formatter={(_, __, ___, ____, p) => { const pay = (p as { days?: number; hours?: number; minutes?: number }) ?? {}; return [`${pay.days ?? 0}d ${pay.hours ?? 0}h ${pay.minutes ?? 0}m`, "Time"]; }} />} />
                          <Area type="monotone" dataKey="value" fill="hsl(217 91% 60% / 0.3)" stroke="hsl(217 91% 60%)" strokeWidth={2} />
                        </AreaChart>
                      </ChartContainer>
                    )}
                  </CardContent>
                </Card>
              </>
            );
          })()}
        </div>
      )}

      {/* Compliance failure trends + Average resolution time */}
      {dashboard && "compliance_failure_trends" in dashboard && (() => {
        const iacDash = dashboard as IACScanDashboardData;
        const failureTrends = iacDash.compliance_failure_trends ?? {};
        const resolutionTime = iacDash.average_resolution_time ?? {};
        const hasFailureTrends = Object.keys(failureTrends).length > 0;
        const hasResolutionTime = Object.keys(resolutionTime).length > 0;
        if (!hasFailureTrends && !hasResolutionTime) return null;
        const failureData = Object.entries(failureTrends).map(([name, count], i) => ({
          xLabel: `F${i + 1}`,
          fullName: name,
          count,
        }));
        const resolutionData = Object.entries(resolutionTime).map(([name, seconds], i) => ({
          name: name.length > 12 ? `${name.slice(0, 12)}…` : name,
          fullName: name,
          seconds,
          hours: Math.round((seconds / 3600) * 10) / 10,
          index: i + 1,
        }));
        return (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {hasFailureTrends && (
              <Card className="border-zinc-200 dark:border-zinc-800">
                <CardHeader>
                  <CardTitle className="text-base">Compliance failure trends</CardTitle>
                  <CardDescription>Total compliance controls violated per finding</CardDescription>
                </CardHeader>
                <CardContent>
                  <ChartContainer config={{ name: { label: "Finding" }, count: { label: "Violations", color: "hsl(25 95% 53%)" } }} className="h-[260px] w-full">
                    <AreaChart data={failureData} margin={{ top: 8, right: 8, bottom: 24, left: 0 }}>
                      <defs>
                        <linearGradient id="fillIacComplianceFailure" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor="hsl(25 95% 53%)" stopOpacity={0.8} />
                          <stop offset="95%" stopColor="hsl(25 95% 53%)" stopOpacity={0.1} />
                        </linearGradient>
                      </defs>
                      <CartesianGrid vertical={false} className="stroke-zinc-200 dark:stroke-zinc-800" />
                      <XAxis dataKey="xLabel" tickLine={false} axisLine={false} tickMargin={8} />
                      <YAxis tickLine={false} axisLine={false} allowDecimals={false} domain={[0, "auto"]} />
                      <ChartTooltip content={<ChartTooltipContent nameKey="fullName" formatter={(v) => [v, "Violations"]} />} />
                      <Area type="monotone" dataKey="count" fill="url(#fillIacComplianceFailure)" stroke="hsl(25 95% 53%)" strokeWidth={2} />
                    </AreaChart>
                  </ChartContainer>
                </CardContent>
              </Card>
            )}
            {hasResolutionTime && (
              <Card className="border-zinc-200 dark:border-zinc-800">
                <CardHeader>
                  <CardTitle className="text-base">Average resolution time</CardTitle>
                  <CardDescription>Time to resolve (hours) per finding</CardDescription>
                </CardHeader>
                <CardContent>
                  <ChartContainer config={{ name: { label: "Finding" }, hours: { label: "Hours", color: "hsl(142 76% 36%)" } }} className="h-[260px] w-full">
                    <AreaChart data={resolutionData} margin={{ top: 8, right: 8, bottom: 24, left: 0 }}>
                      <defs>
                        <linearGradient id="fillIacResolutionTime" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor="hsl(142 76% 36%)" stopOpacity={0.8} />
                          <stop offset="95%" stopColor="hsl(142 76% 36%)" stopOpacity={0.1} />
                        </linearGradient>
                      </defs>
                      <CartesianGrid vertical={false} className="stroke-zinc-200 dark:stroke-zinc-800" />
                      <XAxis dataKey="name" tickLine={false} axisLine={false} tickMargin={8} tickFormatter={(v) => (String(v).length > 10 ? `${String(v).slice(0, 10)}…` : v)} />
                      <YAxis tickLine={false} axisLine={false} allowDecimals domain={[0, "auto"]} tickFormatter={(v) => `${v}h`} />
                      <ChartTooltip
                        content={
                          <ChartTooltipContent
                            nameKey="fullName"
                            formatter={(_, __, ___, ____, payload) => {
                              const raw = (Array.isArray(payload) ? payload[0]?.payload : payload) as { seconds?: number } | undefined;
                              const sec = raw?.seconds ?? 0;
                              const h = Math.floor(sec / 3600);
                              const m = Math.floor((sec % 3600) / 60);
                              return [`${h}h ${m}m`, "Resolution time"];
                            }}
                          />
                        }
                      />
                      <Area type="monotone" dataKey="hours" fill="url(#fillIacResolutionTime)" stroke="hsl(142 76% 36%)" strokeWidth={2} />
                    </AreaChart>
                  </ChartContainer>
                </CardContent>
              </Card>
            )}
          </div>
        );
      })()}

      <Card>
        <CardHeader>
          <CardTitle>Findings</CardTitle>
          <CardDescription>{totalFindings} vulnerability findings — click a title to view details</CardDescription>
        </CardHeader>
        <CardContent>
          {useFindingsMode && findingsList.length > 0 && (
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
            selectedCount={selectedCount}
            onClearSelection={() => {
              setSelectedRows(new Set());
              setSelectedFindingIds(new Set());
            }}
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
                      checked={
                        useFindingsMode
                          ? (filteredFindingsList.length > 0 && selectedFindingIds.size === filteredFindingsList.length)
                          : vulnerabilities.length > 0 && selectedRows.size === vulnerabilities.length
                      }
                      onCheckedChange={toggleSelectAll}
                      aria-label="Select all rows"
                      className="cursor-pointer"
                    />
                  </TableHead>
                  {useFindingsMode ? (
                    <>
                      <TableHead className="min-w-[180px]">Title</TableHead>
                      <TableHead className="min-w-[180px]">Description</TableHead>
                      <TableHead className="min-w-[80px]">Impact</TableHead>
                      <TableHead className="min-w-[70px] text-center">Risk</TableHead>
                      <TableHead className="min-w-[90px]">Status</TableHead>
                      <TableHead className="min-w-[70px] text-center">OWASP</TableHead>
                      <TableHead className="min-w-[80px] text-center">Compliance</TableHead>
                      <TableHead className="min-w-[60px] text-center">CVE</TableHead>
                      <TableHead className="min-w-[100px]">Category</TableHead>
                      <TableHead className="min-w-[100px]">Resource</TableHead>
                      <TableHead className="min-w-[80px]">Actions</TableHead>
                    </>
                  ) : (
                    <>
                      <TableHead className="min-w-[200px]">Vulnerability</TableHead>
                      <TableHead className="min-w-[80px] text-center">OWASP Top 10</TableHead>
                      <TableHead className="min-w-[80px] text-center">Compliance Controls</TableHead>
                      <TableHead className="min-w-[100px]">Impact</TableHead>
                    </>
                  )}
                </TableRow>
              </TableHeader>
              <TableBody>
                {useFindingsMode && filteredFindingsList.length ? (
                  filteredFindingsList.map((f) => {
                    const vTitle = f.title ?? "Untitled finding";
                    const impact = (f.impact ?? "").trim() || "—";
                    const statusLabel = (f.status ?? "not_started").replace(/_/g, " ");
                    const riskScoreNum = f.risk_score != null ? Number(f.risk_score) : 0;
                    const desc = (f.description ?? "").trim();
                    const descTrunc = desc.length > 80 ? `${desc.slice(0, 80)}…` : desc || "—";
                    const owaspCount = countFindingField(f.owasp_top_10);
                    const complianceCount = countFindingField(f.compliance_controls);
                    const cveCount = countFindingField(f.cves);
                    const category = (f.category ?? "").trim() || "—";
                    const resource = (f.resource ?? "").trim() || "—";
                    return (
                      <TableRow
                        key={f.id}
                        className={`cursor-pointer hover:bg-zinc-50 dark:hover:bg-zinc-800/50 ${selectedFindingIds.has(f.id) ? "bg-zinc-100 dark:bg-zinc-800/70" : ""}`}
                      >
                        <TableCell onClick={(e) => e.stopPropagation()} className="min-w-[48px] w-12">
                          <Checkbox
                            checked={selectedFindingIds.has(f.id)}
                            onCheckedChange={() => toggleFindingIdSelection(f.id)}
                            aria-label={`Select finding ${f.id}`}
                            className="cursor-pointer"
                          />
                        </TableCell>
                        <TableCell className="font-medium">
                          <button
                            type="button"
                            onClick={() => openVulnDetail(f)}
                            className="text-left text-blue-600 hover:text-blue-700 dark:text-blue-400 dark:hover:text-blue-300 hover:underline cursor-pointer font-medium"
                          >
                            {vTitle}
                          </button>
                        </TableCell>
                        <TableCell className="text-zinc-700 dark:text-zinc-300 text-sm max-w-[180px] truncate" title={desc || undefined}>
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
                              riskScoreNum >= 4 ? "bg-red-100 text-red-800 dark:bg-red-900/40 dark:text-red-200" :
                              riskScoreNum >= 3 ? "bg-orange-100 text-orange-800 dark:bg-orange-900/40 dark:text-orange-200" :
                              riskScoreNum >= 2 ? "bg-amber-100 text-amber-800 dark:bg-amber-900/40 dark:text-amber-200" :
                              "bg-emerald-100 text-emerald-800 dark:bg-emerald-900/40 dark:text-emerald-200"
                            }`}
                            title="Risk score"
                          >
                            {riskScoreNum > 0 ? riskScoreNum : "—"}
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
                        <TableCell className="text-zinc-700 dark:text-zinc-300 text-sm max-w-[100px] truncate" title={category !== "—" ? category : undefined}>
                          {category}
                        </TableCell>
                        <TableCell className="text-zinc-700 dark:text-zinc-300 text-sm max-w-[100px] truncate" title={resource !== "—" ? resource : undefined}>
                          {resource}
                        </TableCell>
                        <TableCell onClick={(e) => e.stopPropagation()}>
                          <DropdownMenu>
                            <DropdownMenuTrigger asChild>
                              <Button variant="ghost" size="icon" className="h-8 w-8 cursor-pointer">
                                <MoreVertical className="h-4 w-4" />
                              </Button>
                            </DropdownMenuTrigger>
                            <DropdownMenuContent align="end">
                              <DropdownMenuItem className="cursor-pointer" onClick={() => toggleFindingMutation.mutate({ finding_id: f.id, state: "fixed" })} disabled={toggleFindingMutation.isPending}>
                                <CheckCircle className="h-4 w-4 mr-2" />
                                Mark as Fixed
                              </DropdownMenuItem>
                              <DropdownMenuItem className="cursor-pointer" onClick={() => toggleFindingMutation.mutate({ finding_id: f.id, state: "ignored" })} disabled={toggleFindingMutation.isPending}>
                                <EyeOff className="h-4 w-4 mr-2" />
                                Mark as Ignored
                              </DropdownMenuItem>
                              <DropdownMenuItem className="cursor-pointer" onClick={() => toggleFindingMutation.mutate({ finding_id: f.id, state: "in_progress" })} disabled={toggleFindingMutation.isPending}>
                                <Loader2 className="h-4 w-4 mr-2" />
                                Mark as In progress
                              </DropdownMenuItem>
                              <DropdownMenuItem className="cursor-pointer" onClick={() => toggleFindingMutation.mutate({ finding_id: f.id, state: "not_started" })} disabled={toggleFindingMutation.isPending}>
                                <Circle className="h-4 w-4 mr-2" />
                                Mark as Not started
                              </DropdownMenuItem>
                            </DropdownMenuContent>
                          </DropdownMenu>
                        </TableCell>
                      </TableRow>
                    );
                  })
                ) : !useFindingsMode && vulnerabilities.length > 0 ? (
                  vulnerabilities.map((vuln, idx) => {
                    const vTitle = vuln.title ?? "Untitled finding";
                    const impact = (vuln.impact ?? "").trim() || "—";
                    const owaspCount = getOwaspComplianceCount(vuln.owasp_top_10);
                    const complianceCount = getOwaspComplianceCount(vuln.compliance_controls);
                    return (
                      <TableRow
                        key={idx}
                        className={`cursor-pointer hover:bg-zinc-50 dark:hover:bg-zinc-800/50 ${selectedRows.has(idx) ? "bg-zinc-100 dark:bg-zinc-800/70" : ""}`}
                      >
                        <TableCell onClick={(e) => e.stopPropagation()} className="min-w-[48px] w-12">
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
                ) : (
                  <TableRow>
                    <TableCell colSpan={useFindingsMode ? 12 : 5} className="text-center py-8 text-zinc-500 dark:text-zinc-400">
                      No findings to display.
                    </TableCell>
                  </TableRow>
                )}
              </TableBody>
              </Table>
            </div>
            <ScrollBar orientation="horizontal" />
          </ScrollArea>
        </CardContent>
      </Card>

      <DependencyDiagramSection diagramCode={dependencyDiagram} />

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
                  {"risk_score" in selectedVuln && selectedVuln.risk_score != null && (
                    <div>
                      <div className="text-xs font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400 mb-1">Risk score</div>
                      <span className="text-sm font-medium tabular-nums text-zinc-700 dark:text-zinc-300">{selectedVuln.risk_score}</span>
                    </div>
                  )}
                  {"status" in selectedVuln && (selectedVuln.status ?? "").trim() && (
                    <div>
                      <div className="text-xs font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400 mb-1">Status</div>
                      <Badge variant="outline" className={getFindingStatusBadgeClass((selectedVuln as IACFinding).status!.trim())}>
                        {(selectedVuln as IACFinding).status!.trim()}
                      </Badge>
                    </div>
                  )}
                  {"category" in selectedVuln && (selectedVuln.category ?? "").trim() && (
                    <div>
                      <div className="text-xs font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400 mb-1">Category</div>
                      <p className="text-sm text-zinc-700 dark:text-zinc-300">{(selectedVuln as IACFinding).category!.trim()}</p>
                    </div>
                  )}
                  {"resource" in selectedVuln && (selectedVuln.resource ?? "").trim() && (
                    <div>
                      <div className="text-xs font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400 mb-1">Resource</div>
                      <p className="text-sm font-mono text-zinc-700 dark:text-zinc-300">{(selectedVuln as IACFinding).resource!.trim()}</p>
                    </div>
                  )}
                  {(selectedVuln.description ?? "").trim() && (
                    <div>
                      <div className="text-xs font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400 mb-1">Description</div>
                      <p className="text-sm text-zinc-700 dark:text-zinc-300">{selectedVuln.description!.trim()}</p>
                    </div>
                  )}
                  {(selectedVuln.location ?? "").trim() && (
                    <div>
                      <div className="text-xs font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400 mb-1">Location</div>
                      <p className="text-sm font-mono text-zinc-700 dark:text-zinc-300">{selectedVuln.location!.trim()}</p>
                    </div>
                  )}
                  {(selectedVuln.snippet ?? "").trim() && (
                    <div>
                      <div className="text-xs font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400 mb-1">Code snippet</div>
                      <pre className="text-xs bg-zinc-100 dark:bg-zinc-800 p-3 rounded overflow-x-auto whitespace-pre-wrap font-mono text-zinc-800 dark:text-zinc-200">
                        {selectedVuln.snippet!.trim()}
                      </pre>
                    </div>
                  )}
                  {(selectedVuln.suggested_fix ?? "").trim() && (
                    <div>
                      <div className="text-xs font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400 mb-1">Suggested fix</div>
                      <p className="text-sm text-zinc-700 dark:text-zinc-300">{selectedVuln.suggested_fix!.trim()}</p>
                    </div>
                  )}
                  {getOwaspComplianceEntries(selectedVuln.owasp_top_10 as OwaspOrCompliance).length > 0 && (
                    <div>
                      <div className="text-xs font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400 mb-1">OWASP Top 10</div>
                      <div className="flex flex-wrap gap-1">
                        {getOwaspComplianceEntries(selectedVuln.owasp_top_10 as OwaspOrCompliance).map(([, description], i) => (
                          <Badge key={i} variant="secondary" className="text-xs bg-purple-100 dark:bg-purple-900/40 text-purple-800 dark:text-purple-200">
                            {description}
                          </Badge>
                        ))}
                      </div>
                    </div>
                  )}
                  {getOwaspComplianceEntries(selectedVuln.compliance_controls as OwaspOrCompliance).length > 0 && (
                    <div>
                      <div className="text-xs font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400 mb-1">Compliance controls</div>
                      <div className="flex flex-wrap gap-1">
                        {getOwaspComplianceEntries(selectedVuln.compliance_controls as OwaspOrCompliance).map(([, description], i) => (
                          <Badge key={i} variant="outline" className="text-xs">
                            {description}
                          </Badge>
                        ))}
                      </div>
                    </div>
                  )}
                  {(() => {
                    const cves = selectedVuln.cves;
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
                  {'id' in selectedVuln && (
                    <RemediationPanel
                      teamId={teamId ?? ""}
                      scanType="iac"
                      scanId={conversationId ?? 0}
                      findingId={(selectedVuln as IACFinding).id}
                      existingRemediation={(selectedVuln as IACFinding).remediation}
                    />
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

export default function IACResults({ data, conversationId, dashboard, findings, scanMetadata, teamId: teamIdProp, integrationSettings, onIntegrationSettingsUpdated, onFindingsUpdated }: IACResultsProps) {
  const router = useRouter();
  const pathname = usePathname();
  const searchParams = useSearchParams();
  const origin = searchParams.get("origin");

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
  const teamId = params?.team_id as string | undefined;

  const exportMutation = useMutation({
    mutationFn: () => {
      const tid = teamId ? parseInt(teamId, 10) : NaN;
      if (conversationId == null || Number.isNaN(tid)) throw new Error("Missing team or scan");
      return getIACExportResults(tid, conversationId);
    },
    onSuccess: (blob) => {
      const url = URL.createObjectURL(new Blob([blob], { type: "application/pdf" }));
      const a = document.createElement("a");
      a.href = url;
      a.download = `iac_scan_${conversationId}_report.pdf`;
      a.click();
      URL.revokeObjectURL(url);
    },
    onError: (err) => {
      showErrorToast(err, "Failed to download scan report");
    },
  });

  const handleDownloadReport = () => exportMutation.mutate();
  const isExporting = exportMutation.isPending;

  const hasData = data != null && Array.isArray(data) && data.length > 0;
  const hasFindings = findings != null && findings.length > 0;
  if (!hasData && !hasFindings) {
    return (
      <div className="container mx-auto p-6 space-y-6">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-4">
            {(conversationId != null || isCicdContext) && (
              <Button
                variant="outline"
                size="icon"
                onClick={() => {
                  const backRoute =
                    isCicdContext && integrationId
                      ? `/home/ci_cd/${integrationId}`
                      : origin === "chat"
                        ? (teamId ? `/${teamId}/iac/${conversationId}` : `/home/iac/${conversationId}`)
                        : (teamId ? `/${teamId}/iac` : "/home/iac");
                  router.push(backRoute);
                }}
                className="cursor-pointer"
              >
                <ArrowLeft className="h-4 w-4" />
              </Button>
            )}
            <h1 className="text-3xl font-bold text-zinc-900 dark:text-white">IAC Scan Results</h1>
          </div>
          {!isCicdContext && teamId && conversationId != null && (
            <Button
              variant="default"
              className="cursor-pointer bg-blue-600 hover:bg-blue-700 text-white"
              onClick={() => router.push(`/${teamId}/iac/${conversationId}`)}
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
    <IACResultsAgentView
      vulnerabilities={data ?? []}
      conversationId={conversationId}
      teamId={teamId}
      isCicdContext={isCicdContext}
      integrationId={integrationId}
      origin={origin}
      router={router}
      onDownloadReport={teamId && conversationId != null ? handleDownloadReport : undefined}
      isExporting={isExporting}
      dashboard={dashboard}
      findings={findings}
      scanMetadata={scanMetadata}
      onFindingsUpdated={onFindingsUpdated}
      integrationSettings={integrationSettings}
      onIntegrationSettingsUpdated={onIntegrationSettingsUpdated}
    />
  );
}
