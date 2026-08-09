"use client";

import { useState, useMemo, useEffect } from "react";
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
  Github,
  GitBranch,
  Archive,
  Shield,
  Bot,
  Database,
  Cloud,
  ShieldCheck,
  ShieldAlert,
  Activity,
  Clock,
  Crosshair,
  Scale,
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
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { useRouter, useSearchParams, useParams } from "next/navigation";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { getAIBOMExportResults, updateScan, toggleFindingState, createTicket, postCertInAttestation, postCertInSign, getCertInVex, getCertInEvidencePack, type AiBomScanDashboardData, type AiBomFinding, type AiBomScanMetadata, type ScanTicketingIntegrationSettings } from "@/utils/backend_api";
import { showErrorToast } from "@/utils/error-handler";
import {
  buildRefAliasMap,
  findingMatchesRelatedRefs,
} from "@/utils/relatedFindingMatch";
import { OWASP_LLM_KEY_TO_LABEL, COMPLIANCE_KEY_TO_LABEL, OWASP_COLORS } from "@/lib/owasp-compliance-labels";
import { FRAMEWORK_LABELS } from "@/components/compliance/frameworkLabels";

function complianceChartLabel(key: string): string {
  const full =
    COMPLIANCE_KEY_TO_LABEL[key] ?? FRAMEWORK_LABELS[key] ?? key;
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
import { PieChart, BarChart3, TrendingUp, Search, Filter, ChevronDown, Check, X } from "lucide-react";
import {
  AiBomVisualizations,
  type Compliance as AiBomCompliance,
  type Graph as AiBomGraph,
  type Scores as AiBomScores,
} from "@/components/ai-bom/AiBomVisualizations";
import { RbiCsfRollup, type RbiCsfRollupData } from "@/components/rbi/RbiCsfRollup";
import { CertInLanePosture } from "@/components/certin/CertInLanePosture";
import { type CertInRollupData } from "@/components/certin/certinShared";
import { toast } from "sonner";
import TicketingIntegrationsSettings from "@/components/ticketing-integrations-settings";
import FindingSelectionMenu from "@/components/finding-selection-menu";

interface AiBomResultsProps {
  data: unknown;
  conversationId?: number;
  teamId?: string;
  dashboard?: AiBomScanDashboardData | null;
  findings?: AiBomFinding[] | null;
  scanMetadata?: AiBomScanMetadata | Record<string, unknown> | null;
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

const RISK_SCORE_LABELS: Record<RiskScoreFilter, string> = {
  all: "Risk score",
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
};

export default function AiBomResults({
  data,
  conversationId,
  teamId,
  dashboard,
  findings: findingsList = [],
  scanMetadata,
  integrationSettings,
  onIntegrationSettingsUpdated,
  onFindingsUpdated,
}: AiBomResultsProps) {
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
  const [licenseFilter, setLicenseFilter] = useState("all");
  const [typeFilter, setTypeFilter] = useState("all");
  const [providerFilter, setProviderFilter] = useState("all");
  const [filterImpact, setFilterImpact] = useState("all");
  const [filterRiskScore, setFilterRiskScore] = useState<RiskScoreFilter>("all");
  const [selectedFinding, setSelectedFinding] = useState<AiBomFinding | null>(null);
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

  const relatedRefAliases = useMemo(() => {
    const fromMeta = (scanMetadata as AiBomScanMetadata | null)?.ai_bom_graph as
      | { nodes?: { id?: string; label?: string }[] }
      | undefined;
    return buildRefAliasMap(fromMeta?.nodes);
  }, [scanMetadata]);

  const filteredFindings = useMemo(() => {
    if (!findingsList) return [];
    return findingsList.filter((f, i) => {
      const q = searchQuery.toLowerCase();
      const name = (f.asset_name || f.title || "").toLowerCase();
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
      const matchLicense = licenseFilter === "all" || f.license_type === licenseFilter;
      const matchType = typeFilter === "all" || f.asset_type === typeFilter;
      const matchProvider = providerFilter === "all" || f.provider === providerFilter;
      const matchImpact = filterImpact === "all" || (f.impact || "").toLowerCase() === filterImpact.toLowerCase();
      const matchRisk = matchesRiskScoreFilter(f.risk_score, filterRiskScore);
      return matchSearch && matchRefs && matchLicense && matchType && matchProvider && matchImpact && matchRisk;
    });
  }, [findingsList, searchQuery, relatedFindingRefs, relatedRefAliases, licenseFilter, typeFilter, providerFilter, filterImpact, filterRiskScore]);

  const handleViewRelatedFindings = (refs: string[]) => {
    setRelatedFindingRefs(refs);
    setSearchQuery("");
    requestAnimationFrame(() => {
      document.getElementById("bom-findings")?.scrollIntoView({ behavior: "smooth", block: "start" });
    });
  };

  const uniqueTypes = useMemo(() => {
    if (!findingsList) return [];
    const types = new Set(findingsList.map((f) => f.asset_type).filter(Boolean) as string[]);
    return Array.from(types).sort();
  }, [findingsList]);

  const uniqueProviders = useMemo(() => {
    if (!findingsList) return [];
    const providers = new Set(findingsList.map((f) => f.provider).filter(Boolean) as string[]);
    return Array.from(providers).sort();
  }, [findingsList]);

  const uniqueLicenses = useMemo(() => {
    if (!findingsList) return [];
    const licenses = new Set(findingsList.map((f) => f.license_type).filter(Boolean) as string[]);
    return Array.from(licenses).sort();
  }, [findingsList]);

  const tid = parseInt(String(team_id ?? "0"), 10);
  const sid = typeof scan_id === "number" ? scan_id : parseInt(String(scan_id), 10);

  const updateIntegrationMutation = useMutation({
    mutationFn: (payload: { integration_settings: ScanTicketingIntegrationSettings }) =>
      updateScan({ team_id: tid, type: "ai_bom", scan_id: sid, data: payload }),
    onSuccess: () => {
      onIntegrationSettingsUpdated?.();
      queryClient.invalidateQueries({ queryKey: ["ai_bom-conversation-data"] });
      toast.success("Ticketing settings saved");
    },
    onError: (err) => showErrorToast(err, "Failed to save ticketing settings"),
  });

  const toggleFindingMutation = useMutation({
    mutationFn: ({ finding_id, state }: { finding_id: string; state: "fixed" | "ignored" | "in_progress" | "not_started" }) => {
      if (!sid || Number.isNaN(tid)) throw new Error("Missing team or scan");
      return toggleFindingState({ team_id: tid, type: "ai_bom", scan_id: sid, finding_id, state });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["ai_bom-conversation-data"] });
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
      summary = summary + " - AI governance risks found in AI BOM scan";

      const descSections = selected.map((f, idx) => {
        const parts: string[] = [`--- Finding ${idx + 1} ---`];
        parts.push(`Asset: ${(f.asset_name ?? f.title ?? "Unknown").trim()}`);
        if ((f.asset_type ?? "").trim()) parts.push(`Type: ${f.asset_type!.trim()}`);
        if ((f.provider ?? "").trim()) parts.push(`Provider: ${f.provider!.trim()}`);
        if ((f.license_type ?? "").trim()) parts.push(`License: ${f.license_type!.trim()}`);
        if ((f.impact ?? "").trim()) parts.push(`Impact: ${f.impact!.trim()}`);
        if (f.risk_score != null) parts.push(`Risk Score: ${f.risk_score}`);
        if ((f.location ?? "").trim()) parts.push(`Location: ${f.location!.trim()}`);
        if ((f.risk_category ?? "").trim()) parts.push(`Risk Category: ${f.risk_category!.trim()}`);
        if ((f.suggested_fix ?? "").trim()) parts.push(`Suggested Fix: ${f.suggested_fix!.trim()}`);
        return parts.join("\n");
      });
      const description = descSections.join("\n\n");

      await createTicket(tid, "ai_bom", sid, {
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
        await toggleFindingState({ team_id: tid, type: "ai_bom", scan_id: sid, finding_id, state });
      }
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["ai_bom-conversation-data"] });
      onFindingsUpdated?.();
      toast.success(`Updated ${selectedFindings.size} finding(s)`);
      setSelectedFindings(new Set());
    },
    onError: (err) => showErrorToast(err, "Error updating finding status"),
  });

  const exportMutation = useMutation({
    mutationFn: () => {
      if (Number.isNaN(tid) || Number.isNaN(sid) || !tid || !sid) {
        throw new Error("Missing or invalid team or scan id");
      }
      return getAIBOMExportResults(tid, sid);
    },
    onSuccess: (result) => {
      const blob = result instanceof Blob ? result : new Blob([result]);
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `ai-bom-report-${scan_id}.pdf`;
      a.click();
      URL.revokeObjectURL(url);
      toast.success("Report downloaded");
    },
    onError: (err) => showErrorToast(err, "Error exporting PDF"),
  });

  const handleDownloadAiBomJson = () => {
    const metaRecord = scanMetadata as Record<string, unknown> | null;
    const aiBomJson = metaRecord?.ai_bom_json ?? (data as Record<string, unknown> | null)?.ai_bom_json;
    if (!aiBomJson) { toast.error("No AI BOM JSON available"); return; }
    try {
      const blob = new Blob([JSON.stringify(aiBomJson, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `ai-bom-${scan_id}.json`;
      a.click();
      URL.revokeObjectURL(url);
      toast.success("AI BOM JSON downloaded");
    } catch (err) {
      showErrorToast(err, "Failed to download AI BOM JSON");
    }
  };

  // Raw BOM artifacts (SPDX 3.0 / SARIF 2.1.0) — same client-side blob download
  // as the CycloneDX JSON above.
  const handleDownloadArtifact = (
    key: "ai_bom_spdx" | "ai_bom_sarif",
    ext: string,
    label: string,
  ) => {
    const metaRecord = scanMetadata as Record<string, unknown> | null;
    const artifact =
      metaRecord?.[key] ?? (data as Record<string, unknown> | null)?.[key];
    if (!artifact) { toast.error(`No ${label} available`); return; }
    try {
      const blob = new Blob([JSON.stringify(artifact, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `ai-bom-${scan_id}.${ext}`;
      a.click();
      URL.revokeObjectURL(url);
      toast.success(`${label} downloaded`);
    } catch (err) {
      showErrorToast(err, `Failed to download ${label}`);
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
    await postCertInAttestation(tid, "ai_bom", sid, frameworkKey, requirementId, file);
    queryClient.invalidateQueries({ queryKey: ["ai_bom-conversation-data"] });
  };

  const handleDownloadVex = async () => {
    try {
      const cached = (scanMetadata as AiBomScanMetadata | null)?.vex_json;
      const vex = cached ?? (await getCertInVex(tid, "ai_bom", sid));
      downloadBlob(
        new Blob([JSON.stringify(vex, null, 2)], { type: "application/json" }),
        `ai-bom-vex-${scan_id}.json`,
      );
      toast.success("VEX downloaded");
      queryClient.invalidateQueries({ queryKey: ["ai_bom-conversation-data"] });
    } catch (err) {
      showErrorToast(err, "Failed to download VEX");
    }
  };

  const handleDownloadSignature = async () => {
    try {
      let sig = (scanMetadata as AiBomScanMetadata | null)?.bom_signature;
      if (!sig) {
        const res = await postCertInSign(tid, "ai_bom", sid);
        sig = res.bom_signature;
        queryClient.invalidateQueries({ queryKey: ["ai_bom-conversation-data"] });
      }
      downloadBlob(
        new Blob([JSON.stringify(sig, null, 2)], { type: "application/json" }),
        `ai-bom-signature-${scan_id}.json`,
      );
      toast.success("BOM signature downloaded");
    } catch (err) {
      showErrorToast(err, "Failed to download BOM signature");
    }
  };

  const handleDownloadEvidencePack = async () => {
    try {
      const blob = await getCertInEvidencePack(tid, "ai_bom", sid);
      downloadBlob(blob, `certin-evidence-pack-ai_bom-${scan_id}.zip`);
      toast.success("Evidence pack downloaded");
      queryClient.invalidateQueries({ queryKey: ["ai_bom-conversation-data"] });
    } catch (err) {
      showErrorToast(err, "Failed to download evidence pack");
    }
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

  const assetTypeData = useMemo(() => {
    if (!dashboard) return [];
    return Object.entries(dashboard.asset_type_distribution)
      .map(([name, count]) => ({ name: name.replace(/_/g, " "), count }))
      .filter((d) => d.count > 0)
      .sort((a, b) => b.count - a.count);
  }, [dashboard]);

  const providerData = useMemo(() => {
    if (!dashboard) return [];
    return Object.entries(dashboard.provider_distribution)
      .map(([name, count]) => ({ name: name.replace(/_/g, " "), count }))
      .filter((d) => d.count > 0)
      .sort((a, b) => b.count - a.count);
  }, [dashboard]);

  const licenseData = useMemo(() => {
    if (!dashboard) return [];
    const COLORS = [
      "hsl(220 70% 50%)",
      "hsl(142 71% 45%)",
      "hsl(45 93% 47%)",
      "hsl(0 72% 51%)",
      "hsl(280 65% 55%)",
      "hsl(190 80% 45%)",
    ];
    return Object.entries(dashboard.license_distribution)
      .map(([name, count], i) => ({
        name: name.charAt(0).toUpperCase() + name.slice(1),
        count,
        fill: COLORS[i % COLORS.length],
      }))
      .filter((d) => d.count > 0);
  }, [dashboard]);

  const riskCategoryData = useMemo(() => {
    if (!dashboard?.risk_category_distribution) return [];
    const COLORS = [
      "hsl(0 72% 51%)",
      "hsl(25 90% 52%)",
      "hsl(45 93% 47%)",
      "hsl(220 70% 50%)",
      "hsl(142 71% 45%)",
      "hsl(280 65% 55%)",
    ];
    return Object.entries(dashboard.risk_category_distribution)
      .map(([name, count], i) => ({
        name: name.replace(/_/g, " "),
        count,
        fill: COLORS[i % COLORS.length],
      }))
      .filter((d) => d.count > 0);
  }, [dashboard]);

  // OWASP LLM Top 10 data — dashboard keys are LLM01..LLM10 short codes
  const owaspMetrics = useMemo(() => dashboard?.owasp_top_10_llm_issues ?? {}, [dashboard]);
  const owaspEntries = useMemo(() => {
    return Object.entries(owaspMetrics).map(([key, actualCount], index) => {
      // Prefer 2025 short-code labels; fall back to raw key (legacy full label).
      const displayValue = OWASP_LLM_KEY_TO_LABEL[key] ?? key;
      return {
        name: displayValue.length > 28 ? `${displayValue.slice(0, 28)}...` : displayValue,
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
  const complianceMetrics = useMemo(() => dashboard?.compliance_controls ?? {}, [dashboard]);
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
      .map((f) => ({ finding: f.asset_name || f.title, score: f.risk_score, fullName: f.asset_name || f.title }))
      .sort((a, b) => b.score - a.score)
      .slice(0, 24)
      .map((row, i) => ({ ...row, finding: `F${i + 1}` }));
  }, [findingsList]);
  const hasRiskScoresData = riskScoresAreaData.length > 0;

  const hasRiskData = severityRadarData.some((d) => d.count > 0);
  const criticalCount = dashboard?.severity_distribution?.critical ?? 0;
  const meta = scanMetadata as AiBomScanMetadata | null;

  const showTabs = team_id && scan_id != null;
  const hasTicketingTab = showTabs && onIntegrationSettingsUpdated != null;

  return (
    <div className="container mx-auto p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          {origin === "chat" && (
            <Button
              variant="outline"
              size="icon"
              onClick={() => router.back()}
              className="cursor-pointer"
            >
              <ArrowLeft className="h-4 w-4" />
            </Button>
          )}
          <div>
            <h1 className="text-3xl font-bold text-zinc-900 dark:text-white flex items-center gap-2">
              <Bot className="h-6 w-6 text-blue-600 dark:text-blue-400" />
              AI BOM Scan Results
            </h1>
            <p className="text-sm text-zinc-600 dark:text-zinc-400 mt-1">
              Agent analysis of AI assets, providers, and governance readiness
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="outline" className="cursor-pointer">
                <Download className="h-4 w-4 mr-2" />
                Download BOM
                <ChevronDown className="h-4 w-4 ml-1.5 opacity-60" />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end" className="min-w-[210px]">
              <DropdownMenuLabel>Bill of Materials</DropdownMenuLabel>
              <DropdownMenuItem className="cursor-pointer" onClick={handleDownloadAiBomJson}>
                CycloneDX 1.6 (JSON)
              </DropdownMenuItem>
              <DropdownMenuItem
                className="cursor-pointer"
                onClick={() => handleDownloadArtifact("ai_bom_spdx", "spdx.json", "SPDX 3.0")}
              >
                SPDX 3.0 (JSON-LD)
              </DropdownMenuItem>
              <DropdownMenuItem
                className="cursor-pointer"
                onClick={() => handleDownloadArtifact("ai_bom_sarif", "sarif", "SARIF 2.1.0")}
              >
                SARIF 2.1.0
              </DropdownMenuItem>
              <DropdownMenuSeparator />
              <DropdownMenuLabel>CERT-In (advisory)</DropdownMenuLabel>
              <DropdownMenuItem className="cursor-pointer" onClick={() => void handleDownloadVex()}>
                VEX
              </DropdownMenuItem>
              <DropdownMenuItem className="cursor-pointer" onClick={() => void handleDownloadSignature()}>
                Signature JSON
              </DropdownMenuItem>
              <DropdownMenuItem className="cursor-pointer" onClick={() => void handleDownloadEvidencePack()}>
                Evidence pack (ZIP)
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
          <Button
            variant="outline"
            className="cursor-pointer"
            onClick={() => exportMutation.mutate()}
            disabled={exportMutation.isPending}
          >
            {exportMutation.isPending ? (
              <Loader2 className="h-4 w-4 mr-2 animate-spin" />
            ) : (
              <Download className="h-4 w-4 mr-2" />
            )}
            {exportMutation.isPending ? "Downloading..." : "PDF Report"}
          </Button>
          <Button
            variant="default"
            className="cursor-pointer bg-blue-600 hover:bg-blue-700 text-white"
            onClick={() => router.push(`/${team_id}/ai_bom/${scan_id}`)}
          >
            <MessageCircle className="h-4 w-4 mr-2" />
            Chat with the Results
          </Button>
        </div>
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
              integration_settings: {
                jira: { jira_project_id: jiraProjectId.trim() || null },
              },
            });
          }}
          isSaving={updateIntegrationMutation.isPending}
          inputId="ai-bom-jira-project-id"
        />
      ) : (
        <>
          {/* Scan metadata */}
          {scanMetadata && typeof scanMetadata === "object" && (
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
              {meta?.repo_url != null && String(meta.repo_url).trim() !== "" && (
                <Card className="border-zinc-200 dark:border-zinc-800">
                  <CardContent className="pt-4 pb-4 flex items-center gap-3">
                    <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-violet-100 dark:bg-violet-900/30 text-violet-600 dark:text-violet-400">
                      <Github className="h-5 w-5" />
                    </div>
                    <div className="min-w-0 flex-1 overflow-hidden">
                      <p className="text-xs font-medium text-zinc-500 dark:text-zinc-400">Repository</p>
                      <p className="text-sm font-semibold text-zinc-900 dark:text-zinc-100 truncate" title={String(meta.repo_url)}>{String(meta.repo_url)}</p>
                    </div>
                  </CardContent>
                </Card>
              )}
              {meta?.branch != null && String(meta.branch).trim() !== "" && (
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
              {meta?.zip_file_used && (
                <Card className="border-zinc-200 dark:border-zinc-800">
                  <CardContent className="pt-4 pb-4 flex items-center gap-3">
                    <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-zinc-100 dark:bg-zinc-800 text-zinc-600 dark:text-zinc-400">
                      <Archive className="h-5 w-5" />
                    </div>
                    <div className="min-w-0">
                      <p className="text-xs font-medium text-zinc-500 dark:text-zinc-400">Source</p>
                      <p className="text-sm font-semibold text-zinc-900 dark:text-zinc-100">ZIP upload</p>
                    </div>
                  </CardContent>
                </Card>
              )}
              {meta?.ai_bom_file_used && (
                <Card className="border-zinc-200 dark:border-zinc-800">
                  <CardContent className="pt-4 pb-4 flex items-center gap-3">
                    <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-blue-100 dark:bg-blue-900/30 text-blue-600 dark:text-blue-400">
                      <Bot className="h-5 w-5" />
                    </div>
                    <div className="min-w-0">
                      <p className="text-xs font-medium text-zinc-500 dark:text-zinc-400">Input</p>
                      <p className="text-sm font-semibold text-zinc-900 dark:text-zinc-100">AI BOM file</p>
                    </div>
                  </CardContent>
                </Card>
              )}
            </div>
          )}

          {/* Dashboard Summary */}
          {dashboard && cardData && (
            <div className="space-y-6">
              {/* Summary Cards */}
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 xl:grid-cols-8 gap-4">
                {[
                  { label: "AI Assets", value: cardData.total_ai_assets, icon: Bot, color: "bg-blue-100 dark:bg-blue-900/30 text-blue-600 dark:text-blue-400" },
                  { label: "Models", value: cardData.total_models, icon: Bot, color: "bg-violet-100 dark:bg-violet-900/30 text-violet-600 dark:text-violet-400" },
                  { label: "Datasets", value: cardData.total_datasets, icon: Database, color: "bg-teal-100 dark:bg-teal-900/30 text-teal-600 dark:text-teal-400" },
                  { label: "External Providers", value: cardData.total_external_providers, icon: Cloud, color: "bg-amber-100 dark:bg-amber-900/30 text-amber-600 dark:text-amber-400" },
                  { label: "High Risk", value: cardData.total_high_risk_assets, icon: ShieldAlert, color: "bg-red-100 dark:bg-red-900/30 text-red-600 dark:text-red-400" },
                  { label: "Unlicensed", value: cardData.total_unlicensed_assets, icon: Scale, color: "bg-orange-100 dark:bg-orange-900/30 text-orange-600 dark:text-orange-400" },
                  { label: "Governance Ready", value: `${cardData.governance_readiness_score}%`, icon: Shield, color: "bg-emerald-100 dark:bg-emerald-900/30 text-emerald-600 dark:text-emerald-400" },
                  { label: "Avg Risk", value: cardData.average_risk_score?.toFixed(1) ?? "N/A", icon: Activity, color: "bg-pink-100 dark:bg-pink-900/30 text-pink-600 dark:text-pink-400" },
                ].map((c) => (
                  <Card key={c.label} className="border-zinc-200 dark:border-zinc-800">
                    <CardContent className="pt-4 pb-4 flex items-center gap-3">
                      <div className={`flex h-10 w-10 shrink-0 items-center justify-center rounded-lg ${c.color}`}>
                        <c.icon className="h-5 w-5" />
                      </div>
                      <div className="min-w-0">
                        <p className="text-xs font-medium text-zinc-500 dark:text-zinc-400">{c.label}</p>
                        <p className="text-lg font-semibold text-zinc-900 dark:text-zinc-100 tabular-nums">{c.value}</p>
                      </div>
                    </CardContent>
                  </Card>
                ))}
              </div>

              {/* Remediation Progress */}
              {remediation && (
                <Card className="border-zinc-200 dark:border-zinc-800">
                  <CardHeader>
                    <CardTitle className="text-base">Remediation Progress</CardTitle>
                    <CardDescription>Finding status breakdown</CardDescription>
                  </CardHeader>
                  <CardContent className="space-y-2">
                    <div className="flex flex-wrap items-center gap-4 text-sm text-zinc-600 dark:text-zinc-400">
                      <span>Fixed: <span className="text-emerald-600 dark:text-emerald-400 font-medium">{remediation.total_fixed}</span></span>
                      <span>In Progress: <span className="text-blue-600 dark:text-blue-400 font-medium">{remediation.total_in_progress}</span></span>
                      <span>Not Started: <span className="text-zinc-700 dark:text-zinc-300 font-medium">{remediation.total_not_started}</span></span>
                      <span>Ignored: <span className="text-zinc-500 dark:text-zinc-400 font-medium">{remediation.total_ignored}</span></span>
                    </div>
                    <Progress value={(remediation.total_fixed / totalFindings) * 100} className="h-2" />
                    <p className="text-xs text-zinc-500 dark:text-zinc-400">{remediation.total_fixed}/{totalFindings} findings resolved</p>
                  </CardContent>
                </Card>
              )}

              {/* Row 1: OWASP + Risk Radar + Compliance */}
              <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                {/* OWASP LLM Top 10 */}
                <Card className="border-zinc-200 dark:border-zinc-800">
                  <CardHeader>
                    <CardTitle className="text-base flex items-center gap-2">
                      <PieChart className="w-4 h-4" />
                      OWASP LLM Top 10
                    </CardTitle>
                    <CardDescription>Distribution by OWASP LLM category</CardDescription>
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
                      <ChartContainer
                        config={complianceBarChartConfig}
                        className="mx-auto aspect-auto w-full cursor-pointer"
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

              {/* Row 2: AI BOM-specific charts */}
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                {/* Asset Types */}
                <Card className="border-zinc-200 dark:border-zinc-800">
                  <CardHeader>
                    <CardTitle className="text-base flex items-center gap-2">
                      <BarChart3 className="w-4 h-4" />
                      Asset Types
                    </CardTitle>
                    <CardDescription>Distribution by AI asset type</CardDescription>
                  </CardHeader>
                  <CardContent>
                    {assetTypeData.length === 0 ? (
                      <div className="flex items-center justify-center min-h-[280px] text-zinc-500 dark:text-zinc-400 text-sm">No asset type data available</div>
                    ) : (
                      <ChartContainer config={barConfig} className="mx-auto aspect-auto h-[280px] w-full max-h-[280px]">
                        <BarChart data={assetTypeData} layout="vertical" margin={{ top: 0, right: 8, bottom: 0, left: 0 }}>
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

                {/* Providers */}
                <Card className="border-zinc-200 dark:border-zinc-800">
                  <CardHeader>
                    <CardTitle className="text-base flex items-center gap-2">
                      <Cloud className="w-4 h-4" />
                      Providers
                    </CardTitle>
                    <CardDescription>Distribution by AI provider</CardDescription>
                  </CardHeader>
                  <CardContent>
                    {providerData.length === 0 ? (
                      <div className="flex items-center justify-center min-h-[280px] text-zinc-500 dark:text-zinc-400 text-sm">No provider data available</div>
                    ) : (
                      <ChartContainer config={barConfig} className="mx-auto aspect-auto h-[280px] w-full max-h-[280px]">
                        <BarChart data={providerData} layout="vertical" margin={{ top: 0, right: 8, bottom: 0, left: 0 }}>
                          <CartesianGrid horizontal={false} className="stroke-zinc-200 dark:stroke-zinc-800" />
                          <XAxis type="number" tickLine={false} axisLine={false} className="text-xs" />
                          <YAxis dataKey="name" type="category" width={120} tickLine={false} axisLine={false} className="text-xs" />
                          <ChartTooltip content={<ChartTooltipContent />} />
                          <Bar dataKey="count" fill="hsl(280 65% 55%)" radius={[0, 4, 4, 0]} />
                        </BarChart>
                      </ChartContainer>
                    )}
                  </CardContent>
                </Card>

                {/* License Distribution */}
                <Card className="border-zinc-200 dark:border-zinc-800">
                  <CardHeader>
                    <CardTitle className="text-base flex items-center gap-2">
                      <Scale className="w-4 h-4" />
                      License Distribution
                    </CardTitle>
                    <CardDescription>Distribution by license type</CardDescription>
                  </CardHeader>
                  <CardContent>
                    {licenseData.length === 0 ? (
                      <div className="flex items-center justify-center min-h-[280px] text-zinc-500 dark:text-zinc-400 text-sm">No license data available</div>
                    ) : (
                      <ChartContainer config={barConfig} className="mx-auto aspect-auto h-[280px] w-full max-h-[280px]">
                        <BarChart data={licenseData} margin={{ top: 8, right: 8, bottom: 8, left: 0 }}>
                          <CartesianGrid vertical={false} className="stroke-zinc-200 dark:stroke-zinc-800" />
                          <XAxis dataKey="name" tickLine={false} axisLine={false} tickMargin={8} className="text-xs" />
                          <YAxis tickLine={false} axisLine={false} className="text-xs" />
                          <ChartTooltip content={<ChartTooltipContent />} />
                          <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                            {licenseData.map((entry, index) => (
                              <Cell key={`cell-${index}`} fill={entry.fill} />
                            ))}
                          </Bar>
                        </BarChart>
                      </ChartContainer>
                    )}
                  </CardContent>
                </Card>

                {/* Risk Category Distribution */}
                <Card className="border-zinc-200 dark:border-zinc-800">
                  <CardHeader>
                    <CardTitle className="text-base flex items-center gap-2">
                      <ShieldAlert className="w-4 h-4" />
                      Risk Categories
                    </CardTitle>
                    <CardDescription>Distribution by risk category</CardDescription>
                  </CardHeader>
                  <CardContent>
                    {riskCategoryData.length === 0 ? (
                      <div className="flex items-center justify-center min-h-[280px] text-zinc-500 dark:text-zinc-400 text-sm">No risk category data available</div>
                    ) : (
                      <ChartContainer config={barConfig} className="mx-auto aspect-auto h-[280px] w-full max-h-[280px]">
                        <BarChart data={riskCategoryData} margin={{ top: 8, right: 8, bottom: 8, left: 0 }}>
                          <CartesianGrid vertical={false} className="stroke-zinc-200 dark:stroke-zinc-800" />
                          <XAxis dataKey="name" tickLine={false} axisLine={false} tickMargin={8} className="text-xs" />
                          <YAxis tickLine={false} axisLine={false} className="text-xs" />
                          <ChartTooltip content={<ChartTooltipContent />} />
                          <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                            {riskCategoryData.map((entry, index) => (
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
                      Risk Scores per Finding
                    </CardTitle>
                    <CardDescription>Risk score by finding (top 24, descending)</CardDescription>
                  </CardHeader>
                  <CardContent>
                    {!hasRiskScoresData ? (
                      <div className="flex items-center justify-center min-h-[280px] text-zinc-500 dark:text-zinc-400 text-sm">No risk score data to display</div>
                    ) : (
                      <ChartContainer config={riskScoreAreaChartConfig} className="aspect-auto h-[280px] w-full pb-8 cursor-pointer">
                        <AreaChart data={riskScoresAreaData} margin={{ top: 8, right: 8, bottom: 28, left: 0 }}>
                          <defs>
                            <linearGradient id="fillAiBomRiskScore" x1="0" y1="0" x2="0" y2="1">
                              <stop offset="5%" stopColor="hsl(217 91% 60%)" stopOpacity={0.8} />
                              <stop offset="95%" stopColor="hsl(217 91% 60%)" stopOpacity={0.1} />
                            </linearGradient>
                          </defs>
                          <CartesianGrid vertical={false} className="stroke-zinc-200 dark:stroke-zinc-800" />
                          <XAxis dataKey="finding" tickLine={false} axisLine={false} tickMargin={8} minTickGap={16} height={56} interval={0} />
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
                          <Area type="monotone" dataKey="score" fill="url(#fillAiBomRiskScore)" stroke="hsl(217 91% 60%)" strokeWidth={2} />
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
            </div>
          )}

          {/* AI BOM-specific governance & lineage visualizations */}
          <AiBomVisualizations
            compliance={meta?.ai_bom_compliance as AiBomCompliance | undefined}
            graph={meta?.ai_bom_graph as AiBomGraph | undefined}
            graphCompact={meta?.ai_bom_graph_compact as AiBomGraph | undefined}
            graphExpanded={meta?.ai_bom_graph_expanded as AiBomGraph | undefined}
            scores={meta?.ai_bom_scores as AiBomScores | undefined}
            aiBomJson={meta?.ai_bom_json as Record<string, unknown> | undefined}
            findings={(findingsList ?? []) as unknown as Record<string, unknown>[]}
            onAttest={handleCertInAttest}
            onOpenFinding={(f) =>
              setSelectedFinding(f as unknown as AiBomFinding)
            }
          />
          <RbiCsfRollup
            rollup={meta?.rbi_csf_rollup as RbiCsfRollupData | undefined}
            onAttest={handleCertInAttest}
            onViewFindings={handleViewRelatedFindings}
            findings={findingsList ?? []}
            refAliases={relatedRefAliases}
          />
          <CertInLanePosture
            lane="aibom"
            rollup={meta?.certin_posture as CertInRollupData | undefined}
            onAttest={handleCertInAttest}
            onViewFindings={handleViewRelatedFindings}
            findings={findingsList ?? []}
            refAliases={relatedRefAliases}
          />

          {/* Findings Table */}
          <Card id="bom-findings">
            <CardHeader>
              <CardTitle>AI Asset Findings</CardTitle>
              <CardDescription>
                {filteredFindings.length} of {(findingsList ?? []).length} findings. Select rows to create Jira tickets or bulk-change status; use Actions to change finding state.
              </CardDescription>
            </CardHeader>
            <CardContent>
              {/* Filters */}
              <div className="flex flex-wrap items-center gap-3 mb-4">
                <div className="relative flex-1 min-w-[200px] max-w-sm">
                  <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-zinc-400" />
                  <Input
                    type="search"
                    placeholder="Search findings..."
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
                  <SelectTrigger className="h-9 min-w-[130px] cursor-pointer">
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
                <Select value={typeFilter} onValueChange={setTypeFilter}>
                  <SelectTrigger className="h-9 min-w-[160px] cursor-pointer">
                    <SelectValue placeholder="Type" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All types</SelectItem>
                    {uniqueTypes.map((t) => (
                      <SelectItem key={t} value={t}>{t.replace(/_/g, " ")}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                <Select value={providerFilter} onValueChange={setProviderFilter}>
                  <SelectTrigger className="h-9 min-w-[150px] cursor-pointer">
                    <SelectValue placeholder="Provider" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All providers</SelectItem>
                    {uniqueProviders.map((p) => (
                      <SelectItem key={p} value={p}>{p}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                <Select value={licenseFilter} onValueChange={setLicenseFilter}>
                  <SelectTrigger className="h-9 min-w-[150px] cursor-pointer">
                    <SelectValue placeholder="License" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All licenses</SelectItem>
                    {uniqueLicenses.map((l) => (
                      <SelectItem key={l} value={l}>{l}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                {(searchQuery !== "" ||
                  filterImpact !== "all" ||
                  filterRiskScore !== "all" ||
                  licenseFilter !== "all" ||
                  typeFilter !== "all" ||
                  providerFilter !== "all") && (
                  <Button
                    variant="ghost"
                    size="sm"
                    className="h-9 text-zinc-500 hover:text-zinc-700 cursor-pointer"
                    onClick={() => {
                      setSearchQuery("");
                      setFilterImpact("all");
                      setFilterRiskScore("all");
                      setLicenseFilter("all");
                      setTypeFilter("all");
                      setProviderFilter("all");
                    }}
                  >
                    <X className="h-4 w-4 mr-1" />
                    Clear filters
                  </Button>
                )}
              </div>
              <FindingSelectionMenu
                selectedCount={selectedFindings.size}
                onClearSelection={() => setSelectedFindings(new Set())}
                ticketType="jira"
                jiraOnClickHandler={() => createJiraTicketsMutation.mutate()}
                isJiraCreating={createJiraTicketsMutation.isPending}
                onBulkStatusChange={(status) => bulkStatusMutation.mutate(status)}
                isBulkStatusChanging={bulkStatusMutation.isPending}
              />
              <ScrollArea className="h-[500px] w-full rounded-md border border-zinc-200 dark:border-zinc-800">
                <div className="min-w-max">
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead className="w-[48px]">
                          <Checkbox
                            checked={filteredFindings.length > 0 && selectedFindings.size === filteredFindings.length}
                            onCheckedChange={(checked) => {
                              if (checked) {
                                setSelectedFindings(new Set(filteredFindings.map((f) => f.id)));
                              } else {
                                setSelectedFindings(new Set());
                              }
                            }}
                            aria-label="Select all rows"
                            className="cursor-pointer"
                          />
                        </TableHead>
                        <TableHead className="min-w-[180px]">Asset</TableHead>
                        <TableHead className="min-w-[120px]">Type</TableHead>
                        <TableHead className="min-w-[120px]">Provider</TableHead>
                        <TableHead className="min-w-[110px]">License</TableHead>
                        <TableHead className="min-w-[130px]">Risk</TableHead>
                        <TableHead className="min-w-[90px]">Impact</TableHead>
                        <TableHead className="min-w-[90px] text-center">Risk score</TableHead>
                        <TableHead className="min-w-[140px]">Location</TableHead>
                        <TableHead className="min-w-[100px]">Status</TableHead>
                        <TableHead className="min-w-[100px] text-right">Actions</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {filteredFindings.length === 0 ? (
                        <TableRow>
                          <TableCell colSpan={11} className="text-center py-8 text-zinc-500 dark:text-zinc-400">
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
                              className={`cursor-pointer hover:bg-zinc-50 dark:hover:bg-zinc-800/50 ${selectedFindings.has(finding.id) ? "bg-zinc-100 dark:bg-zinc-800/70" : ""}`}
                              onClick={() => setSelectedFinding(finding)}
                            >
                              <TableCell onClick={(e) => e.stopPropagation()} className="w-[48px]">
                                <Checkbox
                                  checked={selectedFindings.has(finding.id)}
                                  onCheckedChange={(checked) => {
                                    const next = new Set(selectedFindings);
                                    if (checked) next.add(finding.id);
                                    else next.delete(finding.id);
                                    setSelectedFindings(next);
                                  }}
                                  aria-label={`Select ${finding.asset_name || finding.title || finding.id}`}
                                  className="cursor-pointer"
                                />
                              </TableCell>
                              <TableCell className="font-medium max-w-[180px] truncate text-zinc-900 dark:text-zinc-100" title={finding.asset_name || finding.title || undefined}>
                                {finding.asset_name || finding.title}
                              </TableCell>
                              <TableCell className="text-sm text-zinc-600 dark:text-zinc-400">
                                {finding.asset_type?.replace(/_/g, " ") ?? "—"}
                              </TableCell>
                              <TableCell className="text-sm text-zinc-600 dark:text-zinc-400">
                                {finding.provider ?? "—"}
                              </TableCell>
                              <TableCell>
                                {finding.license_type ? (
                                  <Badge variant="outline" className="border-zinc-300 text-zinc-600 dark:border-zinc-500/50 dark:text-zinc-400">
                                    {finding.license_type}
                                  </Badge>
                                ) : (
                                  <span className="text-zinc-500 dark:text-zinc-400 text-xs">—</span>
                                )}
                              </TableCell>
                              <TableCell className="text-sm text-zinc-600 dark:text-zinc-400">
                                {finding.risk_category?.replace(/_/g, " ") ?? "—"}
                              </TableCell>
                              <TableCell>
                                <Badge variant="outline" className={getImpactBadgeClass(finding.impact)}>{finding.impact}</Badge>
                              </TableCell>
                              <TableCell className="text-center">
                                <Badge className={getImpactBadgeClass(finding.impact)}>
                                  {finding.risk_score?.toFixed(1) ?? "—"}
                                </Badge>
                              </TableCell>
                              <TableCell className="text-sm text-zinc-600 dark:text-zinc-400 max-w-[140px] truncate" title={finding.location ?? ""}>
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
                </div>
                <ScrollBar orientation="horizontal" />
              </ScrollArea>
            </CardContent>
          </Card>

          {/* Top Risks Table */}
          {dashboard?.top_risks && dashboard.top_risks.length > 0 && (
            <Card className="border-zinc-200 dark:border-zinc-800">
              <CardHeader>
                <CardTitle className="text-base">Top AI Risks</CardTitle>
                <CardDescription>Highest-risk AI assets</CardDescription>
              </CardHeader>
              <CardContent>
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Asset</TableHead>
                      <TableHead>Type</TableHead>
                      <TableHead>Provider</TableHead>
                      <TableHead>License</TableHead>
                      <TableHead>Impact</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {dashboard.top_risks.map((risk, i) => (
                      <TableRow key={i} className="hover:bg-zinc-50 dark:hover:bg-zinc-800/50">
                        <TableCell className="font-medium text-zinc-900 dark:text-zinc-100">{risk.asset_name}</TableCell>
                        <TableCell className="text-sm text-zinc-600 dark:text-zinc-400">{risk.asset_type?.replace(/_/g, " ")}</TableCell>
                        <TableCell className="text-sm text-zinc-600 dark:text-zinc-400">{risk.provider}</TableCell>
                        <TableCell>
                          <Badge variant="outline" className="border-zinc-300 text-zinc-600 dark:border-zinc-500/50 dark:text-zinc-400">
                            {risk.license_type}
                          </Badge>
                        </TableCell>
                        <TableCell className="text-sm text-zinc-600 dark:text-zinc-400 max-w-[200px] truncate">{risk.impact}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </CardContent>
            </Card>
          )}
        </>
      )}

      {/* Finding Detail Dialog */}
      <Dialog open={!!selectedFinding} onOpenChange={(open) => !open && setSelectedFinding(null)}>
        <DialogContent className="sm:max-w-4xl max-h-[90vh] flex flex-col p-0 gap-0 overflow-hidden bg-white dark:bg-zinc-900">
          {selectedFinding && (
            <>
              <DialogHeader className="px-6 pt-6 pb-2 shrink-0">
                <DialogTitle className="pr-8">
                  {selectedFinding.asset_name || selectedFinding.title}
                </DialogTitle>
              </DialogHeader>
              <div className="h-[70vh] min-h-0 shrink px-6 pb-6">
                <ScrollArea className="h-full w-full rounded-md">
                  <div className="space-y-4 pt-2 pr-4">
                    {/* Metadata grid — 3 columns on md+, 2 on sm */}
                    <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
                      <div>
                        <div className="text-xs font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400 mb-1">Asset Type</div>
                        <p className="text-sm text-zinc-700 dark:text-zinc-300">{selectedFinding.asset_type?.replace(/_/g, " ") ?? "—"}</p>
                      </div>
                      <div>
                        <div className="text-xs font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400 mb-1">Provider</div>
                        <p className="text-sm text-zinc-700 dark:text-zinc-300">{selectedFinding.provider ?? "—"}</p>
                      </div>
                      <div>
                        <div className="text-xs font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400 mb-1">Framework</div>
                        <p className="text-sm text-zinc-700 dark:text-zinc-300">{selectedFinding.framework ?? "—"}</p>
                      </div>
                      <div>
                        <div className="text-xs font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400 mb-1">Version</div>
                        <p className="text-sm text-zinc-700 dark:text-zinc-300">{selectedFinding.version ?? "—"}</p>
                      </div>
                      <div>
                        <div className="text-xs font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400 mb-1">License</div>
                        {selectedFinding.license_type ? (
                          <Badge variant="outline" className="border-zinc-300 text-zinc-600 dark:border-zinc-500/50 dark:text-zinc-400">{selectedFinding.license_type}</Badge>
                        ) : <span className="text-sm text-zinc-600 dark:text-zinc-400">—</span>}
                      </div>
                      <div>
                        <div className="text-xs font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400 mb-1">Risk Category</div>
                        <p className="text-sm text-zinc-700 dark:text-zinc-300">{selectedFinding.risk_category?.replace(/_/g, " ") ?? "—"}</p>
                      </div>
                      <div>
                        <div className="text-xs font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400 mb-1">Impact</div>
                        <Badge className={getImpactBadgeClass(selectedFinding.impact)}>{selectedFinding.impact}</Badge>
                      </div>
                      <div>
                        <div className="text-xs font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400 mb-1">Risk Score</div>
                        <Badge className={getImpactBadgeClass(selectedFinding.impact)}>{selectedFinding.risk_score?.toFixed(1) ?? "—"}</Badge>
                      </div>
                    </div>

                    {selectedFinding.location && (
                      <div>
                        <div className="text-xs font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400 mb-1">Location</div>
                        <p className="text-sm font-mono text-zinc-700 dark:text-zinc-300 bg-zinc-50 dark:bg-zinc-800 px-3 py-2 rounded-md border border-zinc-200 dark:border-zinc-700 break-all">{selectedFinding.location}</p>
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
                        <div className="text-xs font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400 mb-1">Code Snippet</div>
                        <pre className="text-xs font-mono text-zinc-700 dark:text-zinc-300 bg-zinc-50 dark:bg-zinc-800 px-3 py-2 rounded-md overflow-x-auto whitespace-pre-wrap border border-zinc-200 dark:border-zinc-700">{selectedFinding.snippet}</pre>
                      </div>
                    )}

                    {/* OWASP LLM Top 10 */}
                    {(() => {
                      const entries = getOwaspComplianceEntries(selectedFinding.owasp_top_10_llm as OwaspOrCompliance);
                      if (entries.length === 0) return null;
                      return (
                        <div>
                          <div className="text-xs font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400 mb-1">OWASP LLM Top 10</div>
                          <div className="flex flex-wrap gap-1.5">
                            {entries.map(([key, value], idx) => (
                              <Badge key={`${key}-${idx}`} variant="secondary" className="text-xs bg-purple-100 dark:bg-purple-900/40 text-purple-800 dark:text-purple-200">
                                {OWASP_LLM_KEY_TO_LABEL[key] ?? value}
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
                          <div className="text-xs font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400 mb-1">Compliance Controls</div>
                          <div className="flex flex-wrap gap-1.5">
                            {entries.map(([key, value], idx) => (
                              <Badge key={`${key}-${idx}`} variant="outline" className="text-xs">
                                {COMPLIANCE_KEY_TO_LABEL[key] ?? value}
                              </Badge>
                            ))}
                          </div>
                        </div>
                      );
                    })()}

                    {selectedFinding.suggested_fix && (
                      <div>
                        <div className="text-xs font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400 mb-1">Suggested Fix</div>
                        <p className="text-sm text-zinc-700 dark:text-zinc-300 whitespace-pre-wrap">{selectedFinding.suggested_fix}</p>
                      </div>
                    )}

                    <RemediationPanel
                      teamId={String(team_id)}
                      scanType="ai_bom"
                      scanId={typeof scan_id === "number" ? scan_id : parseInt(String(scan_id), 10)}
                      findingId={selectedFinding.id}
                      existingRemediation={selectedFinding.remediation}
                    />
                  </div>
                </ScrollArea>
              </div>
            </>
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
}
