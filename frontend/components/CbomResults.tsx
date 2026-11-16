"use client";

import { useState, useEffect, useMemo, useCallback } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { FixClassChip, type FixClassFields } from "@/components/cbom/grade";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  ArrowLeft,
  SlidersHorizontal,
  Download,
  Ticket,
  Pencil,
  CheckCircle,
  Eye,
  EyeOff,
  Loader2,
  Circle,
  GitBranch,
  Archive,
  Lock,
  ShieldCheck,
} from "lucide-react";
import { ScrollArea } from "@/components/ui/scroll-area";
import RemediationPanel from "@/components/RemediationPanel";
import AiRemediationPanel from "@/components/cbom/results/AiRemediationPanel";
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
import { getCBOMExportResults, updateScan, toggleFindingState, createTicket, postCertInAttestation, postCertInSign, getCertInVex, getCertInEvidencePack, type CbomScanDashboardData, type CbomFinding, type CbomScanMetadata, type CbomGraph, type ScanTicketingIntegrationSettings } from "@/utils/backend_api";
import { showErrorToast } from "@/utils/error-handler";
import { downloadCbomScanBom, INFORMATIONAL_LABEL, type CbomCoverageReport, type CbomImportReport } from "@/utils/api/cbom_outputs";
import { downloadOscal } from "@/utils/api/integrations";
import { inventoryRows, isBrokenToday, isUnidentified, matchesQuantumFilter } from "@/components/cbom/quantumFilter";
import {
  buildRefAliasMap,
  findingMatchesRelatedRefs,
} from "@/utils/relatedFindingMatch";
import { OWASP_KEY_TO_LABEL, COMPLIANCE_KEY_TO_LABEL } from "@/lib/owasp-compliance-labels";

import { BarChart3, Search } from "lucide-react";
import { toast } from "@/utils/toast";
import TicketingIntegrationsSettings from "@/components/ticketing-integrations-settings";
import FindingSelectionMenu from "@/components/finding-selection-menu";
import {
  CbomCryptoCharts,
  type CbomDistributions,
  type CbomCompliance,
} from "@/components/cbom/CbomCryptoCharts";
import { RbiCsfRollup, type RbiCsfRollupData } from "@/components/rbi/RbiCsfRollup";
import { CertHygieneSection } from "@/components/cbom/certificates/CertHygiene";
import { CodeChanges } from "@/components/cbom/sources/ChangesPanel";
import { CodeWavesPanel } from "@/components/cbom/sources/WavesControls";
import { CertInLanePosture } from "@/components/certin/CertInLanePosture";
import { CbomDashboardCharts } from "@/components/cbom/results/CbomDashboardCharts";
import { getFindingStatusBadgeClass, getImpactBadgeClass, getRiskScoreBoxClass, getStrengthBadgeClass } from "@/components/cbom/results/badgeClasses";
import { type CertInRollupData } from "@/components/certin/certinShared";
import { InfoTip } from "@/components/ui/info-tip";
import { CompareDialog } from "@/components/cbom/sources/ChangesPanel";
import { applyPostureToDistributions, complianceRows, hasActiveFilters, parityNotes, resolveMigrationRows, RUN_TICKETING_TAB_AVAILABLE, tableTotal } from "@/components/cbom/results/model";
import { useDialogNav } from "@/components/cbom/results/useDialogNav";
import { InfoTipDrawerProvider } from "@/components/ui/info-tip-drawer";
import { ComplianceMappingSection } from "@/components/cbom/results/ComplianceSummary";
import { buildComplianceSummary, runDrillFilters, type DrillTarget } from "@/components/cbom/results/complianceSummary";
import { RunFindingDialog } from "@/components/cbom/results/RunFindingDialog";
import { ColumnChooser, useColumnPrefs } from "@/components/cbom/results/ColumnChooser";
import { FINDING_DIALOG_BODY, FINDING_DIALOG_CONTENT, FINDING_DIALOG_FULLSCREEN_SM, rowOpenProps, SCAN_TABLE_COLUMNS, STICKY_ACTIONS } from "@/components/cbom/results/findingTable";
import { RowOpenButton } from "@/components/cbom/results/RowOpenButton";
import RunTicketingTab from "@/components/cbom/results/RunTicketingTab";
// the Sources run views (results redesign): summary, detail views, URL and drill-downs
import { CollectionView } from "@/components/cbom/results/views/CollectionView";
import { ComplianceView } from "@/components/cbom/results/views/ComplianceView";
import { createDrill, pqcRunAssetId, runRefsDrill, useResultsScroll } from "@/components/cbom/results/views/drill";
import { InventoryView } from "@/components/cbom/results/views/InventoryView";
import { MigrationView } from "@/components/cbom/results/views/MigrationView";
import { QuantumView } from "@/components/cbom/results/views/QuantumView";
import { RemediationView } from "@/components/cbom/results/views/RemediationView";
import { ResultsHero } from "@/components/cbom/results/views/ResultsHero";
import { CoverageNotesCard, ImportNotesCard } from "@/components/cbom/results/views/ScanNotes";
import { SectionView } from "@/components/cbom/results/views/SectionView";
import { SummaryView } from "@/components/cbom/results/views/SummaryView";
import type { RunViewCtx } from "@/components/cbom/results/views/types";
import { useResultsUrl, type DetailSection, type ResultsSection } from "@/components/cbom/results/views/url";
import type { ResultsSource } from "@/components/cbom/results/source";
import { advisoryLine, readAdvisoryData, staleNote } from "@/components/cbom/advisoryData";

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
  backHref?: string;
  /** The data source of this one template (CB-38): a CBOM Sources run (useSourcesRunSource). Absent: the code scan
   * given by the props above (codeScanSource), exactly as before. */
  source?: ResultsSource;
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

/** Quantum column: "Broken today" for a classically broken algorithm (MD5, SHA-1, DES …) instead of a misleading
 * "Safe"; "—" when quantum readiness does not apply (libraries, configuration, certificates). */
function QuantumBadge({ quantumSafe, strength, yesNo = false }: { quantumSafe?: boolean | null; strength?: string | null; yesNo?: boolean }) {
  if (isBrokenToday({ quantum_safe: quantumSafe, crypto_strength: strength })) {
    return (
      <Badge variant="outline" className="border-amber-500/60 text-amber-700 dark:text-amber-400"
        title="Already broken without a quantum computer: replace it now; post-quantum readiness does not help">
        Broken today
      </Badge>
    );
  }
  if (isUnidentified({ quantum_safe: quantumSafe, crypto_strength: strength })) {
    return <span className="text-zinc-500 dark:text-zinc-400 text-xs" title="Not identified by the rule base: not judged, never counted as safe">Unknown</span>;
  }
  if (quantumSafe === true) {
    return <Badge variant="outline" className="border-emerald-500/50 text-emerald-600 dark:text-emerald-400">{yesNo ? "Yes" : "Safe"}</Badge>;
  }
  if (quantumSafe === false) {
    return <Badge variant="outline" className="border-red-500/50 text-red-600 dark:text-red-400">{yesNo ? "No" : "Vulnerable"}</Badge>;
  }
  return <span className="text-zinc-500 dark:text-zinc-400 text-xs" title="Not applicable to this kind of finding">—</span>;
}

export default function CbomResults({
  data,
  conversationId,
  teamId,
  dashboard,
  findings: findingsList = [],
  scanMetadata: scanMetadataProp,
  integrationSettings,
  onIntegrationSettingsUpdated,
  onFindingsUpdated,
  backHref,
  source,
}: CbomResultsProps) {
  // A Sources run fills the same sections from the run APIs; a code scan (no source, or kind "scan") renders as before.
  const run = source?.kind === "run" && source.run ? source : null;
  // A run's scan_metadata is /runs/{id}/parity's (the code scan's own keys: compliance readiness, RBI / CERT-In roll-ups,
  // dependency graph, coverage notes); null on an older backend, which hides those sections as on a legacy scan.
  const scanMetadata = run ? run.parity?.scan_metadata ?? null : scanMetadataProp;
  const runParityNotes = run ? parityNotes(run.parityState, run.parity) : null;
  const router = useRouter();
  const params = useParams();
  const searchParams = useSearchParams();
  const origin = searchParams.get("origin");
  const team_id = teamId ?? params?.team_id;
  const scan_id = conversationId ?? params?.scan_id;
  const queryClient = useQueryClient();
  const goBack = () => {
    const backRoute = backHref
      ? backHref
      : origin === "chat" && team_id && scan_id != null
        ? `/${team_id}/cbom/${scan_id}`
        : team_id
          ? `/${team_id}/cbom`
          : "/cbom";
    router.push(backRoute);
  };

  const [activeTab, setActiveTab] = useState<"results" | "ticketing">("results");
  // A run's view (?section=…): read from the URL every render, ignored on a code scan
  const resultsUrl = useResultsUrl();
  const section: ResultsSection = run ? resultsUrl.section : "";
  const requestFindingsScroll = useResultsScroll(section, !!run && activeTab === "results");
  // the run finding dialog's Previous / Next over the findings table (B3); inert on a code scan (nulls)
  const { nav: dialogNav, openFromTable } = useDialogNav({
    assetId: run?.dialog?.assetId ?? null,
    open: (id) => run?.setDialog({ assetId: id }),
    items: run?.page?.items,
    page: run?.filters.page ?? 1,
    pageSize: run?.filters.page_size ?? 50,
    total: run?.page ? tableTotal(run.page, run.filters.view, hasActiveFilters(run.filters)) : 0,
    placeholder: run?.pagePlaceholder ?? false,
    goToPage: (p) => run?.onFilters({ page: p }),
  });
  const [searchQuery, setSearchQuery] = useState("");
  const [relatedFindingRefs, setRelatedFindingRefs] = useState<string[]>([]);
  const [strengthFilter, setStrengthFilter] = useState("all");
  const [typeFilter, setTypeFilter] = useState("all");
  const [quantumFilter, setQuantumFilter] = useState("all");
  const [filterImpact, setFilterImpact] = useState("all");
  const [filterRiskScore, setFilterRiskScore] = useState<RiskScoreFilter>("all");
  const [selectedFinding, setSelectedFinding] = useState<CbomFinding | null>(null);
  const [selectedFindings, setSelectedFindings] = useState<Set<string>>(new Set());
  // #267: the code findings table's visible columns (per user, localStorage); select and Actions always show
  const scanColumns = useColumnPrefs("scan", SCAN_TABLE_COLUMNS);
  const showCol = scanColumns.isVisible;

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
      const matchQuantum = matchesQuantumFilter(f, quantumFilter);
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
      return getCBOMExportResults(tid, sid, { toast: false });
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

  // The server's CycloneDX document as stored: the file bom_signature signs and the XML is written from. A copy
  // rebuilt in the browser merged crypto assets and dropped library purls, so it never verified against the signature.
  const handleDownloadCBOMJson = () => {
    void downloadCbomScanBom(team_id as string, scan_id as string, "json")
      .then(() => toast.success("CycloneDX CBOM JSON downloaded"))
      .catch(() => undefined);
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
  // An uploaded CBOM file's import report: notes say what was skipped or truncated (null for code scans)
  const importReport = ((scanMetadata as Record<string, unknown> | null)?.cbom_input ?? null) as CbomImportReport | null;
  // A code scan's coverage: archives, images, binaries and firmware it skipped or only counted (null when none)
  const coverageReport = ((scanMetadata as Record<string, unknown> | null)?.cbom_coverage ?? null) as CbomCoverageReport | null;
  // CB-29: the crypto-library advisory data the code scan matched (offline OSV snapshot version and date)
  const advisoryData = run ? null : readAdvisoryData(data, scanMetadata);
  const informationalRows = dashboard?.card_data?.total_informational ?? 0;
  // Every crypto asset (findings + clean inventory) for the readiness gauge, as the PDF and the scan list count them
  const allRows = useMemo(() => inventoryRows(data, findingsList ?? []), [data, findingsList]);

  // Crypto-asset charts from the aibom CBOM lane's run-object (C9). Present only
  // on scans produced by the reconciled aibom lane; legacy worker CBOM scans
  // carry no `cbom_distributions`, so the charts simply don't render.
  const cryptoDistributions = useMemo<CbomDistributions | null>(() => {
    if (run) {
      const dist = run.results?.distributions;
      return dist ? applyPostureToDistributions(resolveMigrationRows(dist), run.posture) : null;
    }
    const fromData = (data as Record<string, unknown> | null)?.cbom_distributions;
    const fromMeta = (scanMetadata as Record<string, unknown> | null)?.cbom_distributions;
    const dist = (fromData ?? fromMeta) as CbomDistributions | undefined;
    return dist ?? null;
  }, [data, scanMetadata, run]);

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

  // Compliance mapping (#270): one view over the tri-state checks (code scans and runs) and, for a run, the knowledge
  // base clauses its findings touch; every asset count drills into the findings table.
  const complianceMapping = useMemo(() => {
    const kb = run ? complianceRows(run.results, run.posture) : { rows: [], basis: "none" as const };
    return {
      basis: kb.basis,
      frameworks: buildComplianceSummary({
        engine: cryptoCompliance,
        mapping: kb.rows,
        findings: run ? null : findingsList ?? [],
        refAliases: relatedRefAliases,
        titles: Object.fromEntries((run?.posture?.top_codes ?? []).map((c) => [c.code, c.title])),
      }),
    };
  }, [run, cryptoCompliance, findingsList, relatedRefAliases]);

  // A run's views: a tile or "Back to summary" pushes a history entry; every drill-down filters the findings table,
  // returns to a view that has it and scrolls there once it is mounted (drillToFindings)
  const { patch: patchResultsUrl } = resultsUrl;
  const goSection = useCallback((next: ResultsSection) => patchResultsUrl({ section: next }, { push: true }), [patchResultsUrl]);
  const drillToFindings = (patch: Parameters<NonNullable<typeof run>["onFilters"]>[0]) => {
    if (!run) return;
    createDrill({ onFilters: run.onFilters, section, goSection, requestScroll: requestFindingsScroll })(patch);
  };
  // RBI CSF / CERT-In "view findings" on a run: their refs name run assets; a requirement with none says so
  const handleViewRunRefs = (refs: string[]) => {
    const d = runRefsDrill(refs, "Assets of this requirement");
    if (!d) {
      toast.info("This requirement names no asset of this run");
      return;
    }
    drillToFindings(d.patch);
    if (d.truncated) toast.warning("The findings table shows the first assets of this requirement only (one request carries up to 500)");
  };
  // a PQC list item on a run opens the run's finding dialog for its asset (never the code scan's dialog)
  const openRunPqcFinding = (f: CbomFinding) => {
    if (!run) return;
    const id = pqcRunAssetId(f as CbomFinding & { asset_id?: number | null });
    if (id != null) run.openAsset(id, f.algorithm_name || f.title || undefined);
    else toast.info("This item names no asset of this run");
  };

  const handleComplianceDrill = (target: DrillTarget) => {
    if (run) {
      const { patch, truncated } = runDrillFilters(target);
      drillToFindings(patch);
      if (truncated) toast.warning("The findings table shows the first assets of this requirement only (one request carries up to 500)");
    } else if (target.kind === "refs") {
      handleViewRelatedFindings(target.refs);
    } else {
      // a code scan's findings carry their finding codes: the same filter, in the browser like its other filters
      const refs = (findingsList ?? []).filter((f) => (f.finding_codes ?? []).some((c) => target.codes.includes(c))).map((f) => f.bom_ref || f.id);
      if (refs.length) handleViewRelatedFindings(refs);
      else toast.info("No finding of this scan carries these finding codes");
    }
  };

  const showTabs = team_id && scan_id != null;
  const hasTicketingTab = run ? RUN_TICKETING_TAB_AVAILABLE : showTabs && onIntegrationSettingsUpdated != null;

  const hasActiveFindingsFilters =
    searchQuery.trim() !== "" ||
    relatedFindingRefs.length > 0 ||
    filterImpact !== "all" ||
    filterRiskScore !== "all" ||
    strengthFilter !== "all" ||
    typeFilter !== "all" ||
    quantumFilter !== "all";

  // the Sources run's views: what they share (built from the figures above), and the one rendered for ?section=
  const viewCtx: RunViewCtx | null = run ? {
    run, meta, parityNotes: runParityNotes, distributions: cryptoDistributions, graph: cryptoGraph, graphCompact: cryptoGraphCompact,
    graphExpanded: cryptoGraphExpanded, compliance: cryptoCompliance, complianceMapping, coverageReport, importReport,
    onComplianceDrill: handleComplianceDrill, onViewRefs: handleViewRunRefs, onOpenPqcFinding: openRunPqcFinding,
    drill: drillToFindings, openFromTable, section, goSection,
  } : null;
  const detailView = (s: DetailSection, ctx: RunViewCtx) => {
    const r = ctx.run;
    const resultsPending = r.resultsState.kind === "loading";
    const back = () => goSection("");
    switch (s) {
      case "collection": return <SectionView section={s} onBack={back}><CollectionView ctx={ctx} /></SectionView>;
      case "quantum": return <SectionView section={s} onBack={back}><QuantumView ctx={ctx} /></SectionView>;
      case "inventory": return <SectionView section={s} onBack={back} loading={resultsPending}><InventoryView ctx={ctx} /></SectionView>;
      case "migration": return <SectionView section={s} onBack={back} loading={resultsPending}><MigrationView ctx={ctx} /></SectionView>;
      case "compliance":
        return <SectionView section={s} onBack={back} loading={resultsPending || r.parityState === "loading"}><ComplianceView ctx={ctx} /></SectionView>;
      case "remediation": return <SectionView section={s} onBack={back}><RemediationView ctx={ctx} /></SectionView>;
    }
  };

  const tabBar = (
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
  );

  return (
    <div className="container mx-auto p-6 space-y-6">
      {run && run.run && viewCtx ? (
        // the Explanations drawer lists the tips of the view on screen (B3's manifest: run.summary, run.<section>)
        <InfoTipDrawerProvider view={`run.${section || "summary"}`}>
          {/* results redesign: the hero header on every view, the Results / Ticketing tabs, then the summary or one view */}
          <ResultsHero teamId={run.teamId} run={run.run} sources={run.sources} posture={run.posture} assetTotal={run.page?.all_total ?? null}
                       canCompare={run.canCompare} onCompare={() => run.setCompareOpen(true)} onBack={scan_id != null || team_id ? goBack : null}
                       targets={run.page?.targets ?? null} showLabBanner={section !== "collection"} />
          {hasTicketingTab && tabBar}
          {activeTab === "ticketing" && hasTicketingTab ? (
            <RunTicketingTab teamId={run.teamId} runId={run.runId} />
          ) : section === "" ? (
            <SummaryView ctx={viewCtx} />
          ) : (
            detailView(section, viewCtx)
          )}
        </InfoTipDrawerProvider>
      ) : (
        <>
      {/* Header: the export buttons wrap under the title on a narrow screen (they ran off a phone's right edge) */}
      <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
        <div className="flex items-center gap-4">
          {(scan_id != null || team_id) && (
            <Button
              variant="outline"
              size="icon"
                aria-label="Back"
              onClick={goBack}
              className="cursor-pointer"
            >
              <ArrowLeft className="h-4 w-4" />
            </Button>
          )}
          <div>
            <h1 className="text-3xl font-bold text-zinc-900 dark:text-white flex items-center gap-2" data-testid="cbom-results-title">
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
        {/* A Sources run is this same [scan_id] route with ?run=1, so params.scan_id is set: its header is ResultsHero
            (RunHeaderActions), rendered instead of this one. One toolbar: the run row, or this code-scan row. */}
        {team_id && scan_id != null ? (
          <div className="flex items-center gap-2 flex-wrap lg:justify-end" data-testid="cbom-scan-header-actions">
            <Button
              variant="outline"
              className="cursor-pointer"
              title="The scan's CycloneDX 1.6 document as stored on the server: the file the BOM signature covers"
              onClick={handleDownloadCBOMJson}
              data-testid="cbom-download-json"
            >
              <Download className="h-4 w-4 mr-2" />
              CycloneDX JSON
            </Button>
            <Button
              variant="outline"
              className="cursor-pointer"
              title="The same CycloneDX 1.6 document as XML (valid against the official schema). The BOM signature covers the JSON form."
              onClick={() => void downloadCbomScanBom(team_id as string, scan_id as string, "xml").then(() => toast.success("CycloneDX XML downloaded")).catch(() => undefined)}
              data-testid="cbom-download-xml"
            >
              <Download className="h-4 w-4 mr-2" />
              CycloneDX XML
            </Button>
            <Button
              variant="outline"
              className="cursor-pointer"
              title="OSCAL 1.2.3 assessment results for a GRC tool: findings mapped to NIST SP 800-53 controls (validated against the official schema)"
              onClick={() => void downloadOscal(team_id as string, { scanId: scan_id as string }).then(() => toast.success("OSCAL assessment results downloaded")).catch(() => undefined)}
              data-testid="cbom-download-oscal"
            >
              <Download className="h-4 w-4 mr-2" />
              OSCAL
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
              <SlidersHorizontal className="h-4 w-4 mr-2" />
              Scan settings
            </Button>
          </div>
        ) : null}
      </div>

      <ImportNotesCard report={importReport} />

      <CoverageNotesCard report={coverageReport} />

      {advisoryData && (
        <p className={`mb-6 text-xs ${advisoryData.stale ? "text-amber-800 dark:text-amber-300" : "text-zinc-500 dark:text-zinc-400"}`}
           data-testid="cbom-advisory-data" data-stale={advisoryData.stale ? "true" : "false"}
           role={advisoryData.stale ? "status" : undefined}>
          {advisoryLine(advisoryData)}{staleNote(advisoryData) ? ` ${staleNote(advisoryData)}` : ""}
        </p>
      )}

      {hasTicketingTab && tabBar}

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
                      <p className="text-xs font-medium text-zinc-500 dark:text-zinc-400">Branch <InfoTip id="results.meta.branch" /></p>
                      <p className="text-lg font-semibold text-zinc-900 dark:text-zinc-100">{String(meta.branch)}</p>
                    </div>
                  </CardContent>
                </Card>
              )}
              {meta.zip_file_used != null && !meta.cbom_file_used && (
                <Card className="border-zinc-200 dark:border-zinc-800">
                  <CardContent className="pt-4 pb-4 flex items-center gap-3">
                    <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-zinc-100 dark:bg-zinc-800 text-zinc-600 dark:text-zinc-400">
                      <Archive className="h-5 w-5" />
                    </div>
                    <div className="min-w-0">
                      <p className="text-xs font-medium text-zinc-500 dark:text-zinc-400">Source <InfoTip id="results.meta.source" /></p>
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
                      <p className="text-xs font-medium text-zinc-500 dark:text-zinc-400">Input <InfoTip id="cbom.res.input" /></p>
                      <p className="text-sm font-semibold text-zinc-900 dark:text-zinc-100">CBOM file</p>
                    </div>
                  </CardContent>
                </Card>
              )}
            </div>
          )}

          {/* Code scans have no Sources posture payload. The same heading still introduces the PQC charts
              this page already renders, so a code scan and a Sources run share the section name. */}
          {cryptoDistributions && (
            <h2 className="text-base font-semibold text-zinc-900 dark:text-white" data-testid="code-posture-heading">
              Post-quantum and risk posture
            </h2>
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
              inventory={allRows}
              onOpenFinding={(f) => setSelectedFinding(f)}
              showCodeHeatmap
              readinessScope="code"
            />
          )}
          {/* the code scan's changes and waves: never on a run (they read and write code scan #<id>, and a run's id is not one) */}
          {!run && cryptoDistributions && Number.isFinite(tid) && tid > 0 && Number.isFinite(sid) && sid > 0 && (
            <>
              <CodeChanges teamId={tid} scanId={sid} />
              <CodeWavesPanel teamId={tid} scanId={sid} />
            </>
          )}
          {Number.isFinite(tid) && tid > 0 && (
            <div className="mt-6" data-testid="code-cert-hygiene">
              <CertHygieneSection teamId={tid} />
            </div>
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

          <ComplianceMappingSection frameworks={complianceMapping.frameworks} onDrill={handleComplianceDrill} scope="scan"
                                    note={null} footnote={null} />

          {/* Dashboard */}
          {dashboard && cardData && (
            <CbomDashboardCharts dashboard={dashboard} findingsList={findingsList ?? []} />
          )}

          {/* Findings */}
          <Card id="bom-findings">
            <CardHeader>
              <CardTitle>Cryptographic findings <InfoTip id="cbom.res.findings" /></CardTitle>
              <CardDescription>
                {filteredFindings.length} of {(findingsList ?? []).length} findings. Select rows to create Jira tickets; use Action to change finding state.
                {informationalRows > 0 && (
                  <span className="block mt-1" data-testid="cbom-informational-note">
                    {INFORMATIONAL_LABEL}: {informationalRows} clean {informationalRows === 1 ? "asset has" : "assets have"} no finding
                    (for example AES-GCM or SHA-256). They are in the inventory charts and the CycloneDX download, not in this table.
                  </span>
                )}
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
                  <InfoTip id="cbom.res.search" className="-ml-2" />
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
                  <InfoTip id="results.filter.impact" className="-ml-2" />
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
                  <InfoTip id="cbom.res.filter.risk" className="-ml-2" />
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
                  <InfoTip id="cbom.res.filter.strength" className="-ml-2" />
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
                  <InfoTip id="cbom.res.filter.type" className="-ml-2" />
                  <Select value={quantumFilter} onValueChange={setQuantumFilter}>
                    <SelectTrigger className="h-9 min-w-[140px] cursor-pointer">
                      <SelectValue placeholder="Quantum" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="all">All</SelectItem>
                      <SelectItem value="safe">Quantum-Safe</SelectItem>
                      <SelectItem value="broken">Broken today</SelectItem>
                      <SelectItem value="vulnerable">Vulnerable</SelectItem>
                    </SelectContent>
                  </Select>
                  <InfoTip id="cbom.res.filter.quantum" className="-ml-2" />
                  <div className="ml-auto">
                    <ColumnChooser defs={SCAN_TABLE_COLUMNS} visible={scanColumns.visible} onToggle={scanColumns.toggle}
                                   onReset={scanColumns.reset} testId="cbom-findings-columns" />
                  </div>
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
                      <TableHead data-col="select" className="w-[72px]">
                        <div className="flex items-center gap-0.5">
                          <Checkbox
                            checked={filteredFindings.length > 0 && selectedFindings.size === filteredFindings.length}
                            onCheckedChange={() => {
                              if (selectedFindings.size === filteredFindings.length) setSelectedFindings(new Set());
                              else setSelectedFindings(new Set(filteredFindings.map((f) => f.id)));
                            }}
                            aria-label="Select all rows"
                            className="cursor-pointer"
                          />
                          <InfoTip id="cbom.res.select_all" />
                        </div>
                      </TableHead>
                      {showCol("algorithm") && <TableHead data-col="algorithm" className="min-w-[160px]">Algorithm <InfoTip id="cbom.res.col.algorithm" /></TableHead>}
                      {showCol("type") && <TableHead data-col="type" className="min-w-[120px]">Type <InfoTip id="cbom.res.col.type" /></TableHead>}
                      {showCol("impact") && <TableHead data-col="impact" className="min-w-[90px]">Impact <InfoTip id="results.table.impact" /></TableHead>}
                      {showCol("strength") && <TableHead data-col="strength" className="min-w-[110px]">Strength <InfoTip id="cbom.res.col.strength" /></TableHead>}
                      {showCol("quantum") && <TableHead data-col="quantum" className="min-w-[100px]">Quantum <InfoTip id="cbom.res.col.quantum" /></TableHead>}
                      {showCol("fixclass") && <TableHead data-col="fixclass" className="min-w-[110px]">Fix class <InfoTip id="cbom.res.col.fix_class" /></TableHead>}
                      {showCol("risk") && <TableHead data-col="risk" className="min-w-[90px] text-center">Risk score <InfoTip id="cbom.res.col.risk" /></TableHead>}
                      {showCol("location") && <TableHead data-col="location" className="min-w-[140px]">Location <InfoTip id="cbom.res.col.location" /></TableHead>}
                      {showCol("status") && <TableHead data-col="status" className="min-w-[100px]">Status <InfoTip id="results.table.status" /></TableHead>}
                      <TableHead data-col="actions" className={`min-w-[150px] text-right ${STICKY_ACTIONS}`}>
                        <span className="inline-flex items-center gap-1">Actions <InfoTip id="results.finding.action" /></span>
                      </TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {filteredFindings.length === 0 ? (
                      <TableRow>
                        <TableCell colSpan={2 + scanColumns.visible.length} className="text-center py-8 text-zinc-500 dark:text-zinc-400">
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
                            data-testid={`cbom-finding-row-${finding.id}`}
                            {...rowOpenProps(() => setSelectedFinding(finding), `Open details of ${finding.algorithm_name || finding.title}`)}
                            className={`cursor-pointer hover:bg-zinc-50 dark:hover:bg-zinc-800/50 focus-visible:outline-none focus-visible:bg-blue-50 dark:focus-visible:bg-blue-950/40 ${selectedFindings.has(finding.id) ? "bg-zinc-100 dark:bg-zinc-800/70" : ""}`}
                          >
                            <TableCell data-col="select" onClick={(e) => e.stopPropagation()} className="w-[72px]">
                              <div className="flex items-center gap-1">
                              {/* infotip-shared: one row of the selection; the Select all tip in the header explains it */}
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
                              <RowOpenButton label={`Open details of ${finding.algorithm_name || finding.title}`} onOpen={() => setSelectedFinding(finding)} />
                              </div>
                            </TableCell>
                            {showCol("algorithm") && (
                            <TableCell data-col="algorithm" className="font-medium">
                              <button
                                type="button"
                                onClick={() => setSelectedFinding(finding)}
                                className="text-left text-blue-600 hover:text-blue-700 dark:text-blue-400 dark:hover:text-blue-300 hover:underline cursor-pointer font-medium max-w-[150px] truncate block"
                                title={finding.algorithm_name || finding.title}
                              >
                                {finding.algorithm_name || finding.title}
                              </button>
                            </TableCell>
                            )}
                            {showCol("type") && (
                            <TableCell data-col="type" className="text-sm text-zinc-600 dark:text-zinc-400">
                              {finding.algorithm_type?.replace(/_/g, " ") ?? "—"}
                            </TableCell>
                            )}
                            {showCol("impact") && (
                            <TableCell data-col="impact">
                              <Badge variant="outline" className={getImpactBadgeClass(finding.impact)}>{finding.impact}</Badge>
                            </TableCell>
                            )}
                            {showCol("strength") && (
                            <TableCell data-col="strength">
                              <Badge variant="outline" className={getStrengthBadgeClass(finding.crypto_strength)}>
                                {finding.crypto_strength ?? "—"}
                              </Badge>
                            </TableCell>
                            )}
                            {showCol("quantum") && (
                            <TableCell data-col="quantum">
                              <QuantumBadge quantumSafe={finding.quantum_safe} strength={finding.crypto_strength} />
                            </TableCell>
                            )}
                            {showCol("fixclass") && (
                            <TableCell data-col="fixclass">
                              <FixClassChip item={finding as FixClassFields} testId={`cbom-finding-fixclass-${finding.id}`} />
                            </TableCell>
                            )}
                            {showCol("risk") && (
                            <TableCell data-col="risk" className="text-center">
                              <span
                                className={`inline-flex items-center justify-center min-w-9 px-2 py-1 rounded-md text-xs font-semibold tabular-nums ${getRiskScoreBoxClass(finding.risk_score)}`}
                                title="Risk score"
                              >
                                {finding.risk_score?.toFixed(1) ?? "—"}
                              </span>
                            </TableCell>
                            )}
                            {showCol("location") && (
                            <TableCell data-col="location" className="text-sm text-zinc-600 dark:text-zinc-400 max-w-[150px] truncate" title={finding.location ?? ""}>
                              {finding.location ?? "—"}
                            </TableCell>
                            )}
                            {showCol("status") && (
                            <TableCell data-col="status">
                              <span className={`inline-flex items-center justify-center px-2.5 py-1 rounded-md text-xs font-medium capitalize ${getFindingStatusBadgeClass(finding.status ?? "not_started")}`}>
                                {statusLabel}
                              </span>
                            </TableCell>
                            )}
                            <TableCell data-col="actions" className={`text-right whitespace-nowrap ${STICKY_ACTIONS}`} onClick={(e) => e.stopPropagation()}
                                       data-testid={`cbom-finding-actions-${finding.id}`}>
                              <div className="inline-flex items-center gap-1.5">
                              <DropdownMenu>
                                {/* infotip-shared: explained by the (i) on the Actions column header */}
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
                              <Button variant="ghost" size="sm" className="cursor-pointer h-8 gap-1" data-testid={`cbom-finding-details-${finding.id}`}
                                      aria-label={`Details of ${finding.algorithm_name || finding.title}`} onClick={() => setSelectedFinding(finding)}>
                                <Eye className="h-3.5 w-3.5" /> Details
                              </Button>
                              </div>
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
                <CardTitle className="text-base">Top cryptographic risks <InfoTip id="cbom.res.top" /></CardTitle>
                <CardDescription>Highest-risk cryptographic assets</CardDescription>
              </CardHeader>
              <CardContent>
                <ScrollArea className="h-[320px] w-full rounded-md border border-zinc-200 dark:border-zinc-800">
                  <Table className="min-w-max">
                    <TableHeader>
                      <TableRow>
                        <TableHead className="min-w-[160px]">Algorithm <InfoTip id="cbom.res.col.algorithm" /></TableHead>
                        <TableHead className="min-w-[120px]">Type <InfoTip id="cbom.res.col.type" /></TableHead>
                        <TableHead className="min-w-[110px]">Strength <InfoTip id="cbom.res.col.strength" /></TableHead>
                        <TableHead className="min-w-[110px]">Quantum safe <InfoTip id="cbom.res.col.quantum_safe" /></TableHead>
                        <TableHead className="min-w-[120px]">Impact <InfoTip id="results.table.impact" /></TableHead>
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
                            <QuantumBadge quantumSafe={risk.quantum_safe} strength={risk.crypto_strength} yesNo />
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

        </>
      )}

      {run && (
        <RunFindingDialog teamId={run.teamId} runId={run.runId} subject={run.dialog} jobs={run.run?.jobs ?? []} waveOf={run.waveOf} onClose={() => run.setDialog(null)}
                          pageItems={run.page?.items} nav={dialogNav} onSetStatus={run.setStatus} statusPending={run.statusPending}
                          priorityOf={(id) => run.posture?.top_risks?.find((r) => r.id === id)?.score} />
      )}
      {run && run.compareOpen && (
        <CompareDialog teamId={run.teamId} runId={run.runId} runs={run.compareRuns} onClose={() => run.setCompareOpen(false)} />
      )}

      {/* Finding Detail Dialog (code scans; a run opens RunFindingDialog) */}
      <Dialog open={!run && !!selectedFinding} onOpenChange={(open) => !open && setSelectedFinding(null)}>
        <DialogContent className={`${FINDING_DIALOG_CONTENT} ${FINDING_DIALOG_FULLSCREEN_SM}`}>
          <DialogHeader className="px-6 pt-6 pb-2 shrink-0">
            <DialogTitle className="pr-8">{selectedFinding?.algorithm_name || selectedFinding?.title || "Finding details"}</DialogTitle>
          </DialogHeader>
          {selectedFinding && (
            // #266: the body div is the dialog's one scroll container (a min-h-0 flex item of the max-h-[90vh] column),
            // at every width; a plain block also keeps the exploit demo's long lines inside the dialog's width.
            <div className={FINDING_DIALOG_BODY} tabIndex={0} role="region" aria-label="Finding details" data-testid="cbom-finding-scroll">
                <div className="space-y-4 pt-2">
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
                      <QuantumBadge quantumSafe={selectedFinding.quantum_safe} strength={selectedFinding.crypto_strength} yesNo />
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
                      <p className="text-sm font-mono text-zinc-700 dark:text-zinc-300 bg-zinc-100 dark:bg-zinc-800 px-3 py-2 rounded-md border border-zinc-200 dark:border-zinc-700 break-all" data-testid="cbom-finding-location">
                        {selectedFinding.location}{selectedFinding.line && !/:\d+$/.test(selectedFinding.location) ? `:${selectedFinding.line}` : ""}
                        {selectedFinding.language ? <span className="ml-2 font-sans text-xs text-zinc-500">({selectedFinding.language})</span> : null}
                      </p>
                      {(selectedFinding.occurrence_count ?? 0) > 1 && (
                        <p className="mt-1 text-xs text-zinc-500" data-testid="cbom-finding-occurrences">
                          {selectedFinding.occurrence_count} occurrences in this file: line{(selectedFinding.occurrences ?? []).length > 1 ? "s" : ""} {(selectedFinding.occurrences ?? []).join(", ")}
                          {(selectedFinding.occurrence_count ?? 0) > (selectedFinding.occurrences ?? []).length ? " …" : ""}
                        </p>
                      )}
                    </div>
                  )}

                  {selectedFinding.description && (
                    <div>
                      <div className="text-xs font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400 mb-1">Description</div>
                      <p className="text-sm text-zinc-700 dark:text-zinc-300 whitespace-pre-wrap">{selectedFinding.description}</p>
                    </div>
                  )}

                  {selectedFinding.snippet && !selectedFinding.snippet_start && (
                    <div>
                      <div className="text-xs font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400 mb-1">Code snippet</div>
                      <pre className="text-xs font-mono text-zinc-700 dark:text-zinc-300 bg-zinc-100 dark:bg-zinc-800 px-3 py-2 rounded-md overflow-x-auto whitespace-pre-wrap border border-zinc-200 dark:border-zinc-700">{selectedFinding.snippet}</pre>
                    </div>
                  )}
                  {selectedFinding.snippet_note && (
                    <p className="text-xs text-zinc-500" data-testid="cbom-snippet-note">{selectedFinding.snippet_note}</p>
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
                            <Badge key={key} variant="secondary" className="text-xs whitespace-normal max-w-full text-left bg-purple-100 dark:bg-purple-900/40 text-purple-800 dark:text-purple-200">
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
                            <Badge key={key} variant="outline" className="text-xs whitespace-normal max-w-full text-left">
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
                    snippetStart={selectedFinding.snippet_start}
                    line={selectedFinding.line}
                  />
                  {/* CB-38 PR-6: optional AI assistant under the KB remediation; renders nothing unless configured */}
                  <AiRemediationPanel
                    key={selectedFinding.id}
                    teamId={Number(team_id)}
                    subject={{ kind: "scan_finding", scanId: Number(scan_id), findingId: selectedFinding.id }}
                  />
                </div>
            </div>
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
}
