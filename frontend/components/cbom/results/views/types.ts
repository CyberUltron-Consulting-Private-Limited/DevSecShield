// What the run results views share (results redesign §2–§3): the run adapter plus the figures CbomResults already
// derives for both modes (crypto distributions, the dependency graph, compliance readiness and mapping, /parity notes,
// the coverage and import notes), and the page's navigation (section switch, drill to the findings table).

import type { CbomFinding, CbomGraph, CbomScanMetadata } from "@/utils/backend_api";
import type { CbomCoverageReport, CbomImportReport } from "@/utils/api/cbom_outputs";
import type { InfoTipId } from "@/content/infotips";

import type { CbomCompliance, CbomDistributions } from "../../CbomCryptoCharts";
import type { DrillTarget, FrameworkSummary } from "../complianceSummary";
import type { parityNotes } from "../model";
import type { SourcesRunSource } from "../source";
import type { DrillToFindings } from "./drill";
import type { DetailSection, ResultsSection } from "./url";

export interface RunViewCtx {
  run: SourcesRunSource;
  meta: CbomScanMetadata | null;
  parityNotes: ReturnType<typeof parityNotes> | null;
  distributions: CbomDistributions | null;
  graph: CbomGraph | null;
  graphCompact: CbomGraph | null;
  graphExpanded: CbomGraph | null;
  compliance: CbomCompliance | null;
  complianceMapping: { basis: "results" | "posture" | "none"; frameworks: FrameworkSummary[] };
  coverageReport: CbomCoverageReport | null;
  importReport: CbomImportReport | null;
  /** compliance mapping counts and the compliance matrix */
  onComplianceDrill: (target: DrillTarget) => void;
  /** RBI CSF / CERT-In "view findings" (their refs name run assets) */
  onViewRefs: (refs: string[]) => void;
  /** a PQC list item: the run's finding dialog for its asset */
  onOpenPqcFinding: (f: CbomFinding) => void;
  drill: DrillToFindings;
  section: ResultsSection;
  /** a tile or "Back to summary": a new history entry */
  goSection: (section: ResultsSection) => void;
}

export interface SectionMeta {
  title: string;
  /** the tip of the view's heading and of its tile on the summary (an existing tip of the same meaning) */
  tip: InfoTipId;
  /** what the tile says the view holds when it has no count to show */
  holds: string;
}

export const SECTION_META: Record<DetailSection, SectionMeta> = {
  collection: { title: "Collection jobs and targets", tip: "cbom.run.covered", holds: "Every job, its targets and provenance" },
  quantum: { title: "Quantum grades & fix effort", tip: "cbom.qgrade.distribution", holds: "Quantum risk grades and who fixes what" },
  inventory: { title: "Inventory & certificates", tip: "cbom.res.kpi.assets",
               holds: "Charts, certificates and keys, family × source, dependency graph" },
  migration: { title: "PQC migration plan", tip: "cbom.chart.roadmap", holds: "Quantum-vulnerable groups, fixes, CNSA 2.0 roadmap" },
  compliance: { title: "Compliance", tip: "cbom.run.compliance", holds: "Framework verdicts, clauses and the assets behind them" },
  remediation: { title: "Remediation waves & changes", tip: "cbom.run.waves", holds: "Waves, progress and drift" },
};
