/**
 * Which (i) tips the Explanations drawer lists for each view of the Sources-run results page and each tab of the run
 * finding dialog (PLAN §5, board 36-D). Ids only (the eager label index names them; the text loads per area through
 * loadTipArea), derived from the components each view and tab mounts:
 *   run.summary     CbomResults run header (RunHeaderActions, RunDeliverablesMenu, RunVerifyButton), coverage notes,
 *                   KPI tiles, RunMetaCards, RunPostureCard + ReadinessExplainer, RunTopRisks, RunFindingsTable
 *   run.collection  RunCoverageSection, RunJobsTable, provenance table, RunResults targets
 *   run.quantum     QDistributionCard (grade/QGrade.tsx), AgilityPostureCard (grade/Agility.tsx, grade/tips.ts)
 *   run.inventory   CbomCryptoCharts (inventory parts), CbomDashboardCharts, certificates (RunSections), CertCalendar
 *   run.migration   CbomCryptoCharts (quantum-vulnerable algorithms, fixes, roadmap, CNSA 2.0, replacements)
 *   run.compliance  ComplianceSummary, CbomDashboardCharts compliance / OWASP cards
 *   run.remediation RunWavesSection, RunChanges, CbomDashboardCharts remediation cards, RunFindingsTable
 *   dialog.*        RunFindingDialog tabs (Overview, Issues, Quantum & effort, Standards, Fix & demo, AI)
 * content/infotips/drawerManifest.test.ts checks every id exists and every dialog id is rendered by the dialog's
 * components. A tip opened from an (i) that is not listed here is still shown (the drawer puts it first).
 */
import type { InfoTipId } from "./labels";

const FINDINGS_TABLE = [
  "cbom.run.findings", "cbom.run.view", "cbom.run.search", "cbom.run.filter.impact", "cbom.run.filter.type",
  "cbom.run.filter.quantum", "cbom.run.filter.source", "cbom.run.filter.status", "results.table.impact",
  "cbom.res.col.algorithm", "cbom.res.col.type", "cbom.run.col.where", "cbom.run.col.finding", "cbom.res.col.strength",
  "cbom.res.col.quantum", "cbom.run.f.risk", "cbom.run.col.source", "cbom.run.col.wave", "cbom.run.col.status",
  "cbom.run.col.qgrade", "cbom.res.col.fix_class", "results.finding.action",
] as const satisfies readonly InfoTipId[];

const AGILITY_CLASSES = [
  "cbom.agility.configurable", "cbom.agility.code_fixed", "cbom.agility.vendor_fixed", "cbom.agility.hardware_fixed",
  "cbom.agility.unknown", "cbom.agility.inferred",
] as const satisfies readonly InfoTipId[];

export const DRAWER_MANIFEST = {
  "run.summary": [
    "cbom.run.downloads", "cbom.run.deliverables", "cbom.run.verify", "cbom.run.covered", "cbom.res.coverage",
    "cbom.res.import_notes", "cbom.res.kpi.assets", "cbom.res.kpi.weak", "cbom.res.kpi.qv", "cbom.res.kpi.certs",
    "cbom.res.kpi.keys", "cbom.res.kpi.ready", "cbom.res.kpi.avg_risk", "cbom.run.col.endpoints", "cbom.run.col.duration",
    "cbom.run.posture", "cbom.run.mosca", "cbom.run.readiness", "cbom.run.readiness_actions", "cbom.run.top_risks",
    "cbom.run.col.priority", "cbom.run.col.asset", "cbom.run.col.criticality",
    "cbom.run.col.exposure", "cbom.run.col.hndl", "cbom.run.summary", "cbom.run.drill",
    ...FINDINGS_TABLE,
  ],
  "run.collection": [
    "cbom.run.provenance", "cbom.run.col.kind", "cbom.run.col.outcome", "cbom.run.col.assets_collected",
    "cbom.run.col.endpoints", "cbom.run.col.duration", "cbom.run.col.credits", "cbom.run.targets",
    "cbsrc.rr.job.source", "cbsrc.rr.job.runs_on", "cbsrc.rr.job.status", "cbsrc.rr.job.assets", "cbsrc.rr.job.attempts",
    "cbsrc.rr.job.credits", "cbsrc.rr.job.error", "cbsrc.rr.skipped_start",
  ],
  "run.quantum": [
    "cbom.run.quantum", "cbom.qgrade.distribution", "cbom.agility.section", "cbom.agility.excl_pq",
    "cbom.agility.self_fixable", ...AGILITY_CLASSES,
  ],
  "run.inventory": [
    "cbom.chart.algorithms", "cbom.chart.weak", "cbom.chart.pqc", "cbom.chart.asset_types", "cbom.chart.protocols",
    "cbom.chart.cert_expiry", "cbom.res.remediation", "cbom.res.owasp", "cbom.res.severity", "cbom.res.compliance",
    "cbom.res.algo_types", "cbom.res.strength", "cbom.res.quantum", "cbom.run.risk_scores", "cbom.res.remed.section",
    "cbom.run.certs", "cbom.run.cert.subject", "cbom.run.cert.issuer", "cbom.run.cert.expires", "cbom.run.cert.location",
    "cbom.run.cert.source", "cbom.cal.expiry", "cbom.run.certs.orphaned", "cbom.run.certs.unmanaged", "cbom.run.certificates",
  ],
  "run.migration": [
    "cbom.chart.qv", "cbom.chart.qv_fixes", "cbom.chart.qv_none", "cbom.chart.roadmap", "cbom.chart.cnsa",
    "cbom.chart.replacements",
  ],
  "run.compliance": ["cbom.run.compliance", "cbom.res.compliance", "cbom.res.owasp", "cbom.run.compliance_readiness"],
  "run.remediation": [
    "cbom.run.waves", "cbom.run.changes", "cbom.res.remediation", "cbom.res.remed.section", "sast.res.remed.backlog",
    "sast.res.remed.critical_fixed", "sast.res.remed.mttr", "sast.res.remed.velocity",
    ...FINDINGS_TABLE,
  ],
  "dialog.overview": [
    "cbom.run.f.type", "cbom.run.f.strength", "cbom.run.f.key_size", "cbom.run.f.quantum", "cbom.run.f.impact",
    "cbom.run.f.risk", "cbom.run.f.tls_grade", "cbom.run.f.status", "cbom.res.col.fix_class", "cbom.run.col.qgrade",
    "cbom.run.f.ticket", "cbom.run.col.priority", "cbom.run.f.location", "cbom.run.f.finding", "cbom.run.f.description",
    "cbom.run.f.suggested_fix", "cbom.run.f.owasp", "cbom.run.f.compliance", "cbom.run.f.origin",
  ],
  "dialog.issues": ["cbom.run.f.finding"],
  "dialog.quantum": ["cbom.run.col.qgrade", "cbom.res.col.fix_class", ...AGILITY_CLASSES],
  "dialog.standards": ["cbom.run.f.compliance"],
  "dialog.fix": ["cbom.run.f.suggested_fix"],
  "dialog.ai": ["cbom.ai.panel", "cbom.ai.question"],
} as const satisfies Record<string, readonly InfoTipId[]>;

export type DrawerView = keyof typeof DRAWER_MANIFEST;

/** Human names of the views and tabs, as the drawer's heading shows them. */
export const DRAWER_VIEW_LABEL: Record<DrawerView, string> = {
  "run.summary": "Summary",
  "run.collection": "Collection jobs and targets",
  "run.quantum": "Quantum grades and fix effort",
  "run.inventory": "Inventory and certificates",
  "run.migration": "PQC migration plan",
  "run.compliance": "Compliance",
  "run.remediation": "Remediation waves and changes",
  "dialog.overview": "Finding: Overview",
  "dialog.issues": "Finding: Issues",
  "dialog.quantum": "Finding: Quantum and effort",
  "dialog.standards": "Finding: Standards",
  "dialog.fix": "Finding: Fix and demo",
  "dialog.ai": "Finding: AI",
};

/** The drawer's ids for a view: the view's own, then (for a dialog tab) the other tabs' ids, each once. */
export function drawerIds(view: DrawerView): InfoTipId[] {
  const own = DRAWER_MANIFEST[view] as readonly InfoTipId[];
  const prefix = view.split(".")[0];
  const siblings = (Object.keys(DRAWER_MANIFEST) as DrawerView[])
    .filter((v) => v !== view && v.startsWith(`${prefix}.`))
    .flatMap((v) => DRAWER_MANIFEST[v] as readonly InfoTipId[]);
  return [...new Set([...own, ...siblings])];
}
