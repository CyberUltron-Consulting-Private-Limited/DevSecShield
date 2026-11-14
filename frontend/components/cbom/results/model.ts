// Pure view-model for the Sources run results page (CB-38 PR-1c). No React, no fetching: every function here takes the
// API payloads and returns what a section shows, so the rules are tested without a browser (model.test.ts,
// ruleP.test.ts).
//
// Rule P (PLAN §2.5): for a run, every readiness / PQC-class / severity-total / posture number on the page is read
// from the run API (`/runs/{id}/posture`, `/runs/{id}/assets` items, `/runs/{id}/heatmap`, `/runs/{id}/results`),
// never recounted from table rows. The mapping functions below copy posture fields 1:1 into the code page's card
// props; none of them looks at a row.

import type {
  CbomFindingStatus,
  CbomRun,
  CbomRunAssetItem,
  CbomRunAssetPage,
  CbomRunDashboard,
  CbomRunPosture,
  CbomRunResults,
  CbomScanDashboardData,
  CbomWaveStatusName,
} from "@/utils/backend_api";
import type { CbomDistributions, PqcMigrationRow } from "@/components/cbom/CbomCryptoCharts";

// ---------------------------------------------------------------------------- statuses

/** Finding status -> assignment status (contracts/cbom/status_buckets.json `assignment_to_finding`, inverted). */
export const FINDING_TO_ASSIGNMENT: Record<CbomFindingStatus, CbomWaveStatusName> = {
  fixed: "done",
  ignored: "accepted_risk",
  in_progress: "in_progress",
  not_started: "open",
};

/** Assignment status -> finding status (contracts/cbom/status_buckets.json `assignment_to_finding`). */
export const ASSIGNMENT_TO_FINDING: Record<CbomWaveStatusName, CbomFindingStatus> = {
  open: "not_started",
  in_progress: "in_progress",
  done: "fixed",
  accepted_risk: "ignored",
};

/** Run status -> the scan list's unified status (contracts/cbom/status_buckets.json `run_to_unified`). */
export const RUN_TO_UNIFIED: Record<string, string> = {
  queued: "pending",
  running: "started",
  done: "success",
  partial: "partial",
  failed: "failure",
  cancelled: "cancelled",
};

export const FINDING_STATUSES: CbomFindingStatus[] = ["not_started", "in_progress", "fixed", "ignored"];

export const FINDING_STATUS_LABEL: Record<CbomFindingStatus, string> = {
  not_started: "Not started",
  in_progress: "In progress",
  fixed: "Fixed",
  ignored: "Ignored",
};

export function isActiveRunStatus(status: string | null | undefined): boolean {
  return status === "queued" || status === "running";
}

/** The unified finding status of a row: the API's `status`, else its raw assignment mapped, else (older backend
 * without either field) the assignment of the row's wave entry from /runs/{id}/remediation, else not started. */
export function findingStatusOf(item: Pick<CbomRunAssetItem, "status" | "assignment_status">,
                                wave?: { assignment?: { status?: CbomWaveStatusName | null } | null } | null): CbomFindingStatus {
  if (item.status && item.status in FINDING_TO_ASSIGNMENT) return item.status;
  if (item.assignment_status && item.assignment_status in ASSIGNMENT_TO_FINDING) return ASSIGNMENT_TO_FINDING[item.assignment_status];
  const fromWave = wave?.assignment?.status;
  if (fromWave && fromWave in ASSIGNMENT_TO_FINDING) return ASSIGNMENT_TO_FINDING[fromWave];
  return "not_started";
}

/** PUT /cbom/remediation accepts at most 2,000 items per request (waves.py MAX_ITEMS). */
export const REMEDIATION_BATCH = 2000;

export interface RemediationStatusBody {
  run_id: number;
  items: { asset_key: string; status: CbomWaveStatusName }[];
}

/** The request bodies that set `status` on every key: de-duplicated, empty keys dropped, ≤ 2,000 items each. */
export function statusRequestBodies(runId: number, keys: (string | null | undefined)[], status: CbomFindingStatus,
                                    batch = REMEDIATION_BATCH): RemediationStatusBody[] {
  const unique = Array.from(new Set(keys.filter((k): k is string => typeof k === "string" && k.length > 0)));
  const mapped = FINDING_TO_ASSIGNMENT[status];
  const out: RemediationStatusBody[] = [];
  for (let i = 0; i < unique.length; i += batch) {
    out.push({ run_id: runId, items: unique.slice(i, i + batch).map((asset_key) => ({ asset_key, status: mapped })) });
  }
  return out;
}

// ---------------------------------------------------------------------------- Rule P mappings

/** Posture classes that count as "ready" in posture's own readiness (posture.py: judged minus quantum-vulnerable). */
export const READY_CLASSES = ["hybrid", "quantum-safe", "grover-weakened"] as const;

type PostureLike = Pick<CbomRunPosture, "pqc_readiness_pct" | "pqc_classes" | "impacts">;

/** Overlay the posture figures onto the run dashboard, 1:1 (Rule P). The /results dashboard already carries the same
 * values (W2 maps them from run_posture); the page still takes them from /posture so the card, the readiness chart and
 * the posture card can never disagree, even while a cached /results lags a live posture. */
export function applyPostureToDashboard(dashboard: CbomScanDashboardData, posture: PostureLike | null | undefined): CbomScanDashboardData {
  if (!posture) return dashboard;
  const classes = posture.pqc_classes ?? ({} as Record<string, number>);
  const vulnerable = classes["quantum-vulnerable"] ?? 0;
  const ready = READY_CLASSES.reduce((n, c) => n + (classes[c] ?? 0), 0);
  const impacts = posture.impacts ?? ({} as Record<string, number>);
  return {
    ...dashboard,
    card_data: {
      ...dashboard.card_data,
      quantum_readiness_score: posture.pqc_readiness_pct ?? 0,
      quantum_readiness_judged: posture.pqc_readiness_pct != null,
      total_quantum_vulnerable: vulnerable,
    },
    severity_distribution: {
      ...dashboard.severity_distribution,
      critical: impacts.Critical ?? 0,
      high: impacts.High ?? 0,
      medium: impacts.Medium ?? 0,
      low: impacts.Low ?? 0,
    },
    quantum_readiness: { ...dashboard.quantum_readiness, quantum_safe: ready, quantum_vulnerable: vulnerable },
  };
}

/** The same overlay for the crypto charts' PQC gauge (distributions.pqc). */
export function applyPostureToDistributions(dist: CbomDistributions, posture: PostureLike | null | undefined): CbomDistributions {
  if (!posture) return dist;
  const classes = posture.pqc_classes ?? ({} as Record<string, number>);
  return {
    ...dist,
    pqc: {
      ...dist.pqc,
      readiness_pct: posture.pqc_readiness_pct ?? 0,
      quantum_vulnerable: classes["quantum-vulnerable"] ?? 0,
      quantum_safe: READY_CLASSES.reduce((n, c) => n + (classes[c] ?? 0), 0),
      hybrid: classes.hybrid ?? 0,
    },
  };
}

export function remediationMetricsAvailable(dashboard: CbomRunDashboard | null | undefined): boolean {
  if (!dashboard) return false;
  if (dashboard.metrics_available === false) return false;
  if (dashboard.remediation_metrics?.metrics_available === false) return false;
  return !!dashboard.remediation_metrics;
}

export interface RunDashboardModel {
  /** what CbomDashboardCharts renders; null when the backend sent no dashboard */
  dashboard: CbomScanDashboardData | null;
  metricsAvailable: boolean;
}

/** S11: the code page's dashboard for a run. Remediation metrics are left out (CbomDashboardCharts then hides the card)
 * when the backend says they are not available yet. */
export function runDashboardModel(dashboard: CbomRunDashboard | null | undefined, posture: PostureLike | null | undefined): RunDashboardModel {
  if (!dashboard || !dashboard.card_data) return { dashboard: null, metricsAvailable: false };
  const metricsAvailable = remediationMetricsAvailable(dashboard);
  const withPosture = applyPostureToDashboard(dashboard, posture);
  const shown = metricsAvailable
    ? withPosture
    : ({ ...withPosture, remediation_metrics: undefined } as unknown as CbomScanDashboardData);
  return { dashboard: shown, metricsAvailable };
}

/** Q-grade (CB-19) and fix-class (CB-24) counts from the posture payload, passed through in the API's order. */
export function postureDistribution(value: unknown): [string, number][] {
  if (!value || typeof value !== "object" || Array.isArray(value)) return [];
  return Object.entries(value as Record<string, unknown>)
    .filter((e): e is [string, number] => typeof e[1] === "number" && Number.isFinite(e[1]));
}

// ---------------------------------------------------------------------------- section plan

export type RunSectionId =
  | "header" | "coverage" | "tabs" | "meta" | "posture" | "insights" | "certificates" | "cryptoCharts" | "changes"
  | "waves" | "compliance" | "dashboard" | "findings" | "topRisks" | "findingDialog";

/** The run page's Ticketing tab (RunTicketingTab, CB-38 PR-4: Jira for Sources runs). */
export const RUN_TICKETING_TAB_AVAILABLE = true;

/** What a run can download or attest today (PLAN §4.4: VEX, signature, evidence pack and PDF are code-scan only until PR-8). */
export const RUN_CAPABILITIES = {
  cdxJson: true, cdxXml: true, oscal: true, vex: false, signature: false, evidencePack: false, pdf: false,
  certInAttest: false, jira: RUN_TICKETING_TAB_AVAILABLE, compare: true, waves: true, statusActions: true,
  ai: true, // AiRemediationPanel in the finding dialog (CB-38 PR-6); it renders nothing when the assistant is off
} as const;

export type ResultsState =
  | { kind: "loading" }
  | { kind: "missing" }            // 404 from a backend without /results
  | { kind: "error" }
  | { kind: "ok"; data: CbomRunResults };

export interface SectionView { show: boolean; note?: string }

export const NOTE = {
  resultsMissing: "This server does not offer the run results summary yet; this section appears after the backend update.",
  resultsError: "The run results summary could not be loaded; reload the page to try again.",
  certsNone: "No orphaned or unmanaged certificates in this run.",
  certsField: "Orphaned and unmanaged certificates are not in this server's run results yet.",
  chartsField: "Crypto charts are not in this server's run results yet.",
  chartsCodeOnly: "The crypto dependency graph and the tri-state compliance matrix are built from source code; a Sources run has neither, so they are shown on code scans only.",
  complianceNone: "No finding of this run maps to a CERT-In, RBI, SEBI CSCRF, NIST or CNSA 2.0 clause.",
  dashboardField: "Dashboard charts are not in this server's run results yet.",
  metricsLater: "Remediation metrics (time to remediate, velocity) appear once fixes are recorded with their completion date.",
  computing: "Computing results for this large run…; this section fills in when the summary is ready.",
  noEndpoints: "This run probed no endpoint, so no stored certificate can be called orphaned (nothing to compare it with).",
} as const;

function resultsNote(results: ResultsState): string | undefined {
  if (results.kind === "missing") return NOTE.resultsMissing;
  if (results.kind === "error") return NOTE.resultsError;
  return undefined;
}

/** Which sections render, and the one-line note a section shows instead of an empty chart. */
export function runSectionPlan(input: {
  results: ResultsState;
  posture: Pick<CbomRunPosture, "assets" | "top_risks" | "compliance"> | null | undefined;
}): Record<RunSectionId, SectionView> {
  const { results, posture } = input;
  const data = results.kind === "ok" ? results.data : null;
  const pending = results.kind === "loading";
  const missing = resultsNote(results);
  const computing = data?.state === "computing";

  const certificates: SectionView = (() => {
    if (pending) return { show: false };
    if (!data) return { show: true, note: missing };
    if (computing) return { show: true, note: NOTE.computing };
    if (data.certificates_orphaned == null && data.certificates_unmanaged == null) return { show: true, note: NOTE.certsField };
    if (data.certificates_basis === "no_endpoints_probed" && !(data.certificates_unmanaged ?? []).length) return { show: true, note: NOTE.noEndpoints };
    if (!(data.certificates_orphaned ?? []).length && !(data.certificates_unmanaged ?? []).length) return { show: true, note: NOTE.certsNone };
    return { show: true };
  })();

  const cryptoCharts: SectionView = (() => {
    if (pending) return { show: false };
    if (!data) return { show: true, note: missing };
    if (computing) return { show: true, note: NOTE.computing };
    if (!data.distributions) return { show: true, note: NOTE.chartsField };
    return { show: true, note: NOTE.chartsCodeOnly };
  })();

  const compliance: SectionView = (() => {
    const fromResults = (data?.compliance?.frameworks ?? []).some((f) => (f.clauses ?? []).length > 0);
    const fromPosture = (posture?.compliance ?? []).some((f) => (f.clauses ?? []).length > 0);
    if (fromResults || fromPosture) return { show: true };
    if (pending || !posture) return { show: false };
    return { show: true, note: NOTE.complianceNone };
  })();

  const dashboard: SectionView = (() => {
    if (pending) return { show: false };
    if (!data) return { show: true, note: missing };
    if (computing) return { show: true, note: NOTE.computing };
    if (!data.dashboard?.card_data) return { show: true, note: NOTE.dashboardField };
    return { show: true, note: remediationMetricsAvailable(data.dashboard) ? undefined : NOTE.metricsLater };
  })();

  return {
    header: { show: true },
    coverage: { show: true },
    tabs: { show: RUN_TICKETING_TAB_AVAILABLE },
    meta: { show: true },
    posture: { show: true },
    insights: { show: true },
    certificates,
    cryptoCharts,
    changes: { show: true },
    waves: { show: true },
    compliance,
    dashboard,
    findings: { show: true },
    topRisks: { show: (posture?.top_risks ?? []).length > 0 },
    findingDialog: { show: true },
  };
}

/** S10 frameworks: /results.compliance when present, else the posture's clauses (the same KB mapping). */
export interface ComplianceRow { framework: string; clauses: { clause: string; title: string; assets: number; codes: string[]; source?: string }[] }

export const FRAMEWORK_ORDER = ["CERT-In", "RBI", "SEBI CSCRF", "NIST", "CNSA 2.0"];

export function complianceRows(results: CbomRunResults | null | undefined,
                               posture: Pick<CbomRunPosture, "compliance"> | null | undefined): { rows: ComplianceRow[]; basis: "results" | "posture" | "none" } {
  const order = (fw: string) => { const i = FRAMEWORK_ORDER.indexOf(fw); return i < 0 ? FRAMEWORK_ORDER.length : i; };
  const sort = (rows: ComplianceRow[]) => [...rows].sort((a, b) => order(a.framework) - order(b.framework) || a.framework.localeCompare(b.framework));
  // /results always lists the five frameworks, empty ones included: only frameworks with a clause are shown
  const fromResults = (results?.compliance?.frameworks ?? []).filter((f) => (f.clauses ?? []).length > 0);
  if (fromResults.length) return { rows: sort(fromResults.map((f) => ({ framework: f.framework, clauses: f.clauses }))), basis: "results" };
  const fromPosture = (posture?.compliance ?? []).filter((f) => (f.clauses ?? []).length > 0);
  if (fromPosture.length) {
    return {
      rows: sort(fromPosture.map((f) => ({
        framework: f.framework,
        clauses: f.clauses.map((c) => ({ clause: c.id, title: c.text, assets: c.assets, codes: c.codes, source: c.source })),
      }))),
      basis: "posture",
    };
  }
  return { rows: [], basis: "none" };
}

// ---------------------------------------------------------------------------- header / metadata

export function runTitle(runId: number): string {
  return `Sources run #${runId}`;
}

/** Seconds from start to finish (to `nowMs` while the run is active); null without a start time. */
export function runDurationSeconds(run: Pick<CbomRun, "created_at" | "finished_at" | "status">, nowMs: number): number | null {
  if (!run.created_at) return null;
  const start = Date.parse(run.created_at);
  if (!Number.isFinite(start)) return null;
  const endIso = run.finished_at ?? null;
  const end = endIso ? Date.parse(endIso) : isActiveRunStatus(run.status) ? nowMs : NaN;
  if (!Number.isFinite(end)) return null;
  return Math.max(0, Math.round((end - start) / 1000));
}

export function formatDuration(seconds: number | null): string {
  if (seconds == null) return "—";
  if (seconds < 60) return `${seconds}s`;
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = seconds % 60;
  if (h > 0) return `${h}h ${m}m`;
  return s ? `${m}m ${s}s` : `${m}m`;
}

/** Distinct sources of the run (from its jobs, else the provenance rows), in first-seen order. */
export function runSources(run: Pick<CbomRun, "jobs">, provenance?: CbomRunResults["provenance"]): { id: number | null; name: string }[] {
  const seen = new Map<string, { id: number | null; name: string }>();
  for (const j of run.jobs ?? []) {
    const name = j.source_name ?? (j.source_id != null ? `Source ${j.source_id}` : null);
    if (name && !seen.has(name)) seen.set(name, { id: j.source_id ?? null, name });
  }
  for (const p of provenance ?? []) {
    const name = p.source ?? (p.source_id != null ? `Source ${p.source_id}` : null);
    if (name && !seen.has(name)) seen.set(name, { id: p.source_id ?? null, name });
  }
  return [...seen.values()];
}

/** Distinct places the run's jobs ran: scan node names, or "ZeroShield cloud". */
export function runNodes(run: Pick<CbomRun, "jobs">, provenance?: CbomRunResults["provenance"]): string[] {
  const out = new Set<string>();
  for (const j of run.jobs ?? []) {
    if (j.runner === "cloud") out.add("ZeroShield cloud");
    else if (j.node_name) out.add(j.node_name);
  }
  for (const p of provenance ?? []) {
    if (p.runner === "cloud") out.add("ZeroShield cloud");
    else if (p.node) out.add(p.node);
  }
  return [...out];
}

/** Endpoints probed: the per-source provenance figures of /results added up (null without provenance). */
export function endpointsProbed(results: CbomRunResults | null | undefined): number | null {
  if (!results?.provenance?.length) return null;
  return results.provenance.reduce((n, p) => n + (p.endpoints_probed ?? 0), 0);
}

// ---------------------------------------------------------------------------- findings table

export interface RunTableFilters {
  view: "findings" | "all";
  type?: string;
  impact?: "Critical" | "High" | "Medium" | "Low";
  quantum?: boolean;
  q?: string;
  source_id?: number;
  status?: CbomFindingStatus;
  page: number;
  page_size: number;
}

export const DEFAULT_FILTERS: RunTableFilters = { view: "findings", page: 1, page_size: 50 };

/** The query the server pages and filters (all filtering is server-side; nothing is filtered in the browser). */
export function filtersToParams(f: RunTableFilters): Record<string, string | number | boolean> {
  const out: Record<string, string | number | boolean> = { view: f.view, page: f.page, page_size: f.page_size };
  if (f.type) out.type = f.type;
  if (f.impact) out.impact = f.impact;
  if (f.quantum) out.quantum = true;
  if (f.q) out.q = f.q;
  if (f.source_id != null) out.source_id = f.source_id;
  if (f.status) out.status = f.status;
  return out;
}

export function hasActiveFilters(f: RunTableFilters): boolean {
  return !!(f.type || f.impact || f.quantum || f.q || f.source_id != null || f.status);
}

/** The server understands `view` / `status` (W1) when it reports `findings_total`; an older server lists every asset. */
export function serverSupportsFindingsView(page: Pick<CbomRunAssetPage, "findings_total"> | null | undefined): boolean {
  return typeof page?.findings_total === "number";
}

/** The toggle counts, exactly as the API reports them (never counted from the page's rows). */
export function viewCounts(page: Pick<CbomRunAssetPage, "findings_total" | "all_total"> | null | undefined): { findings: number | null; all: number | null } {
  return {
    findings: typeof page?.findings_total === "number" ? page.findings_total : null,
    all: typeof page?.all_total === "number" ? page.all_total : null,
  };
}

export function pageCount(page: Pick<CbomRunAssetPage, "total" | "page_size"> | null | undefined): number {
  if (!page) return 1;
  return Math.max(1, Math.ceil(page.total / (page.page_size || 50)));
}

/** data-* attributes the gate reads per row (PLAN §4.2, §11): values straight from the API item. */
export function assetRowAttrs(item: CbomRunAssetItem, wave?: Parameters<typeof findingStatusOf>[1]): Record<string, string> {
  const attrs: Record<string, string> = {
    "data-impact": item.impact ?? "",
    "data-type": item.type ?? "",
    "data-location": item.location ?? "",
    "data-target": item.target ?? "",
    // `||` like the gate's judge (fieldmap.ui_expected: algorithm or protocol): an empty algorithm falls to the protocol
    "data-algorithm": item.algorithm || item.protocol || "",
    "data-key-size": item.key_size != null ? String(item.key_size) : "",
    "data-finding": item.finding ?? "",
    "data-quantum": item.quantum_vulnerable === true ? "vulnerable" : item.quantum_vulnerable === false ? "safe" : "",
    "data-status": findingStatusOf(item, wave),
  };
  if (item.q_grade != null) attrs["data-q-grade"] = item.q_grade;
  if (item.fix_class != null) attrs["data-fix-class"] = item.fix_class;
  return attrs;
}

/** Optional columns appear when the server sends the field at all (CB-19 q_grade, CB-24 fix_class; a null value is
 * "graded, no grade" and shows as such in the chip). */
export function optionalColumns(items: Pick<CbomRunAssetItem, "q_grade" | "fix_class">[]): { qGrade: boolean; fixClass: boolean } {
  return { qGrade: items.some((i) => i.q_grade !== undefined), fixClass: items.some((i) => i.fix_class !== undefined) };
}

/** Rows for the "Risk scores per finding" chart: the page's rows as CbomFinding-shaped records with the API's score. */
export function riskScoreRows(items: CbomRunAssetItem[]): { id: string; title: string; algorithm_name: string; risk_score: number }[] {
  return items
    .filter((i) => typeof i.risk_score === "number")
    .map((i) => ({
      id: `run-${i.id}`,
      title: i.name ?? i.location,
      algorithm_name: i.algorithm_name ?? i.algorithm ?? i.name ?? i.location,
      risk_score: i.risk_score as number,
    }));
}

/** Wave chips (S9) from the run remediation summary, in wave order, "No action" last. */
export function waveChips(byWave: Record<string, number> | null | undefined): { key: string; label: string; count: number; wave: number | null }[] {
  return Object.entries(byWave ?? {})
    .map(([key, count]) => ({ key, count, wave: key === "none" ? null : Number(key), label: key === "none" ? "No action" : `Wave ${key}` }))
    .sort((a, b) => (a.wave ?? 99) - (b.wave ?? 99));
}

// ---------------------------------------------------------------------------- certificates (S6)

export interface CertListView { listed: number; total: number; truncated: boolean; label: string | null }

/** The count to print for a certificate list: the API's total (lists are capped at 2,000), never the list length. */
export function certListView(results: CbomRunResults | null | undefined, which: "orphaned" | "unmanaged"): CertListView {
  const list = (which === "orphaned" ? results?.certificates_orphaned : results?.certificates_unmanaged) ?? [];
  const totalField = which === "orphaned" ? results?.certificates_orphaned_total : results?.certificates_unmanaged_total;
  const total = typeof totalField === "number" ? totalField : list.length;
  return { listed: list.length, total, truncated: total > list.length, label: results?.certificates_labels?.[which] ?? null };
}

export function certCountText(v: Pick<CertListView, "listed" | "total" | "truncated">): string {
  return v.truncated ? `${v.total.toLocaleString()} (showing ${v.listed.toLocaleString()} of ${v.total.toLocaleString()})` : v.total.toLocaleString();
}

// ---------------------------------------------------------------------------- live polling (PLAN §5.3)

/** /results is recomputed per request while a run is active: poll it every 30 s, and only for runs of ≤ 5,000 assets;
 * a larger active run is read once and again when it finishes. */
export const RESULTS_LIVE_MAX_ASSETS = 5000;
export const RESULTS_POLL_MS = 30_000;

export function resultsPollInterval(active: boolean, assetTotal: number | null | undefined): number | false {
  if (!active) return false;
  if (typeof assetTotal !== "number" || assetTotal > RESULTS_LIVE_MAX_ASSETS) return false;
  return RESULTS_POLL_MS;
}

/** The run query stops polling on any error (403 / 404 / 422 / 5xx): it is shown, not retried every few seconds. */
export function runPollInterval(status: string | undefined, hasError: boolean): number | false {
  if (hasError) return false;
  return !status || isActiveRunStatus(status) ? 6000 : false;
}

/** A run URL the viewer cannot open: another team's (403), unknown (404) or not a valid id (422). */
export function isNotFoundStatus(status: number | undefined): boolean {
  return status === 403 || status === 404 || status === 422;
}

/** The whole-run /remediation list is needed only for an older backend (rows without `wave`) or for the S9 chips of a
 * finished run; a newer backend's rows carry their own wave and key. */
export function needsRunRemediationList(page: Pick<CbomRunAssetPage, "findings_total"> | null | undefined, active: boolean): boolean {
  if (!page) return false;
  return !serverSupportsFindingsView(page) || !active;
}

/** The total next to the toggle: with a filter on, the filtered `total`; without, the view's own total. */
export function tableTotal(page: Pick<CbomRunAssetPage, "total" | "all_total" | "findings_total">, view: "findings" | "all",
                           filtered: boolean): number {
  if (filtered) return page.total;
  if (view === "all") return page.all_total;
  return typeof page.findings_total === "number" ? page.findings_total : page.total;
}

// ---------------------------------------------------------------------------- PQC migration rows (S7)

type KbText = { title?: string | null; fix?: string | null; standards?: string[] | null; pqc?: string | null };
type MigrationRowIn = PqcMigrationRow & { migration_code?: string | null; fix_code?: string | null };

/** A run's migration rows carry KB codes instead of text (/results sends each KB entry once, in `pqc.kb`): fill the
 * roadmap and fix from the entry, so the quantum-vulnerable list and the roadmap read as on a code scan. Text the row
 * already has wins; a code missing from `kb` leaves the field empty. */
export function resolveMigrationRows(dist: CbomDistributions): CbomDistributions {
  const pqc = dist.pqc as CbomDistributions["pqc"] & { kb?: Record<string, KbText> };
  const kb = pqc?.kb;
  if (!pqc?.migration?.length || !kb) return dist;
  const text = (code: string | null | undefined) => (code ? kb[code]?.fix ?? null : null);
  const migration = (pqc.migration as MigrationRowIn[]).map((r) => ({
    ...r,
    migration_roadmap: r.migration_roadmap ?? text(r.migration_code) ?? text(r.fix_code),
    suggested_fix: r.suggested_fix ?? text(r.fix_code) ?? text(r.migration_code),
  }));
  return { ...dist, pqc: { ...pqc, migration } };
}
