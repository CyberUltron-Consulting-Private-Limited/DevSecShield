// Tests only: a Sources run adapter (SourcesRunSource) with the payloads every run view reads, built with the real
// plan and dashboard model functions, and a render of CbomResults in run mode at a given URL (?section=…).
import "./cssStub";
import React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { QueryClient } from "@tanstack/react-query";

import { cbomSourcesKeys } from "@/components/cbom/sources/keys";
import { GRADE_KEYS } from "@/components/cbom/grade/model";

import CbomResults from "@/components/CbomResults";
import type { CbomJobTargets, CbomRun, CbomRunResults } from "@/utils/backend_api";
import type { CbomPostureWithExposure } from "@/utils/api/cbom_outputs";

import { DEFAULT_FILTERS, runDashboardModel, runSectionPlan, type ResultsState } from "../model";
import type { SourcesRunSource } from "../source";
import { CODE_DASHBOARD, CODE_DATA } from "./codeModeFixture";
import { normaliseIds, withAppRouter } from "./codeModeRender";

export const RUN: CbomRun = {
  id: 40, team_id: 2, owner_user_id: 1, scan_id: null, status: "partial", include: {} as CbomRun["include"],
  breakdown: { skipped: [] }, credits: { charged: 1, refunded: 0, net: 1 }, soc_ack_by: null, soc_ack_at: null,
  cancelled_by: null, cancelled_at: null, finished_at: "2026-11-15T18:18:00Z", created_at: "2026-11-15T18:13:00Z", last_updated: null,
  jobs: [
    { id: 7, run_id: 40, source_id: 3, source_name: "EJBCA lab", node_id: 1, node_name: "lab-node", kind: "collect", status: "success",
      waiting_reason: null, attempts: 1, credits: 1, refunded: false, created_at: null, claimed_at: null, finished_at: null, result: {},
      error: null, outcome: "ok", asset_count: 3, samples: [], server_time: "2026-11-15T18:18:00Z" },
    { id: 8, run_id: 40, source_id: 4, source_name: "F5 lab", node_id: 1, node_name: "lab-node", kind: "collect", status: "failure",
      waiting_reason: null, attempts: 2, credits: 0, refunded: true, created_at: null, claimed_at: null, finished_at: null, result: {},
      error: "connection refused", outcome: "failed", asset_count: 0, samples: [], server_time: "2026-11-15T18:18:00Z" },
  ],
};

export const TARGETS: CbomJobTargets[] = [
  { job_id: 7, source_id: 3, source_name: "EJBCA lab", status: "success", outcome: "ok", attempt: 1, asset_count: 3, counts: { total: 1, ok: 1 },
    summary: null, truncated: false, asset_mismatch: null, error: null, targets: [{ target: "ejbca.lab", status: "ok" }], duration_s: 4,
    lab_mode: "same_account", assets_read: 3, gaps: 0 },
  { job_id: 8, source_id: 4, source_name: "F5 lab", status: "failure", outcome: "failed", attempt: 2, asset_count: 0, counts: { total: 1, failed: 1 },
    summary: null, truncated: false, asset_mismatch: null, error: "connection refused", targets: [{ target: "10.0.0.64:443", status: "failed", error: "refused" }],
    duration_s: 2, assets_read: 0, gaps: 1 },
];

export const POSTURE = {
  assets: 3,
  pqc_classes: { "quantum-vulnerable": 2, hybrid: 0, "quantum-safe": 1, "grover-weakened": 0, unknown: 0, "not-applicable": 0 },
  pqc_readiness_pct: 33.3,
  readiness_basis: { judged: 3, ready: 1, unknown: 0, not_applicable: 0, status: "ok" },
  readiness_actions: [{ asset_type: "certificate", type_label: "certificate", type_label_plural: "certificates", code: "RSA_QV",
    title: "Quantum-vulnerable algorithm", fix: "Re-issue with ML-DSA", assets: 2, readiness_after: 100 }],
  readiness_excluded: [],
  hndl_assets: 0,
  impacts: { Critical: 1, High: 1, Medium: 0, Low: 0 },
  top_codes: [{ code: "RSA_QV", count: 2, title: "Quantum-vulnerable algorithm" }],
  mosca: { configured: false, x: null, y: null, z: null, note: "Set X, Y and Z to run the Mosca test." },
  mosca_now: null,
  top_risks: [1, 2, 3, 4].map((i) => ({ id: 100 + i, type: "certificate", name: `Risk asset ${i}`, location: `ejbca.lab/${i}`,
    impact: i === 1 ? "Critical" : "High", criticality: "high", source_name: "EJBCA lab", score: 12 - i, hndl: i === 2,
    finding: i === 1 ? "RSA-1024 key; SHA-1 self-signature" : "Quantum-breakable", exposure: i === 1 ? "internet" : "internal" })),
  exposure_factors: { internet: 1.5, internal: 1, unknown: 1 },
  compliance: [{ framework: "NIST", clauses: [{ id: "SP 800-131A", text: "t", source: "https://example.test/nist", assets: 2, codes: ["RSA_QV"] }] }],
  kb_version: "kb-2026.11",
  pqc_context: { z_note: "Z is your organisation's assumption." },
  // one asset graded Critical, one High, one Low (keys from GRADE_KEYS: a grade is never spelled bare in the UI sources)
  q_grades: { ...Object.fromEntries(GRADE_KEYS.map((k, i) => [k, [0, 1, 1, 0, 1][i]])), none: 0 },
  fix_class_self_fixable_pct: 66.7,
} as unknown as CbomPostureWithExposure;

export const RESULTS = {
  run: RUN,
  dashboard: CODE_DASHBOARD,
  distributions: CODE_DATA.cbom_distributions,
  compliance: { frameworks: [{ framework: "NIST", clauses: [{ clause: "SP 800-131A", title: "t", assets: 2, codes: ["RSA_QV"] }] }] },
  certificates_orphaned: [], certificates_unmanaged: [], certificates_basis: "endpoints_probed",
  provenance: [{ source_id: 3, source: "EJBCA lab", kind: "ejbca", runner: "node", node: "lab-node", outcome: "ok", assets: 3, endpoints_probed: 0, duration_s: 4, credits: 1 }],
  computed_at: "2026-11-15T18:19:00Z",
  state: "ready",
} as unknown as CbomRunResults;

export interface RunCalls { openAsset: number[]; filters: unknown[]; dialog: unknown[] }

export function fakeRunSource(over: Partial<SourcesRunSource> = {}, calls: RunCalls = { openAsset: [], filters: [], dialog: [] }): SourcesRunSource {
  const resultsState: ResultsState = { kind: "ok", data: RESULTS };
  const base: SourcesRunSource = {
    kind: "run", teamId: 2, runId: 40, state: "ready", run: RUN, active: false, now: Date.parse("2026-11-15T18:20:00Z"), canCompare: true,
    sources: [{ id: 3, name: "EJBCA lab" }, { id: 4, name: "F5 lab" }], nodes: ["lab-node"],
    results: RESULTS,
    parity: { run_id: 40, scan_metadata: { cbom_coverage: { notes: [{ key: "x", text: "One target was not read", kind: "skipped" }], skipped: 1 } } } as unknown as SourcesRunSource["parity"],
    parityState: "ok", resultsState, posture: POSTURE,
    plan: runSectionPlan({ results: resultsState, posture: POSTURE }),
    dashboardModel: runDashboardModel(RESULTS.dashboard, POSTURE),
    riskRows: [],
    page: { total: 1, all_total: 3, findings_total: 1, page: 1, page_size: 50, facets: { type: {}, impact: {}, quantum_vulnerable: 2 }, targets: TARGETS,
      items: [{ id: 101, type: "certificate", cdx_type: "cryptographic-asset", job_id: 7, source_id: 3, source_name: "EJBCA lab", target: "ejbca.lab",
        location: "ejbca.lab/1", name: "Risk asset 1", algorithm: "RSA", key_size: 1024, protocol: null, quantum_vulnerable: true, impact: "Critical",
        finding: "RSA-1024 key", finding_codes: ["RSA_QV"], facts: {} }] } as unknown as SourcesRunSource["page"],
    pageLoading: false, pagePlaceholder: false, pageError: null, refetchPage: () => undefined,
    filters: { ...DEFAULT_FILTERS },
    onFilters: (patch) => { calls.filters.push(patch); },
    selection: new Map(), setSelection: () => undefined, setStatus: () => undefined, statusPending: false,
    waves: { data: { by_wave: { "1": 1, "4": 1 } } as unknown as SourcesRunSource["waves"]["data"], loading: false, wanted: true },
    waveOf: () => undefined,
    dialog: null, setDialog: (d) => { calls.dialog.push(d); },
    openAsset: (id) => { calls.openAsset.push(id); },
    compareOpen: false, setCompareOpen: () => undefined, compareRuns: [],
  };
  return { ...base, ...over };
}

/** CbomResults in run mode at `?run=1&<search>` (React ids normalised); the posture (and an admin viewer) are in the
 * query cache, as after the adapter's first read. */
export function renderRunMode(search = "", source: SourcesRunSource = fakeRunSource(), posture: CbomPostureWithExposure | null = POSTURE): string {
  const qs = `run=1${search ? `&${search}` : ""}`;
  const client = new QueryClient();
  if (posture) client.setQueryData(cbomSourcesKeys.runPosture(2, 40), posture);
  client.setQueryData(cbomSourcesKeys.overview(2), { viewer: { is_admin: true } });
  return normaliseIds(renderToStaticMarkup(withAppRouter(
    React.createElement(CbomResults, { data: undefined, teamId: "2", source }), qs, { team_id: "2", scan_id: "40" }, client)));
}
