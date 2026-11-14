/**
 * Hermetic tests for the Sources run results page model (CB-38 PR-1c): status mapping and batching, section
 * visibility and honest notes, table helpers and header figures.
 * Run: npx --yes tsx components/cbom/results/model.test.ts
 */
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";

import type { CbomRunAssetItem, CbomRunPosture, CbomRunResults } from "@/utils/backend_api";
import {
  ASSIGNMENT_TO_FINDING,
  assetRowAttrs,
  complianceRows,
  endpointsProbed,
  filtersToParams,
  FINDING_TO_ASSIGNMENT,
  findingStatusOf,
  formatDuration,
  hasActiveFilters,
  NOTE,
  optionalColumns,
  pageCount,
  REMEDIATION_BATCH,
  RUN_CAPABILITIES,
  RUN_TICKETING_TAB_AVAILABLE,
  RUN_TO_UNIFIED,
  runDurationSeconds,
  runNodes,
  runSectionPlan,
  runSources,
  serverSupportsFindingsView,
  statusRequestBodies,
  viewCounts,
  waveChips,
} from "./model";

// ---------------------------------------------------------------- status mapping (BRIEF / contracts/cbom/status_buckets.json)
const CONTRACT = {
  run_to_unified: { queued: "pending", running: "started", done: "success", partial: "partial", failed: "failure", cancelled: "cancelled" },
  assignment_to_finding: { open: "not_started", in_progress: "in_progress", done: "fixed", accepted_risk: "ignored" },
};
// The shared fixture (W3 / W1) when it is in the tree; the brief's copy otherwise. Both must agree with the model.
const fixturePath = path.resolve(__dirname, "../../../../contracts/cbom/status_buckets.json");
const contract = fs.existsSync(fixturePath) ? JSON.parse(fs.readFileSync(fixturePath, "utf8")) : CONTRACT;
assert.deepEqual(ASSIGNMENT_TO_FINDING, contract.assignment_to_finding, "assignment -> finding status matches the contract");
assert.deepEqual(RUN_TO_UNIFIED, contract.run_to_unified, "run -> unified status matches the contract");
for (const [assignment, finding] of Object.entries(contract.assignment_to_finding as Record<string, string>)) {
  assert.equal(FINDING_TO_ASSIGNMENT[finding as keyof typeof FINDING_TO_ASSIGNMENT], assignment, `${finding} is written as ${assignment}`);
}
assert.deepEqual(FINDING_TO_ASSIGNMENT, { fixed: "done", ignored: "accepted_risk", in_progress: "in_progress", not_started: "open" });

assert.equal(findingStatusOf({ status: "fixed", assignment_status: "open" }), "fixed", "the API's status wins");
assert.equal(findingStatusOf({ status: null, assignment_status: "accepted_risk" }), "ignored", "raw assignment mapped");
assert.equal(findingStatusOf({}), "not_started", "no assignment = not started");

// one request per 2,000 keys, de-duplicated, empty keys dropped, status mapped
const keys = Array.from({ length: 4500 }, (_, i) => `node:k${i}`);
const bodies = statusRequestBodies(7, [...keys, "node:k1", "", null, undefined], "fixed");
assert.equal(REMEDIATION_BATCH, 2000);
assert.deepEqual(bodies.map((b) => b.items.length), [2000, 2000, 500]);
assert.ok(bodies.every((b) => b.run_id === 7));
assert.ok(bodies.every((b) => b.items.every((it) => it.status === "done")), "fixed is sent as done");
assert.equal(new Set(bodies.flatMap((b) => b.items.map((it) => it.asset_key))).size, 4500);
assert.deepEqual(statusRequestBodies(7, ["a"], "ignored")[0].items, [{ asset_key: "a", status: "accepted_risk" }]);
assert.deepEqual(statusRequestBodies(7, ["a"], "not_started")[0].items, [{ asset_key: "a", status: "open" }]);
assert.deepEqual(statusRequestBodies(7, [], "fixed"), [], "nothing selected: no request");

// ---------------------------------------------------------------- section plan
const posture = {
  assets: 7,
  top_risks: [{ id: 1 }],
  compliance: [{ framework: "RBI", clauses: [{ id: "RBI-1", text: "Crypto controls", source: "https://rbi", assets: 2, codes: ["TLS_WEAK"] }] }],
} as unknown as Pick<CbomRunPosture, "assets" | "top_risks" | "compliance">;

// older backend (no /results): one honest line per dependent section, never an empty chart
let plan = runSectionPlan({ results: { kind: "missing" }, posture });
assert.equal(plan.certificates.show, true);
assert.equal(plan.certificates.note, NOTE.resultsMissing);
assert.equal(plan.cryptoCharts.note, NOTE.resultsMissing);
assert.equal(plan.dashboard.note, NOTE.resultsMissing);
assert.equal(plan.compliance.show, true, "compliance falls back to the posture's clauses");
assert.equal(plan.compliance.note, undefined);
assert.equal(plan.topRisks.show, true);
assert.equal(plan.tabs.show, RUN_TICKETING_TAB_AVAILABLE);
for (const s of ["header", "coverage", "meta", "posture", "insights", "changes", "waves", "findings", "findingDialog"] as const) {
  assert.equal(plan[s].show, true, `${s} always renders`);
}

plan = runSectionPlan({ results: { kind: "error" }, posture: null });
assert.equal(plan.dashboard.note, NOTE.resultsError);
assert.equal(plan.compliance.show, false, "no posture yet: nothing to say");
assert.equal(plan.topRisks.show, false);

plan = runSectionPlan({ results: { kind: "loading" }, posture: null });
assert.equal(plan.dashboard.show, false, "still loading: no note yet");
assert.equal(plan.certificates.show, false);

const baseResults = { run: { id: 7 } } as unknown as CbomRunResults;
plan = runSectionPlan({ results: { kind: "ok", data: baseResults }, posture: { assets: 0, top_risks: [], compliance: [] } as never });
assert.equal(plan.certificates.note, NOTE.certsField, "fields absent: say so");
assert.equal(plan.cryptoCharts.note, NOTE.chartsField);
assert.equal(plan.dashboard.note, NOTE.dashboardField);
assert.equal(plan.compliance.note, NOTE.complianceNone);
assert.equal(plan.topRisks.show, false);

const fullResults = {
  ...baseResults,
  certificates_orphaned: [], certificates_unmanaged: [],
  distributions: { algorithms: {}, weakness: {}, pqc: { quantum_safe: 0, quantum_vulnerable: 0, readiness_pct: 0 }, certificates: [], protocols: {} },
  dashboard: { card_data: { total_crypto_assets: 1 }, remediation_metrics: { metrics_available: false } },
} as unknown as CbomRunResults;
plan = runSectionPlan({ results: { kind: "ok", data: fullResults }, posture });
assert.equal(plan.certificates.note, NOTE.certsNone);
assert.equal(plan.cryptoCharts.note, NOTE.chartsCodeOnly, "the code-only charts are stated once");
assert.equal(plan.dashboard.show, true);
assert.equal(plan.dashboard.note, NOTE.metricsLater, "remediation metrics hidden with a note");

const certResults = { ...fullResults, certificates_orphaned: [{ asset_id: 3, subject: "CN=a", issuer: null, not_after: null, location: "/etc/a.pem", source: "srv" }] } as CbomRunResults;
assert.equal(runSectionPlan({ results: { kind: "ok", data: certResults }, posture }).certificates.note, undefined);

// capabilities: code-only downloads stay hidden on a run (PLAN §4.4)
assert.equal(RUN_CAPABILITIES.vex, false);
assert.equal(RUN_CAPABILITIES.signature, false);
assert.equal(RUN_CAPABILITIES.evidencePack, false);
assert.equal(RUN_CAPABILITIES.pdf, false);
assert.equal(RUN_CAPABILITIES.oscal, true);

// the Ticketing tab mounts only once lane W6's component exists
const ticketingTab = path.resolve(__dirname, "RunTicketingTab.tsx");
if (!fs.existsSync(ticketingTab)) assert.equal(RUN_TICKETING_TAB_AVAILABLE, false, "no RunTicketingTab.tsx: Results tab only");

// ---------------------------------------------------------------- compliance rows
const cr = complianceRows({
  ...baseResults,
  compliance: { frameworks: [
    { framework: "NIST", clauses: [{ clause: "SC-13", title: "Crypto", assets: 1, codes: ["X"] }] },
    { framework: "CERT-In", clauses: [{ clause: "4.2", title: "CBOM", assets: 3, codes: ["Y"] }] },
    { framework: "CNSA 2.0", clauses: [] },
    { framework: "RBI", clauses: [] },
    { framework: "SEBI CSCRF", clauses: [] },
  ] },
}, posture);
assert.equal(cr.basis, "results");
assert.deepEqual(cr.rows.map((r) => r.framework), ["CERT-In", "RBI", "SEBI CSCRF", "NIST", "CNSA 2.0"]);
const crp = complianceRows(null, posture);
assert.equal(crp.basis, "posture");
assert.deepEqual(crp.rows[0].clauses[0], { clause: "RBI-1", title: "Crypto controls", assets: 2, codes: ["TLS_WEAK"], source: "https://rbi" });
assert.equal(complianceRows(null, null).basis, "none");

// ---------------------------------------------------------------- table helpers
assert.deepEqual(filtersToParams({ view: "all", page: 2, page_size: 50 }), { view: "all", page: 2, page_size: 50 });
assert.deepEqual(
  filtersToParams({ view: "findings", page: 1, page_size: 50, type: "certificate", impact: "High", quantum: true, q: "rsa", source_id: 4, status: "fixed" }),
  { view: "findings", page: 1, page_size: 50, type: "certificate", impact: "High", quantum: true, q: "rsa", source_id: 4, status: "fixed" },
);
assert.equal(hasActiveFilters({ view: "findings", page: 3, page_size: 50 }), false);
assert.equal(hasActiveFilters({ view: "findings", page: 1, page_size: 50, source_id: 0 }), true);

assert.equal(serverSupportsFindingsView({ findings_total: 0 }), true);
assert.equal(serverSupportsFindingsView({}), false, "an older server sends no findings_total");
assert.deepEqual(viewCounts({ findings_total: 12, all_total: 40 }), { findings: 12, all: 40 }, "toggle counts are the API's");
assert.deepEqual(viewCounts({ all_total: 40 } as never), { findings: null, all: 40 });
assert.equal(pageCount({ total: 101, page_size: 50 }), 3);
assert.equal(pageCount({ total: 0, page_size: 50 }), 1);

const item = {
  id: 11, type: "tls_endpoint", location: "10.0.0.5:443", target: "web01", algorithm: null, protocol: "TLS 1.2",
  impact: "High", finding: "Accepts RSA key exchange", quantum_vulnerable: true, assignment_status: "done",
} as unknown as CbomRunAssetItem;
assert.deepEqual(assetRowAttrs(item), {
  "data-impact": "High", "data-type": "tls_endpoint", "data-location": "10.0.0.5:443", "data-target": "web01",
  "data-algorithm": "TLS 1.2", "data-finding": "Accepts RSA key exchange", "data-quantum": "vulnerable", "data-status": "fixed",
});
const graded = { ...item, q_grade: "Q1", fix_class: "configurable" } as CbomRunAssetItem;
assert.equal(assetRowAttrs(graded)["data-q-grade"], "Q1");
assert.equal(assetRowAttrs(graded)["data-fix-class"], "configurable");
assert.deepEqual(optionalColumns([item]), { qGrade: false, fixClass: false });
assert.deepEqual(optionalColumns([item, graded]), { qGrade: true, fixClass: true });

assert.deepEqual(waveChips({ none: 4, "2": 3, "1": 1 }).map((c) => c.label), ["Wave 1", "Wave 2", "No action"]);
assert.deepEqual(waveChips(null), []);

// ---------------------------------------------------------------- header / metadata
const t0 = "2026-11-14T10:00:00Z";
assert.equal(runDurationSeconds({ created_at: t0, finished_at: "2026-11-14T10:02:05Z", status: "done" }, 0), 125);
assert.equal(runDurationSeconds({ created_at: t0, finished_at: null, status: "running" }, Date.parse(t0) + 30_000), 30);
assert.equal(runDurationSeconds({ created_at: t0, finished_at: null, status: "failed" }, Date.now()), null);
assert.equal(formatDuration(125), "2m 5s");
assert.equal(formatDuration(3720), "1h 2m");
assert.equal(formatDuration(null), "—");

const run = { jobs: [
  { source_id: 1, source_name: "k8s-prod", runner: "node", node_name: "dc1-node" },
  { source_id: 2, source_name: "adcs", runner: "cloud", node_name: null },
  { source_id: 1, source_name: "k8s-prod", runner: "node", node_name: "dc1-node" },
] } as never;
assert.deepEqual(runSources(run), [{ id: 1, name: "k8s-prod" }, { id: 2, name: "adcs" }]);
assert.deepEqual(runNodes(run), ["dc1-node", "ZeroShield cloud"]);
assert.equal(endpointsProbed(null), null);
assert.equal(endpointsProbed({ run: { endpoints_probed: 9 }, provenance: [{ endpoints_probed: 1 }] } as never), 9, "the run's own figure first");
assert.equal(endpointsProbed({ run: {}, provenance: [{ endpoints_probed: 2 }, { endpoints_probed: 3 }] } as never), 5);

console.log("run results model tests passed");
