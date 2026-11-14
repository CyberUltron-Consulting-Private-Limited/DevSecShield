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
  certCountText,
  certListView,
  isNotFoundStatus,
  needsRunRemediationList,
  READY_CLASSES,
  resolveMigrationRows,
  RESULTS_LIVE_MAX_ASSETS,
  resultsPollInterval,
  runPollInterval,
  tableTotal,
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
assert.deepEqual(cr.rows.map((r) => r.framework), ["CERT-In", "NIST"], "framework order; frameworks without a clause hidden");
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
  "data-algorithm": "TLS 1.2", "data-key-size": "", "data-finding": "Accepts RSA key exchange", "data-quantum": "vulnerable", "data-status": "fixed",
});
const graded = { ...item, q_grade: "Q1", fix_class: "configurable" } as CbomRunAssetItem;
assert.equal(assetRowAttrs(graded)["data-q-grade"], "Q1");
assert.equal(assetRowAttrs(graded)["data-fix-class"], "configurable");
assert.equal(assetRowAttrs({ ...item, key_size: 2048 } as CbomRunAssetItem)["data-key-size"], "2048", "the gate renders algorithm + key size");
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
assert.equal(endpointsProbed({ run: {}, provenance: [{ endpoints_probed: 2 }, { endpoints_probed: 3 }] } as never), 5);

// ---------------------------------------------------------------- review round 1 (PR #120)
// m5: an older backend sends neither status nor assignment_status: the wave entry's assignment gives the status
assert.equal(findingStatusOf({}, { assignment: { status: "done" } }), "fixed");
assert.equal(findingStatusOf({}, { assignment: { status: "accepted_risk" } }), "ignored");
assert.equal(findingStatusOf({}, { assignment: null }), "not_started");
assert.equal(findingStatusOf({ status: "in_progress" }, { assignment: { status: "done" } }), "in_progress", "the API's status wins");
const oldRow = { ...item, assignment_status: undefined } as CbomRunAssetItem;
assert.equal(assetRowAttrs(oldRow, { assignment: { status: "accepted_risk" } })["data-status"], "ignored");

// m1: any error stops the run polling; 403 / 404 / 422 are "Run not found"
assert.equal(runPollInterval(undefined, true), false, "403 / 5xx with no data: no polling");
assert.equal(runPollInterval(undefined, false), 6000);
assert.equal(runPollInterval("running", false), 6000);
assert.equal(runPollInterval("done", false), false);
assert.deepEqual([403, 404, 422, 500, undefined].map(isNotFoundStatus), [true, true, true, false, false]);

// m7: /results every 30 s only for an active run of ≤ 5,000 assets
assert.equal(resultsPollInterval(true, 1200), 30_000);
assert.equal(resultsPollInterval(true, RESULTS_LIVE_MAX_ASSETS), 30_000);
assert.equal(resultsPollInterval(true, RESULTS_LIVE_MAX_ASSETS + 1), false, "large active run: read once, again on finish");
assert.equal(resultsPollInterval(true, null), false);
assert.equal(resultsPollInterval(false, 10), false);
// m7: the whole-run /remediation list: older backend always; newer backend only for a finished run's chips
assert.equal(needsRunRemediationList({}, true), true, "older backend: rows need the list for wave and key");
assert.equal(needsRunRemediationList({ findings_total: 3 }, true), false, "newer backend, active: not loaded");
assert.equal(needsRunRemediationList({ findings_total: 3 }, false), true, "finished: once, for the S9 chips");
assert.equal(needsRunRemediationList(undefined, false), false);

// m6: with a filter on, the total is the filtered `total`
const pg = { total: 3, all_total: 40, findings_total: 12 };
assert.equal(tableTotal(pg, "findings", false), 12);
assert.equal(tableTotal(pg, "findings", true), 3);
assert.equal(tableTotal(pg, "all", false), 40, "All assets, no filter: N assets found = all_total (gate)");
assert.equal(tableTotal(pg, "all", true), 3);

// m3 (#123 shape): /results lists all five frameworks, empty ones included
const fiveEmpty = { ...baseResults, compliance: { frameworks: ["CERT-In", "RBI", "SEBI CSCRF", "NIST", "CNSA 2.0"].map((framework) => ({ framework, clauses: [] })) } } as CbomRunResults;
assert.equal(complianceRows(fiveEmpty, null).basis, "none");
assert.equal(complianceRows(fiveEmpty, posture).basis, "posture", "empty /results frameworks: the posture's clauses");
const noClausePosture = { assets: 1, top_risks: [], compliance: [] } as never;
plan = runSectionPlan({ results: { kind: "ok", data: fiveEmpty }, posture: noClausePosture });
assert.equal(plan.compliance.note, NOTE.complianceNone, "all frameworks empty: the no-clauses note");
const oneClause = { ...baseResults, compliance: { frameworks: [
  { framework: "RBI", clauses: [] }, { framework: "NIST", clauses: [{ clause: "SC-13", title: "t", assets: 1, codes: ["X"] }] },
] } } as CbomRunResults;
assert.deepEqual(complianceRows(oneClause, null).rows.map((r) => r.framework), ["NIST"], "frameworks with 0 clauses hidden");

// m4: certificate counts from the API totals (lists capped at 2,000) and #123's labels
const capped = {
  ...baseResults,
  certificates_orphaned: Array.from({ length: 2000 }, (_, i) => ({ asset_id: i })),
  certificates_orphaned_total: 2412,
  certificates_unmanaged: [{ asset_id: 1 }], certificates_unmanaged_total: 1,
  certificates_labels: { orphaned: "Not presented by any endpoint probed in this run", unmanaged: "No certificate manager seen for it in this run" },
} as unknown as CbomRunResults;
const ov = certListView(capped, "orphaned");
assert.deepEqual(ov, { listed: 2000, total: 2412, truncated: true, label: "Not presented by any endpoint probed in this run" });
assert.equal(certCountText(ov), `${(2412).toLocaleString()} (showing ${(2000).toLocaleString()} of ${(2412).toLocaleString()})`);
assert.equal(certCountText(certListView(capped, "unmanaged")), "1");
assert.equal(certListView({ ...baseResults, certificates_unmanaged: [{ asset_id: 1 }] } as never, "unmanaged").total, 1, "older shape: list length");
// basis: nothing probed, nothing can be orphaned
plan = runSectionPlan({ results: { kind: "ok", data: { ...fullResults, certificates_basis: "no_endpoints_probed" } as CbomRunResults }, posture });
assert.equal(plan.certificates.note, NOTE.noEndpoints);
// state "computing": the summary sections say so (and the page polls it every 5 s)
plan = runSectionPlan({ results: { kind: "ok", data: { ...fullResults, state: "computing" } as CbomRunResults }, posture });
assert.equal(plan.dashboard.note, NOTE.computing);
assert.equal(plan.cryptoCharts.note, NOTE.computing);
assert.equal(plan.certificates.note, NOTE.computing);

// #123: migration rows carry KB codes, the text is in pqc.kb
const dist = {
  algorithms: {}, weakness: {}, certificates: [], protocols: {},
  pqc: {
    quantum_vulnerable: 2, quantum_safe: 0, readiness_pct: null,
    kb: { DSA: { title: "DSA key", fix: "Move to ECDSA/Ed25519 (and ML-DSA when your stack supports it).", standards: ["FIPS 186-5"], pqc: "quantum-broken" },
          TLS_NO_PQ: { title: "No PQ key exchange", fix: "Enable X25519MLKEM768.", standards: [], pqc: null } },
    migration: [
      { name: "dsa-key", migration_target: null, migration_roadmap: null, suggested_fix: null, migration_code: "DSA", fix_code: "TLS_NO_PQ" },
      { name: "kept", migration_target: "ML-DSA", migration_roadmap: "own text", suggested_fix: "own fix", migration_code: "DSA", fix_code: "DSA" },
      { name: "unknown", migration_target: null, migration_roadmap: null, suggested_fix: null, migration_code: "NOPE", fix_code: null },
    ],
  },
} as never;
const rows = resolveMigrationRows(dist).pqc.migration!;
assert.equal(rows[0].migration_roadmap, "Move to ECDSA/Ed25519 (and ML-DSA when your stack supports it).");
assert.equal(rows[0].suggested_fix, "Enable X25519MLKEM768.");
assert.equal(rows[0].migration_target, null, "the gauge's target falls back to the roadmap text");
assert.deepEqual([rows[1].migration_target, rows[1].migration_roadmap, rows[1].suggested_fix], ["ML-DSA", "own text", "own fix"], "row text wins");
assert.equal(rows[2].migration_roadmap, null, "unknown code: empty, not invented");

// n1: the overlay's "ready" classes are #123's (_READY in run_results.py) when that file is in the tree
const runResultsPy = path.resolve(__dirname, "../../../../backend/utilities/cbom_sources/run_results.py");
assert.deepEqual([...READY_CLASSES].sort(), ["grover-weakened", "hybrid", "quantum-safe"]);
if (fs.existsSync(runResultsPy)) {
  const m = fs.readFileSync(runResultsPy, "utf8").match(/^_READY = \(([^)]*)\)/m);
  assert.ok(m, "_READY found in run_results.py");
  assert.deepEqual(m![1].split(",").map((s) => s.trim().replace(/"/g, "")).filter(Boolean).sort(), [...READY_CLASSES].sort());
}

console.log("run results model tests passed");
