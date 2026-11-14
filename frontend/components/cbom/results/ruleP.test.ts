/**
 * F7 (PLAN §9, Rule P §2.5): on a Sources run page the readiness, quantum-vulnerable and severity figures come from
 * the run posture, never from counting the table's rows. The probe run of the plan: posture says 28.6 % (a 128-bit XTS
 * volume key is grover-weakened = ready), the code lane's row rule says 14.3 % (it calls that key "broken today").
 * Run: npx --yes tsx components/cbom/results/ruleP.test.ts
 */
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";

import type { CbomRunDashboard, CbomRunPosture } from "@/utils/backend_api";
import type { CbomDistributions } from "@/components/cbom/CbomCryptoCharts";
import { quantumCounts } from "../quantumFilter";
import { readinessText } from "../../../utils/cbomReadiness";
import { applyPostureToDistributions, runDashboardModel } from "./model";

// --- the probe run: 7 judged assets
const posture = {
  assets: 9,
  pqc_classes: { "quantum-vulnerable": 5, hybrid: 0, "quantum-safe": 1, "grover-weakened": 1, "not-applicable": 2 },
  pqc_readiness_pct: 28.6,
  impacts: { Critical: 2, High: 3, Medium: 1, Low: 1 },
} as unknown as CbomRunPosture;

// the same assets as code-lane rows: the XTS-128 key is "weak" + quantum_safe, i.e. broken today
const rows = [
  { quantum_safe: true, crypto_strength: "strong" },   // AES-256
  { quantum_safe: true, crypto_strength: "weak" },     // DISK_XTS_128 (Low)
  ...Array.from({ length: 5 }, () => ({ quantum_safe: false, crypto_strength: "moderate" })), // RSA / ECDHE
];
assert.equal(quantumCounts(rows).readinessPct, 14.3, "the row rule computes 14.3 % on this run");

// a /results dashboard whose posture-meaning fields lag (a cached summary): the page must not show them
const dashboard = {
  card_data: {
    total_crypto_assets: 9, total_weak_algorithms: 1, total_quantum_vulnerable: 4, total_certificates: 0, total_keys: 1,
    quantum_readiness_score: 14.3, quantum_readiness_judged: true, average_risk_score: 6.1,
  },
  remediation_metrics: { mean_time_to_remediate: [0, 0, 0], critical_issues_fixed: 0, remediation_velocity: 0, high_priority_backlog: 5 },
  remediation_actions_required: { total_findings: 7, total_fixed: 0, total_in_progress: 0, total_not_started: 7, total_ignored: 0 },
  severity_distribution: { critical: 1, high: 1, medium: 1, low: 1, informational: 2 },
  algorithm_type_distribution: { symmetric: 2, asymmetric: 5 },
  strength_distribution: { weak: 1, moderate: 5, strong: 1 },
  quantum_readiness: { quantum_safe: 1, quantum_vulnerable: 6, unknown: 2 },
  owasp_top_10_issues: {}, compliance_controls: {}, top_risks: [],
} as unknown as CbomRunDashboard;

const model = runDashboardModel(dashboard, posture);
assert.ok(model.dashboard);
const card = model.dashboard!.card_data;
assert.equal(readinessText(card), "28.6%", "the Quantum ready card prints the posture's readiness");
assert.notEqual(readinessText(card), `${quantumCounts(rows).readinessPct}%`);
assert.equal(card.total_quantum_vulnerable, 5, "Quantum vulnerable card = posture class count");
assert.deepEqual(model.dashboard!.quantum_readiness, { quantum_safe: 2, quantum_vulnerable: 5, unknown: 2 },
  "readiness chart = posture classes (hybrid + quantum-safe + grover-weakened vs quantum-vulnerable)");
assert.deepEqual(model.dashboard!.severity_distribution, { critical: 2, high: 3, medium: 1, low: 1, informational: 2 },
  "severity radar = posture impacts");
// inventory distributions (no grade or readiness meaning) pass through from /results untouched
assert.deepEqual(model.dashboard!.algorithm_type_distribution, dashboard.algorithm_type_distribution);
assert.deepEqual(model.dashboard!.strength_distribution, dashboard.strength_distribution);
assert.equal(card.total_crypto_assets, 9);
assert.equal(model.metricsAvailable, true);

// nothing judged: n/a, not 0 %
const none = runDashboardModel(dashboard, { ...posture, pqc_readiness_pct: null } as CbomRunPosture);
assert.equal(readinessText(none.dashboard!.card_data), "n/a");

// remediation metrics not available yet: the card is left out (CbomDashboardCharts hides it), the rest stays
const noMetrics = runDashboardModel({ ...dashboard, metrics_available: false }, posture);
assert.equal(noMetrics.metricsAvailable, false);
assert.equal((noMetrics.dashboard as unknown as Record<string, unknown>).remediation_metrics, undefined);
assert.equal(readinessText(noMetrics.dashboard!.card_data), "28.6%");
assert.equal(runDashboardModel(null, posture).dashboard, null, "no dashboard: the section shows a note");

// the crypto charts' PQC gauge reads the posture too
const dist = {
  algorithms: {}, weakness: {}, certificates: [], protocols: {},
  pqc: { quantum_vulnerable: 6, quantum_safe: 1, readiness_pct: 14.3, hybrid: 0, migration: [] },
} as unknown as CbomDistributions;
const gauge = applyPostureToDistributions(dist, posture).pqc;
assert.equal(gauge.readiness_pct, 28.6);
assert.equal(gauge.quantum_vulnerable, 5);
assert.equal(gauge.quantum_safe, 2);
assert.deepEqual(gauge.migration, [], "migration rows pass through");

// --- grep: the run sections import no row-counting helper for totals (F7)
const dir = __dirname;
const sources = fs.readdirSync(dir)
  .filter((f) => /\.(ts|tsx)$/.test(f) && !f.endsWith(".test.ts"))
  .map((f) => [f, fs.readFileSync(path.join(dir, f), "utf8")] as const);
assert.ok(sources.some(([f]) => f === "RunResultsView.tsx"), "run page sources found");
const FORBIDDEN = [/quantumFilter/, /\binventoryRows\b/, /\bmatchesQuantumFilter\b/, /\bquantumCounts\b/, /\bcodeHeatmap\b/, /\bisBrokenToday\b/];
for (const [file, text] of sources) {
  for (const re of FORBIDDEN) assert.ok(!re.test(text), `${file} must not use ${re} (Rule P: no recount of rows)`);
}
// readinessText may only format a card value, never be fed counts
for (const [file, text] of sources) {
  for (const m of text.matchAll(/readinessText\(([^)]*)\)/g)) assert.equal(m[1].trim(), "cardData", `${file}: readinessText(${m[1]})`);
}
// the crypto charts get no rows on a run, so the gauge cannot recount them
const sections = fs.readFileSync(path.join(dir, "RunSections.tsx"), "utf8");
assert.match(sections, /<CbomCryptoCharts distributions=\{applyPostureToDistributions\(dist, posture\)\} findings=\{\[\]\} inventory=\{\[\]\}/);
// the dashboard on the run page is built by runDashboardModel (posture overlay), nowhere else
const view = fs.readFileSync(path.join(dir, "RunResultsView.tsx"), "utf8");
assert.match(view, /runDashboardModel\(results\?\.dashboard, posture\)/);

console.log("rule P (run page reads posture, never recounts rows) tests passed");
