/**
 * Run results redesign, section restyles (PLAN §3, B2): rendered with react-dom/server.
 *  - CbomCryptoCharts `parts` (default all) and `variant="run"`: one uniform chart grid, the quantum-vulnerable list as
 *    numbered fix cards (09-A) that open their groups and assets, compliance readiness as framework scorecards (12-A),
 *    and the graph / compliance parts from their own data when a run has no distributions (a code scan: nothing).
 *  - ComplianceScorecards: ring = passed / all requirements, verdict chip, failing requirements and assets, a card
 *    opens its requirements inline (collapsed by default; filters and the attestation upload kept).
 *  - CbomDashboardCharts `parts` and `variant="run"` (one grid of equal cards).
 *  - CertificatesCard (10-A): the expiry list, calendar and orphaned / unmanaged tabs with their empty and pending states.
 *  - RunWavesSection (13-A): one column per wave with its count, rule and first assets; the notes and copy unchanged.
 * Code mode without the new props is pinned byte for byte by codeModeSnapshot.test.ts.
 * Run (frontend/): npx --yes tsx@4.23.15 components/cbom/results/redesignSections.test.ts
 */
import "./__tests__/cssStub";
import assert from "node:assert/strict";
import { test } from "node:test";
import React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

import { CRYPTO_CHART_PARTS, CbomCryptoCharts } from "../CbomCryptoCharts";
import { cbomOpsKeys, type CbomRemediationItem, type CbomRunHeatmap } from "@/utils/api/cbom_ops";
import type { CbomRunResults } from "@/utils/backend_api";
import { CbomDashboardCharts, DASHBOARD_CHART_PARTS } from "./CbomDashboardCharts";
import { COMPLIANCE, DASHBOARD, DISTRIBUTIONS, GRAPH } from "./__tests__/codeModeFixtures";
import { ComplianceScorecards, frameworkScore } from "./ComplianceScorecards";
import { RunWavesSection } from "./RunSections";
import { CertificatesCard, RunCertCalendar } from "./views/CertificatesCard";

const h = React.createElement;
const render = (el: React.ReactElement, qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })) =>
  renderToStaticMarkup(h(QueryClientProvider, { client: qc }, el));
const text = (html: string) => html.replace(/<[^>]+>/g, " ").replace(/&#x27;/g, "'").replace(/&quot;/g, '"')
  .replace(/&amp;/g, "&").replace(/\s+/g, " ").trim();
const count = (html: string, re: RegExp) => (html.match(re) ?? []).length;
const tag = (html: string, testId: string) => html.match(new RegExp(`<[^>]*data-testid="${testId}"[^>]*>`))?.[0] ?? "";

test("CbomCryptoCharts parts: only the named charts (code layout), default all", () => {
  assert.equal(CRYPTO_CHART_PARTS.length, 10);
  const only = render(h(CbomCryptoCharts, { distributions: DISTRIBUTIONS, graph: GRAPH, compliance: COMPLIANCE, parts: ["algorithms", "protocols"], showCodeHeatmap: false }));
  assert.ok(only.includes("Algorithm distribution") && only.includes("Protocol / TLS"));
  for (const t of ["Weak-crypto findings", "Quantum-vulnerable algorithms", "PQC migration roadmap", "Asset types", "Certificate expiry",
    "Crypto dependency graph", "Crypto compliance readiness"]) assert.ok(!only.includes(t), t);
  const all = render(h(CbomCryptoCharts, { distributions: DISTRIBUTIONS, graph: GRAPH, compliance: COMPLIANCE, showCodeHeatmap: false }));
  for (const t of ["Algorithm distribution", "Weak-crypto findings", "Quantum-vulnerable algorithms", "PQC migration roadmap", "Asset types",
    "Certificate expiry", "Protocol / TLS", "Crypto dependency graph", "Crypto compliance readiness"]) assert.ok(all.includes(t), t);
});

test("CbomCryptoCharts run variant: one chart grid, fix cards, scorecards", () => {
  const html = render(h(CbomCryptoCharts, { distributions: DISTRIBUTIONS, graph: GRAPH, compliance: COMPLIANCE, findings: [], inventory: [],
    showCodeHeatmap: false, readinessScope: "run", variant: "run", onOpenFinding: () => undefined }));
  assert.match(html, /data-testid="crypto-charts" data-variant="run"/);
  const grid = html.slice(html.indexOf('data-testid="crypto-chart-grid"'), html.indexOf('data-testid="pqc-vulnerable-list"'));
  for (const t of ["Algorithm distribution", "Weak-crypto findings", "Asset types", "Certificate expiry", "Protocol / TLS"]) assert.ok(grid.includes(t), t);
  assert.match(grid, /class="min-w-0 \[&amp;&gt;\[data-slot=card\]\]:h-full"/, "every card stretches to its row");
  // 09-A: two distinct fixes (RSA-2048 x2 and ECDSA), numbered, most assets first, each with its groups
  const list = html.slice(html.indexOf('data-testid="pqc-vulnerable-list"'), html.indexOf('data-testid="pqc-migration-roadmap"'));
  assert.match(list, /data-testid="pqc-fix-list" data-variant="run"/);
  assert.equal(count(list, /data-testid="pqc-fix-item"/g), 2);
  assert.match(list, /data-fix="1"/);
  assert.ok(text(list).includes("Fix 1: Move to ML-KEM-768"), text(list));
  assert.ok(text(list).includes("2 assets"));
  assert.ok(text(list).includes("RSA-2048 (2)"));
  assert.match(list, /data-infotip="cbom.chart.qv"/);
  assert.match(list, /data-infotip="cbom.chart.qv_fixes"/);
  assert.ok(text(list).includes("How to fix (2 distinct fixes)"));
  // each card opens its groups and assets: a button that names the region it shows; the rows stay in the page (hidden)
  const toggle = list.match(/<button[^>]*data-testid="pqc-fix-toggle"[^>]*>/)?.[0] ?? "";
  assert.match(toggle, /aria-expanded="false"/);
  const region = toggle.match(/aria-controls="([^"]+)"/)?.[1] ?? "";
  assert.match(list, new RegExp(`id="${region.replace(/[:]/g, "\\:")}" hidden=""`));
  assert.equal(count(list, /data-testid="pqc-vuln-group"/g), 2);
  assert.equal(count(list, /data-testid="pqc-instance-row"/g), 3);
  // NIST level legend kept
  assert.match(list, /data-testid="pqc-level-legend"/);
  // 12-A compliance scorecards instead of the stacked bars
  assert.match(html, /data-testid="compliance-scorecards"/);
  assert.match(html, /data-infotip="cbom.run.compliance_readiness"/);
  // the roadmap and the graph are still there
  assert.match(html, /data-testid="pqc-migration-roadmap"/);
  assert.ok(html.includes("Crypto dependency graph"));
});

test("CbomCryptoCharts: groups without a fix keep a card; no quantum-vulnerable algorithm keeps the reassurance", () => {
  const noFix = { ...DISTRIBUTIONS, pqc: { ...DISTRIBUTIONS.pqc, migration: DISTRIBUTIONS.pqc.migration!.map((r) => ({ ...r, suggested_fix: null, migration_roadmap: null, migration_target: null })) } };
  const html = render(h(CbomCryptoCharts, { distributions: noFix, variant: "run", parts: ["qv"] }));
  assert.match(html, /data-fix="none"/);
  assert.ok(text(html).includes("No fix recorded for these assets"), text(html));
  assert.ok(text(html).includes("How to fix (0 distinct fixes)"));
  const none = render(h(CbomCryptoCharts, { distributions: { ...DISTRIBUTIONS, pqc: { ...DISTRIBUTIONS.pqc, migration: [] } }, variant: "run", parts: ["qv"] }));
  assert.ok(text(none).includes("No quantum-vulnerable algorithms"));
  assert.match(none, /data-infotip="cbom.chart.qv_none"/);
});

test("CbomCryptoCharts: graph and compliance render from their own data when a run has no distributions; a code scan renders nothing", () => {
  const run = render(h(CbomCryptoCharts, { distributions: null, graph: GRAPH, compliance: COMPLIANCE, variant: "run" }));
  assert.ok(run.includes("Crypto dependency graph"));
  assert.match(run, /data-testid="compliance-scorecards"/);
  const onlyCompliance = render(h(CbomCryptoCharts, { distributions: null, graph: GRAPH, compliance: COMPLIANCE, variant: "run", parts: ["compliance"] }));
  assert.ok(!onlyCompliance.includes("Crypto dependency graph"));
  assert.match(onlyCompliance, /compliance-scorecards/);
  assert.equal(render(h(CbomCryptoCharts, { distributions: null, graph: null, compliance: null, variant: "run" })), "");
  assert.equal(render(h(CbomCryptoCharts, { distributions: null, graph: GRAPH, compliance: COMPLIANCE })), "");
});

test("frameworkScore: passed of all requirements, verdict, failing assets of the worst requirement", () => {
  const cnsa = frameworkScore("cnsa_2_0", { pass: 1, fail: 1, na: 0, coverage: 0.5, requirements: [
    { id: "CNSA-1", title: "t", verdict: "fail", failing: 12 } as never, { id: "CNSA-2", title: "t", verdict: "fail", failing: 3 } as never] });
  assert.deepEqual([cnsa.passed, cnsa.total, cnsa.failing, cnsa.assets, cnsa.verdict], [1, 2, 1, 12, "partial"]);
  assert.equal(frameworkScore("x", { pass: 2, fail: 0, na: 1, coverage: 1 }).verdict, "pass");
  assert.equal(frameworkScore("x", { pass: 0, fail: 2, na: 0, coverage: 0 }).verdict, "fail");
  assert.equal(frameworkScore("x", { pass: 0, fail: 0, na: 0, out_of_scope: 2, coverage: null }).verdict, "not_assessed");
  assert.equal(frameworkScore("x", { pass: 0, fail: 1, na: 0, coverage: 0, requirements: [] }).assets, null);
});

test("ComplianceScorecards: one card per framework; a card opens its requirements inline", () => {
  const html = render(h(ComplianceScorecards, { compliance: COMPLIANCE, groups: [{ id: "all", label: "All", keys: [] }, { id: "q", label: "Quantum-safe", keys: ["cnsa_2_0"] }] }));
  const cnsa = tag(html, "compliance-card-cnsa_2_0");
  assert.match(cnsa, /data-verdict="partial"/);
  assert.match(cnsa, /data-passed="1"/);
  assert.match(cnsa, /data-total="2"/);
  assert.match(cnsa, /aria-expanded="false"/);
  assert.match(tag(html, "compliance-card-fips_140_3"), /data-verdict="pass"/);
  assert.match(html, /aria-label="1 of 2 requirements passed"/);
  assert.ok(text(html).includes("CNSA 2.0 Partial"));
  assert.ok(text(html).includes("1 requirement failing"));
  assert.ok(text(html).includes("No requirement failing"));
  // filters kept: framework groups and Failures only, as toggle buttons
  assert.ok(text(html).includes("Quantum-safe") && text(html).includes("Failures only"));
  assert.match(html, /aria-pressed="true"[^>]*>All</);
  // the detail region exists (aria-controls target), closed until a card is clicked
  const id = cnsa.match(/aria-controls="([^"]+)"/)?.[1] ?? "";
  assert.match(html, new RegExp(`id="${id.replace(/[:]/g, "\\:")}" hidden=""`));
  assert.equal(render(h(ComplianceScorecards, { compliance: { disclaimer: "x" } })), "");
});

test("CbomDashboardCharts parts and run variant", () => {
  assert.equal(DASHBOARD_CHART_PARTS.length, 10);
  const kpisOnly = render(h(CbomDashboardCharts, { dashboard: DASHBOARD, findingsList: [], parts: ["kpis"] }));
  assert.ok(kpisOnly.includes("Crypto assets"));
  for (const t of ["Remediation progress", "OWASP Top 10 issues", "Risk metrics", "Compliance controls", "Algorithm types", "Crypto strength",
    "Quantum readiness", "Risk scores per finding", "Remediation metrics"]) assert.ok(!kpisOnly.includes(t), t);
  const run = render(h(CbomDashboardCharts, { dashboard: DASHBOARD, findingsList: [], variant: "run",
    parts: ["progress", "owasp", "risk", "controls", "algoTypes", "strength", "quantum", "riskScores", "metrics"] }));
  assert.match(run, /data-testid="dashboard-charts" data-variant="run"/);
  assert.ok(!run.includes(">Crypto assets<"), "the KPI cards are left to the summary");
  const grid = run.slice(run.indexOf('data-testid="dashboard-chart-grid"'));
  assert.equal(count(grid.slice(0, grid.indexOf("Remediation metrics")), /class="min-w-0 \[&amp;&gt;\[data-slot=card\]\]:h-full"/g), 8);
  for (const tip of ["cbom.res.remediation", "cbom.res.owasp", "cbom.res.severity", "cbom.res.compliance", "cbom.res.algo_types",
    "cbom.res.strength", "cbom.res.quantum", "cbom.res.risk_scores", "cbom.res.remed.section"]) assert.match(run, new RegExp(`data-infotip="${tip}"`), tip);
  // a dashboard without remediation metrics leaves that card out, the rest stays
  const noMetrics = render(h(CbomDashboardCharts, { dashboard: { ...DASHBOARD, remediation_metrics: undefined } as never, findingsList: [], variant: "run" }));
  assert.ok(!noMetrics.includes("Remediation metrics") && noMetrics.includes("Crypto strength"));
});

const RESULTS = { certificates_orphaned: [{ asset_id: 3, subject: "CN=a", issuer: null, not_after: null, location: "/etc/a.pem", source: "srv" }],
  certificates_unmanaged: [] } as unknown as CbomRunResults;
const heat = (certs: CbomRunHeatmap["certificates"]) => ({ by: "source", rows: ["RSA"], columns: ["a"], cells: [], certificates: certs }) as CbomRunHeatmap;
const cert = { subject: "CN=web", issuer: "CN=CA", not_after: "2026-12-01T00:00:00Z", target: "10.0.0.1", location: "10.0.0.1:443#chain[0]", name: "CN=web" };

test("CertificatesCard: expiry list (certificates, key material) by default, three tabs, pending and missing states", () => {
  const props = { teamId: 1, runId: 12, active: false, distributions: DISTRIBUTIONS, graph: null, chartsView: { show: true },
    certificatesView: { show: true }, results: RESULTS, onOpenAsset: () => undefined };
  const html = render(h(CertificatesCard, props));
  assert.match(html, /data-testid="run-certificates-card"/);
  assert.match(html, /data-infotip="cbom.run.certificates"/);
  for (const t of ["expiry", "calendar", "orphaned"]) assert.match(html, new RegExp(`data-testid="run-certificates-tab-${t}"`));
  assert.match(tag(html, "run-certificates-tab-expiry"), /aria-selected="true"/);
  assert.ok(text(html).includes("X.509 certificates (3)"));
  assert.ok(text(html).includes("Key / keystore material (2)"));
  assert.ok(text(html).includes("opaque (no password parse)"));
  assert.match(html, /data-infotip="cbom.chart.cert_expiry"/);
  // the orphaned / unmanaged tab opens on demand, with the section's own lists
  const orphaned = render(h(CertificatesCard, { ...props, defaultTab: "orphaned" as const }));
  assert.match(orphaned, /data-testid="run-section-certificates" data-bare="true"/);
  assert.match(orphaned, /data-testid="run-certs-orphaned-3"/);
  assert.match(orphaned, /data-infotip="cbom.run.certs"/);
  // no distributions: the expiry tab says why; results pending: a loader, never an empty card
  const missing = render(h(CertificatesCard, { ...props, distributions: null, chartsView: { show: true, note: "Not in this server's results yet." } }));
  assert.match(missing, /data-testid="run-certificates-expiry-note"/);
  assert.ok(text(missing).includes("Not in this server's results yet."));
  assert.doesNotMatch(render(h(CertificatesCard, { ...props, chartsView: { show: false } })), /X\.509 certificates/);
});

test("RunCertCalendar: the run's calendar with its count line, the empty text, loading", () => {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  qc.setQueryData(cbomOpsKeys.heatmap(1, 12, "source", "impact"), heat([cert, { ...cert, location: "10.0.0.1:8443#chain[0]" }]));
  const html = render(h(RunCertCalendar, { teamId: 1, runId: 12, active: false }), qc);
  assert.match(html, /data-testid="run-cert-calendar"/);
  assert.ok(text(html).includes("2 certificates with an expiry date."));
  const qe = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  qe.setQueryData(cbomOpsKeys.heatmap(1, 12, "source", "impact"), heat([]));
  assert.ok(text(render(h(RunCertCalendar, { teamId: 1, runId: 12, active: false }), qe)).includes("No certificates with an expiry date in this run."));
  assert.match(render(h(RunCertCalendar, { teamId: 1, runId: 99, active: false })), /animate-spin/);
});

const item = (id: number, wave: number | null, impact: string | null = "High") => ({ asset_key: `k${id}`, asset_id: id, scope: "node",
  label: `asset-${id}`, type: "tls_endpoint", impact, finding_codes: [], quantum_vulnerable: false, exposure: "internal", hndl: false,
  suggested_wave: wave, wave, wave_source: "suggested", assignment: null }) as CbomRemediationItem;

test("RunWavesSection 13-A: a column per wave with count, rule and first assets; notes and copy unchanged", () => {
  const byWave = { "1": 0, "2": 5, "3": 1, "4": 2, none: 3 };
  const html = render(h(RunWavesSection, { byWave, labels: { "2": "Other Critical or High" }, loading: false, deferred: false, selected: 0,
    items: [item(1, 2), item(2, 2), item(3, 2), item(4, 2), item(5, 3, "Medium"), item(6, null, null)], onOpenAsset: () => undefined }));
  assert.match(html, /data-testid="run-wave-board"/);
  for (const [k, n] of Object.entries(byWave)) assert.match(tag(html, `run-wave-column-${k}`), new RegExp(`data-count="${n}"`), k);
  assert.ok(text(html).includes("Wave 2: 5"));
  assert.match(tag(html, "run-wave-chip-2"), /title="Other Critical or High"/);
  // the first three assets of a wave and how many more the plan counts (never the list length)
  const w2 = html.slice(html.indexOf('data-testid="run-wave-column-2"'), html.indexOf('data-testid="run-wave-column-3"'));
  assert.equal(count(w2, /data-testid="run-wave-item-/g), 3);
  assert.ok(text(w2).includes("+2 more"));
  assert.match(w2, /<button[^>]*>asset-1<\/button>/);
  // an empty wave says why; No action lists its asset
  assert.ok(text(html.slice(html.indexOf('data-testid="run-wave-column-1"'))).includes("so the wave is empty"));
  assert.match(html, /data-testid="run-wave-item-6"/);
  // the legend and the selection copy are unchanged
  assert.match(html, /data-testid="run-wave-legend"/);
  assert.ok(text(html).includes("Select findings in the table below to assign a wave, owner, target date or status."));
  assert.match(html, /data-infotip="cbom.run.waves"/);
  // without items (an older backend): counts only
  const bare = render(h(RunWavesSection, { byWave: { "2": 5 }, loading: false, deferred: false, selected: 2 }));
  assert.ok(text(bare).includes("5 assets"));
  assert.ok(text(bare).includes("2 findings selected in the table below: set wave, owner, target date or status there."));
  // deferred, loading and nothing to plan keep their notes
  assert.match(render(h(RunWavesSection, { byWave: null, loading: false, deferred: true, selected: 0 })), /data-testid="run-waves-deferred"/);
  assert.ok(text(render(h(RunWavesSection, { byWave: null, loading: true, deferred: false, selected: 0 }))).includes("Loading the wave plan…"));
  assert.ok(text(render(h(RunWavesSection, { byWave: {}, loading: false, deferred: false, selected: 0 }))).includes("No asset of this run needs a remediation wave."));
});

test("ComplianceScorecards (R-ux 9): under All the regulator cards lead; the rest stay mounted behind a toggle", () => {
  const html = render(h(ComplianceScorecards, { compliance: COMPLIANCE, groups: [{ id: "all", label: "All", keys: [] }] }));
  // CNSA 2.0 is one of the five regulator frameworks: shown first; FIPS 140-3 is mounted but hidden until "Show … more"
  assert.ok(html.indexOf('data-testid="compliance-card-cnsa_2_0"') < html.indexOf('data-testid="compliance-card-fips_140_3"'));
  assert.match(html, /<li class="min-w-0" hidden="">(?:(?!<\/li>)[\s\S])*compliance-card-fips_140_3/);
  assert.doesNotMatch(html, /<li class="min-w-0" hidden="">(?:(?!<\/li>)[\s\S])*compliance-card-cnsa_2_0/);
  assert.match(tag(html, "compliance-more-frameworks"), /aria-expanded="false"/);
  assert.match(text(html), /Show \d+ more frameworks?/);
});
