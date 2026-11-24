/**
 * Code-scan mode is unchanged by the run results redesign (PLAN §0, brief rule 2). The shared components the redesign
 * restyles (CbomCryptoCharts, CbomDashboardCharts, CryptoHeatmap, QDistributionCard, AgilityPostureCard) render, without
 * the new run-only props (`parts`, `variant`, `totals`), exactly the markup they rendered on dev fbf79f7e before the
 * redesign: codeModeSnapshot.base.json was written from that commit by this file (`WRITE_BASE=1`) and is never
 * regenerated on a later commit, except deliberately: staging QA round 2 on D3 (fix/cbom-d3-qa2) changed code mode on
 * purpose (the risk tile shows the API's 0-100 risk score and words, the weak-crypto bars are coloured by impact, a
 * scan lists its own certificates, the findings table shows impact and risk under the name on phones, the KPI tiles
 * take one row only from 2xl and the risk tile reads "56 · D" over "of 100 · High risk").
 * Run (frontend/): npx --yes tsx@4.23.15 components/cbom/results/codeModeSnapshot.test.ts
 */
import "./__tests__/cssStub";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

import { CbomCryptoCharts } from "../CbomCryptoCharts";
import CryptoHeatmap from "../CryptoHeatmap";
import { AgilityPostureCard, QDistributionCard } from "../grade";
import { CbomDashboardCharts } from "./CbomDashboardCharts";
import { AGILITY, COMPLIANCE, DASHBOARD, DISTRIBUTIONS, FINDINGS, GRAPH, HEAT, Q_POSTURE } from "./__tests__/codeModeFixtures";

// the certificate calendar opens on the current month and the expiry badges count from today: freeze both
process.env.TZ = "UTC";
const FROZEN = Date.parse("2026-11-16T12:00:00Z");
const RealDate = Date;
globalThis.Date = class extends RealDate {
  constructor(...args: unknown[]) {
    if (args.length === 0) super(FROZEN);
    else super(...(args as [string]));
  }
  static now() { return FROZEN; }
} as DateConstructor;

const h = React.createElement;
const render = (el: React.ReactElement) => renderToStaticMarkup(h(QueryClientProvider, { client: new QueryClient() }, el));
const noop = () => undefined;

const CASES: Record<string, () => React.ReactElement> = {
  // the code scan page (CbomResults, !run)
  "crypto-charts-code": () => h(CbomCryptoCharts, {
    distributions: DISTRIBUTIONS, graph: GRAPH, graphCompact: GRAPH, compliance: COMPLIANCE, onAttest: async () => undefined,
    findings: FINDINGS, inventory: FINDINGS, onOpenFinding: noop, showCodeHeatmap: true, readinessScope: "code",
  }),
  "crypto-charts-code-no-graph": () => h(CbomCryptoCharts, {
    distributions: { ...DISTRIBUTIONS, pqc: { ...DISTRIBUTIONS.pqc, migration: [] } }, findings: FINDINGS, inventory: FINDINGS,
    onOpenFinding: noop,
  }),
  "crypto-charts-code-none": () => h(CbomCryptoCharts, { distributions: null, graph: GRAPH, compliance: COMPLIANCE }),
  // a Sources run as CbomResults mounted it before the redesign (no parts, no variant): unchanged too
  "crypto-charts-run-default": () => h(CbomCryptoCharts, {
    distributions: DISTRIBUTIONS, graph: GRAPH, compliance: COMPLIANCE, findings: [], inventory: [], onOpenFinding: noop,
    showCodeHeatmap: false, readinessScope: "run",
  }),
  "dashboard-code": () => h(CbomDashboardCharts, { dashboard: DASHBOARD, findingsList: FINDINGS }),
  "dashboard-run-default": () => h(CbomDashboardCharts, {
    dashboard: { ...DASHBOARD, remediation_metrics: undefined } as unknown as typeof DASHBOARD, findingsList: FINDINGS,
    riskScoresTitle: "Risk scores on this table page (3 rows)", riskScoresTip: "cbom.run.risk_scores", quantumTip: "cbom.run.quantum",
    riskScoresDescription: "Risk score (0-10) of the rows on the findings table's current page and filter, top 24, descending",
  }),
  "heatmap-code": () => h(CryptoHeatmap, { data: HEAT, title: "Algorithm family × source", testId: "code-heatmap" }),
  "q-distribution-card": () => h(QDistributionCard, { posture: Q_POSTURE, model: null }),
  "agility-posture-card": () => h(AgilityPostureCard, { posture: AGILITY, model: null }),
};

const basePath = path.join(__dirname, "__tests__", "codeModeSnapshot.base.json");
const out: Record<string, { sha256: string; html: string }> = {};
for (const [name, el] of Object.entries(CASES)) {
  const html = render(el());
  out[name] = { sha256: createHash("sha256").update(html).digest("hex"), html };
  // deterministic: a second render in the same process is identical (no random ids)
  assert.equal(render(el()), html, `${name}: two renders differ`);
}

if (process.env.WRITE_BASE === "1") {
  fs.writeFileSync(basePath, JSON.stringify(out, null, 1) + "\n");
  console.log(`wrote ${basePath}`);
} else {
  const base = JSON.parse(fs.readFileSync(basePath, "utf8")) as typeof out;
  assert.deepEqual(Object.keys(out).sort(), Object.keys(base).sort(), "the snapshot covers the same cases");
  for (const name of Object.keys(base)) {
    if (out[name].sha256 === base[name].sha256) continue;
    // the first difference, for the failure message
    const a = base[name].html, b = out[name].html;
    let i = 0;
    while (i < a.length && a[i] === b[i]) i++;
    assert.fail(`${name}: code-mode markup changed at ${i}:\n  base: …${a.slice(Math.max(0, i - 120), i + 120)}…\n  head: …${b.slice(Math.max(0, i - 120), i + 120)}…`);
  }
  console.log("codeModeSnapshot.test.ts: ok");
}
