/**
 * Staging QA round 4 on the one results template (lane B8). Logic and rendered components (react-dom/server):
 *  A  quantum-vulnerable group cards at 390 px: the badge row wraps under the title (no shrink-0 row clipping "NIST
 *     Level 0" and the impact badge) and the instance badge is short ("L0", full text in title / aria-label).
 *  B  readiness actions count with the server's plural ("Fix 3 CA templates", not "3 Ca templates").
 *  C  the PQC readiness card says what its number is: run pages "of judged assets" (posture's figure), code scans
 *     "of every crypto asset"; a withheld run readiness is "Withheld" with its reason, never 0 %.
 *  D  code scans' "Remediation waves" shows the same legend as run pages, worded for a code scan.
 *  E  below 768 px each findings row starts with a visible "Open" chevron (Details / Action are off-screen).
 * Run (frontend/): npx --yes tsx@4.23.15 --test components/cbom/results/resultsQaR4.test.ts
 */
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { test } from "node:test";
import React from "react";
import { renderToStaticMarkup } from "react-dom/server";

import { PqcGroupBadges, PqcInstanceLevelBadge, PQC_GROUP_TRIGGER_ROW } from "../PqcBadges";
import { PqcReadinessGauge } from "../PqcReadinessGauge";
import type { CbomRunPosture, CbomScanDashboardData } from "@/utils/backend_api";
import { readinessText } from "@/utils/cbomReadiness";
import { RowOpenButton } from "./RowOpenButton";
import { WaveLegend } from "./WaveLegend";
import { applyPostureToDashboard, applyPostureToDistributions } from "./model";
import { pqcGaugeCopy, readinessExplanation, waveLegend, withheldReason, type ReadinessPostureLike } from "./readinessExplain";
import type { CbomDistributions } from "../CbomCryptoCharts";

const h = React.createElement;
const text = (html: string) => html.replace(/<[^>]+>/g, " ").replace(/&#x27;/g, "'").replace(/&quot;/g, '"')
  .replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&amp;/g, "&").replace(/\s+/g, " ").trim();
const read = (rel: string) => fs.readFileSync(path.join(__dirname, rel), "utf8");
const classOf = (html: string, testId: string) => (html.match(new RegExp(`<[^>]*data-testid="${testId}"[^>]*>`))?.[0]
  .match(/class="([^"]*)"/)?.[1] ?? "").split(/\s+/);

// ------------------------------------------------------------------------------------------------------- A
test("A: the group badge row wraps under the title on narrow widths and never clips", () => {
  const html = renderToStaticMarkup(h(PqcGroupBadges, { count: 6, fix: 7, nistLevel: 0, impact: "High" }));
  const row = classOf(html, "pqc-group-badges");
  assert.ok(row.includes("flex-wrap"), "the badge row wraps");
  assert.ok(!row.includes("shrink-0"), "a shrink-0 row is what clipped NIST Level 0 at 390 px");
  assert.ok(row.some((c) => c.startsWith("gap")), "badges keep a gap when they wrap");
  const t = text(html);
  assert.match(t, /6/);
  assert.match(t, /Fix 7/);
  assert.match(t, /NIST Level 0/);
  assert.match(t, /High/, "the impact badge is rendered");
  // the trigger stacks (title, then badges) below the sm breakpoint and goes side by side from sm up
  const trig = PQC_GROUP_TRIGGER_ROW.split(/\s+/);
  assert.ok(trig.includes("flex-col") && trig.includes("sm:flex-row"), PQC_GROUP_TRIGGER_ROW);
  // no fix number: no "Fix" badge; no impact: a dash
  const bare = text(renderToStaticMarkup(h(PqcGroupBadges, { count: 1, fix: undefined, nistLevel: 0, impact: null })));
  assert.doesNotMatch(bare, /Fix/);
  assert.match(bare, /—/);
});

test("A: the instance badge is short on narrow widths, full text in title and aria-label", () => {
  const html = renderToStaticMarkup(h(PqcInstanceLevelBadge, { level: 0, impact: "High" }));
  assert.match(html, /aria-label="NIST Level 0: no quantum resistance"/);
  assert.match(html, /title="Level 0: no quantum resistance\./);
  const short = html.match(/<span[^>]*class="([^"]*)"[^>]*>L0<\/span>/);
  assert.ok(short, "a short L0 label");
  assert.ok(short![1].split(/\s+/).includes("sm:hidden"), "short label only below sm");
  const full = html.match(/<span[^>]*class="([^"]*)"[^>]*>NIST Level 0: no quantum resistance<\/span>/);
  assert.ok(full && full[1].split(/\s+/).includes("hidden") && full[1].split(/\s+/).includes("sm:inline"), "full label from sm up");
  assert.match(renderToStaticMarkup(h(PqcInstanceLevelBadge, { level: 3, impact: null })), />L3</);
});

test("A: CbomCryptoCharts uses the wrapping badges, not the old shrink-0 row", () => {
  const charts = read("../CbomCryptoCharts.tsx");
  assert.ok(charts.includes("<PqcGroupBadges"), "group cards render PqcGroupBadges");
  assert.ok(charts.includes("<PqcInstanceLevelBadge"), "instance rows render PqcInstanceLevelBadge");
  assert.ok(charts.includes("PQC_GROUP_TRIGGER_ROW"), "the trigger row stacks on narrow widths");
  assert.ok(!charts.includes('className="flex shrink-0 items-center gap-1.5"'), "the clipping row is gone");
});

// ------------------------------------------------------------------------------------------------------- B
test("B: readiness actions count with the server's plural label", () => {
  const p: ReadinessPostureLike = {
    pqc_readiness_pct: 10,
    readiness_actions: [
      { asset_type: "ca_template", type_label: "CA template", type_label_plural: "CA templates", code: null,
        title: "Quantum-vulnerable algorithm", fix: null, assets: 3, readiness_after: 40 },
      { asset_type: "ca_authority", type_label: "CA", type_label_plural: "CAs", code: null,
        title: "Quantum-vulnerable algorithm", fix: null, assets: 1, readiness_after: 20 },
      // an older server: no plural, the label rule still applies
      { asset_type: "tls_endpoint", type_label: "TLS endpoint", code: null, title: "X", fix: null, assets: 2, readiness_after: 30 },
    ],
  };
  assert.deepEqual(readinessExplanation(p).actions.map((a) => a.text), [
    "Fix 3 CA templates: Quantum-vulnerable algorithm",
    "Fix 1 CA: Quantum-vulnerable algorithm",
    "Fix 2 TLS endpoints: X",
  ]);
});

// ------------------------------------------------------------------------------------------------------- C
const WITHHELD = { judged: 3, ready: 0, unknown: 75, not_applicable: 13, status: "not_enough_identified" as const };

test("C: the readiness card's description depends on the source", () => {
  const run = pqcGaugeCopy("run", 3.8, { ...WITHHELD, judged: 78, unknown: 0, status: "ok" });
  assert.match(run.description, /of judged assets/);
  assert.doesNotMatch(run.description, /every crypto asset|clean inventory/);
  assert.equal(run.value, "3.8%");
  assert.equal(run.withheld, null);
  const code = pqcGaugeCopy("code", 25, undefined);
  assert.match(code.description, /^Quantum-safe share of every crypto asset \(findings and clean inventory\)/);
  assert.equal(code.value, "25%");
});

test("C: a withheld run readiness is 'Withheld' with its reason, never 0 %", () => {
  assert.match(withheldReason(WITHHELD)!, /more assets are unidentified \(75\) than judged \(3\)/);
  assert.match(withheldReason({ ...WITHHELD, judged: 0, unknown: 0, status: "nothing_judged" })!, /No asset of this run has a quantum verdict/);
  assert.equal(withheldReason({ ...WITHHELD, status: "ok" }), null);
  const c = pqcGaugeCopy("run", null, WITHHELD);
  assert.equal(c.value, "Withheld");
  assert.match(c.withheld!, /more assets are unidentified \(75\) than judged \(3\)/);
  // no basis (older server) and no number: still not 0 %
  assert.equal(pqcGaugeCopy("run", null, undefined).value, "n/a");

  const pqc = { quantum_vulnerable: 3, quantum_safe: 0, readiness_pct: null, readiness_basis: WITHHELD, migration: [] };
  const html = renderToStaticMarkup(h(PqcReadinessGauge, { pqc, rows: [], scope: "run" }));
  const t = text(html);
  assert.match(t, /Withheld/);
  assert.match(t, /more assets are unidentified \(75\) than judged \(3\)/);
  assert.doesNotMatch(t, /\b0%/, "no 0 % for a withheld readiness");
  assert.match(t, /of judged assets/);
  assert.match(html, /data-testid="pqc-readiness-withheld"/);
});

test("C: the run model passes a withheld readiness through as null with its status (Rule P)", () => {
  const posture = { pqc_readiness_pct: null, pqc_classes: { "quantum-vulnerable": 3 }, impacts: {}, readiness_basis: WITHHELD } as unknown as CbomRunPosture;
  const dist = { algorithms: {}, weakness: {}, certificates: [], protocols: {},
    pqc: { quantum_vulnerable: 3, quantum_safe: 0, readiness_pct: 12, migration: [] } } as unknown as CbomDistributions;
  const g = applyPostureToDistributions(dist, posture).pqc;
  assert.equal(g.readiness_pct, null, "not 0");
  assert.deepEqual(g.readiness_basis, WITHHELD);
  const dashboard = { card_data: { total_crypto_assets: 91, total_weak_algorithms: 0, total_quantum_vulnerable: 3, total_certificates: 0,
    total_keys: 0, quantum_readiness_score: 0, average_risk_score: 0 }, severity_distribution: {}, quantum_readiness: {} } as unknown as CbomScanDashboardData;
  const card = applyPostureToDashboard(dashboard, posture).card_data;
  assert.equal(card.quantum_readiness_score, null);
  assert.equal(card.quantum_readiness_judged, false);
  assert.equal(card.quantum_readiness_status, "not_enough_identified");
  assert.equal(readinessText(card), "Withheld");
  assert.equal(readinessText({ quantum_readiness_score: null, quantum_readiness_judged: false, quantum_readiness_status: "nothing_judged" }), "n/a");
  assert.equal(readinessText({ quantum_readiness_score: 25, quantum_readiness_judged: true, quantum_readiness_status: "ok" }), "25%");
});

test("C: the code-scan gauge keeps its wording; CbomResults passes the scope", () => {
  const html = renderToStaticMarkup(h(PqcReadinessGauge, {
    pqc: { quantum_vulnerable: 1, quantum_safe: 1, readiness_pct: 50 }, rows: [], scope: "code" }));
  assert.match(text(html), /Quantum-safe share of every crypto asset \(findings and clean inventory\)/);
  assert.match(text(html), /50%/);
  const charts = read("../CbomCryptoCharts.tsx");
  assert.match(charts, /<PqcReadinessGauge[^>]*scope=\{readinessScope\}/);
  assert.match(read("../../CbomResults.tsx"), /readinessScope=\{run \? "run" : "code"\}/);
});

// ------------------------------------------------------------------------------------------------------- D
test("D: the wave legend is worded for a code scan, and code scans render it", () => {
  const rows = waveLegend({ "3": 2, "4": 1 }, undefined, "code");
  assert.match(rows[0].empty, /No asset of this scan matches this rule/);
  assert.match(rows[0].empty, /cannot see whether an asset is internet-facing or in transit/);
  assert.match(rows[1].empty, /No asset of this scan/);
  assert.match(waveLegend({}, undefined, "run")[1].empty, /No asset of this run/);
  const html = text(renderToStaticMarkup(h(WaveLegend, { byWave: { "3": 2, "4": 1 }, rules: { "1": "R1", "2": "R2", "3": "R3", "4": "R4", none: "RN" }, scope: "code" })));
  assert.match(html, /What goes in each wave/);
  assert.match(html, /Wave 3 \(2\) ?: R3\./);
  assert.match(html, /move it to another wave in the table below/);
  const waves = read("../sources/WavesControls.tsx");
  assert.match(waves, /<WaveLegend byWave=\{q\.data\.by_wave\} rules=\{q\.data\.rules\} scope="code" \/>/);
  // the run page keeps its legend (RunSections re-exports the shared component)
  assert.match(read("RunSections.tsx"), /<WaveLegend byWave=\{deferred \|\| loading \? null : byWave\} rules=\{rules\} \/>/);
});

// ------------------------------------------------------------------------------------------------------- E
test("E: a visible Open chevron starts each findings row below 768 px", () => {
  let opened = 0;
  const html = renderToStaticMarkup(h(RowOpenButton, { label: "Open details of RSA", onOpen: () => { opened += 1; } }));
  assert.match(html, /<button[^>]*type="button"/);
  assert.match(html, /aria-label="Open details of RSA"/);
  assert.match(html, /data-testid="row-open"/);
  const cls = classOf(html, "row-open");
  assert.ok(cls.includes("md:hidden"), "only below 768 px (Details / Action are pinned on screen from md up)");
  assert.ok(cls.some((c) => /^(size|h)-/.test(c)), "a real tap target");
  assert.match(text(html), /Open/);
  assert.equal(opened, 0);

  const run = read("RunFindingsTable.tsx");
  assert.match(run, /<RowOpenButton label=\{`Open details of \$\{assetName\(item\)\}`\} onOpen=\{\(\) => onOpenDetails\(item\)\}/);
  // the select column grew to hold checkbox + chevron below md, so the sticky name column starts after it
  assert.match(run, /const STICKY_NAME = "max-md:sticky max-md:left-\[76px\]/);
  assert.match(run, /SELECT_COL = "w-\[48px\] max-md:w-\[76px\] max-md:min-w-\[76px\]"/);
  const code = read("../../CbomResults.tsx");
  assert.match(code, /<RowOpenButton label=\{`Open details of \$\{finding\.algorithm_name \|\| finding\.title\}`\} onOpen=\{\(\) => setSelectedFinding\(finding\)\}/);
});
