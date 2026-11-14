/**
 * Issue #271: the run results page explains PQC readiness, groups near-identical quantum-vulnerable rows and labels the
 * remediation waves. Logic (readinessExplain.ts, pqcMigrationGroup.ts) and the rendered components (react-dom/server).
 * Every number asserted here is one the fixture's API payload carries (Rule P): nothing is recomputed in the browser.
 * Run (frontend/): npx --yes tsx@4.23.15 --test components/cbom/results/readinessExplain.test.ts
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import React from "react";
import { renderToStaticMarkup } from "react-dom/server";

import {
  distinctPqcFixes,
  fixIndexByGroup,
  groupPqcMigrationRows,
  pqcRoadmapGroups,
  type PqcMigrationRowLike,
} from "../pqcMigrationGroup";
import { ReadinessExplainer } from "./ReadinessExplainer";
import { WaveLegend } from "./RunSections";
import { filtersToParams, hasActiveFilters, type RunTableFilters } from "./model";
import { nistLevelInfo, readinessDrillFilters, readinessExplanation, waveLegend, type ReadinessPostureLike } from "./readinessExplain";

const h = React.createElement;
const text = (html: string) => html.replace(/<[^>]+>/g, "").replace(/&#x27;/g, "'").replace(/&quot;/g, '"')
  .replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&amp;/g, "&");

// staging run 12 of the issue: 46 judged assets, all quantum-vulnerable; 8 settings rows with no public-key algorithm
const POSTURE: ReadinessPostureLike = {
  pqc_readiness_pct: 0,
  pqc_classes: { "quantum-vulnerable": 46, hybrid: 0, "quantum-safe": 0, "grover-weakened": 0, unknown: 0, "not-applicable": 8 },
  readiness_basis: { judged: 46, ready: 0, unknown: 0, not_applicable: 8, status: "ok" },
  readiness_actions: [
    { asset_type: "tls_endpoint", type_label: "TLS endpoint", code: "NO_PQ_KEX", title: "No post-quantum key exchange",
      fix: "Offer a hybrid key-exchange group first", assets: 38, readiness_after: 82.6 },
    { asset_type: "ssh_endpoint", type_label: "SSH endpoint", code: "SSH_NO_PQ_KEX", title: "SSH has no post-quantum key exchange",
      fix: "Prefer a hybrid SSH key exchange", assets: 8, readiness_after: 17.4 },
  ],
  readiness_excluded: [{ class: "not-applicable", basis: "no_public_key", assets: 8, text: "Settings and inventory with no public-key algorithm" }],
};

test("readiness: formula with the API's numbers, judged, exclusions, symmetric rule, actions", () => {
  const e = readinessExplanation(POSTURE);
  assert.equal(e.value, "0%");
  assert.equal(e.formula, "Ready judged assets ÷ judged assets = 0 ÷ 46 = 0%");
  assert.match(e.judged, /This run judged 46 assets\./);
  assert.deepEqual(e.counts, ["0 quantum-safe, hybrid or Grover-weakened (count as ready)", "46 quantum-vulnerable (count against)"]);
  assert.deepEqual(e.excluded, ["8 assets left out, no quantum verdict: Settings and inventory with no public-key algorithm"]);
  assert.match(e.symmetric, /AES-256/);
  assert.match(e.symmetric, /judged on its key exchange, not on its AES bulk cipher/);
  // review 5906810504: symmetric assets are judged (ready); only settings with no algorithm to judge are left out
  assert.match(e.symmetric, /Settings with no algorithm to judge \(e\.g\. a password-hash setting\) are left out/);
  assert.doesNotMatch(e.symmetric, /no public-key algorithm get no verdict/);
  assert.deepEqual(e.actions.map((a) => [a.text, a.effect, a.assets, a.assetType, a.pqcGroup]), [
    ["Fix 38 TLS endpoints: No post-quantum key exchange", "Readiness 0% → 82.6%", 38, "tls_endpoint", "NO_PQ_KEX"],
    ["Fix 8 SSH endpoints: SSH has no post-quantum key exchange", "Readiness 0% → 17.4%", 8, "ssh_endpoint", "SSH_NO_PQ_KEX"],
  ]);
  assert.equal(e.vulnerable, 46);
});

test("readiness: withheld, nothing judged, and an older API without the new fields", () => {
  const withheld = readinessExplanation({ pqc_readiness_pct: null, pqc_classes: { unknown: 9, "quantum-safe": 2 },
    readiness_basis: { judged: 2, ready: 2, unknown: 9, not_applicable: 0, status: "not_enough_identified" } });
  assert.equal(withheld.value, "Not enough identified");
  assert.match(withheld.excluded[0], /withheld: more assets are unidentified \(9\) than judged \(2\)/);
  assert.match(withheld.excluded[1], /9 assets left out: 9 not identified, 0 with no public-key algorithm/);
  const none = readinessExplanation({ pqc_readiness_pct: null, readiness_basis: { judged: 0, ready: 0, unknown: 0, not_applicable: 3, status: "nothing_judged" } });
  assert.match(none.excluded[0], /no percentage \(not 0%, not 100%\)/);
  const old = readinessExplanation({ pqc_readiness_pct: 50 });
  assert.equal(old.hasBasis, false);
  assert.equal(old.value, "50%");
  assert.deepEqual(old.actions, []);
  assert.equal(readinessExplanation(null).value, "n/a");
});

test("NIST level: spelled out with its meaning and the next level's requirement", () => {
  const l0 = nistLevelInfo(0);
  assert.equal(l0.name, "Level 0: no quantum resistance");
  assert.match(l0.meaning, /Shor's algorithm/);
  assert.match(l0.next, /^Level 1 needs a NIST post-quantum algorithm/);
  assert.equal(nistLevelInfo(3).next, "Level 4: as hard as a SHA-384 collision (a larger parameter set).");
  assert.equal(nistLevelInfo(5).next, "");
  assert.equal(nistLevelInfo(null).name, l0.name);
  assert.equal(nistLevelInfo(9).name, l0.name);
});

test("waves: one legend row per wave, the plan's counts, and why a wave is empty", () => {
  const rows = waveLegend({ "1": 28, "2": 2, "4": 16 }, { "1": "R1", "2": "R2", "3": "R3", "4": "R4", none: "RN" });
  assert.deepEqual(rows.map((r) => [r.label, r.count, r.rule]), [
    ["Wave 1", 28, "R1"], ["Wave 2", 2, "R2"], ["Wave 3", 0, "R3"], ["Wave 4", 16, "R4"], ["No action", 0, "RN"]]);
  assert.match(rows[2].empty, /No asset of this run matches this rule/);
  assert.equal(rows[0].empty, "");
  // an older backend without rules: the same rule set in words
  // wave 3 is any other weakness whatever its impact (suggested_wave), not only Medium and Low
  assert.match(waveLegend({}, undefined)[2].rule, /^Any other weakness, whatever its impact/);
  assert.match(waveLegend({}, undefined)[0].rule, /internet-facing or in-transit \(HNDL\) asset/);
});

const runRow = (i: number, over: Partial<PqcMigrationRowLike> = {}): PqcMigrationRowLike => ({
  name: `HTTPS 10.0.0.${i}:443`, primitive: "key-agree", key_size: null, curve: "x25519", nist_quantum_security_level: 0,
  migration_target: null, migration_roadmap: "Offer a hybrid key-exchange group first", suggested_fix: "Offer a hybrid key-exchange group first",
  impact: "High", location: `10.0.0.${i}:443`, bom_ref: `zs-asset-${i}`, asset_type: "tls_endpoint", type_label: "TLS endpoint",
  algorithm: "X25519", migration_code: "NO_PQ_KEX", fix_code: "NO_PQ_KEX", finding_title: "No post-quantum key exchange", ...over,
});

test("quantum list: one card per (algorithm, finding, fix) with the count, each distinct fix once", () => {
  const rows = [
    ...Array.from({ length: 38 }, (_, i) => runRow(i + 1)),
    ...Array.from({ length: 2 }, (_, i) => runRow(100 + i, { algorithm: "secp256r1" })), // another curve, same fix
    ...Array.from({ length: 6 }, (_, i) => runRow(200 + i, {
      name: `SSH 10.0.1.${i}:22`, asset_type: "ssh_endpoint", type_label: "SSH endpoint", algorithm: "curve25519-sha256",
      migration_code: "SSH_NO_PQ_KEX", fix_code: "SSH_NO_PQ_KEX", finding_title: "SSH has no post-quantum key exchange",
      migration_roadmap: "Prefer a hybrid SSH key exchange", suggested_fix: "Prefer a hybrid SSH key exchange" })),
  ];
  const groups = groupPqcMigrationRows(rows);
  assert.deepEqual(groups.map((g) => [g.name, g.descriptor, g.instances.length]).sort(), [
    ["X25519 on TLS endpoint", "No post-quantum key exchange", 38],
    ["curve25519-sha256 on SSH endpoint", "SSH has no post-quantum key exchange", 6],
    ["secp256r1 on TLS endpoint", "No post-quantum key exchange", 2],
  ]);
  const fixes = distinctPqcFixes(groups);
  assert.deepEqual(fixes.map((f) => [f.index, f.fix, f.instances.length, f.names.length]), [
    [1, "Offer a hybrid key-exchange group first", 40, 2],
    [2, "Prefer a hybrid SSH key exchange", 6, 1],
  ]);
  const byGroup = fixIndexByGroup(fixes);
  assert.equal(byGroup.get(groups.find((g) => g.name.startsWith("secp256r1"))!.key), 1);
  // the roadmap lists each fix once, with every asset it covers
  const roadmap = pqcRoadmapGroups(rows);
  assert.deepEqual(roadmap.map((g) => [g.roadmap, g.instances.length]), [
    ["Offer a hybrid key-exchange group first", 40], ["Prefer a hybrid SSH key exchange", 6]]);
  // nothing is dropped: the cards hold every row
  assert.equal(groups.reduce((s, g) => s + g.instances.length, 0), rows.length);
});

test("render: the readiness explainer and the wave legend", () => {
  const html = renderToStaticMarkup(h(ReadinessExplainer, { posture: POSTURE, onShowAssets: () => undefined }));
  const t = text(html);
  assert.match(t, /What PQC readiness 0% means/);
  assert.match(t, /Formula: Ready judged assets ÷ judged assets = 0 ÷ 46 = 0%/);
  assert.match(t, /8 assets left out, no quantum verdict/);
  assert.match(t, /Fix 38 TLS endpoints: No post-quantum key exchange · Readiness 0% → 82\.6%/);
  assert.equal((html.match(/data-testid="pqc-readiness-action"/g) ?? []).length, 2);
  assert.match(t, /Show the 46 quantum-vulnerable assets in the findings table/);
  assert.match(html, /data-infotip="cbom.run.readiness"/);
  assert.match(html, /data-infotip="cbom.run.readiness_actions"/);
  assert.equal(renderToStaticMarkup(h(ReadinessExplainer, { posture: null })), "");

  const legend = text(renderToStaticMarkup(h(WaveLegend, { byWave: { "1": 28, "2": 2, "4": 16 } })));
  assert.match(legend, /Wave 3 \(0\): Any other weakness, whatever its impact \(Medium, Low, Info or none recorded\)\. No asset of this run matches this rule/);
  assert.match(legend, /Wave 1 \(28\): Urgent/);
  // while the plan is loading: the rules without counts
  const loading = text(renderToStaticMarkup(h(WaveLegend, { byWave: null })));
  assert.doesNotMatch(loading, /\(0\)/);
  assert.match(loading, /Wave 4: A quantum-vulnerable asset with no other weakness/);
});

// review 5906810504 blocker: two TLS groups (RSA key exchange, ECDHE) must open two different lists of N rows each, so
// "Show these N" filters by the group's asset type AND its quantum finding code (server-side pqc_group, judged with
// posture's own functions; test_each_readiness_group_filters_the_table_to_exactly_its_assets checks N == total).
test("show these N: the group's type and code, every other filter cleared", () => {
  const two: ReadinessPostureLike = { ...POSTURE, readiness_actions: [
    { asset_type: "tls_endpoint", type_label: "TLS endpoint", code: "NO_PQ_KEX", title: "No post-quantum key exchange", fix: null, assets: 4, readiness_after: 10 },
    { asset_type: "tls_endpoint", type_label: "TLS endpoint", code: "STATIC_RSA_KEX", title: "RSA key exchange without forward secrecy", fix: null, assets: 1, readiness_after: 2 },
    { asset_type: "private_key", type_label: "Private key", code: null, title: "Quantum-vulnerable algorithm", fix: null, assets: 1, readiness_after: 2 },
  ] };
  const [ecdhe, rsa, nocode] = readinessExplanation(two).actions;
  const before: RunTableFilters = { view: "findings", impact: "High", q: "api", source_id: 3, status: "in_progress", codes: ["X"], page: 4, page_size: 50 };
  const apply = (a?: Parameters<typeof readinessDrillFilters>[0]) => filtersToParams({ ...before, ...readinessDrillFilters(a) } as RunTableFilters);
  assert.deepEqual(apply(ecdhe), { view: "all", page: 1, page_size: 50, type: "tls_endpoint", quantum: true, pqc_group: "NO_PQ_KEX" });
  assert.deepEqual(apply(rsa), { view: "all", page: 1, page_size: 50, type: "tls_endpoint", quantum: true, pqc_group: "STATIC_RSA_KEX" });
  assert.notDeepEqual(apply(ecdhe), apply(rsa)); // the two TLS buttons open different lists
  assert.equal(apply(nocode).pqc_group, "none");
  // "Show the N quantum-vulnerable assets": posture's class (pqc_group=any), any type
  assert.deepEqual(apply(), { view: "all", page: 1, page_size: 50, quantum: true, pqc_group: "any" });
  assert.equal(readinessDrillFilters(ecdhe).drill_label, "Fix 4 TLS endpoints: No post-quantum key exchange");
  assert.ok(hasActiveFilters({ view: "all", page: 1, page_size: 50, pqc_group: "any" }));
  // the rendered buttons carry their group
  const html = renderToStaticMarkup(h(ReadinessExplainer, { posture: two, onShowAssets: () => undefined }));
  assert.deepEqual([...html.matchAll(/data-pqc-group="([^"]+)" data-type="([^"]+)"/g)].map((m) => [m[1], m[2]]),
    [["NO_PQ_KEX", "tls_endpoint"], ["STATIC_RSA_KEX", "tls_endpoint"], ["none", "private_key"]]);
});
