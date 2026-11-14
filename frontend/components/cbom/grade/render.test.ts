/**
 * CB-19 / CB-24 PR-1u components rendered with react-dom/server, as the run page renders them: the grade chip for
 * every grade and "no grade" with its gate hooks, the fix-class chip for every class with unknown and none, the
 * posture cards (every count present, Q0 Unknown reasons and items, self-fixable headline, per-system), the drawer
 * sections, the model dialog body (served text verbatim, served sha), and nothing at all on an older backend.
 * Run (frontend/): npx --yes tsx@4.23.15 components/cbom/grade/render.test.ts
 */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import path from "node:path";
import React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

import {
  AgilityDrawerSection,
  AgilityPostureCard,
  EvidenceFixClass,
  FIX_VALUES,
  FixClassChip,
  GRADE_KEYS,
  GRADE_TEXT,
  Q0ItemList,
  QDistributionCard,
  QGradeChip,
  QGradeDrawerSection,
  QGradeModelBody,
  type AgilityDetail,
  type AgilityModel,
  type AgilityPosture,
  type GradeModel,
  type QExplain,
  type QPosture,
} from "./index";

const [G0, G1, G2, G3, G4] = GRADE_KEYS;
const h = React.createElement;
// a client with no network: every component here gets its model as a prop (or null) and fetches nothing
const render = (el: React.ReactElement) =>
  renderToStaticMarkup(h(QueryClientProvider, { client: new QueryClient() }, el));
const text = (html: string) => html.replace(/<[^>]+>/g, "").replace(/&#x27;/g, "'").replace(/&quot;/g, '"')
  .replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&amp;/g, "&");
const esc = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const attr = (html: string, raw: string, name: string, testId = esc(raw)) =>
  new RegExp(`data-testid="${testId}"[^>]*?${name}="([^"]*)"|${name}="([^"]*)"[^>]*?data-testid="${testId}"`).exec(html)?.slice(1).find((v) => v != null);

const MODEL: GradeModel = {
  model: "qg-1", model_version: "qg-1+abcdef012345",
  text: "ZeroShield quantum risk grade, model qg-1.\n  9. class quantum-vulnerable and X + Y > Z -> Q1 Critical \"qv_exceeds_internet\"\n 13. X + Y <= Z\n",
  text_sha256: "",
  grades: GRADE_TEXT.map((t) => ({ grade: t.split(" ")[0], label: t.split(" ")[1] })),
  reasons: [
    { code: "qv_exceeds_internet", grade: G1, label: "Critical", kind: "asset", text: "Quantum-vulnerable, X + Y > Z, reachable from the internet" },
    { code: "coverage_gap", grade: G0, label: "Unknown", kind: "scope", text: "A check, target or address range was not read" },
    { code: "mosca_missing", grade: G0, label: "Unknown", kind: "inputs", text: "Quantum-vulnerable, and the team's Mosca X, Y or Z is not set" },
    { code: "not_applicable", grade: null, label: null, kind: "no_grade", text: "No public-key cryptography to grade" },
  ],
};
MODEL.text_sha256 = createHash("sha256").update(MODEL.text, "utf8").digest("hex");

// ---- grade chip: every grade with its risk word and hooks; "no grade" is "—" with the reason as title
GRADE_KEYS.forEach((g, i) => {
  const html = render(h(QGradeChip, { item: { q_grade: g, q_label: "ignored", q_reason: "qv_within" }, assetId: 40 + i }));
  assert.equal(text(html), GRADE_TEXT[i]);
  assert.equal(attr(html, `run-asset-q-${40 + i}`, "data-q"), g);
  assert.equal(attr(html, `run-asset-q-${40 + i}`, "data-q-reason"), "qv_within");
});
const none = render(h(QGradeChip, { item: { q_grade: null, q_reason: "not_applicable" }, assetId: 7 }));
assert.equal(attr(none, "run-asset-q-7", "data-q"), "none");
assert.match(text(none), /^— No grade: no public-key cryptography$/);
assert.match(none, /title="No grade: no public-key cryptography"/);
// an older backend (no grade fields at all): a bare "—" that claims nothing about the asset
const absent = render(h(QGradeChip, { item: {}, assetId: 8 }));
assert.equal(attr(absent, "run-asset-q-8", "data-q"), "unavailable");
assert.doesNotMatch(absent, /public-key/);
assert.match(text(absent), /^— Not graded: this server does not send a quantum risk grade$/);
// the served reason sentence is the chip's title
const titled = render(h(QGradeChip, { item: { q_grade: G1, q_reason: "qv_exceeds_internet" },
  reasons: new Map([["qv_exceeds_internet", "Quantum-vulnerable, X + Y &gt; Z, internet"]]) }));
assert.match(titled, /title="Q1 Critical: Quantum-vulnerable/);
// an unseen grade does not crash and is not printed bare
assert.equal(text(render(h(QGradeChip, { item: { q_grade: "Q7" } }))), "Q7 (unrecognised grade)");

// ---- fix-class chip: every value, unknown with its floor, inferred marked "likely", none "—"
for (const v of FIX_VALUES) {
  const html = render(h(FixClassChip, { item: { fix_class: v, fix_class_floor: v === "unknown" ? "vendor-fixed" : null,
    fix_class_confidence: v === "unknown" || v === "none" ? null : "observed" }, assetId: 3 }));
  assert.equal(attr(html, "run-asset-fixclass-3", "data-fix-class"), v);
  assert.equal(text(html).replace(/ No finding code.*$/, ""), {
    configurable: "Configurable", "code-fixed": "Code-fixed", "vendor-fixed": "Vendor-fixed",
    "hardware-fixed": "Hardware-fixed", unknown: "At least vendor-fixed", none: "—",
  }[v]);
}
assert.equal(text(render(h(FixClassChip, { item: { fix_class: "vendor-fixed", fix_class_confidence: "inferred" } }))), "Vendor-fixed· likely");
const fxAbsent = render(h(FixClassChip, { item: {}, assetId: 4 }));
assert.equal(attr(fxAbsent, "run-asset-fixclass-4", "data-fix-class"), "unavailable");
assert.doesNotMatch(fxAbsent, /nothing to change/);
assert.equal(text(render(h(FixClassChip, { item: { fix_class: "unknown" } }))), "Unknown");
assert.equal(text(render(h(FixClassChip, { item: { fix_class: "firmware-fixed" } }))), "firmware-fixed (unrecognised class)");

// ---- the quantum-risk posture card
const posture: QPosture = {
  assets: 20,
  q_grades: { [G0]: 3, [G1]: 2, [G2]: 4, [G3]: 1, [G4]: 0, none: 10 },
  q0_reasons: { coverage_gap: 1, mosca_missing: 1, unknown_verdict: 1 },
  q0_items: [
    { key: "inputs:mosca", kind: "inputs", reason: "mosca_missing", q_grade: G0, source_id: null, source_name: null, count: 2, missing: ["z"] },
    { key: "coverage:src-1:*:timeout", kind: "scope", reason: "coverage_gap", q_grade: G0, source_id: 1, source_name: "DMZ range",
      count: 7, target: "*", status: "timeout", detail: "addresses not read: timeout", addresses: ["10.0.0.1", "10.0.0.2"] },
    { key: "asset:node:abc", kind: "asset", reason: "unknown_verdict", q_grade: G0, source_id: 1, source_name: "DMZ range",
      count: 1, asset_id: 77, location: "10.0.0.9:443" },
  ],
  q0_items_total: 3,
  q0_counts: { assets: 3, scope_items: 1, scope_rows: 7 },
  grade_model: "qg-1", grade_model_version: "qg-1+abcdef012345",
  grade_inputs: { source: "current", mosca: { x: 10, y: 5, z: null }, digest: "0123456789abcdef" },
};
const card = render(h(QDistributionCard, { posture, model: MODEL }));
assert.match(card, /data-testid="posture-q"/);
assert.equal(attr(card, "posture-q", "data-model-version"), "qg-1+abcdef012345");
assert.equal(attr(card, "posture-q", "data-inputs-digest"), "0123456789abcdef");
const expected: Record<string, string> = { [G0]: "3", [G1]: "2", [G2]: "4", [G3]: "1", [G4]: "0", none: "10" };
for (const [bucket, count] of Object.entries(expected)) assert.equal(attr(card, `posture-q-${bucket}`, "data-count"), count, bucket);
assert.equal(attr(card, "posture-q-distribution", "data-total"), "20");
assert.doesNotMatch(card, /posture-q-mismatch/);
for (const t of GRADE_TEXT) assert.ok(text(card).includes(t), t);
assert.ok(text(card).includes("No grade10(50%)"));
// Q0 Unknown reasons with counts, the served sentence when the model is there, the code otherwise
assert.equal(attr(card, "posture-q0-reason-mosca_missing", "data-count"), "1");
assert.ok(text(card).includes("Quantum-vulnerable, and the team's Mosca X, Y or Z is not set"));
assert.ok(text(card).includes("Unknown verdict"));
assert.ok(text(card).includes("3 assets graded Q0 Unknown; 1 unread scope item (7 rows)"));
assert.ok(text(card).includes("Show the 3 Q0 Unknown items"));
assert.ok(text(card).includes("Mosca X 10, Y 5, Z not set (the team's settings now, not when the run started)"));
// counts that do not add up are said, not hidden
assert.match(render(h(QDistributionCard, { posture: { ...posture, assets: 19 }, model: MODEL })), /posture-q-mismatch/);
// an older backend: no grades, no card
assert.equal(render(h(QDistributionCard, { posture: { assets: 5 }, model: MODEL })), "");

// ---- the Q0 Unknown item list (hooks q0-item-<key> with data-reason; asset items open the asset)
const list = render(h(Q0ItemList, { items: posture.q0_items!, total: 250, onOpenAsset: () => undefined }));
for (const item of posture.q0_items!) assert.equal(attr(list, `q0-item-${item.key}`, "data-reason"), item.reason);
assert.match(list, /data-testid="q0-item-open-77"/);
assert.ok(text(list).includes("Mosca Z not set"));
assert.ok(text(list).includes("2 assets ungraded"));
assert.ok(text(list).includes("10.0.0.1, 10.0.0.2"));
assert.ok(text(list).includes("Showing the first 3 of 250 items"));
assert.match(render(h(Q0ItemList, { items: [] })), /q0-items-empty/);
// limit: the first N and a "Show all" button
const limited = render(h(Q0ItemList, { items: posture.q0_items!, limit: 2 }));
assert.equal((limited.match(/data-testid="q0-item-/g) ?? []).length, 2);
assert.ok(text(limited).includes("Show all 3"));

// ---- the model dialog body: served text verbatim, served sha shown
const body = render(h(QGradeModelBody, { model: MODEL }));
const pre = /<pre[^>]*data-testid="grade-model-text"[^>]*>([\s\S]*?)<\/pre>/.exec(body)?.[1] ?? "";
assert.equal(text(pre), MODEL.text);
assert.equal(attr(body, "grade-model-sha", "data-sha"), MODEL.text_sha256);
assert.equal(attr(body, "grade-model-sha", "data-check"), "checking");  // the browser's own check runs after mount
assert.ok(text(body).includes("version qg-1+abcdef012345"));

// ---- the drawer's grade section
const explain: QExplain = {
  class: "quantum-vulnerable", class_basis: null, graded_class: "quantum-vulnerable", fallback: false, fallback_basis: null,
  exposure: "internet", exposure_basis: "public IP address", anchor: false, anchor_basis: null, x: 10, x_basis: "team",
  y: 5, z: 12, missing: [], inequality: "10 + 5 > 12", provenance: "observed", item_kind: "asset", coverage: null,
  check: null, status: null, model: "qg-1", model_version: "qg-1+abcdef012345", inputs_source: "current",
  inputs_digest: "0123456789abcdef",
};
const drawer = render(h(QGradeDrawerSection, { asset: { q_grade: G1, q_label: "Critical", q_reason: "qv_exceeds_internet", q_explain: explain }, model: MODEL }));
assert.equal(attr(drawer, "asset-q-grade", "data-q"), G1);
assert.equal(attr(drawer, "asset-q-chip", "data-q"), G1);
assert.ok(text(drawer).includes("Q1 Critical"));
assert.ok(text(drawer).includes("Quantum-vulnerable, X + Y > Z, reachable from the internet (X + Y vs Z: 10 + 5 > 12)."));
assert.ok(text(drawer).includes("Exposureinternet · public IP address"));
assert.ok(text(drawer).includes("X: years data must stay secret10 · team setting"));
assert.match(drawer, /data-testid="asset-q-input-mosca"/);
const ungraded = render(h(QGradeDrawerSection, { asset: { q_grade: null, q_reason: "not_applicable", q_explain: { ...explain, class: "not-applicable", inequality: null } }, model: MODEL }));
assert.equal(attr(ungraded, "asset-q-grade", "data-q"), "none");
assert.ok(text(ungraded).includes("No grade"));
assert.ok(text(ungraded).includes("No public-key cryptography to grade."));
assert.equal(render(h(QGradeDrawerSection, { asset: {}, model: MODEL })), "");  // older backend

// ---- the agility posture card: six counts (all and excluding post-quantum), self-fixable, unknown reasons, systems
const agility: AgilityPosture = {
  assets: 150,
  fix_classes: { configurable: 30, "code-fixed": 10, "vendor-fixed": 50, "hardware-fixed": 10, unknown: 7, none: 43 },
  fix_classes_excl_pq: { configurable: 30, "code-fixed": 5, "vendor-fixed": 20, "hardware-fixed": 5, unknown: 2, none: 88 },
  fix_class_self_fixable_pct: 40,
  unknown_reasons: { key_provider_not_read: 5, no_fix_class: 2 },
  fix_class_systems: [{ key: "application:payments", label: "Payments", kind: "application", assets: 100, hardest: "hardware-fixed",
    counts: { configurable: 20, "vendor-fixed": 50, "hardware-fixed": 10, unknown: 5, none: 15 }, self_fixable_pct: 25 }],
  fix_class_systems_truncated: false,
  agility_version: "fx-1+0123",
};
const AG_MODEL = { unknown_reasons: { key_provider_not_read: "key provider of a Windows certificate with a private key not read" }, rules: [] } as unknown as AgilityModel;
const ag = render(h(AgilityPostureCard, { posture: agility, model: AG_MODEL }));
const agExpected: Record<string, string> = { configurable: "30", "code-fixed": "10", "vendor-fixed": "50", "hardware-fixed": "10", unknown: "7", none: "43" };
for (const [v, n] of Object.entries(agExpected)) assert.equal(attr(ag, `posture-fix-${v}`, "data-count"), n, v);
assert.equal(attr(ag, "posture-fix-distribution", "data-total"), "150");
assert.equal(attr(ag, "posture-fix-distribution", "data-view"), "all");
assert.equal(attr(ag, "posture-fix-self-fixable", "data-pct"), "40");
assert.ok(text(ag).includes("self-fixable: 40 of 100 assets with a fix class are configurable or code-fixed"));
assert.equal(attr(ag, "posture-fix-unknown-key_provider_not_read", "data-count"), "5");
assert.ok(text(ag).includes("key provider of a Windows certificate with a private key not read"));
assert.ok(text(ag).includes("No fix class"));  // a reason the model did not name: its code, never a crash
assert.ok(text(ag).includes("Show per system (1)"));
for (const id of ["configurable", "code_fixed", "vendor_fixed", "hardware_fixed", "unknown", "inferred", "self_fixable", "excl_pq"]) {
  assert.match(ag, new RegExp(`data-testid="tip-cbom.agility.${id}"`), id);
}
assert.doesNotMatch(ag, /posture-fix-mismatch/);
assert.match(render(h(AgilityPostureCard, { posture: { ...agility, assets: 151 }, model: AG_MODEL })), /posture-fix-mismatch/);
assert.equal(render(h(AgilityPostureCard, { posture: { assets: 3 }, model: AG_MODEL })), "");  // older backend

// ---- the agility drawer section
const detail: AgilityDetail = {
  fix_class: "unknown", floor: "vendor-fixed", confidence: null, fix_class_excl_pq: "configurable",
  by_code: [
    { code: "NO_TLS12", class: "configurable", floor: null, capability: false, rule: "R-TABLE", basis: "a protocol version is a setting", fact: null, confidence: "observed" },
    { code: "QUANTUM_VULNERABLE", class: "unknown", floor: "vendor-fixed", capability: true, rule: "R-HW-UNREAD", basis: "key provider not read", fact: "has_private_key=true", confidence: null },
    { code: "NO_PQ_KEX", class: "vendor-fixed", floor: null, capability: true, rule: "R-INFERRED", basis: "table default", fact: null, confidence: "inferred" },
  ],
  model: "fx-1", model_version: "fx-1+0123", source: "view",
};
const dr = render(h(AgilityDrawerSection, { agility: detail, model: AG_MODEL }));
assert.equal(attr(dr, "asset-fix-class", "data-fix-class"), "unknown");
assert.equal(attr(dr, "asset-fix-class", "data-fix-floor"), "vendor-fixed");
assert.equal(attr(dr, "asset-fix-chip", "data-fix-class"), "unknown");
assert.ok(text(dr).includes("At least vendor-fixed"));
assert.ok(!text(dr).includes("at least at least"));
assert.ok(text(dr).includes("A fact that decides the class was not read: it is at least vendor-fixed."));
assert.ok(text(dr).includes("Without the post-quantum migration codes: Configurable."));
for (const p of detail.by_code) {
  assert.equal(attr(dr, `asset-fix-code-${p.code}`, "data-fix-class"), p.class);
  assert.equal(attr(dr, `asset-fix-code-${p.code}`, "data-rule"), p.rule);
}
assert.ok(text(dr).includes("Read: has_private_key=true"));
assert.ok(text(dr).includes("QUANTUM_VULNERABLEAt least vendor-fixedrule R-HW-UNREADkey provider not read"));
assert.ok(text(dr).includes("\"Likely\": no fact the product read decides that class"));
const plain = render(h(AgilityDrawerSection, { agility: { ...detail, fix_class: "none", floor: null, by_code: [], fix_class_excl_pq: "none" }, model: AG_MODEL }));
assert.ok(text(plain).includes("No finding code: nothing to change today."));
const exclNone = render(h(AgilityDrawerSection, { agility: { ...detail, fix_class: "vendor-fixed", floor: null, fix_class_excl_pq: "none" }, model: AG_MODEL }));
assert.ok(text(exclNone).includes("Without the post-quantum migration codes: nothing to change today."));
assert.equal(render(h(AgilityDrawerSection, { agility: undefined, model: AG_MODEL })), "");  // older backend

// secondary text has a dark-theme variant (text-zinc-500 alone is 3.67:1 on zinc-900): no bare text-zinc-500 anywhere
for (const html of [card, list, body, drawer, render(h(QGradeChip, { item: { q_grade: null } })), ag, dr, plain]) {
  assert.doesNotMatch(html, /text-zinc-500(?![^"]*dark:text-zinc-400)/);
}
// the (i) button is visible enough (>= 3:1): zinc-500 / dark zinc-400, never zinc-400 on white
const tipButton = /<button[^>]*aria-label="About Self-fixable share"[^>]*>/.exec(ag)?.[0] ?? "";
assert.match(tipButton, /class="[^"]*text-zinc-500 dark:text-zinc-400/);
assert.doesNotMatch(tipButton, /title=/);

// evidence items (GET …/sources/evidence): answered HSM firmware / third-party area and vendors carry a class; an
// unanswered one says "not assessed"; the process areas show nothing
const ev = (item: { fix_class?: string | null; not_assessed?: boolean }) => render(h(EvidenceFixClass, { item, testId: "ev" }));
assert.equal(attr(ev({ fix_class: "hardware-fixed", not_assessed: false }), "ev", "data-fix-class"), "hardware-fixed");
assert.equal(text(ev({ fix_class: "vendor-fixed", not_assessed: false })), "Vendor-fixed");
assert.equal(attr(ev({ fix_class: null, not_assessed: true }), "ev", "data-fix-class"), "not_assessed");
assert.equal(text(ev({ fix_class: null, not_assessed: true })), "Fix class: not assessed");
assert.equal(ev({ fix_class: null, not_assessed: false }), "");
assert.equal(ev({}), "");

// mounted where CB-24 PLAN §10 PR-1u says: run results (both columns), code-scan results, Evidence tab
const src = (p: string) => readFileSync(path.join(__dirname, "..", "..", p), "utf8");
assert.match(src("cbom/sources/RunResults.tsx"), /<QGradeChip item=\{asset as QGradeFields\} assetId=\{asset.id\} \/>/);
assert.match(src("cbom/sources/RunResults.tsx"), /<FixClassChip item=\{asset as FixClassFields\} assetId=\{asset.id\} \/>/);
assert.match(src("CbomResults.tsx"), /<FixClassChip item=\{finding as FixClassFields\} testId=\{`cbom-finding-fixclass-\$\{finding.id\}`\} \/>/);
assert.match(src("cbom/sources/EvidenceTab.tsx"), /<EvidenceFixClass item=\{area as [^\n]*testId=\{`evidence-fixclass-\$\{area.area_key\}`\} \/>/);
assert.match(src("cbom/sources/EvidenceTab.tsx"), /<EvidenceFixClass item=\{vendor as [^\n]*testId=\{`vendor-fixclass-\$\{vendor.id\}`\} \/>/);

console.log("grade/render.test.ts: ok");
