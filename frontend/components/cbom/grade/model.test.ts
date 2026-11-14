/**
 * CB-19 / CB-24 PR-1u: how a quantum risk grade and a crypto-agility fix class are shown. Every grade and "no grade",
 * every fix class with unknown (with and without its floor) and none, unseen values, the posture totals, the
 * Q0 Unknown item lines, the drawer's inputs table and the sha256 the model dialog checks.
 * Run (frontend/): npx --yes tsx@4.23.15 components/cbom/grade/model.test.ts
 */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";

import {
  FIX_CLASSES,
  FIX_VALUES,
  GRADE_BUCKETS,
  detailText,
  GRADE_KEYS,
  GRADE_TEXT,
  explainRows,
  fixClassChipClass,
  fixClassText,
  fixClassTitle,
  fixDistribution,
  gradeChipClass,
  gradeText,
  gradeTitle,
  isGrade,
  q0ItemCountText,
  q0ItemLine,
  q0Reasons,
  qDistribution,
  reasonTexts,
  selfFixablePct,
  sha256Hex,
  type GradeModel,
  type QExplain,
  type QPosture,
} from "./model";

const [G0, G1, G2, G3, G4] = GRADE_KEYS;

// ---- grade keys: the five, in the API's order, each printed only with its risk word
assert.equal(GRADE_KEYS.length, 5);
assert.deepEqual(GRADE_KEYS.map(gradeText), [...GRADE_TEXT]);
assert.deepEqual(GRADE_TEXT, ["Q0 Unknown", "Q1 Critical", "Q2 High", "Q3 Medium", "Q4 Low"]);
for (const g of GRADE_KEYS) assert.ok(isGrade(g));
assert.deepEqual([...GRADE_BUCKETS], [...GRADE_KEYS, "none"]);

// no grade: null, undefined and "" print nothing (the chip shows "—"); an unseen value is printed as it came, marked
assert.equal(gradeText(null), null);
assert.equal(gradeText(undefined), null);
assert.equal(gradeText(""), null);
assert.equal(gradeText("Q9"), "Q9 (unrecognised grade)");
assert.equal(isGrade("Q9"), false);
assert.equal(isGrade("q1"), false);

// palette: grey, red, orange, amber, green; an unseen value and "no grade" are neutral
const colour = (g: string | null) => /\b(zinc|red|orange|amber|green)-/.exec(gradeChipClass(g))?.[1];
assert.deepEqual(GRADE_KEYS.map(colour), ["zinc", "red", "orange", "amber", "green"]);
assert.equal(colour(null), "zinc");
assert.equal(colour("Q9"), "zinc");

// the chip's title: the served reason sentence; the reason code when the model is not loaded; "No grade: …" for none
const served = reasonTexts({ reasons: [{ code: "qv_exceeds_internet", grade: G1, label: "Critical", kind: "asset",
  text: "Quantum-vulnerable, X + Y > Z, reachable from the internet" }] } as GradeModel);
assert.equal(gradeTitle({ q_grade: G1, q_reason: "qv_exceeds_internet" }, served),
  "Q1 Critical: Quantum-vulnerable, X + Y > Z, reachable from the internet");
assert.equal(gradeTitle({ q_grade: G3, q_reason: "grover_weakened" }), "Q3 Medium: Grover weakened");
assert.equal(gradeTitle({ q_grade: null, q_reason: "not_applicable" }), "No grade: no public-key cryptography");
assert.equal(gradeTitle({ q_grade: null, q_reason: "attested_no_class" }), "No grade: Attested no class");
assert.equal(gradeTitle({}), "No grade: no public-key cryptography");

// ---- posture distribution: every bucket present (0 too), in order, totals equal the posture's assets
const posture: QPosture = {
  assets: 20,
  q_grades: { [G0]: 3, [G1]: 2, [G2]: 4, [G3]: 1, [G4]: 0, none: 10 },
  q0_reasons: { coverage_gap: 2, mosca_missing: 1, unknown_verdict: 3, source_not_read: 2 },
};
const d = qDistribution(posture);
assert.equal(d.total, 20);
assert.equal(d.consistent, true);
assert.deepEqual(d.segments.map((s) => s.bucket), [...GRADE_BUCKETS]);
assert.deepEqual(d.segments.map((s) => s.count), [3, 2, 4, 1, 0, 10]);
assert.deepEqual(d.segments.map((s) => s.text), [...GRADE_TEXT, "No grade"]);
assert.deepEqual(d.segments.map((s) => s.pct), [15, 10, 20, 5, 0, 50]);
// a total that disagrees with the asset count is flagged, never hidden
assert.equal(qDistribution({ ...posture, assets: 21 }).consistent, false);
// an older backend / an empty run: zeros, nothing divided by zero
const empty = qDistribution({ assets: 0, q_grades: {} });
assert.equal(empty.total, 0);
assert.ok(empty.segments.every((s) => s.count === 0 && s.pct === 0));
// non-numbers are 0
assert.equal(qDistribution({ q_grades: { [G1]: "x" as unknown as number, none: 2 } }).total, 2);

// Q0 Unknown reasons: most items first, then by code
assert.deepEqual(q0Reasons(posture), [
  { code: "unknown_verdict", count: 3 }, { code: "coverage_gap", count: 2 }, { code: "source_not_read", count: 2 },
  { code: "mosca_missing", count: 1 },
]);
assert.deepEqual(q0Reasons({}), []);

// ---- Q0 Unknown item lines
assert.equal(q0ItemLine({ key: "inputs:mosca", kind: "inputs", reason: "mosca_missing", q_grade: G0, source_id: null,
  source_name: null, count: 34, missing: ["x", "z"] }), "Mosca X, Z not set");
assert.equal(q0ItemCountText({ key: "inputs:mosca", kind: "inputs", reason: "mosca_missing", q_grade: G0,
  source_id: null, source_name: null, count: 34 }), "34 assets ungraded");
assert.equal(q0ItemLine({ key: "coverage:s1:*:timeout", kind: "scope", reason: "coverage_gap", q_grade: G0, source_id: 1,
  source_name: "DMZ", count: 7, target: "*", status: "timeout" }), "addresses · timeout");
assert.equal(q0ItemCountText({ key: "k", kind: "scope", reason: "coverage_gap", q_grade: G0, source_id: 1,
  source_name: "DMZ", count: 7 }), "7 rows");
assert.equal(q0ItemLine({ key: "coverage:s2:10.0.0.5:BitLocker", kind: "scope", reason: "coverage_gap", q_grade: G0,
  source_id: 2, source_name: "win", count: 1, target: "10.0.0.5", check: "BitLocker", status: "sudo_denied" }),
"10.0.0.5 · BitLocker · sudo denied");
assert.equal(q0ItemLine({ key: "asset:abc", kind: "asset", reason: "unknown_verdict", q_grade: G0, source_id: 1,
  source_name: "web", count: 1, asset_id: 9, location: "10.0.0.9:443" }), "10.0.0.9:443");
assert.equal(q0ItemCountText({ key: "asset:abc", kind: "asset", reason: "unknown_verdict", q_grade: G0, source_id: 1,
  source_name: "web", count: 1 }), null);

// Q0 Unknown item details: text as sent; an object as words, never raw JSON
assert.equal(detailText("collection not finished"), "collection not finished");
assert.equal(detailText({ reported: 9, stored: 4 }), "reported 9, stored 4");
assert.equal(detailText({ truncated: true, stored: 0 }), "truncated, stored 0");
assert.equal(detailText(null), null);
assert.equal(detailText(""), null);

// ---- the drawer's inputs table
const explain: QExplain = {
  class: "quantum-vulnerable", class_basis: null, graded_class: "quantum-vulnerable", fallback: false, fallback_basis: null,
  exposure: "internet", exposure_basis: "public IP address", anchor: false, anchor_basis: null, x: 10, x_basis: "source",
  y: 5, z: 12, missing: [], inequality: "10 + 5 > 12", provenance: "observed", item_kind: "asset", coverage: null,
  check: null, status: null, model: "qg-1", model_version: "qg-1+abcdef012345", inputs_source: "current",
  inputs_digest: "0123456789abcdef",
};
const rows = explainRows(explain);
const row = (label: string) => rows.find((r) => r.label === label);
assert.deepEqual(row("PQC class"), { label: "PQC class", value: "quantum-vulnerable", basis: null });
assert.deepEqual(row("Exposure"), { label: "Exposure", value: "internet", basis: "public IP address" });
assert.equal(row("X: years data must stay secret")?.value, "10");
assert.equal(row("X: years data must stay secret")?.basis, "set on the source");
assert.equal(row("Mosca")?.value, "10 + 5 > 12");
assert.equal(row("Graded as"), undefined);
assert.equal(row("Grade model")?.value, "qg-1+abcdef012345");
assert.equal(row("Inputs")?.basis, "0123456789abcdef");
// missing Mosca inputs: "Not set", and which ones
const missing = explainRows({ ...explain, x: null, x_basis: null, z: null, missing: ["x", "z"], inequality: null });
assert.equal(missing.find((r) => r.label.startsWith("X:"))?.value, "Not set");
assert.equal(missing.find((r) => r.label === "Missing")?.value, "X, Z");
assert.equal(missing.find((r) => r.label === "Mosca"), undefined);
// a hybrid endpoint graded on its classical fallback says so
const fb = explainRows({ ...explain, class: "hybrid", graded_class: "quantum-vulnerable", fallback: true, fallback_basis: "accepts TLS 1.2" });
assert.equal(fb.find((r) => r.label === "Graded as")?.value, "quantum-vulnerable");
assert.equal(fb.find((r) => r.label === "Classical fallback")?.basis, "accepts TLS 1.2");
// an unread scope row: what was not read
const scope = explainRows({ ...explain, item_kind: "scope", class: null, check: "BitLocker", status: "winrm_denied", coverage: "gap" });
assert.deepEqual(scope.slice(0, 4).map((r) => r.value), ["Unread scope", "BitLocker", "winrm denied", "Gap"]);

// ---- fix class: the four classes, unknown with and without a floor, none, null, an unseen value
assert.deepEqual(FIX_VALUES, ["configurable", "code-fixed", "vendor-fixed", "hardware-fixed", "unknown", "none"]);
assert.deepEqual(FIX_CLASSES.map((c) => fixClassText({ fix_class: c })), ["Configurable", "Code-fixed", "Vendor-fixed", "Hardware-fixed"]);
assert.equal(fixClassText({ fix_class: "unknown", fix_class_floor: "vendor-fixed" }), "At least vendor-fixed");
assert.equal(fixClassText({ fix_class: "unknown", fix_class_floor: "configurable" }), "At least configurable");
assert.equal(fixClassText({ fix_class: "unknown", fix_class_floor: null }), "Unknown");
assert.equal(fixClassText({ fix_class: "unknown", fix_class_floor: "bogus" }), "Unknown");
assert.equal(fixClassText({ fix_class: "none" }), "—");
assert.equal(fixClassText({ fix_class: null }), "—");
assert.equal(fixClassText({}), "—");
assert.equal(fixClassText({ fix_class: "firmware-fixed" }), "firmware-fixed (unrecognised class)");
assert.match(fixClassTitle({ fix_class: "vendor-fixed", fix_class_confidence: "inferred" }), /likely: inferred/);
assert.equal(fixClassTitle({ fix_class: "vendor-fixed", fix_class_confidence: "observed" }), "Vendor-fixed");
assert.match(fixClassTitle({ fix_class: "unknown", fix_class_floor: "vendor-fixed" }), /at least vendor-fixed/);
assert.match(fixClassTitle({ fix_class: "none" }), /nothing to change today/);
// palette: teal, blue, violet, slate, dashed grey; an unseen value gets the unknown style
const fixColour = (v: string | null) => /\b(teal|blue|violet|slate|zinc)-/.exec(fixClassChipClass(v))?.[1];
assert.deepEqual(FIX_CLASSES.map(fixColour), ["teal", "blue", "violet", "slate"]);
assert.match(fixClassChipClass("unknown"), /border-dashed/);
assert.match(fixClassChipClass("firmware-fixed"), /border-dashed/);

// self-fixable: (configurable + code-fixed) / the four classes, one decimal (agility.self_fixable_pct)
assert.equal(selfFixablePct({ configurable: 30, "code-fixed": 10, "vendor-fixed": 50, "hardware-fixed": 10, unknown: 7, none: 40 }), 40);
assert.equal(selfFixablePct({ configurable: 1, "vendor-fixed": 2 }), 33.3);
assert.equal(selfFixablePct({ unknown: 3, none: 9 }), null);
assert.equal(selfFixablePct({}), null);

// posture totals: six counts in order, total = assets, classified excludes unknown and none
const fx = fixDistribution({ configurable: 30, "code-fixed": 10, "vendor-fixed": 50, "hardware-fixed": 10, unknown: 7, none: 43 }, 150);
assert.deepEqual(fx.segments.map((s) => s.value), [...FIX_VALUES]);
assert.deepEqual(fx.segments.map((s) => s.count), [30, 10, 50, 10, 7, 43]);
assert.equal(fx.total, 150);
assert.equal(fx.classified, 100);
assert.equal(fx.selfFixable, 40);
assert.equal(fx.consistent, true);
assert.equal(fixDistribution({ none: 1 }, 2).consistent, false);
assert.equal(fixDistribution(undefined).total, 0);

// ---- the model dialog's check: sha256 hex of the served text, as Python's hashlib computes it
(async () => {
  assert.equal(await sha256Hex(""), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
  const text = "ZeroShield quantum risk grade, model qg-1.\nX + Y > Z -> Q1 Critical \"qv\" <= é\n";
  assert.equal(await sha256Hex(text), createHash("sha256").update(text, "utf8").digest("hex"));
  console.log("grade/model.test.ts: ok");
})().catch((e) => { console.error(e); process.exit(1); });
