/**
 * Grade-key contract (CB-19 §2.7, cx4 OB-1 §3): the UI's grade keys and risk words, fix-class values, labels and
 * tips equal the backend's, read from contracts/cbom/grade_keys.json, which backend/tests/
 * test_cbom_cb19_cb24_ui_contract.py keeps equal to qgrade.py and agility.py. A grade, reason or class the backend
 * adds without the UI fails here, not as a blank chip or a crash on a customer's page (HF-9). Also: the sha the model
 * dialog checks is the sha of the served text, and no file of this module prints a grade without its risk word.
 * Run (frontend/): npx --yes tsx@4.23.15 components/cbom/grade/gradeContract.test.ts
 */
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import path from "node:path";

import { FIX_CLASSES, FIX_LABEL, FIX_VALUES, GRADE_KEYS, GRADE_TEXT, GRADE_WORD, SELF_FIXABLE, isFixValue, sha256Hex } from "./model";
import { GRADE_TIPS, fixClassTipId } from "./tips";

const root = path.join(__dirname, "..", "..", "..", "..");
const contract = JSON.parse(readFileSync(path.join(root, "contracts", "cbom", "grade_keys.json"), "utf8")) as {
  grade_model: string;
  grades: { grade: string; label: string }[];
  reasons: Record<string, string | null>;
  formula_sha256: string;
  formula_text: string;
  pqc_classes: string[];
  agility_model: string;
  fix_classes: string[];
  fix_values: string[];
  fix_class_text: Record<string, { label: string; what: string; example: string }>;
  fix_inferred_text: string;
  self_fixable: string[];
  unknown_reasons: Record<string, string>;
};

// grades: same keys, same order, same risk words
assert.equal(contract.grade_model, "qg-1");
assert.deepEqual(contract.grades.map((g) => g.grade), GRADE_KEYS);
assert.deepEqual(contract.grades.map((g) => `${g.grade} ${g.label}`), [...GRADE_TEXT]);
for (const g of contract.grades) assert.equal(GRADE_WORD[g.grade as keyof typeof GRADE_WORD], g.label);
// every reason grades to a key the UI knows, or to "no grade"
for (const [code, grade] of Object.entries(contract.reasons)) {
  assert.ok(grade === null || (GRADE_KEYS as string[]).includes(grade), `${code} -> ${grade}`);
}
// the reasons the drawer and the "No grade" title rely on exist
for (const code of ["not_applicable", "mosca_missing", "unknown_verdict", "coverage_gap", "source_not_read", "excluded_by_choice"]) {
  assert.ok(code in contract.reasons, code);
}
assert.equal(contract.reasons.not_applicable, null);
// the PQC class the grade reads includes "unknown" (CB-18): the drawer prints any class as the API sends it
assert.ok(contract.pqc_classes.includes("unknown"));

// fix classes: values, order, labels, self-fixable set
assert.equal(contract.agility_model, "fx-1");
assert.deepEqual([...FIX_CLASSES], contract.fix_classes);
assert.deepEqual([...FIX_VALUES], contract.fix_values);
assert.deepEqual([...SELF_FIXABLE], contract.self_fixable);
for (const v of contract.fix_values) {
  assert.ok(isFixValue(v), v);
  assert.equal(FIX_LABEL[v as keyof typeof FIX_LABEL], contract.fix_class_text[v].label, v);
}
// the (i) tips say what the backend says (agility.CLASS_TEXT / INFERRED_TEXT), word for word
for (const v of contract.fix_values) {
  const id = fixClassTipId(v);
  if (v === "none") {
    assert.equal(id, null);
    continue;
  }
  assert.ok(id, v);
  const tip = GRADE_TIPS[id!];
  assert.equal(tip.label, contract.fix_class_text[v].label, v);
  assert.equal(tip.what, contract.fix_class_text[v].what, v);
  assert.equal(tip.example, contract.fix_class_text[v].example, v);
}
assert.equal(GRADE_TIPS["cbom.agility.inferred"].what, contract.fix_inferred_text);
// every tip has text and a `// src:` line above it
const tipsSource = readFileSync(path.join(__dirname, "tips.ts"), "utf8");
for (const [id, tip] of Object.entries(GRADE_TIPS)) {
  assert.ok(tip.label && tip.what && tip.example, id);
  assert.match(tipsSource, new RegExp(`// src: [^\\n]+\\n\\s+"${id.replace(/\./g, "\\.")}"`), `${id}: no // src: line`);
}

// vocabulary (CB-18 / CB-19): no grade key printed alone in this module (the test files included)
for (const file of readdirSync(__dirname).filter((f) => /\.(ts|tsx)$/.test(f))) {
  const src = readFileSync(path.join(__dirname, file), "utf8");
  const bare = [...src.matchAll(/\bQ[0-4]\b(?! (Unknown|Critical|High|Medium|Low|gap))/g)].map((m) => m.index);
  assert.deepEqual(bare, [], `${file}: a grade key without its risk word at ${bare.join(", ")}`);
}

// the model dialog: the served sha256 is the sha256 this browser code computes over the served text
(async () => {
  assert.equal(await sha256Hex(contract.formula_text), contract.formula_sha256);
  assert.match(contract.formula_text, /^ZeroShield quantum risk grade, model qg-1\./);
  console.log("grade/gradeContract.test.ts: ok");
})().catch((e) => { console.error(e); process.exit(1); });
