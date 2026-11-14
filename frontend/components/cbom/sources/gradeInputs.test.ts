// Run: npx --yes tsx components/cbom/sources/gradeInputs.test.ts
// CB-19 PR-2: the run page banner, the drawer's "with current inputs" line and the distribution text, from the API's
// fields (posture.inputs_changed / grade_inputs / grade_inputs_now / q_changed_now / q_grades_now, asset.q_now).
import assert from "node:assert/strict";

import { distributionText, gradeNowText, gradeText, inputsChangedText, moscaText } from "./gradeInputs";

// grade words always printed with the code
assert.equal(gradeText("Q0"), "Q0 Unknown");
assert.equal(gradeText("Q1"), "Q1 Critical");
assert.equal(gradeText("Q4"), "Q4 Low");
assert.equal(gradeText(null), "No grade");
assert.equal(gradeText("none"), "No grade");
assert.equal(gradeText("Q9"), "Q9");

assert.equal(moscaText({ x: 10, y: 5, z: 12 }), "10/5/12");
assert.equal(moscaText({ x: null, y: 5, z: 0 }), "—/5/0"); // 0 is a value, not "unset"
assert.equal(moscaText(null), "—");

const record = { source: "snapshot" as const, mosca: { x: 10, y: 5, z: 12 }, digest: "a" };
const now = { source: "current" as const, mosca: { x: 10, y: 5, z: 20 }, digest: "b" };
assert.equal(
  inputsChangedText({ inputs_changed: true, grade_inputs: record, grade_inputs_now: now, q_changed_now: 1 }),
  "Inputs changed since this run started: Mosca 10/5/12 → 10/5/20 (X/Y/Z years); 1 asset grades differently now",
);
assert.match(inputsChangedText({ inputs_changed: true, grade_inputs: record, grade_inputs_now: now, q_changed_now: 0 })!,
  /0 assets grade differently now$/);
// no banner: inputs equal, a run from before the snapshot, an older backend without the fields
assert.equal(inputsChangedText({ inputs_changed: false, grade_inputs: record, grade_inputs_now: null }), null);
assert.equal(inputsChangedText({ grade_inputs: { ...record, source: "current" } }), null);
assert.equal(inputsChangedText({}), null);

assert.equal(distributionText({ Q0: 1, Q1: 0, Q2: 3, Q3: 0, Q4: 2, none: 4 }),
  "Q0 Unknown 1 · Q1 Critical 0 · Q2 High 3 · Q3 Medium 0 · Q4 Low 2 · no grade 4");
assert.equal(distributionText({ Q2: 1 }), "Q0 Unknown 0 · Q1 Critical 0 · Q2 High 1 · Q3 Medium 0 · Q4 Low 0");
assert.equal(distributionText(null), "");

assert.equal(gradeNowText("Q2", { q_grade: "Q3", q_label: "Medium", q_reason: "qv_within" }),
  "Recorded at Start: Q2 High · with current inputs: Q3 Medium");
assert.equal(gradeNowText("Q2", null), null);

console.log("grade inputs tests passed");
