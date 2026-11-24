// Run: npx --yes tsx components/cbom/grade/inputs.test.ts
// CB-19 PR-2: the run page banner, the drawer's "with current inputs" line and the distribution text, from the API's
// fields (posture.inputs_changed / grade_inputs / grade_inputs_now / q_changed_now / q_grades_now, asset.q_now).
import assert from "node:assert/strict";

import { readFileSync } from "node:fs";
import { join } from "node:path";

import { distributionText, gradeNowText, inputsChangedText, inputsSourceText, MOSCA_DEFAULTS, moscaDefaultsText,
  moscaText } from "./inputs";
import { explainRows, GRADE_KEYS, type QExplain } from "./model";

// grade keys by index (this module's contract test allows a key only next to its own risk word)
const [G0, G1, G2, G3, G4] = GRADE_KEYS;

assert.equal(moscaText({ x: 10, y: 5, z: 12 }), "10/5/12");
assert.equal(moscaText({ x: null, y: 5, z: 0 }), "—/5/0"); // 0 is a value, not "unset"
assert.equal(moscaText(null), "—");

const record = { source: "snapshot", mosca: { x: 10, y: 5, z: 12 }, digest: "a" };
const now = { source: "current", mosca: { x: 10, y: 5, z: 20 }, digest: "b" };
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

assert.equal(distributionText({ [G0]: 1, [G1]: 0, [G2]: 3, [G3]: 0, [G4]: 2, none: 4 }),
  "Q0 Unknown 1 · Q1 Critical 0 · Q2 High 3 · Q3 Medium 0 · Q4 Low 2 · no grade 4");
assert.equal(distributionText({ [G2]: 1 }), "Q0 Unknown 0 · Q1 Critical 0 · Q2 High 1 · Q3 Medium 0 · Q4 Low 0");
assert.equal(distributionText(null), "");

assert.equal(gradeNowText(G2, { q_grade: G3, q_label: "Medium", q_reason: "qv_within" }),
  "Recorded at Start: Q2 High · with current inputs: Q3 Medium");
assert.equal(gradeNowText(null, { q_grade: G0, q_label: "Unknown", q_reason: "mosca_missing" }),
  "Recorded at Start: no grade · with current inputs: Q0 Unknown");
assert.equal(gradeNowText(G2, null), null);

assert.equal(inputsSourceText("snapshot"), " (recorded when the run started)");
assert.match(inputsSourceText("current"), /settings now/);
assert.equal(inputsSourceText(undefined), "");

// the drawer's inputs table names the snapshot in words
const explain = { inputs_source: "snapshot", inputs_digest: "d1", model_version: "qg-1+abc" } as unknown as QExplain;
assert.deepEqual(explainRows(explain).find((r) => r.label === "Inputs"),
  { label: "Inputs", value: "Recorded when the run started", basis: "d1" });

console.log("grade inputs tests passed");

// staging QA2 Q1-06: unset Mosca inputs are filled with the documented defaults (never "grade as Unknown")
assert.equal(moscaDefaultsText({ x: 10, y: 5, z: 12 }), null);
assert.equal(moscaDefaultsText({ x: null, y: null, z: null }),
  "Not set: grades use default Mosca assumptions (X 7 years, 10 for a high or critical source; Y 5 years; Z the years " +
  "left until 2035)");
assert.match(moscaDefaultsText({ x: null, y: 5, z: 0 })!, /^X not set: grades use default Mosca assumptions/);
assert.ok(!/Unknown/.test(moscaDefaultsText(null)!));
const qgrade = readFileSync(join(__dirname, "../../../../backend/utilities/cbom_sources/qgrade.py"), "utf8");
const pin = (name: string) => Number(new RegExp(`^${name} = (\\d+)`, "m").exec(qgrade)?.[1]);
assert.deepEqual({ x: pin("DEFAULT_X"), xCritical: pin("DEFAULT_X_CRITICAL"), y: pin("DEFAULT_Y"), zYear: pin("DEFAULT_Z_YEAR") },
  { ...MOSCA_DEFAULTS }, "the card's defaults are qgrade's");
const card = readFileSync(join(__dirname, "../sources/GradeInputsCard.tsx"), "utf8");
assert.ok(card.includes("moscaDefaultsText(mosca)") && !card.includes("grade as Unknown"), "the card says defaults are used");

