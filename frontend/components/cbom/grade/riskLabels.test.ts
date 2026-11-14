/**
 * Staging QA 14 Nov (build 5f7a817), CBOM -> Dashboard -> agility baseline and CBOM -> Quantum risk -> Q0 gaps:
 * - lab-hsm-token-b (2 Unknown, 1 None; the API's hardest is null because Unknown is not a class) showed the "None"
 *   chip "No finding code: nothing to change today" although two of its assets could not be classed;
 * - the Mosca gap's item read "inputs:mosca" (the raw item key);
 * - the evidence group was headed "Evidence e0".
 * Run: npx --yes tsx components/cbom/grade/riskLabels.test.ts
 */
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { GRADE_KEYS, gradeText, heatCellLabel, q0GapTitle, q0ReasonHeading, systemHardestClass } from "./model";

const counts = (o: Record<string, number>) => ({ configurable: 0, "code-fixed": 0, "vendor-fixed": 0, "hardware-fixed": 0, unknown: 0, none: 0, ...o });
// a system whose only non-None assets are Unknown: Unknown, not "nothing to change"
assert.equal(systemHardestClass({ hardest: null, counts: counts({ unknown: 2, none: 1 }) }), "unknown");
assert.equal(systemHardestClass({ hardest: null, counts: counts({ none: 3 }) }), "none");
assert.equal(systemHardestClass({ hardest: "vendor-fixed", counts: counts({ "vendor-fixed": 2, unknown: 4 }) }), "vendor-fixed");
assert.equal(systemHardestClass({ hardest: null, counts: {} }), "none");

// the Mosca inputs gap reads as words with its count, never the raw key
assert.equal(q0GapTitle({ item_kind: "inputs", item_key: "inputs:mosca", title: "inputs:mosca", detail: { count: 80 } }),
  "Mosca X, Y or Z not set (80 quantum-vulnerable assets left ungraded)");
assert.equal(q0GapTitle({ item_kind: "inputs", item_key: "inputs:mosca", title: "inputs:mosca", detail: { count: 1 } }),
  "Mosca X, Y or Z not set (1 quantum-vulnerable asset left ungraded)");
assert.equal(q0GapTitle({ item_kind: "inputs", item_key: "inputs:mosca", title: "inputs:mosca", detail: null }),
  "Mosca X, Y or Z not set");
// every other gap keeps the server's title
assert.equal(q0GapTitle({ item_kind: "asset", item_key: "asset:obs:1", title: "ssh_host_rsa_key · 10.232.0.10", detail: {} }),
  "ssh_host_rsa_key · 10.232.0.10");

// group headings
assert.equal(q0ReasonHeading("evidence_e0"), "Evidence at E0");
assert.equal(q0ReasonHeading("mosca_missing"), "Mosca inputs missing");
assert.equal(q0ReasonHeading("unknown_verdict"), "PQC class unknown");
assert.equal(q0ReasonHeading("coverage_gap"), "Scope not read");
assert.equal(q0ReasonHeading("something_new"), "Something new");

// the components use them
const here = (f: string) => readFileSync(join(__dirname, f), "utf8");
assert.ok(here("AgilityBaseline.tsx").includes("<FixClassChip item={{ fix_class: systemHardestClass(s) }} />"));
assert.ok(here("Q0Gaps.tsx").includes("{q0GapTitle(gap)}"));
assert.ok(here("Q0Gaps.tsx").includes("{q0ReasonHeading(group.reason)}"));
console.log("riskLabels.test.ts: ok");

// Staging QA 14 Nov (b2e86fa), Quantum risk -> family x source heat-map: 17 of 45 cells held only assets with no grade
// (libraries, DES, "Other": counts {none: n}) and were labelled as Unknown-only cells in the Unknown colour, so
// libraries read as gaps. A cell with no known grade carries the Unknown label only when it holds Unknown assets,
// else "No grade".
{
  const [U, , , , LOW] = GRADE_KEYS;
  const unknownOnly = `${gradeText(U)} only`;
  assert.deepEqual(heatCellLabel({ worst: null, q0: 0, counts: { none: 11 } }), { text: "No grade", grade: null });
  assert.deepEqual(heatCellLabel({ worst: null, q0: 2, counts: { [U]: 2 } }), { text: unknownOnly, grade: U });
  assert.deepEqual(heatCellLabel({ worst: null, q0: 5, counts: { [U]: 5, none: 1 } }), { text: unknownOnly, grade: U });
  assert.deepEqual(heatCellLabel({ worst: null, q0: null, counts: { [U]: 1 } }), { text: unknownOnly, grade: U });
  assert.deepEqual(heatCellLabel({ worst: LOW, q0: 0, counts: { [LOW]: 5 } }), { text: gradeText(LOW), grade: LOW });
  assert.ok(here("RiskRegister.tsx").includes("const label = heatCellLabel(cell);"), "the heat-map does not use heatCellLabel");
  console.log("riskLabels.test.ts: heat-map labels ok");
}
