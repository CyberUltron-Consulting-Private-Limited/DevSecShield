// Run: npx tsx --test components/cbom/population/PopulationReconciliation.test.ts
import assert from "node:assert/strict";
import test from "node:test";

import { populationSteps } from "./PopulationReconciliation";

test("the dashboard renders the served steps as they are (Rule P: no arithmetic in the browser)", () => {
  const block = { title: "Population reconciliation", steps: [
    { key: "run_assets", value: 11, text: "1. Run assets: ... list 11 assets" },
    { key: "dashboard_card", value: 12, text: "3. The dashboard's Crypto Assets card counts 12: the same occurrences." },
    { key: "blank", value: 0, text: "  " },
  ] };
  const steps = populationSteps(block);
  assert.deepEqual(steps?.map((s) => s.key), ["run_assets", "dashboard_card"]);
  assert.equal(steps?.[1].text, block.steps[1].text);
});

test("no block, no panel", () => {
  assert.equal(populationSteps(null), null);
  assert.equal(populationSteps(undefined), null);
  assert.equal(populationSteps({ title: "x", steps: [] }), null);
});
