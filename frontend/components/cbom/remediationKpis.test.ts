/**
 * "Critical issues fixed" on the CBOM code-scan results page: fixed Critical findings over ALL Critical findings of the
 * scan (the severity distribution counts fixed ones too), as on the SAST results page. It used to divide by
 * fixed + all Critical, which never passed 50 %, so the (i) tip ("share of all its Critical findings") disagreed.
 * Run: npx --yes tsx components/cbom/remediationKpis.test.ts
 */
import assert from "node:assert/strict";

import { criticalFixedPct } from "./remediationKpis";

assert.equal(criticalFixedPct(0, 0), 0, "no Critical finding: 0 %");
assert.equal(criticalFixedPct(2, 2), 100, "every Critical finding fixed: 100 %, not 50 %");
assert.equal(criticalFixedPct(1, 4), 25, "1 of 4 fixed: 25 %");
assert.equal(criticalFixedPct(2, 3), 67, "rounded to a whole percent");
assert.equal(criticalFixedPct(5, 3), 100, "never above 100 % (counts from two reads that may disagree)");
assert.equal(criticalFixedPct(-1, 3), 0, "never below 0 %");
console.log("remediation KPIs: tests passed");
