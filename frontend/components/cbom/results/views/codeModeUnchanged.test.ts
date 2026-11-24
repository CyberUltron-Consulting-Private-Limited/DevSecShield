/**
 * Owner rule for the results redesign: a code scan (no `?run=1`) renders exactly as before. codeModeSnapshot.html is
 * CbomResults' markup for the code-mode fixture (codeModeFixture.ts), taken on the base commit fbf79f7e before the
 * run-mode views were added; the page must still produce it byte for byte (generated React ids aside). Regenerated
 * deliberately once, for staging QA round 2 on D3 (fix/cbom-d3-qa2): see codeModeSnapshot.test.ts.
 * Run (frontend/): npx --yes tsx@4.23.15 components/cbom/results/views/codeModeUnchanged.test.ts
 */
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { test } from "node:test";

import { renderCodeMode } from "../__tests__/codeModeRender";

test("code mode renders the same markup as on the base commit", () => {
  const want = fs.readFileSync(path.join(__dirname, "..", "__tests__", "codeModeSnapshot.html"), "utf8").trimEnd();
  const got = renderCodeMode();
  assert.equal(renderCodeMode(), got, "the render is deterministic");
  if (got !== want) {
    let i = 0;
    while (i < got.length && got[i] === want[i]) i += 1;
    assert.fail(`code-mode markup changed at ${i}:\n  base: …${want.slice(Math.max(0, i - 120), i + 200)}\n  now:  …${got.slice(Math.max(0, i - 120), i + 200)}`);
  }
  for (const s of ['data-testid="cbom-results-title"', 'data-testid="cbom-scan-header-actions"', 'data-testid="cbom-import-notes"',
    'data-testid="cbom-coverage-notes"', 'id="bom-findings"', "Top cryptographic risks", 'data-testid="code-posture-heading"']) {
    assert.ok(got.includes(s), `the fixture reaches ${s}`);
  }
  assert.ok(!got.includes("run-section-") && !got.includes("results-section-"), "no run-mode section in code mode");
});
