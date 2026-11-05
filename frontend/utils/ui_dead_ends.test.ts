/**
 * L1 (round 5, local stack): two dead ends a customer met in the browser.
 * 1. DAST and SAST: "Estimate credits required" stayed disabled with no reason on the page (DAST needs the
 *    collapsed Authentication section filled; SAST needs a language). Both sidebars now render ScanInputHint with
 *    the validation message under the button.
 * 2. /<team>/leakage: no backend routes exist; the page called GET /leakage/conversations (404) and spun forever.
 *    All three leakage routes now show ProductUnavailableNotice and call no API.
 * Browser: round5/ui/l1/pw/dast.mjs step estimate-disabled-why; explore.mjs on /3/leakage.
 * Run: npx --yes tsx utils/ui_dead_ends.test.ts
 */
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";

const root = path.join(__dirname, "..");
const read = (p: string) => readFileSync(path.join(root, p), "utf8");

for (const sidebar of ["components/dast-options-sidebar.tsx", "components/sast-options-sidebar.tsx"]) {
  const src = read(sidebar);
  const estimate = src.indexOf("<>Estimate credits required</>");
  assert.ok(estimate > 0, `${sidebar}: estimate button`);
  const hint = src.indexOf("<ScanInputHint validation={validateScanInputs()} />", estimate);
  assert.ok(hint > estimate && hint - estimate < 200, `${sidebar}: the reason is rendered right under the button`);
}
const hint = read("components/scan-input-hint.tsx");
assert.match(hint, /if \(validation\.valid\) return null;/);
assert.match(hint, /\{validation\.message\}/);

for (const page of ["app/[team_id]/leakage/page.tsx", "app/[team_id]/leakage/[conversation_id]/page.tsx",
  "app/[team_id]/leakage/[conversation_id]/results/page.tsx"]) {
  const src = read(page);
  assert.match(src, /<ProductUnavailableNotice product="Data leakage" \/>/, page);
  assert.doesNotMatch(src, /backend_api|useQuery|getLeakage/, `${page} calls no API`);
}
console.log("ui dead ends: ok");
