/**
 * L1 (round 5, local stack): two dead ends a customer met in the browser.
 * 1. DAST and SAST: "Estimate credits required" stayed disabled with no reason on the page (DAST needs the
 *    collapsed Authentication section filled; SAST needs a language). Both sidebars now render ScanInputHint with
 *    the validation message under the button.
 * 2. /<team>/leakage: no backend routes exist; the page called GET /leakage/conversations (404) and spun forever.
 *    All three leakage routes now show ProductUnavailableNotice and call no API.
 * Browser: round5/ui/l1/pw/dast.mjs step estimate-disabled-why; explore.mjs on /3/leakage.
 * 3. #29: the agent discovery and data leakage scan sidebars were imported nowhere, and the API helpers only they used
 *    posted to routes the backend does not have. Both sidebars and those helpers are gone.
 * Run: npx --yes tsx utils/ui_dead_ends.test.ts
 */
import assert from "node:assert/strict";
import { existsSync, readdirSync, readFileSync } from "node:fs";
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

for (const sidebar of ["components/discovery-options-sidebar.tsx", "components/leakage-options-sidebar.tsx"]) {
  assert.ok(!existsSync(path.join(root, sidebar)), `${sidebar}: an unused sidebar for a product without backend routes`);
}
const api = read("utils/backend_api.ts");
for (const helper of ["startDiscoveryScan", "reinitializeDiscoveryScan", "getDiscoveryExportResults",
  "startLeakageScan", "reinitializeLeakageScan", "getLeakageExportResults"]) {
  assert.doesNotMatch(api, new RegExp(String.raw`\b${helper}\b`), `utils/backend_api.ts: ${helper} is still there`);
}
// ... and the backend still has none of their routes (if one comes back, so may a sidebar)
const routers = path.join(root, "..", "backend", "routers");
for (const file of readdirSync(routers).filter((f) => f.endsWith(".py"))) {
  assert.doesNotMatch(readFileSync(path.join(routers, file), "utf8"), /\/(agent_discovery|leakage)\/conversation/,
    `backend/routers/${file}: a discovery or leakage route`);
}
console.log("ui dead ends: ok");
