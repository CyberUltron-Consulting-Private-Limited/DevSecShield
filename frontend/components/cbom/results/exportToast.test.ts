/**
 * #27: one PDF export on the CBOM results page must toast once. The helper also toasts, so the page opts out
 * and keeps its own success and error toasts. The options sidebar does not toast, so it keeps the helper's.
 * The scans page uses the app toast (8 s errors, close button), not sonner's defaults.
 * Run: node --experimental-strip-types --test components/cbom/results/exportToast.test.ts
 */
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const frontend = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const results = readFileSync(join(frontend, "components", "CbomResults.tsx"), "utf8");
const api = readFileSync(join(frontend, "utils", "backend_api.ts"), "utf8");
const sidebar = readFileSync(join(frontend, "components", "cbom-options-sidebar.tsx"), "utf8");
const page = readFileSync(join(frontend, "app", "[team_id]", "cbom", "page.tsx"), "utf8");

function helper(): string {
  const start = api.indexOf("const getCBOMExportResults");
  assert.ok(start > 0, "getCBOMExportResults exists");
  const end = api.indexOf("const postCertInAttestation", start);
  assert.ok(end > start);
  return api.slice(start, end);
}

test("the results page owns the PDF export toasts", () => {
  assert.match(results, /getCBOMExportResults\(tid, sid, \{ toast: false \}\)/);
  const fn = helper();
  assert.match(fn, /opts: \{ toast\?: boolean \}/);
  assert.equal(fn.match(/opts\.toast !== false/g)?.length, 2, "success and error both respect the opt-out");
});

test("the options sidebar keeps the helper toast", () => {
  assert.match(sidebar, /getCBOMExportResults\(team_id, scan_id\)/);
  assert.ok(!sidebar.includes("getCBOMExportResults(team_id, scan_id, { toast: false })"));
});

test("the scans page uses the app toast", () => {
  assert.match(page, /import \{ toast \} from "@\/utils\/toast"/);
  assert.ok(!page.includes('from "sonner"'));
});
