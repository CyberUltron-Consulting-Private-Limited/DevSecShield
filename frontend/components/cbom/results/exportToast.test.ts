/**
 * #27: one PDF export on the CBOM results page must toast once. Plan §7 (PDF report options): the export dialog
 * (components/reports/ExportPdfDialog.tsx, useExportPdf) is the one owner of an export's toasts. The results page and
 * the options sidebar only open it (each keeps its file name); the report helper never toasts. The scans page uses the
 * app toast (8 s errors, close button), not sonner's defaults.
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
const dialog = readFileSync(join(frontend, "components", "reports", "ExportPdfDialog.tsx"), "utf8");

function helper(): string {
  const start = api.indexOf("async function getReport(");
  assert.ok(start > 0, "getReport exists");
  const end = api.indexOf("// ------", start);
  assert.ok(end > start);
  return api.slice(start, end);
}

test("the results page opens the dialog, which owns the PDF export toasts", () => {
  assert.match(results, /useExportPdf\(\{\n\s*teamId: [^\n]+\n\s*target: \{ family: "scan", type: "cbom", scanId: [^\n]+ \},\n\s*fileName: `cbom-report-\$\{scan_id\}\.pdf`,/);
  assert.match(results, /onClick=\{pdf\.open\}\n\s*disabled=\{pdf\.pending\}/);
  assert.ok(!results.includes("getCBOMExportResults") && !results.includes("exportMutation"), "no export of its own");
  const fn = helper();
  assert.match(fn, /export const downloadScanReport = /);
  assert.equal(fn.match(/\btoast\.\w+\(|showErrorToast\(/g), null, "the report helpers never toast");
  assert.equal(dialog.match(/toast\.success\(/g)?.length, 1, "one success toast, in the dialog");
});

test("the options sidebar opens the same dialog (no toast, no error view of its own)", () => {
  assert.match(sidebar, /target: \{ family: "scan", type: "cbom", scanId: scan_id \},\n\s*fileName: \(\) => `\$\{query\.data\?\.title \?\? "cbom"\}_scan_report\.pdf`,\n\s*successText: "CBOM report downloaded",/);
  assert.ok(!sidebar.includes("getCBOMExportResults"));
  assert.match(sidebar, /onClick=\{pdf\.open\}/);
});

test("the scans page uses the app toast", () => {
  assert.match(page, /import \{ toast \} from "@\/utils\/toast"/);
  assert.ok(!page.includes('from "sonner"'));
});
