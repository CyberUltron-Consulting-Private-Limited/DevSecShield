/**
 * X1 (Nov 11): every scan sidebar's error view had one button, "Try Again", which reloaded the page: the customer lost
 * what was typed (repository URL, token, options, target, login fields) and a failed scan reloaded into the same
 * error. Now a refused estimate or start keeps the form with the reason under the estimate button (as X1's 37d808f for
 * DAST), "Try again" returns to the view that matches the scan without a reload, and a failed scan offers Run again.
 * Run: npx --yes tsx utils/scanErrorRecovery.test.ts
 */
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";

import { stateAfterError } from "./scanErrorRecovery";

assert.equal(stateAfterError("success"), "done");
assert.equal(stateAfterError("pending"), "scanning");
assert.equal(stateAfterError("started"), "scanning");
assert.equal(stateAfterError("not_started"), "ready");
assert.equal(stateAfterError(undefined), "ready");
assert.equal(stateAfterError("cancelled"), "ready");
assert.equal(stateAfterError("cancelled", true), "cancelled");

const dir = path.join(__dirname, "..", "components");
const sidebars = fs.readdirSync(dir).filter((f) => f.endsWith("-options-sidebar.tsx"));
assert.equal(sidebars.length, 10, sidebars.join(","));
const section = (src: string, start: string) => {
  const i = src.indexOf(start);
  return i < 0 ? "" : src.slice(i, src.indexOf("\n  const ", i + start.length));
};
for (const file of sidebars) {
  const src = fs.readFileSync(path.join(dir, file), "utf8");
  assert.ok(!src.includes("location.reload"), `${file}: Try again reloads the page`);
  assert.ok(src.includes("stateAfterError(query.data?.scan_status"), `${file}: Try again returns to the scan's view`);
  const estimate = section(src, "const estimateCreditsMutation = useMutation({");
  if (estimate) {
    assert.ok(!estimate.slice(estimate.indexOf("onError")).includes('setOptionsSidebarState("error")'),
      `${file}: a refused estimate opens the error view`);
    assert.ok(/<ScanRequestError message=\{|data-testid="dast-request-error"/.test(src), `${file}: the refusal is not shown`);
  }
  const start = section(src, "const startScanMutation = useMutation({");
  const startError = start.slice(start.indexOf("onError"));
  if (file !== "discovery-options-sidebar.tsx" && file !== "leakage-options-sidebar.tsx") {
    assert.ok(startError.includes('setOptionsSidebarState("ready")'), `${file}: a refused start does not keep the form`);
    assert.ok(src.includes('scan_status === "failure"') && src.includes("scanFailureMessage(query.data)"),
      `${file}: a failed scan does not say why`);
    assert.ok(/<(Dast|NewScan)?RunAgainButton /.test(src), `${file}: a failed scan has no Run again`);
  }
}
console.log("scan sidebars recover without a reload: tests passed");
