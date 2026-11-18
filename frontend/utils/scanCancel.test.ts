/**
 * Cancelling a code scan (C1): the sidebar state for each status, when "Cancel scan" is offered, the confirmation
 * that states the refund, the "Cancelled — N credits refunded" panel, and a second cancel (409 already_cancelled)
 * that is not an error. The five sidebars and the five scan lists are checked for the wiring.
 * Run: npx --yes tsx utils/scanCancel.test.ts
 */
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";

import {
  canCancel,
  cancelConfirmText,
  cancelledSummary,
  chargedCredits,
  formatCredits,
  isAlreadyCancelled,
  sidebarStateFor,
} from "./scanCancel";

// sidebar state for every status GET /{team}/{type}/scan/{id} returns
assert.equal(sidebarStateFor("pending"), "scanning");
assert.equal(sidebarStateFor("started"), "scanning");
assert.equal(sidebarStateFor("retry"), "scanning");
assert.equal(sidebarStateFor("success"), "done");
assert.equal(sidebarStateFor("failure"), "error");
assert.equal(sidebarStateFor("cancelled"), "cancelled");
assert.equal(sidebarStateFor("unknown"), "ready");
assert.equal(sidebarStateFor("NOT_STARTED"), null);
assert.equal(sidebarStateFor(undefined), null);

// "Cancel scan" only while waiting for a worker or running
for (const s of ["pending", "started", "retry"]) assert.equal(canCancel(s), true, s);
for (const s of ["success", "failure", "cancelled", "NOT_STARTED", "not_started", undefined, null]) assert.equal(canCancel(s), false, String(s));

// the confirmation states the refund
assert.equal(chargedCredits({ credit_charged: 2.5 }), 2.5);
assert.equal(chargedCredits({ credit_charged: null }), null);
assert.equal(chargedCredits(null), null);
assert.equal(cancelConfirmText({ credit_charged: 2.5 }),
  "The scan stops and no results are kept. The 2.5 credits it was charged are refunded in full.");
assert.equal(cancelConfirmText({ credit_charged: 1 }),
  "The scan stops and no results are kept. The 1 credit it was charged is refunded in full.");
assert.equal(cancelConfirmText({}),
  "The scan stops and no results are kept. The credits it was charged are refunded in full.");
assert.equal(formatCredits(0.004), "0 credits");
assert.equal(formatCredits(1.006), "1.01 credits");

// the cancelled panel, from the info the server stored (also as a JSON string)
assert.equal(cancelledSummary({ scan_status: "cancelled", info: { cancelled: true, refunded_credits: 3.5 } }),
  "Cancelled — 3.5 credits refunded");
assert.equal(cancelledSummary({ info: JSON.stringify({ refunded_credits: 1 }) }), "Cancelled — 1 credit refunded");
assert.equal(cancelledSummary({ info: null }), "Cancelled — the scan's credits were refunded");

// a second click / another tab: 409 already_cancelled is not an error; other 409s are
assert.equal(isAlreadyCancelled({ response: { status: 409, data: { code: "already_cancelled", detail: "x" } } }), true);
assert.equal(isAlreadyCancelled({ response: { status: 409, data: { code: "already_completed" } } }), false);
assert.equal(isAlreadyCancelled({ response: { status: 500, data: { code: "already_cancelled" } } }), false);
assert.equal(isAlreadyCancelled(new Error("network")), false);

// wiring: each sidebar offers Cancel scan while scanning and the cancelled panel with Run again
const root = path.resolve(__dirname, "..");
const sidebars: Record<string, string> = {
  sast: "sast-options-sidebar.tsx", iac: "iac-options-sidebar.tsx", sbom_sca: "sca-sbom-options-sidebar.tsx",
  cbom: "cbom-options-sidebar.tsx", ai_bom: "ai-bom-options-sidebar.tsx",
};
for (const [type, file] of Object.entries(sidebars)) {
  const src = fs.readFileSync(path.join(root, "components", file), "utf8");
  const scanning = src.slice(src.indexOf('optionsSidebarState === "scanning"'), src.indexOf('optionsSidebarState === "done"'));
  assert.match(scanning, new RegExp(`<CancelScanButton type="${type}"`), file);
  assert.match(src, new RegExp(`optionsSidebarState === "cancelled" && \\(\\s*<CancelledScanPanel type="${type}"`), file);
  assert.match(src, /scan_status === "cancelled"\) \{\s*setOptionsSidebarState\("cancelled"\)/, file);
}
const panel = fs.readFileSync(path.join(root, "components", "scan-cancel.tsx"), "utf8");
assert.match(panel, /<RunAgainButton type=\{type\}/);
assert.match(panel, /<DialogDescription>\{cancelConfirmText\(scan\)\}<\/DialogDescription>/);

// the scan lists show the status (a missing badge entry crashed the list) and can filter by it
for (const type of ["sast", "iac", "sbom_sca", "cbom", "ai_bom"]) {
  const src = fs.readFileSync(path.join(root, "app", "[team_id]", type, "page.tsx"), "utf8");
  if (type === "cbom") {
    // CBOM keeps one badge table for scans and Sources runs (CB-38): variant and label in the same entry
    assert.match(src, /cancelled: \{ variant: "outline", className: "[^"]*", label: "Cancelled" \}/, type);
  } else {
    assert.match(src, /cancelled: \{ variant: "outline" as const/, type);
    assert.match(src, /cancelled: "Cancelled" \}/, type);
  }
  assert.match(src, /<SelectItem value="cancelled">Cancelled<\/SelectItem>/, type);
}

console.log("scanCancel: all assertions passed");
