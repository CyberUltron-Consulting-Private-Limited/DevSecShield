/**
 * X1 M2 (Nov 11): a failed DAST scan said only "An error occurred during the scan" although the worker's reason is in
 * scan.info.error, its only button "Try Again" reloaded into the same error, and DAST had no "Run again". Now the
 * reason is shown (scanFailureMessage, as the five code-scan sidebars), "Run again" creates a new DAST scan prefilled
 * from the failed one (never a password: the customer types it again), and "Try again" no longer reloads the page.
 * Browser check after a rebuild: a failed DAST scan shows "The scan failed: <reason>." and "Run again" opens a new
 * scan with target, login URL, XPaths, user name and options filled in and the password empty.
 * Run: npx --yes tsx utils/dastRerun.test.ts
 */
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";

import { DAST_RERUN_NOTE, dastRerunPrefill, readDastRerun, saveDastRerun } from "./dastRerun";
import { scanFailureMessage } from "./scanFailure";

// what GET /{team}/dast/scan/{id} returns for a failed scan (backend utilities/dashboard/scan_metadata.py, dast)
const failed = {
  title: "shop", scan_status: "failure", info: { error: "Target answered 503 Service Unavailable" },
  scan_metadata: {
    target_url: "https://shop.example", scan_speed: "slow", max_urls: 250,
    additional_urls_to_scan: ["https://shop.example/admin"], include_url_patterns: null, exclude_url_patterns: ["/logout"],
    auth: { login_url: "https://shop.example/login", xpath_of_username_field: "//input[@name='u']",
      xpath_of_password_field: "//input[@name='p']", username: "alice", xpath_of_submit_button: "//button" },
  },
};
assert.deepEqual(dastRerunPrefill(failed), {
  target_url: "https://shop.example", scan_speed: "slow", max_urls: 250, additional_urls: ["https://shop.example/admin"],
  pattern_mode: "exclude", patterns: ["/logout"], login_url: "https://shop.example/login",
  xpath_username: "//input[@name='u']", xpath_password: "//input[@name='p']", username: "alice", xpath_submit: "//button",
});
assert.equal(dastRerunPrefill({ scan_metadata: null }), null, "a scan that never started has nothing to copy");
assert.equal(dastRerunPrefill({ scan_metadata: { target_url: "" } }), null);
assert.match(DAST_RERUN_NOTE, /password again/);

// a password in the response (it must never be there) is not copied anywhere
const leaky = { scan_metadata: { ...failed.scan_metadata, auth: { ...failed.scan_metadata.auth, password: "Canary-pw" } } };
assert.ok(!JSON.stringify(dastRerunPrefill(leaky)).includes("Canary-pw"));

// sessionStorage round trip (this tab only)
const store = new Map<string, string>();
(globalThis as { sessionStorage?: unknown }).sessionStorage = {
  getItem: (k: string) => store.get(k) ?? null, setItem: (k: string, v: string) => void store.set(k, v),
  removeItem: (k: string) => void store.delete(k),
};
saveDastRerun(77, dastRerunPrefill(failed)!);
assert.equal(readDastRerun(77)?.login_url, "https://shop.example/login");
assert.equal(readDastRerun(78), null);

// the reason is the worker's, not the generic text
assert.equal(scanFailureMessage(failed),
  "The scan failed: Target answered 503 Service Unavailable. Use Run again to start it as a new scan with the same settings.");

// the sidebar uses it, offers Run again on a failed scan, and never reloads the page
const src = fs.readFileSync(path.join(__dirname, "..", "components", "dast-options-sidebar.tsx"), "utf8");
assert.ok(src.includes("scanFailureMessage(query.data)"), "the failure reason is shown");
assert.ok(src.includes("<DastRunAgainButton teamId={team_id} scan={query.data} />"), "a failed DAST scan has Run again");
assert.ok(!src.includes("location.reload"), "Try again does not reload the page");
assert.ok(src.includes("readDastRerun(scan_id)"), "the new scan is prefilled");
assert.ok(!/setAuthPassword\(p\./.test(src), "the password is never prefilled");

console.log("dast run again: tests passed");
