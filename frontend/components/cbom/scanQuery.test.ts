/**
 * Staging QA 14 Nov: /{team}/cbom/999999/results showed a spinner for 12 s while the scan query asked four times
 * (404 every time), stacked "Resource not found." toasts, then said "Please try again later" for a scan that does
 * not exist. A 403 or 404 is an answer: not retried, and the page says what it means.
 * Run: npx --yes tsx components/cbom/scanQuery.test.ts
 */
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { isScanGone, scanErrorText } from "./scanQuery";

const err = (status?: number) => (status === undefined ? new Error("network") : { response: { status } });

// 404 and 403: the scan is gone, never retried; everything else (500, 429, network) keeps the app's policy
assert.equal(isScanGone(err(404)), true);
assert.equal(isScanGone(err(403)), true);
for (const other of [err(500), err(429), err(401), err()]) assert.equal(isScanGone(other), false);
assert.equal(isScanGone(null), false);

// what the page says
assert.match(scanErrorText(err(404)), /not found/i);
assert.doesNotMatch(scanErrorText(err(404)), /try again/i);
assert.match(scanErrorText(err(403)), /access/i);
assert.match(scanErrorText(err(500)), /try again/i);
assert.match(scanErrorText(err()), /try again/i);

// both CBOM scan pages use them
const root = join(__dirname, "../..");
for (const page of ["app/[team_id]/cbom/[scan_id]/results/page.tsx", "app/[team_id]/cbom/[scan_id]/page.tsx"]) {
  const src = readFileSync(join(root, page), "utf8");
  assert.ok(src.includes("retry: (failureCount, error) => !isScanGone(error) && queryRetry(failureCount, error),"), `${page}: the scan query still retries a 404`);
  assert.ok(src.includes("scanErrorText(query.error)"), `${page}: the error text ignores the status`);
}
console.log("scanQuery.test.ts: ok");
