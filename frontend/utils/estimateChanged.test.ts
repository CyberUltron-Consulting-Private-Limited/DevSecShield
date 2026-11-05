/**
 * Hermetic tests for the "price changed at start" answer.
 * Run: npx --yes tsx utils/estimateChanged.test.ts
 */
import assert from "node:assert/strict";
import { estimateChangedOf } from "./estimateChanged";

const detail = "The price of this scan changed from 12.5 to 3 credits: the files, options or pricing changed since it was estimated. Nothing was charged. Review the new price and start the scan again.";

// the backend's 409 body (backend/routers/scans.py start_scan)
assert.deepEqual(
  estimateChangedOf({ response: { status: 409, data: { detail, code: "estimate_changed", credits_required: 3, previous_credits: 12.5, minimum_credits: 1 } } }),
  { detail, credits_required: 3, previous_credits: 12.5, minimum_credits: 1 },
);
// a scan that was never estimated has no previous price
assert.equal(
  estimateChangedOf({ response: { status: 409, data: { detail, code: "estimate_changed", credits_required: 1, previous_credits: null } } })?.previous_credits,
  null,
);
// any other error is not a price change
assert.equal(estimateChangedOf({ response: { status: 400, data: { detail: "Team does not have enough credits" } } }), null);
assert.equal(estimateChangedOf({ response: { status: 409, data: { detail: "Scan has already started" } } }), null);
assert.equal(estimateChangedOf({ response: { status: 409, data: { code: "estimate_changed" } } }), null);
assert.equal(estimateChangedOf(new Error("network")), null);
assert.equal(estimateChangedOf(null), null);

console.log("estimateChanged tests passed");
