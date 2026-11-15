/**
 * CB-38 F3: the browser's status mapping equals the shared contract contracts/cbom/status_buckets.json
 * (also read by a backend pytest), so the table and the server cannot drift.
 * Run: npx --yes tsx components/cbom/results/statusBuckets.test.ts (from any directory)
 */
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { STATUS_BUCKETS, isActiveStatus, isUnifiedStatus, runToUnified } from "./statusBuckets";

// resolved from this file, so the test passes from any working directory
const contract = JSON.parse(readFileSync(join(__dirname, "..", "..", "..", "..", "contracts", "cbom", "status_buckets.json"), "utf8"));

test("statusBuckets.ts equals contracts/cbom/status_buckets.json", () => {
  assert.deepEqual(STATUS_BUCKETS, contract);
});

test("every run status maps to a unified status; partial stays partial", () => {
  for (const [runStatus, unified] of Object.entries(contract.run_to_unified as Record<string, string>)) {
    assert.equal(runToUnified(runStatus), unified);
    assert.equal(isUnifiedStatus(unified), true);
  }
  assert.equal(runToUnified("partial"), "partial");
  assert.equal(runToUnified("running"), "started");
  // a status this build does not know is "not_started", as the backend's unified_run_status answers
  assert.equal(runToUnified("something_new"), "not_started");
  assert.equal(runToUnified(null), "not_started");
  assert.equal(runToUnified(undefined), "not_started");
  assert.equal(isActiveStatus(runToUnified("queued")), true);
  assert.equal(isActiveStatus(runToUnified("running")), true);
  assert.equal(isActiveStatus(runToUnified("done")), false);
});
