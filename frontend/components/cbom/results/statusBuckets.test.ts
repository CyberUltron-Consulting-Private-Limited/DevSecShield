/**
 * CB-38 F3: the browser's status mapping equals the shared contract contracts/cbom/status_buckets.json
 * (also read by a backend pytest), so the table and the server cannot drift.
 * Run from frontend/: npx --yes tsx components/cbom/results/statusBuckets.test.ts
 */
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { STATUS_BUCKETS, isActiveStatus, isUnifiedStatus, runToUnified } from "./statusBuckets";

const contract = JSON.parse(readFileSync(join(process.cwd(), "..", "contracts", "cbom", "status_buckets.json"), "utf8"));

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
  assert.equal(runToUnified("something_new"), "something_new");
  assert.equal(runToUnified(null), "not_started");
  assert.equal(isActiveStatus(runToUnified("queued")), true);
  assert.equal(isActiveStatus(runToUnified("running")), true);
  assert.equal(isActiveStatus(runToUnified("done")), false);
});
