/**
 * CB-38 F2: where a row of the CBOM Scans table opens.
 * Run: npx --yes tsx components/cbom/results/resultsHref.test.ts
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { resultsHref, runResultsHref } from "./resultsHref";

test("a run opens its results page at every status", () => {
  for (const s of ["not_started", "pending", "started", "success", "partial", "failure", "cancelled", undefined]) {
    assert.equal(resultsHref("t", { kind: "run", id: 5, scan_status: s }), "/t/cbom/runs/5/results");
  }
  assert.equal(resultsHref(13, { kind: "run", id: 8 }), "/13/cbom/runs/8/results");
  assert.equal(runResultsHref("13", 8), "/13/cbom/runs/8/results");
});

test("a scan opens results only once it succeeded", () => {
  assert.equal(resultsHref("t", { kind: "scan", id: 5, scan_status: "success" }), "/t/cbom/5/results");
  assert.equal(resultsHref("t", { kind: "scan", id: 5, scan_status: "SUCCESS" }), "/t/cbom/5/results");
  for (const s of ["not_started", "pending", "started", "retry", "failure", "cancelled", null]) {
    assert.equal(resultsHref("t", { kind: "scan", id: 5, scan_status: s }), "/t/cbom/5");
  }
});

test("scan #5 and run #5 never share a URL", () => {
  assert.notEqual(
    resultsHref("t", { kind: "scan", id: 5, scan_status: "success" }),
    resultsHref("t", { kind: "run", id: 5, scan_status: "success" }),
  );
});
