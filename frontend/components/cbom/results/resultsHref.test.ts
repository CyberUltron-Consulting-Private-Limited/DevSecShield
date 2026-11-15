/**
 * CB-38 F2: where a row of the CBOM Scans table opens, and how the `[scan_id]` segment tells a run from a scan.
 * Run: npx --yes tsx components/cbom/results/resultsHref.test.ts
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { parseCbomResultsId, resultsHref, runResultsHref } from "./resultsHref";

test("a run opens its results page at every status", () => {
  for (const s of ["not_started", "pending", "started", "success", "partial", "failure", "cancelled", undefined]) {
    assert.equal(resultsHref("t", { kind: "run", id: 5, scan_status: s }), "/t/cbom/run-5/results");
  }
  assert.equal(resultsHref(13, { kind: "run", id: 8 }), "/13/cbom/run-8/results");
  assert.equal(runResultsHref("13", 8), "/13/cbom/run-8/results");
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

test("the [scan_id] segment: run-<n> is a run, a plain number a code scan, anything else not found", () => {
  assert.deepEqual(parseCbomResultsId("run-12"), { kind: "run", id: 12 });
  assert.deepEqual(parseCbomResultsId("12"), { kind: "scan", id: 12 });
  assert.deepEqual(parseCbomResultsId("1"), { kind: "scan", id: 1 });
  for (const bad of ["run-0", "run-abc", "run-12x", "run-", "run-012", "runs-12", "RUN-12", "run--12", " run-12", "0", "012",
    "12x", "-12", "1.5", "abc", "", undefined, null, 12, ["run-12"]]) {
    assert.equal(parseCbomResultsId(bad), null, `${JSON.stringify(bad)} is not found`);
  }
});

test("every generated run link parses back to the same run, every scan link to the same scan", () => {
  for (const id of [1, 5, 12, 98765]) {
    const runSeg = runResultsHref(7, id).split("/")[3];
    assert.deepEqual(parseCbomResultsId(runSeg), { kind: "run", id });
    const scanSeg = resultsHref(7, { kind: "scan", id, scan_status: "success" }).split("/")[3];
    assert.deepEqual(parseCbomResultsId(scanSeg), { kind: "scan", id });
  }
});
