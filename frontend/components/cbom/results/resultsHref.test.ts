/**
 * Where a row of the CBOM Scans table opens, and how `[scan_id]` tells a legacy run prefix from a number.
 * Run: npx --yes tsx components/cbom/results/resultsHref.test.ts
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { asksForRun, legacyRunResultsTarget, parseCbomResultsId, resultsHref, runResultsHref } from "./resultsHref";

test("a run opens the one results template at every status", () => {
  for (const s of ["not_started", "pending", "started", "success", "partial", "failure", "cancelled", undefined]) {
    assert.equal(resultsHref("t", { kind: "run", id: 5, scan_status: s }), "/t/cbom/5/results?run=1");
  }
  assert.equal(resultsHref(13, { kind: "run", id: 8 }), "/13/cbom/8/results?run=1");
  assert.equal(runResultsHref("13", 8), "/13/cbom/8/results?run=1");
  assert.equal(runResultsHref(13, 8, "view=all"), "/13/cbom/8/results?view=all&run=1");
  assert.equal(runResultsHref(13, 8, "?view=all&run=1"), "/13/cbom/8/results?view=all&run=1");
});

test("a scan opens results only once it succeeded, with no run query", () => {
  assert.equal(resultsHref("t", { kind: "scan", id: 5, scan_status: "success" }), "/t/cbom/5/results");
  assert.equal(resultsHref("t", { kind: "scan", id: 5, scan_status: "SUCCESS" }), "/t/cbom/5/results");
  for (const s of ["not_started", "pending", "started", "retry", "failure", "cancelled", null]) {
    assert.equal(resultsHref("t", { kind: "scan", id: 5, scan_status: s }), "/t/cbom/5");
  }
});

test("scan #5 and run #5 do not share a URL: the run asks with ?run=1", () => {
  const scan = resultsHref("t", { kind: "scan", id: 5, scan_status: "success" });
  const run = resultsHref("t", { kind: "run", id: 5, scan_status: "success" });
  assert.equal(scan, "/t/cbom/5/results");
  assert.equal(run, "/t/cbom/5/results?run=1");
  assert.equal(asksForRun(""), false);
  assert.equal(asksForRun(scan.split("?")[1] ?? ""), false);
  assert.equal(asksForRun(run.split("?")[1] ?? ""), true);
  assert.equal(asksForRun("?run=1"), true);
  assert.equal(asksForRun("run=2"), false);
});

test("the [scan_id] segment: run-<n> is a legacy prefix, a plain number a code scan, anything else not found", () => {
  assert.deepEqual(parseCbomResultsId("run-12"), { kind: "run", id: 12 });
  assert.deepEqual(parseCbomResultsId("12"), { kind: "scan", id: 12 });
  assert.deepEqual(parseCbomResultsId("1"), { kind: "scan", id: 1 });
  for (const bad of ["run-0", "run-abc", "run-12x", "run-", "run-012", "runs-12", "RUN-12", "run--12", " run-12", "0", "012",
    "12x", "-12", "1.5", "abc", "", undefined, null, 12, ["run-12"]]) {
    assert.equal(parseCbomResultsId(bad), null, `${JSON.stringify(bad)} is not found`);
  }
});

test("a run link's path is the numeric results path, and the legacy addresses redirect there", () => {
  for (const id of [1, 5, 12, 98765]) {
    const href = runResultsHref(7, id);
    assert.equal(href.split("?")[0], `/7/cbom/${id}/results`);
    assert.equal(asksForRun(href.split("?")[1] ?? ""), true);
    const scanSeg = resultsHref(7, { kind: "scan", id, scan_status: "success" }).split("/")[3];
    assert.deepEqual(parseCbomResultsId(scanSeg), { kind: "scan", id });
  }
  assert.equal(legacyRunResultsTarget("1", "2", ""), "/1/cbom/2/results?run=1");
  assert.equal(legacyRunResultsTarget("1", "2", "?view=all"), "/1/cbom/2/results?view=all&run=1");
  assert.equal(legacyRunResultsTarget("1", "012", "view=findings"), "/1/cbom/12/results?view=findings&run=1");
  for (const bad of ["0", "x", "", undefined]) {
    assert.equal(legacyRunResultsTarget("1", bad, ""), null);
    assert.equal(legacyRunResultsTarget(bad, "2", ""), null);
  }
});
