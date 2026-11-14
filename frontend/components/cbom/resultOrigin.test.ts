/**
 * Hermetic tests for where a CBOM result came from (CBOM landing page, M1x).
 * Run: npx --yes tsx components/cbom/resultOrigin.test.ts
 */
import assert from "node:assert/strict";
import { originLabel, sourcesRunsHref } from "./resultOrigin";

// every row says where it came from
assert.equal(originLabel({ kind: "sources_run", run_id: 8, source_name: "range-172.17.0.4-32" }),
  "Sources run #8: range-172.17.0.4-32");
assert.equal(originLabel({ kind: "sources_run", run_id: 8 }), "Sources run #8: source");
assert.equal(originLabel({ kind: "code_scan", scan_id: 74, scan_title: "x1 cbom code" }), "Code scan: x1 cbom code");
assert.equal(originLabel(undefined), "Code scan");  // a response from before the field existed
assert.equal(sourcesRunsHref("13"), "/13/cbom/sources?tab=review");

console.log("resultOrigin: all assertions passed");
