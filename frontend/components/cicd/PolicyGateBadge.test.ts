/**
 * CB-30: the "Policy gate" column of the CI/CD logs shows what the pipeline was told. A pipeline is blocked for
 * verdict "fail" and for "no_result" (POST /cicd/cbom/scan answers gate_failed: true for both); only "pass" passes; a log
 * made before the gate has none. Rendered with react-dom/server, as the page renders the cell.
 * Run (frontend/): npx --yes tsx@4.23.15 components/cicd/PolicyGateBadge.test.ts
 */
import assert from "node:assert/strict";
import React from "react";
import { renderToStaticMarkup } from "react-dom/server";

import { PolicyGateBadge, policyGateView } from "./PolicyGateBadge";

const gate = (verdict: string, failing_count: number, reason: string) => ({
  policy: "cbom-code-high", verdict, fail_codes: ["WEAK_ALGORITHM"], failing_count, failing: [], truncated: false, reason,
}) as Parameters<typeof policyGateView>[0];

const text = (html: string) => html.replace(/<[^>]+>/g, "").replace(/&#x27;/g, "'").trim();
const render = (g: Parameters<typeof policyGateView>[0]) => renderToStaticMarkup(React.createElement(PolicyGateBadge, { gate: g }));

// pass: the only green state
const pass = render(gate("pass", 0, "No high crypto finding."));
assert.equal(text(pass), "Passed");
assert.match(pass, /title="No high crypto finding\."/);
assert.equal(policyGateView(gate("pass", 0, "")).blocked, false);

// fail: blocked, with the number of failing findings
const fail = render(gate("fail", 3, "3 high crypto finding(s): WEAK_ALGORITHM."));
assert.equal(text(fail), "Blocked (3)");
assert.match(fail, /title="3 high crypto finding\(s\): WEAK_ALGORITHM\."/);
assert.equal(policyGateView(gate("fail", 3, "")).blocked, true);

// no_result: the pipeline was told gate_failed true and its job failed, so the page says blocked too
const none = render(gate("no_result", 0, "No CBOM result arrived within the time limit."));
assert.equal(text(none), "Blocked: no result");
assert.match(none, /title="No CBOM result arrived within the time limit\."/);
assert.equal(policyGateView(gate("no_result", 0, "")).blocked, true);
// an unknown future verdict is not a pass either (gate_failed is "verdict != pass")
assert.equal(policyGateView(gate("something_new", 0, "")).blocked, true);

// a log made before the gate: no verdict was given to that pipeline
assert.equal(text(render(null)), "—");
assert.equal(text(render(undefined)), "—");
assert.equal(policyGateView(null).blocked, null);

// blocked states share the red style, pass is green
assert.match(fail, /bg-red-600/);
assert.match(none, /bg-red-600/);
assert.match(pass, /bg-green-500/);

console.log("ok policy gate badge: pass, fail, no_result, none");
