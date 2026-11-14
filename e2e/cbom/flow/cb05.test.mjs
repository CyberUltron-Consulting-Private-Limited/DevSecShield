// node --test e2e/cbom/flow/cb05.test.mjs : the CB-05 helpers that decide verdicts without a browser.
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { accepts, AWS_NOT_CONFIGURED_TEXT, g10Charge, g11uRuleP, g9Skipped, isResultsPage, openRunResults, RATES_C, readRunRows, RUNTIME_SKIPS,
  VEX_FUTURE_RISK } from "./cb05.mjs";
import { plannedCharge } from "./rates.mjs";

function lab(dir, lines) {
  mkdirSync(join(dir, "lab", "listeners"), { recursive: true });
  writeFileSync(join(dir, "lab", "listeners", "canary.jsonl"), lines.map((ts) => JSON.stringify({ ts, peer: "10.231.0.3:4000", local: "10.231.0.33:443" })).join("\n") + "\n");
  return { RUN: dir, lab: { listeners: [{ name: "canary", log: "lab/listeners/canary.jsonl", role: "canary" }, { name: "control", log: "lab/listeners/control.jsonl", role: "control" }] } };
}

function stepStub() {
  const checks = [];
  return { gate: "G9", dir: mkdtempSync(join(tmpdir(), "cb05-step-")), checks, check(name, ok, o = {}) { checks.push({ name, ok, ...o }); return ok; }, notRun(name, why) { checks.push({ name, notRun: why }); } };
}

test("accepts counts only the window, to the second, and null when the log is missing", () => {
  const ctx = lab(mkdtempSync(join(tmpdir(), "cb05-")), ["2026-11-12T10:00:00Z", "2026-11-12T10:05:00Z", "2026-11-12T10:05:09Z", "2026-11-12T10:09:00Z"]);
  assert.equal(accepts(ctx, "canary", "2026-11-12T10:05:00Z", "2026-11-12T10:05:09Z"), 2);
  assert.equal(accepts(ctx, "canary", "2026-11-12T10:06:00Z", "2026-11-12T10:08:00Z"), 0);
  assert.equal(accepts(ctx, "control", "2026-11-12T10:00:00Z", "2026-11-12T11:00:00Z"), null);
  assert.equal(accepts(ctx, "nope", "2026-11-12T10:00:00Z", "2026-11-12T11:00:00Z"), null);
});

test("the oracle constants are the spec's, not the product's", () => {
  assert.deepEqual(RATES_C, { linux_servers: 20, windows_servers: 20, database: 100, network_range: 100, idp: 0 });
  assert.equal(AWS_NOT_CONFIGURED_TEXT, "This ZeroShield deployment is not set up for AWS collection; contact your administrator");
  assert.deepEqual([...VEX_FUTURE_RISK].sort(), ["NO_PQ_KEX", "QUANTUM_VULNERABLE", "SSH_NO_PQ_KEX"]);
  assert.ok(RUNTIME_SKIPS.has("skipped_never_scan") && !RUNTIME_SKIPS.has("unreachable"));
});

const fakeCtx = (rows, extra = {}) => ({ A: { team: 5 }, state: { runs: [9], estimate: 3.6 }, iso: () => "2026-11-12T10:00:00Z", writeJson() {},
  db: (sql) => (typeof rows === "function" ? rows(sql) : rows), ...extra });

test("G9: the skipped list must name every source whose test failed (the estimate itself is CB-01's)", async () => {
  const plan = plannedCharge([{ kind: "linux_servers", name: "S-host", config: { targets: ["10.231.0.40"] } }, { kind: "linux_servers", name: "S-canary", config: { targets: ["10.231.0.33", "10.231.0.34"] } },
    { kind: "network_range", name: "R-canary", config: { cidr: "10.231.0.32/30" } }], ["10.231.0.33"], ["S-canary"]);
  assert.equal(plan.total_c, 120);  // S-host 0.2 + 3 range addresses -> 1 credit; S-canary not queued
  const ctxWith = (text) => fakeCtx([], { A: { team: 5, page: { getByTestId: () => ({ textContent: async () => text }) } } });
  const s = stepStub();
  await g9Skipped(ctxWith("S-canary Last connection test failed; fix it and test again"), s, plan);
  assert.equal(s.checks[0].ok, true);
  const s2 = stepStub();
  await g9Skipped(ctxWith("nothing skipped"), s2, plan);
  assert.equal(s2.checks[0].ok, false);
});

test("G10 (OA-10b): a never-scan address left out at planning owes nothing; a charged server target skipped at run time is refunded", async () => {
  const jobs = [{ job_id: 1, source_id: 11, source_name: "S-host", targets: [{ target: "10.231.0.40", status: "ok" }, { target: "10.231.0.23", status: "skipped_never_scan" }] },
    { job_id: 2, source_id: 12, source_name: "R-canary", targets: [{ target: "10.231.0.33:443", status: "skipped_never_scan" }, { target: "10.231.0.34:443", status: "ok" }] }];
  const srcs = [["11", "linux_servers", JSON.stringify({ targets: ["10.231.0.40", "10.231.0.23"] })], ["12", "network_range", JSON.stringify({ cidr: "10.231.0.32/30" })]];
  const inCidr = (ip, c) => ip.startsWith("10.231.0.3") && c.endsWith("/30");
  const run = (charged, refunded) => fakeCtx((sql) => (sql.includes("FROM cbomcollectionrun") ? [[String(charged), String(refunded)]] : sql.includes("AND enabled") ? srcs.map(([, k, c], i) => [k, ["S-host", "R-canary"][i], c]) : srcs),
    { inCidr, state: { runs: [9], estimate: 1.4, tests: {}, never_scan_g5: ["10.231.0.33"] }, apiGet: async () => ({ status: 200, body: { targets: jobs } }) });
  const s = stepStub();
  await g10Charge(run(140, 20), s);   // 1.4 charged, 0.2 refunded for the skipped .23
  assert.equal(s.checks.find((x) => x.name === "charge_after_runtime_skips").ok, true);
  const s2 = stepStub();
  await g10Charge(run(140, 0), s2);   // charged in full: KF-8
  assert.equal(s2.checks.find((x) => x.name === "charge_after_runtime_skips").ok, false);
  assert.equal(s2.checks.find((x) => x.name.startsWith("run_target_10.231.0.33")).ok, true);
});

// ------------------------------------------------------------------------------------------------ CB-38 results page
/** A fake Playwright page: the Review & Run button navigates to the results page (as #117 does); the toggle exists
 * unless ``noToggle``; ``reviewTo`` overrides where the button lands. */
function fakeResultsPage({ team = 9, runId = 55, noToggle = false, reviewTo } = {}) {
  let url = "", pressed = "false";
  const loc = (tid) => ({
    click: async () => {
      if (tid.startsWith("review-run-details")) url = reviewTo ?? `http://ui/${team}/cbom/runs/${runId}/results`;
      if (tid === "run-results-view-all") pressed = "true";
    },
    waitFor: async () => {}, count: async () => (tid === "run-results-view-all" && noToggle ? 0 : 1),
    getAttribute: async () => pressed, isDisabled: async () => false,
  });
  const page = { goto: async (u) => { url = u; pressed = "false"; }, getByTestId: loc, waitForURL: async () => {}, url: () => url,
    waitForLoadState: async () => {}, waitForTimeout: async () => {} };
  return { UI: "http://ui", A: { page, team } };
}

test("openRunResults: both openings judge the URL and the All assets view under distinct check ids", async () => {
  const ctx = fakeResultsPage();
  const s = stepStub();
  const direct = await openRunResults(ctx, s, 55, { via: "direct" });
  const review = await openRunResults(ctx, s, 55, { via: "review" });
  assert.equal(direct, "/9/cbom/runs/55/results");
  assert.equal(review, "/9/cbom/runs/55/results");
  const names = s.checks.map((c) => c.name);
  assert.deepEqual(names, ["results_url_direct", "results_view_all_direct", "results_url_review", "results_view_all_review"]);
  assert.equal(new Set(names).size, names.length, "the judge rejects a repeated id");
  assert.ok(s.checks.every((c) => c.ok));
  // captureRun's tag keeps run 1 and run 2 apart too
  const s2 = stepStub();
  await openRunResults(ctx, s2, 55, { via: "direct", tag: "_run1" });
  await openRunResults(ctx, s2, 55, { via: "direct", tag: "_run2" });
  assert.deepEqual(s2.checks.map((c) => c.name), ["results_url_direct_run1", "results_view_all_direct_run1", "results_url_direct_run2", "results_view_all_direct_run2"]);
});

test("openRunResults fails closed: the old dialog URL, and a page without the Findings / All assets toggle", async () => {
  const s = stepStub();
  await openRunResults(fakeResultsPage({ reviewTo: "http://ui/9/cbom/sources" }), s, 55, { via: "review" });
  assert.deepEqual(s.checks.map((c) => [c.name, c.ok]), [["results_url_review", false], ["results_view_all_review", true]]);
  const s2 = stepStub();
  await openRunResults(fakeResultsPage({ noToggle: true }), s2, 55, { via: "direct" });
  assert.deepEqual(s2.checks.map((c) => [c.name, c.ok]), [["results_url_direct", true], ["results_view_all_direct", false]]);
  assert.equal(s2.checks[1].observed, "no Findings / All assets toggle");
});

function tr(testid, attrs = null, cells = []) {
  const dataset = { testid, ...(attrs || {}) };
  return { dataset, hasAttribute: (a) => attrs !== null && a === "data-impact" && "impact" in attrs,
    querySelectorAll: (sel) => (sel === "td" ? cells.map((text) => ({ textContent: text, querySelectorAll: () => [] })) : []) };
}

test("readRunRows: attribute rows raw, absent attributes left out, other test ids skipped", () => {
  const rows = readRunRows([
    tr("run-asset-7", { impact: "High", type: "tls_endpoint", location: "h:443", target: "h", algorithm: "TLS 1.2", keySize: "", finding: "f",
      quantum: "vulnerable", status: "fixed", qGrade: "Q1" }),
    tr("run-asset-select-7", {}),
    tr("run-asset-action-7", {}),
    tr("run-asset-8", { impact: "", type: "coverage" }),
  ]);
  assert.deepEqual(rows, [
    { id: 7, reader: "data-attributes", impact: "High", type: "tls_endpoint", location: "h:443", target: "h", algorithm: "TLS 1.2", key_size: "",
      finding: "f", quantum: "vulnerable", status: "fixed", q_grade: "Q1" },
    { id: 8, reader: "data-attributes", impact: "", type: "coverage" },
  ]);
  assert.ok(readRunRows.toString().startsWith("function readRunRows"), "self-contained: serialisable for page.$$eval");
});

test("readRunRows: on the results page a row without attributes is all missing, never read by cell position", () => {
  const legacy = tr("run-asset-9", null, ["", "", "High", "Certificate", "", "RSA 2048", "f", "Vulnerable"]);
  assert.deepEqual(readRunRows([legacy], { attrsOnly: true }), [{ id: 9, reader: "data-attributes" }]);
  const old = readRunRows([legacy]);  // the old run dialog: by position
  assert.equal(old[0].impact, "High");
  assert.equal(old[0].reader, undefined);
  assert.equal(isResultsPage("/9/cbom/runs/55/results"), true);
  assert.equal(isResultsPage("/9/cbom/sources"), false);
  assert.equal(isResultsPage("/9/cbom/55/results"), false);
});

const POSTURE = { posture: { pqc_readiness_pct: 28.6, pqc_classes: { "quantum-vulnerable": 5, hybrid: 0, "quantum-safe": 1, "grover-weakened": 1, "not-applicable": 2 },
  impacts: { Critical: 2, High: 3, Medium: 1, Low: 1 } } };
// the posture card's innerText (a line per <p>, as the browser lays it out)
const CARD = "Post-quantum and risk posture\nPQC readiness\n28.6%\nAssets with a quantum verdict\nCritical / High\n2 / 3\n1 medium, 1 low\n"
  + "Quantum-vulnerable 5\nQuantum-safe 1\nGrover-weakened 1\nNot applicable 2";

test("G11u: the page's readiness, classes, Critical/High and row grades equal /posture and /assets", () => {
  const s = stepStub();
  const rows = [{ id: 1, reader: "data-attributes", q_grade: "Q1" }, { id: 2, reader: "data-attributes" }];
  const items = [{ id: 1, q_grade: "Q1", fix_class: null }, { id: 2, q_grade: null }];
  g11uRuleP(s, "1", POSTURE, { posture: CARD, readiness: "PQC readiness\n28.6%", dashboard: "Crypto assets\n9\nQuantum ready\n28.6%\nAvg risk" }, rows, items);
  assert.deepEqual(s.checks.map((c) => [c.name, c.ok]), [["g11u_posture_readiness_run1", true], ["g11u_dashboard_readiness_run1", true],
    ["g11u_classes_run1", true], ["g11u_critical_high_run1", true], ["g11u_row_grades_run1", true]]);
});

test("G11u fails on a recount (14.3 % where posture says 28.6 %), a wrong class or severity, and a wrong row grade", () => {
  const s = stepStub();
  g11uRuleP(s, "1", POSTURE, { posture: CARD.replace("Quantum-vulnerable 5", "Quantum-vulnerable 4").replace("2 / 3", "2 / 4"),
    readiness: "PQC readiness\n14.3%", dashboard: "Quantum ready\n14.3%" }, [{ id: 1, reader: "data-attributes", q_grade: "Q2" }], [{ id: 1, q_grade: "Q1" }]);
  assert.ok(s.checks.every((c) => c.ok === false), JSON.stringify(s.checks.map((c) => [c.name, c.ok])));
  const s2 = stepStub();
  g11uRuleP(s2, "1", { pqc_readiness_pct: null, pqc_classes: {}, impacts: {} }, { posture: "", readiness: "PQC readiness\n—", dashboard: null }, [], []);
  assert.deepEqual(s2.checks.map((c) => [c.name, c.ok ?? "not-run"]), [["g11u_posture_readiness_run1", true], ["g11u_dashboard_readiness_run1", "not-run"],
    ["g11u_classes_run1", false], ["g11u_critical_high_run1", false], ["g11u_row_grades_run1", false]]);
});

test("G11u reads Critical / High from line-separated text, not digits glued to the next line", () => {
  const s = stepStub();
  g11uRuleP(s, "1", POSTURE, { posture: CARD, readiness: "28.6%", dashboard: null }, [{ id: 1, reader: "data-attributes" }], [{ id: 1 }]);
  assert.equal(s.checks.find((c) => c.name === "g11u_critical_high_run1").ok, true);
  const glued = stepStub();  // what textContent would give: "2 / 31 medium" reads as High 31
  g11uRuleP(glued, "1", POSTURE, { posture: "Critical / High2 / 31 medium, 1 low", readiness: "28.6%", dashboard: null }, [], []);
  assert.equal(glued.checks.find((c) => c.name === "g11u_critical_high_run1").ok, false);
});
