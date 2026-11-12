// node --test e2e/cbom/flow/cb05.test.mjs : the CB-05 helpers that decide verdicts without a browser.
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { accepts, AWS_NOT_CONFIGURED_TEXT, g10Charge, g9Skipped, RATES_C, RUNTIME_SKIPS, VEX_FUTURE_RISK } from "./cb05.mjs";
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
