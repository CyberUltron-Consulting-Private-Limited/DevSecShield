// node --test e2e/cbom/flow/cb05.test.mjs : the CB-05 helpers that decide verdicts without a browser.
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { accepts, AWS_NOT_CONFIGURED_TEXT, g10Charge, g9Rates, RATES_C, RUNTIME_SKIPS, VEX_FUTURE_RISK } from "./cb05.mjs";

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

test("G9: estimate == the spec's rates over the queued sources (network: 1 per 256 addresses or part, never-scan left out)", async () => {
  const rows = [["linux_servers", "S-host", JSON.stringify({ targets: ["10.231.0.40"] })], ["linux_servers", "S-canary", JSON.stringify({ targets: ["10.231.0.33", "10.231.0.34"] })],
    ["database", "DB-pg-tls", "{}"], ["network_range", "R-zoo", JSON.stringify({ cidr: "10.231.0.16/28" })], ["network_range", "R-canary", JSON.stringify({ cidr: "10.231.0.32/30" })]];
  const inCidr = (ip, c) => { const [n, b] = c.split("/"); const v = (a) => a.split(".").reduce((x, o) => x * 256 + Number(o), 0); const sz = 2 ** (32 - Number(b)); return Math.floor(v(ip) / sz) === Math.floor(v(n) / sz); };
  const ctx = (est) => fakeCtx(rows, { inCidr, state: { runs: [9], estimate: est, tests: { "S-canary": "failed", "S-host": "passed" }, never_scan_g5: ["10.231.0.33"] },
    A: { team: 5, page: { getByTestId: () => ({ textContent: async () => "S-canary Last connection test failed; fix it and test again" }) } } });
  // S-host 0.2 + DB 1 + network 19 addresses -> 1 = 2.2 (S-canary not queued: its test failed)
  const s = stepStub();
  await g9Rates(ctx(2.2), s, 2.2);
  assert.deepEqual(s.checks.map((c) => [c.name, c.ok]), [["estimate_eq_rates", true], ["review_skipped_eq_failed_tests", true]]);
  const s2 = stepStub();
  await g9Rates(ctx(2.6), s2, 2.6);
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
