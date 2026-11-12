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

test("G9: estimate == sum of the spec's rates over the configured sources (ranges: 1 per /24 or part)", () => {
  const rows = [["linux_servers", "S-host", JSON.stringify({ targets: "10.231.0.40" })], ["linux_servers", "S-canary", JSON.stringify({ targets: ["10.231.0.33", "10.231.0.34"] })],
    ["database", "DB-pg-tls", "{}"], ["network_range", "R-zoo", JSON.stringify({ cidr: "10.231.0.16/28" })], ["network_range", "R-big", JSON.stringify({ cidr: "10.0.0.0/23" })]];
  const s = stepStub();
  g9Rates(fakeCtx(rows), s, 4.6);
  assert.equal(s.checks[0].ok, true, JSON.stringify(s.checks[0]));
  const s2 = stepStub();
  g9Rates(fakeCtx(rows), s2, 4.4);
  assert.equal(s2.checks[0].ok, false);
});

test("G10 (OA-10b): skipped server targets and a pro-rata range share are refunded", async () => {
  const jobs = [{ job_id: 1, source_id: 11, source_name: "S-canary", targets: [{ target: "10.231.0.33", status: "skipped_never_scan" }, { target: "10.231.0.34", status: "ok" }] },
    { job_id: 2, source_id: 12, source_name: "R-canary", targets: [{ target: "10.231.0.33:443", status: "skipped_never_scan" }, { target: "10.231.0.34:443", status: "ok" }] }];
  const db = (sql) => (sql.includes("FROM cbomcollectionsource") ? [["11", "linux_servers", "{}"], ["12", "network_range", JSON.stringify({ cidr: "10.231.0.32/30" })]]
    : sql.includes("FROM cbomcollectionrun") ? [["360", "45"]] : []);
  const s = stepStub();
  await g10Charge(fakeCtx(db, { apiGet: async () => ({ status: 200, body: { targets: jobs } }) }), s);
  // 3.60 - 0.20 (one server target) - 0.25 (one of four addresses of a /30 at 1 credit) = 3.15 == 3.60 - 0.45 refunded
  const c = s.checks.find((x) => x.name === "charge_after_runtime_skips");
  assert.equal(c.ok, true, JSON.stringify(c));
});
