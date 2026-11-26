/**
 * PR #500 takeover: a finding the engine found in test, fixture or example code (row ``code_context: "test"``) is
 * labelled "test code" in the findings table, on every screen size, and stays listed (never filtered out).
 * Run (frontend/): npx --yes tsx@4.23.15 --test components/cbom/results/testCodeLabel.test.ts
 */
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const src = readFileSync(new URL("../../CbomResults.tsx", import.meta.url), "utf8");

test("the findings table labels test code beside the name", () => {
  const at = src.indexOf('finding.code_context === "test"');
  assert.ok(at > 0, "no test-code label");
  const block = src.slice(at, at + 600);
  assert.match(block, />\s*test code\s*</);
  assert.match(block, /data-testid="cbom-finding-test-code"/);
  assert.ok(!block.includes("sm:hidden") && !block.includes("hidden sm:"), "shown on phones and desktops alike");
});

test("test code is never filtered out of the findings", () => {
  assert.ok(!/filter\([^)]*code_context/.test(src), "rows in test code must stay listed");
});

test("the findings table labels an unconfirmed setting (review 6063599094)", () => {
  const at = src.indexOf('finding.config_status === "unconfirmed"');
  assert.ok(at > 0, "no unconfirmed label");
  const block = src.slice(at, at + 700);
  assert.match(block, />\s*unconfirmed \(configuration only\)\s*</);
  assert.match(block, /data-testid="cbom-finding-unconfirmed"/);
});
