/**
 * Issue #99 review (R-qa minor 1): a double Enter in the create form made two integrations and showed only the
 * second one's key. The page submits through singleFlight; this pins the gate, and that both submit paths use it.
 */
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";

import { singleFlight } from "./singleFlight";

function deferred() {
  let resolve!: () => void;
  let reject!: (e: unknown) => void;
  const promise = new Promise<void>((res, rej) => { resolve = res; reject = rej; });
  return { promise, resolve, reject };
}

test("a second call while the first runs is dropped; the gate reopens when it settles", async () => {
  const calls: string[] = [];
  let current = deferred();
  const submit = singleFlight(async (title: string) => { calls.push(title); await current.promise; });
  assert.equal(submit("a"), true);
  assert.equal(submit("a"), false); // double Enter
  assert.equal(submit("b"), false); // button click during the same create
  assert.deepEqual(calls, ["a"]);
  current.resolve();
  await new Promise((r) => setTimeout(r, 0));
  current = deferred();
  assert.equal(submit("c"), true);
  assert.deepEqual(calls, ["a", "c"]);
  current.reject(new Error("409"));
  await new Promise((r) => setTimeout(r, 0));
  assert.equal(submit("d"), true, "an error reopens the gate too");
  current.resolve();
});

test("a synchronous throw does not leave the gate shut", () => {
  let n = 0;
  const submit = singleFlight((): Promise<void> => { n += 1; throw new Error("boom"); });
  submit();
  submit();
  assert.equal(n, 2);
});

test("the create form's Enter key and Create button both go through the gate", () => {
  const page = fs.readFileSync(path.resolve(__dirname, "../../app/[team_id]/ci_cd/page.tsx"), "utf8");
  assert.equal((page.match(/createCicdIntegrationMutation\.mutate\(/g) ?? []).length, 0, "no ungated create");
  assert.ok(/singleFlight\(/.test(page), "the page builds the gate");
  assert.ok(/e\.key === "Enter"[^\n]*\n?[^\n]*submitCreate\(\)/.test(page), "Enter submits through the gate");
  assert.ok(/onClick=\{submitCreate\}/.test(page), "the button submits through the gate");
  assert.ok(page.includes("disabled={!formTitle.trim() || !formScanType || createCicdIntegrationMutation.isPending}"));
});
