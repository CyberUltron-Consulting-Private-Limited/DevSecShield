/**
 * CB-38 (R-qa #117): a backend outage keeps the loaded rows and toasts once.
 * Run: npx --yes tsx components/cbom/results/listErrors.test.ts
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { createOutageGate, listView } from "./listErrors";

test("one toast per outage", () => {
  const gate = createOutageGate();
  // four failed refetches during one outage: one toast
  assert.deepEqual([gate.failed(), gate.failed(), gate.failed(), gate.failed()], [true, false, false, false]);
  gate.succeeded();
  // a later outage toasts again, once
  assert.deepEqual([gate.failed(), gate.failed()], [true, false]);
  // successes alone never toast
  gate.succeeded();
  gate.succeeded();
  assert.equal(gate.failed(), true);
});

test("the error screen replaces the table only when nothing was loaded", () => {
  assert.equal(listView({ isLoading: true, isError: false, hasData: false }), "loading");
  assert.equal(listView({ isLoading: false, isError: true, hasData: false }), "error");
  // a failed background refetch keeps the cached rows (and the tab and filters with them)
  assert.equal(listView({ isLoading: false, isError: true, hasData: true }), "rows");
  assert.equal(listView({ isLoading: false, isError: false, hasData: true }), "rows");
});
