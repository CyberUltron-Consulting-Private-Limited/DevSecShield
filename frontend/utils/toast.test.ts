/**
 * X1 (Nov 11): toasts lasted 1.5 s and only one was visible, so a validation error flashed past. Errors and warnings
 * now stay 8 s with a close button, successes 4 s, up to 3 visible.
 * Browser check: New SAST scan > Create with an empty title: the error toast is still there after 5 s and has a close
 * button; three quick errors are all visible.
 * Run: npx --yes tsx utils/toast.test.ts
 */
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";

import { toast as sonner } from "sonner";

const calls: [string, unknown, Record<string, unknown> | undefined][] = [];
for (const kind of ["success", "error", "warning", "info", "message"] as const) {
  (sonner as unknown as Record<string, unknown>)[kind] = (m: unknown, d?: Record<string, unknown>) => {
    calls.push([kind, m, d]);
    return 1;
  };
}
// imported after the spies, as the app's modules do at runtime
// eslint-disable-next-line @typescript-eslint/no-require-imports
const { toast, TOAST_ERROR_MS, TOAST_SUCCESS_MS, TOASTS_VISIBLE } = require("./toast") as typeof import("./toast");

toast.error("Title is required");
toast.warning("careful");
toast.success("SAST scan created");
toast.info("note");
toast.error("custom", { duration: Infinity });
assert.deepEqual(calls[0], ["error", "Title is required", { duration: 8000, closeButton: true }]);
assert.deepEqual(calls[1], ["warning", "careful", { duration: 8000, closeButton: true }]);
assert.deepEqual(calls[2], ["success", "SAST scan created", { duration: 4000 }]);
assert.deepEqual(calls[3], ["info", "note", { duration: 4000 }]);
assert.equal(calls[4][2]?.duration, Infinity, "a caller's own duration wins");
assert.equal(TOAST_ERROR_MS, 8000);
assert.equal(TOAST_SUCCESS_MS, 4000);
assert.equal(TOASTS_VISIBLE, 3);
assert.equal(typeof toast.dismiss, "function");

const layout = fs.readFileSync(path.join(__dirname, "..", "app", "layout.tsx"), "utf8");
assert.ok(layout.includes("duration={TOAST_SUCCESS_MS}") && layout.includes("visibleToasts={TOASTS_VISIBLE}"));
assert.ok(!layout.includes("duration={1500}") && !layout.includes("visibleToasts={1}"));

console.log("toasts: tests passed");
