/**
 * Admin > Teams > Update Credits (browser QA of PR #30): the console only took whole numbers. parseInt turned
 * "4984.79" into 4984 without a word (and the field opened pre-filled with the current fractional balance, so Save
 * without an edit dropped the fraction), and POST /admin/update took an int. Credits are fractional (a server is
 * 0.2 credits, a scan chat message 0.006, prices are to the cent), so both sides now take any finite number of 0 or
 * more (backend/routers/admin.py UpdateTeamCreditBalanceData, backend/tests/test_admin_credit_balance.py).
 * Browser check: Admin > Teams > Update Credits > 4984.79 > Save: the table shows 4984.79.
 * Run: npx --yes tsx utils/adminCredits.test.ts
 */
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";

import { parseCreditBalance } from "./adminCredits";

for (const [input, value] of [
  ["4984.79", 4984.79], ["0.2", 0.2], ["0.006", 0.006], ["0", 0], ["12", 12], ["12.0", 12], [" 7.5 ", 7.5],
  ["1000000.5", 1000000.5], ["4984.784000000001", 4984.784000000001], ["0012.50", 12.5],
] as const) {
  assert.equal(parseCreditBalance(input), value, `"${input}" is a balance`);
}
// what the API refuses (negative: 400; not a finite number: 422), and what a number field may still hand over
for (const input of ["", " ", "-1", "-0.01", "abc", "12abc", "1e3", "1e999", "NaN", "Infinity", ".5", "5.", "1,000", "0x10", "1 000"]) {
  assert.equal(parseCreditBalance(input), null, `"${input}" is not a balance`);
}

// the Teams table uses it, and the field takes decimals
const page = fs.readFileSync(path.join(__dirname, "..", "app", "admin", "page.tsx"), "utf8");
const save = page.slice(page.indexOf("const handleSave = (team_id: number) => {"), page.indexOf("const handleCancel"));
assert.ok(save.includes("parseCreditBalance(creditInput)"), "Save reads the balance with parseCreditBalance");
assert.ok(!/parseInt\(creditInput/.test(page), "parseInt drops the fraction");
const field = page.slice(page.indexOf("value={creditInput}") - 200, page.indexOf("value={creditInput}"));
assert.ok(/step="any"/.test(field) && /min=\{0\}/.test(field), "the number field accepts decimals");

console.log("admin credit balance input: tests passed");
