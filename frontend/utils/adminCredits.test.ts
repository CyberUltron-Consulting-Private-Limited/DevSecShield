/**
 * Admin > Teams > Update Credits (browser QA of PR #30): the console only took whole numbers. parseInt turned
 * "4984.79" into 4984 without a word (and the field opened pre-filled with the current fractional balance, so Save
 * without an edit dropped the fraction), and POST /admin/update took an int. Credits are fractional (a server is
 * 0.2 credits, a scan chat message 0.006, prices are to the cent), so both sides now take a number from 0 to
 * MAX_CREDIT_BALANCE (backend/routers/admin.py UpdateTeamCreditBalanceData, backend/tests/test_admin_credit_balance.py).
 * PR #67 review: the API also took text, booleans and 1e308, and the field was pre-filled with String(balance), which
 * is "1e-7" for a tiny balance: the console refused its own value on Save without an edit.
 * Browser check: Admin > Teams > Update Credits > 4984.79 > Save: the table shows 4984.79.
 * Run: npx --yes tsx utils/adminCredits.test.ts
 */
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";

import { formatCreditBalance, MAX_CREDIT_BALANCE, parseCreditBalance } from "./adminCredits";

for (const [input, value] of [
  ["4984.79", 4984.79], ["0.2", 0.2], ["0.006", 0.006], ["0", 0], ["12", 12], ["12.0", 12], [" 7.5 ", 7.5],
  ["1000000.5", 1000000.5], ["4984.784000000001", 4984.784000000001], ["0012.50", 12.5],
  ["1000000000", 1_000_000_000], ["999999999.99", 999999999.99], ["0.0000001", 1e-7],
] as const) {
  assert.equal(parseCreditBalance(input), value, `"${input}" is a balance`);
}
// what the API refuses (negative or above the highest: 400; not a finite JSON number: 422), and what a number field may
// still hand over
for (const input of [
  "", " ", "-1", "-0.01", "abc", "12abc", "1e3", "1e999", "NaN", "Infinity", ".5", "5.", "1,000", "0x10", "1 000",
  "1000000000.01", "1000000001", "1".padEnd(309, "0"), "true",
]) {
  assert.equal(parseCreditBalance(input), null, `"${input}" is not a balance`);
}

// the API takes the same range (backend/routers/admin.py)
assert.equal(MAX_CREDIT_BALANCE, 1_000_000_000);
const api = fs.readFileSync(path.join(__dirname, "..", "..", "backend", "routers", "admin.py"), "utf8");
assert.ok(api.includes("MAX_CREDIT_BALANCE = 1_000_000_000\n"), "the console and the API take the same range");

// the field is pre-filled with the balance in plain decimals: String() gives "1e-7" and "1e+21", which the console
// refuses, and toFixed would round the balance on Save without an edit
for (const [value, text] of [
  [0, "0"], [4984.79, "4984.79"], [0.006, "0.006"], [1_000_000_000, "1000000000"], [123456789.12, "123456789.12"],
  [1e-7, "0.0000001"], [1.5e-7, "0.00000015"], [5.551115123125783e-17, "0.00000000000000005551115123125783"],
  [1e21, "1000000000000000000000"], [1.7976931348623157e308, "17976931348623157".padEnd(309, "0")],
] as const) {
  assert.equal(formatCreditBalance(value), text, `${value} is shown as ${text}`);
}
// ... exactly the stored number: every balance in range reads back as itself, so Save without an edit changes nothing
let seed = 67;
const random = () => (seed = (seed * 1103515245 + 12345) % 2147483648) / 2147483648;
const samples = [Number.MIN_VALUE, 5e-324, 1e-300, 2 ** -1074, 0.1 + 0.2, 4984.784000000001, MAX_CREDIT_BALANCE];
for (let i = 0; i < 20000; i++) samples.push(random() * 10 ** Math.floor(random() * 40 - 30));
for (const value of samples.filter((v) => v <= MAX_CREDIT_BALANCE)) {
  const text = formatCreditBalance(value);
  assert.match(text, /^\d+(\.\d+)?$/, `${value} is shown without an exponent: ${text}`);
  assert.equal(parseCreditBalance(text), value, `${value} reads back as itself from ${text}`);
}
assert.equal(formatCreditBalance(-0), "0");

// the Teams table uses it, and the field takes decimals
const page = fs.readFileSync(path.join(__dirname, "..", "app", "admin", "page.tsx"), "utf8");
const save = page.slice(page.indexOf("const handleSave = (team_id: number) => {"), page.indexOf("const handleCancel"));
assert.ok(save.includes("parseCreditBalance(creditInput)"), "Save reads the balance with parseCreditBalance");
assert.ok(!/parseInt\(creditInput/.test(page), "parseInt drops the fraction");
const edit = page.slice(page.indexOf("const handleStartEdit = "), page.indexOf("const handleSave"));
assert.ok(edit.includes("setCreditInput(formatCreditBalance(team.team_credit_balance))"),
  "the field is pre-filled with the balance in plain decimals");
assert.ok(!/String\(team\.team_credit_balance\)|\{team\.team_credit_balance\}/.test(page),
  "the balance is never shown with an exponent");
const field = page.slice(page.lastIndexOf("<Input", page.indexOf("value={creditInput}")), page.indexOf("value={creditInput}"));
assert.ok(/step="any"/.test(field) && /min=\{0\}/.test(field) && /max=\{MAX_CREDIT_BALANCE\}/.test(field),
  "the number field accepts decimals from 0 to the highest balance");

console.log("admin credit balance input: tests passed");
