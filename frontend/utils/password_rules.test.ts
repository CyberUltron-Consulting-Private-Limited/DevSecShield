/**
 * Hermetic tests for the password rules (must agree with backend new_password_problem).
 * Run: npx --yes tsx utils/password_rules.test.ts
 */
import assert from "node:assert/strict";
import {
  loginPasswordProblem,
  MAX_PASSWORD_CHARS,
  MIN_NEW_PASSWORD_CHARS,
  newPasswordProblem,
  passwordLength,
} from "./password_rules";

assert.equal(MIN_NEW_PASSWORD_CHARS, 8);
assert.equal(MAX_PASSWORD_CHARS, 128);

// code points, not UTF-16 units: 128 emoji are 256 units but 128 characters (and 512 UTF-8 bytes)
const emoji128 = "\u{1F511}".repeat(128);
assert.equal(emoji128.length, 256);
assert.equal(passwordLength(emoji128), 128);
assert.equal(newPasswordProblem(emoji128), null);
assert.match(newPasswordProblem("\u{1F511}".repeat(129)) ?? "", /8 to 128 characters/);

// NFC first: "e" + combining acute counts once
assert.equal(passwordLength("é".repeat(64)), 64);
assert.equal(newPasswordProblem("é".repeat(64)), null);

assert.match(newPasswordProblem("short7!") ?? "", /it has 7/);
assert.equal(newPasswordProblem("exactly8"), null);
assert.match(newPasswordProblem("tab\there-long-enough") ?? "", /control characters/);
assert.match(newPasswordProblem("nul\u0000-long-enough") ?? "", /control characters/);
assert.match(newPasswordProblem("del\u007f-long-enough") ?? "", /control characters/);

// sign-in accepts every existing password (old rules allowed 5..24, admin-made accounts had no length rule):
// 1 to 512 UTF-8 bytes after NFC, as the backend
assert.equal(loginPasswordProblem("abcde"), null);
assert.equal(loginPasswordProblem("a"), null);
assert.match(loginPasswordProblem("") ?? "", /Enter your password/);
assert.equal(loginPasswordProblem("A".repeat(130)), null);
assert.equal(loginPasswordProblem("x".repeat(512)), null);
assert.match(loginPasswordProblem("x".repeat(513)) ?? "", /at most 512 bytes/);
assert.equal(loginPasswordProblem("é".repeat(256)), null); // 768 bytes as typed, 512 after NFC
assert.match(loginPasswordProblem("é".repeat(257)) ?? "", /at most 512 bytes/);

console.log("password_rules: all assertions passed");
