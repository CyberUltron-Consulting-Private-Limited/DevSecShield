/**
 * X1 (Nov 11): the user menu had only Logout; there was no Account page to change the password while signed in or to
 * sign out everywhere. Now: user menu > Account (app/[team_id]/account) with the email, a note that every sign-in
 * also needs an emailed code (no authenticator app), Change password (current + new with the sign-up rules; other
 * sessions are signed out by the server, this one keeps new tokens) and Sign out everywhere (with a confirmation).
 * Browser check: user menu > Account > change password with a wrong current password (error shown, nothing changes),
 * then a valid one (toast, still signed in; a second browser is signed out); Sign out everywhere > confirm > /login.
 * Run: npx --yes tsx utils/accountForm.test.ts
 */
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";

import { changePasswordProblems } from "./accountForm";

assert.deepEqual(changePasswordProblems("Old-pass-1", "New-pass-12", "New-pass-12"), {});
assert.equal(changePasswordProblems("", "New-pass-12", "New-pass-12").current, "Enter your current password.");
assert.match(changePasswordProblems("Old-pass-1", "short", "short").next, /8 to 128 characters/);
assert.match(changePasswordProblems("Same-pass-1", "Same-pass-1", "Same-pass-1").next, /different/);
assert.match(changePasswordProblems("Old-pass-1", "New-pass-12", "New-pass-13").confirm, /not the same/);
assert.equal(changePasswordProblems("Old-pass-1", "", "").next, "Enter a new password.");

const root = path.join(__dirname, "..");
const page = fs.readFileSync(path.join(root, "app", "[team_id]", "account", "page.tsx"), "utf8");
assert.ok(page.includes("changePassword(current, next)"), "the form calls POST /change_password");
assert.ok(page.includes("mutationFn: logout"), "sign out everywhere uses /logout (it revokes every token)");
assert.ok(page.includes("6-digit code we email"), "says sign-in already uses an emailed code");
assert.ok(page.includes('data-testid="account-email"'));
const layout = fs.readFileSync(path.join(root, "app", "[team_id]", "layout.tsx"), "utf8");
assert.ok(layout.includes("router.push(`/${teamId}/account`)"), "the user menu opens the Account page");
const api = fs.readFileSync(path.join(root, "utils", "backend_api.ts"), "utf8");
const fn = api.slice(api.indexOf("const changePassword = async"), api.indexOf("const logout = async"));
assert.ok(fn.includes('api.post("/change_password"') && fn.includes('localStorage.setItem("access_token"'),
  "this tab keeps the new tokens");
console.log("account page: tests passed");
