/**
 * #15 (R2 regression): Admin > Create admin user said the new user "will receive an email with their credentials".
 * Since S2 the server (POST /admin/create_admin_user, backend routers/admin.py) mails a single-use "choose your
 * password" link and never a password, and the password typed in the dialog is temporary: signing in with it asks for
 * a new one first (must_change_password). The dialog now says that.
 * Browser check: as a superuser, Admin > Create admin user: the dialog describes the link and the temporary password;
 * create one: the mail has a "Choose your password" link and no password; signing in with the temporary password asks
 * for a new one.
 * Run: npx --yes tsx utils/adminCreateUser.test.ts
 */
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";

const page = fs.readFileSync(path.join(__dirname, "..", "app", "admin", "page.tsx"), "utf8");
const dialog = page.slice(page.indexOf('<DialogTitle className="text-zinc-100">Create admin user</DialogTitle>'),
  page.indexOf("</form>"));
assert.ok(dialog.length > 0, "the Create admin user dialog");
const description = dialog.slice(dialog.indexOf("<DialogDescription"), dialog.indexOf("</DialogDescription>"))
  .replace(/\s+/g, " ");

assert.ok(!/credential/i.test(description), `still says the credentials are emailed: ${description}`);
assert.ok(!/email with (their|the) password/i.test(description));
assert.ok(description.includes("a link to choose their own password"), description);
assert.ok(description.includes("never contains a password"), description);
assert.ok(description.includes("The password you set here is temporary"), description);
assert.ok(description.includes("they must choose a new one"), description);

// the field says what the password is for
assert.ok(dialog.includes('<Label htmlFor="admin-password" className="text-zinc-300">Temporary password</Label>'));

console.log("create admin user dialog: tests passed");
