/**
 * #15: Admin > Create admin user said the new user "will receive an email with their credentials". The server
 * (POST /admin/create_admin_user, backend routers/admin.py) mails a single-use "choose your password" link and never a
 * password, and the password typed in the dialog is temporary: signing in with it asks for a new one first
 * (must_change_password, backend routers/auth.py). The dialog now says that.
 * Failing-first on origin/dev 1884f564: the dialog said "They will receive an email with their credentials."
 * Browser check: as a superuser, Admin > Create admin user: the dialog describes the link and the temporary password.
 * Run: npx --yes tsx@4.23.15 utils/adminCreateUser.test.ts
 */
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";

const root = path.join(__dirname, "..");
const page = fs.readFileSync(path.join(root, "app", "admin", "page.tsx"), "utf8");
const dialog = page.slice(page.indexOf("function CreateAdminUserDialog("), page.indexOf("</form>"));
assert.ok(dialog.length > 0, "the Create admin user dialog");
const description = dialog.slice(dialog.indexOf("<DialogDescription"), dialog.indexOf("</DialogDescription>"))
  .replace(/^<DialogDescription[^>]*>/, "").replace(/\s+/g, " ").trim();

assert.ok(!/credential/i.test(description), `still says the credentials are emailed: ${description}`);
assert.ok(description.includes("a single-use link to choose their own password"), description);
assert.ok(description.includes("never contains a password"), description);
assert.ok(description.includes("The password you set here is temporary"), description);

// what the server does, so the copy and the code cannot drift apart
const admin = fs.readFileSync(path.join(root, "..", "backend", "routers", "admin.py"), "utf8");
const create = admin.slice(admin.indexOf("async def create_admin_user"), admin.indexOf("async def update_team_credit_balance"));
assert.ok(create.includes("must_change_password=True"), "the account must replace the temporary password");
assert.ok(create.includes("send_account_created_email(new_user.email, set_password_link(link_token)"),
  "the mail carries the choose-your-password link");

console.log("create admin user dialog: tests passed");
