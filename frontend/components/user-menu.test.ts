/**
 * #14: the user menu on /home said "Logout" and had no Account entry, while inside a team it offers "Account" and
 * "Sign out". /home now renders UserMenu (components/user-menu.tsx), the team layout's menu moved to a shared
 * component, and its Account entry opens /home/account outside a team (the same Account page inside the /home
 * layout, so a user without a team can change their password too) and /<team>/account inside one.
 * The team layout (app/[team_id]/layout.tsx) is a file of open PR #42, so it keeps its own copy of the menu for now:
 * part 3 pins the two to the same entries.
 * Failing-first on origin/dev 1884f564: the /home menu said "Logout" and had no Account entry.
 * Browser check: /home > user menu: "Account" and "Sign out"; Account opens /home/account with the change-password
 * form; inside a team the menu is the same and Account opens /<team>/account.
 * Run: npx --yes tsx@4.23.15 components/user-menu.test.ts
 */
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";

import { accountPath } from "../utils/accountForm";

const root = path.join(__dirname, "..");
const read = (rel: string) => fs.readFileSync(path.join(root, rel), "utf8");

// 1. /home renders the shared menu in its sidebar footer, and no menu of its own
const home = read("app/home/layout.tsx");
assert.ok(!/Logout</.test(home), "the /home user menu says Logout");
assert.ok(home.includes('import { UserMenu } from "@/components/user-menu";'), "/home imports the shared menu");
const footer = home.slice(home.indexOf("<SidebarFooter>"), home.indexOf("</SidebarFooter>"));
assert.ok(footer.includes("<UserMenu />"), "/home renders it in the sidebar footer");
assert.ok(!home.includes("function UserFooter"), "/home has a menu of its own");

// 2. the menu: Account (the team's Account page, or /home/account outside a team) and Sign out
const menu = read("components/user-menu.tsx");
assert.ok(menu.includes("export function UserMenu()"));
assert.ok(menu.includes("router.push(accountPath(teamId))"), "Account follows the team, or /home outside one");
assert.ok(menu.includes('data-testid="user-menu-account"') && menu.includes("<span>Account</span>"));
assert.ok(menu.includes("<span>Sign out</span>") && !/Logout</.test(menu), "the menu says Sign out");
assert.equal(accountPath("13"), "/13/account");
assert.equal(accountPath("4096"), "/4096/account");
assert.equal(accountPath(undefined), "/home/account", "outside a team");
assert.equal(accountPath(""), "/home/account");
assert.equal(accountPath(["13"]), "/home/account", "a catch-all segment is not a team");
// only a team id (an integer, backend Team.id) becomes part of the link: the segment comes from the URL, and a decoded
// "%5C" is a backslash, so "/\evil.example/account" would resolve to another origin (PR #67 security review)
for (const segment of ["%5Cevil.example", "\\evil.example", "/evil.example", "%2F%2Fevil.example", "13abc", "1 3", " 13",
  "-1", "1e3", "0x1"]) {
  assert.equal(accountPath(segment), "/home/account", `not a team id: ${JSON.stringify(segment)}`);
}

// 3. inside a team the menu has the same entries (its own copy until the team layout renders UserMenu)
const team = read("app/[team_id]/layout.tsx");
const teamMenu = team.slice(team.indexOf("function UserFooter()"), team.indexOf("export default function"));
for (const entry of ['data-testid="user-menu-account"', "<span>Account</span>", "<span>Sign out</span>"]) {
  assert.ok(teamMenu.includes(entry) && menu.includes(entry), `the two menus differ: ${entry}`);
}

// 4. /home/account is the team Account page inside the /home layout
const homeAccount = read("app/home/account/page.tsx");
assert.ok(homeAccount.includes('import AccountPage from "@/app/[team_id]/account/page";'));
assert.ok(homeAccount.includes("<AccountPage />"));

console.log("user menu: tests passed");
