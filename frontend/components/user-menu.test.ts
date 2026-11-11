/**
 * #14 (R2 regression): the user menu on /home said "Logout" and had no Account entry, while inside a team it offers
 * "Account" and "Sign out". Both layouts now render the one UserMenu (components/user-menu.tsx), and its Account
 * entry opens /home/account outside a team (the same Account page, so a user without a team can still change their
 * password) and /<team>/account inside one.
 * Browser check: /home > user menu: "Account" and "Sign out"; Account opens /home/account with the change-password
 * form; inside a team the menu is the same and Account opens /<team>/account.
 * Run: npx --yes tsx components/user-menu.test.ts
 */
import assert from "node:assert/strict"
import fs from "node:fs"
import path from "node:path"

import { accountPath } from "../utils/accountForm"

assert.equal(accountPath("13"), "/13/account")
assert.equal(accountPath(undefined), "/home/account", "outside a team")
assert.equal(accountPath(""), "/home/account")
assert.equal(accountPath(["13"]), "/home/account", "a catch-all segment is not a team")

const root = path.join(__dirname, "..")
const read = (rel: string) => fs.readFileSync(path.join(root, rel), "utf8")

const menu = read("components/user-menu.tsx")
assert.ok(menu.includes("export function UserMenu()"))
assert.ok(menu.includes("router.push(accountPath(teamId))"), "Account follows the team, or /home outside one")
assert.ok(menu.includes('data-testid="user-menu-account"') && menu.includes("<span>Account</span>"))
assert.ok(menu.includes("<span>Sign out</span>"))
assert.ok(!/Logout</.test(menu), "the menu says Sign out")

for (const layout of ["app/[team_id]/layout.tsx", "app/home/layout.tsx"]) {
  const src = read(layout)
  assert.ok(src.includes('import { UserMenu } from "@/components/user-menu";'), `${layout}: imports the shared menu`)
  const footer = src.slice(src.indexOf("<SidebarFooter>"), src.indexOf("</SidebarFooter>"))
  assert.ok(footer.includes("<UserMenu />"), `${layout}: renders it in the sidebar footer`)
  assert.ok(!src.includes("function UserFooter") && !/Logout</.test(src), `${layout}: a menu of its own`)
}

// /home/account is the same Account page, inside the /home layout
const homeAccount = read("app/home/account/page.tsx")
assert.ok(homeAccount.includes('import AccountPage from "@/app/[team_id]/account/page";'))
assert.ok(homeAccount.includes("<AccountPage />"))

console.log("user menu tests passed")
