/**
 * S2 (round 5): team invitations instead of mailed passwords. The invitation page logic, the settings page's write-only
 * Jira token, and the guards the pages must keep.
 * Run: npx --yes tsx utils/invite.test.ts
 */
import assert from "node:assert/strict"
import fs from "node:fs"
import path from "node:path"

import { detailText, inviteLoginHref, inviteView, registerProblem, sameAddress, type InviteInfo } from "./invite"
import { JIRA_INCOMPLETE, jiraFormFrom, jiraToSave } from "./jiraSettings"

const base: InviteInfo = { email: "bob@corp.test", team_name: "Acme", invited_by: "alice@acme.test", expires_at: null, account_exists: true }

// --- which screen
assert.equal(inviteView({ ...base, account_exists: false }, null), "register")
assert.equal(inviteView({ ...base, account_exists: false }, "someone@else.test"), "register")
assert.equal(inviteView(base, null), "sign_in")
assert.equal(inviteView(base, "olga@other.test"), "wrong_account")
assert.equal(inviteView(base, " BOB@Corp.TEST "), "respond")
assert.ok(sameAddress("a@b.c", "A@B.C ") && !sameAddress("", "") && !sameAddress(null, "a@b.c"))

// --- sign in and come back: LoginForm turns "-" into "/" and only follows relative paths
const token = "ab".repeat(32)
const href = inviteLoginHref(token)
const back = new URLSearchParams(href.split("?")[1]).get("redirect_url")!.split("-").join("/")
assert.equal(back, `/invite/${token}`)

// --- create-account form: sign-up rules, both passwords equal, names without markup
assert.equal(registerProblem("", "B", "Long-enough-1", "Long-enough-1"), "First name is required.")
assert.equal(registerProblem("Nia", " ", "Long-enough-1", "Long-enough-1"), "Last name is required.")
assert.match(registerProblem("<b>", "B", "Long-enough-1", "Long-enough-1")!, /cannot contain/)
assert.match(registerProblem("N", "B", "short", "short")!, /8 to 128/)
assert.equal(registerProblem("N", "B", "Long-enough-1", "Long-enough-2"), "The two passwords do not match.")
assert.equal(registerProblem("N", "B", "Long-enough-1", "Long-enough-1"), null)
assert.equal(detailText({ detail: "gone" }), "gone")
assert.equal(detailText({ detail: [{ msg: "Value error, Password must be 8 to 128 characters long" }] }),
  "Password must be 8 to 128 characters long")
assert.equal(detailText(null, "x"), "x")

// --- Jira token is write-only
assert.deepEqual(jiraFormFrom({ jira: { email: "a@b.co", url: "https://x.atlassian.net", api_token_set: true } }),
  { email: "a@b.co", url: "https://x.atlassian.net", apiToken: "", tokenSet: true })
assert.deepEqual(jiraFormFrom({ jira: { email: "a@b.co", url: "u", api_token: "••••••••" } }).apiToken, "",
  "never pre-filled from the API, whatever it sends")
assert.deepEqual(jiraFormFrom(null), { email: "", url: "", apiToken: "", tokenSet: false })
assert.deepEqual(jiraToSave("a@b.co", "https://x.atlassian.net", "", true),
  { ok: true, jira: { email: "a@b.co", url: "https://x.atlassian.net" } }, "empty token keeps the stored one")
assert.deepEqual(jiraToSave("a@b.co", "https://x.atlassian.net", "", false), { ok: false, message: JIRA_INCOMPLETE })
assert.deepEqual(jiraToSave("", "", "", true), { ok: true, jira: null }, "clearing email and URL removes Jira")
assert.deepEqual(jiraToSave("a@b.co", "", "", true), { ok: false, message: JIRA_INCOMPLETE })

// --- the pages keep their guards
const root = path.join(__dirname, "..")
const settings = fs.readFileSync(path.join(root, "app", "[team_id]", "settings", "page.tsx"), "utf8")
assert.ok(!settings.includes("api_token ??") && settings.includes("const jira = jiraFormFrom(team.team_integration_settings);"),
  "token never pre-filled from the API")
assert.ok(settings.includes("jiraToSave(jiraEmail, jiraUrl, jiraApiToken, jiraTokenSet)"))
assert.ok(settings.includes("readOnly={!is_team_admin}") && settings.includes("JIRA_ADMIN_ONLY"), "members see read-only Jira")
assert.ok(settings.includes("removeDialogOpen") && settings.includes("Remove members?"), "removal asks first")
assert.ok(settings.includes("listTeamInvitations") && settings.includes("resendTeamInvitation") && settings.includes("revokeTeamInvitation"))
const saveName = settings.slice(settings.indexOf("const handleSaveNameDescription"), settings.indexOf("const handleSaveJira"))
assert.ok(!saveName.includes("integration_settings"), "renaming the team never re-sends integration settings")
const page = fs.readFileSync(path.join(root, "app", "invite", "[token]", "page.tsx"), "utf8")
assert.ok(!page.includes("@/utils/interceptors\"") || page.includes("apiBaseURL"), "plain fetch, no 401 redirect")
assert.ok(!page.includes("import api"), "the shared axios client is not used on the public page")
assert.ok(page.includes("inviteView(") && page.includes("registerProblem("))
const layout = fs.readFileSync(path.join(root, "app", "invite", "layout.tsx"), "utf8")
assert.ok(layout.includes('referrer: "no-referrer"') && layout.includes("index: false"))
const login = fs.readFileSync(path.join(root, "components", "auth", "LoginForm.tsx"), "utf8")
assert.ok(login.includes("password_change_required") && login.includes('"/change_password"'), "forced change at sign-in")

console.log("invite tests passed")
