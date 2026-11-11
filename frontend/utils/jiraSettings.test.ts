/**
 * X1 (round 5 customer walkthrough): Settings > Jira integration, email "bad", URL "http://169.254.169.254/", no token,
 * Save integration settings -> PUT /team/13 {"integration_settings":{"jira":null}} and the toast
 * "Team updated successfully": the typed values were dropped (and an existing Jira configuration would be removed).
 * Browser check after a rebuild: fill only email + URL > Save: toast "Fill in the Jira email, URL and API token, or
 * clear all three to remove Jira." and no PUT /team/13.
 * Run: npx --yes tsx utils/jiraSettings.test.ts
 */
import assert from "node:assert/strict"
import fs from "node:fs"
import path from "node:path"

import { JIRA_INCOMPLETE, jiraToSave } from "./jiraSettings"

assert.deepEqual(jiraToSave("bad", "http://169.254.169.254/", ""), { ok: false, message: JIRA_INCOMPLETE })
assert.deepEqual(jiraToSave("", "", "tok"), { ok: false, message: JIRA_INCOMPLETE })
assert.deepEqual(jiraToSave("  ", "\t", " "), { ok: true, jira: null }, "clearing all three removes Jira on purpose")
assert.deepEqual(jiraToSave(" a@b.co ", " https://x.atlassian.net ", " t "), {
  ok: true,
  jira: { email: "a@b.co", url: "https://x.atlassian.net", api_token: "t" },
})

const page = fs.readFileSync(path.join(__dirname, "..", "app", "[team_id]", "settings", "page.tsx"), "utf8")
const save = page.slice(page.indexOf("const handleSaveJira"), page.indexOf("const toggleMemberSelection"))
assert.ok(save.includes("const decision = jiraToSave(jiraEmail, jiraUrl, jiraApiToken);"), "the page asks the helper")
assert.ok(save.indexOf("toast.error(decision.message);") < save.indexOf("updateTeamMutation.mutate"), "refused before any request")
assert.ok(save.includes("jira: decision.jira,"), "only what the helper allowed is sent")

console.log("jira settings tests passed")
