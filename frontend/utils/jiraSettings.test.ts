/**
 * X1 (round 5 customer walkthrough): Settings > Jira integration, email "bad", URL "http://169.254.169.254/", no token,
 * Save integration settings -> PUT /team/13 {"integration_settings":{"jira":null}} and the toast
 * "Team updated successfully": the typed values were dropped (and an existing Jira configuration would be removed).
 * Browser check after a rebuild: fill only email + URL > Save: toast "Fill in the Jira email, URL and API token, or
 * clear all three to remove Jira." and no PUT /team/13.
 * Since SOW S2 the form lives on Settings > Integrations (components/integrations/JiraCard.tsx).
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

// SOW S2: Jira moved to Settings > Integrations; the card asks the helper before any request
const card = fs.readFileSync(path.join(__dirname, "..", "components", "integrations", "JiraCard.tsx"), "utf8")
const save = card.slice(card.indexOf("const save = useMutation"), card.indexOf("const test = useMutation"))
assert.ok(save.includes("const decision = jiraToSave(email, url, token, jira.api_token_set);"), "the card asks the helper")
assert.ok(save.indexOf("throw new Error(decision.message)") < save.indexOf("saveJira(teamId"), "refused before any request")
assert.ok(save.includes("...decision.jira"), "only what the helper allowed is sent")
const settings = fs.readFileSync(path.join(__dirname, "..", "app", "[team_id]", "settings", "page.tsx"), "utf8")
assert.ok(!settings.includes("jiraToSave") && settings.includes("settings/integrations#int-jira"), "Team settings link to the card")

console.log("jira settings tests passed")
