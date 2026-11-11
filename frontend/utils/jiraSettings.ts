/**
 * What "Save integration settings" sends for Jira. Before, any blank field turned the whole Jira block into null and
 * the page still said "Team updated successfully": a customer who typed an email and URL but no token saved nothing
 * (and an existing Jira configuration was removed) without being told (X1, round 5).
 * All three filled: save them. All three empty: remove Jira on purpose. Anything in between: refuse with a reason.
 */
export type JiraFields = { email: string; url: string; api_token: string }

export type JiraSave =
  | { ok: true; jira: JiraFields | null }
  | { ok: false; message: string }

export const JIRA_INCOMPLETE = "Fill in the Jira email, URL and API token, or clear all three to remove Jira."

export function jiraToSave(email: string, url: string, apiToken: string): JiraSave {
  const fields = { email: email.trim(), url: url.trim(), api_token: apiToken.trim() }
  const filled = [fields.email, fields.url, fields.api_token].filter(Boolean).length
  if (filled === 0) return { ok: true, jira: null }
  if (filled < 3) return { ok: false, message: JIRA_INCOMPLETE }
  return { ok: true, jira: fields }
}
