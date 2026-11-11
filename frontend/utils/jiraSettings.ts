/**
 * What "Save integration settings" sends for Jira. Before, any blank field turned the whole Jira block into null and
 * the page still said "Team updated successfully": a customer who typed an email and URL but no token saved nothing
 * (and an existing Jira configuration was removed) without being told (X1, round 5).
 * All three filled: save them. All three empty: remove Jira on purpose. Anything in between: refuse with a reason.
 *
 * The token is write-only (S2, round 5): GET /team says only whether one is stored (`api_token_set`), the field starts
 * empty, and leaving it empty keeps the stored token (the API then refuses a changed URL or email until the token
 * is typed again, so a stored token is never sent to another Jira site).
 */
export type JiraFields = { email: string; url: string; api_token?: string }

export type JiraSave =
  | { ok: true; jira: JiraFields | null }
  | { ok: false; message: string }

export const JIRA_INCOMPLETE = "Fill in the Jira email, URL and API token, or clear all three to remove Jira."
export const JIRA_TOKEN_KEPT_HINT = "A token is saved. Leave this empty to keep it, or type a new one to replace it."
export const JIRA_ADMIN_ONLY = "Only team admins can change the Jira integration."

export function jiraToSave(email: string, url: string, apiToken: string, tokenSet = false): JiraSave {
  const fields = { email: email.trim(), url: url.trim(), api_token: apiToken.trim() }
  const filled = [fields.email, fields.url, fields.api_token].filter(Boolean).length
  if (filled === 0) return { ok: true, jira: null }
  if (tokenSet && !fields.api_token && fields.email && fields.url) {
    return { ok: true, jira: { email: fields.email, url: fields.url } } // keep the stored token
  }
  if (filled < 3) return { ok: false, message: JIRA_INCOMPLETE }
  return { ok: true, jira: fields }
}

/** The Jira part of GET /team as the form shows it: the token field always starts empty. */
export function jiraFormFrom(settings: unknown): { email: string; url: string; apiToken: string; tokenSet: boolean } {
  const jira = (settings && typeof settings === "object" ? (settings as { jira?: unknown }).jira : null) as
    | { email?: unknown; url?: unknown; api_token_set?: unknown }
    | null
    | undefined
  return {
    email: typeof jira?.email === "string" ? jira.email : "",
    url: typeof jira?.url === "string" ? jira.url : "",
    apiToken: "",
    tokenSet: jira?.api_token_set === true,
  }
}
