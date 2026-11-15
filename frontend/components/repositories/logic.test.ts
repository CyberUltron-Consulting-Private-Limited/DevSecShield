// Run: npx --yes tsx components/repositories/logic.test.ts
import assert from "node:assert/strict"

import {
  connectionBody,
  connectionErrors,
  DEFAULT_API,
  editErrors,
  editFormFrom,
  editMovesCredential,
  editPatch,
  filterChange,
  emptyConnectionForm,
  emptyFilters,
  estimateSentence,
  filtersError,
  filtersFrom,
  formatCredits,
  joinList,
  listError,
  parseList,
  parseSizeLimit,
  PRODUCT_LABEL,
  PRODUCTS,
  reasonLabel,
  REASON_LABEL,
  repoCount,
  ROTATE_WARNING,
  scheduleText,
  SCOPES,
  selectionText,
  SIZE_RULE,
  sizeLabel,
  sizeLimitError,
  skippedSentence,
  toggleIds,
  webhookUrl,
} from "./logic"
import type { ScmConnection, ScmRepositoryQuery } from "@/utils/api/scm"

// lists: commas or new lines, trimmed, no repeats
assert.deepEqual(parseList(" payments-*, core/*\n\n payments-* ,legacy-?"), ["payments-*", "core/*", "legacy-?"])
assert.equal(joinList(["a", "b"]), "a, b")
assert.equal(listError(Array.from({ length: 101 }, (_, i) => `p${i}`)), "At most 100 entries")
assert.equal(listError(["x".repeat(201)]), "Each entry is at most 200 characters")
assert.equal(listError(["ok"]), null)
assert.equal(filtersError({ ...emptyFilters(), max_size_mb: -1 }), SIZE_RULE)
// the size limit is typed as text: empty is "no limit"; anything else must be a number from 0 to 1,000,000 MB
// (filters.RepoFilters.max_size_mb). Text that is not a number must block the preview and the import, not silently
// become "no limit" (the snapshot turned "abc" into null and imported every repository).
assert.equal(parseSizeLimit(""), null)
assert.equal(parseSizeLimit("   "), null)
assert.equal(parseSizeLimit(" 250 "), 250)
assert.equal(parseSizeLimit("0"), 0)
assert.equal(parseSizeLimit("1.5"), 1.5)
assert.ok(Number.isNaN(parseSizeLimit("abc") as number))
assert.ok(Number.isNaN(parseSizeLimit("12abc") as number))
assert.equal(filtersError({ ...emptyFilters(), max_size_mb: parseSizeLimit("abc") }), SIZE_RULE)
assert.equal(filtersError({ ...emptyFilters(), max_size_mb: 1_000_001 }), SIZE_RULE)
assert.equal(filtersError({ ...emptyFilters(), max_size_mb: 1_000_000 }), null)
assert.equal(filtersError({ ...emptyFilters(), max_size_mb: 0 }), null)
assert.equal(sizeLimitError(parseSizeLimit("-3")), SIZE_RULE)
assert.equal(sizeLimitError(null), null)
// a list error is reported first; the size field still shows its own error
assert.equal(filtersError({ ...emptyFilters(), languages: ["x".repeat(201)], max_size_mb: Number.NaN }), "Each entry is at most 200 characters")
assert.equal(filtersError(emptyFilters()), null)
assert.deepEqual(filtersFrom({ languages: ["Go"] }), { ...emptyFilters(), languages: ["Go"] })

// every reason the backend gives has a label (backend/utilities/scm/filters.py REASONS)
for (const r of ["matched", "manual_include", "manual_exclude", "archived", "fork", "visibility", "too_large",
  "excluded_name", "not_included_name", "excluded_topic", "missing_topic", "language", "removed"]) {
  assert.ok(REASON_LABEL[r], r)
}
assert.equal(reasonLabel("some_new_reason"), "some new reason")
assert.deepEqual(PRODUCTS, ["sast", "iac", "sbom_sca", "cbom", "ai_bom"])
assert.equal(PRODUCT_LABEL.sbom_sca, "SCA + SBOM")

// credits and the estimate sentence
assert.equal(formatCredits(1), "1 credit")
assert.equal(formatCredits(1234.5), "1,234.5 credits")
assert.equal(formatCredits(0.004), "0 credits")
assert.equal(
  estimateSentence({ scans: 120, repos: 60, credits: 54.3, balance: 1000, affordable: true }),
  "120 scans of 60 repositories for 54.3 credits. The team has 1,000 credits; the run is charged once, when it starts.",
)
assert.match(estimateSentence({ scans: 1, repos: 1, credits: 2, balance: 0.5, affordable: false }), /only 0.5 credits, so the run cannot start/)
assert.match(estimateSentence({ scans: 0, repos: 0, credits: 0, balance: 5, affordable: true }), /^Nothing to scan/)
assert.equal(skippedSentence({ already_queued: 2, sast_language: 1 }),
  "Not queued: 2 already queued or running; 1 SAST cannot read the repository's language.")
assert.equal(skippedSentence({}), "")

// schedules
assert.equal(scheduleText({ frequency: "off" }), "No schedule")
assert.equal(scheduleText({ frequency: "daily", time_of_day: "02:30", timezone: "Asia/Kolkata" }), "Daily at 02:30 (Asia/Kolkata)")
assert.equal(scheduleText({ frequency: "weekly", time_of_day: "03:00", weekday: 6, timezone: "UTC" }), "Weekly on Sunday at 03:00 (UTC)")
assert.equal(scheduleText({ frequency: "monthly", time_of_day: "00:15", monthday: 28, timezone: "UTC" }), "Monthly on day 28 at 00:15 (UTC)")

// connection form: the server's rules, before sending
const blank = emptyConnectionForm("github")
assert.equal(blank.auth_kind, "github_app")
const errs = connectionErrors(blank)
assert.ok(errs.name && errs.app_id && errs.installation_id && errs.private_key)
const token = { ...emptyConnectionForm("github"), auth_kind: "token" as const, scope_kind: "org" as const, name: "Acme", scope_name: "", token: "" }
assert.deepEqual(Object.keys(connectionErrors(token)).sort(), ["scope_name", "token"])
assert.deepEqual(connectionErrors({ ...token, scope_name: "acme", token: "ghp_x" }), {})
assert.equal(connectionErrors({ ...token, scope_name: "acme", token: "x", api_base: "ghe.corp/api/v3" }).api_base, "Start with https://")
const gl = { ...emptyConnectionForm("gitlab"), name: "GL", token: "t" }
assert.equal(connectionErrors(gl).scope_name, "The group path is required")
const body = connectionBody({ ...token, scope_name: " acme ", token: " ghp_x " }, emptyFilters())
assert.deepEqual(body.secrets, { token: "ghp_x" })
assert.equal(body.scope_name, "acme")
assert.equal(body.api_base, null)
const app = connectionBody({ ...blank, name: "App", app_id: "12", installation_id: "34", private_key: "-----BEGIN PRIVATE KEY-----" }, emptyFilters())
assert.deepEqual(app.config, { app_id: "12", installation_id: "34" })
assert.deepEqual(Object.keys(app.secrets), ["private_key"])
for (const provider of ["github", "gitlab", "bitbucket"] as const) assert.ok(SCOPES[provider].length >= 1)

// misc
assert.equal(webhookUrl("https://api.example/", "/scm/webhooks/github/abc"), "https://api.example/scm/webhooks/github/abc")
assert.equal(sizeLabel(512), "512 KB")
assert.equal(sizeLabel(2048), "2.0 MB")
assert.equal(sizeLabel(268585), "262 MB")
assert.equal(sizeLabel(3 * 1024 * 1024), "3.0 GB")
assert.deepEqual(toggleIds([1, 2], [2, 3], true).sort(), [1, 2, 3])
assert.deepEqual(toggleIds([1, 2, 3], [2, 3], false), [1])

// counts read as English: "1 repository", "1,234 repositories" (the browser run showed "1 repositories")
assert.equal(repoCount(1), "1 repository")
assert.equal(repoCount(0), "0 repositories")
assert.equal(repoCount(1234), "1,234 repositories")

// ---- review of #66, major 1: editing a connection (the wizard sends people to Edit on the Connections tab)
const conn = (over: Partial<ScmConnection> = {}): ScmConnection => ({
  id: 7, name: "Acme GitHub", provider: "github", auth_kind: "token", api_base: DEFAULT_API.github, scope_kind: "org",
  scope_name: "acme", config: {}, filters: {}, secrets_set: ["token"], enabled: true, webhook_path: "/scm/webhooks/github/x",
  webhook_secret_set: true, sync_interval_min: 360, row_version: 4, created_at: null, updated_at: null,
  sync: { status: "ok", last_at: null, next_at: null, requested_at: null, summary: {}, error: null },
  last_test: { status: "ok", at: null, message: null }, ...over,
})
assert.equal(DEFAULT_API.github, "https://api.github.com")
assert.equal(DEFAULT_API.gitlab, "https://gitlab.com")
assert.equal(DEFAULT_API.bitbucket, "https://api.bitbucket.org")
{
  const c = conn()
  const f = editFormFrom(c, DEFAULT_API.github)
  assert.equal(f.secret, "", "the saved token is never put back in the form")
  assert.equal(f.api_base, "", "the cloud API shows as empty")
  assert.deepEqual(editErrors(c, f, DEFAULT_API.github), {}, "an unchanged form is valid without the token")
  assert.deepEqual(editPatch(c, f, DEFAULT_API.github), { expected_version: 4 }, "nothing changed: only the row version")
  // a new token alone replaces the saved one, without exposing it
  assert.deepEqual(editPatch(c, { ...f, secret: " ghp_new " }, DEFAULT_API.github), { expected_version: 4, secrets: { token: "ghp_new" } })
  // pointing the token at another organisation needs it again (the server refuses otherwise)
  const moved = { ...f, scope_name: "other-org" }
  assert.ok(editMovesCredential(c, moved, DEFAULT_API.github))
  assert.match(editErrors(c, moved, DEFAULT_API.github).secret ?? "", /Enter the access token again/)
  assert.deepEqual(editPatch(c, { ...moved, secret: "ghp_x" }, DEFAULT_API.github),
    { expected_version: 4, scope_name: "other-org", secrets: { token: "ghp_x" } })
  // a rename or a new interval does not need the token
  assert.deepEqual(editErrors(c, { ...f, name: "Acme GH", sync_interval_min: "60" }, DEFAULT_API.github), {})
  assert.deepEqual(editPatch(c, { ...f, name: "Acme GH", sync_interval_min: "60" }, DEFAULT_API.github),
    { expected_version: 4, name: "Acme GH", sync_interval_min: 60 })
  assert.ok(editErrors(c, { ...f, sync_interval_min: "5" }, DEFAULT_API.github).sync_interval_min)
}
{
  const app = conn({ auth_kind: "github_app", scope_kind: "installation", config: { app_id: "12", installation_id: "34" }, secrets_set: ["private_key"] })
  const f = editFormFrom(app, DEFAULT_API.github)
  assert.equal(f.app_id, "12")
  const other = { ...f, installation_id: "99" }
  assert.match(editErrors(app, other, DEFAULT_API.github).secret ?? "", /private key again/)
  assert.deepEqual(editPatch(app, { ...other, secret: "-----BEGIN RSA PRIVATE KEY-----\nx" }, DEFAULT_API.github), {
    expected_version: 4, config: { app_id: "12", installation_id: "99" }, secrets: { private_key: "-----BEGIN RSA PRIVATE KEY-----\nx" },
  })
}

// ---- major 2: the webhook secret is rotated only after a confirmation that says what breaks
assert.match(ROTATE_WARNING, /stops working at once/)
assert.match(ROTATE_WARNING, /scan on push stops/)
assert.match(ROTATE_WARNING, /paste the new secret into the provider's webhook/)
assert.match(ROTATE_WARNING, /shown only once/)

// ---- minor 5: a filter change empties the selection and goes back to page 1; the text says what is off-page
{
  const start: ScmRepositoryQuery = { scope: "in", page: 3, page_size: 50 }
  const next = filterChange(start, { language: "Python" })
  assert.deepEqual(next, { query: { scope: "in", page: 1, page_size: 50, language: "Python" }, selected: [] })
  assert.deepEqual(filterChange({ page: 2 }, {}).selected, [])
}
assert.equal(selectionText([1, 2, 3], [1, 2, 3]), "3 selected")
assert.equal(selectionText([1, 2, 3], [3, 4]), "3 selected (2 not on this page)")

console.log("repositories logic: ok")
