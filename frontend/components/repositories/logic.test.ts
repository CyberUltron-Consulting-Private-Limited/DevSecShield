// Run: npx --yes tsx components/repositories/logic.test.ts
import assert from "node:assert/strict"

import {
  connectionBody,
  connectionErrors,
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
  scheduleText,
  SCOPES,
  SIZE_RULE,
  sizeLabel,
  sizeLimitError,
  skippedSentence,
  toggleIds,
  webhookUrl,
} from "./logic"

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

console.log("repositories logic: ok")
