/**
 * Azure and Google Cloud accounts: the forms list the exact read-only grants the reader scripts make, and an account
 * whose Save and validate has not passed (no tenant connected yet) says collection is "not available" in the same
 * words as the run estimate (backend planning.CLOUD_NOT_CONNECTED).
 * Run: npx --yes tsx components/cbom/sources/cloudAzureGcp.test.ts
 */
import assert from "node:assert/strict"
import fs from "node:fs"
import path from "node:path"

const tab = fs.readFileSync(path.join(__dirname, "CloudIdentityTab.tsx"), "utf8")
const backend = (f: string) => fs.readFileSync(path.join(__dirname, "../../../../backend/utilities/cbom_sources", f), "utf8")
const planning = backend("planning.py")
const templates = backend("templates.py")

const list = (name: string): string[] => {
  const start = tab.indexOf(`const ${name} = [`)
  assert.ok(start >= 0, `${name} is declared`)
  const body = tab.slice(start, tab.indexOf("];", start))
  return [...body.matchAll(/"([^"]+)"/g)].map((m) => m[1])
}

// 1. the sentences match the backend's skip reasons
for (const words of [
  "Not available until the Azure tenant is connected: Save and validate must pass first",
  "Not available until the Google Cloud project is connected: Save and validate must pass first",
]) {
  assert.ok(tab.includes(`"${words}"`), `the tab says: ${words}`)
  assert.ok(planning.includes(`"${words}"`), `the planner says: ${words}`)
}
assert.ok(tab.includes('data-testid="cloud-validation-not-connected"'), "the validation panel shows it")
assert.ok(tab.includes("data-testid={`cloud-account-not-connected-${s.id}`}"), "and each unconnected account row")
assert.ok(tab.includes('s.kind !== "aws_account" && s.last_test_status !== "passed" && s.last_test_status !== "failed"'),
  "only Azure / Google Cloud rows not yet validated (a failed test keeps the planner's own reason)")
// a grant added by this release is a warning, never a failed validation, and tells the customer what to do
assert.ok(tab.includes('warning: ["amber", "Warning"]'), "warning checks have a badge")
assert.ok(tab.includes('data-testid="cloud-validation-rerun-script"') && tab.includes("re-run the reader script"), "and say re-run the script")
assert.ok(tab.includes('view.checks.some((c) => c.status === "fail" || c.status === "error")'), "warnings keep the account connected")

// 2. the permissions shown are exactly the ones the reader scripts grant
const azure = list("AZURE_READ_ACTIONS")
assert.ok(azure.length === 10 && azure.every((a) => a.endsWith("/read")), "Azure: read actions only")
const role = templates.slice(templates.indexOf('"Actions": ['), templates.indexOf('"NotActions"'))
assert.deepEqual([...role.matchAll(/"(Microsoft\.[^"]+)"/g)].map((m) => m[1]), azure, "same actions as the Azure reader script")
for (const p of [...list("GCP_READ_ROLES"), ...list("GCP_READ_PERMISSIONS")]) {
  assert.ok(templates.includes(p), `the Google Cloud reader script grants ${p}`)
}
assert.ok(!tab.includes("roles/compute.viewer"), "no broad Compute viewer role")
assert.ok(tab.includes('<PermissionsHelp provider="azure" />') && tab.includes('<PermissionsHelp provider="gcp" />'), "both forms show them")
console.log("cloud azure / gcp tests passed")
