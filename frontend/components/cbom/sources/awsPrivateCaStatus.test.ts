/**
 * Issue #223 (staging, 14 Nov 2026):
 * (a) the "AWS Private CA (through a connected AWS account)" card said "Connected" for a CA whose AWS account could
 *     never be validated (each run: "Not read in this run ... Validate the AWS role first"). Its status now comes from
 *     the last real result of the AWS account that reads it: the newer of that account's last validation and its last
 *     collection (caCardStatus), "Not available" when the deployment has no AWS collection, "Not read" when the
 *     account was removed. Never a bare "Connected".
 * (b) "This ZeroShield deployment is not set up for AWS collection; contact your administrator" was a dead end for a
 *     SaaS customer: the sentence now says AWS collection isn't enabled on this deployment and names ZeroShield support.
 * Run: npx --yes tsx components/cbom/sources/awsPrivateCaStatus.test.ts
 */
import assert from "node:assert/strict"
import fs from "node:fs"
import path from "node:path"

import {
  AWS_NOT_CONFIGURED,
  AWS_SUPPORT_EMAIL,
  awsPrivateCaStatus,
  worstAwsPrivateCaStatus,
  type AwsAccountStatusInput,
} from "./awsPrivateCaStatus"

const NOW = new Date("2026-11-14T12:00:00Z")
const hoursAgo = (h: number) => new Date(NOW.getTime() - h * 3600_000).toISOString()
const account = (over: Partial<AwsAccountStatusInput> = {}): AwsAccountStatusInput => ({
  name: "Prod account",
  last_test_status: "never",
  last_test_at: null,
  last_test_summary: null,
  last_collect: null,
  ...over,
})

// (b) the sentence: not enabled on this deployment, who to contact, no "administrator"
assert.match(AWS_NOT_CONFIGURED, /AWS collection isn't enabled on this ZeroShield deployment/)
assert.ok(AWS_NOT_CONFIGURED.includes(AWS_SUPPORT_EMAIL), "names the support address")
assert.equal(AWS_SUPPORT_EMAIL, "support@zeroshield.ai")
assert.ok(!/administrator/i.test(AWS_NOT_CONFIGURED), "no administrator a SaaS customer does not have")
const backend = fs.readFileSync(path.join(__dirname, "../../../../backend/utilities/cbom_sources/templates.py"), "utf8")
assert.ok(backend.includes(JSON.stringify(AWS_NOT_CONFIGURED)), "the backend says the same sentence (templates.AWS_NOT_CONFIGURED)")

// (a) the deployment cannot do AWS: never Connected, the same reason as the AWS form
{
  const s = awsPrivateCaStatus(account({ last_test_status: "passed", last_test_at: hoursAgo(1) }), false, NOW)
  assert.equal(s.kind, "unavailable")
  assert.equal(s.label, "Not available")
  assert.equal(s.detail, AWS_NOT_CONFIGURED)
}

// (a) the AWS account it names was removed
{
  const s = awsPrivateCaStatus(null, true, NOW)
  assert.equal(s.kind, "removed")
  assert.equal(s.tone, "red")
  assert.equal(s.label, "Not read")
  assert.match(s.detail ?? "", /AWS account was removed/)
}

// (a) the issue's case: the AWS account's validation failed -> Failed, with the validation's own summary and time
{
  const s = awsPrivateCaStatus(account({ last_test_status: "failed", last_test_at: hoursAgo(2), last_test_summary: "Role could not be assumed" }), true, NOW)
  assert.equal(s.kind, "failed")
  assert.equal(s.label, "Failed")
  assert.equal(s.tone, "red")
  assert.equal(s.detail, "Last validation of AWS account Prod account: Failed, 14 Nov 2026, 10:00 UTC · Role could not be assumed")
}

// (a) never validated, never collected -> Not checked, saying what to do
{
  const s = awsPrivateCaStatus(account(), true, NOW)
  assert.equal(s.kind, "never")
  assert.equal(s.label, "Not checked")
  assert.equal(s.detail, "AWS account Prod account has not been validated or collected yet: validate it to read this CA")
}

// (a) a newer failed collection wins over an older passed validation (the last REAL read)
{
  const s = awsPrivateCaStatus(account({
    last_test_status: "passed", last_test_at: hoursAgo(5),
    last_collect: { status: "failed", at: hoursAgo(1), summary: "AccessDenied on acm-pca", job_id: 9, run_id: 3 },
  }), true, NOW)
  assert.equal(s.kind, "failed")
  assert.equal(s.detail, "Last collection of AWS account Prod account: Failed, 14 Nov 2026, 11:00 UTC · AccessDenied on acm-pca")
}

// (a) a passed validation is Passed; older than a day it is "Not checked since ..."
assert.equal(awsPrivateCaStatus(account({ last_test_status: "passed", last_test_at: hoursAgo(1) }), true, NOW).label, "Passed")
assert.equal(awsPrivateCaStatus(account({ last_test_status: "passed", last_test_at: hoursAgo(48) }), true, NOW).label,
  "Not checked since 12 Nov 2026, 12:00 UTC")
// a validation in progress
assert.equal(awsPrivateCaStatus(account({ last_test_status: "pending" }), true, NOW).kind, "testing")
// settings not loaded yet (undefined): judged on the account, not called unavailable
assert.equal(awsPrivateCaStatus(account({ last_test_status: "failed", last_test_at: hoursAgo(1) }), undefined, NOW).kind, "failed")
// no status ever says Connected
for (const st of ["never", "pending", "passed", "partial", "failed", "error"] as const) {
  assert.notEqual(awsPrivateCaStatus(account({ last_test_status: st, last_test_at: hoursAgo(1) }), true, NOW).label, "Connected")
}

// a row with several AWS Private CAs shows the worst
{
  const ok = awsPrivateCaStatus(account({ last_test_status: "passed", last_test_at: hoursAgo(1) }), true, NOW)
  const removed = awsPrivateCaStatus(null, true, NOW)
  const failed = awsPrivateCaStatus(account({ last_test_status: "failed", last_test_at: hoursAgo(1) }), true, NOW)
  assert.equal(worstAwsPrivateCaStatus([ok, failed]).kind, "failed")
  assert.equal(worstAwsPrivateCaStatus([ok, failed, removed]).kind, "removed")
  assert.equal(worstAwsPrivateCaStatus([ok]).kind, "passed")
}

// the tab uses it: the AWS Private CA row's header status, never the ConnectorRow default
const tab = fs.readFileSync(path.join(__dirname, "CloudIdentityTab.tsx"), "utf8")
assert.ok(tab.includes("worstAwsPrivateCaStatus("), "the AWS Private CA row header shows the derived status")
assert.ok(!tab.includes(': row.key === "aws_private_ca" ? undefined :'), "the AWS Private CA row no longer falls back to Connected")
// AWS-dependent cards are disabled with the same reason when the deployment has no AWS collection
assert.ok(tab.includes('unavailable={row.key === "aws_private_ca" && awsUnavailable ? AWS_NOT_CONFIGURED : undefined}'),
  "the AWS Private CA Connect is disabled with the reason")
assert.ok(tab.includes("data-testid={`${testId}-unavailable`}"), "the row says why it cannot be connected")
assert.ok(tab.includes('data-testid="cloud-accounts-aws-off"'), "the empty accounts card does not pitch AWS when it is off")
assert.ok(tab.includes(`href={\`mailto:\${AWS_SUPPORT_EMAIL}\`}`), "a link to support")

console.log("awsPrivateCaStatus: ok")
