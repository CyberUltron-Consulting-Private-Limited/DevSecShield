/**
 * The AWS form says the deployment is not set up for AWS collection instead of offering a CloudFormation template
 * that trusts the placeholder account 000000000000 (round 5, G3 item 6). Same sentence as the backend's
 * templates.AWS_NOT_CONFIGURED (template download 409, Validate).
 * Run: npx --yes tsx components/cbom/sources/awsNotConfigured.test.ts
 */
import assert from "node:assert/strict"
import fs from "node:fs"
import path from "node:path"

const tab = fs.readFileSync(path.join(__dirname, "CloudIdentityTab.tsx"), "utf8")
const backend = fs.readFileSync(path.join(__dirname, "../../../../backend/utilities/cbom_sources/templates.py"), "utf8")
const sentence = "This ZeroShield deployment is not set up for AWS collection; contact your administrator"
assert.ok(tab.includes(`"${sentence}"`), "the form carries the sentence")
assert.ok(backend.includes(`"${sentence}"`), "the backend says the same sentence")
assert.ok(tab.includes('settings.aws_collection_configured === false && ('), "the message shows when AWS is not configured")
assert.ok(tab.includes('settings.aws_collection_configured !== false && (\n            <AwsForm'), "the template form is hidden then")
console.log("aws not configured tests passed")
