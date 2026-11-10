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
assert.ok(tab.includes('const awsOff = form.provider === "aws" && settings.aws_collection_configured === false;'),
  "one flag for AWS not configured")
assert.ok(tab.includes('{awsOff && ('), "the message shows when AWS is not configured")
assert.ok(tab.includes('settings.aws_collection_configured !== false && (\n            <AwsForm'), "the template form is hidden then")
// lab UI r1: the Validation side panel still said "Fill in the role ARN ... Validate connection" with no form on screen
assert.ok(tab.includes("awsNotConfigured={awsOff}"), "the side panel knows")
const panel = tab.slice(tab.indexOf("function ValidationPanel"), tab.indexOf("// ---------------------------------------------------------------------------- AWS"))
const off = panel.slice(panel.indexOf("if (awsNotConfigured && !view && !pending)"), panel.indexOf("{pending && ("))
assert.ok(panel.indexOf("if (awsNotConfigured && !view && !pending)") < panel.indexOf("Fill in the role ARN"), "checked before the form hint")
assert.ok(off.includes("Nothing to validate. {AWS_NOT_CONFIGURED}."), "the panel says the same sentence")
assert.ok(tab.includes('? "AWS collection is not set up on this deployment"'), "and its description")
console.log("aws not configured tests passed")
