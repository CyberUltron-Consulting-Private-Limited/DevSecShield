/**
 * Lab mode (CBOM_AWS_LAB_SAME_ACCOUNT on a test deployment): the AWS source form and every run of such a source carry
 * a banner that cannot be dismissed, with the backend's sentence (lab_mode.LAB_BANNER).
 * Run: npx --yes tsx components/cbom/sources/awsLabMode.test.ts
 */
import assert from "node:assert/strict"
import fs from "node:fs"
import path from "node:path"

const read = (p: string) => fs.readFileSync(path.join(__dirname, p), "utf8")
const banner = read("LabModeBanner.tsx")
const tab = read("CloudIdentityTab.tsx")
const run = read("RunResults.tsx")
const backend = read("../../../../backend/utilities/cbom_sources/lab_mode.py")
const sentence = "Lab mode: same-account collection — not for production"
assert.ok(banner.includes(`export const AWS_LAB_BANNER = "${sentence}";`), "the banner carries the sentence")
assert.ok(backend.includes(`LAB_BANNER = "${sentence}"`), "the backend says the same sentence")
assert.ok(banner.includes('role="alert"') && !/onClose|onDismiss|setOpen|useState|<button/.test(banner), "it cannot be dismissed")
// the form: shown whenever the AWS form is (settings say lab mode), above it
assert.ok(tab.includes('{form.provider === "aws" && !awsOff && settings.aws_lab_same_account === true && (\n            <LabModeBanner'),
  "the AWS form shows the banner when the deployment is in lab mode")
assert.ok(tab.indexOf('testId="aws-lab-mode"') < tab.indexOf("<AwsForm"), "above the form")
// every run of such a source: a banner on the run and a badge on the source's job
assert.ok(run.includes("{data.targets.some((job) => job.lab_mode) && (\n        <LabModeBanner testId=\"run-results-lab-mode\""),
  "a run with a lab-mode job shows the banner")
assert.ok(run.indexOf('testId="run-results-lab-mode"') < run.indexOf("<TargetsBlock"), "at the top of the run")
assert.ok(run.includes("{job.lab_mode && ("), "and the job is marked")
console.log("aws lab mode tests passed")
