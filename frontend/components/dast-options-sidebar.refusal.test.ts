/**
 * X1 (round 5 customer walkthrough): on a DAST scan, a refused "Estimate credits required" (target "not-a-url" ->
 * 400 "Only http:// and https:// URLs can be scanned", or a private/internal target refused by design) switched the
 * whole options panel to the error view; its only button, "Try Again", reloads the page and the customer lost the
 * target URL, login URL, three XPaths, username and password. A refused start did the same.
 * Now a refused estimate or start keeps the filled-in form and says the reason under the estimate button; editing
 * any input clears it.
 * Browser check after a rebuild: DAST scan > target http://172.17.0.4:8443 + auth fields > Estimate: the refusal is
 * shown under the button (data-testid="dast-request-error") and every field keeps its value.
 * Run: npx --yes tsx components/dast-options-sidebar.refusal.test.ts
 */
import assert from "node:assert/strict"
import fs from "node:fs"
import path from "node:path"

const src = fs.readFileSync(path.join(__dirname, "dast-options-sidebar.tsx"), "utf8")
const block = (start: string, end: string) => src.slice(src.indexOf(start), src.indexOf(end, src.indexOf(start)))

const estimate = block("const estimateCreditsMutation = useMutation({", "const handleStartScan")
const estimateError = estimate.slice(estimate.indexOf("onError"))
assert.ok(estimateError.includes("setErrorMessage(handleApiError(err).message);"), "the refusal reason is kept")
assert.ok(!estimateError.includes('setOptionsSidebarState("error")'), "a refused estimate does not open the error view")

const start = block("const startScanMutation = useMutation({", "/** Reset estimation")
const startError = start.slice(start.indexOf("onError"))
assert.ok(startError.includes('setOptionsSidebarState("ready");'), "a refused start goes back to the filled-in form")
assert.ok(!startError.includes('setOptionsSidebarState("error")'), "a refused start does not open the error view")

const reset = block("/** Reset estimation", "const displayCredits")
assert.ok(reset.includes("setErrorMessage(null);"), "changing an input clears the old refusal")

const hint = src.indexOf("<ScanInputHint validation={validateScanInputs()} />")
const shown = src.indexOf('data-testid="dast-request-error"')
assert.ok(shown > hint && shown - hint < 250, "the refusal is rendered right under the estimate hint")
assert.ok(src.includes('{errorMessage && optionsSidebarState === "ready" && ('), "only in the form view")

console.log("dast refusal keeps the form: tests passed")
