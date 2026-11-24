/**
 * Staging QA round 2 (D5 AI BOM, live findings): the AI Governance subtitle follows the team's regulatory profile
 * (Q2-08 UI part), licence labels fit the licence chart (N5), and a provider-served model is still a model.
 * Run: npx --yes tsx components/ai-bom/aibomDisplay.test.ts
 */
import assert from "node:assert/strict";
import { governanceSubtitle, isHealthcareBom, licenceLabel } from "./aibomDisplay";
import { inventoryModelNames } from "./modelCardDisplay";

const HEALTH_BOM = {
  metadata: {
    properties: [
      {
        name: "regulatory:disclaimer",
        value: "Regulatory mappings are advisory only; … does not by itself satisfy FDA, EU AI Act, or HIPAA obligations.",
      },
    ],
  },
};
const PLAIN_BOM = {
  metadata: { properties: [{ name: "regulatory:disclaimer", value: "… does not by itself satisfy EU AI Act, NIST AI RMF or RBI" }] },
};

// Q2-08 UI: a bank or an NBFC never reads "Healthcare AI-BOM insights", even for a clinical scan
for (const entity of ["bank", "nbfc", "sfb", "payments_bank", "ucb", "aifi", "credit_info_company"]) {
  for (const bom of [HEALTH_BOM, PLAIN_BOM]) {
    const text = governanceSubtitle(entity, bom);
    assert.ok(!/healthcare/i.test(text), `${entity}: ${text}`);
  }
}
assert.match(governanceSubtitle("bank", PLAIN_BOM), /^Commercial bank AI BOM: /);
assert.match(governanceSubtitle("nbfc", PLAIN_BOM), /^NBFC AI BOM: /);
// an "other" entity with a clinical BOM keeps the healthcare wording; without one it is neutral
assert.match(governanceSubtitle("other", HEALTH_BOM), /^Healthcare AI BOM: /);
assert.match(governanceSubtitle("other", PLAIN_BOM), /^AI BOM: /);
// the profile not loaded (or not readable by this user): neutral, never healthcare
assert.match(governanceSubtitle(undefined, HEALTH_BOM), /^AI BOM: /);
assert.equal(isHealthcareBom(HEALTH_BOM), true);
assert.equal(isHealthcareBom(PLAIN_BOM), false);
assert.equal(isHealthcareBom(undefined), false);

// N5: every licence gets a short, readable axis label; the full id stays available for the tooltip
assert.equal(licenceLabel("LicenseRef-proprietary"), "proprietary");
assert.equal(licenceLabel("LicenseRef-llama-community"), "llama community");
assert.equal(licenceLabel("Apache-2.0"), "Apache-2.0");
assert.equal(licenceLabel("NOASSERTION"), "unknown (not resolved)");
const long = licenceLabel("LicenseRef-Mistral-AI-Non-Production-License");
assert.ok(long.length <= 24, long);
assert.ok(long.endsWith("…"), long);
// the findings table's badge uses a shorter label (its title keeps the full id)
assert.ok(licenceLabel("LicenseRef-Mistral-AI-Non-Production-License", 16).length <= 16);
assert.equal(licenceLabel("NOASSERTION", 16), "unknown");

// Q2-06: an API model typed external_provider is still counted as a model (component_kind)
const names = inventoryModelNames([
  { component_name: "anthropic.claude-3-5-sonnet-20240620-v1:0", component_type: "external_provider", component_kind: "model" },
  { component_name: "Amazon Bedrock Runtime", component_type: "external_provider", component_kind: "cloud_service" },
  { component_name: "w.safetensors", component_type: "local_model_file", component_kind: "model_file" },
]);
assert.ok(names.has("anthropic.claude-3-5-sonnet-20240620-v1:0"));
assert.ok(!names.has("Amazon Bedrock Runtime"));

console.log("aibomDisplay tests passed");
