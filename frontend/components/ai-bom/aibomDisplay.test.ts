/**
 * Staging QA round 2 (D5 AI BOM, live findings): the AI Governance subtitle follows the team's regulatory profile
 * (Q2-08 UI part), licence labels fit the licence chart (N5), and a provider-served model is still a model.
 * Run: npx --yes tsx components/ai-bom/aibomDisplay.test.ts
 */
import assert from "node:assert/strict";
import {
  applicabilityNote,
  bindingCompliance,
  governanceSubtitle,
  isHealthcareBom,
  licenceLabel,
  unnamedModelHint,
  completenessNotice,
} from "./aibomDisplay";
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
// no declared profile (review 6037909737 M4): nothing filtered, a clinical BOM keeps the healthcare wording
assert.match(governanceSubtitle(undefined, HEALTH_BOM), /^Healthcare AI BOM: /);
assert.match(governanceSubtitle(null, PLAIN_BOM), /^AI BOM: /);
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

// M3: the page keeps only the frameworks that bind the team, like the PDF and the pack
const compliance = { cert_in_aibom: {}, rbi_free_ai: {}, nist_rmf: {}, eu_ai_act_annexIV: {}, sebi_cscrf_aibom: {},
  fda_524b: {}, hipaa: {}, gmlp: {}, disclaimer: "advisory" };
const bank = { regulatory_profile: { entity: "bank", flags: [] }, basis: "Commercial bank in India, not SEBI-regulated",
  binding: ["cert_in_aibom", "rbi_free_ai", "nist_rmf", "eu_ai_act_annexIV"],
  not_applicable: [{ framework: "fda_524b", label: "FDA Section 524B" }, { framework: "hipaa", label: "HIPAA" },
    { framework: "gmlp", label: "FDA GMLP" }, { framework: "sebi_cscrf_aibom", label: "SEBI CSCRF" }] };
assert.deepEqual(Object.keys(bindingCompliance(compliance, bank) ?? {}).sort(),
  ["cert_in_aibom", "disclaimer", "eu_ai_act_annexIV", "nist_rmf", "rbi_free_ai"]);
assert.equal(bindingCompliance(compliance, null), compliance); // an older backend: unchanged
assert.match(applicabilityNote(bank) ?? "", /Not applicable to it: FDA Section 524B, HIPAA, FDA GMLP, SEBI CSCRF\./);
assert.match(applicabilityNote({ regulatory_profile: null, binding: Object.keys(compliance) }) ?? "",
  /regulated entity not set/);

// #498 round 3: ChatOpenAI() with no model runs the library default: the Models tile says so, never a silent 0
const unnamedBom = {
  metadata: {
    properties: [
      { name: "aibom:model_unnamed_calls", value: "2" },
      { name: "aibom:model_unnamed_library", value: "langchain 0.0.184" },
    ],
  },
};
assert.equal(unnamedModelHint(unnamedBom), "2 calls name no model: library default or configuration (langchain 0.0.184)");
// #498 round 4: the dashboard's split when the card carries it, and a strict count
assert.equal(unnamedModelHint(unnamedBom, { total: 3, unidentified: 2 }), "1 identified + 2 not identified (langchain 0.0.184)");
assert.equal(unnamedModelHint({ metadata: { properties: [{ name: "aibom:model_unnamed_calls", value: "2abc" }] } }), null);
assert.equal(unnamedModelHint(PLAIN_BOM, { total: 2, unidentified: 0 }), null);
assert.equal(
  unnamedModelHint({ metadata: { properties: [{ name: "aibom:model_unnamed_calls", value: "1" }] } }),
  "1 call names no model: library default or configuration",
);
assert.equal(unnamedModelHint(PLAIN_BOM), null);
assert.equal(unnamedModelHint(undefined), null);

// review 6063080163 R4-M2: a scanner that did not finish is said, and the grade withheld
assert.equal(completenessNotice(null), null);
assert.equal(
  completenessNotice({ status: "partial", scanner_errors: "model-ref: RuntimeError (unexpected)", notebooks_unreadable: "a.ipynb" }),
  "Scan incomplete: grade withheld. Did not finish: model-ref: RuntimeError (unexpected). Notebooks read as raw text (not valid notebooks): a.ipynb.",
);

console.log("aibomDisplay tests passed");
