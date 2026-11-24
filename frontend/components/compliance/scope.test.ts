/**
 * Second review of #487 (n-b): a bank's AI BOM stores HIPAA / FDA §524B / GMLP reports whose every requirement is
 * out of scope. The AI BOM results page draws no bar for a framework that does not apply at all; a framework with
 * any requirement in scope keeps its bar (and its out-of-scope share). CBOM / SBOM matrices are unchanged.
 * Run: npx --yes tsx components/compliance/scope.test.ts
 */
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { appliesAtAll } from "./scope";

const none = { pass: 0, fail: 0, na: 0, coverage: null };
assert.equal(appliesAtAll({ ...none, out_of_scope: 12 }), false); // hipaa for a bank
assert.equal(appliesAtAll({ ...none, out_of_scope: 3, pass: 1 }), true);
assert.equal(appliesAtAll({ ...none, out_of_scope: 3, fail: 1 }), true);
assert.equal(appliesAtAll({ ...none, out_of_scope: 3, pass_with_evidence: 1 }), true);
assert.equal(appliesAtAll({ ...none, out_of_scope: 3, not_bom_evidenceable: 1 }), true);
assert.equal(appliesAtAll({ ...none, out_of_scope: 3, na: 1 }), true);
// counts missing but requirements listed: decided from the requirements
assert.equal(
  appliesAtAll({ ...none, requirements: [{ id: "a", title: "a", verdict: "out_of_scope" }] }),
  false,
);
assert.equal(
  appliesAtAll({
    ...none,
    requirements: [
      { id: "a", title: "a", verdict: "out_of_scope" },
      { id: "b", title: "b", verdict: "fail" },
    ],
  }),
  true,
);
// a framework with nothing at all is not hidden by this rule (the matrix shows what it was given)
assert.equal(appliesAtAll(none), true);

// wiring: the shared matrix filters only when asked, and the AI BOM wrapper asks
const here = path.dirname(new URL(import.meta.url).pathname);
const matrix = fs.readFileSync(path.join(here, "ComplianceMatrix.tsx"), "utf8");
assert.match(matrix, /hideOutOfScope\s*\?\s*[^:]*appliesAtAll/);
const aibom = fs.readFileSync(path.join(here, "..", "ai-bom", "AiBomVisualizations.tsx"), "utf8");
assert.match(aibom, /<ComplianceMatrix[\s\S]*?hideOutOfScope=\{hideOutOfScope\}[\s\S]*?\/>/);
assert.match(aibom, /<ComplianceCoverage compliance=\{compliance\} onAttest=\{onAttest\} hideOutOfScope \/>/);
const sbom = fs.readFileSync(path.join(here, "..", "SbomResults.tsx"), "utf8");
assert.doesNotMatch(sbom.split("<ComplianceCoverage")[1].split("/>")[0], /hideOutOfScope/); // SBOM unchanged

console.log("scope.test.ts: ok");
