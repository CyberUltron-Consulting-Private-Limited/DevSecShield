/**
 * Staging QA 15 Nov (689fdfb), CBOM Sources -> Fleet -> Transports -> Files to install: with no verified zs-collect
 * release, the page says only the role template and the signing key can be made, yet ansible-collection, salt-state,
 * ssm-document and zs-collect-manifest stayed clickable (dev d4dcf180 now disables them), and each click answered 400
 * and showed "Could not load the file": the files are fetched as text, so the server's JSON {"detail": ...} reached
 * refusalReason as a string.
 * Run: npx --yes tsx components/cbom/sources/fleet/transportFiles.test.ts
 */
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { refusalReason } from "../logic";
import { NEEDS_RELEASE } from "./transportsLogic";

// a refusal fetched with responseType "text": the body is still the server's JSON
const textRefusal = { response: { status: 400, data: '{"detail":"No verified zs-collect release is active in this deployment"}' } };
assert.equal(refusalReason(textRefusal), "No verified zs-collect release is active in this deployment");
assert.equal(refusalReason({ response: { status: 400, data: "not json" } }), null);
assert.equal(refusalReason({ response: { status: 400, data: '{"other": 1}' } }), null);
assert.equal(refusalReason({ response: { status: 403, data: { detail: "Forbidden here" } } }), "Forbidden here"); // unchanged
assert.equal(refusalReason({ response: { status: 500, data: '{"detail":"x"}' } }), null);                       // unchanged

// the files that need a release are the backend's NEEDS_RELEASE, read from its source
const backend = readFileSync(join(__dirname, "../../../../../backend/utilities/cbom_sources/transports/artifacts.py"), "utf8");
const m = backend.match(/^NEEDS_RELEASE\s*=\s*\{([^}]*)\}/m);
assert.ok(m, "NEEDS_RELEASE not found in artifacts.py");
const needs = [...m[1].matchAll(/"([^"]+)"/g)].map((x) => x[1]).sort();
assert.deepEqual([...NEEDS_RELEASE].sort(), needs);

// the section disables them while no release is active (dev's d4dcf180 did this part; checked here too)
const section = readFileSync(join(__dirname, "TransportsSection.tsx"), "utf8");
assert.ok(section.includes("const waiting = !data.release && NEEDS_RELEASE.has(name);") && section.includes("disabled={fetchFile.isPending || waiting}"),
  "the release-only files are not disabled without a release");
console.log("transportFiles.test.ts: ok");
