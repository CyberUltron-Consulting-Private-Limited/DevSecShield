/**
 * Source metadata "Operated by" (CB-24): the single-source form round-trips us / vendor / not set (null), and the bulk
 * editor (Review & Run) keeps the value by default, sets us or vendor, or clears it with an explicit null (review
 * 5903702387: "Not set" there used to change nothing).
 * Run (frontend/): npx --yes tsx@4.23.15 components/cbom/sources/sourceMetadata.test.ts
 */
import assert from "node:assert/strict";

import { bulkMetadataChanges, metadataConfig, metadataFrom, type SourceMetadata } from "./SourceMetadata";

// single source: what the form loads and what it sends
assert.equal(metadataFrom({ operated_by: "vendor" }).operated_by, "vendor");
assert.equal(metadataFrom({ operated_by: "us" }).operated_by, "us");
assert.equal(metadataFrom({ operated_by: "Vendor" }).operated_by, "");  // not a value the API accepts
assert.equal(metadataFrom(null).operated_by, "");
const sent = (operated_by: SourceMetadata["operated_by"]) =>
  (metadataConfig({ ...metadataFrom(null), operated_by }) as Record<string, unknown>).operated_by;
assert.equal(sent("vendor"), "vendor");
assert.equal(sent("us"), "us");
assert.equal(sent(""), null);  // "Not set (our team)" clears the stored value

// bulk: "Keep" sends nothing, us / vendor set it, "Clear" sends null; other empty fields are left as they are
const draft = (patch: Partial<SourceMetadata> = {}): SourceMetadata => ({ ...metadataFrom(null), ...patch });
assert.ok(!("operated_by" in (bulkMetadataChanges(draft({ owner: "payments" }), "keep") as object)));
assert.deepEqual(bulkMetadataChanges(draft({ operated_by: "vendor" }), "keep"), { operated_by: "vendor" });
assert.deepEqual(bulkMetadataChanges(draft({ operated_by: "us" }), "keep"), { operated_by: "us" });
assert.deepEqual(bulkMetadataChanges(draft({ operated_by: "clear" }), "keep"), { operated_by: null });
assert.deepEqual(bulkMetadataChanges(draft({ owner: " ops ", data_lifetime_years: "7" }), "high"),
  { owner: "ops", data_lifetime_years: 7, business_criticality: "high" });
assert.equal(bulkMetadataChanges(draft(), "keep"), "Enter at least one value to set");
assert.equal(bulkMetadataChanges(draft({ data_lifetime_years: "101" }), "keep"), "Data lifetime: a whole number of years from 0 to 100");

console.log("sources/sourceMetadata.test.ts: ok");
