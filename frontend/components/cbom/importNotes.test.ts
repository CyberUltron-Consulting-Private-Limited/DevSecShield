/**
 * Hermetic tests for the uploaded-CBOM import notes (results card and scan sidebar).
 * Run: npx --yes tsx components/cbom/importNotes.test.ts
 */
import assert from "node:assert/strict";
import { importHeadline, importNoteLines, importReportHasNews, notCryptoNote } from "./importNotes";

// the local stack's report for a CycloneDX 1.5 file with two libraries (u2, round 5)
const cdx15 = {
  components_total: 2, crypto_assets: 0, imported: 0, skipped_not_crypto: 2, skipped_invalid: 0, duplicates: 0,
  truncated: false, spec_version: "1.5", notes: ["CycloneDX 1.5 has no cryptographic-asset type; export a 1.6 CBOM."],
};
assert.equal(importReportHasNews(cdx15), true);
assert.deepEqual(importNoteLines(cdx15), [cdx15.notes[0], notCryptoNote(2)]);
assert.equal(importHeadline(cdx15), "No cryptographic assets were imported from the uploaded file, so there are no findings.");

// the product's own CBOM re-uploaded: 27 of 27 imported, 19 libraries/config skipped, no engine note
const roundTrip = {
  components_total: 46, crypto_assets: 27, imported: 27, skipped_not_crypto: 19, skipped_invalid: 0, duplicates: 0,
  truncated: false, spec_version: "1.6", notes: [],
};
assert.equal(importReportHasNews(roundTrip), true, "the card shows although the engine wrote no note");
assert.deepEqual(importNoteLines(roundTrip), [notCryptoNote(19)]);
assert.equal(importHeadline(roundTrip), "27 of 27 cryptographic assets were imported from the uploaded file.");

// a clean import: nothing to say
const clean = { ...roundTrip, components_total: 27, skipped_not_crypto: 0 };
assert.equal(importReportHasNews(clean), false);
assert.deepEqual(importNoteLines(clean), []);
assert.equal(importReportHasNews(null), false);
assert.deepEqual(importNoteLines(undefined), []);
// a code scan (no import report) or an old report without counts
assert.equal(importReportHasNews({ truncated: true, spec_version: null, notes: [] }), true);
console.log("importNotes tests passed");
