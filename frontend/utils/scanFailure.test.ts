/**
 * Hermetic tests for the scan failure reason shown in the scan sidebars.
 * Run: npx --yes tsx utils/scanFailure.test.ts
 */
import assert from "node:assert/strict";
import { scanFailureMessage } from "./scanFailure";

// what the lab returned for a failed SAST scan (GET /{team}/sast/scan/{id}): the reason is in info.error
assert.equal(
  scanFailureMessage({
    scan_status: "failure",
    info: { error: "Error occured while running agent : Error in getting vector store: QDRANT_API_KEY not found" },
    scan_metadata: { repo_url: null, zip_file_used: true },
  }),
  "The scan failed: Error occured while running agent : Error in getting vector store: QDRANT_API_KEY not found. " +
    "Use Run again to start it as a new scan with the same settings.",
);
// info stored as a JSON string
assert.equal(
  scanFailureMessage({ info: JSON.stringify({ error: "Clone failed." }) }),
  "The scan failed: Clone failed. Use Run again to start it as a new scan with the same settings.",
);
// an older server that sent scan_metadata.error_message
assert.equal(
  scanFailureMessage({ info: null, scan_metadata: { error_message: "boom" } }),
  "The scan failed: boom. Use Run again to start it as a new scan with the same settings.",
);
// nothing stored
assert.equal(scanFailureMessage({ info: null, scan_metadata: {} }), "The scan failed. Use Run again to start it as a new scan with the same settings.");
assert.equal(scanFailureMessage(undefined), "The scan failed. Use Run again to start it as a new scan with the same settings.");
assert.equal(scanFailureMessage({ info: { error: "   " } }), "The scan failed. Use Run again to start it as a new scan with the same settings.");
assert.equal(scanFailureMessage({ info: "not json" }), "The scan failed. Use Run again to start it as a new scan with the same settings.");
console.log("scanFailure tests passed");
