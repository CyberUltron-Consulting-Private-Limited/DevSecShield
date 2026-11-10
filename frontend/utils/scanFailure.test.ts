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
    "Create a new scan to run it again.",
);
// info stored as a JSON string
assert.equal(
  scanFailureMessage({ info: JSON.stringify({ error: "Clone failed." }) }),
  "The scan failed: Clone failed. Create a new scan to run it again.",
);
// an older server that sent scan_metadata.error_message
assert.equal(
  scanFailureMessage({ info: null, scan_metadata: { error_message: "boom" } }),
  "The scan failed: boom. Create a new scan to run it again.",
);
// nothing stored
assert.equal(scanFailureMessage({ info: null, scan_metadata: {} }), "The scan failed. Create a new scan to run it again.");
assert.equal(scanFailureMessage(undefined), "The scan failed. Create a new scan to run it again.");
assert.equal(scanFailureMessage({ info: { error: "   " } }), "The scan failed. Create a new scan to run it again.");
assert.equal(scanFailureMessage({ info: "not json" }), "The scan failed. Create a new scan to run it again.");
console.log("scanFailure tests passed");
