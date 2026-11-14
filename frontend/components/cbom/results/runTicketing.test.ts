/**
 * Hermetic tests for the Sources run Ticketing tab logic (CB-38 PR-4).
 * Run: npx --yes tsx components/cbom/results/runTicketing.test.ts
 */
import assert from "node:assert/strict";

import type { CbomRunTicketAsset, CbomSourcesTicketing } from "@/utils/backend_api";
import {
  batchFailure,
  batches,
  errorMessage,
  hasTicket,
  isTicketable,
  MAX_TICKETS_PER_REQUEST,
  mergeResults,
  normalizeProjectKey,
  outcomes,
  resultSummary,
  safeTicketUrl,
  selectableIds,
  ticketingState,
} from "./runTicketing";

function asset(id: number, extra: Partial<CbomRunTicketAsset> = {}): CbomRunTicketAsset {
  return {
    id, type: "tls_endpoint", cdx_type: "protocol", job_id: 1, source_id: 1, source_name: "src-a",
    target: "10.20.0.1", location: `10.20.0.1:${400 + id}`, name: null, algorithm: "TLS", key_size: null,
    protocol: "TLSv1.0", quantum_vulnerable: false, impact: "High", finding: "TLS 1.0 enabled",
    finding_codes: ["PROTO_TLS10"], facts: {}, ticket_key: null, ticket_url: null, ...extra,
  };
}

const settings: CbomSourcesTicketing = {
  connected: true, jira_project_key: "SEC", jira_issue_type: "Task", issue_type_default: "Task", is_admin: false,
  row_version: 3,
};

// the team's Jira state decides what the tab shows
assert.equal(ticketingState(undefined), "loading");
assert.equal(ticketingState({ ...settings, connected: false }), "not_connected");
assert.equal(ticketingState({ ...settings, connected: false, jira_project_key: null }), "not_connected");
assert.equal(ticketingState({ ...settings, jira_project_key: null }), "no_project");
assert.equal(ticketingState(settings), "ready");

// project key: the API's rule
assert.deepEqual(normalizeProjectKey(" sec "), { value: "SEC", error: null });
assert.deepEqual(normalizeProjectKey("10042"), { value: "10042", error: null });
assert.deepEqual(normalizeProjectKey("pay_ops"), { value: "PAY_OPS", error: null });
assert.deepEqual(normalizeProjectKey(""), { value: null, error: null }); // clears the project
for (const bad of ["S", "1SEC", "se c", "SEC;DROP", "0123", "X".repeat(33)]) {
  assert.equal(normalizeProjectKey(bad).value, null, bad);
  assert.ok(normalizeProjectKey(bad).error, bad);
}

// which rows can be ticketed
const clean = asset(1, { impact: null, quantum_vulnerable: false, finding: null, finding_codes: [] });
const pqc = asset(2, { impact: null, quantum_vulnerable: true });
const coverage = asset(3, { type: "coverage", impact: "Low" });
const weak = asset(4);
const ticketed = asset(5, { ticket_key: "SEC-9", ticket_url: "https://bank.atlassian.net/browse/SEC-9" });
assert.equal(isTicketable(clean), false);
assert.equal(isTicketable(pqc), true);
assert.equal(isTicketable(coverage), false);
assert.equal(isTicketable(weak), true);
assert.equal(hasTicket(ticketed), true);
assert.equal(hasTicket(weak), false);
assert.deepEqual(selectableIds([clean, pqc, coverage, weak, ticketed]), [2, 4]);

// batching at the API cap
const ids = Array.from({ length: 120 }, (_, i) => i + 1);
assert.deepEqual(batches(ids).map((b) => b.length), [MAX_TICKETS_PER_REQUEST, MAX_TICKETS_PER_REQUEST, 20]);
assert.deepEqual(batches([]), []);

// per-asset outcomes: one failure never hides the others
const merged = mergeResults([
  { created: [{ asset_id: 4, asset_key: "k4", ticket_key: "SEC-1", ticket_url: "https://bank.atlassian.net/browse/SEC-1" }],
    existing: [], failed: [{ asset_id: 2, asset_key: "k2", error: "Failed to create issue in Jira: issuetype" }] },
  { created: [], existing: [{ asset_id: 5, asset_key: "k5", ticket_key: "SEC-9", ticket_url: "https://bank.atlassian.net/browse/SEC-9" }],
    failed: [] },
]);
assert.equal(resultSummary(merged), "1 Jira issue created, 1 already had one, 1 failed");
assert.equal(resultSummary({ created: [], existing: [], failed: [] }), "Nothing to create");
const rows = outcomes(merged, [pqc, weak, ticketed]);
assert.deepEqual(rows.map((r) => [r.asset_id, r.state, r.ticket_key]), [[4, "created", "SEC-1"], [5, "existing", "SEC-9"], [2, "failed", null]]);
assert.equal(rows[0].label, "TLS · 10.20.0.1:404");
assert.match(rows[2].error ?? "", /issuetype/);
assert.equal(outcomes({ created: [], existing: [], failed: [{ asset_id: 99, error: "x" }] }, [])[0].label, "Asset #99");

// links: http(s) only
assert.equal(safeTicketUrl("https://bank.atlassian.net/browse/SEC-1"), "https://bank.atlassian.net/browse/SEC-1");
assert.equal(safeTicketUrl("javascript:alert(1)"), null);
assert.equal(safeTicketUrl("not a url"), null);
assert.equal(safeTicketUrl(null), null);

// skipped (not a finding) and deferred (retry) buckets
const withBuckets = mergeResults([
  { created: [], existing: [], failed: [], skipped: [{ asset_id: 1, reason: "Not a finding" }] },
  { created: [], existing: [], failed: [], deferred: [{ asset_id: 4, reason: "Not attempted (time limit); try again." }] },
]);
assert.equal(resultSummary(withBuckets), "1 to retry, 1 not a finding");
assert.deepEqual(outcomes(withBuckets, [clean, weak]).map((r) => [r.asset_id, r.state, r.error]),
  [[4, "deferred", "Not attempted (time limit); try again."], [1, "skipped", "Not a finding"]]);

// a batch that failed as a whole keeps the earlier batches' results and reports every asset of its own
const apiError = { response: { data: { detail: "No Jira project is set for CBOM Sources." } }, message: "Request failed with status code 400" };
assert.equal(errorMessage(apiError), "No Jira project is set for CBOM Sources.");
assert.equal(errorMessage(new Error("Network Error")), "Network Error");
assert.equal(errorMessage(null), "The request failed");
const kept = mergeResults([
  { created: [{ asset_id: 4, asset_key: "k4", ticket_key: "SEC-1", ticket_url: "https://bank.atlassian.net/browse/SEC-1" }], existing: [], failed: [] },
  batchFailure([2, 5], new Error("timeout of 0ms exceeded")),
]);
assert.equal(resultSummary(kept), "1 Jira issue created, 2 failed");
assert.deepEqual(kept.failed, [{ asset_id: 2, error: "timeout of 0ms exceeded" }, { asset_id: 5, error: "timeout of 0ms exceeded" }]);

console.log("runTicketing: all assertions passed");
