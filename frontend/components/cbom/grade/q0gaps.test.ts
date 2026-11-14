/**
 * CB-23 PR-A: the Q0 gap list (Quantum risk -> Q0 gaps). Grouping by reason (largest first, server counts win over the
 * loaded page), age / cause / sub-reason text, pages flattened without duplicates, and the list rendered with its gate
 * hooks: every row with its reason and status, closed rows with their cause and the grade they closed to.
 * Run (frontend/): npx --yes tsx@4.23.15 components/cbom/grade/q0gaps.test.ts
 */
import assert from "node:assert/strict";
import React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

import {
  GRADE_KEYS,
  Q0GapList,
  ageText,
  causeText,
  flattenPages,
  groupByReason,
  subReasonText,
  type Q0Gap,
  type Q0GapPage,
} from "./index";

const [, , G2] = GRADE_KEYS;
const h = React.createElement;
const render = (el: React.ReactElement) =>
  renderToStaticMarkup(h(QueryClientProvider, { client: new QueryClient() }, el));

function gap(id: number, reason: string, extra: Partial<Q0Gap> = {}): Q0Gap {
  return {
    id, item_kind: "evidence", item_key: `evidence:area:a${id}`, reason, reason_text: null, sub_reason: null,
    title: `Item ${id}`, source_id: null, source_name: null, detail: {}, status: "open",
    opened_at: "2026-11-01T10:00:00Z", as_of: "2026-11-14", last_seen_at: "2026-11-14T10:00:00Z", closed_at: null,
    close_cause: null, closed_grade: null, forwarded: null, age_days: 13, run_id: null, ...extra,
  };
}

// grouping: largest group first, ties by code; server counts (all pages) win over the rows loaded so far
const rows = [gap(1, "evidence_e0"), gap(2, "coverage_gap"), gap(3, "evidence_e0"), gap(4, "unknown_verdict")];
const groups = groupByReason(rows, { evidence_e0: 2, coverage_gap: 5, unknown_verdict: 1, mosca_missing: 1 });
assert.deepEqual(groups.map((g) => [g.reason, g.total, g.items.length]), [
  ["coverage_gap", 5, 1], ["evidence_e0", 2, 2], ["mosca_missing", 1, 0], ["unknown_verdict", 1, 1],
]);
assert.deepEqual(groups[1].items.map((g) => g.id), [1, 3]); // the server's order is kept inside a group
assert.deepEqual(groupByReason([]).length, 0);

// texts
assert.equal(ageText(0), "today");
assert.equal(ageText(1), "1 day");
assert.equal(ageText(400), "400 days");
assert.equal(ageText(undefined), "today");
assert.equal(causeText("model_change"), "Grade model changed (not sent to integrations)");
assert.equal(causeText("removed"), "Removed (vendor or source deleted)");
assert.equal(causeText(null), "—");
assert.equal(causeText("future_cause"), "future_cause"); // an unseen value is printed as it came
assert.equal(subReasonText("evidence_expired"), "Evidence older than 12 months");
assert.equal(subReasonText(null), null);

// pages: a row repeated across a page boundary is listed once
const page = (items: Q0Gap[], next: string | null): Q0GapPage => ({
  status: "open", items, next_after: next, by_reason: {}, counts: { open: 3, closed: 0 }, server_time: "", source: "latest_runs",
});
assert.deepEqual(flattenPages([page([gap(1, "x"), gap(2, "x")], "c1"), page([gap(2, "x"), gap(3, "x")], null)])
  .map((g) => g.id), [1, 2, 3]);
assert.deepEqual(flattenPages(undefined), []);

// render: open list
const open = render(h(Q0GapList, {
  status: "open", model: null, byReason: { evidence_e0: 1, coverage_gap: 1 },
  items: [gap(7, "evidence_e0", { sub_reason: "no_answer", title: "Key hierarchy" }),
          gap(8, "coverage_gap", { item_kind: "scope", source_name: "src-b", title: "10.20.0.2" })],
}));
assert.match(open, /data-testid="q0-gap-group-evidence_e0" data-count="1"/);
assert.match(open, /data-testid="q0-gap-7" data-reason="evidence_e0" data-status="open"/);
assert.match(open, /Key hierarchy/);
assert.match(open, /Evidence · Unanswered/);
assert.match(open, /Unread scope · src-b/);
assert.match(open, /13 days/);

// render: closed list with cause and the grade it closed to
const closed = render(h(Q0GapList, {
  status: "closed", model: null,
  items: [gap(9, "unknown_verdict", { item_kind: "asset", status: "closed", closed_at: "2026-11-14T11:00:00Z",
                                      close_cause: "observation", closed_grade: G2, forwarded: true }),
          gap(10, "unknown_verdict", { item_kind: "asset", status: "closed", closed_at: "2026-11-14T11:00:00Z",
                                       close_cause: "model_change", closed_grade: null, forwarded: false })],
}));
assert.match(closed, /data-testid="q0-gap-9" data-reason="unknown_verdict" data-status="closed"/);
assert.match(closed, /Read again in a later collection/);
assert.match(closed, /Q2 High/);
assert.match(closed, /Grade model changed \(not sent to integrations\)/);

// empty states
assert.match(render(h(Q0GapList, { status: "open", items: [] })), /data-testid="q0-gaps-empty-open"/);
assert.match(render(h(Q0GapList, { status: "closed", items: [] })), /No closed Q0 gaps yet/);

console.log("q0gaps.test.ts: ok");
