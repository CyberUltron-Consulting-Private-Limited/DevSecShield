/**
 * CB-38 F1: one CBOM Scans table for code scans and CBOM Sources runs.
 * Run: npx --yes tsx components/cbom/results/resultRows.test.ts
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import type { CbomSourcesRun } from "../resultOrigin";
import type { CBOMConversation, RunListRow } from "../../../utils/backend_api";
import {
  NO_FILTERS,
  displayRiskScore,
  filterAndSortRows,
  matchesRiskTier,
  mergeResultRows,
  runProgress,
  runsLoadedNote,
  type ResultFilters,
  type RunResultRow,
} from "./resultRows";

function scan(id: number, over: Partial<CBOMConversation> = {}): CBOMConversation {
  return {
    id, title: `scan ${id}`, scan_status: "success", created_at: "2026-11-10T10:00:00Z", last_updated: "2026-11-10T10:05:00Z",
    estimated_credits: 4, average_risk_score: 6.8, branch: "main", repo_url: "https://github.com/acme/payments-api",
    owner_user_email: "dev@example.com", owner_user_full_name: "Dev One", total_quantum_vulnerable: 2,
    total_weak_algorithms: 1, zip_file_used: false, cbom_file_used: false, scan_binaries: false, info: null,
    risk_data: { total_critical: 1, total_high: 7, total_medium: 2, total_low: 0, total_quantum_vulnerable: 2 },
    scan_metadata: null, ...over,
  };
}

function run(id: number, over: Partial<RunListRow> = {}): RunListRow {
  return {
    kind: "run", id, title: `Sources run #${id} · lab-k8s-tier1, lab-k8s-tier2`,
    created_at: "2026-11-12T17:30:00Z", last_updated: "2026-11-12T17:32:00Z", finished_at: "2026-11-12T17:32:00Z",
    scan_status: "success", run_status: "done",
    risk_data: { total_critical: 3, total_high: 5, total_medium: 1, total_low: 0, total_informational: 4, total_quantum_vulnerable: 6 },
    average_risk_score: 7.4,
    sources: [{ id: 11, name: "lab-k8s-tier1", kind: "kubernetes" }, { id: 12, name: "lab-k8s-tier2", kind: "kubernetes" }],
    repo_url: null, branch: null, estimated_credits: 12, credits_refunded: 0,
    owner_user_email: "admin@example.com", owner_user_full_name: "Team Admin",
    asset_count: 36, endpoints_probed: 2, jobs_total: 2, jobs_done: 2, linked_scan_id: null, counts_basis: "as_collected",
    ...over,
  };
}

const f = (over: Partial<ResultFilters>): ResultFilters => ({ ...NO_FILTERS, ...over });
const keys = (rows: { key: string }[]) => rows.map((r) => r.key);

test("unique keys when a scan and a run share id 5", () => {
  const rows = mergeResultRows([scan(5)], [run(5)]);
  assert.equal(rows.length, 2);
  assert.deepEqual(new Set(keys(rows)), new Set(["scan-5", "run-5"]));
  assert.equal(new Set(keys(rows)).size, rows.length);
  const r = rows.find((x) => x.kind === "run") as RunResultRow;
  assert.equal(r.id, 5);
  assert.equal(r.branch, null);
  assert.equal(r.repo_url, null);
  assert.deepEqual(r.sources.map((s) => s.name), ["lab-k8s-tier1", "lab-k8s-tier2"]);
});

test("default order is newest first across both kinds", () => {
  const rows = mergeResultRows(
    [scan(1, { created_at: "2026-11-01T00:00:00Z" }), scan(2, { created_at: "2026-11-13T00:00:00Z" })],
    [run(9, { created_at: "2026-11-12T00:00:00Z" })],
  );
  assert.deepEqual(keys(rows), ["scan-2", "run-9", "scan-1"]);
});

test("search hits run source names, run number, scan repo and branch", () => {
  const rows = mergeResultRows(
    [scan(1, { title: "payments", repo_url: "https://github.com/acme/payments-api", branch: "release/2.1" })],
    [run(5), run(6, { title: "Sources run #6 · lab-adcs", sources: [{ id: 3, name: "lab-adcs", kind: "windows" }] })],
  );
  assert.deepEqual(keys(filterAndSortRows(rows, f({ search: "k8s-tier2" }))), ["run-5"]);
  assert.deepEqual(keys(filterAndSortRows(rows, f({ search: "LAB-ADCS" }))), ["run-6"]);
  assert.deepEqual(keys(filterAndSortRows(rows, f({ search: "#6" }))), ["run-6"]);
  assert.deepEqual(keys(filterAndSortRows(rows, f({ search: "payments-api" }))), ["scan-1"]);
  assert.deepEqual(keys(filterAndSortRows(rows, f({ search: "release/2" }))), ["scan-1"]);
  assert.deepEqual(keys(filterAndSortRows(rows, f({ search: "  " }))).length, 3);
  // a source name typed in the search never matches a scan
  assert.equal(filterAndSortRows(rows, f({ search: "lab-" })).every((r) => r.kind === "run"), true);
});

test("status filter includes Partial; run statuses are mapped", () => {
  const rows = mergeResultRows(
    [scan(1, { scan_status: "failure" }), scan(2, { scan_status: "success" })],
    [
      run(3, { scan_status: "partial", run_status: "partial" }),
      run(4, { scan_status: "started", run_status: "running", jobs_total: 4, jobs_done: 1 }),
      // an older or partial payload without the mapped status: mapped from run_status in the browser
      run(5, { scan_status: undefined as unknown as RunListRow["scan_status"], run_status: "failed" }),
    ],
  );
  assert.deepEqual(keys(filterAndSortRows(rows, f({ status: "partial" }))), ["run-3"]);
  assert.deepEqual(keys(filterAndSortRows(rows, f({ status: "started" }))), ["run-4"]);
  assert.deepEqual(new Set(keys(filterAndSortRows(rows, f({ status: "failure" })))), new Set(["scan-1", "run-5"]));
  assert.deepEqual(new Set(keys(filterAndSortRows(rows, f({ status: "success" })))), new Set(["scan-2"]));
  const active = rows.find((r) => r.key === "run-4") as RunResultRow;
  assert.deepEqual(runProgress(active), { done: 1, total: 4, pct: 25 });
});

test("risk tiers on average_risk_score across kinds", () => {
  const rows = mergeResultRows(
    [scan(1, { average_risk_score: 9.2 }), scan(2, { average_risk_score: 4.9 }), scan(3, { average_risk_score: null })],
    [run(4, { average_risk_score: 7 }), run(5, { average_risk_score: 5 }), run(6, { average_risk_score: 12 })],
  );
  assert.deepEqual(new Set(keys(filterAndSortRows(rows, f({ risk: "critical" })))), new Set(["scan-1", "run-6"]));
  assert.deepEqual(keys(filterAndSortRows(rows, f({ risk: "high" }))), ["run-4"]);
  assert.deepEqual(keys(filterAndSortRows(rows, f({ risk: "medium" }))), ["run-5"]);
  assert.deepEqual(keys(filterAndSortRows(rows, f({ risk: "low" }))), ["scan-2"]);
  assert.equal(filterAndSortRows(rows, f({ risk: "all" })).length, 6);
  assert.equal(displayRiskScore({ average_risk_score: 12 }), 10);
  assert.equal(displayRiskScore({ average_risk_score: 6.84 }), 6.8);
  assert.equal(matchesRiskTier(null, "low"), false);
});

test("the three sorts work across kinds", () => {
  const rows = mergeResultRows(
    [
      scan(1, { created_at: "2026-11-01T00:00:00Z", average_risk_score: 3, estimated_credits: 10 }),
      scan(2, { created_at: "2026-11-03T00:00:00Z", average_risk_score: null, estimated_credits: null }),
    ],
    [
      run(1, { created_at: "2026-11-02T00:00:00Z", average_risk_score: 8, estimated_credits: 2 }),
      run(7, { created_at: "2026-11-04T00:00:00Z", average_risk_score: 5, estimated_credits: 30 }),
    ],
  );
  assert.deepEqual(keys(filterAndSortRows(rows, f({ sort: "created_desc" }))), ["run-7", "scan-2", "run-1", "scan-1"]);
  assert.deepEqual(keys(filterAndSortRows(rows, f({ sort: "created_asc" }))), ["scan-1", "run-1", "scan-2", "run-7"]);
  assert.deepEqual(keys(filterAndSortRows(rows, f({ sort: "risk_desc" }))), ["run-1", "run-7", "scan-1", "scan-2"]);
  assert.deepEqual(keys(filterAndSortRows(rows, f({ sort: "risk_asc" }))), ["scan-2", "scan-1", "run-7", "run-1"]);
  assert.deepEqual(keys(filterAndSortRows(rows, f({ sort: "credits_desc" }))), ["run-7", "scan-1", "run-1", "scan-2"]);
  assert.deepEqual(keys(filterAndSortRows(rows, f({ sort: "credits_asc" }))), ["scan-2", "run-1", "scan-1", "run-7"]);
});

test("deploy skew: no runs_list_data builds one row per run from sources_runs", () => {
  const sourcesRuns: CbomSourcesRun[] = [
    { run_id: 5, job_id: 51, source_name: "lab-k8s-tier2", source_kind: "kubernetes", finished_at: "2026-11-12T17:32:00Z", asset_count: 20, endpoints_probed: 1 },
    { run_id: 5, job_id: 50, source_name: "lab-k8s-tier1", source_kind: "kubernetes", finished_at: "2026-11-12T17:31:00Z", asset_count: 16, endpoints_probed: 1 },
    { run_id: 4, job_id: 40, source_name: "lab-adcs", source_kind: "windows", finished_at: "2026-11-12T17:30:00Z", asset_count: 20, endpoints_probed: 0 },
  ];
  const rows = mergeResultRows([scan(5, { created_at: "2026-11-01T00:00:00Z" })], undefined, sourcesRuns);
  assert.deepEqual(keys(rows), ["run-5", "run-4", "scan-5"]);
  const r5 = rows[0] as RunResultRow;
  assert.equal(r5.title, "Sources run #5 · lab-k8s-tier1, lab-k8s-tier2");
  assert.equal(r5.limited, true);
  assert.equal(r5.run, null);
  assert.equal(r5.scan_status, "success");
  assert.equal(r5.asset_count, 36);
  assert.equal(r5.endpoints_probed, 2);
  assert.equal(r5.created_at, "2026-11-12T17:32:00Z");
  assert.equal(r5.risk_data, null);
  assert.equal(r5.average_risk_score, null);
  assert.equal(r5.estimated_credits, null);
  assert.deepEqual(keys(filterAndSortRows(rows, f({ search: "adcs" }))), ["run-4"]);
  // a backend that sends runs_list_data (even empty) is the only source: sources_runs is then ignored
  assert.deepEqual(keys(mergeResultRows([], [], sourcesRuns)), []);
  assert.deepEqual(keys(mergeResultRows(null, null, null)), []);
});

test("footer note only when runs were left out", () => {
  assert.equal(runsLoadedNote(200, 350), "200 newest runs loaded · 350 runs in total");
  assert.equal(runsLoadedNote(5, 5), null);
  assert.equal(runsLoadedNote(5, undefined), null);
});
