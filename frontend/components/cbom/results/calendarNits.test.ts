/**
 * Follow-ups from the #285 review:
 * - the calendar's day badge and its aria-label count certificates after dedupeCerts, like the day's list;
 * - the run results template (RunCoverageSection, both the findings and all-assets views) carries the lab-mode note
 *   when any job of the run was read in lab mode, with the shared LabModeBanner; since the results redesign the hero
 *   carries it on every view but Collection (whose jobs card has it);
 * - the old Sources run page component (RunResults default export, with its own lab banner) is gone: it was rendered
 *   nowhere; the helpers other modules import from that file stay.
 * Run (frontend/): npx --yes tsx@4.23.15 components/cbom/results/calendarNits.test.ts
 */
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import { test } from "node:test";
import React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

import { fakeRunSource, renderRunMode, TARGETS } from "./__tests__/runModeFixture";
import CertCalendar from "../CertCalendar";
import { RunCoverageSection, RunJobsStatusLine } from "./RunSections";
import { SOURCE_CARD_FIELDS, sourceCardModels } from "./RunSourceCards";
import type { CbomJob, CbomJobTargets, CbomRun, CbomRunProvenance } from "@/utils/backend_api";

const h = React.createElement;
const read = (p: string) => readFileSync(path.join(__dirname, p), "utf8");
const web4 = (port: number) => ({
  subject: "CN=web4.lab", issuer: "CN=Lab CA", not_after: "2026-12-01T00:00:00Z",
  target: "10.20.0.14", location: `10.20.0.14:${port}#chain[0]`,
});

test("day badge and aria-label count deduped certificates", () => {
  const dup = renderToStaticMarkup(h(CertCalendar, { certs: [web4(443), web4(443)], now: new Date("2026-11-14T00:00:00Z"), testId: "cal" }));
  const day = dup.match(/<button[^>]*data-testid="cal-day-2026-12-01"[^>]*>.*?<\/button>/);
  assert.ok(day, "the day with the certificate is a button");
  assert.match(day![0], /aria-label="1 December 2026: 1 certificate expire/, day![0]);
  assert.ok(!/text-\[9px\][^>]*>2</.test(day![0]), `no "2" badge for one certificate reported twice: ${day![0]}`);
  // two ports are two certificates in place: the badge says 2
  const two = renderToStaticMarkup(h(CertCalendar, { certs: [web4(443), web4(8443)], now: new Date("2026-11-14T00:00:00Z"), testId: "cal" }));
  assert.match(two, /aria-label="1 December 2026: 2 certificates expire/);
});

const run = { id: 12, status: "done", jobs: [] } as unknown as CbomRun;
const job = (lab: string | null) => ({ job_id: 1, source_id: 3, source_name: "aws-lab", status: "done", outcome: "ok", attempt: 1,
  asset_count: 4, counts: null, summary: null, truncated: false, asset_mismatch: null, error: null, targets: [], duration_s: 3,
  lab_mode: lab }) as unknown as CbomJobTargets;
const coverage = (targets: CbomJobTargets[] | null) => renderToStaticMarkup(h(QueryClientProvider, { client: new QueryClient() },
  h(RunCoverageSection, { run, targets, provenance: [] })));

test("run results template shows the lab-mode note when a job ran in lab mode", () => {
  const html = coverage([job("same_account"), job(null)]);
  assert.match(html, /role="note"[^>]*data-testid="run-lab-mode"|data-testid="run-lab-mode"[^>]*role="note"/);
  assert.ok(html.indexOf('data-testid="run-lab-mode"') < html.indexOf('data-testid="run-results-job-1"'), "above the jobs' targets");
  assert.ok(!coverage([job(null)]).includes("run-lab-mode"), "no note without lab mode");
  assert.ok(!coverage(null).includes("run-lab-mode"), "no note before the targets load");
});

test("results redesign: every run view shows the lab-mode note once, above the jobs (hero; Collection: its jobs card)", () => {
  const job = (id: number, lab: string | null) => ({ ...TARGETS[0], job_id: id, lab_mode: lab });
  const lab = fakeRunSource({ page: { ...fakeRunSource().page!, targets: [job(1, "same_account"), job(2, null)] } });
  const summary = renderRunMode("", lab);
  assert.equal(summary.split('data-testid="run-lab-mode"').length - 1, 1);
  assert.match(summary, /role="note"[^>]*data-testid="run-lab-mode"|data-testid="run-lab-mode"[^>]*role="note"/);
  assert.ok(summary.indexOf('data-testid="run-lab-mode"') < summary.indexOf('data-testid="run-results-job-1"'), "above the jobs line");
  const collection = renderRunMode("section=collection", lab);
  assert.equal(collection.split('data-testid="run-lab-mode"').length - 1, 1, "the jobs card's note only");
  assert.ok(collection.indexOf('data-testid="run-lab-mode"') > collection.indexOf('data-testid="results-section-collection"'));
  const none = fakeRunSource({ page: { ...fakeRunSource().page!, targets: [job(1, null)] } });
  assert.ok(!renderRunMode("", none).includes("run-lab-mode"), "no note without lab mode");
});

// 03-B (run results redesign): one card per source; the full jobs and provenance tables stay one click away
const jobRow = (id: number, extra: Partial<CbomJob> = {}) => ({ id, run_id: 12, source_id: id + 100, source_name: `src-${id}`, node_id: 1,
  node_name: "node-dr1", kind: "collect", status: "success", waiting_reason: null, attempts: 1, credits: 2, refunded: false,
  created_at: null, claimed_at: null, finished_at: null, result: {}, error: null, outcome: "ok", asset_count: 9, runner: "node",
  samples: [], server_time: "", ...extra }) as CbomJob;
const prov = (sourceId: number, extra: Partial<CbomRunProvenance> = {}) => ({ source_id: sourceId, source: `src-${sourceId - 100}`, kind: "Appliance",
  node: "node-dr1", runner: "node", outcome: "ok", assets: 7, endpoints_probed: 3, duration_s: 0.3, credits: 2, ...extra }) as CbomRunProvenance;

test("source cards: a job with its source's provenance and targets; every field named once with its tip", () => {
  const runWithJobs = { ...run, jobs: [jobRow(1), jobRow(2, { status: "failure", error: "connection refused", attempts: 3, refunded: true,
    credits_refunded: 2, outcome: "failed" })] } as unknown as CbomRun;
  const targets = [{ ...job(null), job_id: 1, counts: { total: 1, ok: 1, failed: 0, skipped: 0 } }] as CbomJobTargets[];
  const html = renderToStaticMarkup(h(QueryClientProvider, { client: new QueryClient() },
    h(RunCoverageSection, { run: runWithJobs, targets, provenance: [prov(101), prov(999, { source: "orphan source" })] })));
  assert.match(html, /data-testid="run-source-cards"/);
  for (const id of ["1", "2"]) assert.match(html, new RegExp(`data-testid="run-source-card-${id}"`));
  const card1 = html.slice(html.indexOf('data-testid="run-source-card-1"'), html.indexOf('data-testid="run-source-card-2"')).replace(/<[^>]+>/g, " ");
  for (const t of ["src-1", "Appliance", "node-dr1", "Done", "Assets 9", "Assets (excl. not collected) 7", "Endpoints probed 3", "Duration",
    "Credits", "Attempts 1", "Outcome ok", "Targets: 1 fully read"]) assert.ok(card1.replace(/\s+/g, " ").includes(t), `${t}: ${card1}`);
  assert.match(html, /data-testid="run-source-card-error-2"/);
  // a provenance row no job names keeps its own card
  assert.ok(html.includes("orphan source"));
  // one key line, every field with the tip of the table column it comes from
  for (const f of SOURCE_CARD_FIELDS) assert.match(html, new RegExp(`data-infotip="${f.tip.replace(/\./g, "\\.")}"`), f.key);
  // the targets list (gate hooks run-results-job-<id>) is still on the view
  assert.match(html, /data-testid="run-results-job-1"/);
  // the full tables: a collapsed disclosure that names the region it opens
  const toggle = html.match(/<button[^>]*data-testid="run-coverage-tables-toggle"[^>]*>/)?.[0] ?? "";
  assert.match(toggle, /aria-expanded="false"/);
  const controls = toggle.match(/aria-controls="([^"]+)"/)?.[1];
  assert.ok(controls && html.includes(`id="${controls}"`), "aria-controls names the tables region");
  assert.ok(html.replace(/<[^>]+>/g, "").includes("Show the full jobs and provenance tables"));
  // the lab-mode note stays above the cards and the targets
  const lab = renderToStaticMarkup(h(QueryClientProvider, { client: new QueryClient() },
    h(RunCoverageSection, { run: runWithJobs, targets: [{ ...targets[0], lab_mode: "same_account" }], provenance: [] })));
  assert.ok(lab.indexOf('data-testid="run-lab-mode"') < lab.indexOf('data-testid="run-source-cards"'));
  // no job: the empty state, no cards
  assert.ok(coverage(null).includes("No jobs in this run"));
  assert.ok(!coverage(null).includes("run-source-cards"));
});

test("sourceCardModels pairs each job with its source's provenance once, keeps unmatched provenance rows", () => {
  const m = sourceCardModels([jobRow(1), jobRow(2)], [prov(102), prov(101), prov(101, { assets: 1 })], null);
  assert.deepEqual(m.map((x) => [x.job?.id ?? null, x.provenance?.source_id ?? null]), [[1, 101], [2, 102], [null, 101]]);
  assert.deepEqual(sourceCardModels([], null, null), []);
});

test("RunJobsStatusLine: one gate hook per job with the targets list's label", () => {
  const html = renderToStaticMarkup(h(RunJobsStatusLine, { targets: [{ ...job(null), counts: { total: 1, ok: 1 } },
    { ...job("same_account"), job_id: 2, status: "failure", outcome: "failed" }] as CbomJobTargets[], onOpen: () => undefined }));
  const t = (id: number) => (html.match(new RegExp(`<li[^>]*data-testid="run-results-job-${id}"[^>]*>(.*?)</li>`))?.[1] ?? "").replace(/<[^>]+>/g, " ");
  assert.match(t(1), /aws-lab/);
  assert.match(t(1), /All targets read/);
  assert.match(t(2), /Nothing read/);
  assert.match(t(2), /Failed/, "a job that did not finish says its status");
  assert.match(t(2), /Lab mode/);
  assert.match(html, /data-testid="run-jobs-status-open"/);
  assert.equal(renderToStaticMarkup(h(RunJobsStatusLine, { targets: null })), "");
  assert.equal(renderToStaticMarkup(h(RunJobsStatusLine, { targets: [] })), "");
});

test("the old Sources run page component is removed; its shared helpers stay", () => {
  const src = read("../sources/RunResults.tsx");
  assert.ok(!/export default function RunResults/.test(src), "no unrendered second results page");
  assert.ok(!src.includes("LabModeBanner"), "no second lab banner");
  for (const name of ["ASSET_TYPE_LABEL", "factsRows", "TargetsBlock", "TargetProblemRow", "ImpactBadge"]) {
    assert.match(src, new RegExp(`export (const|function) ${name}\\b`), name);
  }
});
