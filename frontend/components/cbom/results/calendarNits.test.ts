/**
 * Follow-ups from the #285 review:
 * - the calendar's day badge and its aria-label count certificates after dedupeCerts, like the day's list;
 * - the run results template (RunCoverageSection, both the findings and all-assets views) carries the lab-mode note
 *   when any job of the run was read in lab mode, with the shared LabModeBanner;
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

import CertCalendar from "../CertCalendar";
import { RunCoverageSection } from "./RunSections";
import type { CbomJobTargets, CbomRun } from "@/utils/backend_api";

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

test("the old Sources run page component is removed; its shared helpers stay", () => {
  const src = read("../sources/RunResults.tsx");
  assert.ok(!/export default function RunResults/.test(src), "no unrendered second results page");
  assert.ok(!src.includes("LabModeBanner"), "no second lab banner");
  for (const name of ["ASSET_TYPE_LABEL", "factsRows", "TargetsBlock", "TargetProblemRow", "ImpactBadge"]) {
    assert.match(src, new RegExp(`export (const|function) ${name}\\b`), name);
  }
});
