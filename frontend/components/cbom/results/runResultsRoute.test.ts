/**
 * Issue #158: every run "Results" link (Scans table and Review & Run) resolves to a route file of the Next.js app, and
 * that page renders the run results UI (RunResults). Resolves the link the way the App Router does: a static folder
 * first, else the one dynamic `[param]` folder; a link with no matching page.tsx is the staging 404.
 * Run: npx --yes tsx components/cbom/results/runResultsRoute.test.ts
 */
import assert from "node:assert/strict";
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { resultsHref, runResultsHref } from "./resultsHref";

const frontend = join(__dirname, "..", "..", "..");
const appDir = join(frontend, "app");

/** The page.tsx a URL path resolves to under app/, or null (a 404). Route groups and parallel routes are not used here. */
function resolvePage(urlPath: string): string | null {
  let dir = appDir;
  for (const segment of urlPath.split("/").filter(Boolean)) {
    const children = readdirSync(dir).filter((name) => statSync(join(dir, name)).isDirectory());
    const next = children.includes(segment)
      ? segment
      : children.find((name) => /^\[[^.\]]+\]$/.test(name));
    if (!next) return null;
    dir = join(dir, next);
  }
  const page = join(dir, "page.tsx");
  return existsSync(page) ? page : null;
}

test("the run results link resolves to the runs/[run_id]/results page, not to a 404", () => {
  for (const href of [runResultsHref(13, 8), runResultsHref("2", 5), resultsHref(2, { kind: "run", id: 5, scan_status: "success" })]) {
    const page = resolvePage(href);
    assert.ok(page, `${href} has a page.tsx`);
    assert.equal(page, join(appDir, "[team_id]", "cbom", "runs", "[run_id]", "results", "page.tsx"), href);
  }
});

test("a code scan's results link still resolves to the scan results page (run #5 and scan #5 differ)", () => {
  assert.equal(resolvePage(resultsHref(2, { kind: "scan", id: 5, scan_status: "success" })),
               join(appDir, "[team_id]", "cbom", "[scan_id]", "results", "page.tsx"));
  assert.equal(resolvePage(resultsHref(2, { kind: "scan", id: 5, scan_status: "started" })),
               join(appDir, "[team_id]", "cbom", "[scan_id]", "page.tsx"));
});

test("the run results page renders the existing RunResults UI for the route's team and run", () => {
  const src = readFileSync(join(appDir, "[team_id]", "cbom", "runs", "[run_id]", "results", "page.tsx"), "utf8");
  assert.ok(src.startsWith('"use client";'), "a client page (RunResults uses react-query hooks)");
  assert.ok(src.includes('import RunResults from "@/components/cbom/sources/RunResults";'));
  assert.ok(/<RunResults teamId=\{teamId as number\} runId=\{runId as number\} active=\{/.test(src));
  assert.ok(src.includes("params?.team_id") && src.includes("params?.run_id"), "ids come from the route's params");
  assert.ok(src.includes("export default function"), "a default export, so Next.js serves it");
  assert.ok(src.includes("delete when #120 merges"), "marked as the bridge PR #120 replaces");
  const runResults = readFileSync(join(frontend, "components", "cbom", "sources", "RunResults.tsx"), "utf8");
  assert.ok(runResults.includes("<RunPostureCard") && runResults.includes("<AssetDetailPanel"), "posture and asset detail come along");
  assert.ok(runResults.includes("QGradeChip") && runResults.includes("FixClassChip"), "#138's Q-grade and fix-class chips come along");
});

test("both run Results links use the helper this route answers", () => {
  const scans = readFileSync(join(appDir, "[team_id]", "cbom", "page.tsx"), "utf8");
  const review = readFileSync(join(frontend, "components", "cbom", "sources", "ReviewRunTab.tsx"), "utf8");
  assert.ok(scans.includes("resultsHref(team_id, row)"), "Scans table rows");
  assert.ok(review.includes("href={runResultsHref(teamId, run.id)}"), "Review & Run runs table");
});
