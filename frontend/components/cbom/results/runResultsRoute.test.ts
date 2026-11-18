/**
 * Issue #158: every run "Results" link (Scans table and Review & Run) resolves to a route file of the Next.js app, and
 * that page renders the one results template (CbomResults with the run adapter; #166's bridge page rendered RunResults). Resolves the link the way the App Router does: a static folder
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

test("the run results link resolves to the one [scan_id]/results page, not to a separate run page", () => {
  const results = join(appDir, "[team_id]", "cbom", "[scan_id]", "results", "page.tsx");
  for (const href of [runResultsHref(13, 8), runResultsHref("2", 5), resultsHref(2, { kind: "run", id: 5, scan_status: "success" })]) {
    const page = resolvePage(href.split("?")[0]);
    assert.equal(page, results, href);
    assert.equal(href.includes("?run=1"), true, href);
  }
});

test("a code scan's results link still resolves to the scan results page (run #5 and scan #5 differ)", () => {
  assert.equal(resolvePage(resultsHref(2, { kind: "scan", id: 5, scan_status: "success" })),
               join(appDir, "[team_id]", "cbom", "[scan_id]", "results", "page.tsx"));
  assert.equal(resolvePage(resultsHref(2, { kind: "scan", id: 5, scan_status: "started" })),
               join(appDir, "[team_id]", "cbom", "[scan_id]", "page.tsx"));
});

test("the one results page renders CbomResults for a run, and the old run URLs only redirect", () => {
  const src = readFileSync(join(appDir, "[team_id]", "cbom", "[scan_id]", "results", "page.tsx"), "utf8");
  assert.ok(src.startsWith('"use client";'), "a client page (react-query hooks)");
  assert.ok(src.includes("asksForRun(search.toString())") && src.includes("<RunResultsRoute teamId={teamId} runId={scanId} />"));
  assert.ok(src.includes("router.replace(target)") && src.includes("runResultsHref(teamId, runId, search.toString())"), "run-<id> redirects");
  assert.ok(src.includes("scanErrorText(query.error)"), "a missing or forbidden code scan stays that message");
  const legacy = readFileSync(join(appDir, "[team_id]", "cbom", "runs", "[run_id]", "results", "page.tsx"), "utf8");
  assert.ok(legacy.includes("legacyRunResultsTarget") && legacy.includes("router.replace(target)"));
  assert.ok(!legacy.includes("CbomResults"), "the old /runs/ page is a redirect, not a second template");
  const route = readFileSync(join(frontend, "components", "cbom", "results", "RunResultsRoute.tsx"), "utf8");
  assert.ok(route.includes("useSourcesRunSource(teamId, runId,") && route.includes("<CbomResults data={undefined} teamId={String(teamId)} source={source} />"));
  const view = readFileSync(join(frontend, "components", "CbomResults.tsx"), "utf8");
  const views = (f: string) => readFileSync(join(frontend, "components", "cbom", "results", "views", f), "utf8");
  // results redesign: a run's header is ResultsHero, with the code scan's heading and test id
  const hero = views("ResultsHero.tsx");
  for (const src of [view, hero]) {
    assert.ok(src.includes('data-testid="cbom-results-title"') && src.includes("CBOM Scan Results"));
    assert.ok(!src.includes("run-results-title") && !src.includes("runTitle("), "a Sources run uses the code-scan heading");
  }
  assert.ok(view.includes("<ResultsHero"), "the template renders the hero for a run");
  assert.ok(views("SummaryView.tsx").includes("<PostureSummary") && view.includes("<RunFindingDialog"), "posture and the asset detail dialog come along");
  const table = readFileSync(join(frontend, "components", "cbom", "results", "RunFindingsTable.tsx"), "utf8");
  assert.ok(table.includes("<QGradeChip") && table.includes("<FixClassChip"), "#138's Q-grade and fix-class chips come along");
});

test("both run Results links use the helper this route answers", () => {
  const scans = readFileSync(join(appDir, "[team_id]", "cbom", "page.tsx"), "utf8");
  const review = readFileSync(join(frontend, "components", "cbom", "sources", "ReviewRunTab.tsx"), "utf8");
  assert.ok(scans.includes("resultsHref(team_id, row)"), "Scans table rows");
  assert.ok(review.includes("href={runResultsHref(teamId, run.id)}"), "Review & Run runs table");
});
