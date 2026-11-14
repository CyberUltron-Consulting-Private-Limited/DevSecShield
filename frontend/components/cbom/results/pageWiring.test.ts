/**
 * CB-38: the CBOM Scans page and the CBOM Sources Review & Run tab are wired to the unified table (source checks, like
 * refusal.test.ts / scanCancel.test.ts).
 * Run: npx --yes tsx components/cbom/results/pageWiring.test.ts (from any directory)
 */
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";

const frontend = join(__dirname, "..", "..", "..");
const page = readFileSync(join(frontend, "app", "[team_id]", "cbom", "page.tsx"), "utf8");
const review = readFileSync(join(frontend, "components", "cbom", "sources", "ReviewRunTab.tsx"), "utf8");
const waves = readFileSync(join(frontend, "components", "cbom", "sources", "WavesControls.tsx"), "utf8");

/** The JSX of the run branch of the row's actions menu: from `{run ? (` to the scan branch. */
function runMenu(src: string): string {
  const start = src.indexOf("{run ? (\n                                    <DropdownMenuContent");
  assert.ok(start > 0, "the actions menu has a run branch");
  const end = src.indexOf(") : conversation ? (", start);
  assert.ok(end > start, "followed by the scan branch");
  return src.slice(start, end);
}

test("one table: no separate CBOM Sources runs block", () => {
  assert.ok(!page.includes('data-testid="cbom-sources-runs"'));
  assert.ok(!page.includes("CBOM Sources runs</h3>"));
  assert.ok(!page.includes("groupSourcesRuns"));
  assert.ok(page.includes("rowsFromListResponse(query.data)"), "rows come from the merged list (with the runs_list_error fallback)");
  assert.ok(page.includes("{RUNS_LIST_ERROR_NOTICE}"), "a failed run listing is said, not hidden");
  assert.ok(page.includes("No scans or runs yet"));
});

test("rows are keyed and test-id'd by the prefixed key", () => {
  assert.ok(page.includes("key={row.key}"));
  assert.ok(page.includes("data-testid={`cbom-result-${row.key}`}"));
  assert.ok(!page.includes("key={conversation.id}"));
  assert.ok(page.includes("resultsHref(team_id, row)"), "row click and title use resultsHref");
});

test("run rows have no rename or delete", () => {
  const menu = runMenu(page);
  assert.ok(menu.includes("View results"));
  assert.ok(menu.includes("Open in CBOM Sources"));
  assert.ok(!/Rename|Delete|handleRename|handleDelete/.test(menu), "no rename/delete in the run menu");
});

test("the list is keyed per team and not re-fetched on a timer; active runs use the cheap run poll", () => {
  assert.ok(page.includes("cbomResultsListKey(teamIdNumber)"));
  assert.ok(!page.includes('"cbom-conversations"'));
  const list = page.slice(page.indexOf("const query = useQuery({"), page.indexOf("});", page.indexOf("const query = useQuery({")));
  assert.ok(!list.includes("refetchInterval"), "the list query does not poll (its build loads every Sources asset)");
  assert.ok(page.includes("queryFn: () => getCbomRun(teamIdNumber, runId)"));
  assert.ok(page.includes('enabled: activeTab === "table"'));
  assert.ok(/refetchInterval: (\d+)/.test(page) && Number(/refetchInterval: (\d+)/.exec(page)![1]) >= 15000);
});

test("Review & Run Results opens the run results page; run changes refresh the list", () => {
  assert.match(review, /<Link href=\{runResultsHref\(teamId, run\.id\)\} data-testid=\{`review-run-details-\$\{run\.id\}`\}>/);
  assert.ok(!review.includes("setDetailsRunId"), "the dialog is no longer opened from the Runs table");
  assert.ok(review.includes("const invalidate = () => invalidateRunViews(queryClient, teamId);"), "cancel");
  assert.ok(review.includes("onSettled: () => invalidateRunViews(queryClient, teamId),"), "start");
  assert.ok(waves.includes("invalidateRunViews(queryClient, teamId);"), "status / wave changes");
});
