/**
 * Issue #224: the Sources page shows usage against the team's source cap, and warns near and at the cap.
 * Run: npx --yes tsx components/cbom/sources/sourceLimit.test.ts
 */
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";

import { sourceUsage } from "./sourceLimit";

assert.equal(sourceUsage(null), null);
assert.equal(sourceUsage(undefined), null);
const some = sourceUsage({ used: 145, max: 500, remaining: 355, setting: "CBOM_MAX_SOURCES" });
assert.deepEqual(some && { text: some.text, tone: some.tone }, { text: "145 of 500 sources", tone: "zinc" });
assert.match(some!.title, /can add 355 more sources \(limit 500, set by CBOM_MAX_SOURCES\)/);
assert.equal(sourceUsage({ used: 9_000, max: 10_000, remaining: 1_000, setting: "CBOM_MAX_SOURCES" })!.tone, "amber");
const full = sourceUsage({ used: 10_000, max: 10_000, remaining: 0, setting: "CBOM_MAX_SOURCES_TEAMS" })!;
assert.equal(full.text, "10,000 of 10,000 sources");
assert.equal(full.tone, "red");
assert.match(full.title, /reached its limit of 10,000 sources.*CBOM_MAX_SOURCES_TEAMS/);

// wired: the page header shows it, and the CMDB preview shows the over-limit count, the limit and the warnings
const here = path.dirname(new URL(import.meta.url).pathname);
const page = fs.readFileSync(path.join(here, "../../../app/[team_id]/cbom/sources/page.tsx"), "utf8");
assert.match(page, /sourceUsage\(/);
assert.match(page, /data-testid="cbom-source-usage"/);
const dialog = fs.readFileSync(path.join(here, "CmdbImportDialog.tsx"), "utf8");
assert.match(dialog, /counts\.over_limit/);
assert.match(dialog, /data-testid="cmdb-over-limit"/);
assert.match(dialog, /plan\.warnings/);
console.log("sourceLimit.test.ts: ok");
