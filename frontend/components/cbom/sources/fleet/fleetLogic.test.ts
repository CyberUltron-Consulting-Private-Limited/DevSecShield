// Run: npx --yes tsx components/cbom/sources/fleet/fleetLogic.test.ts
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";

import { ALL_OFF, fleetTabState, fleetTabVisible, isNotFound, pickTab, visibleSections } from "./fleetLogic";

// The Fleet tab shows when any fleet feature is on; while the status loads, failed (an older server answers 404) or
// all flags are off, it is hidden.
assert.equal(fleetTabVisible(undefined), false);
assert.equal(fleetTabVisible(ALL_OFF), false);
assert.equal(fleetTabVisible({ ...ALL_OFF, inventory: true }), true);
assert.equal(fleetTabVisible({ ...ALL_OFF, ssh_ca: true }), true);

// Each section shows only while its own flag is on, in registry order.
const sections = [
  { id: "inventory", flag: "inventory" as const },
  { id: "policies", flag: "policies" as const },
  { id: "transports", flag: "transports" as const },
  { id: "ssh-ca", flag: "ssh_ca" as const },
];
assert.deepEqual(visibleSections(sections, undefined), []);
assert.deepEqual(visibleSections(sections, { ...ALL_OFF, policies: true, ssh_ca: true }).map((s) => s.id), ["policies", "ssh-ca"]);

// ?tab=fleet while the tab is hidden falls back to the first tab; an unknown tab too.
const tabs = ["scan-nodes", "servers", "fleet", "review"] as const;
assert.equal(pickTab("fleet", tabs, (t) => t !== "fleet"), "scan-nodes");
assert.equal(pickTab("fleet", tabs, () => true), "fleet");
assert.equal(pickTab("nope", tabs, () => true), "scan-nodes");
assert.equal(pickTab(null, tabs, () => true), "scan-nodes");
assert.equal(pickTab("review", tabs, (t) => t !== "fleet"), "review");

// A failed background refetch keeps the sections (TanStack keeps data and sets isError); only a failed first load
// shows the error block.
const flags = { ...ALL_OFF, inventory: true };
assert.equal(fleetTabState({ data: undefined, isError: false, isLoading: true }), "loading");
assert.equal(fleetTabState({ data: undefined, isError: true }), "error");
assert.equal(fleetTabState({ data: flags, isError: false }), "ok");
assert.equal(fleetTabState({ data: flags, isError: true }), "stale");

// Only a 404 (an older server) is not retried; a 429 or a network error keeps the app's retry policy.
assert.equal(isNotFound({ response: { status: 404 } }), true);
assert.equal(isNotFound({ response: { status: 429 } }), false);
assert.equal(isNotFound(new Error("Network Error")), false);
assert.equal(isNotFound(null), false);

// The registry keeps the markers F1.3 and F1.4 insert their sections under (contract section 5).
const registry = readFileSync(join(__dirname, "sections.tsx"), "utf8");
for (const marker of ["// F1.3 import", "// F1.4 import", "  // F1.3\n", "  // F1.4\n"]) {
  assert.ok(registry.includes(marker), `sections.tsx lost the marker ${JSON.stringify(marker)}`);
}

// The page wiring the helpers above rely on (architecture review): the tab is computed from the status query,
// filtered out of the tab list, and its content mounted only when shown; it sits before Review & Run.
const page = readFileSync(join(__dirname, "../../../../app/[team_id]/cbom/sources/page.tsx"), "utf8");
assert.ok(page.indexOf('value: "fleet"') > 0 && page.indexOf('value: "fleet"') < page.indexOf('value: "review"'));
assert.ok(page.includes("const showFleet = fleetTabVisible(useFleetStatus(teamId).data);"), "showFleet is not computed from the status");
assert.ok(page.includes('const shown = (value: TabValue) => value !== "fleet" || showFleet;'), "shown() lost the fleet rule");
assert.ok(page.includes("TABS.filter((t) => shown(t.value)).map((t) => ("), "the tab list is not filtered by shown()");
assert.ok(page.includes("pickTab(requested, TABS.map((t) => t.value), shown)"), "?tab= is not checked against shown()");
assert.ok(/\{showFleet && \(\s*<TabsContent value="fleet">/.test(page), "the Fleet content is mounted without showFleet");
assert.equal((page.match(/<TabsContent value="fleet">/g) ?? []).length, 1);

// FleetTab renders from the last data on a failed refetch, and keeps the app's 429 retry policy.
const tab = readFileSync(join(__dirname, "FleetTab.tsx"), "utf8");
assert.ok(tab.includes("const state = fleetTabState(status);"), "FleetTab does not use fleetTabState");
assert.ok(!tab.includes("status.isError ||"), "FleetTab replaces its sections on any error");
assert.ok(tab.includes("retry: (failureCount, error) => !isNotFound(error) && queryRetry(failureCount, error)"));

console.log("fleetLogic tests passed");
