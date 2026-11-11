// Run: npx --yes tsx components/cbom/sources/fleet/fleetLogic.test.ts
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";

import { ALL_OFF, fleetTabVisible, pickTab, visibleSections } from "./fleetLogic";

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

// The registry keeps the markers F1.3 and F1.4 insert their sections under (contract section 5), and the page puts the
// Fleet tab before Review & Run.
const registry = readFileSync(join(__dirname, "sections.tsx"), "utf8");
for (const marker of ["// F1.3 import", "// F1.4 import", "  // F1.3\n", "  // F1.4\n"]) {
  assert.ok(registry.includes(marker), `sections.tsx lost the marker ${JSON.stringify(marker)}`);
}
const page = readFileSync(join(__dirname, "../../../../app/[team_id]/cbom/sources/page.tsx"), "utf8");
assert.ok(page.indexOf('value: "fleet"') > 0 && page.indexOf('value: "fleet"') < page.indexOf('value: "review"'));

console.log("fleetLogic tests passed");
