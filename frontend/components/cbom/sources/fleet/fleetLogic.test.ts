// Run: npx --yes tsx components/cbom/sources/fleet/fleetLogic.test.ts
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";

import {
  actionText,
  ALL_OFF,
  conditionProblems,
  coverageGaps,
  decisionText,
  draftFromSelector,
  targetLabel,
  fleetTabMode,
  fleetTabShown,
  fleetTabState,
  isNotFound,
  pickTab,
  selectorFromDraft,
  selectorText,
  visibleSections,
} from "./fleetLogic";

// Each section shows only while its own flag is on, in registry order.
const sections = [
  { id: "inventory", flag: "inventory" as const },
  { id: "policies", flag: "policies" as const },
  { id: "transports", flag: "transports" as const },
  { id: "ssh-ca", flag: "ssh_ca" as const },
];
assert.deepEqual(visibleSections(sections, undefined), []);
assert.deepEqual(visibleSections(sections, { ...ALL_OFF, policies: true, ssh_ca: true }).map((s) => s.id), ["policies", "ssh-ca"]);

// The Fleet tab has four states (PR #34 UX review, threads 4547018316 and 4547018330): "on" only when a section that
// is registered here has its flag on, so nobody sees an empty tab; "off" when the flags say so or an older server
// answers 404; "pending" while the status loads or retries (a 429 waits for Retry-After); "error" when it failed.
const registered = [{ flag: "inventory" as const }, { flag: "policies" as const }];
const notFound = { response: { status: 404 } };
assert.equal(fleetTabMode({ data: undefined, isError: false }, registered), "pending");
assert.equal(fleetTabMode({ data: { ...ALL_OFF, inventory: true }, isError: false }, registered), "on");
assert.equal(fleetTabMode({ data: { ...ALL_OFF, inventory: true }, isError: true, error: new Error("x") }, registered), "on"); // stale
assert.equal(fleetTabMode({ data: ALL_OFF, isError: false }, registered), "off");
assert.equal(fleetTabMode({ data: { ...ALL_OFF, transports: true }, isError: false }, registered), "off"); // no section for it
assert.equal(fleetTabMode({ data: { ...ALL_OFF, inventory: true }, isError: false }, []), "off"); // nothing registered
assert.equal(fleetTabMode({ data: undefined, isError: true, error: notFound }, registered), "off");
assert.equal(fleetTabMode({ data: undefined, isError: true, error: new Error("Network Error") }, registered), "error");
// A deep link to ?tab=fleet waits on Fleet while the status is not known yet (loading, retrying, failed) instead of
// showing Scan nodes and then jumping; without the deep link an undecided tab stays hidden.
assert.equal(fleetTabShown("on", null), true);
assert.equal(fleetTabShown("off", "fleet"), false);
assert.equal(fleetTabShown("pending", "fleet"), true);
assert.equal(fleetTabShown("error", "fleet"), true);
assert.equal(fleetTabShown("pending", "servers"), false);
assert.equal(fleetTabShown("pending", null), false);
assert.equal(fleetTabShown("error", null), false);

// ?tab=fleet while the tab is hidden falls back to the first tab; an unknown tab too.
const tabs = ["scan-nodes", "servers", "fleet", "review"] as const;
assert.equal(pickTab("fleet", tabs, (t) => t !== "fleet"), "scan-nodes");
assert.equal(pickTab("fleet", tabs, () => true), "fleet");
assert.equal(pickTab("nope", tabs, () => true), "scan-nodes");
assert.equal(pickTab(null, tabs, () => true), "scan-nodes");
assert.equal(pickTab("review", tabs, (t) => t !== "fleet"), "review");
// The deep link while the status loads: Fleet, not the first tab.
assert.equal(pickTab("fleet", tabs, (t) => t !== "fleet" || fleetTabShown("pending", "fleet")), "fleet");

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
assert.ok(page.includes("const fleetMode = fleetTabMode(useFleetStatus(teamId), FLEET_SECTIONS);"), "the Fleet tab mode is not computed from the status and the registry");
assert.ok(page.includes("const showFleet = fleetTabShown(fleetMode, requested);"), "showFleet ignores the deep link while the status is unknown");
assert.ok(!page.includes("fleetTabVisible("), "page.tsx still treats loading as flag-off");
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
// No operator wording in what any member sees (UX review 4547018330).
for (const operatorWords of ["this deployment", "in this version", "none of its sections"]) {
  assert.ok(!tab.includes(operatorWords), `FleetTab shows operator wording: ${operatorWords}`);
}

// ---------------------------------------------------------------------------- policies (F1.2)
const draft = {
  mode: "all" as const,
  conditions: [
    { on: "tag" as const, key: " Env ", op: "eq" as const, value: "prod" },
    { on: "tag" as const, key: "team", op: "in" as const, value: "pay, ops," },
    { on: "field" as const, key: "region", op: "prefix" as const, value: "ap-" },
  ],
};
const sel = selectorFromDraft(draft);
assert.deepEqual(sel, {
  all: [
    { tag: "env", op: "eq", value: "prod" },
    { tag: "team", op: "in", value: ["pay", "ops"] },
    { field: "region", op: "prefix", value: "ap-" },
  ],
});
// A condition left half-done is never dropped (PR #81 UX review 4550301242): dropping it turned "Tag (empty) is prod"
// into {}, which matches every target. The form names the condition and sends nothing.
const halfDone = { ...draft, conditions: [...draft.conditions, { on: "tag" as const, key: "", op: "eq" as const, value: "prod" }] };
assert.deepEqual(conditionProblems(halfDone), ["Condition 4: enter a tag key"]);
assert.throws(() => selectorFromDraft(halfDone), /Condition 4: enter a tag key/);
assert.deepEqual(
  conditionProblems({
    mode: "any",
    conditions: [
      { on: "tag", key: "env", op: "eq", value: " " },
      { on: "tag", key: "team", op: "in", value: " , ," },
      { on: "field", key: "region", op: "prefix", value: "" },
      { on: "tag", key: "pci", op: "exists", value: "" },
    ],
  }),
  ["Condition 1: enter a value", "Condition 2: enter at least one value", "Condition 3: enter a value"],
);
assert.deepEqual(conditionProblems(draft), []);
assert.deepEqual(selectorFromDraft({ mode: "any", conditions: [] }), {}); // no condition at all: every target, as the form says
assert.deepEqual(selectorFromDraft({ mode: "any", conditions: [{ on: "tag", key: "x", op: "exists", value: "zzz" }] }), { tag: "x", op: "exists" });
assert.deepEqual(draftFromSelector(sel)?.conditions.map((c) => c.key), ["env", "team", "region"]);
assert.equal(draftFromSelector({ not: { tag: "env", op: "exists" } }), null); // edited as JSON
assert.equal(selectorText(sel), "env is prod and team is one of pay, ops and region starts with ap-");
assert.equal(selectorText({}), "every target");
assert.equal(actionText({ never_scan: true }), "Never scan");
assert.equal(
  actionText({ transport: "ssh", tier: 1, batch_size: 100, schedule: { frequency: "weekly", time_of_day: "02:00", weekday: 6, monthday: null } }),
  "Collect over SSH, tier 1, batches of 100; Sundays at 02:00",
);
const names = { "2": { name: "prod-never", priority: 90 }, "5": { name: "all-pay", priority: 10 } };
assert.equal(decisionText({ action: "never_scan", policy_id: 2, matched_policy_ids: [2, 5] }, names), "prod-never (priority 90) (also matched 1 more)");
assert.equal(decisionText({ action: "never_scan", policy_id: null, matched_policy_ids: [5] }, names), "Never-scan list (overrides 1 matching policy)");
assert.equal(decisionText({ action: "unmanaged", policy_id: null, matched_policy_ids: [] }, names), "No policy matches");
// A policy that won a target the list has not loaded the name of still says which one won.
assert.equal(decisionText({ action: "collect", policy_id: 9, matched_policy_ids: [9] }, names), "Policy #9");
// How the screens show these (the decision column, the winner in the detail, the layout at 1440/1024/768/390 px) is
// checked by rendering them (*.render.test.ts) and in a browser, not by reading the source.

// An AWS sync's gaps read as words, and only the scopes that were not read are listed.
assert.deepEqual(
  coverageGaps({
    "us-east-1": { ec2: "ok", kms: "denied" },
    "me-south-1": { ec2: "unreachable", rds: "skipped:region_unreachable" },
    "eu-west-1": { eks: "error:ThrottlingException", acm: "cancelled", secretsmanager: "something-new" },
  }),
  [
    "us-east-1/kms: access denied",
    "me-south-1/ec2: could not be reached",
    "me-south-1/rds: skipped (the region could not be reached)",
    "eu-west-1/eks: error ThrottlingException",
    "eu-west-1/acm: stopped (the sync ran out of time)",
    "eu-west-1/secretsmanager: something-new",
  ],
);
assert.deepEqual(coverageGaps(undefined), []);

// A wildcard certificate has no host name (live AWS finding): it is called by its domain, not by its ARN.
const arn = "arn:aws:acm:ap-south-1:1:certificate/x";
assert.equal(targetLabel({ hostname: null, address: null, external_id: arn, attributes: { domain: "*.bank.example" } }), "*.bank.example");
assert.equal(targetLabel({ hostname: "app-1.bank.local", address: "10.0.0.1", external_id: "srv-1", attributes: {} }), "app-1.bank.local");
assert.equal(targetLabel({ hostname: null, address: "10.0.0.1", external_id: "srv-1" }), "10.0.0.1");
assert.equal(targetLabel({ hostname: null, address: null, external_id: arn, attributes: { name: "prod/db-password" } }), "prod/db-password");
assert.equal(targetLabel({ hostname: null, address: null, external_id: arn, attributes: { key_id: "" } }), arn);

console.log("fleetLogic tests passed");
