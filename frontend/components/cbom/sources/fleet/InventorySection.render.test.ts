// Run: npx --yes tsx components/cbom/sources/fleet/InventorySection.render.test.ts
// The inventory as a customer uses it (PR #81 UX review 5874305598, PR #80 round 2 shapes), rendered in jsdom.
// The layout at 1440/1024/768/390 px is measured in a browser (bounding boxes), not here: jsdom has no layout.
import { FakeApi, button, byId, click, press, render, run, settle, text, type } from "./testing/harness";

import assert from "node:assert/strict";
import { createElement } from "react";

import InventorySection from "./InventorySection";

const TEAM = 11;
const FRESH = { evaluated_at: "2026-11-12T10:00:00Z", stale: false, evaluation_requested: false, reconcile_requested: false, last_reconcile: {} };
const DECISION = { action: "collect", policy_id: 41, matched_policy_ids: [41, 42], transport: "ssh", transport_id: null, credential_id: 3, node_id: 7,
  node_segment: null, tier: 1, schedule: null, batch_size: 100, reason: "Policy 'prod-collect' (priority 100): collect over SSH" };
function target(id: number, extra: Record<string, unknown> = {}) {
  return { id, inventory_source_id: 1, external_id: `h${id}`, kind: "linux_host", address: `10.0.0.${id}`, addresses: [`10.0.0.${id}`], hostname: null,
    tags: { env: "prod" }, account_id: null, region: null, platform: null, handles: {}, attributes: {}, first_seen_at: null, last_seen_at: null,
    missing_since: null, deleted_at: null, managed_source_id: 9, pending: false, pending_since: null, decision: DECISION, ...extra };
}
const SOURCE = { id: 1, kind: "aws", name: "aws-prod", config: { aws_account_source_id: 2, regions: ["ap-south-1"], services: ["ec2"] }, enabled: true,
  sync_every_min: 60, last_sync_at: null, last_sync_status: "ok", last_sync_summary: {}, coverage: {}, syncing: false, target_count: 3, row_version: 1,
  created_at: null, last_updated: null };
const NAMES = { "41": { name: "prod-collect", priority: 100, enabled: true, deleted: false }, "42": { name: "all", priority: 1, enabled: true, deleted: false } };

function api(targets: unknown[] = [target(1), target(2)], evaluation: unknown = FRESH): FakeApi {
  const fake = new FakeApi()
    .on("get", /\/inventory\/targets$/, { data: { targets, next_cursor: null, total: targets.length, policies: NAMES, evaluation } })
    .on("get", /\/inventory\/targets\/\d+$/, (req) => {
      const id = Number(req.url.split("/").at(-1));
      return { data: { target: target(id), decision: DECISION, matched_policies: [{ id: 41, name: "prod-collect", priority: 100, won: true }, { id: 42, name: "all", priority: 1, won: false }], managed_source: { id: 9, name: "fleet-prod-1" } } };
    })
    .on("get", /\/inventory\/sources$/, { data: { sources: [SOURCE], aws_accounts: [{ id: 2, name: "prod", validated: true }] } })
    .on("patch", /\/inventory\/sources\/\d+$/, { data: { source: { ...SOURCE, enabled: false } } })
    .on("delete", /\/inventory\/sources\/\d+$/, { data: { deleted: 1, targets_removed: 3, evaluation: "done", decisions_changed: 3 } });
  fake.install();
  return fake;
}

const show = () => render(createElement(InventorySection, { teamId: TEAM, status: { inventory: true, policies: true, transports: false, ssh_ca: false } }));
const lastTargetsParams = (fake: FakeApi) => fake.calls("get", /\/inventory\/targets$/).at(-1)?.params ?? {};

run(
  [
    ["the tag filter sends the key and the value apart, so a key may contain colons", async () => {
      const fake = api();
      await show();
      await type(byId("fleet-tag-key"), "aws:cloudformation:stack-name");
      await type(byId("fleet-tag-value"), "web:blue");
      await settle(450); // typing is debounced
      const params = lastTargetsParams(fake);
      assert.equal(params.tag_key, "aws:cloudformation:stack-name");
      assert.equal(params.tag_value, "web:blue");
      assert.equal(params.tag, undefined, "the old tag=key:value parameter is still sent");
    }],
    ["each target says which policy won, and the detail lists the matches in order", async () => {
      api();
      await show();
      assert.match(text(), /prod-collect \(priority 100\) \(also matched 1 more\)/);
      await click(button("10.0.0.1"));
      const detail = document.querySelector('[data-testid="fleet-target-decision"]')?.textContent ?? "";
      assert.match(detail, /prod-collect · priority 100 · won/);
      assert.match(detail, /all · priority 1 · overridden/);
    }],
    ["no tag value is sent without a tag key", async () => {
      const fake = api();
      await show();
      await type(byId("fleet-tag-key"), "env");
      await type(byId("fleet-tag-value"), "prod");
      await settle(450);
      assert.equal(lastTargetsParams(fake).tag_value, "prod");
      await type(byId("fleet-tag-key"), "");
      await settle(450);
      assert.equal(lastTargetsParams(fake).tag_key, undefined);
      assert.equal(lastTargetsParams(fake).tag_value, undefined, "a value was sent without its key");
    }],
    ["the waiting badge wraps in a narrow decision column (390 px: 139 px wide, the badge 159 px)", async () => {
      api([target(1, { pending: true, pending_since: "2026-11-12T10:00:00Z" })]);
      await show();
      const badge = [...document.querySelectorAll('[data-testid="fleet-target-1"] [data-slot="badge"]')]
        .find((b) => /Waiting for a running job/.test(b.textContent ?? ""));
      assert.ok(badge, "no waiting badge");
      assert.ok(badge.classList.contains("whitespace-normal") && !badge.classList.contains("whitespace-nowrap"),
        `the badge cannot wrap: ${badge.className}`);
    }],
    ["closing a source's Delete confirm gives the focus back to its Delete button", async () => {
      api();
      await show();
      for (const how of ["Escape", "Cancel"]) {
        const del = button("Delete aws-prod");
        await click(del);
        const confirm = document.querySelector<HTMLElement>('[role="dialog"]');
        assert.ok(confirm, "Delete opened no confirm");
        if (how === "Escape") await press("Escape");
        else await click([...confirm.querySelectorAll("button")].find((b) => b.textContent?.trim() === "Cancel")!);
        assert.ok(document.querySelector('[role="dialog"]') === null, `${how} did not close the confirm`);
        assert.ok(document.activeElement === del, `${how}: focus went to ${document.activeElement?.tagName}`);
      }
    }],
    ["a target waiting for a running job and a removed target say so", async () => {
      api([target(1, { pending: true, pending_since: "2026-11-12T10:00:00Z" }), target(2, { deleted_at: "2026-11-12T09:00:00Z", missing_since: "2026-11-12T09:00:00Z" })]);
      await show();
      const row1 = document.querySelector('[data-testid="fleet-target-1"]')?.textContent ?? "";
      const row2 = document.querySelector('[data-testid="fleet-target-2"]')?.textContent ?? "";
      assert.match(row1, /Waiting for a running job/);
      assert.match(row2, /Removed/);
    }],
    ["while a large team's decisions are being updated, the targets say so and refresh", async () => {
      const fake = api([target(1)], { ...FRESH, stale: true, evaluation_requested: true });
      await show();
      assert.match(text(), /being updated/);
      const before = fake.calls("get", /\/inventory\/targets$/).length;
      fake.on("get", /\/inventory\/targets$/, { data: { targets: [target(1)], next_cursor: null, total: 1, policies: NAMES, evaluation: FRESH } });
      await settle(3600);
      assert.ok(fake.calls("get", /\/inventory\/targets$/).length > before, "the targets do not refresh while stale");
      assert.doesNotMatch(text(), /being updated/);
    }],
    ["closing Import, Discover from AWS or a target's detail gives the focus back to what opened it", async () => {
      api();
      await show();
      for (const name of ["Import CSV / JSON", "Discover from AWS", "10.0.0.2"]) {
        const opener = button(name);
        await click(opener);
        assert.ok(document.querySelector('[role="dialog"]'), `${name} opened no dialog`);
        await press("Escape");
        assert.ok(document.querySelector('[role="dialog"]') === null, `${name}: Escape did not close it`);
        assert.ok(document.activeElement === opener, `${name}: focus went to ${document.activeElement?.tagName}`);
      }
    }],
    ["pausing a source refreshes the sources, not the targets", async () => {
      const fake = api();
      await show();
      const targetsBefore = fake.calls("get", /\/inventory\/targets$/).length;
      const sourcesBefore = fake.calls("get", /\/inventory\/sources$/).length;
      await click(button("Pause aws-prod"));
      await settle(60);
      assert.ok(fake.calls("get", /\/inventory\/sources$/).length > sourcesBefore, "the sources were not refreshed");
      assert.equal(fake.calls("get", /\/inventory\/targets$/).length, targetsBefore, "pausing a source refetched the targets");
    }],
    ["deleting a source says its targets leave the inventory at once, and refreshes the targets", async () => {
      const fake = api();
      await show();
      await click(button("Delete aws-prod"));
      assert.match(document.querySelector('[role="alertdialog"], [role="dialog"]')?.textContent ?? "", /removed from the inventory/);
      const before = fake.calls("get", /\/inventory\/targets$/).length;
      await click(button("Delete"));
      await settle(60);
      assert.equal(fake.calls("delete", /\/inventory\/sources\/1$/).length, 1);
      assert.ok(fake.calls("get", /\/inventory\/targets$/).length > before, "the targets were not refreshed");
    }],
    ["a sync that finishes brings its targets into the list without a reload", async () => {
      const fake = api();
      fake.on("get", /\/inventory\/sources$/, { data: { sources: [{ ...SOURCE, syncing: true, last_sync_status: "running" }], aws_accounts: [] } });
      await show();
      const before = fake.calls("get", /\/inventory\/targets$/).length;
      fake.on("get", /\/inventory\/sources$/, { data: { sources: [{ ...SOURCE, last_sync_at: "2026-11-12T11:00:00Z" }], aws_accounts: [] } });
      await settle(5600); // a syncing source is polled every 5 s
      assert.ok(fake.calls("get", /\/inventory\/targets$/).length > before, "the finished sync's targets were not fetched");
    }],
    ["an import names the targets another source owns", async () => {
      const fake = api();
      fake.on("post", /\/inventory\/import$/, { data: { created: 1, updated: 0, unchanged: 0, missing: 0, skipped: 1, rows: 2, digest: "x", dry_run: false,
        inventory_source_id: 5, missing_skipped: false, error_count: 1, errors: [{ external_id: "shared-1", error: "belongs to inventory source 'cmdb' (#4)" }] } });
      await show();
      await click(button("Import CSV / JSON"));
      await type(byId<HTMLTextAreaElement>("fleet-import-content"), "external_id,address\nshared-1,10.8.0.1\nnew-1,10.8.0.2\n");
      await click(button("Import"));
      const result = document.querySelector('[role="dialog"]')?.textContent ?? "";
      assert.match(result, /1 skipped/);
      assert.match(result, /shared-1: belongs to inventory source 'cmdb' \(#4\)/);
    }],
  ],
  "InventorySection render tests",
);
