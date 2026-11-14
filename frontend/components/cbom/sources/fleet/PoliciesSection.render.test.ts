// Run: npx --yes tsx components/cbom/sources/fleet/PoliciesSection.render.test.ts
// The policy form as a customer uses it (PR #81 UX review 5874305598), rendered in jsdom against a fake API.
import { FakeApi, button, byId, byLabel, click, maybeButton, press, render, run, settle, spyToasts, text, type } from "./testing/harness";

import assert from "node:assert/strict";
import { createElement } from "react";

import PoliciesSection from "./PoliciesSection";

const TEAM = 11;
const P = {
  id: 41, name: "prod-collect", enabled: true, priority: 100, row_version: 3, precedence: 1, matched_targets: 4, won_targets: 4,
  selector: { tag: "env", op: "eq", value: "prod" },
  action: { never_scan: false, transport: "ssh", credential_id: 3, node_id: 7, tier: 1, batch_size: 100, schedule: null },
  created_at: null, last_updated: null,
};
const OFF = { ...P, id: 42, name: "old-never", enabled: false, priority: 5, row_version: 1, precedence: null, action: { never_scan: true } };
const FRESH = { evaluated_at: "2026-11-12T10:00:00Z", stale: false, evaluation_requested: false, reconcile_requested: false, last_reconcile: {} };
const PREVIEW = { matched: 4, would_collect: 3, never_scan: 0, conflicts: [], sample: [], enabled: true };

function api(policies: unknown[] = [P, OFF], evaluation: unknown = FRESH): FakeApi {
  const fake = new FakeApi()
    .on("get", /\/fleet\/policies$/, { data: { policies, materialize: false, order: "priority, then the older policy", evaluation } })
    .on("get", /\/fleet\/credentials$/, { data: { credentials: [{ id: 3, name: "c", credential_type: "node_key", config: {}, secrets_set: [], row_version: 1 }] } })
    .on("get", /\/cbom\/sources\/nodes$/, { data: { nodes: [{ id: 7, name: "n1", mode: "agentless", status: "online" }] } })
    .on("post", /\/fleet\/policies\/preview$/, { data: PREVIEW })
    .on("patch", /\/fleet\/policies\/\d+$/, (req) => ({ data: { policy: { ...P, ...(req.body as object), row_version: 4 }, evaluation: "done", decisions_changed: 0 } }))
    .on("post", /\/fleet\/policies$/, (req) => ({ status: 201, data: { policy: { ...P, ...(req.body as object), id: 50 }, evaluation: "done", decisions_changed: 0 } }));
  fake.install();
  return fake;
}

const show = () => render(createElement(PoliciesSection, { teamId: TEAM, status: { inventory: true, policies: true, transports: false, ssh_ca: false } }));
const dialog = () => document.querySelector<HTMLElement>('[role="dialog"]');
function inDialog(name: string): HTMLButtonElement {
  const hit = [...(dialog()?.querySelectorAll("button") ?? [])].find((b) => (b.getAttribute("aria-label") ?? b.textContent ?? "").trim() === name);
  assert.ok(hit, `no ${name} button in the dialog`);
  return hit;
}

run(
  [
    ["a condition without a tag key blocks Preview and Save and says which condition", async () => {
      const fake = api();
      await show();
      await click(button("Add policy"));
      await type(byId("policy-name"), "half-done");
      await click(inDialog("Add condition"));
      assert.equal(byLabel("Tag key").placeholder, "e.g. env", "the key's placeholder reads like a value");
      assert.match(dialog()?.textContent ?? "", /Condition 1: enter a tag key/);
      assert.equal(inDialog("Preview").disabled, true);
      assert.equal(inDialog("Add policy").disabled, true);
      assert.equal(fake.calls("post", /\/fleet\/policies/).length, 0, "an incomplete selector reached the server");
      await type(byLabel("Tag key"), "env");
      assert.match(dialog()?.textContent ?? "", /Condition 1: enter a value/);
      await type(byLabel("Value"), "prod");
      assert.doesNotMatch(dialog()?.textContent ?? "", /Condition 1:/);
      await click(inDialog("Preview"));
      const sent = fake.calls("post", /\/preview$/);
      assert.equal(sent.length, 1);
      assert.deepEqual((sent[0].body as { policy: { selector: unknown } }).policy.selector, { tag: "env", op: "eq", value: "prod" });
    }],
    ["an edit is previewed in place of the saved policy (same id)", async () => {
      const fake = api();
      await show();
      await click(button("Edit prod-collect"));
      await click(inDialog("Preview"));
      assert.equal((fake.calls("post", /\/preview$/)[0].body as { policy_id: number }).policy_id, 41);
    }],
    ["a change after Preview takes the old preview away", async () => {
      api();
      await show();
      await click(button("Edit prod-collect"));
      await click(inDialog("Preview"));
      assert.ok(document.querySelector('[data-testid="policy-preview"]'), "no preview shown");
      await type(byId("policy-priority"), "300");
      assert.ok(document.querySelector('[data-testid="policy-preview"]') === null, "a stale preview stays beside Save");
    }],
    ["Save sends exactly the previewed policy, with the version it was loaded at", async () => {
      const fake = api();
      await show();
      await click(button("Edit prod-collect"));
      await type(byId("policy-priority"), "250");
      await click(inDialog("Preview"));
      await click(inDialog("Save"));
      const patch = fake.calls("patch", /\/fleet\/policies\/41$/);
      assert.equal(patch.length, 1);
      const { expected_version, ...body } = patch[0].body as { expected_version: number; priority: number };
      assert.equal(expected_version, 3);
      assert.deepEqual(body, (fake.calls("post", /\/preview$/)[0].body as { policy: unknown }).policy);
      assert.equal(body.priority, 250);
    }],
    ["after a 409 the form loads the latest version, and saving it works", async () => {
      const fake = api();
      fake.on("patch", /\/fleet\/policies\/41$/, { status: 409, data: { detail: "This policy was changed since you loaded it" } });
      await show();
      await click(button("Edit prod-collect"));
      await click(inDialog("Save"));
      assert.match(dialog()?.textContent ?? "", /changed elsewhere/);
      const before = fake.calls("get", /\/fleet\/policies$/).length;
      fake.on("get", /\/fleet\/policies$/, { data: { policies: [{ ...P, priority: 215, row_version: 4 }, OFF], materialize: false, order: "", evaluation: FRESH } });
      fake.on("patch", /\/fleet\/policies\/41$/, (req) => ({ data: { policy: { ...P, ...(req.body as object), row_version: 5 }, evaluation: "done", decisions_changed: 0 } }));
      await click(inDialog("Load the latest version"));
      assert.ok(fake.calls("get", /\/fleet\/policies$/).length > before, "the latest version was not fetched");
      assert.equal(byId("policy-priority").value, "215", "the form still shows the stale version");
      await click(inDialog("Save"));
      const last = fake.calls("patch", /\/fleet\/policies\/41$/).at(-1);
      assert.equal((last?.body as { expected_version: number }).expected_version, 4);
      assert.ok(dialog() === null, "the form did not close after saving");
      assert.match(text(), /priority 215/, "the list still shows the old version");
    }],
    ["a 409 on Disable refetches the list instead of failing again and again", async () => {
      const fake = api();
      fake.on("patch", /\/fleet\/policies\/41$/, { status: 409, data: { detail: "This policy was changed since you loaded it" } });
      await show();
      const before = fake.calls("get", /\/fleet\/policies$/).length;
      await click(button("Disable prod-collect"));
      await settle(60);
      assert.ok(fake.calls("get", /\/fleet\/policies$/).length > before, "the list was not refetched after a 409");
    }],
    ["each Disable / Enable button names its policy", async () => {
      api();
      await show();
      assert.ok(maybeButton("Disable prod-collect"));
      assert.ok(maybeButton("Enable old-never"));
      assert.equal(maybeButton("Disable"), undefined, "a button is announced as just Disable");
    }],
    ["closing the policy form gives the focus back to the button that opened it", async () => {
      api();
      await show();
      const edit = button("Edit prod-collect");
      await click(edit);
      assert.ok(dialog());
      await press("Escape");
      assert.ok(dialog() === null, "Escape did not close the form");
      assert.ok(document.activeElement === edit, `focus went to ${document.activeElement?.tagName}`); // (never diff DOM nodes)
      const add = button("Add policy");
      await click(add);
      await press("Escape");
      assert.ok(document.activeElement === add, `focus went to ${document.activeElement?.tagName}`);
    }],
    ["the preview of a disabled policy says it matches nothing until enabled", async () => {
      const fake = api();
      fake.on("post", /\/preview$/, { data: { ...PREVIEW, matched: 0, would_collect: 0, enabled: false, matched_if_enabled: 3 } });
      await show();
      await click(button("Edit old-never"));
      await click(inDialog("Preview"));
      assert.match(document.querySelector('[data-testid="policy-preview"]')?.textContent ?? "", /disabled.*would match 3/i);
    }],
    ["while a large team's decisions are being updated, the list says so and refreshes", async () => {
      const fake = api([P, OFF], { ...FRESH, stale: true, evaluation_requested: true });
      await show();
      assert.match(text(), /being updated/);
      const before = fake.calls("get", /\/fleet\/policies$/).length;
      fake.on("get", /\/fleet\/policies$/, { data: { policies: [P, OFF], materialize: false, order: "", evaluation: FRESH } });
      await settle(3600);
      assert.ok(fake.calls("get", /\/fleet\/policies$/).length > before, "the list does not refresh while stale");
      assert.doesNotMatch(text(), /being updated/);
    }],
    ["a save that the worker evaluates says the counts follow", async () => {
      const fake = api();
      fake.on("patch", /\/fleet\/policies\/41$/, (req) => ({ data: { policy: { ...P, ...(req.body as object), row_version: 4 }, evaluation: "queued", decisions_changed: null } }));
      await show();
      const toasts = spyToasts();
      await click(button("Edit prod-collect"));
      await click(inDialog("Save"));
      assert.ok(dialog() === null, "the form did not close");
      assert.deepEqual(toasts, [{ kind: "success", message: "Policy saved; the decisions and counts update in a few seconds" }]);
      fake.on("patch", /\/fleet\/policies\/41$/, (req) => ({ data: { policy: { ...P, ...(req.body as object), row_version: 5 }, evaluation: "done", decisions_changed: 1 } }));
      await click(button("Edit prod-collect"));
      await click(inDialog("Save"));
      assert.deepEqual(toasts.at(-1), { kind: "success", message: "Policy saved" });
    }],
    ["after a 409 Save stays off until the latest version is loaded", async () => {
      const fake = api();
      fake.on("patch", /\/fleet\/policies\/41$/, { status: 409, data: { detail: "changed" } });
      await show();
      await click(button("Edit prod-collect"));
      await click(inDialog("Save"));
      assert.match(dialog()?.textContent ?? "", /changed elsewhere/);
      assert.equal(inDialog("Save").disabled, true, "Save is still on after a 409");
      fake.on("get", /\/fleet\/policies$/, { data: { policies: [{ ...P, priority: 515, row_version: 9 }, OFF], materialize: false, order: "", evaluation: FRESH } });
      fake.on("patch", /\/fleet\/policies\/41$/, (req) => ({ data: { policy: { ...P, ...(req.body as object), row_version: 10 }, evaluation: "done", decisions_changed: 0 } }));
      await click(inDialog("Load the latest version"));
      assert.equal(byId("policy-priority").value, "515");
      assert.equal(inDialog("Save").disabled, false);
      await click(inDialog("Save"));
      assert.equal((fake.calls("patch", /\/fleet\/policies\/41$/).at(-1)?.body as { expected_version: number }).expected_version, 9);
    }],
    ["closing a Delete confirm gives the focus back to its Delete button", async () => {
      api();
      await show();
      for (const how of ["Escape", "Cancel"]) {
        const del = button("Delete prod-collect");
        await click(del);
        assert.ok(dialog(), "Delete opened no confirm");
        if (how === "Escape") await press("Escape");
        else await click(inDialog("Cancel"));
        assert.ok(dialog() === null, `${how} did not close the confirm`);
        assert.ok(document.activeElement === del, `${how}: focus went to ${document.activeElement?.tagName}`);
      }
    }],
  ],
  "PoliciesSection render tests",
);
