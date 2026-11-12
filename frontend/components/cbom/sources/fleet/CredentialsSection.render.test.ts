// Run: npx --yes tsx components/cbom/sources/fleet/CredentialsSection.render.test.ts
// Editing a credential (PR #81 UX review 4550301311): name and login settings change in place; secrets are write-only
// (never shown; a blank field keeps the stored one). No secret-shaped literal here: the test makes one at run time.
import { FakeApi, button, byId, click, press, render, run, settle, type } from "./testing/harness";

import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { createElement, Fragment } from "react";

import CredentialsSection from "./CredentialsSection";
import PoliciesSection from "./PoliciesSection";

const TEAM = 11;
const PW = { id: 3, name: "linux-pw", credential_type: "password", row_version: 2, secrets_set: ["password"], managed_sources: 1,
  config: { login_user: "zs-cbom", port: 22, host_key_policy: "pinned", known_hosts: "web-1.example.test ssh-ed25519 (pinned key)" } };
const FRESH = { evaluated_at: null, stale: false, evaluation_requested: false, reconcile_requested: false, last_reconcile: {} };

function api(): FakeApi {
  const fake = new FakeApi()
    .on("get", /\/fleet\/credentials$/, { data: { credentials: [PW] } })
    .on("get", /\/fleet\/policies$/, { data: { policies: [], materialize: false, order: "", evaluation: FRESH } })
    .on("patch", /\/fleet\/credentials\/3$/, (req) => ({ data: { credential: { ...PW, ...(req.body as object), row_version: 3 }, evaluation: "done", decisions_changed: 0 } }))
    .on("post", /\/fleet\/credentials$/, { status: 201, data: { credential: { ...PW, id: 4, name: "new", credential_type: "node_key", secrets_set: [] } } });
  fake.install();
  return fake;
}

const status = { inventory: true, policies: true, transports: false, ssh_ca: false };
const show = () => render(createElement(Fragment, null, createElement(CredentialsSection, { teamId: TEAM, status }), createElement(PoliciesSection, { teamId: TEAM, status })));
const dialog = () => document.querySelector<HTMLElement>('[role="dialog"]');
function inDialog(name: string): HTMLButtonElement {
  const hit = [...(dialog()?.querySelectorAll("button") ?? [])].find((b) => (b.getAttribute("aria-label") ?? b.textContent ?? "").trim() === name);
  assert.ok(hit, `no ${name} button in the dialog`);
  return hit;
}

run(
  [
    ["Edit changes the login and keeps the stored password when its field is left blank", async () => {
      const fake = api();
      await show();
      await click(button("Edit linux-pw"));
      assert.equal(byId("cred-login").value, "zs-cbom");
      const password = byId("cred-password");
      assert.equal(password.value, "", "a stored secret is shown");
      assert.equal(password.type, "password");
      assert.match(password.placeholder, /leave blank/i);
      await type(byId("cred-name"), "linux-pw-2");
      await click(inDialog("Save"));
      const sent = fake.calls("patch", /\/fleet\/credentials\/3$/);
      assert.equal(sent.length, 1);
      const body = sent[0].body as { name: string; config: Record<string, unknown>; secrets?: Record<string, string>; expected_version: number };
      assert.equal(body.name, "linux-pw-2");
      assert.equal(body.expected_version, 2);
      assert.equal(body.config.login_user, "zs-cbom");
      assert.equal(body.config.known_hosts, PW.config.known_hosts);
      assert.equal(body.secrets, undefined, "a blank secret field was sent (it would erase the stored one)");
      assert.ok(dialog() === null, "the form did not close");
    }],
    ["a new password typed in Edit is sent, once, and only as a secret", async () => {
      const fake = api();
      await show();
      await click(button("Edit linux-pw"));
      const fresh = randomBytes(12).toString("base64url");
      await type(byId("cred-password"), fresh);
      await click(inDialog("Save"));
      const body = fake.calls("patch", /\/fleet\/credentials\/3$/)[0].body as { secrets?: Record<string, string>; config: Record<string, unknown> };
      assert.deepEqual(body.secrets, { password: fresh });
      assert.ok(!JSON.stringify(body.config).includes(fresh));
    }],
    ["changing the login warns that the stored secret must be entered again", async () => {
      api();
      await show();
      await click(button("Edit linux-pw"));
      await type(byId("cred-login"), "other-user");
      assert.match(dialog()?.textContent ?? "", /enter the password again/i);
    }],
    ["closing the credential form gives the focus back to the button that opened it", async () => {
      api();
      await show();
      for (const name of ["Edit linux-pw", "Add credential"]) {
        const opener = button(name);
        await click(opener);
        assert.ok(dialog(), `${name} opened no dialog`);
        await press("Escape");
        assert.ok(document.activeElement === opener, `${name}: focus went to ${document.activeElement?.tagName}`);
      }
    }],
    ["adding a credential refreshes the credentials only; editing one refreshes the policies' decisions too", async () => {
      const fake = api();
      await show();
      const policiesBefore = fake.calls("get", /\/fleet\/policies$/).length;
      await click(button("Add credential"));
      await type(byId("cred-name"), "new");
      await click(inDialog("Add credential"));
      await settle(60);
      assert.equal(fake.calls("get", /\/fleet\/policies$/).length, policiesBefore, "adding a credential refetched the policies");
      await click(button("Edit linux-pw"));
      await click(inDialog("Save"));
      await settle(60);
      assert.ok(fake.calls("get", /\/fleet\/policies$/).length > policiesBefore, "editing a credential did not refresh the policies");
    }],
  ],
  "CredentialsSection render tests",
);
