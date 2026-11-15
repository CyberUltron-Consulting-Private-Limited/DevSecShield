// Run: npx --yes tsx components/cbom/sources/fleet/TransportsSection.render.test.ts
// #318: the Fleet tab's Transports section (Ansible AWX/AAP, Salt, AWS SSM) as a customer uses it, in jsdom against a
// fake API: list, add (secrets entered once, never shown back), test (SSM; AWX and Salt are tested through a source),
// delete (refused while a source uses it), and the files to install on the customer's side.
import { FakeApi, byId, click, render, run, settle, spyToasts, text, type } from "./testing/harness";

import assert from "node:assert/strict";
import { act, createElement } from "react";

import TransportsSection from "./TransportsSection";
import { TEST_ELSEWHERE } from "./transportsLogic";

const TEAM = 11;
const SECRET = "awx-token-must-never-show";
const AWX = {
  id: 1, kind: "awx", name: "awx-prod", enabled: true, row_version: 1, secrets_set: ["token"],
  config: { base_url: "https://awx.example.com", job_template_id: 42, verify_tls: true, timeout_s: 30, max_hosts_per_launch: 200 },
  last_validated_at: null, last_validation_status: "never", last_validation_summary: null, used_by: [{ id: 9, name: "fleet-3-1" }],
};
const SSM = {
  id: 2, kind: "ssm", name: "ssm-prod", enabled: true, row_version: 1, secrets_set: [],
  config: { role_arn: "arn:aws:iam::123456789012:role/zs-run", regions: ["ap-south-1"], document_name: "devsecshield-collect" },
  last_validated_at: null, last_validation_status: "never", last_validation_summary: null, used_by: [],
};
const RELEASE = { version: "1.4.0", fingerprint: "SHA256:abc", sha256: { amd64: "a", arm64: "b" }, verified_at: "2026-11-01T00:00:00Z" };

function api(transports: unknown[] = [AWX, SSM]): FakeApi {
  const fake = new FakeApi()
    .on("get", /\/fleet\/transports$/, () => ({ data: { transports, release: RELEASE, release_key_fingerprint: "SHA256:abc" } }))
    .on("post", /\/fleet\/transports$/, (req) => {
      const b = req.body as { kind: string; name: string; config: object; secrets: Record<string, string> };
      return { status: 201, data: { transport: { ...AWX, id: 3, used_by: [], kind: b.kind, name: b.name, config: b.config, secrets_set: Object.keys(b.secrets).sort() } } };
    })
    .on("post", /\/fleet\/transports\/2\/validate$/, {
      data: { transport: { ...SSM, last_validation_status: "failed" }, status: "failed", summary: "The run-command role could not be used: AccessDenied" },
    })
    .on("delete", /\/fleet\/transports\/2$/, { data: { deleted: 2 } })
    .on("delete", /\/fleet\/transports\/1$/, { status: 409, data: { detail: "Sources still use this transport: fleet-3-1" } })
    .on("get", /\/fleet\/transports\/artifacts\/ansible-collection$/, { data: '{"version": "1.4.0", "files": {}}' });
  fake.install();
  return fake;
}

const show = () => render(createElement(TransportsSection, { teamId: TEAM, status: { inventory: true, policies: true, transports: true, ssh_ca: false } }));
const dialog = () => document.querySelector<HTMLElement>('[role="dialog"]');
const inDialog = (name: string): HTMLButtonElement => {
  const hit = [...(dialog()?.querySelectorAll("button") ?? [])].find((b) => (b.getAttribute("aria-label") ?? b.textContent ?? "").trim() === name);
  assert.ok(hit, `no ${name} button in the dialog`);
  return hit;
};
const row = (id: number) => document.querySelector<HTMLElement>(`[data-testid="fleet-transport-${id}"]`);
const rowButton = (id: number, name: string) => [...(row(id)?.querySelectorAll("button") ?? [])].find((b) => (b.getAttribute("aria-label") ?? b.textContent ?? "").trim() === name);
const radio = (label: string) => {
  const hit = [...(dialog()?.querySelectorAll("label") ?? [])].find((l) => l.textContent?.includes(label))?.querySelector("input");
  assert.ok(hit, `no ${label} choice`);
  return hit as HTMLInputElement;
};

void run([
  ["lists each transport with its kind, where it points, the secrets stored (names only) and what uses it", async () => {
    api();
    await show();
    const awx = row(1)?.textContent ?? "";
    assert.match(awx, /awx-prod/);
    assert.match(awx, /Ansible \(AWX \/ AAP\)/);
    assert.match(awx, /https:\/\/awx\.example\.com · job template 42/);
    assert.match(awx, /token/);
    assert.match(awx, /fleet-3-1/);
    assert.match(row(2)?.textContent ?? "", /AWS Systems Manager \(SSM\)[\s\S]*arn:aws:iam::123456789012:role\/zs-run · ap-south-1/);
    assert.match(text(), /zs-collect 1\.4\.0/);
  }],
  ["adds an AWX transport: the token is sent once, never shown back, and the form starts empty next time", async () => {
    const fake = api();
    const toasts = spyToasts();
    await show();
    await click(byId<HTMLButtonElement>("fleet-add-transport"));
    assert.ok(dialog(), "no dialog");
    assert.ok(radio("Ansible (AWX / AAP)").checked, "AWX is the default kind");
    await type(byId("transport-name"), "awx-dc1");
    await type(byId("transport-base-url"), "https://awx.dc1.example.com/");
    await type(byId("transport-job-template"), "7");
    await type(byId("transport-token"), SECRET);
    assert.equal(byId("transport-token").getAttribute("type"), "password");
    await click(inDialog("Add transport"));
    const [post] = fake.calls("post", /\/fleet\/transports$/);
    assert.deepEqual(post.body, {
      kind: "awx", name: "awx-dc1", config: { base_url: "https://awx.dc1.example.com", job_template_id: 7, verify_tls: true }, secrets: { token: SECRET },
    });
    assert.equal(dialog(), null, "the dialog stays open after a save");
    assert.ok(toasts.some((t) => t.kind === "success" && /Transport added/.test(t.message)));
    assert.ok(!text().includes(SECRET) && !toasts.some((t) => t.message.includes(SECRET)), "the token is shown back");
    await click(byId<HTMLButtonElement>("fleet-add-transport"));
    assert.equal(byId("transport-token").value, "", "the token is still in the form");
  }],
  ["names each missing field and sends nothing until they are filled", async () => {
    const fake = api();
    await show();
    await click(byId<HTMLButtonElement>("fleet-add-transport"));
    await click(inDialog("Add transport"));
    assert.equal(fake.calls("post", /\/fleet\/transports$/).length, 0);
    const t = dialog()?.textContent ?? "";
    assert.match(t, /Enter a name/);
    assert.match(t, /https:\/\/ URL/);
    assert.match(t, /job template ID/);
    assert.match(t, /AWX \/ AAP token/);
  }],
  ["Salt asks for the salt-api user and password; SSM for a role, regions and a document, and no secret", async () => {
    const fake = api();
    await show();
    await click(byId<HTMLButtonElement>("fleet-add-transport"));
    await click(radio("Salt"));
    assert.ok(byId("transport-salt-username") && byId("transport-salt-password"), "no Salt login fields");
    assert.equal(document.getElementById("transport-token"), null, "an AWX token field on a Salt form");
    await click(radio("AWS Systems Manager (SSM)"));
    assert.equal(document.getElementById("transport-salt-password"), null);
    await type(byId("transport-name"), "ssm-dc1");
    await type(byId("transport-role-arn"), "arn:aws:iam::123456789012:role/zs-run");
    await type(byId("transport-regions"), "ap-south-1, eu-west-1");
    await click(inDialog("Add transport"));
    const [post] = fake.calls("post", /\/fleet\/transports$/);
    assert.deepEqual(post.body, {
      kind: "ssm", name: "ssm-dc1", secrets: {},
      config: { role_arn: "arn:aws:iam::123456789012:role/zs-run", regions: ["ap-south-1", "eu-west-1"], document_name: "devsecshield-collect" },
    });
  }],
  ["Test checks an SSM transport and shows the result; AWX and Salt say they are tested through a source", async () => {
    const fake = api();
    const toasts = spyToasts();
    await show();
    assert.equal(rowButton(1, "Test awx-prod"), undefined, "AWX offers a Test ZeroShield cannot run");
    assert.match(row(1)?.textContent ?? "", new RegExp(TEST_ELSEWHERE.slice(0, 30).replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
    await click(rowButton(2, "Test ssm-prod")!);
    assert.equal(fake.calls("post", /\/transports\/2\/validate$/).length, 1);
    assert.ok(toasts.some((t) => t.kind === "error" && /AccessDenied/.test(t.message)), JSON.stringify(toasts));
  }],
  ["Delete asks first, deletes, and says why when a source still uses the transport", async () => {
    const fake = api();
    const toasts = spyToasts();
    await show();
    await click(rowButton(2, "Delete ssm-prod")!);
    const confirm = document.querySelector<HTMLElement>('[role="alertdialog"], [role="dialog"]');
    assert.ok(confirm, "no confirmation");
    await click([...confirm.querySelectorAll("button")].find((b) => b.textContent?.trim() === "Delete")!);
    assert.equal(fake.calls("delete", /\/transports\/2$/).length, 1);
    await click(rowButton(1, "Delete awx-prod")!);
    const again = document.querySelector<HTMLElement>('[role="alertdialog"], [role="dialog"]');
    await click([...again!.querySelectorAll("button")].find((b) => b.textContent?.trim() === "Delete")!);
    await settle();
    assert.ok(toasts.some((t) => t.kind === "error" && /Sources still use this transport: fleet-3-1/.test(t.message)), JSON.stringify(toasts));
  }],
  ["shows the files to install on your side", async () => {
    const fake = api();
    await show();
    const btn = [...document.querySelectorAll("button")].find((b) => b.textContent?.trim() === "ansible-collection");
    assert.ok(btn, "no ansible-collection file");
    await act(async () => btn!.click());
    await settle(60);
    assert.equal(fake.calls("get", /\/artifacts\/ansible-collection$/).length, 1);
    assert.match(document.querySelector('[data-testid="fleet-transport-file"]')?.textContent ?? "", /"version": "1\.4\.0"/);
  }],
  ["without an active zs-collect release, only the files that need none can be loaded (no request that can only fail)", async () => {
    const fake = new FakeApi().on("get", /\/fleet\/transports$/, { data: { transports: [AWX], release: null, release_key_fingerprint: "SHA256:abc" } });
    fake.install();
    await show();
    const files = document.querySelector('[data-testid="fleet-transport-files"]');
    const btn = (name: string) => [...(files?.querySelectorAll("button") ?? [])].find((b) => b.textContent?.trim() === name);
    for (const name of ["ansible-collection", "salt-state", "ssm-document", "zs-collect-manifest"]) {
      assert.equal(btn(name)?.disabled, true, `${name} can be clicked without a release`);
      assert.match(btn(name)?.getAttribute("title") ?? "", /zs-collect release/);
    }
    for (const name of ["ssm-role-cfn", "zs-collect-pubkey", "sshca-trust-salt", "sshca-trust-ansible", "sshca-trust-ssm"]) {
      assert.equal(btn(name)?.disabled, false, `${name} is off`);
    }
    await act(async () => btn("ansible-collection")!.click());
    await settle();
    assert.equal(fake.calls("get", /\/artifacts\//).length, 0, "a file that needs a release was asked for");
  }],
  ["an empty list says what a transport is for", async () => {
    api([]);
    await show();
    assert.match(text(), /No transport yet/);
  }],
], "TransportsSection");
