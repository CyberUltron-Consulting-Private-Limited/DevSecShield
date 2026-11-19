/**
 * Settings > Report branding (plan §5, §7) rendered in jsdom against a fake API at the HTTP layer: an admin uploads
 * the logo as the raw file with the Content-Type its magic bytes say (not its name), a file that is not PNG, JPEG or
 * WebP or is over 2 MB never leaves the browser, Replace and Remove (confirmed) work, a light logo gets the contrast
 * hint, object URLs are revoked when the logo changes and on unmount, the team-details query is never refetched (it
 * would wipe the settings form), and a viewer sees the preview with no upload control.
 * Run (frontend/): npx --yes tsx@4.23.15 components/settings/reportBranding.dom.test.ts
 */
import { FakeApi, button, click, render, run, settle, spyToasts, text } from "@/components/cbom/sources/fleet/testing/harness";

import assert from "node:assert/strict";
import { act, createElement, type ComponentType, type ReactNode } from "react";

import { TeamAccessProvider } from "@/components/rbac/team-access";
import { TooltipProvider } from "@/components/ui/tooltip";

import { ReportBrandingCard } from "./ReportBrandingCard";

const PNG = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 13, 0x49, 0x48, 0x44, 0x52]);
const JPEG = new Uint8Array([0xff, 0xd8, 0xff, 0xe0, 0, 16, 0x4a, 0x46, 0x49, 0x46]);
const GIF = new Uint8Array([0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 1, 0, 1, 0]);
const meta = (sha: string, tone: "dark" | "light" = "dark") => ({ logo_set: true, sha256: sha, width: 400, height: 120, tone, bytes: 12_288, updated_at: "2026-11-19T10:00:00Z" });
const NONE = { logo_set: false, sha256: null, width: null, height: null, tone: null, bytes: null, updated_at: null };

// object URLs made and revoked by the previews
const made: string[] = [];
const revoked: string[] = [];
URL.createObjectURL = (() => {
  const url = `blob:test/${made.length}`;
  made.push(url);
  return url;
}) as typeof URL.createObjectURL;
URL.revokeObjectURL = (url: string) => void revoked.push(url);

function api(role: "admin" | "viewer", branding: unknown = NONE) {
  const permissions = role === "admin" ? ["team.read", "team.branding.manage"] : ["team.read"];
  let current = branding;
  const fake = new FakeApi()
    .on("get", /^\/team\/7$/, { data: { team_id: 7, role, permissions } })
    .on("get", /^\/team\/7\/branding$/, () => ({ data: current }))
    .on("get", /^\/team\/7\/branding\/logo$/, { data: new Blob([PNG], { type: "image/png" }) })
    .on("put", /^\/team\/7\/branding\/logo$/, (req) => {
      current = meta(req.headers["content-type"] === "image/jpeg" ? "b".repeat(64) : "a".repeat(64));
      return { data: current };
    })
    .on("delete", /^\/team\/7\/branding\/logo$/, () => {
      current = NONE;
      return { status: 204, data: "" };
    });
  fake.install();
  return fake;
}

// createElement's typing wants `children` in the props object; it is passed as the third argument
const Provider = TeamAccessProvider as unknown as ComponentType<{ teamId: string; children?: ReactNode }>;

async function mount() {
  const client = await render(createElement(TooltipProvider, null,
    createElement(Provider, { teamId: "7" }, createElement(ReportBrandingCard, { teamId: "7" }))));
  await settle(90);
  return client;
}

const byTest = <T extends HTMLElement = HTMLElement>(id: string) => document.querySelector(`[data-testid="${id}"]`) as T | null;

/** Choose a file in the hidden picker, as the browser does after the dialog. */
async function choose(file: File) {
  const input = byTest<HTMLInputElement>("branding-file")!;
  await act(async () => {
    Object.defineProperty(input, "files", { value: [file], configurable: true });
    input.dispatchEvent(new Event("change", { bubbles: true }));
  });
  await settle(90);
}

run([
  ["an admin uploads the raw bytes with the sniffed type; the preview shows both logos", async () => {
    const fake = api("admin");
    const toasts = spyToasts();
    await mount();
    assert.ok(text().includes("No client logo"));
    assert.equal(byTest("branding-upload")!.textContent, "Upload logo");
    // named .jpg, but the bytes are a PNG: the PNG type is sent
    const file = new File([PNG], "logo.jpg", { type: "image/jpeg" });
    await choose(file);
    const puts = fake.calls("put", /branding\/logo$/);
    assert.equal(puts.length, 1);
    assert.equal(puts[0].body, file, "the raw file is the body (no form, no base64)");
    assert.equal(puts[0].headers["content-type"], "image/png", "Content-Type from the magic bytes");
    assert.deepEqual(toasts.map((t) => t.kind), ["success"]);
    await settle(90);
    assert.equal(fake.calls("get", /branding\/logo$/).length, 1, "the image is read once for its sha256");
    assert.ok(byTest("branding-header-logo") && byTest("branding-cover-logo"), "header and cover previews");
    assert.equal(byTest("branding-header-chip")!.getAttribute("data-chip"), "white", "a dark logo sits on a white chip on navy");
    assert.ok(text().includes("ZERO SHIELD") && text().includes("Prepared for"));
    assert.ok(byTest("branding-meta")!.textContent!.includes("400 × 120 px"));
    assert.equal(byTest("branding-contrast-hint"), null);
    assert.equal(byTest("branding-upload")!.textContent, "Replace logo");
    assert.equal(fake.calls("get", /^\/team\/7$/).length, 1, "team-details is never refetched (it would wipe the settings form)");
  }],
  ["Replace makes new object URLs and revokes the old ones; unmount revokes the rest", async () => {
    const fake = api("admin", meta("a".repeat(64)));
    await mount();
    const first = made.slice(-2);
    assert.equal(first.length, 2);
    await choose(new File([JPEG], "new.png", { type: "image/png" }));
    assert.equal(fake.calls("put", /branding\/logo$/)[0].headers["content-type"], "image/jpeg");
    await settle(90);
    for (const url of first) assert.ok(revoked.includes(url), `${url} revoked when the logo changed`);
    const second = made.slice(-2);
    assert.notDeepEqual(second, first);
    const { cleanup } = await import("@/components/cbom/sources/fleet/testing/harness");
    await cleanup();
    for (const url of second) assert.ok(revoked.includes(url), `${url} revoked on unmount`);
  }],
  ["a file that is not PNG, JPEG or WebP, or is over 2 MB, never leaves the browser", async () => {
    const fake = api("admin");
    await mount();
    await choose(new File([GIF], "logo.png", { type: "image/png" }));
    assert.match(byTest("branding-problem")!.textContent!, /PNG, JPEG or WebP/);
    await choose(new File([new TextEncoder().encode("<svg xmlns='http://www.w3.org/2000/svg'/>")], "logo.svg", { type: "image/svg+xml" }));
    assert.match(byTest("branding-problem")!.textContent!, /SVG, GIF and other formats are not accepted/);
    const big = new Uint8Array(2 * 1024 * 1024 + 1);
    big.set(PNG);
    await choose(new File([big], "huge.png", { type: "image/png" }));
    assert.match(byTest("branding-problem")!.textContent!, /2 MB or smaller/);
    assert.equal(fake.calls("put", /branding\/logo$/).length, 0, "nothing was sent");
  }],
  ["Remove asks first, then deletes; the preview empties", async () => {
    const fake = api("admin", meta("a".repeat(64)));
    const toasts = spyToasts();
    await mount();
    await click(byTest("branding-remove")!);
    assert.ok(text().includes("Remove the team logo?"));
    assert.equal(fake.calls("delete", /branding\/logo$/).length, 0, "not before the confirmation");
    await click(button("Remove logo"));
    await settle(90);
    assert.equal(fake.calls("delete", /branding\/logo$/).length, 1);
    assert.ok(text().includes("No client logo"));
    assert.equal(byTest("branding-remove"), null);
    assert.deepEqual(toasts.map((t) => t.kind), ["success"]);
    assert.equal(fake.calls("get", /^\/team\/7$/).length, 1, "team-details untouched");
  }],
  ["a light logo: no chip on navy, a navy chip on the cover, and the contrast hint", async () => {
    api("admin", meta("c".repeat(64), "light"));
    await mount();
    assert.equal(byTest("branding-header-chip")!.getAttribute("data-chip"), "none");
    assert.equal(byTest("branding-cover-chip")!.getAttribute("data-chip"), "navy");
    assert.match(byTest("branding-contrast-hint")!.textContent!, /This logo is light/);
  }],
  ["a viewer sees the preview, read-only: no upload control", async () => {
    const fake = api("viewer", meta("a".repeat(64)));
    await mount();
    assert.ok(byTest("branding-header-logo"), "the preview is shown");
    assert.equal(byTest("branding-file"), null, "no file input");
    assert.equal(byTest("branding-upload"), null, "no Upload / Replace");
    assert.equal(byTest("branding-remove"), null, "no Remove");
    assert.match(byTest("branding-read-only")!.textContent!, /Only team admins/);
    assert.equal(fake.calls("put", /./).length + fake.calls("delete", /./).length, 0);
  }],
], "reportBranding.dom.test.ts");
