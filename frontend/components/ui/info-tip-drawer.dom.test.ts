/**
 * The Explanations drawer (results redesign 36-D) in a DOM (jsdom) with the real Radix Sheet and Tooltip:
 *  - without a provider: no "Explanations" button and no "More in Explanations ›" in a tip (InfoTip unchanged; the
 *    full InfoTip behaviour is info-tip.dom.test.ts);
 *  - with a provider: the button opens the drawer, which lists the view's tips from the manifest, loads their text with
 *    loadTipArea (loading state, then the text; an error state with a retry), filters by search, and uses
 *    data-infotip-entry (never data-infotip);
 *  - a tip's "More in Explanations ›" opens the drawer at that tip (scrolled to and focused);
 *  - inline mode (inside a dialog): a panel, not a portaled layer, closed by Escape or its close button.
 * Run (frontend/): npx --yes tsx@4.23.15 components/ui/info-tip-drawer.dom.test.ts
 */
import "@/components/cbom/sources/fleet/testing/dom";

import assert from "node:assert/strict";

async function main() {
  const React = await import("react");
  const { act, useEffect } = React;
  const { createRoot } = await import("react-dom/client");
  const { InfoTip } = await import("./info-tip");
  const { ExplanationsButton, InfoTipDrawerProvider, useInfoTipDrawer } = await import("./info-tip-drawer");
  const { TooltipProvider } = await import("./tooltip");
  const { setTipAreaLoaderForTests } = await import("../../content/infotips/load");
  const { INFO_TIPS } = await import("../../content/infotips/all");
  const { DRAWER_MANIFEST, drawerIds } = await import("../../content/infotips/drawerManifest");
  const h = React.createElement;
  const doc = document;
  const settle = () => act(async () => new Promise((r) => setTimeout(r, 20)));
  const scrolled: string[] = [];
  (window.HTMLElement.prototype as unknown as { scrollIntoView: () => void }).scrollIntoView = function (this: HTMLElement) {
    scrolled.push(this.getAttribute("data-infotip-entry") ?? "");
  };

  // the cbom-run area answers when the test says so, so the loading state can be seen
  let release: (() => void) | null = null;
  let fail = false;
  setTipAreaLoaderForTests("cbom-run", () => new Promise((resolve, reject) => {
    release = () => (fail ? reject(new Error("chunk")) : resolve({ default: Object.fromEntries(Object.entries(INFO_TIPS).filter(([id]) => id.startsWith("cbom.run."))) as never }));
  }));

  // ------------------------------------------------------------ no provider: nothing changes
  const host = doc.createElement("div");
  doc.body.appendChild(host);
  let root = createRoot(host);
  const seen: { api: unknown } = { api: "unset" };
  function Probe() {
    const api = useInfoTipDrawer();
    useEffect(() => {
      seen.api = api;
    });
    return null;
  }
  await act(async () => {
    root.render(h(TooltipProvider, null, h("div", null, h(ExplanationsButton), h(InfoTip, { id: "cbom.res.col.fix_class" }), h(Probe))));
  });
  await settle();
  assert.equal(seen.api, null, "no provider: no drawer");
  assert.equal(doc.querySelector('[data-testid="infotip-drawer-open"]'), null, "no Explanations button without a provider");
  await act(async () => (doc.querySelector('[data-infotip="cbom.res.col.fix_class"]') as HTMLButtonElement).click());
  await settle();
  assert.ok(doc.querySelector('[role="tooltip"]') || doc.body.textContent?.includes("Fix class"), "the tip opens");
  assert.equal(doc.querySelector('[data-testid="infotip-more"]'), null, "no 'More in Explanations' without a provider");
  await act(async () => root.unmount());

  // ------------------------------------------------------------ sheet mode
  root = createRoot(host);
  await act(async () => {
    root.render(h(TooltipProvider, null, h(InfoTipDrawerProvider, { view: "dialog.overview" },
      h(ExplanationsButton), h(InfoTip, { id: "cbom.res.col.fix_class" }))));
  });
  await settle();
  const button = doc.querySelector('[data-testid="infotip-drawer-open"]') as HTMLButtonElement;
  assert.ok(button, "the Explanations button");
  assert.equal(button.getAttribute("aria-expanded"), "false");
  await act(async () => button.click());
  await settle();
  const drawer = () => doc.querySelector('[data-testid="infotip-drawer"]') as HTMLElement | null;
  assert.ok(drawer(), "the drawer opens");
  const entries = () => [...drawer()!.querySelectorAll("[data-infotip-entry]")].map((e) => e.getAttribute("data-infotip-entry"));
  assert.deepEqual(entries(), drawerIds("dialog.overview"), "the view's tips first, then the other tabs' (each once)");
  assert.equal(entries().slice(0, DRAWER_MANIFEST["dialog.overview"].length).join(), DRAWER_MANIFEST["dialog.overview"].join());
  assert.equal(drawer()!.querySelectorAll("[data-infotip]").length, 0, "entries never carry data-infotip");
  assert.ok(drawer()!.querySelector('[data-testid="infotip-drawer-loading"]'), "loading state while the area loads");
  await act(async () => release?.());
  await settle();
  const typeEntry = () => drawer()!.querySelector('[data-infotip-entry="cbom.run.f.type"]') as HTMLElement;
  assert.ok(typeEntry().textContent!.includes(INFO_TIPS["cbom.run.f.type"].what), "the tip's text, word for word");
  assert.ok(typeEntry().textContent!.includes(INFO_TIPS["cbom.run.f.type"].example));
  // search
  const search = drawer()!.querySelector('[data-testid="infotip-drawer-search"]') as HTMLInputElement;
  await act(async () => {
    const setter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, "value")!.set!;
    setter.call(search, "key size");
    search.dispatchEvent(new window.Event("input", { bubbles: true }));
  });
  await settle();
  assert.ok(entries().includes("cbom.run.f.key_size") && !entries().includes("cbom.run.f.origin"), `search filters: ${entries().join(",")}`);
  // close with Escape (Radix Sheet)
  await act(async () => {
    doc.activeElement?.dispatchEvent(new window.KeyboardEvent("keydown", { key: "Escape", bubbles: true, cancelable: true }));
  });
  await settle();
  assert.equal(drawer(), null, "Escape closes the sheet");

  // a tip's "More in Explanations ›" opens the drawer at that tip
  await act(async () => (doc.querySelector('[data-infotip="cbom.res.col.fix_class"]') as HTMLButtonElement).click());
  await settle();
  const more = doc.querySelector('[data-testid="infotip-more"]') as HTMLButtonElement;
  assert.ok(more, "with a provider the tip has 'More in Explanations ›'");
  assert.equal(more.textContent, "More in Explanations ›");
  assert.equal(more.getAttribute("tabindex"), "-1", "tooltip content takes no focus");
  scrolled.length = 0;
  await act(async () => more.click());
  await settle();
  assert.ok(drawer(), "the drawer opens from the tip");
  assert.ok(scrolled.includes("cbom.res.col.fix_class"), `scrolled to the tip: ${scrolled.join(",")}`);
  assert.equal(doc.activeElement?.getAttribute("data-infotip-entry"), "cbom.res.col.fix_class", "the entry has focus");
  await act(async () => root.unmount());

  // ------------------------------------------------------------ error state + retry
  setTipAreaLoaderForTests("cbom-run", null);
  fail = true;
  setTipAreaLoaderForTests("cbom-run", () => (fail ? Promise.reject(new Error("offline")) : import("../../content/infotips/text/cbom-run")));
  root = createRoot(host);
  const grabbed: { api: ReturnType<typeof useInfoTipDrawer> } = { api: null };
  function Grab() {
    const api = useInfoTipDrawer();
    useEffect(() => {
      grabbed.api = api;
    });
    return null;
  }
  await act(async () => {
    root.render(h(InfoTipDrawerProvider, { view: "dialog.ai", mode: "inline" }, h("div", { className: "relative" }, h(Grab))));
  });
  const aside = () => doc.querySelector('aside[data-testid="infotip-drawer"]') as HTMLElement;
  assert.ok(aside().hidden, "inline: mounted and hidden while closed");
  await act(async () => grabbed.api!.open());
  await settle();
  assert.equal(aside().hidden, false, "inline: open");
  assert.ok(aside().querySelector('[data-testid="infotip-drawer-error"]'), "an area that fails shows the error state");
  assert.equal(doc.activeElement, aside().querySelector('[data-testid="infotip-drawer-search"]'), "inline: the search field takes focus");
  fail = false;
  await act(async () => (aside().querySelector('[data-testid="infotip-drawer-error"] button') as HTMLButtonElement).click());
  await settle();
  assert.equal(aside().querySelector('[data-testid="infotip-drawer-error"]'), null, "Retry loads it");
  assert.ok(aside().querySelector('[data-infotip-entry="cbom.ai.panel"]'), "the AI tab's tips");
  await act(async () => {
    aside().querySelector("input")!.dispatchEvent(new window.KeyboardEvent("keydown", { key: "Escape", bubbles: true, cancelable: true }));
  });
  await settle();
  assert.ok(aside().hidden, "inline: Escape closes the panel");
  assert.equal(grabbed.api!.isOpen, false);
  await act(async () => root.unmount());
  setTipAreaLoaderForTests("cbom-run", null);

  console.log("info-tip drawer DOM: tests passed");
}

main().then(() => process.exit(0), (err) => {
  console.error(err);
  process.exit(1);
});
