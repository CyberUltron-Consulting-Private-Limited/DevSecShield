/**
 * <InfoTip> and <FieldLabel> rendered in a DOM (jsdom, already in the lockfile through isomorphic-dompurify), with the
 * real Radix tooltip: keyboard focus opens and Escape closes; the trigger is named "About <label>" and, while open,
 * described (aria-describedby) by the tip's text; a tap opens, a second tap and a tap outside close; a mouse click
 * keeps an open tip open; the label stays outside the <label>, so it is not part of the input's name.
 * Layout (no tip clipped at the viewport edges) needs a real browser: e2e/infotip.e2e.mjs.
 * Run: npx --yes tsx components/ui/info-tip.dom.test.ts
 */
import assert from "node:assert/strict";

// jsdom ships no type declarations (and @types/jsdom is not a dependency): only the constructor is used here.
// eslint-disable-next-line @typescript-eslint/no-require-imports
const { JSDOM } = require("jsdom") as {
  JSDOM: new (html: string, options: object) => { window: Window & typeof globalThis };
};

const dom = new JSDOM("<!doctype html><html><body></body></html>", { pretendToBeVisual: true, url: "http://localhost/" });
const g = globalThis as unknown as Record<string, unknown>;
// jsdom's DOM classes and events replace Node's own (Node has Event, EventTarget and CustomEvent too, which jsdom
// nodes reject in dispatchEvent).
const DOM_NAME = /Event$|^EventTarget$|^Node$|^Element$|^Text$|^HTML|^SVG|^DOM|^Document|^MutationObserver$|^getComputedStyle$|AnimationFrame$/;
for (const key of Object.getOwnPropertyNames(dom.window)) {
  if (!(key in g) || DOM_NAME.test(key)) {
    Object.defineProperty(g, key, { value: (dom.window as unknown as Record<string, unknown>)[key], configurable: true, writable: true });
  }
}
// Node has a read-only global navigator: define these instead of assigning them.
for (const [key, value] of Object.entries({ window: dom.window, document: dom.window.document, navigator: dom.window.navigator })) {
  Object.defineProperty(g, key, { value, configurable: true, writable: true });
}
g.IS_REACT_ACT_ENVIRONMENT = true;
// Radix's popper measures with ResizeObserver, which jsdom does not have.
class ResizeObserverStub {
  observe() {}
  unobserve() {}
  disconnect() {}
}
g.ResizeObserver = ResizeObserverStub;
(dom.window as unknown as Record<string, unknown>).ResizeObserver = ResizeObserverStub;

async function main() {
  const React = await import("react");
  const { act } = React;
  const { createRoot } = await import("react-dom/client");
  const { InfoTip, FieldLabel } = await import("./info-tip");
  const { INFO_TIPS } = await import("../../content/infotips");

  const doc = dom.window.document;
  const container = doc.createElement("div");
  doc.body.appendChild(container);
  const outside = doc.createElement("button");
  outside.textContent = "elsewhere";
  doc.body.appendChild(outside);
  const root = createRoot(container);
  const id = "scan.table.credits" as const;
  const tip = INFO_TIPS[id];
  await act(async () => {
    root.render(
      React.createElement(
        "div",
        null,
        React.createElement(InfoTip, { id }),
        React.createElement(FieldLabel, { htmlFor: "title", infoId: "scan.new.title" } as Parameters<typeof FieldLabel>[0], "Scan title"),
        React.createElement("input", { id: "title" }),
      ),
    );
  });

  const trigger = () => doc.querySelector(`[data-infotip="${id}"]`) as HTMLButtonElement;
  const tooltip = () => doc.querySelector('[role="tooltip"]');
  const isOpen = () => trigger().getAttribute("data-state")?.endsWith("open") ?? false;
  const settle = () => act(async () => new Promise((r) => setTimeout(r, 10)));
  const press = async (el: Element, pointerType: string) => {
    await act(async () => {
      el.dispatchEvent(new dom.window.PointerEvent("pointerdown", { bubbles: true, cancelable: true, pointerType, button: 0 }));
      el.dispatchEvent(new dom.window.PointerEvent("pointerup", { bubbles: true, cancelable: true, pointerType, button: 0 }));
      el.dispatchEvent(new dom.window.MouseEvent("click", { bubbles: true, cancelable: true, button: 0 }));
    });
    await settle();
  };
  const key = async (k: string) => {
    await act(async () => {
      doc.activeElement?.dispatchEvent(new dom.window.KeyboardEvent("keydown", { key: k, bubbles: true, cancelable: true }));
    });
    await settle();
  };

  // the trigger: a real button, named after the tip, outside any <label>
  const t = trigger();
  assert.ok(t, "the (i) button is rendered");
  assert.equal(t.tagName, "BUTTON");
  assert.equal(t.getAttribute("type"), "button", "never submits a form");
  assert.equal(t.getAttribute("aria-label"), `About ${tip.label}`);
  assert.equal(isOpen(), false, "closed at first");
  assert.equal(t.getAttribute("aria-describedby"), null, "no description while closed");

  // keyboard: focus opens, Escape closes, focus stays on the button
  await act(async () => t.focus());
  await settle();
  assert.equal(doc.activeElement, t, "the (i) button takes keyboard focus");
  assert.equal(isOpen(), true, "keyboard focus opens the tip");
  const describedBy = t.getAttribute("aria-describedby");
  assert.ok(describedBy, "while open the button is described by the tip");
  const described = doc.getElementById(describedBy!);
  assert.ok(described, "aria-describedby points at an element in the page");
  assert.equal(described!.getAttribute("role"), "tooltip");
  assert.ok(described!.textContent!.includes(tip.what), "the description is the tip's text");
  assert.ok(described!.textContent!.includes(tip.example), "…and its example");
  await key("Escape");
  assert.equal(isOpen(), false, "Escape closes the tip");
  assert.equal(tooltip(), null, "nothing left in the page");
  assert.equal(doc.activeElement, t, "focus stays on the (i) button after Escape");
  await act(async () => t.blur());
  await settle();

  // touch: Radix never opens on touch; a tap toggles, a tap outside closes
  await press(t, "touch");
  assert.equal(isOpen(), true, "a tap opens the tip");
  await press(t, "touch");
  assert.equal(isOpen(), false, "a second tap closes it");
  await press(t, "touch");
  assert.equal(isOpen(), true, "a third tap opens it again");
  await press(outside, "touch");
  assert.equal(isOpen(), false, "a tap outside closes it");

  // mouse: a click on an open tip (opened by hovering) keeps it open
  await press(t, "touch");
  assert.equal(isOpen(), true);
  await press(t, "mouse");
  assert.equal(isOpen(), true, "a mouse click does not close what the user is reading");
  await key("Escape");
  assert.equal(isOpen(), false);

  // FieldLabel: the label names the input; the (i) is beside the <label>, not inside it
  const label = doc.querySelector('label[for="title"]');
  assert.ok(label, "FieldLabel renders a <label for>");
  assert.equal(label!.textContent, "Scan title", "the input's accessible name is the label text only");
  assert.equal(label!.querySelector("button"), null, "no button inside the label");
  assert.ok(doc.querySelector('[data-infotip="scan.new.title"]'), "the label's tip is rendered beside it");

  await act(async () => root.unmount());
  console.log("info-tip DOM: tests passed");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
