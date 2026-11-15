/**
 * <InfoTip> and <FieldLabel> rendered in a DOM (jsdom, already in the lockfile through isomorphic-dompurify), with the
 * real Radix tooltip: focus reached with Tab opens and Escape closes, a programmatic focus does not (a dialog that
 * focuses an (i) first opens with the tip closed and closes on the first Esc); the trigger is named "About <label>" and
 * always described (aria-describedby) by the tip's text, open or not; a tap opens, a second tap and a tap outside close; a mouse click
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
  const { Dialog, DialogContent, DialogDescription, DialogTitle } = await import("./dialog");
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
        React.createElement(InfoTip, { id: "cbsrc.meta.lifetime" }),
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
  // a Tab press, then the focus it moves: what a keyboard user does (a programmatic focus has no Tab before it)
  const tabTo = async (el: HTMLElement) => {
    await act(async () => {
      doc.dispatchEvent(new dom.window.KeyboardEvent("keydown", { key: "Tab", bubbles: true, cancelable: true }));
      el.focus();
    });
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
  // screen readers: the button is described by the tip's text while it is closed too, so it is read without a popup
  const closedDesc = doc.getElementById(t.getAttribute("aria-describedby") ?? "");
  assert.ok(closedDesc, "aria-describedby points at an element in the page while the tip is closed");
  assert.equal(closedDesc!.hidden, true, "the description is hidden from view and from the reading order");
  for (const part of [tip.what, `Why it matters: ${tip.why}`, `Example: ${tip.example}`]) {
    assert.ok(closedDesc!.textContent!.includes(part), `the closed description has: ${part.slice(0, 40)}`);
  }

  // a programmatic focus (a dialog focusing its first button when it opens) does not open the tip, so the dialog's
  // first Esc closes the dialog, not a tip nobody asked for
  await act(async () => {
    doc.dispatchEvent(new dom.window.PointerEvent("pointerdown", { bubbles: true, pointerType: "mouse" }));
    t.focus();
  });
  await settle();
  assert.equal(doc.activeElement, t);
  assert.equal(isOpen(), false, "a programmatic focus does not open the tip");
  await act(async () => t.blur());
  await settle();

  // keyboard: focus reached with Tab opens, Escape closes, focus stays on the button
  await tabTo(t);
  await settle();
  assert.equal(doc.activeElement, t, "the (i) button takes keyboard focus");
  assert.equal(isOpen(), true, "keyboard focus opens the tip");
  // the page scrolls to bring a Tab-focused button into view (review of #135, QA M1): Radix closes a tooltip on a scroll
  // that contains its trigger, but a keyboard-focused tip stays open until Esc or blur
  await act(async () => {
    doc.dispatchEvent(new dom.window.Event("scroll", { bubbles: false }));
  });
  await settle();
  assert.equal(isOpen(), true, "a scroll after keyboard focus does not close the tip");
  const describedBy = t.getAttribute("aria-describedby");
  assert.equal(describedBy, closedDesc!.id, "while open the button keeps the same description");
  const described = doc.getElementById(describedBy!);
  assert.ok(described!.textContent!.includes(tip.what), "the description is the tip's text");
  assert.ok(described!.textContent!.includes(tip.example), "…and its example");
  assert.ok(tooltip()?.textContent?.includes(tip.what), "the open tip (role=tooltip) shows the same text");
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

  // every tip: what, then "Why it matters: …", then the example
  assert.ok(described!.textContent!.includes(`Why it matters: ${tip.why}`), "every tip has its why line");
  const withWhy = doc.querySelector('[data-infotip="cbsrc.meta.lifetime"]') as HTMLButtonElement;
  const whyTip = INFO_TIPS["cbsrc.meta.lifetime"];
  await tabTo(withWhy);
  await settle();
  const whyText = doc.getElementById(withWhy.getAttribute("aria-describedby") ?? "")?.textContent ?? "";
  assert.ok(whyText.includes(whyTip.what) && whyText.includes(`Why it matters: ${whyTip.why}`) && whyText.includes(whyTip.example), "what, why and example are shown");
  assert.ok(whyText.indexOf(whyTip.what) < whyText.indexOf("Why it matters") && whyText.indexOf("Why it matters") < whyText.indexOf("Example:"), "in that order");
  await key("Escape");
  assert.equal(doc.querySelector('[role="tooltip"]'), null, "Escape closes it");

  // one tip open at a time (review of #135): opening a second tip closes the first
  await press(t, "touch");
  assert.equal(isOpen(), true, "the first tip is open");
  await press(withWhy, "touch");
  await settle();
  assert.equal(isOpen(), false, "opening another tip closes the first");
  assert.ok(withWhy.getAttribute("data-state")?.endsWith("open"), "the second tip is open");
  assert.equal(doc.querySelectorAll('[role="tooltip"]').length, 1, "only one tip on screen");
  await key("Escape");

  // a focus that did not open the tip (it was already open from hover) leaves no flag behind that blocks the next
  // hover (review of #276)
  const hover = async (el: Element, on: boolean) => {
    await act(async () => {
      if (on) el.dispatchEvent(new dom.window.PointerEvent("pointermove", { bubbles: true, pointerType: "mouse" }));
      else {
        // React's onPointerLeave comes from pointerout; Radix's grace area listens for the native pointerleave
        el.dispatchEvent(new dom.window.PointerEvent("pointerout", { bubbles: true, pointerType: "mouse", relatedTarget: doc.body }));
        el.dispatchEvent(new dom.window.PointerEvent("pointerleave", { bubbles: false, pointerType: "mouse" }));
      }
    });
    // leaving: the pointer then moves well away from the trigger and the tip (Radix's grace area, set up on leave)
    if (!on) {
      await act(async () => {
        doc.dispatchEvent(new dom.window.PointerEvent("pointermove", { bubbles: true, pointerType: "mouse", clientX: 5000, clientY: 5000 }));
      });
    }
    await act(async () => new Promise((r) => setTimeout(r, 250)));
  };
  const wOpen = () => withWhy.getAttribute("data-state")?.endsWith("open") ?? false;
  // a mouse user: the keyboard focus left by the checks above ends (a mouse press elsewhere)
  await act(async () => {
    withWhy.blur();
    doc.body.dispatchEvent(new dom.window.PointerEvent("pointerdown", { bubbles: true, pointerType: "mouse" }));
  });
  await settle();
  await hover(withWhy, true);
  assert.equal(wOpen(), true, "hover opens the tip");
  await act(async () => withWhy.focus());
  await settle();
  assert.equal(wOpen(), true, "a focus on an open tip keeps it open");
  // Enter toggles it closed: the tip closes without Radix being asked, so nothing else would clear the flag
  await act(async () => {
    withWhy.dispatchEvent(new dom.window.KeyboardEvent("keydown", { key: "Enter", bubbles: true, cancelable: true }));
    withWhy.click();
  });
  await settle();
  assert.equal(wOpen(), false, "Enter closes the open tip");
  await act(async () => {
    withWhy.dispatchEvent(new dom.window.PointerEvent("pointerout", { bubbles: true, pointerType: "mouse", relatedTarget: doc.body }));
  });
  await hover(withWhy, true);
  assert.equal(wOpen(), true, "the next hover opens it again");
  await hover(withWhy, false);
  await act(async () => withWhy.blur());
  await settle();

  // FieldLabel: the label names the input; the (i) is beside the <label>, not inside it
  const label = doc.querySelector('label[for="title"]');
  assert.ok(label, "FieldLabel renders a <label for>");
  assert.equal(label!.textContent, "Scan title", "the input's accessible name is the label text only");
  assert.equal(label!.querySelector("button"), null, "no button inside the label");
  assert.ok(doc.querySelector('[data-infotip="scan.new.title"]'), "the label's tip is rendered beside it");

  await act(async () => root.unmount());

  // a Radix Dialog whose first focusable element is an (i) (staging QA: the run finding dialog): it focuses that button
  // when it opens; the tip stays closed and the first Esc closes the dialog, opened by mouse or by keyboard
  const h = React.createElement;
  function DialogCase() {
    const [open, setOpen] = React.useState(false);
    return h(React.Fragment, null,
      h("button", { type: "button", "data-testid": "open-dialog", onClick: () => setOpen(true) }, "Open"),
      h(Dialog, { open, onOpenChange: setOpen },
        h(DialogContent, null,
          h(DialogTitle, null, "Edit"),
          h(DialogDescription, null, "A form whose first focusable element is a tip"),
          h(FieldLabel, { htmlFor: "dlg-name", infoId: "cbsrc.meta.lifetime" } as Parameters<typeof FieldLabel>[0], "Name"),
          h("input", { id: "dlg-name" }))));
  }
  const dialogBox = doc.createElement("div");
  doc.body.appendChild(dialogBox);
  const dialogRoot = createRoot(dialogBox);
  await act(async () => dialogRoot.render(h(DialogCase)));
  const opener = () => doc.querySelector('[data-testid="open-dialog"]') as HTMLButtonElement;
  const dialogEl = () => doc.querySelector('[role="dialog"]');
  for (const how of ["mouse", "keyboard"] as const) {
    if (how === "mouse") {
      await press(opener(), "mouse");
    } else {
      await tabTo(opener());
      await act(async () => {
        opener().dispatchEvent(new dom.window.KeyboardEvent("keydown", { key: "Enter", bubbles: true, cancelable: true }));
        opener().click();
      });
    }
    await settle();
    await settle();
    assert.ok(dialogEl(), `${how}: the dialog opened`);
    const first = doc.activeElement as HTMLElement | null;
    assert.equal(first?.getAttribute("data-infotip"), "cbsrc.meta.lifetime", `${how}: the dialog focused its first focusable element, the (i)`);
    assert.equal(first?.getAttribute("data-state")?.endsWith("open") ?? false, false, `${how}: the tip is closed when the dialog opens`);
    assert.equal(doc.querySelector('[role="tooltip"]'), null, `${how}: no tip on screen`);
    await key("Escape");
    await settle();
    assert.equal(dialogEl(), null, `${how}: the first Esc closes the dialog`);
  }
  await act(async () => dialogRoot.unmount());
  console.log("info-tip DOM: tests passed");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
