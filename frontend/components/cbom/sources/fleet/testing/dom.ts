// A browser-like global environment (jsdom) for the Fleet tab's render tests, which run under tsx like every other
// *.test.ts of the frontend (CI: reusable-frontend.yml, "Unit tests"). Import it before React DOM: React reads
// `window` when it loads.
import { JSDOM } from "jsdom";

export const dom = new JSDOM("<!doctype html><html><body></body></html>", { url: "http://localhost/", pretendToBeVisual: true });

const g = globalThis as unknown as Record<string, unknown>;
const win = dom.window as unknown as Record<string, unknown>;
for (const key of Object.getOwnPropertyNames(win)) {
  // Node has its own Event, CustomEvent and EventTarget: jsdom only dispatches its own, so those are replaced too
  if (key in g && !/Event$|^EventTarget$/.test(key)) continue;
  try {
    Object.defineProperty(g, key, { value: win[key], configurable: true, writable: true });
  } catch {
    // a property Node does not let us replace
  }
}
for (const key of ["window", "document", "navigator", "localStorage", "getComputedStyle", "requestAnimationFrame", "cancelAnimationFrame"]) {
  Object.defineProperty(g, key, { value: key === "window" ? dom.window : win[key], configurable: true, writable: true });
}
g.IS_REACT_ACT_ENVIRONMENT = true;
g.ResizeObserver = class {
  observe() {}
  unobserve() {}
  disconnect() {}
};
