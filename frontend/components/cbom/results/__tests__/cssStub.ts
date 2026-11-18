// Test helper: lets a node test (tsx, CommonJS) import a component that imports a stylesheet (BomGraphCanvas imports
// @xyflow/react's style.css): the stylesheet becomes an empty module. Import it before the component.
// eslint-disable-next-line @typescript-eslint/no-require-imports
const Module = require("node:module") as { _extensions: Record<string, (m: { exports: unknown }) => void> };
Module._extensions[".css"] = (m) => { m.exports = {}; };
export {};
