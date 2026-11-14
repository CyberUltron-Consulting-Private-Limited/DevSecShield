/**
 * The detector behind the source guards (utils/creditBalance.test.ts, utils/teamSettingsToasts.test.ts): which helpers a
 * file takes from utils/backend_api. Each guard had its own regex copy, and both missed the two most common dynamic
 * forms (PR #67 review): `const { deleteTeam } = await import(...)` and `import(...).then((m) => m.updateTeam(...))`,
 * so a new caller written that way passed the guard. Every form is listed here; one the detector cannot follow throws.
 * Run: npx --yes tsx utils/backendApiImports.test.ts
 */
import assert from "node:assert/strict";

import { backendApiImportRanges, backendApiImports } from "./backendApiImports";

const API = '"@/utils/backend_api"';
const found = (src: string, file?: string) => backendApiImports(src, file).sort();

// static imports, by the exported name; types are not uses
assert.deepEqual(found(`import { a, deleteTeam as remove,\n  type T } from ${API};`), ["a", "deleteTeam"]);
assert.deepEqual(found("import { updateTeam } from '../utils/backend_api'"), ["updateTeam"]);
assert.deepEqual(found('import { updateTeam } from "./backend_api"'), ["updateTeam"]);
assert.deepEqual(found(`import type { RemediationData, Team } from ${API};`), []);
assert.deepEqual(found(`import * as api from ${API}; api.removeOrAddTeamMembers(1, x); api["deleteTeam"](2);`),
  ["deleteTeam", "removeOrAddTeamMembers"]);
assert.deepEqual(found(`import api from ${API}; const f = () => api.startScan(1);`), ["startScan"]);
assert.deepEqual(found(`import api = require(${API}); api.cancelScan(1);`), ["cancelScan"]);
// dynamic imports: the two forms the review found missed ...
assert.deepEqual(found(`async function f(id) { const { deleteTeam } = await import(${API}); return deleteTeam(id); }`),
  ["deleteTeam"]);
assert.deepEqual(found(`const go = (id, x) => import(${API}).then((m) => m.updateTeam(id, x));`), ["updateTeam"]);
// ... and the rest of them
assert.deepEqual(found(`const run = async () => { const { startScan: start, cancelScan } = await import(${API}); };`),
  ["cancelScan", "startScan"]);
assert.deepEqual(found(`let m; async function f() { const m = await import(${API}); m.deleteTeam(1); }`), ["deleteTeam"]);
assert.deepEqual(found(`async () => (await import(${API})).startScan(1)`), ["startScan"]);
assert.deepEqual(found(`async () => (await (import(${API})))["cancelScan"](1)`), ["cancelScan"]);
assert.deepEqual(found(`import(${API}).then(({ updateTeam, deleteTeam: d }) => d(1));`), ["deleteTeam", "updateTeam"]);
assert.deepEqual(found(`import(${API}).then(function (api) { return api.startDASTScan(x); });`), ["startDASTScan"]);
assert.deepEqual(found(`const { cancelCbomRun } = require(${API});`), ["cancelCbomRun"]);
assert.deepEqual(found(`async () => { const { startScan, ...rest } = await import(${API}); rest.cancelScan(1); }`),
  ["cancelScan", "startScan"]);
// an alias is followed only where it is visible: outside its block, or as a parameter of the same name, it is another variable
assert.deepEqual(found(`async () => { const m = await import(${API}); m.startScan(1); [1].map((m) => send(m)); }; send(m);`),
  ["startScan"]);
// not uses: other modules, comments, strings, an import() in a type
assert.deepEqual(found(`import { deleteTeam } from "@/utils/other"; // deleteTeam(1)`), []);
assert.deepEqual(found(`/* const { deleteTeam } = await import(${API}); */ const s = 'import(${API}).then((m) => m.x())';`), []);
assert.deepEqual(found(`type P = { remediation?: import('@/utils/backend_api').RemediationData | null };`, "p.tsx"), []);
assert.deepEqual(found(`const mermaid = (await import("mermaid")).default; const { codeToHtml } = await import("shiki");`), []);
// a use it cannot follow fails the guard instead of hiding a helper
for (const [src, why] of [
  [`const p = import(${API}); p.then(() => 1);`, "an import() kept as a promise"],
  [`async () => { const m = await import(${API}); call(m); }`, `"m" passes on the module`],
  [`import * as api from ${API}; register(api);`, `"api" passes on the module`],
  [`export { startScan } from ${API};`, "a re-export"],
  [`export * from ${API};`, "a re-export"],
  [`import(${API}).then(handler);`, "a .then"],
  [`async () => { const [a] = await import(${API}); }`, "an array pattern"],
  [`async () => { const { [k]: f } = await import(${API}); }`, "a computed name"],
] as const) {
  assert.throws(() => backendApiImports(src, "hooks/x.ts"), (e: Error) => e.message.startsWith(`hooks/x.ts:1: ${why} of utils/backend_api`),
    `${src}: should throw "${why}"`);
}
// the static import statements (their names are not calls)
const src = `import { a } from "x";\nimport {\n  startScan,\n} from ${API};\nstartScan(1);`;
assert.deepEqual(backendApiImportRanges(src).map(([s, e]) => src.slice(s, e)), [`import {\n  startScan,\n} from ${API};`]);

console.log("backend_api import detector: tests passed");
