/**
 * The TEMP QA page /pqc-vuln-verify ("delete after verification") was reachable without signing in and rendered
 * fixture data. It is gone: no app route serves it (the path now falls to the signed-in [team_id] layout) and
 * nothing links to it.
 * Run: npx --yes tsx utils/removedDebugRoutes.test.ts
 */
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";

const root = path.join(__dirname, "..");
const REMOVED = ["pqc-vuln-verify"];

function walk(dir: string, out: string[] = []): string[] {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (entry.name === "node_modules" || entry.name === ".next" || entry.name.startsWith(".")) continue;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) walk(full, out);
    else if (/\.(tsx?|jsx?|mjs|json)$/.test(entry.name) && !full.endsWith("removedDebugRoutes.test.ts")) out.push(full);
  }
  return out;
}

for (const route of REMOVED) {
  assert.equal(fs.existsSync(path.join(root, "app", route)), false, `app/${route} still exists`);
  const dirs = walk(path.join(root, "app")).map((f) => path.relative(path.join(root, "app"), f).split(path.sep));
  assert.ok(!dirs.some((parts) => parts.includes(route)), `a route segment named ${route} still exists`);
  for (const dir of ["app", "components", "utils", "hooks", "lib"]) {
    const base = path.join(root, dir);
    if (!fs.existsSync(base)) continue;
    for (const file of walk(base)) {
      assert.ok(!fs.readFileSync(file, "utf8").includes(`/${route}`), `${path.relative(root, file)} links to /${route}`);
    }
  }
}
console.log("removed debug routes tests passed");
