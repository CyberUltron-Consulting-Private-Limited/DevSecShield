import assert from "node:assert/strict";
import { everythingExcludeMessage, matchesEverything } from "./pathPatterns";

// #443 review finding 4: an exclude of only "*" / "**" names matches every file (backend path_patterns.py agrees)
for (const p of [["*"], ["**"], ["**", "*"], ["**/*"], [" ** "]]) assert.ok(matchesEverything(p), JSON.stringify(p));
for (const p of [["tests"], ["*.min.js"], ["**", "vendor"], ["src", "*"], [".tf"], [], [""], ["/"]]) {
  assert.ok(!matchesEverything(p), JSON.stringify(p));
}
assert.equal(everythingExcludeMessage([["tests"], ["vendor"]]), null);
assert.match(everythingExcludeMessage([["tests"], ["**"]]) ?? "", /^The exclude pattern "\*\*" matches every file/);
// the SAST form checks it before the estimate
import { readFileSync } from "node:fs";
import { join } from "node:path";
const form = readFileSync(join(__dirname, "..", "components", "sast-options-sidebar.tsx"), "utf8");
assert.match(form, /const everything = everythingExcludeMessage\(exclude_path_arrays\);/);
console.log("pathPatterns tests passed");
