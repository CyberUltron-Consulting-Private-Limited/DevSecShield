/**
 * X1 (Nov 11): the LLM scan page (and other scan and results pages) had icon-only buttons with no accessible name: the
 * chat's send and scroll-to-latest buttons, Back arrows, row action menus, remove (trash, x) buttons and an info
 * button. A screen reader announced "button". Every icon-size Button now has an aria-label (or a title).
 * Pages owned by other groups this round (team settings, CBOM dashboard) and components/ui are not checked here.
 * Run: npx --yes tsx utils/iconButtonNames.test.ts
 */
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";

const root = path.join(__dirname, "..");
const skip = new Set(["components/Settings.tsx", "app/[team_id]/settings/page.tsx", "app/[team_id]/cbom/page.tsx"]);

function walk(dir: string): string[] {
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap((e) => {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) return e.name === "ui" || e.name === "deprecated" || e.name === "admin" ? [] : walk(p);
    return e.name.endsWith(".tsx") ? [p] : [];
  });
}

/** The visible text of a JSX fragment: {expressions} and <tags> removed. */
function visibleText(jsx: string): string {
  let out = "";
  let depth = 0;
  for (const ch of jsx) {
    if (ch === "{") depth++;
    else if (ch === "}") depth = Math.max(0, depth - 1);
    else if (depth === 0) out += ch;
  }
  return out.replace(/<[^>]*>/g, "").trim();
}

/** Index of the ">" that closes the opening tag (a ">" inside {...}, such as "=>", does not count). */
function openingEnd(el: string): number {
  let depth = 0;
  for (let i = 0; i < el.length; i++) {
    const ch = el[i];
    if (ch === "{") depth++;
    else if (ch === "}") depth--;
    else if (ch === ">" && depth === 0) return i;
  }
  return el.length;
}

const unnamed: string[] = [];
for (const file of [...walk(path.join(root, "app")), ...walk(path.join(root, "components"))]) {
  const rel = path.relative(root, file);
  if (skip.has(rel)) continue;
  const src = fs.readFileSync(file, "utf8");
  for (const m of src.matchAll(/<Button\b[\s\S]*?<\/Button>/g)) {
    const el = m[0];
    if (!/size="icon/.test(el)) continue;
    if (/aria-label=|title=|sr-only|aria-labelledby=/.test(el)) continue;
    const children = el.slice(openingEnd(el) + 1, el.lastIndexOf("</Button>"));
    if (/[A-Za-z]/.test(visibleText(children))) continue;
    unnamed.push(`${rel}:${src.slice(0, m.index).split("\n").length}`);
  }
}
assert.deepEqual(unnamed, [], `icon-only buttons without a name:\n${unnamed.join("\n")}`);

const prompt = fs.readFileSync(path.join(root, "components", "ai", "prompt-input.tsx"), "utf8");
assert.ok(prompt.includes("aria-label={children ? undefined : label}"), "the chat's send button has a name");
const conv = fs.readFileSync(path.join(root, "components", "ai", "conversation.tsx"), "utf8");
assert.ok(conv.includes('aria-label="Scroll to the latest message"'));
console.log("icon buttons have names: tests passed");
